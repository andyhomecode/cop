from __future__ import annotations

import asyncio
import fnmatch
import os
import pwd
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import TripwireMonitorConfig

AUDIT_KEY = "cop_tripwire"

# auditd's "r" permission includes reading extended attributes, which `ls -l`
# (ACLs), Finder and Samba do just by listing a folder. Those aren't opens.
# x86_64: getxattr, lgetxattr, fgetxattr, listxattr, llistxattr, flistxattr
_XATTR_READ_SYSCALLS_X86_64 = {"191", "192", "193", "194", "195", "196"}


class _TripwireEventHandler(FileSystemEventHandler):
    """Bridges watchdog accessed events onto the asyncio event queue."""

    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop, tripwire_paths: set[str]):
        super().__init__()
        self._queue = queue
        self._loop = loop
        self._tripwire_paths = tripwire_paths

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if event.event_type != "opened":
            return
        src = str(event.src_path)
        if src not in self._tripwire_paths:
            return

        def _put() -> None:
            try:
                self._queue.put_nowait(src)
            except asyncio.QueueFull:
                pass
        self._loop.call_soon_threadsafe(_put)


#: Basenames that must never be armed as tripwires, even if a config lists them.
#: ``.netrc`` is probed by curl/wget/apt's HTTP fetch path on every request
#: regardless of whether auth is needed, so it fires from routine root-owned
#: timers (apt-daily*, motd-news). Attribution never resolves (quick
#: open/read/close finishes before the /proc/*/fd scan), so there's no process
#: identity to allowlist — the only fix is not watching it. See the README's
#: TripwireMonitor section.
_BLOCKED_TRIPWIRE_NAMES = {".netrc"}


def _username(uid: str | int | None) -> str:
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, TypeError, ValueError):
        return str(uid)


class TripwireMonitor(BaseMonitor):
    """Honeypot files: anything opening one fires CRITICAL.

    With auditd (ExecMonitor enabled and use_audit), each file gets an audit
    watch (`auditctl -w <file> -p rwa -k cop_tripwire`), so the alert says
    exactly which process and user opened it, and readers in allowed_readers
    (a backup's rsync, a search indexer, Samba) are ignored. cop re-adds the
    watches if a rule reload removed them. Without auditd it falls back to
    inotify, whose process attribution is best-effort.
    """

    name = "TripwireMonitor"

    def __init__(self, config: TripwireMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        self._event_queue: asyncio.Queue | None = None
        self._observer: Observer | None = None
        self.audit_source = None  # ExecMonitor, set by main when auditd is used
        self._paths: set[str] = set()

    # ------------------------------------------------------------- run

    async def run(self) -> None:
        tripwire_paths = self._setup_files()
        self._paths = tripwire_paths
        if not tripwire_paths:
            self._logger.warning("No tripwire files available — monitor inactive")
            return
        if self.audit_source is not None and self._config.use_audit:
            await self._run_audit(tripwire_paths)
        else:
            await self._run_inotify(tripwire_paths)

    async def _run_audit(self, paths: set[str]) -> None:
        self.audit_source.subscribe(AUDIT_KEY, self.on_audit_event)
        loop = asyncio.get_running_loop()
        first = True
        while self._running:
            try:
                added = await loop.run_in_executor(None, self._ensure_audit_watches, paths)
                if added and not first:
                    await self._alerts.fire(Alert(
                        rule_id="tripwire_watches_restored",
                        severity=Severity.WARN,
                        title="Tripwire audit watches were missing; restored",
                        message=(
                            "These honeypot audit watches had been removed (an `augenrules --load`, "
                            "or someone clearing audit rules) and cop re-added them:\n" + "\n".join(added)
                        ),
                        source_monitor=self.name,
                        context={"paths": added},
                    ))
                if first:
                    for p in sorted(paths):
                        self._logger.info("Tripwire armed (auditd): %s", p)
                first = False
            except Exception:
                self._logger.exception("Could not check tripwire audit watches")
            await asyncio.sleep(60)

    def _ensure_audit_watches(self, paths: set[str]) -> list[str]:
        """Add any missing `-w <path> -p rwa -k cop_tripwire`. Returns those added."""
        listing = subprocess.run(["auditctl", "-l"], capture_output=True, text=True, timeout=10).stdout
        added = []
        for p in sorted(paths):
            if f"-w {p} -p rwa -k {AUDIT_KEY}" in listing:
                continue
            r = subprocess.run(
                ["auditctl", "-w", p, "-p", "rwa", "-k", AUDIT_KEY],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                added.append(p)
            else:
                self._logger.warning("auditctl -w %s failed: %s", p, r.stderr.strip())
        return added

    async def _run_inotify(self, tripwire_paths: set[str]) -> None:
        loop = asyncio.get_event_loop()
        self._event_queue = asyncio.Queue(maxsize=100)
        handler = _TripwireEventHandler(self._event_queue, loop, tripwire_paths)
        self._observer = Observer()
        dirs_watched: set[str] = set()
        for path_str in tripwire_paths:
            parent = str(Path(path_str).parent)
            if parent not in dirs_watched:
                self._observer.schedule(handler, parent, recursive=False)
                dirs_watched.add(parent)
            self._logger.info("Tripwire armed (inotify): %s", path_str)
        self._observer.start()
        try:
            while self._running:
                try:
                    path = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                    await self._handle_access(path)
                except asyncio.TimeoutError:
                    continue
        finally:
            self._observer.stop()
            self._observer.join(timeout=5)

    async def learn(self) -> None:
        self._logger.info("TripwireMonitor has no baseline to learn")

    async def mark_expected(self, alert) -> str:
        return ("👍 Acknowledged. Tripwires always alert. If a legitimate program reads this "
                "file, add it to monitors.tripwire.allowed_readers (e.g. \"rsync@root\").")

    # ----------------------------------------------------------- files

    def _entries(self) -> list[dict]:
        """files entries as dicts: a plain path, or {path, owner, mode, content}."""
        out = []
        for e in self._config.files:
            out.append({"path": e} if isinstance(e, str) else dict(e))
        return out

    def _setup_files(self) -> set[str]:
        """Resolve paths and create missing decoy files when configured."""
        resolved: set[str] = set()
        for entry in self._entries():
            path = Path(str(entry.get("path", ""))).expanduser()
            if not entry.get("path"):
                continue
            if path.name in _BLOCKED_TRIPWIRE_NAMES:
                self._logger.warning(
                    "Refusing to arm tripwire %s: %s is a known false-positive source "
                    "(probed by curl/wget/apt on every request) and cannot be attributed "
                    "or allowlisted — remove it from tripwire.files. See README.",
                    path, path.name,
                )
                continue
            if not path.exists():
                if self._config.create_missing:
                    try:
                        self._create_decoy(path, entry)
                        self._logger.info("Created decoy tripwire file: %s", path)
                    except OSError as exc:
                        self._logger.warning("Could not create tripwire file %s: %s", path, exc)
                        continue
                else:
                    self._logger.debug("Tripwire file not found, skipping: %s", path)
                    continue
            resolved.add(str(path))
        return resolved

    def _create_decoy(self, path: Path, entry: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(entry.get("content", ""))
        path.chmod(int(str(entry.get("mode", "600")), 8))
        owner = entry.get("owner")
        if owner:
            pw = pwd.getpwnam(owner)
            os.chown(path, pw.pw_uid, pw.pw_gid)

    # ---------------------------------------------------------- alerts

    def _allowed(self, comm: str, user: str) -> bool:
        """allowed_readers entries: "comm" or "comm@user"; comm may be a glob or prefix
        ("smbd" matches smbd's per-client names like "smbd[192.168.1.")."""
        for rule in self._config.allowed_readers:
            name, _, ruser = rule.partition("@")
            if ruser and ruser != user:
                continue
            if comm == name or comm.startswith(name) or fnmatch.fnmatch(comm, name):
                return True
        return False

    async def on_audit_event(self, ev: dict) -> None:
        """An audit event with key cop_tripwire (from ExecMonitor)."""
        if ev.get("arch") in ("c000003e", None) and ev.get("syscall") in _XATTR_READ_SYSCALLS_X86_64:
            return
        path = next((p for p in ev["paths"] if p in self._paths), None) or (ev["paths"] or ["?"])[0]
        if path not in self._paths:
            # e.g. the directory entry record; find the watched file by name
            path = next((p for p in self._paths if any(Path(x).name == Path(p).name for x in ev["paths"])), path)
        user = _username(ev["uid"])
        login = _username(ev["auid"]) if ev.get("auid") not in (None, "4294967295", "-1") else None
        if self._allowed(ev["comm"], user):
            self._logger.debug("Tripwire %s read by allowed %s@%s", path, ev["comm"], user)
            return
        chain = self.audit_source.parent_chain(ev["ppid"]) if self.audit_source else []
        who = f"{ev['comm']} (pid {ev['pid']}, user {user}" + (f", logged in as {login}" if login and login != user else "") + ")"
        name = Path(path).name
        await self._alerts.fire(Alert(
            rule_id=f"tripwire_{name}",
            severity=Severity.CRITICAL,
            title=f"Tripwire: {name} opened by {ev['comm']} ({user})",
            message=(
                f"Honeypot file {path} was opened by {who}"
                + ("" if ev.get("success") == "yes" else " (the open failed)")
                + f"\nProgram: {ev['exe']}\nCMD: {ev['cmdline'][:300]}"
                + (f"\nParents: {' < '.join(chain)}" if chain else "")
            ),
            source_monitor=self.name,
            context={
                "path": path, "pid": ev["pid"], "process_name": ev["comm"], "exe": ev["exe"],
                "username": user, "login_user": login, "cmdline": ev["cmdline"][:300], "parents": chain,
            },
            subject=f"{path}:{ev['comm']}",
        ))

    async def _handle_access(self, path: str) -> None:
        loop = asyncio.get_event_loop()
        proc_info = await loop.run_in_executor(None, self._find_accessor, path)
        context: dict = {"path": path}
        if proc_info:
            context.update(proc_info)
            proc_str = f" by {proc_info['process_name']} (pid {proc_info['pid']})"
        else:
            proc_str = ""
        name = Path(path).name
        await self._alerts.fire(Alert(
            rule_id=f"tripwire_{name}",
            severity=Severity.CRITICAL,
            title=f"Tripwire: {name} accessed{proc_str}",
            message=f"Honeypot file was opened{proc_str}: {path}",
            source_monitor=self.name,
            context=context,
        ))

    def _find_accessor(self, path: str) -> dict | None:
        """Scan /proc/*/fd to find which process has the tripwire file open."""
        try:
            target_inode = os.stat(path).st_ino
        except OSError:
            return None
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            fd_dir = pid_dir / "fd"
            try:
                for fd_link in fd_dir.iterdir():
                    try:
                        if os.stat(fd_link).st_ino == target_inode:
                            comm = (pid_dir / "comm").read_text().strip()
                            return {"pid": int(pid_dir.name), "process_name": comm}
                    except OSError:
                        continue
            except (OSError, PermissionError):
                continue
        return None
