"""ExecMonitor: every program start, from auditd, as it happens.

Polling /proc every 30 s misses anything short-lived, which is exactly what a
command run through a hacked web app is (`sh -c 'curl ... | sh'` finishes in
milliseconds). With an auditd rule logging execve under a key, the kernel
records every program start with its pid, parent pid, path, arguments and
AppArmor label; this monitor tails audit.log and checks each one.

Rules:
- container_suspicious_exec (CRITICAL): in an internet-facing container, a
  shell, downloader or inline interpreter started by the app itself (an
  ancestor that isn't the container's init/supervisor, a shim or a shell).
  Docker healthchecks and `docker exec` have containerd-shim as parent, so they
  don't count.
- exec_from_temp (CRITICAL): a program run from /tmp, /var/tmp or /dev/shm,
  host or container: the classic dropped payload.
- reverse_shell (CRITICAL): a shell whose stdio, or whose parent's stdio, is one
  TCP/UDP socket (bash -i >& /dev/tcp/..., or python's pty.spawn trick).
- suspicious_shell_spawn (CRITICAL): on the host, a shell whose parent is one
  of process.suspicious_parent_names.
- audit_disabled (CRITICAL): the audit rule is gone or auditing is off.
"""
from __future__ import annotations

import asyncio
import fnmatch
import os
import re
import subprocess
from collections import OrderedDict
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator


from cop.alerts import Alert, Severity
from cop.containers import ContainerNames
from cop.monitors.base import BaseMonitor
from cop.procinfo import proc_stat, stdio_on_one_inet_socket

if TYPE_CHECKING:
    from cop.config import ExecMonitorConfig

_LINE_RE = re.compile(r"^type=(\w+) msg=audit\((\d+\.\d+):(\d+)\): (.*)$")
_KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')
_HEX_RE = re.compile(r"^(?:[0-9A-F]{2})+$")
_PID_MAP_SIZE = 5000
_PENDING_MAX = 500


def _parse_fields(body: str) -> dict[str, str]:
    body = body.split("\x1d", 1)[0]  # drop ENRICHED log_format's translated fields
    return {k: v for k, v in _KV_RE.findall(body)}


def _unquote(v: str | None) -> str:
    if v is None:
        return ""
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    if _HEX_RE.match(v):  # args with spaces/specials are hex-encoded
        try:
            return bytes.fromhex(v).decode(errors="replace")
        except ValueError:
            return v
    return v


def build_event(records: dict[str, dict[str, str]]) -> dict | None:
    """One execve event from its SYSCALL/EXECVE/CWD records, or None."""
    sc = records.get("SYSCALL")
    if not sc or sc.get("success") != "yes":
        return None
    ex = records.get("EXECVE", {})
    try:
        argc = int(ex.get("argc", "0"))
    except ValueError:
        argc = 0
    argv = [_unquote(ex.get(f"a{i}")) for i in range(argc) if f"a{i}" in ex]
    try:
        pid, ppid = int(sc["pid"]), int(sc["ppid"])
    except (KeyError, ValueError):
        return None
    return {
        "pid": pid,
        "ppid": ppid,
        "uid": sc.get("uid"),
        "auid": sc.get("auid"),
        "comm": _unquote(sc.get("comm")),
        "exe": _unquote(sc.get("exe")),
        "subj": sc.get("subj", ""),
        "key": _unquote(sc.get("key")),
        "argv": argv,
        "cwd": _unquote(records.get("CWD", {}).get("cwd")),
    }


def build_record_event(records: dict[str, dict[str, str]]) -> dict | None:
    """Any syscall event (e.g. an audit file watch): who did it, and to which paths."""
    sc = records.get("SYSCALL")
    if not sc:
        return None
    try:
        pid, ppid = int(sc["pid"]), int(sc["ppid"])
    except (KeyError, ValueError):
        return None
    cwd = _unquote(records.get("CWD", {}).get("cwd"))
    paths = []
    for name in records.get("_PATHS", []):
        name = _unquote(name)
        if name and not name.startswith("/") and cwd:
            name = os.path.normpath(os.path.join(cwd, name))
        paths.append(name)
    return {
        "pid": pid,
        "ppid": ppid,
        "uid": sc.get("uid"),
        "auid": sc.get("auid"),
        "success": sc.get("success"),
        "syscall": sc.get("syscall"),
        "arch": sc.get("arch"),
        "comm": _unquote(sc.get("comm")),
        "exe": _unquote(sc.get("exe")),
        "key": _unquote(sc.get("key")),
        "cwd": cwd,
        "paths": paths,
        "cmdline": _unquote(records.get("PROCTITLE", {}).get("proctitle")).replace("\x00", " ").strip(),
    }


class ExecMonitor(BaseMonitor):
    name = "ExecMonitor"

    def __init__(
        self,
        config: ExecMonitorConfig,
        baseline,
        alert_engine,
        suspicious_parent_names: list[str] | None = None,
        shell_names: list[str] | None = None,
    ):
        super().__init__(config, baseline, alert_engine)
        self._containers = ContainerNames()
        self._public = set(config.public_containers)
        self._shells = set(shell_names or ["bash", "sh", "zsh", "dash", "fish", "ash", "ksh"])
        self._host_parents = list(suspicious_parent_names or [])
        # pid -> (comm, ppid) from exec events, for parents that already exited
        self._pids: OrderedDict[int, tuple[str, int]] = OrderedDict()
        self._pending: OrderedDict[str, dict[str, dict[str, str]]] = OrderedDict()
        self._approvals: dict[str, set[str]] = {}
        self._audit_ok = True
        # audit key -> async callback(event), for other monitors' audit rules
        self._subscribers: dict[str, object] = {}

    def subscribe(self, key: str, callback) -> None:
        """Pass events with this audit key to callback(event dict) (see build_record_event)."""
        self._subscribers[key] = callback

    def parent_chain(self, ppid: int) -> list[str]:
        return self._ancestors(ppid)

    # ------------------------------------------------------------------ run

    async def run(self) -> None:
        for kind in ("container_exec", "temp_exec", "shell_parent"):
            self._approvals[kind] = await self._approved(kind)
        checker = asyncio.create_task(self._rules_loop())
        first = True
        try:
            while self._running:
                try:
                    async for line in self._tail(self._config.audit_log, from_end=first):
                        await self._handle_line(line)
                    first = False
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._logger.exception("ExecMonitor error — restarting tail in 5s")
                    await asyncio.sleep(5)
        finally:
            checker.cancel()

    async def learn(self) -> None:
        self._logger.info("ExecMonitor reads auditd events — no baseline to learn")

    # -------------------------------------------------------------- parsing

    async def _handle_line(self, line: str) -> None:
        m = _LINE_RE.match(line.rstrip("\n"))
        if not m:
            return
        rtype, serial = m.group(1), m.group(3)
        recs = self._pending.setdefault(serial, {})
        fields = _parse_fields(m.group(4))
        if rtype == "PATH":  # one per path; keep them all
            recs.setdefault("_PATHS", []).append(fields.get("name", ""))
        recs[rtype] = fields
        if rtype in ("PROCTITLE", "EOE"):
            self._pending.pop(serial, None)
            key = _unquote(recs.get("SYSCALL", {}).get("key"))
            if key == self._config.audit_key:
                ev = build_event(recs)
                if ev:
                    await self.check_event(ev)
            elif key in self._subscribers:
                ev = build_record_event(recs)
                if ev:
                    try:
                        await self._subscribers[key](ev)
                    except Exception:
                        self._logger.exception("Audit subscriber for %s failed", key)
        while len(self._pending) > _PENDING_MAX:
            self._pending.popitem(last=False)

    # ---------------------------------------------------------------- rules

    def _remember_pid(self, pid: int, comm: str, ppid: int) -> None:
        self._pids[pid] = (comm, ppid)
        self._pids.move_to_end(pid)
        while len(self._pids) > _PID_MAP_SIZE:
            self._pids.popitem(last=False)

    def _lookup(self, pid: int) -> tuple[str, int] | None:
        return proc_stat(pid) or self._pids.get(pid)

    def _ancestors(self, ppid: int, limit: int = 8) -> list[str]:
        """comm of the parent, grandparent, ... up to and including a shim."""
        chain: list[str] = []
        pid = ppid
        for _ in range(limit):
            if pid <= 1:
                break
            info = self._lookup(pid)
            if info is None:
                chain.append("?")
                break
            comm, parent = info
            chain.append(comm)
            if self._is_shim(comm):
                break
            pid = parent
        return chain

    def _is_shim(self, comm: str) -> bool:
        return comm.startswith(("containerd-shim", "runc"))

    def _is_infra(self, comm: str) -> bool:
        return self._is_shim(comm) or any(fnmatch.fnmatch(comm, p) for p in self._config.container_infra_names)

    def _command_name(self, ev: dict) -> str:
        return ev["comm"] or Path(ev["exe"]).name

    def _is_shell(self, ev: dict) -> bool:
        names = {ev["comm"], Path(ev["exe"]).name}
        if ev["argv"]:
            names.add(Path(ev["argv"][0]).name)
        return bool(names & self._shells)

    def _is_suspicious_command(self, ev: dict) -> bool:
        name = self._command_name(ev)
        if self._is_shell(ev) or name in self._config.suspicious_commands:
            return True
        # python3.12 -c '...', perl -e '...'
        base = re.sub(r"[\d.]+$", "", name)
        if base in self._config.inline_interpreters:
            return any(a in ("-c", "-e", "-E", "-r") for a in ev["argv"][1:3])
        return False

    def _container_of(self, ev: dict) -> str | None:
        return self._containers.for_pid(ev["pid"]) or (
            self._containers.for_pid(ev["ppid"]) if "docker" in ev["subj"] else None
        )

    async def check_event(self, ev: dict) -> None:
        self._remember_pid(ev["pid"], self._command_name(ev), ev["ppid"])
        cmdline = " ".join(ev["argv"])[:400]
        container = self._container_of(ev)
        where = f" [{container}]" if container else ""
        base_ctx = {
            "pid": ev["pid"], "ppid": ev["ppid"], "name": self._command_name(ev),
            "exe": ev["exe"], "cmdline": cmdline, "uid": ev["uid"], "container": container,
        }

        # 1. program run from a temp dir
        exe = ev["exe"]
        if any(exe.startswith(d) for d in self._config.temp_dirs) and not any(
            fnmatch.fnmatch(exe, pat) for pat in self._config.temp_exec_allow
        ) and exe not in self._approvals.get("temp_exec", set()):
            await self._alerts.fire(Alert(
                rule_id="exec_from_temp",
                severity=Severity.CRITICAL,
                title=f"Program run from a temp dir: {exe}{where}",
                message=f"{exe} started{where} (pid {ev['pid']}, uid {ev['uid']})\nCMD: {cmdline}\nParents: {' < '.join(self._ancestors(ev['ppid']))}",
                source_monitor=self.name,
                context=base_ctx,
                subject=f"{container}:{exe}",
            ))

        # 2. reverse shell: own stdio on one socket, or parent's (python pty trick)
        if self._is_shell(ev):
            # Key on the process holding the socket: the shell's own children
            # (startup scripts, the attacker's commands) don't each alert.
            holder = ev["pid"] if stdio_on_one_inet_socket(ev["pid"]) else (
                ev["ppid"] if stdio_on_one_inet_socket(ev["ppid"]) else None)
            if holder is not None:
                await self._alerts.fire(Alert(
                    rule_id="reverse_shell",
                    severity=Severity.CRITICAL,
                    title=f"Reverse shell: {self._command_name(ev)} (pid {ev['pid']}){where}",
                    message=f"Shell with its input/output on a network socket{where}\nCMD: {cmdline}\nParents: {' < '.join(self._ancestors(ev['ppid']))}",
                    source_monitor=self.name,
                    context=base_ctx,
                    subject=f"socket-holder={holder}",
                ))
                return

        # 3. internet-facing container: shell/downloader started by the app
        if container in self._public and self._is_suspicious_command(ev):
            chain = self._ancestors(ev["ppid"])
            app = next((c for c in chain if c != "?" and not self._is_infra(c) and c not in self._shells), None)
            key = f"{container}:{self._command_name(ev)}"
            if app and key not in self._approvals.get("container_exec", set()):
                await self._alerts.fire(Alert(
                    rule_id="container_suspicious_exec",
                    severity=Severity.CRITICAL,
                    title=f"{app} started {self._command_name(ev)} in {container}",
                    message=(
                        f"In internet-facing container {container}, the app ({app}) started "
                        f"{self._command_name(ev)} — how a hacked web app runs commands.\n"
                        f"CMD: {cmdline}\nParents: {' < '.join(chain)}"
                    ),
                    source_monitor=self.name,
                    context={**base_ctx, "app": app, "parents": chain},
                    subject=key,
                ))
            return

        # 4. host shell spawned by a network-facing parent
        if container is None and self._is_shell(ev) and self._host_parents:
            info = self._lookup(ev["ppid"])
            parent = info[0] if info else ""
            if parent and any(parent == p or parent.startswith(p) for p in self._host_parents):
                key = f"{parent}:{self._command_name(ev)}"
                if key not in self._approvals.get("shell_parent", set()):
                    await self._alerts.fire(Alert(
                        rule_id="suspicious_shell_spawn",
                        severity=Severity.CRITICAL,
                        title=f"Suspicious shell spawned by {parent}",
                        message=f"Shell '{self._command_name(ev)}' (pid {ev['pid']}) spawned by '{parent}'\nCMD: {cmdline}",
                        source_monitor=self.name,
                        context={**base_ctx, "parent": parent},
                        subject=key,
                    ))

    # ------------------------------------------------------- tamper check

    async def _rules_loop(self) -> None:
        while True:
            try:
                problem = await asyncio.get_running_loop().run_in_executor(None, self._audit_problem)
                if problem and self._audit_ok:
                    await self._alerts.fire(Alert(
                        rule_id="audit_disabled",
                        severity=Severity.CRITICAL,
                        title="Exec auditing is off",
                        message=f"{problem}\ncop can't see program starts until it's restored: sudo augenrules --load",
                        source_monitor=self.name,
                        context={"problem": problem},
                    ))
                self._audit_ok = problem is None
            except asyncio.CancelledError:
                raise
            except Exception:
                self._logger.exception("Audit rule check failed")
            await asyncio.sleep(self._config.rules_check_interval_seconds)

    def _audit_problem(self) -> str | None:
        try:
            status = subprocess.run(["auditctl", "-s"], capture_output=True, text=True, timeout=10).stdout
            rules = subprocess.run(["auditctl", "-l"], capture_output=True, text=True, timeout=10).stdout
        except Exception as exc:
            return f"auditctl failed: {exc}"
        if not re.search(r"^enabled [12]$", status, re.M):
            return "Kernel auditing is disabled (auditctl -s: enabled 0)."
        if f"key={self._config.audit_key}" not in rules:
            return f"The execve audit rule (key {self._config.audit_key}) is not loaded."
        if not os.path.exists(self._config.audit_log):
            return f"{self._config.audit_log} is missing."
        return None

    # ------------------------------------------------------- Mark Expected

    async def mark_expected(self, alert) -> str:
        ctx = alert.context
        kinds = {
            "container_suspicious_exec": ("container_exec", f"{ctx.get('container')}:{ctx.get('name')}"),
            "exec_from_temp": ("temp_exec", ctx.get("exe")),
            "suspicious_shell_spawn": ("shell_parent", f"{ctx.get('parent')}:{ctx.get('name')}"),
        }
        if alert.rule_id in kinds and kinds[alert.rule_id][1]:
            kind, value = kinds[alert.rule_id]
            await self._baseline.add_approval(kind, value)
            self._approvals.setdefault(kind, set()).add(value)
            return f"✅ {value} won't alert again."
        if alert.rule_id in ("reverse_shell", "audit_disabled"):
            return "👍 Acknowledged. This always alerts."
        return await super().mark_expected(alert)

    # --------------------------------------------------------------- tail

    async def _tail(self, path: str, from_end: bool) -> AsyncIterator[str]:
        """Yield lines; after a rotation, read the new file from the start so
        nothing written around the rotation is lost.

        Reads in chunks with plain blocking reads (a regular file read never
        waits) instead of a thread-pool call per line: the log gets ~25 lines a
        second, and per-line dispatch doubled cop's CPU use.
        """
        while not os.path.exists(path):
            self._logger.warning("%s not found — waiting", path)
            await asyncio.sleep(5)
            if not self._running:
                return
        with open(path, "rb") as f:
            if from_end:
                f.seek(0, 2)
            inode = os.fstat(f.fileno()).st_ino
            buf = b""
            while self._running:
                chunk = f.read(1 << 16)
                if chunk:
                    buf += chunk
                    *lines, buf = buf.split(b"\n")
                    for line in lines:
                        yield line.decode(errors="replace")
                    continue
                try:
                    if os.stat(path).st_ino != inode:
                        self._logger.info("audit.log rotated, reopening")
                        return
                except FileNotFoundError:
                    return
                await asyncio.sleep(1.0)
