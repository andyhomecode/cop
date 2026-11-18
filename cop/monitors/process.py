from __future__ import annotations

import asyncio
import os
import re
import time
from typing import TYPE_CHECKING

import psutil

from cop.alerts import Alert, Severity
from cop.containers import ContainerNames, container_id_for_pid
from cop.procinfo import stdio_on_one_inet_socket
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.alerts import AlertEngine
    from cop.baseline import BaselineDB
    from cop.config import ProcessMonitorConfig


_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


def normalize_name(name: str | None) -> str:
    """smbd[192.168.1.5] -> smbd; 2.1.322 -> * (Claude Code names itself by version)."""
    name = name or ""
    if "[" in name:
        name = name.split("[", 1)[0]
    return _VERSION_RE.sub("*", name)


def normalize_exe(exe: str | None) -> str | None:
    """Replace version numbers in the path so updates don't look like new programs:
    .../claude/versions/2.1.322 -> .../claude/versions/*"""
    return _VERSION_RE.sub("*", exe) if exe else exe


def process_key(proc: dict) -> tuple:
    return (normalize_name(proc.get("name")), normalize_exe(proc.get("exe")), proc.get("username"))


class ProcessMonitor(BaseMonitor):
    name = "ProcessMonitor"

    def __init__(
        self,
        config: ProcessMonitorConfig,
        baseline: BaselineDB,
        alert_engine: AlertEngine,
        poll_interval: int = 30,
        known_containers: list[str] | None = None,
        public_containers: list[str] | None = None,
    ):
        super().__init__(config, baseline, alert_engine)
        self._poll_interval = poll_interval
        self._known: set[tuple] = set()
        self._known_containers: set[str] = set(known_containers or [])
        # Internet-facing containers are never exempt: their processes alert
        # like the host's (one alert per new program, then remembered).
        self._public_containers: set[str] = set(public_containers or [])
        self._containers = ContainerNames()
        self._seen_pids: set[int] = set()

    def _is_known(self, proc: dict) -> bool:
        # Check exact key first, then fall back to name+user in case exe is
        # inconsistently readable for short-lived processes.
        name, exe, user = process_key(proc)
        return (name, exe, user) in self._known or (name, None, user) in self._known

    def _remember(self, proc: dict) -> None:
        self._known.add(process_key(proc))

    def _container_name(self, cid: str) -> str | None:
        return self._containers.name(cid)

    async def run(self) -> None:
        # Prime cpu_percent tracking — first call per process always returns 0.0
        for proc in psutil.process_iter(["pid"]):
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        baseline = await self._baseline.get_process_baseline()
        for p in baseline:
            self._remember(p)
        try:
            self._known_containers |= {c["name"] for c in await self._baseline.get_container_baseline()}
        except Exception:
            self._logger.exception("Could not load container baseline")

        while self._running:
            try:
                # Only processes started since the last poll need a look; reading
                # exe/cmdline/user for all ~400 every 30 s was most of cop's CPU.
                pids = set(psutil.pids())
                new_pids = pids - self._seen_pids
                self._seen_pids = pids
                for proc in self._snapshot_processes(new_pids):
                    if self._is_known(proc):
                        # bash/sh are in every baseline, so a reverse shell is
                        # almost always a "known" program: check each new PID.
                        if self._is_reverse_shell(proc["pid"]):
                            await self._alert_new_process(proc)
                        continue
                    self._remember(proc)
                    await self._handle_new(proc)
            except Exception:
                self._logger.exception("Error in process scan cycle")
            await asyncio.sleep(self._poll_interval)

    async def _handle_new(self, proc: dict) -> None:
        """A process not seen before. Alert (unless exempt), then store it so it
        stays known across cop restarts. A scheduled job alerts the first time
        it runs, not again after every restart."""
        cid = container_id_for_pid(proc["pid"])
        if cid:
            cname = self._container_name(cid)
            proc["container"] = cname or cid[:12]
            if (
                self._config.skip_known_container_processes
                and cname in self._known_containers
                and cname not in self._public_containers
            ):
                # DockerMonitor covers exec into containers; still catch shells.
                if self._is_reverse_shell(proc["pid"]) or self._is_suspicious_shell(proc):
                    await self._alert_new_process(proc)
                return  # not persisted: container contents change with images
        if normalize_name(proc["name"]) not in self._config.ignored_process_names and proc["name"] not in self._config.ignored_process_names:
            await self._alert_new_process(proc)
        await self._baseline.add_process_to_baseline(self._db_row(proc))

    @staticmethod
    def _db_row(proc: dict) -> dict:
        name, exe, user = process_key(proc)
        return {"name": name, "exe": exe, "username": user}

    async def learn(self) -> None:
        procs = [self._db_row(p) for p in self._snapshot_processes()]
        # Additive: keeps "Mark Expected" approvals and processes seen earlier.
        await self._baseline.set_process_baseline(procs, replace=False)
        self._logger.info("Added %d running processes to baseline", len(procs))

    async def mark_expected(self, alert) -> str:
        if alert.rule_id in ("new_process", "new_root_process"):
            await self.learn_one(alert.context)
            return f"✅ Remembered: {alert.context.get('name')} won't alert again."
        return "👍 Acknowledged. Reverse-shell and suspicious-shell alerts always fire; there's nothing to approve."

    async def learn_one(self, context: dict) -> None:
        await self._baseline.add_process_to_baseline(self._db_row(context))
        # Add both exact and fuzzy keys so the current session suppresses re-alerts
        # even if exe readability is inconsistent for short-lived processes.
        name, exe, user = process_key(context)
        self._known.add((name, exe, user))
        self._known.add((name, None, user))

    def _snapshot_processes(self, pids: set[int] | None = None) -> list[dict]:
        """Info for every process, or only for the given pids."""
        result = []
        attrs = ["pid", "name", "exe", "cmdline", "username", "ppid"]
        if pids is None:
            procs = list(psutil.process_iter(attrs))
        else:
            procs = []
            for pid in pids:
                try:
                    p = psutil.Process(pid)
                    p.info = p.as_dict(attrs)
                    procs.append(p)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        names = {p.info["pid"]: p.info.get("name") for p in procs}

        def parent_name(ppid):
            if ppid in names:
                return names[ppid]
            try:
                return psutil.Process(ppid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return None

        for proc in procs:
            try:
                info = proc.info
                # Skip kernel threads: direct children of kthreadd (ppid=2) OR any thread
                # with no exe and no cmdline — kworker threads spawned by intermediate kernel
                # threads have a ppid != 2 but are still kernel-space and can't be baselined.
                if info.get("ppid") == 2:
                    continue
                if not info.get("exe") and not (info.get("cmdline") or []):
                    continue
                ppid_name = parent_name(info["ppid"]) if info.get("ppid") else None
                result.append({
                    "pid": info["pid"],
                    "name": info["name"] or "",
                    "exe": info.get("exe"),
                    "cmdline": " ".join(info.get("cmdline") or []),
                    "username": info.get("username"),
                    "ppid_name": ppid_name,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return result

    def _is_reverse_shell(self, pid: int) -> bool:
        return stdio_on_one_inet_socket(pid)

    async def _alert_new_process(self, proc: dict) -> None:
        if self._is_reverse_shell(proc["pid"]):
            await self._alerts.fire(Alert(
                rule_id="reverse_shell",
                severity=Severity.CRITICAL,
                title=f"Reverse shell: {proc['name']} (pid {proc['pid']})",
                message=(
                    f"Process '{proc['name']}' (pid {proc['pid']}) has all stdio on the same socket\n"
                    f"Parent: {proc.get('ppid_name', '?')}\n"
                    f"CMD: {proc.get('cmdline', '')}"
                ),
                source_monitor=self.name,
                context=proc,
            ))
            return
        if self._is_suspicious_shell(proc):
            await self._alerts.fire(Alert(
                rule_id="suspicious_shell_spawn",
                severity=Severity.CRITICAL,
                title=f"Suspicious shell spawned by {proc.get('ppid_name', '?')}",
                message=(
                    f"Shell '{proc['name']}' (pid {proc['pid']}) spawned by "
                    f"'{proc.get('ppid_name', '?')}'\n"
                    f"CMD: {proc.get('cmdline', '')}"
                ),
                source_monitor=self.name,
                context=proc,
            ))
        elif proc.get("username") in ("root", "0"):
            await self._alerts.fire(Alert(
                rule_id="new_root_process",
                severity=Severity.CRITICAL,
                title=f"New root process: {proc['name']}" + (f" [{proc['container']}]" if proc.get("container") else ""),
                message=(
                    f"New root process: {proc['name']} (pid {proc['pid']})\n"
                    f"Not in baseline. Parent: {proc.get('ppid_name', '?')}\n"
                    f"CMD: {proc.get('cmdline', '')}"
                ),
                source_monitor=self.name,
                context=proc,
            ))
        else:
            await self._alerts.fire(Alert(
                rule_id="new_process",
                severity=Severity.INFO,
                title=f"New process: {proc['name']}",
                message=(
                    f"New process: {proc['name']} "
                    f"(pid {proc['pid']}, user {proc.get('username', '?')})\n"
                    f"CMD: {proc.get('cmdline', '')}"
                ),
                source_monitor=self.name,
                context=proc,
            ))

    def _is_suspicious_shell(self, proc: dict) -> bool:
        return (
            proc["name"] in self._config.shell_names
            and proc.get("ppid_name") in self._config.suspicious_parent_names
        )
