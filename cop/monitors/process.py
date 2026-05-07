from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

import psutil

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.alerts import AlertEngine
    from cop.baseline import BaselineDB
    from cop.config import ProcessMonitorConfig


class ProcessMonitor(BaseMonitor):
    name = "ProcessMonitor"

    def __init__(
        self,
        config: ProcessMonitorConfig,
        baseline: BaselineDB,
        alert_engine: AlertEngine,
        poll_interval: int = 30,
    ):
        super().__init__(config, baseline, alert_engine)
        self._poll_interval = poll_interval
        self._known: set[tuple] = set()

    def _is_known(self, proc: dict) -> bool:
        # Check exact key first, then fall back to name+user in case exe is
        # inconsistently readable for short-lived processes.
        exact = (proc["name"], proc.get("exe"), proc.get("username"))
        fuzzy = (proc["name"], None, proc.get("username"))
        return exact in self._known or fuzzy in self._known

    async def run(self) -> None:
        # Prime cpu_percent tracking — first call per process always returns 0.0
        for proc in psutil.process_iter(["pid"]):
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        baseline = await self._baseline.get_process_baseline()
        for p in baseline:
            self._known.add((p["name"], p.get("exe"), p.get("username")))

        while self._running:
            try:
                for proc in self._snapshot_processes():
                    if not self._is_known(proc):
                        if proc["name"] not in self._config.ignored_process_names:
                            await self._alert_new_process(proc)
                        self._known.add((proc["name"], proc.get("exe"), proc.get("username")))
            except Exception:
                self._logger.exception("Error in process scan cycle")
            await asyncio.sleep(self._poll_interval)

    async def learn(self) -> None:
        procs = self._snapshot_processes()
        await self._baseline.set_process_baseline(procs)
        self._logger.info("Learned %d processes into baseline", len(procs))

    async def learn_one(self, context: dict) -> None:
        await self._baseline.add_process_to_baseline(context)
        # Add both exact and fuzzy keys so the current session suppresses re-alerts
        # even if exe readability is inconsistent for short-lived processes.
        self._known.add((context["name"], context.get("exe"), context.get("username")))
        self._known.add((context["name"], None, context.get("username")))

    def _snapshot_processes(self) -> list[dict]:
        result = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "ppid"]):
            try:
                info = proc.info
                # Skip kernel threads: direct children of kthreadd (ppid=2) OR any thread
                # with no exe and no cmdline — kworker threads spawned by intermediate kernel
                # threads have a ppid != 2 but are still kernel-space and can't be baselined.
                if info.get("ppid") == 2:
                    continue
                if not info.get("exe") and not (info.get("cmdline") or []):
                    continue
                ppid_name = None
                if info.get("ppid"):
                    try:
                        ppid_name = psutil.Process(info["ppid"]).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
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
        try:
            fds = [os.readlink(f"/proc/{pid}/fd/{i}") for i in (0, 1, 2)]
            return all(f.startswith("socket:") for f in fds) and len(set(fds)) == 1
        except OSError:
            return False

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
                title=f"New root process: {proc['name']}",
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
