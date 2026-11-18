from __future__ import annotations

import asyncio
import glob
import os
import pwd
from pathlib import Path
from typing import TYPE_CHECKING

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import PersistenceMonitorConfig


class PersistenceMonitor(BaseMonitor):
    name = "PersistenceMonitor"

    def __init__(self, config: PersistenceMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        self._known_cron: dict[str, float] = {}
        self._known_units: dict[str, float] = {}

    async def run(self) -> None:
        await self._seed()
        while self._running:
            try:
                await self._scan_cron()
                await self._scan_systemd()
            except Exception:
                self._logger.exception("Error in persistence scan cycle")
            await asyncio.sleep(30)

    async def mark_expected(self, alert) -> str:
        return ("👍 Acknowledged. The change is now part of cop's snapshot (re-read from disk at "
                "every start), so it alerts again only if the file changes again. To ignore a "
                "unit for good, add it to monitors.persistence.known_units.")

    async def learn(self) -> None:
        await self._seed()
        self._logger.info(
            "PersistenceMonitor seeded: %d cron files, %d systemd units",
            len(self._known_cron),
            len(self._known_units),
        )

    async def _seed(self) -> None:
        loop = asyncio.get_event_loop()
        self._known_cron = await loop.run_in_executor(
            None, self._scan_paths, self._config.cron_paths
        )
        self._known_units = await loop.run_in_executor(
            None, self._scan_paths, self._config.systemd_paths, True
        )

    def _scan_paths(self, paths: list[str], dropins: bool = False) -> dict[str, float]:
        """mtime per file in paths (globs allowed). With dropins, also the files
        in each *.d/ directory (systemd drop-ins: override.conf etc.)."""
        result: dict[str, float] = {}
        expanded: list[str] = []
        for path_str in paths:
            expanded.extend(sorted(glob.glob(path_str)) if any(c in path_str for c in "*?[") else [path_str])
        for path_str in expanded:
            p = Path(path_str)
            if not p.exists():
                continue
            if p.is_file():
                try:
                    result[str(p)] = p.stat().st_mtime
                except OSError:
                    pass
            elif p.is_dir():
                try:
                    for entry in os.scandir(p):
                        if entry.is_file(follow_symlinks=False):
                            result[entry.path] = entry.stat().st_mtime
                        elif dropins and entry.name.endswith(".d") and entry.is_dir(follow_symlinks=False):
                            for sub in os.scandir(entry.path):
                                if sub.is_file(follow_symlinks=False):
                                    result[sub.path] = sub.stat().st_mtime
                except PermissionError:
                    self._logger.warning("Permission denied scanning %s", p)
        return result

    async def _scan_cron(self) -> None:
        loop = asyncio.get_event_loop()
        current = await loop.run_in_executor(
            None, self._scan_paths, self._config.cron_paths
        )
        for path, mtime in current.items():
            if path not in self._known_cron:
                self._known_cron[path] = mtime
                owner = self._file_owner(path)
                await self._alerts.fire(Alert(
                    rule_id="new_cron_job",
                    severity=Severity.CRITICAL,
                    title=f"New cron file: {Path(path).name}",
                    message=f"New cron file detected: {path}\nOwner: {owner}",
                    source_monitor=self.name,
                    context={"path": path, "owner": owner},
                ))
            elif mtime != self._known_cron[path]:
                self._known_cron[path] = mtime
                owner = self._file_owner(path)
                await self._alerts.fire(Alert(
                    rule_id="cron_job_modified",
                    severity=Severity.WARN,
                    title=f"Cron file modified: {Path(path).name}",
                    message=f"Cron file modified: {path}\nOwner: {owner}",
                    source_monitor=self.name,
                    context={"path": path, "owner": owner},
                ))

    async def _scan_systemd(self) -> None:
        loop = asyncio.get_event_loop()
        current = await loop.run_in_executor(
            None, self._scan_paths, self._config.systemd_paths, True
        )
        for path, mtime in current.items():
            p = Path(path)
            dropin = p.parent.name.endswith(".d")
            if dropin:
                # /etc/systemd/system/foo.service.d/override.conf -> foo.service
                unit = p.parent.name[:-2]
                if not p.name.endswith(".conf"):
                    continue
            else:
                unit = p.name
                if not unit.endswith((".service", ".timer", ".socket", ".path")):
                    continue
            prev = self._known_units.get(path)
            self._known_units[path] = mtime
            if prev == mtime:
                continue
            if unit in self._config.known_units:
                continue
            owner = self._file_owner(path)
            ctx = {"path": path, "name": unit, "owner": owner}
            if prev is None and dropin:
                await self._alerts.fire(Alert(
                    rule_id="new_systemd_dropin",
                    severity=Severity.CRITICAL,
                    title=f"New systemd drop-in: {unit}/{p.name}",
                    message=f"New drop-in for {unit} (can change what it runs or as whom): {path}\nOwner: {owner}",
                    source_monitor=self.name,
                    context=ctx,
                ))
            elif prev is None:
                await self._alerts.fire(Alert(
                    rule_id="new_systemd_unit",
                    severity=Severity.CRITICAL,
                    title=f"New systemd unit: {unit}",
                    message=f"New systemd unit detected: {path}\nOwner: {owner}",
                    source_monitor=self.name,
                    context=ctx,
                ))
            else:
                await self._alerts.fire(Alert(
                    rule_id="systemd_unit_modified",
                    severity=Severity.WARN,
                    title=f"systemd {'drop-in' if dropin else 'unit'} modified: {unit}" + (f"/{p.name}" if dropin else ""),
                    message=f"Modified: {path}\nOwner: {owner}",
                    source_monitor=self.name,
                    context=ctx,
                ))

    def _file_owner(self, path: str) -> str:
        try:
            uid = os.stat(path).st_uid
            return pwd.getpwuid(uid).pw_name
        except (OSError, KeyError):
            return "unknown"
