from __future__ import annotations

import asyncio
import os
import re
from typing import TYPE_CHECKING, AsyncIterator

import aiofiles

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import PackageMonitorConfig

_DPKG_INSTALL_RE = re.compile(
    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} install (\S+) <none> (\S+)"
)
_DPKG_UPGRADE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} upgrade (\S+) (\S+) (\S+)"
)
_DPKG_REMOVE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} remove (\S+) (\S+) <none>"
)


class PackageMonitor(BaseMonitor):
    name = "PackageMonitor"

    def __init__(self, config: PackageMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        self._known_packages: set[str] = set()

    async def run(self) -> None:
        await self._seed()
        while self._running:
            try:
                async for line in self._tail_file(self._config.log_path):
                    if not self._running:
                        return
                    await self._handle_line(line)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._logger.exception("PackageMonitor error — restarting tail in 5s")
                await asyncio.sleep(5)

    async def learn(self) -> None:
        await self._seed()
        self._logger.info("PackageMonitor: seeded %d known packages", len(self._known_packages))

    async def _seed(self) -> None:
        if not os.path.exists(self._config.log_path):
            self._logger.warning("dpkg.log not found at %s", self._config.log_path)
            return
        try:
            async with aiofiles.open(self._config.log_path, "r", errors="replace") as f:
                async for line in f:
                    m = _DPKG_INSTALL_RE.search(line)
                    if m:
                        self._known_packages.add(m.group(1).split(":")[0])
        except PermissionError:
            self._logger.warning("Permission denied reading %s", self._config.log_path)

    async def _tail_file(self, path: str) -> AsyncIterator[str]:
        while not os.path.exists(path):
            self._logger.warning("%s not found — waiting", path)
            await asyncio.sleep(5)
            if not self._running:
                return
        try:
            async with aiofiles.open(path, "r", errors="replace") as f:
                await f.seek(0, 2)
                current_inode = os.stat(path).st_ino
                while self._running:
                    line = await f.readline()
                    if line:
                        yield line
                    else:
                        try:
                            if os.stat(path).st_ino != current_inode:
                                self._logger.info("dpkg.log rotated, reopening")
                                return
                        except FileNotFoundError:
                            return
                        await asyncio.sleep(0.5)
        except PermissionError:
            self._logger.error("Permission denied: %s — package monitor disabled", path)

    async def _handle_line(self, line: str) -> None:
        m = _DPKG_INSTALL_RE.search(line)
        if m:
            pkg = m.group(1).split(":")[0]
            version = m.group(2)
            if pkg in self._config.ignored_packages:
                return
            self._known_packages.add(pkg)
            if self._config.alert_on_install:
                await self._alerts.fire(Alert(
                    rule_id="package_installed",
                    severity=Severity.WARN,
                    title=f"Package installed: {pkg}",
                    message=f"Package '{pkg}' ({version}) installed",
                    source_monitor=self.name,
                    context={"package": pkg, "version": version},
                ))
            return
        m = _DPKG_UPGRADE_RE.search(line)
        if m:
            pkg = m.group(1).split(":")[0]
            old_ver, new_ver = m.group(2), m.group(3)
            if pkg in self._config.ignored_packages:
                return
            await self._alerts.fire(Alert(
                rule_id="package_upgraded",
                severity=Severity.INFO,
                title=f"Package upgraded: {pkg}",
                message=f"Package '{pkg}' upgraded {old_ver} → {new_ver}",
                source_monitor=self.name,
                context={"package": pkg, "old_version": old_ver, "new_version": new_ver},
            ))
            return
        m = _DPKG_REMOVE_RE.search(line)
        if m:
            pkg = m.group(1).split(":")[0]
            if pkg in self._config.ignored_packages:
                return
            if self._config.alert_on_remove:
                await self._alerts.fire(Alert(
                    rule_id="package_removed",
                    severity=Severity.WARN,
                    title=f"Package removed: {pkg}",
                    message=f"Package '{pkg}' was removed",
                    source_monitor=self.name,
                    context={"package": pkg},
                ))
