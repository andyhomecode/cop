from __future__ import annotations

import asyncio
import os
import re
import subprocess
from typing import TYPE_CHECKING, AsyncIterator

import aiofiles

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import KernelMonitorConfig

_MODULE_LOADED_RE = re.compile(r": (\S+): module loaded")


class KernelMonitor(BaseMonitor):
    name = "KernelMonitor"

    def __init__(self, config: KernelMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        self._known_modules: set[str] = set(config.known_modules)

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
                self._logger.exception("KernelMonitor error — restarting tail in 5s")
                await asyncio.sleep(5)

    async def learn(self) -> None:
        await self._seed()
        self._logger.info("KernelMonitor: seeded %d known modules", len(self._known_modules))

    async def _seed(self) -> None:
        loop = asyncio.get_event_loop()
        modules = await loop.run_in_executor(None, self._get_loaded_modules)
        self._known_modules.update(modules)

    def _get_loaded_modules(self) -> set[str]:
        try:
            result = subprocess.run(
                ["lsmod"], capture_output=True, text=True, timeout=10
            )
            modules: set[str] = set()
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if parts:
                    modules.add(parts[0])
            return modules
        except Exception:
            return set()

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
                                self._logger.info("kern.log rotated, reopening")
                                return
                        except FileNotFoundError:
                            return
                        await asyncio.sleep(0.5)
        except PermissionError:
            self._logger.error("Permission denied: %s — kernel monitor disabled", path)

    async def _handle_line(self, line: str) -> None:
        m = _MODULE_LOADED_RE.search(line)
        if not m:
            return
        module = m.group(1).rstrip(":")
        if module in self._known_modules:
            return
        self._known_modules.add(module)
        await self._alerts.fire(Alert(
            rule_id="kernel_module_loaded",
            severity=Severity.CRITICAL,
            title=f"Unknown kernel module loaded: {module}",
            message=f"Kernel module '{module}' was loaded and is not in known modules list",
            source_monitor=self.name,
            context={"module": module},
        ))
