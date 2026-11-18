from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import KernelMonitorConfig

_PROC_MODULES = "/proc/modules"


def read_loaded_modules(path: str = _PROC_MODULES) -> set[str]:
    """Names of currently loaded kernel modules (first field of /proc/modules)."""
    with open(path) as f:
        return {line.split(" ", 1)[0] for line in f if line.strip()}


class KernelMonitor(BaseMonitor):
    """Alerts on kernel modules loaded after cop started.

    Polls /proc/modules. (It used to tail kern.log for "module loaded", but only
    a few drivers print that, e.g. loop, so it missed almost every load.)
    """

    name = "KernelMonitor"

    def __init__(self, config: KernelMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        self._known_modules: set[str] = set(config.known_modules)

    async def run(self) -> None:
        self._known_modules.update(read_loaded_modules())
        self._known_modules |= await self._approved("kernel_module")
        while self._running:
            try:
                await self._check()
            except Exception:
                self._logger.exception("Error in kernel module scan")
            await asyncio.sleep(self._config.poll_interval_seconds)

    async def learn(self) -> None:
        self._logger.info("KernelMonitor seeds from /proc/modules at startup — no baseline to learn")

    async def mark_expected(self, alert) -> str:
        module = alert.context.get("module")
        if not module:
            return await super().mark_expected(alert)
        await self._baseline.add_approval("kernel_module", module)
        self._known_modules.add(module)
        return f"✅ Module {module} approved; it won't alert again, even after a reboot."

    async def _check(self, path: str = _PROC_MODULES) -> None:
        for module in sorted(read_loaded_modules(path) - self._known_modules):
            self._known_modules.add(module)
            await self._alerts.fire(Alert(
                rule_id="kernel_module_loaded",
                severity=Severity.CRITICAL,
                title=f"Unknown kernel module loaded: {module}",
                message=f"Kernel module '{module}' was loaded and is not in known modules list",
                source_monitor=self.name,
                context={"module": module},
            ))
