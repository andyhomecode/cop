from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import TYPE_CHECKING

import psutil

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import ResourceMonitorConfig


class ResourceMonitor(BaseMonitor):
    name = "ResourceMonitor"

    def __init__(self, config: ResourceMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        # pid -> deque of (monotonic_time, cpu_percent)
        self._cpu_history: dict[int, deque] = {}
        self._prev_net_io = None
        self._prev_net_time: float | None = None
        # Bytes transferred in the most recent measurement interval (for alert attribution)
        self._last_net_sent_bytes: int = 0
        self._last_net_recv_bytes: int = 0

    async def run(self) -> None:
        # Prime cpu_percent so second call returns real values
        psutil.cpu_percent(interval=None)
        for proc in psutil.process_iter(["pid"]):
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        while self._running:
            try:
                cpu_pct = psutil.cpu_percent(interval=None)
                mem_pct = psutil.virtual_memory().percent
                send_mbps, recv_mbps = self._calc_net_rates()

                await self._check_per_process_cpu()
                await self._check_memory(mem_pct)
                await self._check_network(send_mbps, recv_mbps)
                await self._baseline.add_resource_sample({
                    "cpu_percent": cpu_pct,
                    "mem_percent": mem_pct,
                    "net_send_mbps": send_mbps,
                    "net_recv_mbps": recv_mbps,
                })
            except Exception:
                self._logger.exception("Error in resource check cycle")
            await self._sleep_sampling(self._config.check_interval_seconds)

    async def learn(self) -> None:
        psutil.cpu_percent(interval=None)
        for _ in range(5):
            await asyncio.sleep(1)
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            send, recv = self._calc_net_rates()
            await self._baseline.add_resource_sample({
                "cpu_percent": cpu,
                "mem_percent": mem,
                "net_send_mbps": send,
                "net_recv_mbps": recv,
            })
        self._logger.info("Seeded resource baseline with 5 samples")

    async def _check_per_process_cpu(self) -> None:
        now = time.monotonic()
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                pname = proc.info["name"] or ""
                if pname in self._config.resource_whitelist:
                    continue
                pid = proc.info["pid"]
                pusername = proc.info.get("username") or "?"
                cpu = proc.cpu_percent(interval=None)
                if pid not in self._cpu_history:
                    self._cpu_history[pid] = deque()
                self._cpu_history[pid].append((now, cpu))
                # Prune samples older than the sustained window
                cutoff = now - self._config.cpu_sustained_seconds
                while self._cpu_history[pid] and self._cpu_history[pid][0][0] < cutoff:
                    self._cpu_history[pid].popleft()
                samples = self._cpu_history[pid]
                window = samples[-1][0] - samples[0][0] if len(samples) > 1 else 0
                if (
                    len(samples) >= 3
                    and window >= self._config.cpu_sustained_seconds
                    and all(s[1] >= self._config.cpu_threshold_percent for s in samples)
                ):
                    await self._alerts.fire(Alert(
                        rule_id="high_cpu_sustained",
                        severity=Severity.WARN,
                        title=f"Sustained high CPU: {pname}",
                        message=(
                            f"Process '{pname}' (pid {pid}, user {pusername}) has used "
                            f"≥{self._config.cpu_threshold_percent:.0f}% CPU "
                            f"for {window:.0f}s"
                        ),
                        source_monitor=self.name,
                        context={"pid": pid, "name": pname, "username": pusername, "cpu_percent": cpu},
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        live_pids = {p.pid for p in psutil.process_iter(["pid"])}
        self._cpu_history = {pid: v for pid, v in self._cpu_history.items() if pid in live_pids}

    async def _check_memory(self, mem_pct: float) -> None:
        if mem_pct >= self._config.memory_threshold_percent:
            await self._alerts.fire(Alert(
                rule_id="high_memory",
                severity=Severity.WARN,
                title=f"High memory usage: {mem_pct:.0f}%",
                message=(
                    f"System memory at {mem_pct:.1f}% "
                    f"(threshold: {self._config.memory_threshold_percent:.0f}%)"
                ),
                source_monitor=self.name,
                context={"mem_percent": mem_pct},
            ))

    async def _check_network(self, send_mbps: float, recv_mbps: float) -> None:
        over_send = send_mbps >= self._config.net_send_threshold_mbps
        over_recv = recv_mbps >= self._config.net_recv_threshold_mbps
        if not (over_send or over_recv):
            return

        conns = self._get_connections()
        remote_ips = list({c["raddr"] for c in conns})

        if over_send:
            conn_str = await self._format_connections(
                conns, total_sent_bytes=self._last_net_sent_bytes,
            )
            await self._alerts.fire(Alert(
                rule_id="high_network_send",
                severity=Severity.WARN,
                title=f"High outbound bandwidth: {send_mbps:.1f} Mbps",
                message=(
                    f"System sending {send_mbps:.1f} Mbps "
                    f"(threshold: {self._config.net_send_threshold_mbps:.0f} Mbps)"
                    + (f"\n{conn_str}" if conn_str else "")
                ),
                source_monitor=self.name,
                context={"send_mbps": send_mbps, "remote_ips": remote_ips},
            ))
        if over_recv:
            conn_str = await self._format_connections(
                conns, total_recv_bytes=self._last_net_recv_bytes,
            )
            await self._alerts.fire(Alert(
                rule_id="high_network_recv",
                severity=Severity.WARN,
                title=f"High inbound bandwidth: {recv_mbps:.1f} Mbps",
                message=(
                    f"System receiving {recv_mbps:.1f} Mbps "
                    f"(threshold: {self._config.net_recv_threshold_mbps:.0f} Mbps)"
                    + (f"\n{conn_str}" if conn_str else "")
                ),
                source_monitor=self.name,
                context={"recv_mbps": recv_mbps, "remote_ips": remote_ips},
            ))


    def _calc_net_rates(self) -> tuple[float, float]:
        now = time.monotonic()
        counters = psutil.net_io_counters()
        if self._prev_net_io and self._prev_net_time:
            elapsed = now - self._prev_net_time
            if elapsed > 0:
                sent_b = counters.bytes_sent - self._prev_net_io.bytes_sent
                recv_b = counters.bytes_recv - self._prev_net_io.bytes_recv
                self._last_net_sent_bytes = sent_b
                self._last_net_recv_bytes = recv_b
                send_mbps = sent_b * 8 / 1_000_000 / elapsed
                recv_mbps = recv_b * 8 / 1_000_000 / elapsed
                self._prev_net_io = counters
                self._prev_net_time = now
                self._snapshot_connections()
                return send_mbps, recv_mbps
        self._last_net_sent_bytes = 0
        self._last_net_recv_bytes = 0
        self._prev_net_io = counters
        self._prev_net_time = now
        self._snapshot_connections()
        return 0.0, 0.0
