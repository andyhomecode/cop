from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import TYPE_CHECKING

import psutil

_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_LOOPBACK6 = ipaddress.ip_network("::1/128")


def _is_alertable_addr(addr: str) -> bool:
    """Only alert on ports bound to public-facing or well-known addresses.

    Skips Tailscale, LAN, and other non-canonical binds that are expected to
    appear/disappear without being security-relevant.
    """
    if addr in ("0.0.0.0", "::", ""):
        return True
    try:
        ip = ipaddress.ip_address(addr)
        if ip in _LOOPBACK or ip in _LOOPBACK6:
            return True
    except ValueError:
        pass
    return False

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.alerts import AlertEngine
    from cop.baseline import BaselineDB
    from cop.config import NetworkMonitorConfig


class NetworkMonitor(BaseMonitor):
    name = "NetworkMonitor"

    def __init__(
        self,
        config: NetworkMonitorConfig,
        baseline: BaselineDB,
        alert_engine: AlertEngine,
        poll_interval: int = 30,
    ):
        super().__init__(config, baseline, alert_engine)
        self._poll_interval = poll_interval
        self._prev_net_bytes: dict | None = None
        self._prev_net_time: float | None = None
        self._alerted_outbound: set[tuple] = set()

    async def run(self) -> None:
        port_baseline = await self._baseline.get_port_baseline()
        known_ports: set[tuple] = {(p["proto"], p["local_port"]) for p in port_baseline}

        while self._running:
            try:
                for port in self._get_listening_ports():
                    if not _is_alertable_addr(port["local_addr"]):
                        continue
                    key = (port["proto"], port["local_port"])
                    if key not in known_ports:
                        await self._alerts.fire(Alert(
                            rule_id="new_listen_port",
                            severity=Severity.CRITICAL,
                            title=f"New listening port: {port['local_port']}/{port['proto']}",
                            message=(
                                f"New port {port['local_port']}/{port['proto']} "
                                f"on {port['local_addr']}\n"
                                f"Process: {port.get('process_name', '?')} "
                                f"(pid {port.get('pid', '?')}, "
                                f"user {port.get('username', '?')})"
                            ),
                            source_monitor=self.name,
                            context=port,
                        ))
                        known_ports.add(key)

                await self._check_data_volume()
                await self._check_suspicious_outbound()
            except Exception:
                self._logger.exception("Error in network scan cycle")
            await self._sleep_sampling(self._poll_interval)

    async def learn(self) -> None:
        ports = self._get_listening_ports()
        alertable = [p for p in ports if _is_alertable_addr(p["local_addr"])]
        await self._baseline.set_port_baseline(alertable)
        self._logger.info("Learned %d listening ports into baseline", len(alertable))

    async def learn_one(self, context: dict) -> None:
        await self._baseline.add_port_to_baseline(context)

    def _get_listening_ports(self) -> list[dict]:
        result = []
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self._logger.warning("Access denied reading net connections — need root")
            return result
        for conn in conns:
            if conn.status != psutil.CONN_LISTEN:
                continue
            process_name = None
            process_user = None
            if conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    process_name = p.name()
                    process_user = p.username()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            result.append({
                "proto": "tcp",
                "local_addr": conn.laddr.ip if conn.laddr else "",
                "local_port": conn.laddr.port if conn.laddr else 0,
                "pid": conn.pid,
                "process_name": process_name,
                "username": process_user,
            })
        return result

    async def _check_suspicious_outbound(self) -> None:
        port_set = set(getattr(self._config, "suspicious_outbound_ports", []))
        if not port_set:
            return
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return
        for conn in conns:
            if conn.status != psutil.CONN_ESTABLISHED:
                continue
            if not conn.raddr:
                continue
            if conn.raddr.port not in port_set:
                continue
            process_name = None
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            trusted_names = getattr(self._config, "trusted_outbound_process_names", [])
            if process_name in trusted_names:
                continue
            key = (conn.pid, conn.raddr.ip, conn.raddr.port)
            if key in self._alerted_outbound:
                continue
            self._alerted_outbound.add(key)
            await self._alerts.fire(Alert(
                rule_id="suspicious_outbound_port",
                severity=Severity.CRITICAL,
                title=f"Suspicious outbound: {process_name or '?'} → :{conn.raddr.port}",
                message=(
                    f"Process '{process_name or '?'}' (pid {conn.pid}) connected to "
                    f"{conn.raddr.ip}:{conn.raddr.port}"
                ),
                source_monitor=self.name,
                context={
                    "pid": conn.pid,
                    "process_name": process_name,
                    "raddr": conn.raddr.ip,
                    "rport": conn.raddr.port,
                },
            ))

    def _is_trusted_addr(self, addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
            for cidr in self._config.trusted_cidrs:
                try:
                    if ip in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    pass
        except ValueError:
            pass
        return False

    async def _check_data_volume(self) -> None:
        counters = psutil.net_io_counters()
        now = time.monotonic()
        if self._prev_net_bytes and self._prev_net_time:
            elapsed = now - self._prev_net_time
            if elapsed > 0:
                sent_mb = (counters.bytes_sent - self._prev_net_bytes["sent"]) / 1_000_000
                recv_mb = (counters.bytes_recv - self._prev_net_bytes["recv"]) / 1_000_000
                sent_rate = sent_mb / elapsed * 60
                recv_rate = recv_mb / elapsed * 60
                threshold = self._config.data_volume_threshold_mb

                over_send = sent_rate > threshold
                over_recv = recv_rate > threshold
                if over_send or over_recv:
                    conns = self._get_connections()
                    remote_ips = list({c["raddr"] for c in conns})
                    if over_send:
                        conn_str = await self._format_connections(
                            conns,
                            total_sent_bytes=int(sent_mb * 1_000_000),
                        )
                        await self._alerts.fire(Alert(
                            rule_id="data_volume_anomaly",
                            severity=Severity.WARN,
                            title=f"High outbound data: {sent_mb:.1f} MB in {elapsed:.0f}s",
                            message=(
                                f"System sent {sent_mb:.1f} MB in {elapsed:.0f}s "
                                f"({sent_rate:.1f} MB/min, threshold: {threshold} MB/min)"
                                + (f"\n{conn_str}" if conn_str else "")
                            ),
                            source_monitor=self.name,
                            context={"sent_mb": sent_mb, "elapsed_s": elapsed, "remote_ips": remote_ips},
                        ))
                    if over_recv:
                        conn_str = await self._format_connections(
                            conns,
                            total_recv_bytes=int(recv_mb * 1_000_000),
                        )
                        await self._alerts.fire(Alert(
                            rule_id="data_volume_anomaly_recv",
                            severity=Severity.WARN,
                            title=f"High inbound data: {recv_mb:.1f} MB in {elapsed:.0f}s",
                            message=(
                                f"System received {recv_mb:.1f} MB in {elapsed:.0f}s "
                                f"({recv_rate:.1f} MB/min, threshold: {threshold} MB/min)"
                                + (f"\n{conn_str}" if conn_str else "")
                            ),
                            source_monitor=self.name,
                            context={"recv_mb": recv_mb, "elapsed_s": elapsed, "remote_ips": remote_ips},
                        ))
        self._snapshot_connections()
        self._prev_net_bytes = {
            "sent": counters.bytes_sent,
            "recv": counters.bytes_recv,
        }
        self._prev_net_time = now

