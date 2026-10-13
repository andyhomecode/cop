from __future__ import annotations

import asyncio
import ipaddress
import re
import subprocess
import time
from typing import TYPE_CHECKING

import psutil

_DOCKER_SIZE_RE = re.compile(r"^([\d.]+)\s*([kKmMgGtT]?)[bB]$")
_DOCKER_SIZE_MULTIPLIERS = {"": 1, "k": 1_000, "m": 1_000_000, "g": 1_000_000_000, "t": 1_000_000_000_000}



def _parse_docker_size(s: str) -> int:
    m = _DOCKER_SIZE_RE.match(s.strip())
    if not m:
        return 0
    value, unit = m.groups()
    return int(float(value) * _DOCKER_SIZE_MULTIPLIERS[unit.lower()])

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
        self._prev_trusted_bytes: dict[str, tuple[int, int]] = {}
        # Per direction: when unexplained traffic went over the threshold, and
        # whether this episode has already alerted (one alert per episode).
        self._over_since: dict[str, float | None] = {"sent": None, "recv": None}
        self._episode_alerted: dict[str, bool] = {"sent": False, "recv": False}

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

    def _trusted_docker_stats(self) -> dict[str, tuple[int, int]]:
        """Cumulative (rx_bytes, tx_bytes) per trusted container name, via `docker stats`."""
        names = self._config.trusted_docker_containers
        if not names:
            return {}
        try:
            out = subprocess.check_output(
                ["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.NetIO}}"],
                text=True, stderr=subprocess.DEVNULL, timeout=10,
            )
        except Exception:
            return {}
        result: dict[str, tuple[int, int]] = {}
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) != 2 or parts[0] not in names:
                continue
            halves = [h.strip() for h in parts[1].split("/")]
            if len(halves) != 2:
                continue
            result[parts[0]] = (_parse_docker_size(halves[0]), _parse_docker_size(halves[1]))
        return result

    def _trusted_unit_stats(self) -> dict[str, tuple[int, int]]:
        """Cumulative (ingress, egress) bytes per trusted systemd unit (IPAccounting)."""
        result: dict[str, tuple[int, int]] = {}
        for unit in self._config.trusted_systemd_units:
            try:
                out = subprocess.check_output(
                    ["systemctl", "show", "-p", "IPIngressBytes", "-p", "IPEgressBytes", unit],
                    text=True, stderr=subprocess.DEVNULL, timeout=5,
                )
            except Exception:
                continue
            props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
            try:
                result[unit] = (int(props["IPIngressBytes"]), int(props["IPEgressBytes"]))
            except (KeyError, ValueError):
                # "[no data]": IPAccounting isn't enabled on the unit
                self._logger.debug("No IP accounting data for %s", unit)
        return result

    def _trusted_delta(self) -> tuple[int, int, dict[str, tuple[int, int]]]:
        """(recv_bytes, sent_bytes, per-source deltas) moved by trusted sources since the last poll.

        Containers sharing a network namespace (`network_mode: service:gluetun`)
        report identical cumulative NetIO, so sources with identical counters
        are counted once. A source whose counters went down (restarted) counts
        as zero for that poll.
        """
        current = {**self._trusted_docker_stats(), **self._trusted_unit_stats()}
        per_source: dict[str, tuple[int, int]] = {}
        seen_counters: set[tuple[int, int]] = set()
        recv = sent = 0
        for name, counters in current.items():
            prev = self._prev_trusted_bytes.get(name)
            if prev is None:
                continue
            d_recv = max(0, counters[0] - prev[0])
            d_sent = max(0, counters[1] - prev[1])
            per_source[name] = (d_recv, d_sent)
            if counters in seen_counters:
                continue
            seen_counters.add(counters)
            recv += d_recv
            sent += d_sent
        self._prev_trusted_bytes = current
        return recv, sent, per_source

    async def _fire_data_volume(
        self,
        direction: str,
        rate: float,
        held: float,
        total: int,
        trusted: int,
        unexplained: int,
        per_source: dict[str, tuple[int, int]],
    ) -> None:
        outbound = direction == "sent"
        idx = 1 if outbound else 0
        threshold = self._config.data_volume_threshold_mb
        busy = sorted(
            ((name, d[idx]) for name, d in per_source.items() if d[idx] >= 1_000_000),
            key=lambda x: -x[1],
        )
        trusted_str = ", ".join(f"{n} {b / 1_000_000:.0f} MB" for n, b in busy) or "none"
        conns = self._get_connections()
        conn_str = await self._format_connections(
            conns, **({"total_sent_bytes": unexplained} if outbound else {"total_recv_bytes": unexplained}),
        )
        noun = "outbound" if outbound else "inbound"
        await self._alerts.fire(Alert(
            rule_id="data_volume_anomaly" if outbound else "data_volume_anomaly_recv",
            severity=Severity.WARN,
            title=f"Unexplained {noun} data: {rate:.0f} MB/min for {held / 60:.0f} min",
            message=(
                f"{rate:.0f} MB/min {noun} not accounted for by trusted sources, "
                f"for {held / 60:.0f} min (threshold: {threshold:.0f} MB/min for "
                f"{self._config.data_volume_sustained_seconds / 60:.0f} min)\n"
                f"Last interval: {total / 1_000_000:.1f} MB total, "
                f"{trusted / 1_000_000:.1f} MB trusted ({trusted_str}), "
                f"{unexplained / 1_000_000:.1f} MB unexplained"
                + (f"\n{conn_str}" if conn_str else "")
            ),
            source_monitor=self.name,
            context={
                "direction": direction,
                "rate_mb_min": rate,
                "held_s": held,
                "unexplained_bytes": unexplained,
                "remote_ips": list({c["raddr"] for c in conns}),
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
        """Alert when *unexplained* traffic stays high.

        Unexplained = traffic on the external interfaces minus what trusted
        containers and systemd units moved in the same interval. It must stay
        over data_volume_threshold_mb (MB/min) for data_volume_sustained_seconds,
        and each episode alerts once; it re-arms after dropping back under.
        """
        sent_bytes, recv_bytes = self._external_net_io_counters()
        now = time.monotonic()
        # Read every poll, so the trusted counters cover the same interval.
        trusted_recv, trusted_sent, per_source = self._trusted_delta()
        if self._prev_net_bytes is not None and self._prev_net_time is not None:
            elapsed = now - self._prev_net_time
            if elapsed > 0:
                total = {
                    "sent": max(0, sent_bytes - self._prev_net_bytes["sent"]),
                    "recv": max(0, recv_bytes - self._prev_net_bytes["recv"]),
                }
                trusted = {"sent": trusted_sent, "recv": trusted_recv}
                directions = ["sent"] + (["recv"] if self._config.alert_on_inbound else [])
                for d in directions:
                    unexplained = max(0, total[d] - trusted[d])
                    rate = unexplained / 1_000_000 / elapsed * 60
                    if rate <= self._config.data_volume_threshold_mb:
                        self._over_since[d] = None
                        self._episode_alerted[d] = False
                        continue
                    if self._over_since[d] is None:
                        self._over_since[d] = now - elapsed
                    held = now - self._over_since[d]
                    if held < self._config.data_volume_sustained_seconds or self._episode_alerted[d]:
                        continue
                    self._episode_alerted[d] = True
                    await self._fire_data_volume(
                        d, rate, held, total[d], trusted[d], unexplained, per_source,
                    )
        self._snapshot_connections()
        self._prev_net_bytes = {
            "sent": sent_bytes,
            "recv": recv_bytes,
        }
        self._prev_net_time = now

