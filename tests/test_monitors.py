from __future__ import annotations

import asyncio
import time
from collections import deque
from unittest.mock import AsyncMock, MagicMock, patch

import psutil
import pytest

from cop.alerts import Severity
from cop.config import (
    NetworkMonitorConfig,
    ProcessMonitorConfig,
    ResourceMonitorConfig,
    TripwireMonitorConfig,
)
from cop.monitors.network import NetworkMonitor
from cop.monitors.process import ProcessMonitor
from cop.monitors.resource import ResourceMonitor
from cop.monitors.tripwire import TripwireMonitor


@pytest.fixture
def mock_baseline():
    b = AsyncMock()
    b.get_process_baseline = AsyncMock(return_value=[])
    b.get_port_baseline = AsyncMock(return_value=[])
    return b


@pytest.fixture
def mock_engine():
    e = AsyncMock()
    e.fire = AsyncMock(return_value=True)
    return e


class TestProcessMonitor:
    def test_snapshot_returns_list_of_dicts(self, mock_baseline, mock_engine):
        monitor = ProcessMonitor(ProcessMonitorConfig(), mock_baseline, mock_engine)
        procs = monitor._snapshot_processes()
        assert isinstance(procs, list)
        if procs:
            p = procs[0]
            assert "name" in p
            assert "pid" in p
            assert "username" in p

    def test_suspicious_shell_detected(self, mock_baseline, mock_engine):
        config = ProcessMonitorConfig(
            suspicious_parent_names=["caddy"],
            shell_names=["bash"],
        )
        monitor = ProcessMonitor(config, mock_baseline, mock_engine)
        proc = {"name": "bash", "ppid_name": "caddy", "pid": 999, "username": "www-data"}
        assert monitor._is_suspicious_shell(proc) is True

    def test_normal_shell_not_suspicious(self, mock_baseline, mock_engine):
        config = ProcessMonitorConfig(
            suspicious_parent_names=["caddy"],
            shell_names=["bash"],
        )
        monitor = ProcessMonitor(config, mock_baseline, mock_engine)
        proc = {"name": "bash", "ppid_name": "sshd", "pid": 999, "username": "user"}
        assert monitor._is_suspicious_shell(proc) is False

    def test_non_shell_not_suspicious(self, mock_baseline, mock_engine):
        config = ProcessMonitorConfig(
            suspicious_parent_names=["caddy"],
            shell_names=["bash"],
        )
        monitor = ProcessMonitor(config, mock_baseline, mock_engine)
        proc = {"name": "python3", "ppid_name": "caddy", "pid": 999, "username": "root"}
        assert monitor._is_suspicious_shell(proc) is False

    @pytest.mark.asyncio
    async def test_new_root_process_fires_critical(self, mock_baseline, mock_engine):
        monitor = ProcessMonitor(ProcessMonitorConfig(), mock_baseline, mock_engine)
        proc = {
            "name": "malware",
            "pid": 9999,
            "username": "root",
            "exe": "/tmp/malware",
            "cmdline": "/tmp/malware",
            "ppid_name": "bash",
        }
        await monitor._alert_new_process(proc)
        mock_engine.fire.assert_called_once()
        alert = mock_engine.fire.call_args[0][0]
        assert alert.rule_id == "new_root_process"
        from cop.alerts import Severity
        assert alert.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_new_nonroot_process_fires_info(self, mock_baseline, mock_engine):
        monitor = ProcessMonitor(ProcessMonitorConfig(), mock_baseline, mock_engine)
        proc = {
            "name": "myapp",
            "pid": 1234,
            "username": "user",
            "exe": "/usr/bin/myapp",
            "cmdline": "myapp --start",
            "ppid_name": "systemd",
        }
        await monitor._alert_new_process(proc)
        alert = mock_engine.fire.call_args[0][0]
        assert alert.rule_id == "new_process"
        from cop.alerts import Severity
        assert alert.severity == Severity.INFO


class TestNetworkMonitor:
    def test_loopback_is_trusted(self, mock_baseline, mock_engine):
        config = NetworkMonitorConfig(trusted_cidrs=["127.0.0.0/8", "::1/128", "100.64.0.0/10"])
        monitor = NetworkMonitor(config, mock_baseline, mock_engine)
        assert monitor._is_trusted_addr("127.0.0.1") is True
        assert monitor._is_trusted_addr("127.0.0.50") is True
        assert monitor._is_trusted_addr("::1") is True

    def test_tailscale_is_trusted(self, mock_baseline, mock_engine):
        config = NetworkMonitorConfig(trusted_cidrs=["100.64.0.0/10"])
        monitor = NetworkMonitor(config, mock_baseline, mock_engine)
        assert monitor._is_trusted_addr("100.75.2.112") is True

    def test_external_ip_not_trusted(self, mock_baseline, mock_engine):
        config = NetworkMonitorConfig(trusted_cidrs=["127.0.0.0/8"])
        monitor = NetworkMonitor(config, mock_baseline, mock_engine)
        assert monitor._is_trusted_addr("8.8.8.8") is False
        assert monitor._is_trusted_addr("1.1.1.1") is False

    def test_get_listening_ports_returns_list(self, mock_baseline, mock_engine):
        monitor = NetworkMonitor(NetworkMonitorConfig(), mock_baseline, mock_engine)
        ports = monitor._get_listening_ports()
        assert isinstance(ports, list)
        # Expect at least SSH to be running
        port_nums = {p["local_port"] for p in ports}
        assert 22 in port_nums

    def test_get_listening_ports_includes_username(self, mock_baseline, mock_engine):
        monitor = NetworkMonitor(NetworkMonitorConfig(), mock_baseline, mock_engine)

        mock_conn = MagicMock()
        mock_conn.status = psutil.CONN_LISTEN
        mock_conn.pid = 1234
        mock_conn.laddr = MagicMock(ip="0.0.0.0", port=8080)

        mock_proc = MagicMock()
        mock_proc.name.return_value = "myapp"
        mock_proc.username.return_value = "deploy"

        with patch("cop.monitors.network.psutil.net_connections", return_value=[mock_conn]), \
             patch("cop.monitors.network.psutil.Process", return_value=mock_proc):
            ports = monitor._get_listening_ports()

        assert len(ports) == 1
        assert ports[0]["process_name"] == "myapp"
        assert ports[0]["username"] == "deploy"

    @pytest.mark.asyncio
    async def test_new_listen_port_always_critical(self, mock_baseline, mock_engine):
        monitor = NetworkMonitor(NetworkMonitorConfig(), mock_baseline, mock_engine)

        fake_port = {
            "proto": "tcp", "local_addr": "0.0.0.0", "local_port": 8080,
            "pid": 1234, "process_name": "myapp", "username": "deploy",
        }

        async def stop_loop(*args, **kwargs):
            monitor._running = False

        monitor._running = True
        with patch.object(monitor, "_get_listening_ports", return_value=[fake_port]), \
             patch.object(monitor, "_check_data_volume", side_effect=stop_loop), \
             patch("cop.monitors.network.asyncio.sleep", new_callable=AsyncMock):
            await monitor.run()

        mock_engine.fire.assert_called_once()
        alert = mock_engine.fire.call_args[0][0]
        assert alert.rule_id == "new_listen_port"
        assert alert.severity == Severity.CRITICAL


class TestBaseMonitorConnections:
    """Tests for connection tracking and formatting in BaseMonitor."""

    @pytest.mark.asyncio
    async def test_format_connections_groups_by_process(self, mock_baseline, mock_engine):
        monitor = NetworkMonitor(NetworkMonitorConfig(), mock_baseline, mock_engine)
        conns = [
            {"laddr": "1.2.3.4", "lport": 50001, "raddr": "8.8.8.8", "rport": 443,
             "bytes_sent": 1_000_000, "bytes_received": 500, "process_name": "curl", "pid": 100},
            {"laddr": "1.2.3.4", "lport": 50002, "raddr": "8.8.8.9", "rport": 443,
             "bytes_sent": 2_000_000, "bytes_received": 500, "process_name": "curl", "pid": 100},
            {"laddr": "1.2.3.4", "lport": 50003, "raddr": "9.9.9.9", "rport": 80,
             "bytes_sent": 100, "bytes_received": 200, "process_name": "wget", "pid": 200},
        ]
        with patch.object(monitor, "_enrich_ip", return_value=""):
            result = await monitor._format_connections(conns)
        assert "curl/100" in result
        assert "wget/200" in result
        # curl's two connections should be aggregated
        assert "3.0 MB" in result or "↑3.0 MB" in result or "3,000" in result or "↑2.9 MB" in result

    @pytest.mark.asyncio
    async def test_estimated_bytes_sort_closed_above_small_active(self, mock_baseline, mock_engine):
        """Closed connections should rank above tiny ESTAB connections when total bytes are provided."""
        monitor = NetworkMonitor(NetworkMonitorConfig(), mock_baseline, mock_engine)
        conns = [
            # Small ESTAB connection (sshd) - has measured bytes
            {"laddr": "1.2.3.4", "lport": 22, "raddr": "192.168.1.1", "rport": 54321,
             "bytes_sent": 20_000, "bytes_received": 12_000, "process_name": "sshd", "pid": 1001},
            # Closed connection (speedtest) - 0 measured bytes
            {"laddr": "1.2.3.4", "lport": 50000, "raddr": "34.117.59.81", "rport": 443,
             "bytes_sent": 0, "bytes_received": 0, "closed": True},
        ]
        # System sent 165 MB total; 20 KB is attributed → 165 MB estimated for closed group
        with patch.object(monitor, "_enrich_ip", return_value=""):
            result = await monitor._format_connections(
                conns, total_sent_bytes=165_000_000,
            )
        lines = result.splitlines()
        # First data line should be the unknown (estimated ~165 MB), not sshd
        assert "unknown" in lines[1]
        assert "~" in lines[1]
        assert "sshd" in lines[2]

    @pytest.mark.asyncio
    async def test_multiple_destination_ips_enriched(self, mock_baseline, mock_engine):
        """All destination IPs for a process group should be enriched, not just the first."""
        monitor = NetworkMonitor(NetworkMonitorConfig(), mock_baseline, mock_engine)
        conns = [
            {"laddr": "1.2.3.4", "lport": 50001, "raddr": "8.8.8.8", "rport": 443,
             "bytes_sent": 1_000, "bytes_received": 0, "process_name": "curl", "pid": 100},
            {"laddr": "1.2.3.4", "lport": 50002, "raddr": "8.8.4.4", "rport": 443,
             "bytes_sent": 1_000, "bytes_received": 0, "process_name": "curl", "pid": 100},
        ]
        enriched = {}
        async def fake_enrich(ip):
            enriched[ip] = True
            return f"org-{ip}"
        with patch.object(monitor, "_enrich_ip", side_effect=fake_enrich):
            result = await monitor._format_connections(conns)
        # Both IPs should have been enriched
        assert "8.8.8.8" in enriched
        assert "8.8.4.4" in enriched
        assert "8.8.8.8" in result
        assert "8.8.4.4" in result

    @pytest.mark.asyncio
    async def test_closed_connections_attributed_via_cache(self, mock_baseline, mock_engine):
        monitor = NetworkMonitor(NetworkMonitorConfig(), mock_baseline, mock_engine)
        key = ("1.2.3.4", 50001, "5.6.7.8", 443)
        monitor._conn_proc_cache[key] = {"process_name": "speedtest-cli", "pid": 9999}
        conns = [
            {"laddr": "1.2.3.4", "lport": 50001, "raddr": "5.6.7.8", "rport": 443,
             "bytes_sent": 0, "bytes_received": 0, "closed": True,
             "process_name": "speedtest-cli", "pid": 9999},
        ]
        with patch.object(monitor, "_enrich_ip", return_value="AT&T"):
            result = await monitor._format_connections(conns)
        assert "speedtest-cli/9999" in result
        assert "closed" in result

    def test_snapshot_populates_proc_cache(self, mock_baseline, mock_engine):
        monitor = NetworkMonitor(NetworkMonitorConfig(), mock_baseline, mock_engine)
        fake_ss = (
            "State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n"
            'ESTAB  0       0       1.2.3.4:50001       5.6.7.8:443        users:(("curl",pid=100,fd=5))\n'
            "         cubic bytes_sent:1000 bytes_received:500\n"
        )
        with patch("cop.monitors.base.subprocess.check_output", return_value=fake_ss):
            monitor._snapshot_connections()
        key = ("1.2.3.4", 50001, "5.6.7.8", 443)
        assert key in monitor._conn_proc_cache
        assert monitor._conn_proc_cache[key]["process_name"] == "curl"
        assert monitor._conn_proc_cache[key]["pid"] == 100

    def test_refresh_proc_cache_captures_short_lived_connections(self, mock_baseline, mock_engine):
        monitor = NetworkMonitor(NetworkMonitorConfig(), mock_baseline, mock_engine)
        # Simulate ss -t -n -p output (no -i, so no indented continuation lines)
        fake_ss = (
            "State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n"
            'ESTAB  0       0       1.2.3.4:60000       8.8.8.8:443        users:(("speedtest-cli",pid=5555,fd=3))\n'
        )
        with patch("cop.monitors.base.subprocess.check_output", return_value=fake_ss):
            monitor._refresh_proc_cache()
        key = ("1.2.3.4", 60000, "8.8.8.8", 443)
        assert key in monitor._conn_proc_cache
        assert monitor._conn_proc_cache[key]["process_name"] == "speedtest-cli"
        assert monitor._conn_proc_cache[key]["pid"] == 5555

    # --- data volume: unexplained traffic, sustained, one alert per episode ---

    @staticmethod
    def _counters(sent: int, recv: int) -> dict:
        c = MagicMock()
        c.bytes_sent = sent
        c.bytes_recv = recv
        return {"eno2": c}

    async def _poll(self, monitor, t: float, sent: int, recv: int = 0, trusted=None):
        """One _check_data_volume call at time t with cumulative counters."""
        with patch("cop.monitors.base.psutil.net_io_counters", return_value=self._counters(sent, recv)), \
             patch("cop.monitors.network.time.monotonic", return_value=t), \
             patch.object(monitor, "_trusted_docker_stats", return_value=trusted or {}), \
             patch.object(monitor, "_trusted_unit_stats", return_value={}), \
             patch.object(monitor, "_get_connections", return_value=[]), \
             patch.object(monitor, "_format_connections", new_callable=AsyncMock, return_value=""):
            await monitor._check_data_volume()

    @staticmethod
    def _fired(engine) -> list[str]:
        return [call[0][0].rule_id for call in engine.fire.call_args_list]

    @pytest.mark.asyncio
    async def test_outbound_fires_once_after_sustained_period(self, mock_baseline, mock_engine):
        config = NetworkMonitorConfig(data_volume_threshold_mb=10.0, data_volume_sustained_seconds=90)
        monitor = NetworkMonitor(config, mock_baseline, mock_engine)
        # 60 MB per 30 s = 120 MB/min, well over 10 MB/min
        for i in range(3):
            await self._poll(monitor, 30.0 * i, sent=60_000_000 * i)
        assert self._fired(mock_engine) == []          # held 60 s < 90 s
        await self._poll(monitor, 90.0, sent=180_000_000)
        assert self._fired(mock_engine) == ["data_volume_anomaly"]
        await self._poll(monitor, 120.0, sent=240_000_000)
        assert self._fired(mock_engine) == ["data_volume_anomaly"]  # same episode: no repeat

    @pytest.mark.asyncio
    async def test_outbound_rearms_after_dropping_under(self, mock_baseline, mock_engine):
        config = NetworkMonitorConfig(data_volume_threshold_mb=10.0, data_volume_sustained_seconds=30)
        monitor = NetworkMonitor(config, mock_baseline, mock_engine)
        await self._poll(monitor, 0.0, sent=0)
        await self._poll(monitor, 30.0, sent=60_000_000)            # episode 1 fires
        await self._poll(monitor, 60.0, sent=60_000_000)            # quiet: re-arm
        await self._poll(monitor, 90.0, sent=120_000_000)           # episode 2 fires
        assert self._fired(mock_engine) == ["data_volume_anomaly", "data_volume_anomaly"]

    @pytest.mark.asyncio
    async def test_short_burst_does_not_fire(self, mock_baseline, mock_engine):
        config = NetworkMonitorConfig(data_volume_threshold_mb=10.0, data_volume_sustained_seconds=300)
        monitor = NetworkMonitor(config, mock_baseline, mock_engine)
        await self._poll(monitor, 0.0, sent=0)
        await self._poll(monitor, 30.0, sent=500_000_000)           # big 30 s burst
        await self._poll(monitor, 60.0, sent=500_000_000)
        assert self._fired(mock_engine) == []

    @pytest.mark.asyncio
    async def test_trusted_traffic_is_subtracted(self, mock_baseline, mock_engine):
        config = NetworkMonitorConfig(
            data_volume_threshold_mb=10.0, data_volume_sustained_seconds=0,
            trusted_docker_containers=["jellyfin"],
        )
        monitor = NetworkMonitor(config, mock_baseline, mock_engine)
        await self._poll(monitor, 0.0, sent=0, trusted={"jellyfin": (0, 0)})
        # 100 MB out, 98 MB of it from jellyfin -> 2 MB/30 s = 4 MB/min unexplained
        await self._poll(monitor, 30.0, sent=100_000_000, trusted={"jellyfin": (0, 98_000_000)})
        assert self._fired(mock_engine) == []
        # 100 MB more out, jellyfin only 50 MB -> 100 MB/min unexplained
        await self._poll(monitor, 60.0, sent=200_000_000, trusted={"jellyfin": (0, 148_000_000)})
        assert self._fired(mock_engine) == ["data_volume_anomaly"]

    @pytest.mark.asyncio
    async def test_shared_netns_containers_counted_once(self, mock_baseline, mock_engine):
        config = NetworkMonitorConfig(
            data_volume_threshold_mb=10.0, data_volume_sustained_seconds=0,
            trusted_docker_containers=["gluetun", "qbittorrent"],
        )
        monitor = NetworkMonitor(config, mock_baseline, mock_engine)
        zero = {"gluetun": (0, 0), "qbittorrent": (0, 0)}
        await self._poll(monitor, 0.0, sent=0, trusted=zero)
        # Both report the same 50 MB; real total is 100 MB, so 50 MB (100 MB/min)
        # is unexplained. Summing both would wrongly hide it.
        same = {"gluetun": (0, 50_000_000), "qbittorrent": (0, 50_000_000)}
        await self._poll(monitor, 30.0, sent=100_000_000, trusted=same)
        assert self._fired(mock_engine) == ["data_volume_anomaly"]

    @pytest.mark.asyncio
    async def test_inbound_ignored_unless_enabled(self, mock_baseline, mock_engine):
        quiet = NetworkMonitor(
            NetworkMonitorConfig(data_volume_threshold_mb=10.0, data_volume_sustained_seconds=0),
            mock_baseline, mock_engine,
        )
        await self._poll(quiet, 0.0, sent=0, recv=0)
        await self._poll(quiet, 30.0, sent=0, recv=200_000_000)
        assert self._fired(mock_engine) == []

        loud = NetworkMonitor(
            NetworkMonitorConfig(data_volume_threshold_mb=10.0, data_volume_sustained_seconds=0,
                                 alert_on_inbound=True),
            mock_baseline, mock_engine,
        )
        await self._poll(loud, 0.0, sent=0, recv=0)
        await self._poll(loud, 30.0, sent=0, recv=200_000_000)
        assert self._fired(mock_engine) == ["data_volume_anomaly_recv"]

    def test_unit_stats_parsed_and_no_data_skipped(self, mock_baseline, mock_engine):
        config = NetworkMonitorConfig(trusted_systemd_units=["dropbox.service", "off.service"])
        monitor = NetworkMonitor(config, mock_baseline, mock_engine)
        outputs = {
            "dropbox.service": "IPIngressBytes=1000\nIPEgressBytes=2000\n",
            "off.service": "IPIngressBytes=[no data]\nIPEgressBytes=[no data]\n",
        }
        with patch("cop.monitors.network.subprocess.check_output",
                   side_effect=lambda cmd, **kw: outputs[cmd[-1]]):
            assert monitor._trusted_unit_stats() == {"dropbox.service": (1000, 2000)}


class TestResourceMonitor:
    @pytest.mark.asyncio
    async def test_raw_network_alerts_off_by_default(self, mock_baseline, mock_engine):
        monitor = ResourceMonitor(ResourceMonitorConfig(), mock_baseline, mock_engine)
        await monitor._check_network(send_mbps=900.0, recv_mbps=900.0)
        mock_engine.fire.assert_not_called()

    @pytest.mark.asyncio
    async def test_raw_network_alerts_when_enabled(self, mock_baseline, mock_engine):
        monitor = ResourceMonitor(ResourceMonitorConfig(net_alerts_enabled=True), mock_baseline, mock_engine)
        with patch.object(monitor, "_get_connections", return_value=[]), \
             patch.object(monitor, "_format_connections", new_callable=AsyncMock, return_value=""):
            await monitor._check_network(send_mbps=900.0, recv_mbps=0.0)
        assert [c[0][0].rule_id for c in mock_engine.fire.call_args_list] == ["high_network_send"]

    @pytest.mark.asyncio
    async def test_high_cpu_alert_includes_username(self, mock_baseline, mock_engine):
        config = ResourceMonitorConfig(cpu_threshold_percent=50, cpu_sustained_seconds=60)
        monitor = ResourceMonitor(config, mock_baseline, mock_engine)

        fake_proc = MagicMock()
        fake_proc.info = {"pid": 1234, "name": "hoggerd", "username": "mallory"}
        fake_proc.cpu_percent.return_value = 90.0

        # Pin time so that cutoff = fixed_now - 60 and we can place samples precisely.
        # The oldest sample at fixed_now - 60 is NOT pruned (prune condition is strict <).
        fixed_now = 10000.0
        monitor._cpu_history[1234] = deque([
            (fixed_now - 60, 90.0),
            (fixed_now - 30, 90.0),
        ])

        with patch("cop.monitors.resource.time.monotonic", return_value=fixed_now), \
             patch("cop.monitors.resource.psutil.process_iter", return_value=[fake_proc]):
            await monitor._check_per_process_cpu()

        mock_engine.fire.assert_called_once()
        alert = mock_engine.fire.call_args[0][0]
        assert alert.rule_id == "high_cpu_sustained"
        assert "mallory" in alert.message
        assert alert.context["username"] == "mallory"


class TestTripwireMonitor:
    def test_netrc_is_never_armed_even_if_configured(self, tmp_path, mock_baseline, mock_engine):
        netrc = tmp_path / ".netrc"
        netrc.write_text("machine example.com login x password y\n")
        real = tmp_path / ".env"
        real.write_text("SECRET=1\n")

        config = TripwireMonitorConfig(
            files=[str(netrc), str(real)], create_missing=False
        )
        monitor = TripwireMonitor(config, mock_baseline, mock_engine)

        resolved = monitor._setup_files()

        assert str(netrc) not in resolved
        assert str(real) in resolved

    def test_netrc_blocked_regardless_of_directory(self, tmp_path, mock_baseline, mock_engine):
        nested = tmp_path / "home" / "someuser" / ".netrc"
        nested.parent.mkdir(parents=True)
        nested.write_text("x\n")

        config = TripwireMonitorConfig(files=[str(nested)], create_missing=True)
        monitor = TripwireMonitor(config, mock_baseline, mock_engine)

        assert monitor._setup_files() == set()
