from __future__ import annotations

import asyncio
import time
from collections import deque
from unittest.mock import AsyncMock, MagicMock, patch

import psutil
import pytest

from cop.alerts import Severity
from cop.config import NetworkMonitorConfig, ProcessMonitorConfig, ResourceMonitorConfig
from cop.monitors.network import NetworkMonitor
from cop.monitors.process import ProcessMonitor
from cop.monitors.resource import ResourceMonitor


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

    @pytest.mark.asyncio
    async def test_data_volume_anomaly_fires_for_high_inbound(self, mock_baseline, mock_engine):
        config = NetworkMonitorConfig(data_volume_threshold_mb=10.0)
        monitor = NetworkMonitor(config, mock_baseline, mock_engine)

        base_sent = 1_000_000
        base_recv = 1_000_000
        # 200 MB received in 30s → 400 MB/min, over threshold of 10 MB/min
        high_recv = base_recv + 200_000_000
        monitor._prev_net_bytes = {"sent": base_sent, "recv": base_recv}
        monitor._prev_net_time = 1.0  # non-zero so the truthiness check passes

        fake_counters = MagicMock()
        fake_counters.bytes_sent = base_sent       # no outbound traffic
        fake_counters.bytes_recv = high_recv

        with patch("cop.monitors.network.psutil.net_io_counters", return_value=fake_counters), \
             patch("cop.monitors.network.time.monotonic", return_value=31.0), \
             patch.object(monitor, "_get_connections", return_value=[]), \
             patch.object(monitor, "_format_connections", new_callable=AsyncMock, return_value=""):
            await monitor._check_data_volume()

        fired_ids = [call[0][0].rule_id for call in mock_engine.fire.call_args_list]
        assert "data_volume_anomaly_recv" in fired_ids
        assert "data_volume_anomaly" not in fired_ids


class TestResourceMonitor:
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
