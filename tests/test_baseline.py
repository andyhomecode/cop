from __future__ import annotations

import pytest

from cop.baseline import BaselineDB


@pytest.fixture
async def db(tmp_path):
    db = BaselineDB(tmp_path / "test.db")
    await db.open()
    yield db
    await db.close()


@pytest.mark.asyncio
async def test_process_baseline_roundtrip(db):
    procs = [
        {"name": "nginx", "exe": "/usr/sbin/nginx", "username": "www-data"},
        {"name": "sshd", "exe": "/usr/sbin/sshd", "username": "root"},
    ]
    await db.set_process_baseline(procs)
    result = await db.get_process_baseline()
    names = {r["name"] for r in result}
    assert "nginx" in names
    assert "sshd" in names


@pytest.mark.asyncio
async def test_process_baseline_deduplication(db):
    proc = {"name": "nginx", "exe": "/usr/sbin/nginx", "username": "www-data"}
    await db.set_process_baseline([proc])
    await db.add_process_to_baseline(proc)  # should not create a duplicate
    result = await db.get_process_baseline()
    assert len(result) == 1


@pytest.mark.asyncio
async def test_process_baseline_reset_on_set(db):
    await db.set_process_baseline([{"name": "old", "exe": None, "username": "root"}])
    await db.set_process_baseline([{"name": "new", "exe": None, "username": "root"}])
    result = await db.get_process_baseline()
    names = {r["name"] for r in result}
    assert "old" not in names
    assert "new" in names


@pytest.mark.asyncio
async def test_port_baseline_roundtrip(db):
    ports = [
        {"proto": "tcp", "local_addr": "0.0.0.0", "local_port": 22, "process_name": "sshd"},
        {"proto": "tcp", "local_addr": "0.0.0.0", "local_port": 80, "process_name": "caddy"},
    ]
    await db.set_port_baseline(ports)
    result = await db.get_port_baseline()
    port_nums = {r["local_port"] for r in result}
    assert 22 in port_nums
    assert 80 in port_nums


@pytest.mark.asyncio
async def test_ssh_source_add_and_retrieve(db):
    await db.add_ssh_source("1.2.3.4")
    sources = await db.get_ssh_sources()
    assert "1.2.3.4" in sources


@pytest.mark.asyncio
async def test_ssh_source_no_duplicate(db):
    await db.add_ssh_source("1.2.3.4")
    await db.add_ssh_source("1.2.3.4")
    sources = await db.get_ssh_sources()
    assert len([s for s in sources if s == "1.2.3.4"]) == 1


@pytest.mark.asyncio
async def test_resource_sample_and_stats(db):
    for i in range(5):
        await db.add_resource_sample({
            "cpu_percent": float(i * 10),
            "mem_percent": 50.0,
            "net_send_mbps": 1.0,
            "net_recv_mbps": 2.0,
        })
    stats = await db.get_resource_stats()
    assert "avg_cpu" in stats
    assert stats["avg_mem"] == pytest.approx(50.0)


@pytest.mark.asyncio
async def test_alert_history_record_and_retrieve(db):
    await db.record_alert(
        rule_id="test_rule",
        severity="WARN",
        title="Test Alert",
        message="Something happened",
        context_json="{}",
        source_monitor="TestMonitor",
        fired_at="2026-05-02T12:00:00+00:00",
        sent_ntfy=True,
        deduped=False,
    )
    alerts = await db.get_recent_alerts(limit=10)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "test_rule"
    assert alerts[0]["sent_ntfy"] == 1
    assert alerts[0]["deduped"] == 0


@pytest.mark.asyncio
async def test_alert_counts(db):
    await db.record_alert("r1", "CRITICAL", "t", "m", "{}", "M", "2026-05-02T12:00:00+00:00", False, False)
    await db.record_alert("r2", "WARN", "t", "m", "{}", "M", "2026-05-02T12:00:01+00:00", False, False)
    await db.record_alert("r3", "WARN", "t", "m", "{}", "M", "2026-05-02T12:00:02+00:00", False, True)  # deduped
    counts = await db.get_alert_counts()
    assert counts.get("CRITICAL") == 1
    assert counts.get("WARN") == 1  # deduped one not counted


@pytest.mark.asyncio
async def test_container_baseline_roundtrip(db):
    containers = [
        {"container_id": "abc123", "name": "caddy", "image": "caddy:2.8"},
        {"container_id": "def456", "name": "myapp", "image": "myorg/myapp:latest"},
    ]
    await db.set_container_baseline(containers)
    result = await db.get_container_baseline()
    names = {r["name"] for r in result}
    assert "caddy" in names
    assert "myapp" in names
