from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from cop.alerts import Alert, AlertEngine, Severity
from cop.config import AlertsConfig


@pytest.fixture
def config():
    c = AlertsConfig()
    c.dedup_window_seconds = 300
    c.rule_cooldowns = {"ssh_brute_force": 60}
    return c


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.record_alert = AsyncMock()
    return db


@pytest.fixture
def mock_sink():
    sink = AsyncMock()
    sink.send = AsyncMock(return_value=True)
    sink._is_ntfy = False
    return sink


@pytest.fixture
def engine(config, mock_db, mock_sink):
    return AlertEngine(config, mock_db, [mock_sink])


def make_alert(rule_id: str = "test_rule", severity: Severity = Severity.WARN) -> Alert:
    return Alert(
        rule_id=rule_id,
        severity=severity,
        title="Test alert",
        message="Something happened",
        source_monitor="TestMonitor",
    )


@pytest.mark.asyncio
async def test_first_alert_fires(engine, mock_sink):
    fired = await engine.fire(make_alert())
    assert fired is True
    mock_sink.send.assert_called_once()


@pytest.mark.asyncio
async def test_dedup_suppresses_repeat_within_window(engine, mock_sink):
    await engine.fire(make_alert())
    fired = await engine.fire(make_alert())
    assert fired is False
    assert mock_sink.send.call_count == 1


@pytest.mark.asyncio
async def test_different_rule_ids_not_deduped(engine, mock_sink):
    await engine.fire(make_alert("rule_a"))
    await engine.fire(make_alert("rule_b"))
    assert mock_sink.send.call_count == 2


@pytest.mark.asyncio
async def test_rule_specific_cooldown_respected(engine, mock_sink):
    # ssh_brute_force has 60s cooldown (shorter than global 300s)
    await engine.fire(make_alert("ssh_brute_force", Severity.CRITICAL))
    # Wind back last_fired to 59s ago — still inside 60s cooldown
    engine._last_fired["ssh_brute_force"] = datetime.now(timezone.utc) - timedelta(seconds=59)
    fired = await engine.fire(make_alert("ssh_brute_force", Severity.CRITICAL))
    assert fired is False


@pytest.mark.asyncio
async def test_alert_fires_after_cooldown_expires(engine, mock_sink):
    await engine.fire(make_alert("ssh_brute_force", Severity.CRITICAL))
    # Wind back to 61s ago — past the 60s cooldown
    engine._last_fired["ssh_brute_force"] = datetime.now(timezone.utc) - timedelta(seconds=61)
    fired = await engine.fire(make_alert("ssh_brute_force", Severity.CRITICAL))
    assert fired is True
    assert mock_sink.send.call_count == 2


@pytest.mark.asyncio
async def test_alert_recorded_even_when_deduped(engine, mock_db):
    await engine.fire(make_alert())
    await engine.fire(make_alert())  # deduped
    assert mock_db.record_alert.call_count == 2
    # Second call should have deduped=True
    _, kwargs = mock_db.record_alert.call_args_list[1]
    # record_alert is called with positional args via await
    call_args = mock_db.record_alert.call_args_list[1]
    # deduped is the 9th positional arg
    assert call_args.kwargs.get("deduped", call_args.args[8] if len(call_args.args) > 8 else None)
