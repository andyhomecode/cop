from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from cop.alerts import Alert, AlertEngine, Severity, _redact
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


class TestRedact:
    def test_bearer_token(self):
        assert _redact("Authorization: Bearer abc123") == "Authorization: Bearer [REDACTED]"

    def test_basic_auth(self):
        assert _redact("Authorization: Basic dXNlcjpwYXNz") == "Authorization: Basic [REDACTED]"

    def test_authorization_token(self):
        assert _redact("Authorization: Token abc123xyz") == "Authorization: Token [REDACTED]"

    def test_url_password(self):
        assert _redact("postgresql://user:s3cr3t@localhost/db") == "postgresql://user:[REDACTED]@localhost/db"

    def test_password_equals(self):
        assert _redact("password=hunter2") == "password=[REDACTED]"

    def test_passwd_equals(self):
        assert _redact("passwd=hunter2") == "passwd=[REDACTED]"

    def test_secret_equals(self):
        assert _redact("secret=topsecret") == "secret=[REDACTED]"

    def test_token_equals(self):
        assert _redact("GITHUB_TOKEN=ghp_abcdef") == "GITHUB_TOKEN=[REDACTED]"

    def test_api_key(self):
        assert _redact("api_key=abc123") == "api_key=[REDACTED]"

    def test_api_dash_key(self):
        assert _redact("api-key=abc123") == "api-key=[REDACTED]"

    def test_access_token(self):
        assert _redact("access_token=abc123") == "access_token=[REDACTED]"

    def test_flag_password_space(self):
        assert _redact("mysql --password hunter2 --host localhost") == "mysql --password [REDACTED] --host localhost"

    def test_flag_passwd_space(self):
        assert _redact("mysqldump --passwd secret123") == "mysqldump --passwd [REDACTED]"

    def test_pem_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK\n-----END RSA PRIVATE KEY-----"
        result = _redact(text)
        assert "MIIEpAIBAAK" not in result
        assert "-----BEGIN RSA PRIVATE KEY-----" in result
        assert "-----END RSA PRIVATE KEY-----" in result

    def test_no_false_positive_on_plain_text(self):
        text = "process started with pid 1234"
        assert _redact(text) == text

    def test_context_is_redacted_in_alert(self):
        alert = Alert(
            rule_id="test", severity=Severity.WARN, title="test",
            message="curl -H 'Authorization: Bearer secrettoken'",
            source_monitor="test",
            context={"cmdline": "curl --password hunter2 https://example.com"},
        )
        from cop.alerts import _redact_alert
        _redact_alert(alert)
        assert "secrettoken" not in alert.message
        assert "hunter2" not in alert.context["cmdline"]


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
