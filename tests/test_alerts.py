from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from cop.alerts import Alert, AlertEngine, Severity, _redact
from cop.config import AlertsConfig, OllamaConfig


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


def make_scorer():
    """Minimal fake scorer — fire() only calls score() when scorer is not None."""
    scorer = AsyncMock()
    scorer.score = AsyncMock(return_value=(7, "suspicious activity"))
    return scorer


def make_ollama_engine(config, mock_db, mock_sink, ollama_cfg: OllamaConfig):
    scorer = make_scorer()
    return AlertEngine(config, mock_db, [mock_sink], scorer=scorer, ollama_config=ollama_cfg), scorer


class TestIsOllamaSuppressed:
    def _engine(self, config, mock_db, mock_sink, ollama_cfg):
        scorer = make_scorer()
        return AlertEngine(config, mock_db, [mock_sink], scorer=scorer, ollama_config=ollama_cfg)

    def _alert(self, risk, comment):
        a = make_alert()
        a.context["ollama_risk"] = risk
        a.context["ollama_comment"] = comment
        return a

    def test_no_suppression_without_ollama_config(self, config, mock_db, mock_sink):
        engine = AlertEngine(config, mock_db, [mock_sink], scorer=make_scorer(), ollama_config=None)
        assert engine._is_ollama_suppressed(self._alert(2, "routine")) is False

    def test_no_suppression_without_scorer(self, config, mock_db, mock_sink):
        ollama_cfg = OllamaConfig(min_risk=5)
        engine = AlertEngine(config, mock_db, [mock_sink], scorer=None, ollama_config=ollama_cfg)
        assert engine._is_ollama_suppressed(self._alert(2, "routine")) is False

    def test_risk_below_threshold_suppressed(self, config, mock_db, mock_sink):
        engine = self._engine(config, mock_db, mock_sink, OllamaConfig(min_risk=5))
        assert engine._is_ollama_suppressed(self._alert(4, "looks fine")) is True

    def test_risk_at_threshold_not_suppressed(self, config, mock_db, mock_sink):
        engine = self._engine(config, mock_db, mock_sink, OllamaConfig(min_risk=5))
        assert engine._is_ollama_suppressed(self._alert(5, "looks fine")) is False

    def test_risk_above_threshold_not_suppressed(self, config, mock_db, mock_sink):
        engine = self._engine(config, mock_db, mock_sink, OllamaConfig(min_risk=5))
        assert engine._is_ollama_suppressed(self._alert(8, "looks fine")) is False

    def test_min_risk_zero_disables_risk_filter(self, config, mock_db, mock_sink):
        engine = self._engine(config, mock_db, mock_sink, OllamaConfig(min_risk=0))
        assert engine._is_ollama_suppressed(self._alert(0, "looks fine")) is False

    def test_comment_pattern_match_suppressed(self, config, mock_db, mock_sink):
        cfg = OllamaConfig(suppressed_comment_patterns=["routine"])
        engine = self._engine(config, mock_db, mock_sink, cfg)
        assert engine._is_ollama_suppressed(self._alert(8, "routine package update")) is True

    def test_comment_pattern_case_insensitive(self, config, mock_db, mock_sink):
        cfg = OllamaConfig(suppressed_comment_patterns=["legitimate"])
        engine = self._engine(config, mock_db, mock_sink, cfg)
        assert engine._is_ollama_suppressed(self._alert(8, "LEGITIMATE admin action")) is True

    def test_comment_no_match_not_suppressed(self, config, mock_db, mock_sink):
        cfg = OllamaConfig(suppressed_comment_patterns=["routine", "legitimate"])
        engine = self._engine(config, mock_db, mock_sink, cfg)
        assert engine._is_ollama_suppressed(self._alert(8, "suspicious outbound connection")) is False

    def test_comment_multi_word_phrase(self, config, mock_db, mock_sink):
        cfg = OllamaConfig(suppressed_comment_patterns=["no malicious indicators"])
        engine = self._engine(config, mock_db, mock_sink, cfg)
        assert engine._is_ollama_suppressed(self._alert(3, "no malicious indicators found")) is True

    def test_both_filters_either_suppresses(self, config, mock_db, mock_sink):
        # High risk but matching comment → suppressed by comment pattern
        cfg = OllamaConfig(min_risk=5, suppressed_comment_patterns=["routine"])
        engine = self._engine(config, mock_db, mock_sink, cfg)
        assert engine._is_ollama_suppressed(self._alert(9, "routine maintenance")) is True

    def test_regex_pattern_supported(self, config, mock_db, mock_sink):
        cfg = OllamaConfig(suppressed_comment_patterns=[r"routine|legitimate"])
        engine = self._engine(config, mock_db, mock_sink, cfg)
        assert engine._is_ollama_suppressed(self._alert(6, "legitimate admin task")) is True


class TestOllamaSuppressionDispatch:
    @pytest.mark.asyncio
    async def test_suppressed_alert_does_not_reach_sink(self, config, mock_db, mock_sink):
        cfg = OllamaConfig(min_risk=5)
        engine, scorer = make_ollama_engine(config, mock_db, mock_sink, cfg)
        scorer.score.return_value = (2, "low risk activity")

        fired = await engine.fire(make_alert())

        assert fired is False
        mock_sink.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_suppressed_alert_still_recorded_to_db(self, config, mock_db, mock_sink):
        cfg = OllamaConfig(min_risk=5)
        engine, scorer = make_ollama_engine(config, mock_db, mock_sink, cfg)
        scorer.score.return_value = (2, "low risk activity")

        await engine.fire(make_alert())

        mock_db.record_alert.assert_called_once()

    @pytest.mark.asyncio
    async def test_non_suppressed_alert_reaches_sink(self, config, mock_db, mock_sink):
        cfg = OllamaConfig(min_risk=5)
        engine, scorer = make_ollama_engine(config, mock_db, mock_sink, cfg)
        scorer.score.return_value = (7, "suspicious activity")

        fired = await engine.fire(make_alert())

        assert fired is True
        mock_sink.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_suppressed_alert_updates_dedup_window(self, config, mock_db, mock_sink):
        # A suppressed alert should still advance _last_fired so the next
        # identical event within the cooldown is deduped (not re-scored).
        cfg = OllamaConfig(min_risk=5)
        engine, scorer = make_ollama_engine(config, mock_db, mock_sink, cfg)
        scorer.score.return_value = (2, "low risk")

        await engine.fire(make_alert("test_rule"))
        # Second identical alert within window — should be deduped, not scored again
        await engine.fire(make_alert("test_rule"))

        assert scorer.score.call_count == 1  # only scored once
