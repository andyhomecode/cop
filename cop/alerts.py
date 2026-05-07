from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cop.baseline import BaselineDB
    from cop.config import AlertsConfig
    from cop.ollama import OllamaScorer
    from cop.sinks.base import AlertSink

logger = logging.getLogger("cop.alerts")

_REDACT_PATTERNS: list[tuple[re.Pattern, str]] = [
    # HTTP Authorization header values
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-_\.~\+\/]+=*", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(Basic\s+)[A-Za-z0-9+/]+=*", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(Authorization:\s*Token\s+)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    # Credentials embedded in URLs: proto://user:pass@host
    (re.compile(r"(://[^:@\s/]+:)[^@\s/]+(?=@)"), r"\1[REDACTED]"),
    # Key=value or key: value for common secret field names
    (re.compile(
        r"(?i)((?:password|passwd|secret|token|api[-_]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[=:]\s*)\S+",
    ), r"\1[REDACTED]"),
    # --password/--passwd/--secret/--token <space-separated value>
    (re.compile(r"(?i)(--(?:password|passwd|secret|token)\s+)\S+"), r"\1[REDACTED]"),
    # PEM private key blocks
    (re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).+?(-----END [A-Z ]*PRIVATE KEY-----)", re.DOTALL), r"\1[REDACTED]\2"),
]


def _redact(text: str) -> str:
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_alert(alert: Alert) -> None:
    alert.message = _redact(alert.message)
    alert.title = _redact(alert.title)
    for key, val in alert.context.items():
        if isinstance(val, str):
            alert.context[key] = _redact(val)


class Severity(Enum):
    CRITICAL = "CRITICAL"
    WARN = "WARN"
    INFO = "INFO"


@dataclass
class Alert:
    rule_id: str
    severity: Severity
    title: str
    message: str
    source_monitor: str
    context: dict[str, Any] = field(default_factory=dict)
    fired_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AlertEngine:
    def __init__(
        self,
        config: AlertsConfig,
        db: BaselineDB,
        sinks: list[AlertSink],
        scorer: OllamaScorer | None = None,
    ):
        self._config = config
        self._db = db
        self._sinks = sinks
        self._scorer = scorer
        self._last_fired: dict[str, datetime] = {}
        self._lock = asyncio.Lock()

    async def fire(self, alert: Alert) -> bool:
        """Check dedup, record to DB, dispatch to sinks. Returns True if alert was sent."""
        async with self._lock:
            _redact_alert(alert)
            deduped = self._is_duplicate(alert)
            sent_ntfy = False
            if not deduped:
                if self._scorer is not None:
                    risk, comment = await self._scorer.score(alert)
                    alert.context["ollama_risk"] = risk
                    alert.context["ollama_comment"] = comment
                sent_ntfy = await self._dispatch(alert)
                self._last_fired[alert.rule_id] = alert.fired_at
            await self._record(alert, deduped=deduped, sent_ntfy=sent_ntfy)
            if not deduped:
                logger.info("[%s] %s — %s", alert.severity.value, alert.rule_id, alert.title)
            return not deduped

    def _is_duplicate(self, alert: Alert) -> bool:
        last = self._last_fired.get(alert.rule_id)
        if last is None:
            return False
        cooldown = self._cooldown_for(alert.rule_id)
        return (alert.fired_at - last).total_seconds() < cooldown

    async def _dispatch(self, alert: Alert) -> bool:
        ntfy_ok = False
        for sink in self._sinks:
            try:
                result = await sink.send(alert)
                if getattr(sink, "_is_ntfy", False):
                    ntfy_ok = result
            except Exception:
                logger.exception("Sink %s raised unexpectedly", sink.__class__.__name__)
        return ntfy_ok

    async def _record(self, alert: Alert, *, deduped: bool, sent_ntfy: bool) -> None:
        try:
            await self._db.record_alert(
                rule_id=alert.rule_id,
                severity=alert.severity.value,
                title=alert.title,
                message=alert.message,
                context_json=json.dumps(alert.context),
                source_monitor=alert.source_monitor,
                fired_at=alert.fired_at.isoformat(),
                sent_ntfy=sent_ntfy,
                deduped=deduped,
            )
        except Exception:
            logger.exception("Failed to record alert to DB")

    def _cooldown_for(self, rule_id: str) -> int:
        return self._config.rule_cooldowns.get(rule_id, self._config.dedup_window_seconds)
