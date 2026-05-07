from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import aiohttp

from cop.alerts import Severity
from cop.sinks.base import AlertSink

if TYPE_CHECKING:
    from cop.alerts import Alert
    from cop.config import NtfyConfig

logger = logging.getLogger("cop.sinks.ntfy")

_SEVERITY_MAP = {
    Severity.CRITICAL: {"priority": "5", "tags": "rotating_light,warning"},
    Severity.WARN: {"priority": "4", "tags": "eyes"},
    Severity.INFO: {"priority": "2", "tags": "information_source"},
}


class NtfySink(AlertSink):
    _is_ntfy = True

    def __init__(self, config: NtfyConfig, session: aiohttp.ClientSession):
        self._config = config
        self._session = session

    async def send(self, alert: Alert) -> bool:
        if not self._config.enabled:
            return False
        mapping = _SEVERITY_MAP[alert.severity]
        headers = {
            "X-Title": alert.title,
            "X-Priority": mapping["priority"],
            "X-Tags": mapping["tags"],
            "Content-Type": "text/plain",
        }
        if self._config.token:
            headers["Authorization"] = f"Bearer {self._config.token}"
        body = alert.message
        if "ollama_risk" in alert.context:
            risk = alert.context["ollama_risk"]
            comment = alert.context.get("ollama_comment", "")
            if risk <= 1:
                risk_emoji = "😐"
            elif risk <= 5:
                risk_emoji = "🤨🤨"
            elif risk <= 8:
                risk_emoji = "😨😨😨"
            else:
                risk_emoji = "🤬🤬🤬🤬"
            body = f"{body}\n\n 🤖{risk_emoji} risk: {risk}/10 — {comment}" if comment else f"{body}\n\n🤖{risk_emoji} risk: {risk}/10"
        try:
            async with self._session.post(
                self._config.url,
                data=body.encode(),
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self._config.timeout_seconds),
            ) as resp:
                if resp.status >= 400:
                    logger.warning("ntfy returned HTTP %d", resp.status)
                    return False
                return True
        except Exception as exc:
            logger.warning("ntfy send failed: %s", exc)
            return False

    async def close(self) -> None:
        pass  # session lifecycle managed by caller
