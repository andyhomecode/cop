from __future__ import annotations

import json
import logging
import logging.handlers
from pathlib import Path
from typing import TYPE_CHECKING

from cop.sinks.base import AlertSink

if TYPE_CHECKING:
    from cop.alerts import Alert
    from cop.config import LogSinkConfig

logger = logging.getLogger("cop.sinks.jsonlog")


class JsonLogSink(AlertSink):
    """Writes one JSON object per line to a size-rotating log file."""

    def __init__(self, config: LogSinkConfig):
        self._config = config
        self._handler: logging.handlers.RotatingFileHandler | None = None
        self._log: logging.Logger | None = None
        self._setup()

    def _setup(self) -> None:
        path = Path(self._config.path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handler = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=self._config.max_bytes,
            backupCount=self._config.backup_count,
        )
        self._log = logging.getLogger("cop.alert_record")
        self._log.addHandler(self._handler)
        self._log.setLevel(logging.INFO)
        self._log.propagate = False

    async def send(self, alert: Alert) -> bool:
        if not self._config.enabled or not self._log:
            return False
        try:
            record = {
                "fired_at": alert.fired_at.isoformat(),
                "severity": alert.severity.value,
                "rule_id": alert.rule_id,
                "title": alert.title,
                "message": alert.message,
                "source_monitor": alert.source_monitor,
                "context": alert.context,
            }
            self._log.info(json.dumps(record))
            return True
        except Exception as exc:
            logger.warning("jsonlog send failed: %s", exc)
            return False

    async def close(self) -> None:
        if self._handler:
            self._handler.close()
