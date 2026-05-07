from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cop.alerts import Alert


class AlertSink(ABC):
    _is_ntfy: bool = False

    @abstractmethod
    async def send(self, alert: "Alert") -> bool:
        """Send alert. Return True on success. Must not raise."""

    @abstractmethod
    async def close(self) -> None:
        """Release any resources."""
