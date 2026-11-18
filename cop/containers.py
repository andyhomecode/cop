"""Which Docker container a process belongs to (from its cgroup), by name."""
from __future__ import annotations

import logging
import re
import time

_CGROUP_CONTAINER_RE = re.compile(r"(?:docker-|/docker/)([0-9a-f]{64})")
_MIN_REFRESH = 2.0  # only on a miss (an unknown container id), so cheap

logger = logging.getLogger("cop.containers")


def container_id_for_pid(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            m = _CGROUP_CONTAINER_RE.search(f.read())
    except OSError:
        return None
    return m.group(1) if m else None


class ContainerNames:
    """Container id -> name, refreshed from Docker at most every 2 s on a miss."""

    def __init__(self) -> None:
        self.names: dict[str, str] = {}
        self._refreshed = 0.0

    def name(self, cid: str) -> str | None:
        if cid not in self.names and time.monotonic() - self._refreshed > _MIN_REFRESH:
            self._refreshed = time.monotonic()
            try:
                import docker
                client = docker.from_env()
                try:
                    self.names = {c.id: c.name for c in client.containers.list()}
                finally:
                    client.close()
            except Exception as exc:
                logger.debug("Could not list containers: %s", exc)
        return self.names.get(cid)

    def for_pid(self, pid: int) -> str | None:
        """Container name (or short id if unnamed) for a pid, None on the host."""
        cid = container_id_for_pid(pid)
        if not cid:
            return None
        return self.name(cid) or cid[:12]
