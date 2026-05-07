from __future__ import annotations

import asyncio
import fnmatch
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import FileMonitorConfig

# Matches a 64-char hex container ID anywhere in a path component
_CONTAINER_ID_RE = re.compile(r'(?<![a-f0-9])([a-f0-9]{64})(?![a-f0-9])')

# Docker containerd drops these files directly in /var/run during container lifecycle
_DOCKER_RUNTIME_FILE_RE = re.compile(r'^\.?[a-f0-9]{64}(-stdout|\.pid)$')

_CONTAINER_CACHE_TTL = 120  # seconds between Docker mount-map refreshes


class _CopEventHandler(FileSystemEventHandler):
    """Bridges watchdog (threaded) events onto the asyncio event queue."""

    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop, alert_on_events: set[str]):
        super().__init__()
        self._queue = queue
        self._loop = loop
        self._alert_on_events = alert_on_events

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if event.event_type not in self._alert_on_events:
            return
        data = {
            "event_type": event.event_type,
            "src_path": str(event.src_path),
            "dest_path": str(getattr(event, "dest_path", "") or ""),
        }
        def _put() -> None:
            try:
                self._queue.put_nowait(data)
            except asyncio.QueueFull:
                pass
        self._loop.call_soon_threadsafe(_put)


class FileMonitor(BaseMonitor):
    name = "FileMonitor"

    def __init__(self, config: FileMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        self._event_queue: asyncio.Queue | None = None
        self._observer: Observer | None = None
        # host_path_prefix -> container_name, refreshed periodically
        self._mount_map: dict[str, str] = {}
        self._mount_map_refreshed: float = 0.0

    async def run(self) -> None:
        loop = asyncio.get_event_loop()
        self._event_queue = asyncio.Queue(maxsize=1000)
        await self._refresh_mount_map()
        self._observer = self._start_observer(loop)
        try:
            while self._running:
                try:
                    event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                    await self._process_event(event)
                except asyncio.TimeoutError:
                    continue
        finally:
            self._observer.stop()
            self._observer.join(timeout=5)

    async def learn(self) -> None:
        self._logger.info("FileMonitor uses config-defined watch paths — no learned baseline needed")

    def _start_observer(self, loop: asyncio.AbstractEventLoop) -> Observer:
        handler = _CopEventHandler(self._event_queue, loop, set(self._config.alert_on_events))
        observer = Observer()
        for path_str in self._config.watch_paths:
            path = Path(path_str).expanduser()
            if not path.exists():
                self._logger.warning("Watch path does not exist, skipping: %s", path)
                continue
            if path.is_dir():
                observer.schedule(handler, str(path), recursive=True)
                self._logger.info("Watching (recursive): %s", path)
            else:
                # For files (e.g. docker.sock), watch parent non-recursively
                # to avoid pulling in sibling subdirectories like /var/run/containerd/
                observer.schedule(handler, str(path.parent), recursive=False)
                self._logger.info("Watching (non-recursive): %s", path.parent)
        observer.start()
        return observer

    async def _process_event(self, event: dict) -> None:
        src = event["src_path"]
        if self._should_ignore(src):
            return
        if event["event_type"] not in self._config.alert_on_events:
            return

        # Refresh container mount map if stale
        if time.monotonic() - self._mount_map_refreshed > _CONTAINER_CACHE_TTL:
            await self._refresh_mount_map()

        container = self._container_for_path(src)
        container_tag = f" [{container}]" if container else ""

        if self._is_critical(src):
            await self._alerts.fire(Alert(
                rule_id="file_critical_modified",
                severity=Severity.CRITICAL,
                title=f"Critical file {event['event_type']}: {Path(src).name}{container_tag}",
                message=f"Critical path {event['event_type']}: {src}{container_tag}",
                source_monitor=self.name,
                context={**event, "container": container},
            ))
        else:
            await self._alerts.fire(Alert(
                rule_id=f"file_{event['event_type']}",
                severity=Severity.WARN,
                title=f"File {event['event_type']}: {Path(src).name}{container_tag}",
                message=f"File {event['event_type']}: {src}{container_tag}",
                source_monitor=self.name,
                context={**event, "container": container},
            ))

    def _should_ignore(self, path: str) -> bool:
        name = Path(path).name
        if _DOCKER_RUNTIME_FILE_RE.match(name):
            return True
        if any(fnmatch.fnmatch(name, pat) for pat in self._config.ignore_patterns):
            return True
        for ignore_path in self._config.ignore_paths:
            expanded = str(Path(ignore_path).expanduser())
            if path.startswith(expanded.rstrip("/") + "/") or path == expanded:
                return True
        return False

    def _is_critical(self, path: str) -> bool:
        for p in self._config.critical_paths:
            pattern = str(Path(p).expanduser())
            if fnmatch.fnmatch(path, pattern) or path == pattern:
                return True
        return False

    def _container_for_path(self, path: str) -> str | None:
        """Return the container name whose volume mount best matches this path."""
        best_match: str | None = None
        best_len = 0
        for host_prefix, name in self._mount_map.items():
            if path.startswith(host_prefix) and len(host_prefix) > best_len:
                best_match = name
                best_len = len(host_prefix)
        return best_match

    async def _refresh_mount_map(self) -> None:
        """Build host_path -> container_name map from running container mounts."""
        loop = asyncio.get_event_loop()
        mount_map = await loop.run_in_executor(None, self._build_mount_map)
        self._mount_map = mount_map
        self._mount_map_refreshed = time.monotonic()
        if mount_map:
            self._logger.debug("Container mount map: %d entries", len(mount_map))

    def _build_mount_map(self) -> dict[str, str]:
        """Synchronous Docker SDK call — runs in executor."""
        try:
            import docker
            client = docker.from_env()
            result: dict[str, str] = {}
            for container in client.containers.list():
                name = container.name
                for mount in container.attrs.get("Mounts", []):
                    host_path = mount.get("Source", "")
                    if host_path:
                        # Ensure trailing slash so prefix matching doesn't collide
                        result[host_path.rstrip("/") + "/"] = name
            client.close()
            return result
        except Exception as exc:
            self._logger.warning("Could not build container mount map: %s", exc)
            return {}
