from __future__ import annotations

import asyncio
import fnmatch
import re
import psutil
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

# Processes whose presence means a package operation is running
_PACKAGE_MANAGERS = {"dpkg", "apt", "apt-get", "aptitude", "unattended-upgr", "unattended-upgrade"}
_PKG_CHECK_TTL = 5.0


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
        self._pkg_active = False
        self._pkg_checked: float = 0.0
        self._approved_paths: set[str] = set()  # non-critical paths marked expected

    @property
    def _watch_paths(self) -> list[str]:
        return list(self._config.watch_paths) + list(self._config.extra_watch_paths)

    @property
    def _critical_paths(self) -> list[str]:
        return list(self._config.critical_paths) + list(self._config.extra_critical_paths)

    async def run(self) -> None:
        loop = asyncio.get_event_loop()
        self._approved_paths = await self._approved("file_path")
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

    async def mark_expected(self, alert) -> str:
        if alert.rule_id == "file_critical_modified":
            return "👍 Acknowledged. Critical files always alert; there's nothing to approve."
        path = alert.context.get("dest_path") or alert.context.get("src_path")
        if not path:
            return await super().mark_expected(alert)
        await self._baseline.add_approval("file_path", path)
        self._approved_paths.add(path)
        return (f"✅ Changes to {path} won't alert again. "
                "To silence a whole folder, add it to monitors.file.ignore_paths.")

    def _start_observer(self, loop: asyncio.AbstractEventLoop) -> Observer:
        handler = _CopEventHandler(self._event_queue, loop, set(self._config.alert_on_events))
        observer = Observer()
        scheduled: set[tuple[str, bool]] = set()
        for path_str in self._watch_paths:
            path = Path(path_str).expanduser()
            if not path.exists():
                self._logger.warning("Watch path does not exist, skipping: %s", path)
                continue
            if path.is_dir():
                target = (str(path), True)
            else:
                # For files (e.g. docker.sock), watch parent non-recursively
                # to avoid pulling in sibling subdirectories like /var/run/containerd/
                target = (str(path.parent), False)
            if target in scheduled:
                continue
            scheduled.add(target)
            observer.schedule(handler, target[0], recursive=target[1])
            self._logger.info("Watching (%s): %s", "recursive" if target[1] else "non-recursive", target[0])
        observer.start()
        return observer

    async def _process_event(self, event: dict) -> None:
        src = event["src_path"]
        dest = event.get("dest_path") or ""
        # A move's dest is where the content ends up: useradd, passwd, visudo,
        # sed -i and most editors write a temp file and rename it over the
        # real one (/etc/passwd+ -> /etc/passwd), so judge both ends.
        paths = [p for p in (src, dest) if p]
        if all(self._should_ignore(p) for p in paths):
            return
        if event["event_type"] not in self._config.alert_on_events:
            return
        target = dest or src
        critical = any(self._is_critical(p) for p in paths)

        if not critical and target in self._approved_paths:
            return
        if not critical and self._config.quiet_during_package_ops and self._package_op_running():
            self._logger.debug("Package operation running, skipping %s %s", event["event_type"], target)
            return

        # Refresh container mount map if stale
        if time.monotonic() - self._mount_map_refreshed > _CONTAINER_CACHE_TTL:
            await self._refresh_mount_map()

        container = self._container_for_path(target)
        container_tag = f" [{container}]" if container else ""
        where = f"{src} -> {dest}" if dest else src

        if critical:
            await self._alerts.fire(Alert(
                rule_id="file_critical_modified",
                severity=Severity.CRITICAL,
                title=f"Critical file {event['event_type']}: {Path(target).name}{container_tag}",
                message=f"Critical path {event['event_type']}: {where}{container_tag}",
                source_monitor=self.name,
                context={**event, "container": container},
            ))
        else:
            await self._alerts.fire(Alert(
                rule_id=f"file_{event['event_type']}",
                severity=Severity.WARN,
                title=f"File {event['event_type']}: {Path(target).name}{container_tag}",
                message=f"File {event['event_type']}: {where}{container_tag}",
                source_monitor=self.name,
                context={**event, "container": container},
            ))

    def _package_op_running(self) -> bool:
        now = time.monotonic()
        if now - self._pkg_checked > _PKG_CHECK_TTL:
            self._pkg_checked = now
            try:
                self._pkg_active = any(
                    (p.info.get("name") or "") in _PACKAGE_MANAGERS
                    for p in psutil.process_iter(["name"])
                )
            except Exception:
                self._pkg_active = False
        return self._pkg_active

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
        for p in self._critical_paths:
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
