from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import TYPE_CHECKING

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import TripwireMonitorConfig


class _TripwireEventHandler(FileSystemEventHandler):
    """Bridges watchdog accessed events onto the asyncio event queue."""

    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop, tripwire_paths: set[str]):
        super().__init__()
        self._queue = queue
        self._loop = loop
        self._tripwire_paths = tripwire_paths

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if event.event_type != "opened":
            return
        src = str(event.src_path)
        if src not in self._tripwire_paths:
            return
        def _put() -> None:
            try:
                self._queue.put_nowait(src)
            except asyncio.QueueFull:
                pass
        self._loop.call_soon_threadsafe(_put)


class TripwireMonitor(BaseMonitor):
    name = "TripwireMonitor"

    def __init__(self, config: TripwireMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        self._event_queue: asyncio.Queue | None = None
        self._observer: Observer | None = None

    async def run(self) -> None:
        tripwire_paths = self._setup_files()
        if not tripwire_paths:
            self._logger.warning("No tripwire files available — monitor inactive")
            return

        loop = asyncio.get_event_loop()
        self._event_queue = asyncio.Queue(maxsize=100)
        handler = _TripwireEventHandler(self._event_queue, loop, tripwire_paths)
        self._observer = Observer()

        dirs_watched: set[str] = set()
        for path_str in tripwire_paths:
            parent = str(Path(path_str).parent)
            if parent not in dirs_watched:
                self._observer.schedule(handler, parent, recursive=False)
                dirs_watched.add(parent)
                self._logger.info("Tripwire armed: %s", path_str)

        self._observer.start()
        try:
            while self._running:
                try:
                    path = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                    await self._handle_access(path)
                except asyncio.TimeoutError:
                    continue
        finally:
            self._observer.stop()
            self._observer.join(timeout=5)

    async def learn(self) -> None:
        self._logger.info("TripwireMonitor has no baseline to learn")

    def _setup_files(self) -> set[str]:
        """Resolve paths and create missing decoy files when configured."""
        resolved: set[str] = set()
        for p_str in self._config.files:
            path = Path(p_str).expanduser()
            if not path.exists():
                if self._config.create_missing:
                    try:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.touch()
                        self._logger.info("Created decoy tripwire file: %s", path)
                    except OSError as exc:
                        self._logger.warning("Could not create tripwire file %s: %s", path, exc)
                        continue
                else:
                    self._logger.debug("Tripwire file not found, skipping: %s", path)
                    continue
            resolved.add(str(path))
        return resolved

    async def _handle_access(self, path: str) -> None:
        loop = asyncio.get_event_loop()
        proc_info = await loop.run_in_executor(None, self._find_accessor, path)

        context: dict = {"path": path}
        if proc_info:
            context.update(proc_info)
            proc_str = f" by {proc_info['process_name']} (pid {proc_info['pid']})"
        else:
            proc_str = ""

        name = Path(path).name
        await self._alerts.fire(Alert(
            rule_id=f"tripwire_{name}",
            severity=Severity.CRITICAL,
            title=f"Tripwire: {name} accessed{proc_str}",
            message=f"Honeypot file was opened{proc_str}: {path}",
            source_monitor=self.name,
            context=context,
        ))

    def _find_accessor(self, path: str) -> dict | None:
        """Scan /proc/*/fd to find which process has the tripwire file open."""
        try:
            target_inode = os.stat(path).st_ino
        except OSError:
            return None
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            fd_dir = pid_dir / "fd"
            try:
                for fd_link in fd_dir.iterdir():
                    try:
                        if os.stat(fd_link).st_ino == target_inode:
                            comm = (pid_dir / "comm").read_text().strip()
                            return {"pid": int(pid_dir.name), "process_name": comm}
                    except OSError:
                        continue
            except (OSError, PermissionError):
                continue
        return None
