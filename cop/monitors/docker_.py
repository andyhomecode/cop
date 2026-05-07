from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import DockerMonitorConfig


class DockerMonitor(BaseMonitor):
    name = "DockerMonitor"

    def __init__(self, config: DockerMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        self._restart_tracker: dict[str, list[datetime]] = defaultdict(list)
        self._learned_containers: set[str] = set()

    async def run(self) -> None:
        import docker
        import docker.errors

        learned = await self._baseline.get_container_baseline()
        self._learned_containers = {c["name"] for c in learned}

        while self._running:
            try:
                client = docker.from_env()
                event_queue: asyncio.Queue = asyncio.Queue(maxsize=500)
                loop = asyncio.get_event_loop()

                stream_future = loop.run_in_executor(
                    None, self._stream_events, client, event_queue, loop
                )
                try:
                    while self._running:
                        try:
                            event = await asyncio.wait_for(event_queue.get(), timeout=2.0)
                            await self._handle_event(client, event)
                        except asyncio.TimeoutError:
                            continue
                finally:
                    client.close()
                    stream_future.cancel()
            except asyncio.CancelledError:
                raise
            except Exception:
                self._logger.exception("DockerMonitor error — retrying in 10s")
                await asyncio.sleep(10)

    async def learn_one(self, context: dict) -> None:
        name = context.get("name", "")
        if name:
            self._learned_containers.add(name)
            await self._baseline.add_container_to_baseline(name, context.get("image", "unknown"))

    async def learn(self) -> None:
        import docker
        try:
            client = docker.from_env()
            containers = []
            for c in client.containers.list():
                image_tag = c.image.tags[0] if c.image.tags else c.image.id[:12]
                containers.append({
                    "container_id": c.id,
                    "name": c.name,
                    "image": image_tag,
                })
            await self._baseline.set_container_baseline(containers)
            self._logger.info("Learned %d running containers into baseline", len(containers))
            client.close()
        except Exception:
            self._logger.exception("Failed to learn Docker baseline")

    def _stream_events(
        self,
        client,
        queue: asyncio.Queue,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        try:
            for event in client.events(
                decode=True,
                filters={"type": ["container", "image"]},
            ):
                if not self._running:
                    break
                try:
                    loop.call_soon_threadsafe(queue.put_nowait, event)
                except asyncio.QueueFull:
                    pass
        except Exception as exc:
            self._logger.warning("Docker event stream ended: %s", exc)

    async def _handle_event(self, client, event: dict) -> None:
        action = event.get("Action", "")
        status = event.get("status", action)
        attrs = event.get("Actor", {}).get("Attributes", {})
        name = attrs.get("name", (event.get("id") or "?")[:12])
        image = attrs.get("image", "?")

        if status == "start":
            await self._handle_start(client, name, image)
        elif status == "die":
            await self._handle_die(name)
        elif status in ("exec_start", "exec_create"):
            await self._handle_exec(name, attrs)
        elif event.get("Type") == "image" and action == "pull":
            await self._handle_image_pull(image)

    async def _handle_start(self, client, name: str, image: str) -> None:
        if name not in self._config.known_containers and name not in self._learned_containers:
            await self._alerts.fire(Alert(
                rule_id="docker_unknown_container",
                severity=Severity.WARN,
                title=f"Unknown container started: {name}",
                message=(
                    f"Container '{name}' (image: {image}) started\n"
                    f"Not in known_containers list"
                ),
                source_monitor=self.name,
                context={"name": name, "image": image},
            ))

        try:
            container = client.containers.get(name)
            if container.attrs.get("HostConfig", {}).get("Privileged"):
                await self._alerts.fire(Alert(
                    rule_id="docker_privileged_container",
                    severity=Severity.CRITICAL,
                    title=f"Privileged container: {name}",
                    message=(
                        f"Container '{name}' started with --privileged (full host access)"
                    ),
                    source_monitor=self.name,
                    context={"name": name, "image": image},
                ))
        except Exception:
            pass

        await self._check_restart_loop(name)

    async def _handle_die(self, name: str) -> None:
        self._restart_tracker[name].append(datetime.now(timezone.utc))

    async def _handle_exec(self, name: str, attrs: dict) -> None:
        await self._alerts.fire(Alert(
            rule_id="docker_exec_into_container",
            severity=Severity.WARN,
            title=f"exec into container: {name}",
            message=f"docker exec entered container '{name}'",
            source_monitor=self.name,
            context={"name": name, "exec_id": attrs.get("execID", "?")},
        ))

    async def _handle_image_pull(self, image: str) -> None:
        await self._alerts.fire(Alert(
            rule_id="docker_image_pull",
            severity=Severity.INFO,
            title=f"Docker image pulled: {image}",
            message=f"Image '{image}' was pulled",
            source_monitor=self.name,
            context={"image": image},
        ))

    async def _check_restart_loop(self, name: str) -> None:
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - self._config.restart_window_seconds
        self._restart_tracker[name] = [
            t for t in self._restart_tracker[name] if t.timestamp() >= cutoff
        ]
        count = len(self._restart_tracker[name])
        if count >= self._config.restart_count_threshold:
            await self._alerts.fire(Alert(
                rule_id="docker_restart_loop",
                severity=Severity.WARN,
                title=f"Container restart loop: {name}",
                message=(
                    f"Container '{name}' has restarted {count} times "
                    f"in {self._config.restart_window_seconds}s"
                ),
                source_monitor=self.name,
                context={"name": name, "restart_count": count},
            ))
