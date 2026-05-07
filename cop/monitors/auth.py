from __future__ import annotations

import asyncio
import ipaddress
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING, AsyncIterator

import aiofiles

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import AuthMonitorConfig

_SSH_FAIL_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+) port \d+"
)
_PAM_FAIL_RE = re.compile(
    r"pam_unix\([^)]+:auth\): authentication failure.*?rhost=([\d.:a-fA-F]+)"
)
_SSH_ACCEPT_RE = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.:a-fA-F]+) port \d+"
)
_SUDO_RE = re.compile(
    r"sudo:\s+(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.+)"
)
_NEW_USER_RE = re.compile(r"new user: name=(\S+)")


class AuthMonitor(BaseMonitor):
    name = "AuthMonitor"

    def __init__(self, config: AuthMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        self._ssh_failures: dict[str, list[datetime]] = defaultdict(list)

    async def run(self) -> None:
        # Restart tail loop to handle log rotation transparently
        while self._running:
            try:
                async for line in self._tail_file(self._config.log_path):
                    if not self._running:
                        return
                    await self._handle_line(line)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._logger.exception("AuthMonitor error — restarting tail in 5s")
                await asyncio.sleep(5)

    async def learn_one(self, context: dict) -> None:
        ip = context.get("ip")
        if ip:
            await self._baseline.add_ssh_source(ip)

    async def learn(self) -> None:
        log_path = self._config.log_path
        if not os.path.exists(log_path):
            self._logger.warning("auth.log not found at %s", log_path)
            return
        count = 0
        try:
            async with aiofiles.open(log_path, "r", errors="replace") as f:
                async for line in f:
                    m = _SSH_ACCEPT_RE.search(line)
                    if m:
                        await self._baseline.add_ssh_source(m.group(2))
                        count += 1
        except PermissionError:
            self._logger.warning("Permission denied reading %s — need root or adm group", log_path)
        self._logger.info("Learned %d SSH source IPs from auth.log", count)

    async def _tail_file(self, path: str) -> AsyncIterator[str]:
        """Yield new lines as they appear; handles log rotation via inode check."""
        while not os.path.exists(path):
            self._logger.warning("%s not found — waiting", path)
            await asyncio.sleep(5)
            if not self._running:
                return

        try:
            async with aiofiles.open(path, "r", errors="replace") as f:
                await f.seek(0, 2)  # seek to end; don't replay history
                current_inode = os.stat(path).st_ino
                while self._running:
                    line = await f.readline()
                    if line:
                        yield line
                    else:
                        # Check for rotation (new inode or file gone)
                        try:
                            if os.stat(path).st_ino != current_inode:
                                self._logger.info("auth.log rotated, reopening")
                                return
                        except FileNotFoundError:
                            return
                        await asyncio.sleep(0.5)
        except PermissionError:
            self._logger.error("Permission denied: %s — auth monitor disabled", path)

    async def _handle_line(self, line: str) -> None:
        m = _SSH_FAIL_RE.search(line)
        if m:
            await self._handle_ssh_failure(m.group(1), m.group(2))
            return
        m = _PAM_FAIL_RE.search(line)
        if m:
            await self._handle_ssh_failure("unknown", m.group(1))
            return
        m = _SSH_ACCEPT_RE.search(line)
        if m:
            await self._handle_ssh_success(m.group(1), m.group(2))
            return
        m = _SUDO_RE.search(line)
        if m:
            await self._handle_sudo(m.group(1), m.group(2), m.group(3).strip())
            return
        m = _NEW_USER_RE.search(line)
        if m:
            await self._handle_new_user(m.group(1))

    async def _handle_ssh_failure(self, user: str, ip: str) -> None:
        now = datetime.now(timezone.utc)
        self._ssh_failures[ip].append(now)
        cutoff = now.timestamp() - self._config.brute_force_window_seconds
        self._ssh_failures[ip] = [t for t in self._ssh_failures[ip] if t.timestamp() >= cutoff]
        count = len(self._ssh_failures[ip])
        if count >= self._config.brute_force_threshold:
            await self._alerts.fire(Alert(
                rule_id="ssh_brute_force",
                severity=Severity.CRITICAL,
                title=f"SSH brute force from {ip}",
                message=(
                    f"{count} failed SSH attempts from {ip} "
                    f"in {self._config.brute_force_window_seconds}s\n"
                    f"Target user: {user}"
                ),
                source_monitor=self.name,
                context={"ip": ip, "user": user, "count": count},
            ))

    async def _handle_ssh_success(self, user: str, ip: str) -> None:
        known = await self._baseline.get_ssh_sources()
        if not self._ip_is_known(ip, known):
            await self._alerts.fire(Alert(
                rule_id="ssh_unknown_source",
                severity=Severity.WARN,
                title=f"SSH login from unknown IP: {ip}",
                message=f"Successful SSH login by '{user}' from previously unseen IP {ip}",
                source_monitor=self.name,
                context={"user": user, "ip": ip},
            ))
        await self._baseline.add_ssh_source(ip)

    async def _handle_sudo(self, user: str, target_user: str, command: str) -> None:
        if user not in self._config.known_sudo_users:
            await self._alerts.fire(Alert(
                rule_id="unexpected_sudo",
                severity=Severity.WARN,
                title=f"Unexpected sudo by {user}",
                message=f"User '{user}' ran sudo as '{target_user}': {command}",
                source_monitor=self.name,
                context={"user": user, "target_user": target_user, "command": command},
            ))
        else:
            await self._alerts.fire(Alert(
                rule_id="sudo_usage",
                severity=Severity.INFO,
                title=f"sudo: {user} → {target_user}",
                message=f"{user} ran sudo as {target_user}: {command}",
                source_monitor=self.name,
                context={"user": user, "target_user": target_user, "command": command},
            ))

    async def _handle_new_user(self, username: str) -> None:
        await self._alerts.fire(Alert(
            rule_id="new_system_user",
            severity=Severity.CRITICAL,
            title=f"New system user created: {username}",
            message=f"A new system user account '{username}' was created",
            source_monitor=self.name,
            context={"username": username},
        ))

    def _ip_is_known(self, ip: str, known_ips: set[str]) -> bool:
        if ip in known_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for source in self._config.known_ssh_sources:
                try:
                    if addr in ipaddress.ip_network(source, strict=False):
                        return True
                except ValueError:
                    if ip == source:
                        return True
        except ValueError:
            pass
        return False
