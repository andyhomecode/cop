from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, AsyncIterator

import aiofiles

from cop.alerts import Alert, Severity
from cop.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from cop.config import PackageMonitorConfig

# 2026-11-18 06:59:56 upgrade needrestart:all 3.6-7ubuntu4.5 3.6-7ubuntu4.6
_DPKG_ACTION_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (install|upgrade|remove|purge) (\S+) (\S+) (\S+)"
)
_TS_FMT = "%Y-%m-%d %H:%M:%S"
_LIST_LIMIT = 25  # package names shown per category


@dataclass
class _Run:
    """Package actions grouped into one apt/dpkg run."""
    first_ts: str = ""
    last_ts: str = ""
    installed: dict[str, str] = field(default_factory=dict)   # pkg -> version
    upgraded: dict[str, tuple[str, str]] = field(default_factory=dict)
    removed: dict[str, str] = field(default_factory=dict)
    last_seen: float = 0.0  # monotonic time of the last action

    def empty(self) -> bool:
        return not (self.installed or self.upgraded or self.removed)


def _names(d: dict, fmt=None) -> str:
    items = sorted(d.items())
    shown = [fmt(k, v) if fmt else k for k, v in items[:_LIST_LIMIT]]
    more = len(items) - len(shown)
    return ", ".join(shown) + (f" (+{more} more)" if more > 0 else "")


def parse_apt_history(text: str) -> list[dict]:
    """Blocks of /var/log/apt/history.log as dicts (Start-Date, Commandline, Requested-By...)."""
    blocks, cur = [], {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        key, sep, val = line.partition(": ")
        if sep:
            cur[key] = val.strip()
    if cur:
        blocks.append(cur)
    return blocks


def _parse_ts(s: str) -> datetime | None:
    try:
        return datetime.strptime(" ".join(s.split()), _TS_FMT)  # history.log uses two spaces
    except (ValueError, AttributeError):
        return None


class PackageMonitor(BaseMonitor):
    """One alert per apt/dpkg run, not one per package.

    Tails dpkg.log (so plain `dpkg -i` counts too) and groups actions until
    there's been no package activity for summary_quiet_seconds; unattended-
    upgrades' back-to-back apt sessions become one run. The summary says who
    ran it, from the matching apt history.log entries. A run that only upgrades
    is INFO; any install or removal makes it WARN.
    """

    name = "PackageMonitor"

    def __init__(self, config: PackageMonitorConfig, baseline, alert_engine):
        super().__init__(config, baseline, alert_engine)
        self._run = _Run()

    async def run(self) -> None:
        flusher = asyncio.create_task(self._flush_loop())
        try:
            while self._running:
                try:
                    async for line in self._tail_file(self._config.log_path):
                        if not self._running:
                            return
                        self._handle_line(line)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._logger.exception("PackageMonitor error — restarting tail in 5s")
                    await asyncio.sleep(5)
        finally:
            flusher.cancel()

    async def learn(self) -> None:
        self._logger.info("PackageMonitor tails dpkg.log — no baseline to learn")

    async def mark_expected(self, alert) -> str:
        return "👍 Acknowledged. Each apt/dpkg run alerts once; there's nothing to remember."

    def _handle_line(self, line: str) -> None:
        m = _DPKG_ACTION_RE.match(line)
        if not m:
            return
        ts, action, pkgarch, v1, v2 = m.groups()
        pkg = pkgarch.split(":")[0]
        if pkg in self._config.ignored_packages:
            return
        r = self._run
        if r.empty():
            r.first_ts = ts
        r.last_ts = ts
        r.last_seen = time.monotonic()
        if action == "install":
            if v1 == "<none>":
                r.installed[pkg] = v2
            else:  # reinstall/upgrade via install
                r.upgraded[pkg] = (v1, v2)
        elif action == "upgrade":
            r.upgraded[pkg] = (v1, v2)
        else:  # remove / purge
            r.installed.pop(pkg, None)
            r.removed[pkg] = v1

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(5)
            try:
                if not self._run.empty() and time.monotonic() - self._run.last_seen >= self._config.summary_quiet_seconds:
                    run, self._run = self._run, _Run()
                    await self._fire_summary(run)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._logger.exception("Could not send package summary")

    def _who(self, run: _Run) -> list[str]:
        """Distinct 'Requested-By: command' lines from apt history entries in the run."""
        try:
            with open(self._config.apt_history_path, errors="replace") as f:
                f.seek(max(0, os.path.getsize(self._config.apt_history_path) - 200_000))
                blocks = parse_apt_history(f.read())
        except OSError:
            return []
        first, last = _parse_ts(run.first_ts), _parse_ts(run.last_ts)
        if not first or not last:
            return []
        slack = timedelta(seconds=30)
        seen: list[str] = []
        for b in blocks:
            start = _parse_ts(b.get("Start-Date", ""))
            if not start or not (first - slack <= start <= last + slack):
                continue
            who = b.get("Requested-By", "").split(" (")[0] or "root"
            cmd = b.get("Commandline", "?")
            if cmd == "/usr/bin/unattended-upgrade":
                entry = "unattended-upgrades"
            else:
                entry = f"{who}: {cmd}"
            if entry not in seen:
                seen.append(entry)
        return seen

    async def _fire_summary(self, run: _Run) -> None:
        n_i, n_u, n_r = len(run.installed), len(run.upgraded), len(run.removed)
        notable = (n_i and self._config.alert_on_install) or (n_r and self._config.alert_on_remove)
        counts = ", ".join(
            f"{n} {word}" for n, word in ((n_i, "installed"), (n_r, "removed"), (n_u, "upgraded")) if n
        )
        who = self._who(run)
        lines = [f"{run.first_ts} – {run.last_ts[11:]}: {counts}"]
        if who:
            lines.append("By: " + "; ".join(who))
        if n_i:
            lines.append("Installed: " + _names(run.installed, lambda k, v: f"{k} {v}"))
        if n_r:
            lines.append("Removed: " + _names(run.removed))
        if n_u:
            lines.append("Upgraded: " + _names(run.upgraded))
        await self._alerts.fire(Alert(
            rule_id="package_activity",
            severity=Severity.WARN if notable else Severity.INFO,
            title=f"Packages: {counts}" + (" (unattended)" if who == ["unattended-upgrades"] else ""),
            message="\n".join(lines),
            source_monitor=self.name,
            context={
                "first": run.first_ts,
                "last": run.last_ts,
                "installed": sorted(run.installed),
                "removed": sorted(run.removed),
                "upgraded": sorted(run.upgraded),
                "requested_by": who,
            },
            subject=f"run={run.first_ts}",
        ))

    async def _tail_file(self, path: str) -> AsyncIterator[str]:
        while not os.path.exists(path):
            self._logger.warning("%s not found — waiting", path)
            await asyncio.sleep(5)
            if not self._running:
                return
        try:
            async with aiofiles.open(path, "r", errors="replace") as f:
                await f.seek(0, 2)
                current_inode = os.stat(path).st_ino
                while self._running:
                    line = await f.readline()
                    if line:
                        yield line
                    else:
                        try:
                            if os.stat(path).st_ino != current_inode:
                                self._logger.info("dpkg.log rotated, reopening")
                                return
                        except FileNotFoundError:
                            return
                        await asyncio.sleep(0.5)
        except PermissionError:
            self._logger.error("Permission denied: %s — package monitor disabled", path)
