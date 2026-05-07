from __future__ import annotations

import asyncio
import logging
import re
import socket
import subprocess
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import aiohttp
import psutil

if TYPE_CHECKING:
    from cop.alerts import AlertEngine
    from cop.baseline import BaselineDB

_SS_BYTES_SENT_RE = re.compile(r'\bbytes_sent:(\d+)\b')
_SS_BYTES_RECV_RE = re.compile(r'\bbytes_received:(\d+)\b')
_SS_USERS_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')

# Shared across all monitor instances for the daemon's lifetime
_IP_CACHE: dict[str, str] = {}


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n / 1024 ** 2:.1f} MB"
    return f"{n / 1024 ** 3:.1f} GB"


class BaseMonitor(ABC):
    name: str = "BaseMonitor"

    def __init__(self, config: object, baseline: BaselineDB, alert_engine: AlertEngine):
        self._config = config
        self._baseline = baseline
        self._alerts = alert_engine
        self._logger = logging.getLogger(f"cop.{self.name}")
        self._running = False
        self._task: asyncio.Task | None = None
        # Snapshot updated each measurement cycle; _get_connections() diffs against it
        self._prev_conn_bytes: dict[tuple[str, int, str, int], dict] = {}
        # Remembers (laddr, lport, raddr, rport) → {process_name, pid} across intervals so
        # that TIME_WAIT connections (which have no process info) can still be attributed.
        self._conn_proc_cache: dict[tuple[str, int, str, int], dict] = {}

    async def start(self) -> asyncio.Task:
        self._running = True
        self._task = asyncio.create_task(self._safe_run(), name=self.name)
        return self._task

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _safe_run(self) -> None:
        try:
            await self.run()
        except asyncio.CancelledError:
            raise
        except Exception:
            self._logger.exception("%s crashed — monitor disabled until restart", self.name)

    @abstractmethod
    async def run(self) -> None:
        """Main monitor loop. Must check self._running and handle CancelledError."""

    @abstractmethod
    async def learn(self) -> None:
        """Snapshot current state into baseline DB."""

    # ------------------------------------------------------------------ #
    # Connection enrichment — shared by NetworkMonitor & ResourceMonitor   #
    # ------------------------------------------------------------------ #

    def _snapshot_connections(self) -> None:
        """Save the current ss byte snapshot as the baseline for the next delta.

        Call this alongside updating prev_net_bytes / prev_net_io so the connection
        snapshot is always co-timed with the byte counters.
        """
        new_bytes = self._connection_bytes()
        for key, info in new_bytes.items():
            if info.get("process_name"):
                self._conn_proc_cache[key] = {
                    "process_name": info["process_name"],
                    "pid": info["pid"],
                }
        self._prev_conn_bytes = new_bytes

    def _refresh_proc_cache(self) -> None:
        """Lightweight mid-interval ss scan (no -i) to catch short-lived connections.

        Upload/download bursts often open and close entirely within the polling sleep
        window, so they never appear in a full _snapshot_connections() call.  Sampling
        every few seconds here ensures their process info lands in _conn_proc_cache even
        after the socket transitions to TIME_WAIT.
        """
        try:
            out = subprocess.check_output(
                ["ss", "-t", "-n", "-p"],
                text=True, stderr=subprocess.DEVNULL, timeout=5,
            )
        except Exception:
            return
        for line in out.splitlines():
            if line[:1] in (" ", "\t"):
                continue
            parts = line.split()
            if len(parts) < 5 or parts[0] != "ESTAB":
                continue
            try:
                lraw, lport_s = parts[3].rsplit(":", 1)
                rraw, rport_s = parts[4].rsplit(":", 1)
                key = (lraw.strip("[]"), int(lport_s), rraw.strip("[]"), int(rport_s))
            except (ValueError, IndexError):
                continue
            users_m = _SS_USERS_RE.search(line)
            if users_m:
                self._conn_proc_cache[key] = {
                    "process_name": users_m.group(1),
                    "pid": int(users_m.group(2)),
                }

    async def _sleep_sampling(self, duration: float, step: float = 5.0) -> None:
        """Sleep for duration while refreshing the proc cache every step seconds."""
        remaining = duration
        while remaining > 0 and self._running:
            await asyncio.sleep(min(step, remaining))
            remaining -= step
            self._refresh_proc_cache()

    def _get_connections(self) -> list[dict]:
        """Connections active during the last measurement interval.

        Diffs the current ss snapshot against the baseline saved by
        _snapshot_connections(), so bytes reflect activity during the interval
        rather than cumulative totals since connection establishment.  Recently-
        closed (TIME_WAIT / CLOSE_WAIT) connections are included even though ss
        no longer reports bytes for them.  Sorted by total bytes descending.
        """
        current = self._connection_bytes()
        result: list[dict] = []
        seen: set[tuple[str, int, str, int]] = set()

        # Connections visible to ss (ESTAB): compute delta vs prev snapshot
        for key in set(current) | set(self._prev_conn_bytes):
            laddr, lport, raddr, rport = key
            cur = current.get(key, {})
            prv = self._prev_conn_bytes.get(key, {})
            if key not in self._prev_conn_bytes:
                # New connection: use its full bytes as the interval proxy
                delta_sent = cur.get("bytes_sent", 0)
                delta_recv = cur.get("bytes_received", 0)
            else:
                delta_sent = max(0, cur.get("bytes_sent", 0) - prv.get("bytes_sent", 0))
                delta_recv = max(0, cur.get("bytes_received", 0) - prv.get("bytes_received", 0))
            # Prefer process info from the current snapshot; fall back to previous
            pname = cur.get("process_name") or prv.get("process_name")
            pid = cur.get("pid") or prv.get("pid")
            seen.add(key)
            entry: dict = {
                "laddr": laddr, "lport": lport,
                "raddr": raddr, "rport": rport,
                "bytes_sent": delta_sent, "bytes_received": delta_recv,
            }
            if pname:
                entry["process_name"] = pname
            if pid is not None:
                entry["pid"] = pid
            result.append(entry)

        # Recently-closed connections (TIME_WAIT / CLOSE_WAIT) not in ss output
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status not in (psutil.CONN_TIME_WAIT, psutil.CONN_CLOSE_WAIT):
                    continue
                if not conn.raddr:
                    continue
                rip = conn.raddr.ip
                if rip.startswith("127.") or rip == "::1":
                    continue
                key = (conn.laddr.ip, conn.laddr.port, rip, conn.raddr.port)
                if key in seen:
                    continue
                seen.add(key)
                cached = self._conn_proc_cache.get(key, {})
                entry: dict = {
                    "laddr": conn.laddr.ip, "lport": conn.laddr.port,
                    "raddr": rip, "rport": conn.raddr.port,
                    "bytes_sent": 0, "bytes_received": 0,
                    "closed": True,
                }
                if cached.get("process_name"):
                    entry["process_name"] = cached["process_name"]
                    entry["pid"] = cached["pid"]
                result.append(entry)
        except psutil.AccessDenied:
            pass

        result.sort(key=lambda c: c["bytes_sent"] + c["bytes_received"], reverse=True)
        return result

    def _connection_bytes(self) -> dict[tuple[str, int, str, int], dict]:
        """Parse ss -t -n -i -p for cumulative per-connection byte counts (ESTAB only)."""
        result: dict[tuple[str, int, str, int], dict] = {}
        try:
            out = subprocess.check_output(
                ["ss", "-t", "-n", "-i", "-p"],
                text=True, stderr=subprocess.DEVNULL, timeout=5,
            )
        except Exception:
            return result
        conn_key: tuple[str, int, str, int] | None = None
        conn_proc: dict = {}
        for line in out.splitlines():
            if line[:1] in (" ", "\t"):
                if conn_key is not None:
                    sent_m = _SS_BYTES_SENT_RE.search(line)
                    recv_m = _SS_BYTES_RECV_RE.search(line)
                    if sent_m or recv_m:
                        result[conn_key] = {
                            "bytes_sent": int(sent_m.group(1)) if sent_m else 0,
                            "bytes_received": int(recv_m.group(1)) if recv_m else 0,
                            **conn_proc,
                        }
                    conn_key = None
                    conn_proc = {}
            else:
                parts = line.split()
                if len(parts) < 5 or parts[0] != "ESTAB":
                    conn_key = None
                    conn_proc = {}
                    continue
                try:
                    lraw, lport_s = parts[3].rsplit(":", 1)
                    rraw, rport_s = parts[4].rsplit(":", 1)
                    conn_key = (lraw.strip("[]"), int(lport_s), rraw.strip("[]"), int(rport_s))
                    users_m = _SS_USERS_RE.search(line)
                    conn_proc = (
                        {"process_name": users_m.group(1), "pid": int(users_m.group(2))}
                        if users_m else {}
                    )
                except (ValueError, IndexError):
                    conn_key = None
                    conn_proc = {}
        return result

    async def _format_connections(
        self,
        conns: list[dict],
        limit: int = 5,
        total_sent_bytes: int = 0,
        total_recv_bytes: int = 0,
    ) -> str:
        """Format connections grouped by process, sorted by data usage.

        When total_sent_bytes / total_recv_bytes are provided (the system-wide byte
        delta for the alert interval), unattributed traffic is distributed among
        closed-connection groups as estimates (~), giving them a realistic sort rank
        even though ss can't provide byte counts for TIME_WAIT sockets.
        """
        if not conns:
            return ""

        # Aggregate per (process_name, pid) — unknown processes share one bucket
        groups: dict[tuple, dict] = {}
        for conn in conns:
            key = (conn.get("process_name"), conn.get("pid"))
            if key not in groups:
                groups[key] = {
                    "bytes_sent": 0, "bytes_received": 0,
                    "count": 0, "closed": 0, "raddrs": [],
                }
            g = groups[key]
            g["bytes_sent"] += conn["bytes_sent"]
            g["bytes_received"] += conn.get("bytes_received", 0)
            g["count"] += 1
            if conn.get("closed"):
                g["closed"] += 1
            raddr = conn.get("raddr", "")
            if raddr and raddr not in g["raddrs"]:
                g["raddrs"].append(raddr)

        # Estimate unattributed bytes and distribute among closed-connection groups.
        # Closed sockets lose their ss byte stats; this gives them a realistic sort rank.
        total_attributed_sent = sum(g["bytes_sent"] for g in groups.values())
        total_attributed_recv = sum(g["bytes_received"] for g in groups.values())
        unattr_sent = max(0, total_sent_bytes - total_attributed_sent)
        unattr_recv = max(0, total_recv_bytes - total_attributed_recv)
        total_closed = sum(g["closed"] for g in groups.values())
        for g in groups.values():
            if total_closed > 0 and g["closed"] > 0:
                g["est_sent"] = int(unattr_sent * g["closed"] / total_closed)
                g["est_recv"] = int(unattr_recv * g["closed"] / total_closed)
            else:
                g["est_sent"] = 0
                g["est_recv"] = 0

        sorted_groups = sorted(
            groups.items(),
            key=lambda kv: (
                kv[1]["bytes_sent"] + kv[1]["bytes_received"]
                + kv[1]["est_sent"] + kv[1]["est_recv"],
                kv[1]["count"],
            ),
            reverse=True,
        )
        top_groups = sorted_groups[:limit]

        # Enrich up to 3 destination IPs per top group, all in parallel
        _MAX_DEST = 3
        all_ips = list(dict.fromkeys(
            ip
            for _, g in top_groups
            for ip in g["raddrs"][:_MAX_DEST]
        ))
        labels = await asyncio.gather(*[self._enrich_ip(ip) for ip in all_ips])
        label_map = dict(zip(all_ips, labels))

        total_c = len(conns)
        total_p = len(groups)
        lines = [
            f"Top processes "
            f"({total_c} conn{'s' if total_c != 1 else ''}, "
            f"{total_p} process{'es' if total_p != 1 else ''}):"
        ]
        for (pname, pid), g in top_groups:
            if pname and pid is not None:
                proc_label = f"{pname}/{pid}"
            elif pname:
                proc_label = pname
            elif pid is not None:
                proc_label = f"unknown/pid={pid}"
            else:
                proc_label = "unknown"

            size_parts = []
            if g["bytes_sent"]:
                size_parts.append(f"↑{_fmt_bytes(g['bytes_sent'])}")
            if g["bytes_received"]:
                size_parts.append(f"↓{_fmt_bytes(g['bytes_received'])}")
            est_total = g["est_sent"] + g["est_recv"]
            if est_total:
                size_parts.append(f"~{_fmt_bytes(est_total)}")
            if g["closed"]:
                size_parts.append(f"{g['closed']} closed")
            size_str = f" [{', '.join(size_parts)}]" if size_parts else ""

            # Show up to _MAX_DEST enriched destination IPs
            shown_ips = g["raddrs"][:_MAX_DEST]
            dest_parts = []
            for ip in shown_ips:
                label = label_map.get(ip, "")
                dest_parts.append(ip + (f" ({label})" if label else ""))
            extra_dests = len(g["raddrs"]) - len(shown_ips)
            dest = ""
            if dest_parts:
                dest = " → " + ", ".join(dest_parts)
                if extra_dests:
                    dest += f" +{extra_dests}"

            n = g["count"]
            lines.append(
                f"  {proc_label}{size_str}{dest} ({n} conn{'s' if n != 1 else ''})"
            )

        extra_procs = len(sorted_groups) - limit
        if extra_procs > 0:
            lines.append(f"  +{extra_procs} more process{'es' if extra_procs != 1 else ''}")
        return "\n".join(lines)

    async def _enrich_ip(self, ip: str) -> str:
        """Return 'hostname, Org Name' (or whichever parts resolve) for an IP. Cached."""
        if ip in _IP_CACHE:
            return _IP_CACHE[ip]
        hostname, org = await asyncio.gather(
            self._reverse_dns(ip),
            self._ip_org(ip),
        )
        parts = []
        if hostname:
            parts.append(hostname)
        if org and org not in parts:
            parts.append(org)
        label = ", ".join(parts)
        _IP_CACHE[ip] = label
        return label

    async def _reverse_dns(self, ip: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=2.0,
            )
            host = result[0]
            return host if host != ip else ""
        except Exception:
            return ""

    async def _ip_org(self, ip: str) -> str:
        """Look up the registered organisation for an IP via ipinfo.io."""
        try:
            timeout = aiohttp.ClientTimeout(total=3)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"https://ipinfo.io/{ip}/json") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        org = data.get("org", "")
                        # strip the leading ASN ("AS53420 Anthropic" -> "Anthropic")
                        if org and " " in org:
                            org = org.split(" ", 1)[1]
                        return org
        except Exception:
            pass
        return ""
