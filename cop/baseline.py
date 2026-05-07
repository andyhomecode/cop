from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS process_baseline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    exe         TEXT,
    username    TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE(name, exe, username)
);

CREATE TABLE IF NOT EXISTS port_baseline (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    proto        TEXT NOT NULL,
    local_addr   TEXT NOT NULL,
    local_port   INTEGER NOT NULL,
    process_name TEXT,
    created_at   TEXT NOT NULL,
    UNIQUE(proto, local_port)
);

CREATE TABLE IF NOT EXISTS container_baseline (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    image        TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resource_baseline (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_time   TEXT NOT NULL,
    cpu_percent   REAL,
    mem_percent   REAL,
    net_send_mbps REAL,
    net_recv_mbps REAL
);

CREATE TABLE IF NOT EXISTS alert_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id        TEXT NOT NULL,
    severity       TEXT NOT NULL,
    title          TEXT NOT NULL,
    message        TEXT NOT NULL,
    context_json   TEXT,
    source_monitor TEXT NOT NULL,
    fired_at       TEXT NOT NULL,
    sent_ntfy      INTEGER NOT NULL DEFAULT 0,
    deduped        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alert_rule_fired ON alert_history(rule_id, fired_at);

CREATE TABLE IF NOT EXISTS ssh_sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT NOT NULL UNIQUE,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    login_count INTEGER NOT NULL DEFAULT 1
);
"""


class BaselineDB:
    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def open(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # --- process baseline ---

    async def get_process_baseline(self) -> list[dict]:
        async with self._db.execute(
            "SELECT name, exe, username FROM process_baseline"
        ) as cur:
            return [dict(row) for row in await cur.fetchall()]

    async def set_process_baseline(self, procs: list[dict]) -> None:
        await self._db.execute("DELETE FROM process_baseline")
        now = self._now()
        await self._db.executemany(
            "INSERT OR IGNORE INTO process_baseline(name, exe, username, created_at) VALUES (?,?,?,?)",
            [(p["name"], p.get("exe"), p.get("username"), now) for p in procs],
        )
        await self._db.commit()

    async def add_process_to_baseline(self, proc: dict) -> None:
        await self._db.execute(
            "INSERT OR IGNORE INTO process_baseline(name, exe, username, created_at) VALUES (?,?,?,?)",
            (proc["name"], proc.get("exe"), proc.get("username"), self._now()),
        )
        await self._db.commit()

    # --- port baseline ---

    async def get_port_baseline(self) -> list[dict]:
        async with self._db.execute(
            "SELECT proto, local_addr, local_port, process_name FROM port_baseline"
        ) as cur:
            return [dict(row) for row in await cur.fetchall()]

    async def set_port_baseline(self, ports: list[dict]) -> None:
        await self._db.execute("DELETE FROM port_baseline")
        now = self._now()
        await self._db.executemany(
            "INSERT OR IGNORE INTO port_baseline(proto, local_addr, local_port, process_name, created_at) VALUES (?,?,?,?,?)",
            [(p["proto"], p["local_addr"], p["local_port"], p.get("process_name"), now) for p in ports],
        )
        await self._db.commit()

    async def add_port_to_baseline(self, port: dict) -> None:
        await self._db.execute(
            "INSERT OR IGNORE INTO port_baseline(proto, local_addr, local_port, process_name, created_at) VALUES (?,?,?,?,?)",
            (port["proto"], port["local_addr"], port["local_port"], port.get("process_name"), self._now()),
        )
        await self._db.commit()

    # --- container baseline ---

    async def get_container_baseline(self) -> list[dict]:
        async with self._db.execute(
            "SELECT container_id, name, image FROM container_baseline"
        ) as cur:
            return [dict(row) for row in await cur.fetchall()]

    async def set_container_baseline(self, containers: list[dict]) -> None:
        await self._db.execute("DELETE FROM container_baseline")
        now = self._now()
        await self._db.executemany(
            "INSERT OR IGNORE INTO container_baseline(container_id, name, image, created_at) VALUES (?,?,?,?)",
            [(c["container_id"], c["name"], c["image"], now) for c in containers],
        )
        await self._db.commit()

    async def add_container_to_baseline(self, name: str, image: str) -> None:
        await self._db.execute(
            "INSERT OR IGNORE INTO container_baseline(container_id, name, image, created_at) VALUES (?,?,?,?)",
            (name, name, image, self._now()),
        )
        await self._db.commit()

    # --- resource baseline ---

    async def add_resource_sample(self, sample: dict) -> None:
        await self._db.execute(
            "INSERT INTO resource_baseline(sample_time, cpu_percent, mem_percent, net_send_mbps, net_recv_mbps) VALUES (?,?,?,?,?)",
            (
                self._now(),
                sample.get("cpu_percent"),
                sample.get("mem_percent"),
                sample.get("net_send_mbps"),
                sample.get("net_recv_mbps"),
            ),
        )
        # Keep last 1440 rows (24h at 1-min samples)
        await self._db.execute(
            "DELETE FROM resource_baseline WHERE id NOT IN "
            "(SELECT id FROM resource_baseline ORDER BY id DESC LIMIT 1440)"
        )
        await self._db.commit()

    async def get_resource_stats(self) -> dict:
        async with self._db.execute(
            "SELECT AVG(cpu_percent), AVG(mem_percent), AVG(net_send_mbps), AVG(net_recv_mbps) FROM resource_baseline"
        ) as cur:
            row = await cur.fetchone()
            if not row or row[0] is None:
                return {}
            return {
                "avg_cpu": row[0],
                "avg_mem": row[1],
                "avg_send_mbps": row[2],
                "avg_recv_mbps": row[3],
            }

    # --- ssh sources ---

    async def get_ssh_sources(self) -> set[str]:
        async with self._db.execute("SELECT ip_address FROM ssh_sources") as cur:
            return {row[0] for row in await cur.fetchall()}

    async def add_ssh_source(self, ip: str) -> None:
        now = self._now()
        await self._db.execute(
            "INSERT INTO ssh_sources(ip_address, first_seen, last_seen, login_count) VALUES (?,?,?,1) "
            "ON CONFLICT(ip_address) DO UPDATE SET last_seen=excluded.last_seen, login_count=login_count+1",
            (ip, now, now),
        )
        await self._db.commit()

    # --- alert history ---

    async def record_alert(
        self,
        rule_id: str,
        severity: str,
        title: str,
        message: str,
        context_json: str,
        source_monitor: str,
        fired_at: str,
        sent_ntfy: bool,
        deduped: bool,
    ) -> None:
        await self._db.execute(
            "INSERT INTO alert_history "
            "(rule_id, severity, title, message, context_json, source_monitor, fired_at, sent_ntfy, deduped) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                rule_id,
                severity,
                title,
                message,
                context_json,
                source_monitor,
                fired_at,
                int(sent_ntfy),
                int(deduped),
            ),
        )
        await self._db.commit()

    async def get_recent_alerts(self, limit: int = 100, severity: str | None = None, minutes: int | None = None) -> list[dict]:
        from datetime import timedelta
        conditions: list[str] = []
        params: list = []
        if severity:
            conditions.append("severity=?")
            params.append(severity)
        if minutes is not None:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
            conditions.append("fired_at >= ?")
            params.append(cutoff)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        async with self._db.execute(
            f"SELECT * FROM alert_history {where} ORDER BY fired_at DESC LIMIT ?", params
        ) as cur:
            return [dict(row) for row in await cur.fetchall()]

    async def get_alert_counts(self) -> dict:
        async with self._db.execute(
            "SELECT severity, COUNT(*) FROM alert_history WHERE deduped=0 GROUP BY severity"
        ) as cur:
            return {row[0]: row[1] for row in await cur.fetchall()}

    async def get_baseline_age(self) -> str | None:
        async with self._db.execute("SELECT MIN(created_at) FROM process_baseline") as cur:
            row = await cur.fetchone()
            return row[0] if row else None

    async def __aenter__(self) -> "BaselineDB":
        await self.open()
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()
