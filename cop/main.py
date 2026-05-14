from __future__ import annotations

import asyncio
import datetime
import logging
import signal

import aiohttp

from cop.alerts import AlertEngine
from cop.baseline import BaselineDB
from cop.config import CopConfig, NtfyConfig
from cop.ollama import OllamaScorer
from cop.monitors.auth import AuthMonitor
from cop.monitors.docker_ import DockerMonitor
from cop.monitors.file import FileMonitor
from cop.monitors.kernel import KernelMonitor
from cop.monitors.network import NetworkMonitor
from cop.monitors.package import PackageMonitor
from cop.monitors.persistence import PersistenceMonitor
from cop.monitors.process import ProcessMonitor
from cop.monitors.resource import ResourceMonitor
from cop.sinks.jsonlog import JsonLogSink
from cop.sinks.ntfy import NtfySink
from cop.sinks.telegram import TelegramSink


async def _ntfy_notify(session: aiohttp.ClientSession, config: NtfyConfig, title: str, message: str, tags: str = "shield") -> None:
    if not config.enabled:
        return
    headers = {"X-Title": title, "X-Priority": "3", "X-Tags": tags}
    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"
    try:
        async with session.post(
            config.url,
            data=message.encode(),
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=config.timeout_seconds),
        ) as resp:
            if resp.status >= 400:
                logging.getLogger("cop.main").warning("ntfy lifecycle notify returned HTTP %d", resp.status)
    except Exception as exc:
        logging.getLogger("cop.main").warning("ntfy lifecycle notify failed: %s", exc)


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(name)-30s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def build_monitors(config: CopConfig, baseline: BaselineDB, engine: AlertEngine) -> list:
    m = config.monitors
    poll = config.general.poll_interval_seconds
    monitors = []
    if m.process.enabled:
        monitors.append(ProcessMonitor(m.process, baseline, engine, poll_interval=poll))
    if m.network.enabled:
        monitors.append(NetworkMonitor(m.network, baseline, engine, poll_interval=poll))
    if m.resource.enabled:
        monitors.append(ResourceMonitor(m.resource, baseline, engine))
    if m.auth.enabled:
        monitors.append(AuthMonitor(m.auth, baseline, engine))
    if m.docker.enabled:
        monitors.append(DockerMonitor(m.docker, baseline, engine))
    if m.file.enabled:
        monitors.append(FileMonitor(m.file, baseline, engine))
    if m.persistence.enabled:
        monitors.append(PersistenceMonitor(m.persistence, baseline, engine))
    if m.package.enabled:
        monitors.append(PackageMonitor(m.package, baseline, engine))
    if m.kernel.enabled:
        monitors.append(KernelMonitor(m.kernel, baseline, engine))
    return monitors


async def run_daemon(config: CopConfig) -> None:
    setup_logging(config.general.log_level)
    logger = logging.getLogger("cop.main")

    config.data_path.mkdir(parents=True, exist_ok=True)

    async with BaselineDB(config.db_path) as db:
        async with aiohttp.ClientSession() as session:
            sinks = []
            if config.ntfy.enabled:
                sinks.append(NtfySink(config.ntfy, session))
            if config.log_sink.enabled:
                sinks.append(JsonLogSink(config.log_sink))

            telegram_sink: TelegramSink | None = None
            if config.telegram.enabled:
                telegram_sink = TelegramSink(config.telegram, config.data_path)
                sinks.append(telegram_sink)

            scorer = OllamaScorer(config.ollama, session, data_dir=config.data_path) if config.ollama.enabled else None
            engine = AlertEngine(config.alerts, db, sinks, scorer=scorer, ollama_config=config.ollama if scorer else None)
            monitors = build_monitors(config, db, engine)

            if telegram_sink is not None:
                telegram_sink.set_monitors({m.name: m for m in monitors})
                telegram_sink.set_db(db)
                if scorer is not None:
                    telegram_sink.set_scorer(scorer)
                try:
                    await telegram_sink.start()
                except Exception:
                    logger.exception("Telegram sink failed to start — continuing without it")
                    sinks.remove(telegram_sink)
                    telegram_sink = None

            if not monitors:
                logger.warning("No monitors enabled — exiting")
                return

            tasks = [await m.start() for m in monitors]
            logger.info("cop started with %d monitors: %s", len(monitors), [m.name for m in monitors])
            if config.config_path:
                mtime = datetime.datetime.fromtimestamp(config.config_path.stat().st_mtime).strftime("%Y-%m-%dT%H:%M:%S")
                config_info = f"config: {config.config_path} (modified {mtime})"
            else:
                config_info = "config: defaults (no file found)"
            await _ntfy_notify(session, config.ntfy, "cop started", f"{len(monitors)} monitors active\n{config_info}", tags="white_check_mark")
            if telegram_sink is not None:
                await telegram_sink.send_text(f"✅ cop started\n{len(monitors)} monitors active\n{config_info}")

            loop = asyncio.get_running_loop()
            stop_event = asyncio.Event()

            def _shutdown(sig: signal.Signals) -> None:
                logger.info("Received %s, shutting down...", sig.name)
                stop_event.set()

            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, lambda s=sig: _shutdown(s))

            await stop_event.wait()

            if telegram_sink is not None:
                await telegram_sink.send_text("🛑 cop stopping")
            await _ntfy_notify(session, config.ntfy, "cop stopped", "Daemon shutting down", tags="zzz")
            logger.info("Stopping monitors...")
            for m in monitors:
                await m.stop()
            for sink in sinks:
                await sink.close()
            logger.info("cop stopped cleanly")


async def run_learn(config: CopConfig) -> None:
    setup_logging(config.general.log_level)
    logger = logging.getLogger("cop.learn")
    config.data_path.mkdir(parents=True, exist_ok=True)

    async with BaselineDB(config.db_path) as db:
        async with aiohttp.ClientSession() as session:
            engine = AlertEngine(config.alerts, db, [])
            monitors = build_monitors(config, db, engine)
            for m in monitors:
                try:
                    await m.learn()
                except Exception:
                    logger.exception("Failed to learn baseline for %s", m.name)

    logger.info("Baseline learning complete — DB: %s", config.db_path)


async def show_baseline(config: CopConfig, table: str) -> None:
    if not config.db_path.exists():
        print(f"Baseline DB not found at {config.db_path}\nRun 'cop learn' first.")
        return
    async with BaselineDB(config.db_path) as db:
        if table in ("processes", "all"):
            procs = await db.get_process_baseline()
            print(f"\n=== Processes ({len(procs)}) ===")
            for p in procs:
                print(f"  {(p.get('username') or '?'):20}  {p['name']:30}  {p.get('exe') or ''}")
        if table in ("ports", "all"):
            ports = await db.get_port_baseline()
            print(f"\n=== Listening Ports ({len(ports)}) ===")
            for p in ports:
                print(f"  {p['proto']:4}  {p['local_addr']:20}  :{p['local_port']:<6}  {p.get('process_name') or ''}")
        if table in ("containers", "all"):
            containers = await db.get_container_baseline()
            print(f"\n=== Containers ({len(containers)}) ===")
            for c in containers:
                print(f"  {c['name']:30}  {c['image']}")


async def show_alerts(config: CopConfig, limit: int, severity: str | None) -> None:
    if not config.db_path.exists():
        print(f"No DB at {config.db_path}")
        return
    async with BaselineDB(config.db_path) as db:
        alerts = await db.get_recent_alerts(limit=limit, severity=severity)
    if not alerts:
        print("No alerts found")
        return
    for a in alerts:
        deduped = " [dedup]" if a["deduped"] else ""
        print(f"[{a['fired_at']}] {a['severity']:8}  {a['rule_id']:35}  {a['title']}{deduped}")


async def show_status(config: CopConfig) -> None:
    print(f"DB path:    {config.db_path}")
    print(f"Alert log:  {config.log_path}")
    if not config.db_path.exists():
        print("Baseline:   not found (run 'cop learn' first)")
        return
    async with BaselineDB(config.db_path) as db:
        age = await db.get_baseline_age()
        counts = await db.get_alert_counts()
    print(f"Baseline since: {age or 'no baseline yet'}")
    print("Alert counts (sent, non-deduped):")
    for sev in ("CRITICAL", "WARN", "INFO"):
        print(f"  {sev}: {counts.get(sev, 0)}")
