from __future__ import annotations

import asyncio
from pathlib import Path

import click

from cop.config import load_config


@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config YAML (default: ~/.config/cop/config.yaml)",
)
@click.pass_context
def cli(ctx: click.Context, config: Path | None) -> None:
    """cop — security monitoring daemon"""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)


@cli.command()
@click.pass_context
def run(ctx: click.Context) -> None:
    """Start the monitoring daemon (foreground). systemd calls this."""
    from cop.main import run_daemon
    asyncio.run(run_daemon(ctx.obj["config"]))


@cli.command()
@click.pass_context
def learn(ctx: click.Context) -> None:
    """Snapshot current system state as the new baseline.

    Run this on first install and after intentional system changes
    to prevent false positives.
    """
    from cop.main import run_learn
    asyncio.run(run_learn(ctx.obj["config"]))


@cli.group()
def baseline() -> None:
    """Baseline management commands."""


@baseline.command(name="show")
@click.option(
    "--table",
    type=click.Choice(["processes", "ports", "containers", "all"]),
    default="all",
    show_default=True,
)
@click.pass_context
def baseline_show(ctx: click.Context, table: str) -> None:
    """Print current baseline contents."""
    from cop.main import show_baseline
    asyncio.run(show_baseline(ctx.obj["config"], table))


@baseline.command(name="update")
@click.pass_context
def baseline_update(ctx: click.Context) -> None:
    """Re-snapshot current state as baseline (alias for 'cop learn')."""
    from cop.main import run_learn
    asyncio.run(run_learn(ctx.obj["config"]))


@cli.command()
@click.option("--limit", "-n", default=50, show_default=True, help="Number of alerts to show")
@click.option(
    "--severity",
    type=click.Choice(["CRITICAL", "WARN", "INFO"]),
    default=None,
    help="Filter by severity",
)
@click.pass_context
def alerts(ctx: click.Context, limit: int, severity: str | None) -> None:
    """Show recent alerts from the database."""
    from cop.main import show_alerts
    asyncio.run(show_alerts(ctx.obj["config"], limit, severity))


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show baseline age, DB path, and alert counts."""
    from cop.main import show_status
    asyncio.run(show_status(ctx.obj["config"]))
