from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cop.alerts import Alert, Severity
from cop.sinks.base import AlertSink

if TYPE_CHECKING:
    from cop.alerts import Alert
    from cop.config import TelegramConfig

logger = logging.getLogger("cop.sinks.telegram")

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🚨",
    Severity.WARN: "⚠️",
    Severity.INFO: "ℹ️",
}


def _risk_line(context: dict) -> str:
    if "ollama_risk" not in context:
        return ""
    risk = context["ollama_risk"]
    comment = context.get("ollama_comment", "")
    if risk <= 1:
        emoji = "😐"
    elif risk <= 5:
        emoji = "🤨🤨"
    elif risk <= 8:
        emoji = "😨😨😨"
    else:
        emoji = "🤬🤬🤬🤬"
    base = f"🤖{emoji} Risk: {risk}/10"
    return f"{base} — {comment}" if comment else base


def _esc(text: str) -> str:
    """Escape text for Telegram's HTML parse mode (<, >, &)."""
    return html.escape(str(text), quote=False)


def _alert_key(alert: Alert) -> str:
    data = f"{alert.rule_id}:{alert.fired_at.isoformat()}"
    return hashlib.md5(data.encode()).hexdigest()[:8]


class TelegramSink(AlertSink):
    def __init__(self, config: TelegramConfig, data_dir: Path) -> None:
        self._config = config
        self._data_dir = data_dir
        self._app: Any = None
        self._monitors: dict[str, Any] = {}
        self._scorer: Any = None
        self._db: Any = None
        self._pending_alerts: dict[str, Any] = {}       # key -> Alert
        self._pending_note: dict[int, Any] = {}         # user_id -> Alert
        self._pending_exec: dict[int, list[str]] = {}   # user_id -> parsed args

    def set_monitors(self, monitors: dict[str, Any]) -> None:
        self._monitors = monitors

    def set_scorer(self, scorer: Any) -> None:
        self._scorer = scorer

    def set_db(self, db: Any) -> None:
        self._db = db

    async def start(self) -> None:
        from telegram.ext import Application, CallbackQueryHandler, CommandHandler, MessageHandler, filters

        app = Application.builder().token(self._config.bot_token).build()
        app.add_handler(CallbackQueryHandler(self._on_callback))
        app.add_handler(CommandHandler("exec", self._on_exec))
        app.add_handler(CommandHandler("health", self._on_health))
        app.add_handler(CommandHandler("assessment", self._on_assessment))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self._on_message))

        await app.initialize()
        await app.start()
        await app.updater.start_polling(drop_pending_updates=True)
        self._app = app
        logger.info("Telegram polling started")

    async def send(self, alert: Alert) -> bool:
        if not self._config.enabled or self._app is None:
            return False
        try:
            key = _alert_key(alert)
            # Stored with the alert, so the buttons still work after a restart
            # or once the alert has left the in-memory cache (_lookup_alert).
            alert.context["alert_key"] = key
            self._pending_alerts[key] = alert
            if len(self._pending_alerts) > 200:
                oldest = next(iter(self._pending_alerts))
                del self._pending_alerts[oldest]

            sev_emoji = _SEVERITY_EMOJI.get(alert.severity, "❗")
            # Alert text is escaped: a "<" (e.g. "Parents: bash < sshd") or "&"
            # made Telegram reject the whole message as bad HTML, losing the alert.
            text = f"{sev_emoji} <b>{_esc(alert.title)}</b>\n\n{_esc(alert.message)}"
            plain = f"{sev_emoji} {alert.title}\n\n{alert.message}"
            risk = _risk_line(alert.context)
            if risk:
                text += f"\n\n{_esc(risk)}"
                plain += f"\n\n{risk}"

            from telegram import InlineKeyboardButton, InlineKeyboardMarkup

            keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("✅ Mark Expected", callback_data=f"b:{key}"),
                InlineKeyboardButton("📝 Prompt", callback_data=f"n:{key}"),
                InlineKeyboardButton("🔍 Details", callback_data=f"d:{key}"),
            ]])
            silent = alert.severity.value == "INFO"  # audit trail: no sound or buzz
            try:
                await self._app.bot.send_message(
                    chat_id=self._config.chat_id, text=text, parse_mode="HTML",
                    reply_markup=keyboard, disable_notification=silent,
                )
            except Exception as exc:
                if "parse" not in str(exc).lower() and "entit" not in str(exc).lower():
                    raise
                # Never lose an alert to formatting: resend as plain text
                logger.warning("Telegram rejected HTML (%s); sending as plain text", exc)
                await self._app.bot.send_message(
                    chat_id=self._config.chat_id, text=plain,
                    reply_markup=keyboard, disable_notification=silent,
                )
            return True
        except Exception as exc:
            logger.warning("Telegram send failed: %s", exc)
            return False

    async def send_text(self, text: str) -> None:
        if not self._config.enabled or self._app is None:
            return
        try:
            await self._app.bot.send_message(chat_id=self._config.chat_id, text=text)
        except Exception as exc:
            logger.warning("Telegram notify failed: %s", exc)

    async def close(self) -> None:
        if self._app is not None:
            try:
                await self._app.updater.stop()
                await self._app.stop()
                await self._app.shutdown()
            except Exception as exc:
                logger.warning("Telegram shutdown error: %s", exc)

    def _is_authorized(self, user_id: int) -> bool:
        ids = self._config.allowed_user_ids
        if not ids:
            return True
        if isinstance(ids, int):
            return user_id == ids
        return user_id in ids

    async def _on_callback(self, update: Any, context: Any) -> None:
        query = update.callback_query
        await query.answer()
        user_id = query.from_user.id
        if not self._is_authorized(user_id):
            await query.edit_message_text("⛔ Not authorized.")
            return

        action, _, key = query.data.partition(":")
        alert = await self._lookup_alert(key)

        if action == "b":
            if alert is None:
                await query.edit_message_text("⚠️ Alert not found (older than the alert history?).")
                return
            msg = await self._do_learn_one(alert)
            await query.edit_message_text(msg)

        elif action == "n":
            if alert is None:
                await query.edit_message_text("⚠️ Alert expired from memory.")
                return
            self._pending_note[user_id] = alert
            await self._app.bot.send_message(
                chat_id=self._config.chat_id,
                text=f"📝 Explain why <b>{_esc(alert.title)}</b> is benign (this will suppress future false positives):\n<i>e.g. \"was a one-time speedtest\", \"scheduled backup job\"</i>",
                parse_mode="HTML",
            )

        elif action == "d":
            if alert is None:
                await query.edit_message_text("⚠️ Alert expired from memory.")
                return
            ctx_text = json.dumps(alert.context, indent=2, default=str)[:3500]
            await self._app.bot.send_message(
                chat_id=self._config.chat_id,
                text=f"<pre>{_esc(ctx_text)}</pre>",
                parse_mode="HTML",
            )

    async def _on_message(self, update: Any, context: Any) -> None:
        message = update.message
        user_id = message.from_user.id
        if not self._is_authorized(user_id):
            return
        text = message.text.strip()

        if user_id in self._pending_exec:
            cmd = self._pending_exec.pop(user_id)
            if text.upper() == "YES":
                await self._run_exec(cmd, message)
            else:
                await message.reply_text("❌ Cancelled.")
            return

        if user_id in self._pending_note:
            alert = self._pending_note.pop(user_id)
            await self._append_note(alert, text)
            await message.reply_text("📝 Note saved to context.md.")
            return

    async def _on_health(self, update: Any, context: Any) -> None:
        message = update.message
        if not self._is_authorized(message.from_user.id):
            await message.reply_text("⛔ Not authorized.")
            return
        await message.reply_text("🔍 Gathering health data…")
        from cop import health
        summary = await health.gather()
        await message.reply_text(summary or "No data.")

    async def _on_assessment(self, update: Any, context: Any) -> None:
        message = update.message
        if not self._is_authorized(message.from_user.id):
            await message.reply_text("⛔ Not authorized.")
            return
        if self._scorer is None:
            await message.reply_text("⚠️ Ollama is not enabled — set ollama.enabled: true in config.")
            return
        await message.reply_text("🛰️ Running assessment…")
        from cop import health
        health_text = await health.gather()
        context_notes = ""
        context_path = self._data_dir / "context.md"
        if context_path.exists():
            context_notes = context_path.read_text().strip()
        limit = self._scorer._config.history_count
        recent_alerts: list = []
        if self._db is not None:
            recent_alerts = await self._db.get_recent_alerts(limit=limit)
        result = await self._scorer.assess(health_text, context_notes, recent_alerts)
        full = result + "\n\n─────────────────────\n\n" + (health_text or "No health data.")
        for chunk in [full[i:i+4000] for i in range(0, max(len(full), 1), 4000)]:
            await message.reply_text(chunk)

    async def _on_exec(self, update: Any, context: Any) -> None:
        message = update.message
        user_id = message.from_user.id
        if not self._is_authorized(user_id):
            await message.reply_text("⛔ Not authorized.")
            return

        cmd = " ".join(context.args) if context.args else ""
        if not cmd:
            await message.reply_text("Usage: /exec <command>")
            return

        try:
            args = shlex.split(cmd)
        except ValueError as exc:
            await message.reply_text(f"❌ Bad command syntax: {exc}")
            return
        if not args:
            await message.reply_text("Usage: /exec <command>")
            return
        executable = args[0]
        if not any(executable == prefix or cmd.startswith(prefix + " ") or cmd == prefix
                   for prefix in self._config.allowed_commands):
            await message.reply_text(f"❌ Not in whitelist: {cmd}")
            return

        if self._config.confirm_destructive:
            self._pending_exec[user_id] = args
            await message.reply_text(f"⚠️ Confirm: run `{cmd}`?\nReply YES to proceed.")
            return

        await self._run_exec(args, message)

    async def _run_exec(self, args: list[str], message: Any) -> None:
        cmd = shlex.join(args)
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            except asyncio.TimeoutError:
                proc.kill()
                await message.reply_text(f"⏱ Command timed out: {cmd}")
                return
            output = stdout.decode(errors="replace")[:3500]
            rc = proc.returncode
            icon = "✅" if rc == 0 else "❌"
            await message.reply_text(
                f"{icon} <code>{_esc(cmd)}</code> (exit {rc})\n<pre>{_esc(output)}</pre>",
                parse_mode="HTML",
            )
        except Exception as exc:
            logger.warning("exec failed: %s", exc)
            await message.reply_text(f"❌ Error: {exc}")

    async def _lookup_alert(self, key: str) -> Any:
        alert = self._pending_alerts.get(key)
        if alert is not None or self._db is None:
            return alert
        try:
            row = await self._db.get_alert_by_key(key)
        except Exception as exc:
            logger.warning("Alert lookup failed: %s", exc)
            return None
        if row is None:
            return None
        from datetime import datetime
        alert = Alert(
            rule_id=row["rule_id"],
            severity=Severity(row["severity"]),
            title=row["title"],
            message=row["message"],
            source_monitor=row["source_monitor"],
            context=json.loads(row["context_json"] or "{}"),
            fired_at=datetime.fromisoformat(row["fired_at"]),
        )
        self._pending_alerts[key] = alert
        return alert

    async def _do_learn_one(self, alert: Any) -> str:
        monitor = self._monitors.get(alert.source_monitor)
        if monitor is None:
            return f"⚠️ Monitor {alert.source_monitor} isn't running."
        try:
            return await monitor.mark_expected(alert)
        except Exception as exc:
            logger.warning("mark_expected failed for %s: %s", alert.rule_id, exc)
            return f"⚠️ Failed to update baseline: {exc}"

    async def _append_note(self, alert: Any, note: str) -> None:
        context_path = self._data_dir / "context.md"
        entry = f"- EXPLAINED: {alert.title} — {note}\n"
        try:
            with open(context_path, "a") as f:
                f.write(entry)
        except Exception as exc:
            logger.warning("Failed to append to context.md: %s", exc)
