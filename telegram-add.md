# Plan: Interactive Two-Way Alerting via Telegram

## Should You Shift to Telegram?

**Yes.** Telegram gives you:
- Free-form replies (ntfy cannot do this — it has no reply concept)
- Inline buttons for one-tap actions (ntfy "actions" require a separate HTTP server)
- Message threading (each alert is a message you can reply to)
- Excellent async Python library (`python-telegram-bot` with full `asyncio` support)
- No self-hosting required

The main cost: create a bot via BotFather (2 minutes), get a `bot_token` and your `chat_id`, add them to config. ntfy stays in the codebase as an optional parallel sink for users who don't want Telegram.

---

## Context

cop currently sends one-way alerts via ntfy.sh. The goal is to close the feedback loop: reply to alerts to update baselines, annotate context for the AI, or trigger real system actions. ntfy supports static action buttons but not free-form replies, making it unsuitable. Telegram's Bot API supports rich two-way conversations, inline keyboards, and free-form text.

---

## Three Reply Intents

| User says | Bot does |
|-----------|----------|
| "expected activity" / `[✅ Mark Expected]` button | Adds the alert's data to the SQLite baseline — alert won't fire again |
| "normal, keep watching" / `[📝 Keep Watching]` button | Appends a timestamped note to `context.md`, injected into future Ollama prompts |
| "shut docker down" / `/exec docker stop mycontainer` | Runs a whitelisted shell command and replies with stdout/stderr |

---

## Architecture

### New: `cop/sinks/telegram.py`

The main new file. Parallel to `cop/sinks/ntfy.py`.

**`send_alert(alert)`:**
- Formats message with title, body, AI risk score (emoji + number)
- Sends via `Bot.send_message()` with `InlineKeyboardMarkup`:
  - `[✅ Mark Expected]` → callback `baseline:{rule_id}:{alert_hash}`
  - `[📝 Keep Watching]` → prompts user to add a note
  - `[🔍 Show Details]` → sends full `alert.context` as a code block
- Stores `alert_id → telegram_message_id` mapping for reply threading

**Polling loop (asyncio Task):**
- `CallbackQueryHandler` — handles inline button taps
- `MessageHandler` — handles free-form text and `/commands`
- Auth gate: only processes messages from `allowed_user_ids`

### Handler: `handle_baseline(alert)`

- Looks up `alert.source_monitor` to pick the right baseline table
- Calls a new `monitor.learn_one(data)` method (see below)
- Replies: "✅ Added to baseline. This alert won't fire again."

### Handler: `handle_note(alert, note_text)`

Appends to `~/.local/share/cop/context.md`:
```markdown
## 2026-05-03 14:32 — new_listen_port
Port 8888: normal, python3 dev server. Keep watching for unusual traffic patterns.
```

### Handler: `handle_exec(command_str)`

- Prefix-matches against `allowed_commands` whitelist
- If `confirm_destructive: true`, sends confirmation prompt — waits for "YES"
- On confirm: `asyncio.create_subprocess_exec()` with timeout
- Sends stdout/stderr back to the chat

---

## Files to Create / Modify

| File | Action | What changes |
|------|--------|--------------|
| `cop/sinks/telegram.py` | **Create** | New Telegram sink with polling loop and all handlers |
| `cop/config.py` | **Modify** | Add `TelegramConfig` dataclass |
| `cop/ollama.py` | **Modify** | Load `context.md` and inject into Ollama system prompt |
| `cop/main.py` | **Modify** | Wire up Telegram sink, start polling task, cancel on shutdown |
| `cop/monitors/process.py` | **Modify** | Add `learn_one(context)` method |
| `cop/monitors/network.py` | **Modify** | Add `learn_one(context)` method |
| `cop/monitors/docker_.py` | **Modify** | Add `learn_one(context)` method |
| `cop/monitors/auth.py` | **Modify** | Add `learn_one(context)` method |
| `config.example.yaml` | **Modify** | Add `telegram:` section |
| `pyproject.toml` | **Modify** | Add `python-telegram-bot>=20` dependency |

---

## New Config Section

```yaml
telegram:
  enabled: false
  bot_token: ""          # from BotFather
  chat_id: ""            # your personal or group chat ID
  allowed_user_ids: []   # Telegram user IDs allowed to issue commands
  allowed_commands:      # prefix whitelist for /exec
    - "docker stop"
    - "docker restart"
    - "systemctl stop"
    - "kill"
  confirm_destructive: true   # require "YES" before exec runs
```

---

## `TelegramConfig` Dataclass

```python
@dataclass
class TelegramConfig:
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""
    allowed_user_ids: list[int] = field(default_factory=list)
    allowed_commands: list[str] = field(default_factory=list)
    confirm_destructive: bool = True
```

---

## Ollama Context Injection

In `OllamaScorer.score()`, load `context.md` if it exists and prepend it to the system prompt:

```python
context_path = data_dir / "context.md"
if context_path.exists():
    notes = context_path.read_text()
    system_prompt = f"Operator notes (consider when scoring):\n{notes}\n\n{base_prompt}"
```

This lets the AI factor in your running commentary when rating future alerts.

---

## `learn_one()` on Monitors

Each monitor needs a `learn_one(context: dict)` method that inserts a single row from an alert's context dict into the relevant baseline table. Currently only `learn()` (bulk snapshot) exists.

Example for `NetworkMonitor.learn_one()`:
```python
async def learn_one(self, context: dict) -> None:
    port = context.get("port")
    proto = context.get("proto", "tcp")
    if port:
        await self._db.execute(
            "INSERT OR IGNORE INTO port_baseline (proto, local_port) VALUES (?, ?)",
            (proto, port)
        )
        await self._db.commit()
```

---

## Alert Message Format

```
🚨 New Listen Port Detected

Port 8888 (TCP) — python3 (PID 12345)
Risk: 😨😨😨 7/10 — "unexpected dev server, verify intent"

[✅ Mark Expected]  [📝 Keep Watching]  [🔍 Details]
```

---

## Verification Steps

1. Create bot via BotFather, get `bot_token`; get your `chat_id` (message the bot, call `/getUpdates`)
2. Add both to `config.yaml`, set `telegram.enabled: true`
3. `sudo cop run` — confirm "✅ cop started" arrives in Telegram
4. Open port: `nc -l 9999` — alert should arrive with buttons
5. Tap "Mark Expected" — confirm `port_baseline` row inserted
6. Re-trigger same port — confirm alert suppressed
7. Reply "this is my dev server, keep watching" — confirm `context.md` updated
8. Reply `/exec docker stop testcontainer` — confirm confirmation prompt, then exec
9. Restart cop — confirm Ollama prompt now reflects `context.md` content
