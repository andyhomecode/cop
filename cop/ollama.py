from __future__ import annotations

import json
import logging
import re
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import aiohttp

if TYPE_CHECKING:
    from cop.alerts import Alert
    from cop.config import OllamaConfig

logger = logging.getLogger("cop.ollama")

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
_JSON_RE = re.compile(r"\{[^{}]*\}", re.DOTALL)


class OllamaScorer:
    def __init__(self, config: OllamaConfig, session: aiohttp.ClientSession, data_dir: Path | None = None) -> None:
        self._config = config
        self._session = session
        self._data_dir = data_dir
        self._history: deque[tuple[datetime, str, str]] = deque(maxlen=config.history_count)

    async def score(self, alert: Alert) -> tuple[int, str]:
        """Call Ollama and return (risk 0-10, comment). Returns (0, 'Ollama Down') on connection failure."""
        prompt = (
            "You are a calm, experienced Linux security analyst. "
            "Score the actual risk of this alert, not just its surface appearance. "
            "Reserve 8-10 for clear attacks: brute-force, rootkits, unauthorized access, data exfiltration to unknown hosts. "
            "Score 5-7 for genuinely suspicious but possibly legitimate activity: unexpected shells, unknown SSH sources, new listening ports. "
            "Score 1-4 for routine admin activity that is worth logging but rarely dangerous: sudo usage, file changes, high bandwidth from known processes, docker events. "
            "Score 0 only if it is completely benign. "
            f"You will be given the last {self._config.history_count} scored events as context for what has been happening on the system. "
            "Use this history to inform your overall assessment — consider patterns, clustering of suspicious events, or whether the current alert fits a larger picture. "
            "Do not mention the history in your comment; just let it shape your understanding. "
            "Return only JSON with 'risk' (int 0-10) and 'comment' (string, max 30 words).\n"
            f"Rule: {alert.rule_id}. Title: {alert.title}. Detail: {alert.message}"
        )
        if self._history:
            now_s = datetime.now().strftime("%Y-%m-%d %H:%M")
            lines = [f"  {ts.strftime('%Y-%m-%d %H:%M')} — {rule}: {comment}"
                     for ts, rule, comment in self._history]
            history_block = (
                f"** last {len(self._history)} events **\n"
                + "\n".join(lines)
                + f"\n** end of last events, current timestamp is {now_s} **"
            )
            prompt = history_block + "\n\n" + prompt
        if self._data_dir:
            context_path = self._data_dir / "context.md"
            if context_path.exists():
                notes = context_path.read_text().strip()
                if notes:
                    prompt = "Operator background knowledge (historical one-off events already explained — NOT recent, do not treat as current context):\n" + notes + "\n\n" + prompt
        payload = {
            "model": self._config.model,
            "prompt": prompt,
            "stream": False,
        }
        try:
            async with self._session.post(
                self._config.url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self._config.timeout_seconds),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
                raw = _THINK_RE.sub("", data.get("response", "")).strip()
                m = _JSON_RE.search(raw)
                if not m:
                    raise ValueError(f"no JSON object in response: {raw[:100]!r}")
                parsed = json.loads(m.group())
                risk = max(0, min(10, int(parsed.get("risk", 0))))
                comment = str(parsed.get("comment", ""))
                self._history.append((datetime.now(), alert.rule_id, comment))
                logger.debug("Ollama scored %s: risk=%d %s", alert.rule_id, risk, comment)
                return risk, comment
        except Exception as exc:
            logger.error("Ollama scoring failed for %s: %s: %s", alert.rule_id, type(exc).__name__, exc)
            return 0, "Ollama Down"

    async def assess(self, health_text: str, context_notes: str, recent_alerts: list[dict]) -> str:
        """Generate a free-text situational assessment from health, notes, and recent events."""
        now_s = datetime.now().strftime("%Y-%m-%d %H:%M")

        if recent_alerts:
            lines = []
            for a in recent_alerts:
                deduped = " [dedup]" if a.get("deduped") else ""
                risk = ""
                try:
                    ctx = json.loads(a.get("context_json") or "{}")
                    if "ollama_risk" in ctx:
                        risk = f" risk={ctx['ollama_risk']}/10"
                except Exception:
                    pass
                lines.append(f"  {a['fired_at']} [{a['severity']}] {a['rule_id']}: {a['title']}{deduped}{risk}")
            alerts_block = "\n".join(lines)
        else:
            alerts_block = "  No recent alerts."

        prompt = (
            f"You are a senior Linux security analyst. It is {now_s}.\n"
            "Given the system health snapshot, operator notes, and recent security events below, "
            "provide a concise situational assessment of this system's security posture and overall health.\n\n"
            "Focus on: active threats or high-risk patterns, notable resource or container anomalies, "
            "and an overall risk verdict (Low / Medium / High / Critical) with brief justification. "
            "Be concise — 4 to 8 sentences. Synthesize; do not list every item verbatim.\n\n"
            f"## System Health\n{health_text}\n\n"
        )
        if context_notes:
            prompt += f"## Operator Notes\n{context_notes}\n\n"
        prompt += f"## Recent Events (last {len(recent_alerts)})\n{alerts_block}\n"

        payload = {"model": self._config.model, "prompt": prompt, "stream": False}
        try:
            async with self._session.post(
                self._config.url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self._config.timeout_seconds),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
                raw = _THINK_RE.sub("", data.get("response", "")).strip()
                return raw or "Ollama returned an empty response."
        except Exception as exc:
            logger.error("Ollama assessment failed: %s: %s", type(exc).__name__, exc)
            return f"Ollama assessment failed: {exc}"
