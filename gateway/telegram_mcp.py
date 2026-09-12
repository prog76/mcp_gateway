#!/usr/bin/env python3
"""telegram_mcp — generic Telegram messaging exposed as an MCP stdio server.

Tools:
    send(text, parse_mode?)        -> fire-and-forget push to the operator chat
    ask(text, choices=?, timeout=?) -> push + wait for an answer, return it
    status()                       -> notifier health + pending ask count

The chat_id is pinned by notification config (notifications.yaml 'telegram'
block); callers cannot choose a recipient. The stdio server is spawned per-
request by the policy proxy (exec-style, stdio transport).
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from fastmcp import FastMCP
except ImportError:
    from mcp.server.fastmcp import FastMCP

log = logging.getLogger("telegram-mcp")

# Ask/reply contract (shared with the policy proxy’s poll loop)
_ASK_PREFIX = "❓"
_REPLY_TAG_PREFIX = "{@reply:"
_REPLY_TAG_SUFFIX = "}"

mcp = FastMCP("telegram")


@dataclass
class PendingAsk:
    ask_id: str
    text: str
    event: asyncio.Event = field(default_factory=asyncio.Event)
    answer: Optional[str] = None
    message_id: Optional[int] = None
    chat_id: Optional[int] = None
    created_at: float = field(default_factory=time.monotonic)


_pending_asks: Dict[str, PendingAsk] = {}


def _find_ask_id(text: str) -> Optional[str]:
    m = re.match(r"^reply:([A-Za-z0-9-]+)(?::.*)?$", text)
    if m:
        return m.group(1)
    m = re.search(re.escape(_REPLY_TAG_PREFIX) + r"([A-Za-z0-9-]+)" + re.escape(_REPLY_TAG_SUFFIX), text)
    return m.group(1) if m else None


def _split_payload(text: str, limit: int = 3800) -> List[str]:
    if len(text) <= limit:
        return [text]
    parts, rest = [], text
    while len(rest) > limit:
        cut = rest.rfind("\n", 0, limit)
        if cut < limit * 0.5:
            cut = rest.rfind(" ", 0, limit)
        if cut <= 0:
            cut = limit
        parts.append(rest[:cut])
        rest = rest[cut:].lstrip("\n")
    parts.append(rest)
    return parts


class TelegramNotifier:
    API_BASE = "https://api.telegram.org/bot{token}"

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self._api_base = self.API_BASE.format(token=bot_token)
        self._client = None
        self._ensure_client()

    def _ensure_client(self):
        if self._client is None:
            import httpx
            self._client = httpx.AsyncClient(timeout=10.0)

    async def send_message(self, text: str, parse_mode: Optional[str] = None,
                           reply_markup: Optional[str] = None) -> dict:
        payload: Dict[str, Any] = {"chat_id": self.chat_id, "text": text}
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if reply_markup:
            payload["reply_markup"] = reply_markup
        try:
            r = await self._client.post(f"{self._api_base}/sendMessage", json=payload)
            if r.status_code != 200:
                log.error("sendMessage failed: %s %s", r.status_code, r.text)
                return {"ok": False, "chat_id": None, "message_id": None}
            res = r.json()
            if res.get("ok"):
                msg = res.get("result", {})
                return {"ok": True, "chat_id": msg.get("chat", {}).get("id"),
                        "message_id": msg.get("message_id")}
            return {"ok": False, "chat_id": None, "message_id": None}
        except Exception as e:
            log.error("sendMessage error: %s", e)
            return {"ok": False, "chat_id": None, "message_id": None}

    async def answer_callback(self, callback_id: str, text: str) -> None:
        try:
            await self._client.post(f"{self._api_base}/answerCallbackQuery",
                                    json={"callback_query_id": callback_id, "text": text})
        except Exception:
            pass

    async def edit_message(self, chat_id: int, message_id: int, text: str,
                           remove_keyboard: bool = False) -> None:
        try:
            payload = {"chat_id": chat_id, "message_id": message_id, "text": text}
            if remove_keyboard:
                payload["reply_markup"] = '{"inline_keyboard": []}'
            await self._client.post(f"{self._api_base}/editMessageText", json=payload)
        except Exception:
            pass

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


_backend: Optional[TelegramNotifier] = None
_ask_timeout: int = 120
_max_choices: int = 6


def configure(bot_token: str, chat_id: str, ask_timeout: int = 120, max_choices: int = 6) -> None:
    global _backend, _ask_timeout, _max_choices
    _ask_timeout = ask_timeout
    _max_choices = max_choices
    if bot_token and chat_id:
        _backend = TelegramNotifier(bot_token=bot_token, chat_id=chat_id)


def _fire(coro):
    """Fire-and-forget a coroutine, tolerating no running event loop."""
    try:
        asyncio.ensure_future(coro)
    except RuntimeError:
        pass


async def _send_chunked(text: str, parse_mode=None, reply_markup=None) -> dict:
    last = {"ok": False, "chat_id": None, "message_id": None}
    if _backend is None:
        return last
    for chunk in _split_payload(text):
        last = await _backend.send_message(chunk, parse_mode=parse_mode, reply_markup=reply_markup)
        if not last.get("ok"):
            break
    return last


def _build_keyboard(choices: List[Any], ask_id: str) -> Optional[str]:
    if not choices:
        return None
    import json as _json
    rows = [[{"text": str(c), "callback_data": f"reply:{ask_id}:{c}"}]
            for c in choices[:_max_choices]]
    return _json.dumps({"inline_keyboard": rows})


@mcp.tool()
async def send(text: str, parse_mode: Optional[str] = None) -> str:
    """Push a message to the operator chat (fire-and-forget)."""
    if _backend is None:
        return "Error: Telegram notifier not configured"
    last = await _send_chunked(text, parse_mode=parse_mode)
    if last.get("ok"):
        return f"OK: message sent ({len(text)} chars)"
    return "Error: Telegram send failed"


@mcp.tool()
async def ask(text: str, choices: Optional[List[Any]] = None,
              timeout: Optional[int] = None) -> str:
    """Push a message to the operator chat and wait for a reply."""
    if _backend is None:
        return "Error: Telegram notifier not configured"
    tmo = int(timeout) if timeout else _ask_timeout
    ask_id = uuid.uuid4().hex[:8]
    kb = _build_keyboard(choices or [], ask_id)
    body = text if len(text) <= 3500 else text[:3500] + "... (truncated)"
    if kb is None:
        body = body + f"  {_ASK_PREFIX} answer {ask_id[:8]}"
    sent = await _send_chunked(body, reply_markup=kb)
    if not sent.get("ok"):
        return "Error: Failed to send ask message"
    pending = PendingAsk(ask_id=ask_id, text=text, message_id=sent["message_id"],
                         chat_id=sent["chat_id"])
    _pending_asks[ask_id] = pending
    try:
        await asyncio.wait_for(pending.event.wait(), timeout=tmo)
    except asyncio.TimeoutError:
        _pending_asks.pop(ask_id, None)
        return f"Timeout: no answer within {tmo}s (ask {ask_id[:8]}…)"
    _pending_asks.pop(ask_id, None)
    return pending.answer if pending.answer is not None else "OK: ask posted"


@mcp.tool()
def status() -> str:
    """Notifier health + pending ask count."""
    if _backend is None:
        return "telegram: not configured"
    return f"telegram: configured (chat_id {_backend.chat_id}, pending asks: {len(_pending_asks)})"


def _dispatch_callback(backend: Any, update: dict) -> bool:
    cq = update.get("callback_query")
    if not cq:
        return False
    ask_id = _find_ask_id(cq.get("data", ""))
    if not ask_id:
        return False
    pending = _pending_asks.get(ask_id)
    if not pending:
        _fire(backend.answer_callback(cq["id"], "Ask expired"))
        return True
    parts = cq.get("data", "").split(":", 2)
    val = parts[2] if len(parts) > 2 else "✅"
    pending.answer = val
    pending.event.set()
    _fire(backend.answer_callback(cq["id"], f"Answered: {val}"))
    msg = cq.get("message", {}) or {}
    _fire(backend.edit_message(
        (msg.get("chat") or {}).get("id", 0), msg.get("message_id", 0),
        (msg.get("text") or "") + f"\n\nAnswered: {val}", remove_keyboard=True))
    return True


def _dispatch_message(backend: Any, update: dict) -> bool:
    msg = update.get("message") or {}
    text = msg.get("text", "") or ""
    if _REPLY_TAG_PREFIX not in text:
        return False
    ask_id = _find_ask_id(text)
    if not ask_id:
        return False
    pending = _pending_asks.get(ask_id)
    if not pending:
        return False
    cleaned = re.sub(re.escape(_REPLY_TAG_PREFIX) + r"[A-Za-z0-9-]+" + re.escape(_REPLY_TAG_SUFFIX), "", text).strip()
    pending.answer = cleaned or "(empty reply)"
    pending.event.set()
    return True


def register_telegram_handlers(backend: Any, pending_asks: Dict[str, PendingAsk]) -> None:
    """Hook ask-reply dispatch into the policy proxy’s shared poll loop."""
    global _pending_asks
    _pending_asks = pending_asks or _pending_asks
    backend._ask_dispatchers = [_dispatch_callback, _dispatch_message]


def main() -> None:
    try:
        mcp.run()
    except KeyboardInterrupt:
        pass
    finally:
        import asyncio as aio
        try:
            loop = aio.new_event_loop()
            if _backend:
                loop.run_until_complete(_backend.close())
        except Exception:
            pass


if __name__ == "__main__":
    main()
