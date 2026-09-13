#!/usr/bin/env python3
"""telegram_mcp - generic Telegram messaging helpers for the policy proxy.

NOT an MCP server. Exports tool handlers + dispatch helpers that the policy
proxy wires into its existing TelegramBackend so there is ONE Bot-API client
and ONE long-poll loop (avoids Telegram 409 Conflict).
"""

from __future__ import annotations

import asyncio
import logging
import re as _re
import uuid as _uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("telegram-mcp")

_ASK_PREFIX = "❓"
_REPLY_TAG_PREFIX = "{@reply:"
_REPLY_TAG_SUFFIX = "}"


@dataclass
class PendingAsk:
    ask_id: str
    text: str
    event: asyncio.Event = field(default_factory=asyncio.Event)
    answer: Optional[str] = None
    message_id: Optional[int] = None
    chat_id: Optional[int] = None


_pending_asks: Dict[str, PendingAsk] = {}
_installed_backend: Any = None


def _find_ask_id(text: str) -> Optional[str]:
    m = _re.match(r"^reply:([A-Za-z0-9-]+)(?::.*)?$", text)
    if m:
        return m.group(1)
    m = _re.search(
        _re.escape(_REPLY_TAG_PREFIX) + r"([A-Za-z0-9-]+)" + _re.escape(_REPLY_TAG_SUFFIX),
        text,
    )
    return m.group(1) if m else None


def _fire(coro) -> None:
    try:
        asyncio.ensure_future(coro)
    except RuntimeError:
        pass


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


async def _tool_send(**kw) -> str:
    text = kw.get("text", "")
    parse_mode = kw.get("parse_mode")
    if not text:
        return "Error: text is required"
    backend = _installed_backend
    if backend is None:
        return "Error: Telegram notifier not configured"
    last = {"ok": False}
    for chunk in _split_payload(text):
        last = await backend._tg_send(chunk, parse_mode=parse_mode)
        if not last.get("ok"):
            break
    if last.get("ok"):
        return f"OK: message sent ({len(text)} chars)"
    return "Error: Telegram send failed"


async def _tool_ask(**kw) -> str:
    text = kw.get("text", "")
    choices = kw.get("choices")
    timeout = kw.get("timeout", 120)
    if not text:
        return "Error: text is required"
    backend = _installed_backend
    if backend is None:
        return "Error: Telegram notifier not configured"
    try:
        tmo = int(timeout)
    except (TypeError, ValueError):
        tmo = 120
    ask_id = _uuid.uuid4().hex[:8]
    kb = _build_keyboard(choices or [], ask_id)
    body = text if len(text) <= 3500 else text[:3500] + "... (truncated)"
    if kb is None:
        body = body + f"  {_ASK_PREFIX} answer {ask_id}"
    sent = await backend._tg_send(body, reply_markup=kb)
    if not sent.get("ok"):
        return "Error: Failed to send ask message"
    pending = PendingAsk(ask_id=ask_id, text=text,
                         message_id=sent.get("message_id"), chat_id=sent.get("chat_id"))
    _pending_asks[ask_id] = pending
    try:
        await asyncio.wait_for(pending.event.wait(), timeout=tmo)
    except asyncio.TimeoutError:
        _pending_asks.pop(ask_id, None)
        return f"Timeout: no answer within {tmo}s (ask {ask_id})"
    _pending_asks.pop(ask_id, None)
    return pending.answer if pending.answer is not None else "OK: ask posted"


def _tool_status(**kw) -> str:
    backend = _installed_backend
    if backend is None:
        return "telegram: not configured"
    return (f"telegram: configured (chat_id {backend._tg_chat_id}, "
            f"pending asks: {len(_pending_asks)})")


def _build_keyboard(choices: List[Any], ask_id: str) -> Optional[str]:
    if not choices:
        return None
    import json as _json
    rows = [[{"text": str(c), "callback_data": f"reply:{ask_id}:{c}"}]
            for c in choices[:6]]
    return _json.dumps({"inline_keyboard": rows})


TOOL_SPECS = [
    {"name": "telegram_send",
     "description": "Send a message to the operator chat (fire-and-forget).",
     "handler": _tool_send,
     "schema": {"type": "object",
                "properties": {"text": {"type": "string"},
                               "parse_mode": {"type": "string",
                                              "enum": ["Markdown", "MarkdownV2", "HTML"]}},
                "required": ["text"]}},
    {"name": "telegram_ask",
     "description": "Send a message to the operator chat and wait for a reply.",
     "handler": _tool_ask,
     "schema": {"type": "object",
                "properties": {"text": {"type": "string"},
                               "choices": {"type": "array", "items": {"type": "string"}},
                               "timeout": {"type": "integer", "default": 120}},
                "required": ["text"]}},
    {"name": "telegram_status",
     "description": "Telegram notifier health + pending ask count.",
     "handler": _tool_status,
     "schema": {"type": "object", "properties": {}}},
]


def install_telegram_tools(server, backend) -> None:
    """Register send/ask/status on a MountedServer and wire the shared backend."""
    global _installed_backend
    _installed_backend = backend
    for spec in TOOL_SPECS:
        server.tool(name=spec["name"], description=spec["description"],
                    inputSchema=spec["schema"])(spec["handler"])


def _dispatch_callback(backend, update: dict) -> bool:
    cq = update.get("callback_query")
    if not cq:
        return False
    ask_id = _find_ask_id(cq.get("data", ""))
    if not ask_id:
        return False
    pending = _pending_asks.get(ask_id)
    if not pending:
        _fire(backend._answer_callback(cq["id"], "Ask expired"))
        return True
    parts = cq.get("data", "").split(":", 2)
    val = parts[2] if len(parts) > 2 else "✅"
    pending.answer = val
    pending.event.set()
    _fire(backend._answer_callback(cq["id"], f"Answered: {val}"))
    msg = (cq.get("message") or {})
    _fire(backend._edit_message(
        (msg.get("chat") or {}).get("id", 0),
        msg.get("message_id", 0),
        (msg.get("text") or "") + f"\nAnswered: {val}",
        remove_keyboard=True))
    return True


def _dispatch_message(backend, update: dict) -> bool:
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
    cleaned = _re.sub(
        _re.escape(_REPLY_TAG_PREFIX) + r"[A-Za-z0-9-]+" + _re.escape(_REPLY_TAG_SUFFIX),
        "", text).strip()
    pending.answer = cleaned or "(empty reply)"
    pending.event.set()
    return True
