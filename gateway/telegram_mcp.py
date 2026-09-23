#!/usr/bin/env python3
"""telegram_mcp - generic Telegram messaging helpers for the policy proxy.

NOT an MCP server. Exports tool handlers + dispatch helpers that the policy
proxy wires into its EXISTING TelegramBackend so there is ONE Bot-API client
and ONE long-poll loop (a second client would cause Telegram 409 Conflict).

Tools: telegram_send / telegram_ask / telegram_status.

- telegram_ask with `choices` renders an inline keyboard; the tap resolves it
  through callback_query.
- telegram_ask WITHOUT `choices` uses Telegram ForceReply: the operator types a
  free-text answer, the answer arrives as a reply to the ask message, and the
  pending ask is resolved by reply_to_message.message_id.
- `photo_base64` (or `photo_url`) turns send/ask into sendPhoto with the text as
  caption. This is the captcha path: a py-skill captures the image bytes and asks
  the operator to read the code off the picture.

`local_tools()` / `forward()` / `attach_synthetic_backend()` expose the same
three tools to compounds as an in-process "virtual backend" (see
policy_proxy.create_compound_server + the attach call in main()).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re as _re
import uuid as _uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("telegram-mcp")

_REPLY_TAG_PREFIX = "{@reply:"
_REPLY_TAG_SUFFIX = "}"
_NL = chr(10)
# Telegram's caption limit is 1024 chars; leave room for the truncation marker.
_CAPTION_LIMIT = 1000
_FORCE_REPLY_PLACEHOLDER = "Type your answer"
_REPLY_HINT = "Reply to this message with your answer."
# Default ask timeout. Deliberately BELOW the gateway's
# MCP_TOOL_TIMEOUT_SECONDS (120) and below skills-ipybox's own httpx timeout
# (120): an ask that outlives the caller's timeout can never deliver its answer.
_DEFAULT_ASK_TIMEOUT = 100


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


def _ask_id_for_message(message_id: Optional[int]) -> Optional[str]:
    """Resolve a pending ask from the message it was delivered as.

    ForceReply answers arrive as ordinary messages whose reply_to_message is the
    ask message itself, so message_id -- not a text tag -- is the correlation key
    for the free-text path. Newest wins if an id ever recurs.
    """
    if message_id is None:
        return None
    found = None
    for ask_id, pending in _pending_asks.items():
        if pending.message_id == message_id:
            found = ask_id
    return found


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
        cut = rest.rfind(_NL, 0, limit)
        if cut < limit * 0.5:
            cut = rest.rfind(" ", 0, limit)
        if cut <= 0:
            cut = limit
        parts.append(rest[:cut])
        rest = rest[cut:].lstrip(_NL)
    parts.append(rest)
    return parts


def _force_reply_markup() -> str:
    return json.dumps({"force_reply": True,
                       "input_field_placeholder": _FORCE_REPLY_PLACEHOLDER})


def _build_keyboard(choices: List[Any], ask_id: str) -> Optional[str]:
    if not choices:
        return None
    rows = [[{"text": str(c), "callback_data": f"reply:{ask_id}:{c}"}]
            for c in choices[:6]]
    return json.dumps({"inline_keyboard": rows})


def _photo_payload(kw: Dict[str, Any]) -> Dict[str, Any]:
    """Extract an optional photo from tool arguments.

    Returns kwargs for TelegramBackend.send_photo: `photo_bytes` for inline
    image data (base64, with or without a data: URL prefix) or `photo_url` for a
    Telegram-side fetch. Empty dict when no photo was supplied.
    """
    raw = kw.get("photo_base64")
    if raw:
        if isinstance(raw, str) and raw.startswith("data:"):
            raw = raw.split(",", 1)[-1]
        try:
            return {"photo_bytes": base64.b64decode(raw)}
        except Exception as e:
            log.warning("telegram: photo_base64 decode failed: %s", e)
            return {}
    url = kw.get("photo_url")
    if url:
        return {"photo_url": str(url)}
    return {}


def _cap_caption(text: str) -> str:
    return text if len(text) <= _CAPTION_LIMIT else text[:_CAPTION_LIMIT] + "... (truncated)"


async def _tool_send(**kw) -> str:
    text = kw.get("text", "")
    parse_mode = kw.get("parse_mode")
    if not text:
        return "Error: text is required"
    backend = _installed_backend
    if backend is None:
        return "Error: Telegram notifier not configured"
    photo = _photo_payload(kw)
    if photo:
        sent = await backend.send_photo(caption=_cap_caption(text), **photo)
        if not sent.get("ok"):
            return "Error: Telegram sendPhoto failed"
        return f"OK: photo sent (caption {len(text)} chars)"
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
    timeout = kw.get("timeout", _DEFAULT_ASK_TIMEOUT)
    if not text:
        return "Error: text is required"
    backend = _installed_backend
    if backend is None:
        return "Error: Telegram notifier not configured"
    try:
        tmo = int(timeout)
    except (TypeError, ValueError):
        tmo = _DEFAULT_ASK_TIMEOUT
    ask_id = _uuid.uuid4().hex[:8]
    kb = _build_keyboard(choices or [], ask_id)
    body = text
    if kb is None:
        # Free-text ask: ForceReply, so the answer comes back as a reply to THIS
        # message and is resolved by message_id in the shared poll loop.
        kb = _force_reply_markup()
        body = body + _NL + _NL + _REPLY_HINT
    photo = _photo_payload(kw)
    if photo:
        sent = await backend.send_photo(caption=_cap_caption(body),
                                        reply_markup=kb, **photo)
    else:
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
        _fire(backend._tg_send(f"Ask {ask_id} timed out after {tmo}s - no answer received."))
        return f"Timeout: no answer within {tmo}s (ask {ask_id})"
    _pending_asks.pop(ask_id, None)
    return pending.answer if pending.answer is not None else "OK: ask posted"


async def _tool_status(**kw) -> str:
    # NOTE: must be a coroutine - MountedServer.call_tool awaits every tool
    # handler, so a sync def here fails with "object str can't be used in
    # 'await' expression" at tools/call time.
    backend = _installed_backend
    if backend is None:
        return "telegram: not configured"
    pending = ", ".join(f"{a}@{p.message_id}" for a, p in _pending_asks.items()) or "none"
    return (f"telegram: configured (chat_id {backend._tg_chat_id}, "
            f"pending asks: {len(_pending_asks)} [{pending}])")


TOOL_SPECS = [
    {"name": "telegram_send",
     "description": ("Send a message to the operator chat. Fire-and-forget. "
                     "Pass photo_base64 to send a photo with `text` as caption."),
     "handler": _tool_send,
     "schema": {"type": "object",
                "properties": {"text": {"type": "string"},
                               "parse_mode": {"type": "string",
                                              "enum": ["Markdown", "MarkdownV2", "HTML"]},
                               "photo_base64": {"type": "string"},
                               "photo_url": {"type": "string"}},
                "required": ["text"]}},
    {"name": "telegram_ask",
     "description": ("Ask the operator and wait for the answer. Without `choices` "
                     "the message is sent with ForceReply and the operator replies "
                     "with free text; with `choices` the answer comes from a button. "
                     "Pass photo_base64 to attach an image to the question (e.g. a "
                     "captcha). Keep `timeout` below the caller's own timeout "
                     "(gateway MCP_TOOL_TIMEOUT_SECONDS, default 120)."),
     "handler": _tool_ask,
     "schema": {"type": "object",
                "properties": {"text": {"type": "string"},
                               "choices": {"type": "array", "items": {"type": "string"}},
                               "photo_base64": {"type": "string"},
                               "photo_url": {"type": "string"},
                               "timeout": {"type": "integer",
                                           "default": _DEFAULT_ASK_TIMEOUT}},
                "required": ["text"]}},
    {"name": "telegram_status",
     "description": "Telegram notifier health + pending ask count.",
     "handler": _tool_status,
     "schema": {"type": "object", "properties": {}}},
]


# Closed default for the compound path: only these three tools are reachable.
# Compound membership is the outer gate - a compound that does not list
# `telegram` cannot see them at all.
TELEGRAM_RULES = [
    {"match": {"tool": "^(telegram_send|telegram_ask|telegram_status)$"},
     "action": "allow"},
    {"match": {"tool": ".*"},
     "action": "deny",
     "reason": "telegram exposes only telegram_send/telegram_ask/telegram_status."},
]


class SyntheticTool:
    """Stand-in for mcp.types.Tool (name/description/inputSchema only)."""

    def __init__(self, name: str, description: str, input_schema: dict):
        self.name = name
        self.description = description
        self.inputSchema = input_schema


def local_tools() -> List[SyntheticTool]:
    return [SyntheticTool(s["name"], s["description"], s["schema"]) for s in TOOL_SPECS]


async def forward(tool_name: str, arguments: dict) -> dict:
    """Dispatch a compound-dispatched call to a local tool handler.

    Mirrors the return shape of policy_proxy.forward() so compound handlers can
    treat this in-process backend exactly like a remote one.
    """
    for spec in TOOL_SPECS:
        if spec["name"] == tool_name:
            try:
                out = await spec["handler"](**(arguments or {}))
            except Exception as e:
                log.exception("telegram tool %s failed", tool_name)
                return {"error": f"telegram {tool_name}: {e}"}
            return {"content": [out], "structuredContent": None, "isError": False}
    return {"error": f"telegram: unknown tool '{tool_name}'"}


def attach_synthetic_backend(backend_status_cls, backend_config_cls, name: str = "telegram"):
    """Build the BackendStatus that makes compounds see the telegram tools.

    A compound aggregates tools through `backend_status_map` + cached tool
    discovery. This backend has no transport and nothing to discover, so it is
    registered by hand with `synthetic = True`: create_compound_server reads its
    cached `tools` and dispatches calls through telegram_mcp.forward() instead of
    policy_proxy.forward().
    """
    cfg = backend_config_cls(name=name)
    status = backend_status_cls(name=name, config=cfg, rules=TELEGRAM_RULES)
    status.synthetic = True
    status.healthy = True
    status.tools = local_tools()
    status.tools_count = len(status.tools)
    status.error = None
    return status


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
    val = parts[2] if len(parts) > 2 else "ok"
    pending.answer = val
    pending.event.set()
    _fire(backend._answer_callback(cq["id"], f"Answered: {val}"))
    msg = (cq.get("message") or {})
    _fire(backend._edit_message(
        (msg.get("chat") or {}).get("id", 0),
        msg.get("message_id", 0),
        (msg.get("text") or "") + _NL + "Answered: " + val,
        remove_keyboard=True))
    return True


def _dispatch_message(backend, update: dict) -> bool:
    """Resolve a pending ask from an operator message.

    Two carriers, in priority order:
      1. reply_to_message.message_id - the ForceReply path (free-text answer)
      2. a `{@reply:<ask_id>}` tag    - works when replying is not possible
    """
    msg = update.get("message") or {}
    text = (msg.get("text") or msg.get("caption") or "").strip()
    if not text:
        return False
    reply_to = (msg.get("reply_to_message") or {}).get("message_id")
    ask_id = _ask_id_for_message(reply_to)
    if ask_id is None:
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
    # Echo the captured answer into the chat: proof for the human that the skill
    # received exactly this text.
    _fire(backend._tg_send(f"Answer recorded (ask {ask_id}): {pending.answer}"))
    return True
