#!/usr/bin/env python3
"""Tests for gateway.telegram_mcp — Telegram tool handlers + dispatch helpers.

Covers:
- _tool_status() reports "not configured" until install_telegram_tools wires a backend
- _find_ask_id parsing for both button callbacks and {@reply:..} free-text tags
- _dispatch_callback resolves a pending ask when the operator taps a button
- _dispatch_message resolves a pending ask when the operator replies with text
- _dispatch_callback returns False for non-ask callbacks (approval flow)
- _split_payload splits long text within Telegram limits
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure the package under test is on the path.
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))

from gateway import telegram_mcp as tm


@pytest.fixture(autouse=True)
def reset_state():
    tm._pending_asks.clear()
    tm._installed_backend = None
    yield
    tm._pending_asks.clear()
    tm._installed_backend = None


@pytest.fixture
def fake_backend():
    b = MagicMock()
    b._tg_chat_id = "12345"
    b._tg_send = AsyncMock(return_value={"ok": True, "chat_id": 12345, "message_id": 99})
    b._answer_callback = AsyncMock()
    b._edit_message = AsyncMock()
    return b


# ---------------------------------------------------------------------------
# configuration + status
# ---------------------------------------------------------------------------

class TestConfiguration:
    def test_status_not_configured(self):
        tm._installed_backend = None
        assert tm._tool_status() == "telegram: not configured"

    def test_status_configured_no_pending(self, fake_backend):
        tm._installed_backend = fake_backend
        out = tm._tool_status()
        assert "configured" in out
        assert "chat_id 12345" in out
        assert "pending asks: 0" in out

    def test_install_wires_backend_and_tools(self, fake_backend):
        server = MagicMock()
        tm.install_telegram_tools(server, fake_backend)
        assert tm._installed_backend is fake_backend
        registered = [c.kwargs.get("name") for c in server.tool.call_args_list]
        assert registered == ["telegram_send", "telegram_ask", "telegram_status"]


# ---------------------------------------------------------------------------
# ask_id parsing
# ---------------------------------------------------------------------------

class TestFindAskId:
    @pytest.mark.parametrize("text,expected", [
        ("reply:abc-123", "abc-123"),
        ("reply:abc-123:Option A", "abc-123"),
        ("plain text", None),
        ("{@reply:abc-123}", "abc-123"),
        ("prefix {@reply:xyz-99} suffix", "xyz-99"),
        ("reply:", None),
        ("", None),
    ])
    def test_find(self, text, expected):
        assert tm._find_ask_id(text) == expected


# ---------------------------------------------------------------------------
# split_payload
# ---------------------------------------------------------------------------

class TestSplitPayload:
    def test_short(self):
        assert tm._split_payload("hello")[0] == "hello"
        assert len(tm._split_payload("hello")) == 1

    def test_long_splits(self):
        big = "line " * 2000  # ~12000 chars, exceeds default 3800 limit
        parts = tm._split_payload(big)
        assert len(parts) > 1
        for p in parts:
            assert len(p) <= 3800 + 20  # small slack for word-boundary search


# ---------------------------------------------------------------------------
# button-tap dispatch
# ---------------------------------------------------------------------------

class TestDispatchCallback:
    def test_non_ask_callback_returns_false(self, fake_backend):
        update = {"callback_query": {"data": "approve:req-1", "id": "c1", "message": {}}}
        assert tm._dispatch_callback(fake_backend, update) is False

    def test_expired_ask_callback_returns_true(self, fake_backend):
        ask_id = "dead-beef"
        update = {"callback_query": {"data": f"reply:{ask_id}:Yes", "id": "c2",
                                   "message": {"chat": {"id": 1}, "message_id": 1, "text": "q?"}}}
        assert tm._dispatch_callback(fake_backend, update) is True

    def test_valid_button_tap_resolves_pending(self, fake_backend):
        ask_id = "live-id-001"
        pending = tm.PendingAsk(ask_id=ask_id, text="Pick one")
        tm._pending_asks[ask_id] = pending
        update = {"callback_query": {"data": f"reply:{ask_id}:Approve", "id": "c3",
                                   "message": {"chat": {"id": 12345}, "message_id": 99, "text": "q?"}}}
        assert tm._dispatch_callback(fake_backend, update) is True
        assert pending.answer == "Approve"
        assert pending.event.is_set()


# ---------------------------------------------------------------------------
# free-text reply dispatch
# ---------------------------------------------------------------------------

class TestDispatchMessage:
    def test_non_reply_text_returns_false(self, fake_backend):
        update = {"message": {"text": "hello world"}}
        assert tm._dispatch_message(fake_backend, update) is False

    def test_reply_tag_missing_returns_false(self, fake_backend):
        update = {"message": {"text": "no tag here"}}
        assert tm._dispatch_message(fake_backend, update) is False

    def test_expired_reply_returns_false(self, fake_backend):
        update = {"message": {"text": "answer {@reply:deadbeef}"}}
        assert tm._dispatch_message(fake_backend, update) is False

    def test_valid_reply_resolves_pending(self, fake_backend):
        ask_id = "live-id-002"
        pending = tm.PendingAsk(ask_id=ask_id, text="Pick one")
        tm._pending_asks[ask_id] = pending
        update = {"message": {"text": "привет {@reply:live-id-002}"}}
        assert tm._dispatch_message(fake_backend, update) is True
        assert pending.answer == "привет"
        assert pending.event.is_set()

    def test_empty_reply_stripped_to_placeholder(self, fake_backend):
        ask_id = "live-id-003"
        pending = tm.PendingAsk(ask_id=ask_id, text="Pick one")
        tm._pending_asks[ask_id] = pending
        update = {"message": {"text": "  {@reply:live-id-003}  "}}
        assert tm._dispatch_message(fake_backend, update) is True
        assert pending.answer == "(empty reply)"
