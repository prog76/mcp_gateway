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
import httpx
import json
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
        assert asyncio.run(tm._tool_status()) == "telegram: not configured"

    def test_status_configured_no_pending(self, fake_backend):
        tm._installed_backend = fake_backend
        out = asyncio.run(tm._tool_status())
        assert "configured" in out
        assert "chat_id 12345" in out
        assert "pending asks: 0" in out

    def test_all_tool_handlers_are_async(self):
        """MountedServer.call_tool does `await handler(**arguments)` — a sync
        handler returns a str and blows up with "object str can't be used in
        'await' expression" at tools/call time. Every TOOL_SPECS handler must
        therefore be a coroutine function.
        """
        import inspect

        for spec in tm.TOOL_SPECS:
            assert inspect.iscoroutinefunction(spec["handler"]), (
                f"{spec['name']} handler must be async — MountedServer awaits "
                "tool handlers"
            )

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


# ---------------------------------------------------------------------------
# REAL TelegramBackend send path (regression: _tg_send → missing send_message)
# ---------------------------------------------------------------------------

class TestTelegramBackendSendMessage:
    """Regression: _tg_send called self.send_message(), a method that never
    existed on TelegramBackend (the real sendMessage POST lived inline in
    send_approval_request), so every telegram_send/telegram_ask MCP call died
    with "'TelegramBackend' object has no attribute 'send_message'". The
    fake_backend fixture mocks _tg_send itself and could not catch this —
    these tests exercise the REAL backend over a mocked httpx transport.
    """

    def _backend(self, responder):
        from gateway.policy_proxy import TelegramBackend

        be = TelegramBackend("test-token", "-1002309067089")
        asyncio.run(be._client.aclose())  # close the real client we replace
        be._client = httpx.AsyncClient(transport=httpx.MockTransport(responder))
        return be

    def test_tg_send_returns_ok_shape(self):
        def responder(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/sendMessage")
            body = json.loads(request.content)
            assert body["chat_id"] == "-1002309067089"
            assert body["text"] == "hello"
            return httpx.Response(200, json={"ok": True, "result": {
                "message_id": 42, "chat": {"id": -1002309067089}}})

        be = self._backend(responder)
        out = asyncio.run(be._tg_send("hello"))
        assert out == {"ok": True, "message_id": 42, "chat_id": -1002309067089}

    def test_tg_send_passes_parse_mode_and_markup(self):
        seen = {}

        def responder(request: httpx.Request) -> httpx.Response:
            seen.update(json.loads(request.content))
            return httpx.Response(200, json={"ok": True, "result": {
                "message_id": 1, "chat": {"id": 1}}})

        be = self._backend(responder)
        asyncio.run(be._tg_send("x", parse_mode="HTML",
                                reply_markup=json.dumps({"inline_keyboard": []})))
        assert seen["parse_mode"] == "HTML"
        assert seen["reply_markup"] == '{"inline_keyboard": []}'

    def test_tg_send_api_error_is_ok_false(self):
        be = self._backend(
            lambda req: httpx.Response(200, json={"ok": False, "description": "chat not found"}))
        assert asyncio.run(be._tg_send("x")) == {"ok": False}

    def test_tg_send_http_error_is_ok_false(self):
        be = self._backend(lambda req: httpx.Response(500, text="boom"))
        assert asyncio.run(be._tg_send("x")) == {"ok": False}

    def test_tool_send_end_to_end_via_real_backend(self):
        def responder(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": True, "result": {
                "message_id": 7, "chat": {"id": -1002309067089}}})

        tm._installed_backend = self._backend(responder)
        out = asyncio.run(tm._tool_send(text="hello"))
        assert out == "OK: message sent (5 chars)"

    def test_tool_ask_send_path_via_real_backend_then_timeout(self):
        def responder(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": True, "result": {
                "message_id": 8, "chat": {"id": -1002309067089}}})

        tm._installed_backend = self._backend(responder)
        # timeout=0 → wait_for raises TimeoutError right after the send,
        # proving the ask path reaches sendMessage without AttributeError.
        out = asyncio.run(tm._tool_ask(text="pick one", timeout=0))
        assert out.startswith("Timeout: no answer within 0s")

    def test_backend_api_surface_matches_tool_handlers(self):
        """telegram_mcp handlers duck-type these members on the backend; any
        rename/removal breaks every telegram MCP tool at call time."""
        import inspect

        from gateway.policy_proxy import TelegramBackend

        be = TelegramBackend("t", "1")
        for name in ("send_message", "_tg_send", "_answer_callback", "_edit_message"):
            assert inspect.iscoroutinefunction(getattr(be, name)), name
        assert be._tg_chat_id == "1"
        asyncio.run(be._client.aclose())
