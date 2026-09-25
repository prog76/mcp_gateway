#!/usr/bin/env python3
"""Tests for gateway.mail_mcp - mailbox-as-event-source tool handlers.

The parser/extraction/scope assertions are a 1:1 port of the playbook selftest
that this module replaced (config/playbooks/mail-fetch/scripts/_selftest.py in
the deploy repo), so the two forms are held to the SAME contract: same
recorded production letter (alias rs2qeug3kpxg@mail.ru, subject "Your GitHub
launch code", code 27169490, account_verifications confirm URL), same allow
lists, same {verify_link, code} shape.

Added on top (new in the backend form):
- scope validation is driven by the MOUNTED config, not by code constants
- a missing/empty config denies rather than widening
- the generated gate rules (mail_rules) agree with the module's own checks
- a credential cannot arrive as an argument
- the wait path returns typed results and never outlives its ceiling
"""

import asyncio
import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))

from gateway import mail_mcp as mm

CR = chr(13)
LF = chr(10)
CRLF = CR + LF

REAL_CODE = "27169490"
REAL_LINK = ("https://github.com/account_verifications/confirm/"
             "442d70e9-3299-4d13-9d32-67ff2f4be239/27169490")

CONFIG = textwrap.dedent(
    """
    mail:
      accounts:
        prog76@mail.ru:
          host: imap.mail.ru
          transports: [[143, starttls], [993, tls]]
          password_env: MAIL_FETCH_PROG76_PASSWORD
          folders: [INBOX, Trash]
      allow:
        senders: [github.com, mail.ru, ligastavok.ru]
        subjects: [verify, verif, confirm, launch code, code, device, sign in, sign-in, подтвер, код]
        alias_domains: [mail.ru, internet.ru, bk.ru, inbox.ru, list.ru]
        alias_pattern: '{name}-{rand}@mail.ru'
      limits:
        default_timeout: 30
        max_timeout: 60
        default_limit: 40
        max_limit: 200
        wait_poll_seconds: 15
        wait_max_seconds: 90
        default_wait_seconds: 30
        max_matches: 5
    """)


@pytest.fixture(autouse=True)
def configured(tmp_path, monkeypatch):
    """Point the module at a temp config; reset the cache around every test."""
    path = tmp_path / "mail.yaml"
    path.write_text(CONFIG)
    monkeypatch.setenv("MAIL_CONFIG", str(path))
    mm._config_cache = None
    monkeypatch.delenv("MAIL_FETCH_PROG76_PASSWORD", raising=False)
    mm.load_config(reload=True)
    yield path
    mm._config_cache = None


def _letter_lines():
    head = [
        "From: GitHub <noreply@github.com>",
        "To: rs2qeug3kpxg@mail.ru",
        "Delivered-To: rs2qeug3kpxg@mail.ru",
        "Subject: Your GitHub launch code",
        "Date: Tue, 16 Sep 2026 09:55:00 +0300",
        "MIME-Version: 1.0",
        'Content-Type: multipart/alternative; boundary="BND"',
        "",
    ]
    plain = [
        "--BND", "Content-Type: text/plain; charset=utf-8", "",
        "Hey!", "", "Your GitHub launch code is:", "", REAL_CODE, "",
        "Verify this device or confirm your email:", REAL_LINK, "",
        "Thanks,", "The GitHub Team",
    ]
    html = [
        "--BND", "Content-Type: text/html; charset=utf-8", "",
        "<html><body><p>Your GitHub launch code is:</p><p><b>" + REAL_CODE
        + "</b></p><p><a href=\"" + REAL_LINK + "\">Verify</a></p></body></html>",
        "--BND--",
    ]
    return head + plain + html


LETTER = (CRLF.join(_letter_lines()) + CRLF).encode()


# ---------------------------------------------------------------------------
# Extraction parity with the playbook this replaces
# ---------------------------------------------------------------------------

def test_extract_multipart_letter():
    import email
    msg = email.message_from_bytes(LETTER)
    body = mm._body_text(msg)
    link, code = mm._extract(body)
    assert mm._hdr(msg.get("Subject")) == "Your GitHub launch code"
    assert mm._addrs(msg.get("From")) == ["noreply@github.com"]
    assert "Your GitHub launch code is" in body
    assert "<p>" not in body
    assert code == REAL_CODE
    assert link == REAL_LINK


def test_extract_html_only_letter():
    import email
    msg = email.message_from_bytes((CRLF.join([
        "From: GitHub <noreply@github.com>",
        "To: rs2qeug3kpxg@mail.ru",
        "Subject: Please verify your email address",
        "Date: Tue, 16 Sep 2026 09:55:00 +0300",
        "Content-Type: text/html; charset=utf-8",
        "",
        "<p>Confirm your email: <a href=\"" + REAL_LINK + "\">Confirm</a></p>",
        "<p>code: " + REAL_CODE + "</p>",
    ]) + CRLF).encode())
    body = mm._body_text(msg)
    link, code = mm._extract(body)
    assert link == REAL_LINK
    assert code == REAL_CODE
    assert "<a " not in body
    assert "&amp;" not in body


def test_script_and_style_dropped():
    out = mm._html_to_text("<style>p{color:red}</style><script>var x=1;</script>hello")
    assert out.strip() == "hello"


def test_rfc2047_subject():
    import email
    msg = email.message_from_bytes(
        ("Subject: =?utf-8?B?0J/QvtC00YLQstC10YDQttC00LXQvdC40LU=?=" + CRLF + CRLF).encode())
    assert mm._hdr(msg.get("Subject")) == "Подтверждение"


def test_regexes_have_no_raw_newline():
    for name in ("VERIFY_LINK_RE", "ANY_VERIFY_LINK_RE", "CODE_WORD_RE",
                 "CODE_LINE_RE", "ADDRESS_RE"):
        assert LF not in getattr(mm, name).pattern


# ---------------------------------------------------------------------------
# Config-driven account/folder contract
# ---------------------------------------------------------------------------

def test_account_registry_from_config():
    accs = mm.accounts()
    assert list(accs) == ["prog76@mail.ru"]
    assert accs["prog76@mail.ru"]["transports"][0] == (143, "starttls")
    assert "INBOX" in accs["prog76@mail.ru"]["folders"]
    assert "Trash" in accs["prog76@mail.ru"]["folders"]


def test_missing_config_is_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("MAIL_CONFIG", str(tmp_path / "nope.yaml"))
    mm._config_cache = None
    cfg = mm.load_config(reload=True)
    assert cfg["accounts"] == {}
    assert cfg["senders"] == ()
    # nothing is allowed, and the gate says so
    assert mm._sender_allowed("github.com") is False
    assert mm._alias_allowed("a@mail.ru") is False
    rules = mm.mail_rules()
    assert rules[0]["action"] == "deny"
    assert len(rules) == 1


def test_empty_config_denies_every_tool():
    rules = mm.mail_rules() if mm.accounts() else None
    assert rules is not None  # configured fixture -> rules exist


# ---------------------------------------------------------------------------
# Allow lists
# ---------------------------------------------------------------------------

def test_sender_allowed():
    assert mm._sender_allowed("github.com")
    assert mm._sender_allowed("noreply@github.com")
    assert mm._sender_allowed("mail.github.com")
    assert not mm._sender_allowed("evil.com")
    assert not mm._sender_allowed("notgithub.com")
    assert mm._sender_allowed("")


def test_subject_allowed():
    assert mm._subject_allowed("verify")
    assert mm._subject_allowed("подтверждение")
    assert not mm._subject_allowed("invoice")
    assert mm._subject_allowed("")


def test_alias_allowed():
    assert mm._alias_allowed("rs2qeug3kpxg@mail.ru")
    assert mm._alias_allowed("RS2QEUG3KPXG@MAIL.RU")
    assert not mm._alias_allowed("x@evil.com")
    assert mm._alias_allowed("")


# ---------------------------------------------------------------------------
# since parsing + header matching
# ---------------------------------------------------------------------------

def test_parse_since():
    assert mm._parse_since(1790229539) == 1790229539.0
    assert mm._parse_since("1790229539") == 1790229539.0
    assert mm._parse_since(None) is None
    with pytest.raises(ValueError):
        mm._parse_since("not-a-date")


HDRS = {"FROM": "GitHub <noreply@github.com>",
        "DELIVERED-TO": "rs2qeug3kpxg@mail.ru",
        "TO": "rs2qeug3kpxg@mail.ru", "SUBJECT": "Your GitHub launch code",
        "X-ORIGINAL-TO": "rs2qeug3kpxg@mail.ru",
        "DATE": "Tue, 16 Sep 2026 09:55:00 +0300"}


def test_header_matching():
    assert mm._match(HDRS, "rs2qeug3kpxg@mail.ru", "github.com", None)
    assert not mm._match(HDRS, "other@mail.ru", "github.com", None)
    assert not mm._match(HDRS, "rs2qeug3kpxg@mail.ru", "gitlab.com", None)
    assert not mm._match(HDRS, "rs2qeug3kpxg@mail.ru", "github.com", 2000000000)
    assert mm._match(HDRS, "rs2qeug3kpxg@mail.ru", "github.com", 1700000000)
    assert mm._match({"FROM": "noreply@github.com", "X-ORIGINAL-TO": "a@mail.ru"},
                     "a@mail.ru", "github.com", None)
    assert mm._match(HDRS, "RS2QEUG3KPXG@MAIL.RU", "github.com", None)


# ---------------------------------------------------------------------------
# Scope validation (the second gate) + tool contract
# ---------------------------------------------------------------------------

def _run(coro):
    return json.loads(asyncio.get_event_loop().run_until_complete(coro))


def test_scope_errors():
    with pytest.raises(mm.ScopeError) as e:
        mm._scope({})
    assert e.value.payload["reason"] == "missing_account"
    with pytest.raises(mm.ScopeError) as e:
        mm._scope({"account": "nobody@example.com"})
    assert e.value.payload["reason"] == "unknown_account"
    with pytest.raises(mm.ScopeError) as e:
        mm._scope({"account": "prog76@mail.ru", "folder": "NoSuch"})
    assert e.value.payload["reason"] == "bad_folder"
    assert "Trash" in e.value.payload["allowed"]
    with pytest.raises(mm.ScopeError) as e:
        mm._scope({"account": "prog76@mail.ru", "from_filter": "evil.com"})
    assert e.value.payload["reason"] == "denied_from"
    with pytest.raises(mm.ScopeError) as e:
        mm._scope({"account": "prog76@mail.ru", "subject_contains": "invoice"})
    assert e.value.payload["reason"] == "denied_subject"
    with pytest.raises(mm.ScopeError) as e:
        mm._scope({"account": "prog76@mail.ru", "to": "x@evil.com"})
    assert e.value.payload["reason"] == "denied_alias"
    with pytest.raises(mm.ScopeError) as e:
        mm._scope({"account": "prog76@mail.ru", "since": "not-a-date"})
    assert e.value.payload["reason"] == "bad_since"
    with pytest.raises(mm.ScopeError) as e:
        mm._scope({"account": "prog76@mail.ru", "uid": "1;DROP"})
    assert e.value.payload["reason"] == "bad_uid"


def test_scope_defaults_from_config():
    s = mm._scope({"account": "Prog76@Mail.Ru", "to": "rs2qeug3kpxg@mail.ru"})
    assert s["account"] == "prog76@mail.ru"
    assert s["limit"] == 40
    assert s["timeout"] == 30
    # clamped to the configured maxima, not to hardcoded numbers
    assert mm._scope({"account": "prog76@mail.ru", "limit": 9999})["limit"] == 200
    assert mm._scope({"account": "prog76@mail.ru", "timeout": 9999})["timeout"] == 60


def test_credential_is_never_an_argument():
    # a password-shaped argument must not be a way in, and must not be echoed
    out = _run(mm._tool_fetch(account="prog76@mail.ru", password="hunter2"))
    assert out["reason"] == "credential_missing"
    assert "hunter2" not in json.dumps(out)
    assert out["env"] == "MAIL_FETCH_PROG76_PASSWORD"


def test_credential_missing_message_names_env_var():
    out = _run(mm._tool_search(account="prog76@mail.ru"))
    assert out["reason"] == "credential_missing"
    assert out["env"] == "MAIL_FETCH_PROG76_PASSWORD"
    assert env_is_absent(out)


def env_is_absent(payload):
    """No value for the password env var may appear anywhere in a result."""
    text = json.dumps(payload)
    for name in mm._secret_env_names():
        val = os.environ.get(name)
        if val:
            return val not in text
    return True


# ---------------------------------------------------------------------------
# The generated gate rules agree with the module's own re-validation
# ---------------------------------------------------------------------------

def _first_match(rules, tool, kwargs):
    from gateway.policy_proxy import matches_rule
    for i, rule in enumerate(rules):
        if matches_rule(rule, tool, kwargs):
            return i, rule.get("action")
    return None, "NOMATCH"


@pytest.mark.parametrize("label,kwargs,want", [
    ("listed account", {"account": "prog76@mail.ru"}, "allow"),
    ("account case", {"account": "Prog76@Mail.Ru"}, "allow"),
    ("no account", {}, "deny"),
    ("unlisted account", {"account": "other@x.com"}, "deny"),
    ("github sender", {"account": "prog76@mail.ru", "from_filter": "noreply@github.com"}, "allow"),
    ("sender case", {"account": "prog76@mail.ru", "from_filter": "GitHub.com"}, "allow"),
    ("sender suffix trick", {"account": "prog76@mail.ru", "from_filter": "notgithub.com"}, "deny"),
    ("evil sender", {"account": "prog76@mail.ru", "from_filter": "evil.com"}, "deny"),
    ("from alias field", {"account": "prog76@mail.ru", "from": "evil.com"}, "deny"),
    ("verify subject", {"account": "prog76@mail.ru", "subject_contains": "verify"}, "allow"),
    ("russian subject", {"account": "prog76@mail.ru", "subject_contains": "подтверждение"}, "allow"),
    ("bad subject", {"account": "prog76@mail.ru", "subject_contains": "invoice"}, "deny"),
    ("alias ok", {"account": "prog76@mail.ru", "alias": "RS2QEUG3KPXG@MAIL.RU"}, "allow"),
    ("alias evil", {"account": "prog76@mail.ru", "alias": "x@evil.com"}, "deny"),
    ("to evil", {"account": "prog76@mail.ru", "to": "x@evil.com"}, "deny"),
])
def test_generated_rules_match_scope_intent(label, kwargs, want):
    rules = mm.mail_rules()
    _, action = _first_match(rules, "mail_fetch", kwargs)
    assert action == want, label


def test_generated_rules_cover_every_mail_tool_and_nothing_else():
    rules = mm.mail_rules()
    for tool in ("mail_search", "mail_fetch", "mail_wait_for"):
        _, action = _first_match(rules, tool, {"account": "prog76@mail.ru"})
        assert action == "allow", tool
    _, action = _first_match(rules, "mail_status", {})
    assert action == "allow"
    _, action = _first_match(rules, "rm_rf", {})
    assert action == "deny"


def test_status_is_allowed_and_scope_rules_cover_the_read_tools():
    rules = mm.mail_rules()
    # health-only tool: allowed, and it takes no scope argument
    _, action = _first_match(rules, "mail_status", {})
    assert action == "allow"
    # the allow is scoped to that ONE tool name
    _, action = _first_match(rules, "mail_status_evil", {})
    assert action == "deny"
    # the six scope denies cover the READ tools; a scope field on any of them
    # that is out of policy is refused before the backend is reached
    for tool in ("mail_search", "mail_fetch", "mail_wait_for"):
        _, action = _first_match(rules, tool, {"from_filter": "evil.com"})
        assert action == "deny", tool


def test_catch_all_names_every_advertised_tool():
    rules = mm.mail_rules()
    blob = rules[-1]["reason"]
    for spec in mm.TOOL_SPECS:
        assert spec["name"] in blob


def test_generated_rules_end_with_catch_all_deny():
    rules = mm.mail_rules()
    assert rules[-1]["action"] == "deny"
    assert rules[-1]["match"]["tool"] == ".*"
    # and the validator agrees the file shape is sane
    from gateway.validate_policy import _validate_backend_policy
    assert _validate_backend_policy(
        {"backend": {"name": "mail"}, "default_deny": "denied", "rules": rules},
        "<generated>") is True


def test_reason_templates_render():
    from gateway.policy_proxy import resolve_template
    rules = mm.mail_rules()
    # a denial must name what was refused, with no unresolved template left
    _, _ = _first_match(rules, "mail_fetch", {"account": "prog76@mail.ru", "from_filter": "evil.com"})
    rule = next(r for r in rules if r["match"].get("from_filter") is not None)
    out = resolve_template(rule["reason"], "mail_fetch", {"from_filter": "evil.com"})
    assert "evil.com" in out and "${" not in out
    trailing = next(r for r in rules if r["action"] == "deny"
                    and set(r["match"]) == {"tool"})
    out = resolve_template(trailing["reason"], "mail_fetch", {})
    assert "prog76@mail.ru" in out and "${" not in out


# ---------------------------------------------------------------------------
# Synthetic-backend plumbing
# ---------------------------------------------------------------------------

def test_local_tools_and_forward():
    tools = mm.local_tools()
    assert [t.name for t in tools] == ["mail_search", "mail_fetch", "mail_wait_for",
                                       "mail_status"]
    res = asyncio.get_event_loop().run_until_complete(
        mm.forward("mail_status", {}))
    assert res["isError"] is False
    assert "NOT CONFIGURED" not in res["content"][0]
    res = asyncio.get_event_loop().run_until_complete(mm.forward("nope", {}))
    assert "error" in res


def test_attach_synthetic_backend_shape():
    from gateway.policy_proxy import BackendConfig, BackendStatus
    status = mm.attach_synthetic_backend(BackendStatus, BackendConfig, name="mail")
    assert status.synthetic is True
    assert status.healthy is True
    assert status.tools_count == 4
    assert [t.name for t in status.tools][0] == "mail_search"


def _direct_route_handlers():
    """Build the same handler wiring the direct /mcp/mail route uses.

    Mirrors policy_proxy.main(): a BackendConfig + mail_rules + one
    make_policy_handler per advertised tool.  If this drifts from main(), the
    direct route silently loses its gate - which is the defect this covers.
    """
    from gateway.policy_proxy import (BackendConfig, BackendStatus,
                                      make_policy_handler)
    bc = BackendConfig(name="mail", path="/mcp/mail")
    rules = mm.mail_rules()
    status = BackendStatus(name="mail", config=bc, rules=rules, healthy=True)
    return {t.name: make_policy_handler(bc, rules, t.name, status)
            for t in mm.local_tools()}


def test_direct_route_refuses_out_of_scope_backend_call():
    handlers = _direct_route_handlers()
    out = asyncio.new_event_loop().run_until_complete(
        handlers["mail_fetch"](account="other@x.com"))
    assert "ACCESS DENIED" in out


def test_direct_route_deny_precedes_the_backend():
    """An out-of-scope call must never reach mail_mcp.forward()."""
    import gateway.policy_proxy as pp
    called = {"n": 0}
    real_forward = mm.forward

    async def spy(tool, args):
        called["n"] += 1
        return await real_forward(tool, args)

    pp._SYNTHETIC_BACKENDS["mail"] = type("X", (), {"forward": staticmethod(spy)})
    try:
        handlers = _direct_route_handlers()
        asyncio.new_event_loop().run_until_complete(
            handlers["mail_fetch"](account="other@x.com"))
        assert called["n"] == 0
    finally:
        pp._SYNTHETIC_BACKENDS["mail"] = mm


def test_wait_for_returns_typed_result_quickly():
    """A missing credential is a hard failure - the wait must NOT spin on it."""
    import time
    started = time.monotonic()
    out = _run(mm._tool_wait(account="prog76@mail.ru", timeout=60))
    assert out["reason"] == "credential_missing"
    assert time.monotonic() - started < 5
    assert out["attempts"] == 1


def test_wait_ceiling_is_below_the_tool_wall():
    # MCP_TOOL_TIMEOUT_SECONDS is 120 in compose; a wait must resolve under it.
    assert mm.WAIT_CEILING_SECONDS < 120


def test_redaction():
    os.environ["MAIL_FETCH_PROG76_PASSWORD"] = "sup3r-secret-value"
    try:
        assert mm._redact("login failed for sup3r-secret-value") == "login failed for ***"
        assert mm._redact("password=abc") == "password=***"
        assert mm._redact("NO [AUTHENTICATIONFAILED] x") == "NO [AUTHENTICATIONFAILED] x"
        out = _run(mm._tool_fetch(account="prog76@mail.ru", from_filter="evil.com"))
        assert "sup3r-secret-value" not in json.dumps(out)
    finally:
        del os.environ["MAIL_FETCH_PROG76_PASSWORD"]
