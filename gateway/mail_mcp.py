#!/usr/bin/env python3
"""mail_mcp - mailbox as an event source for the policy proxy.

NOT an MCP server. Exports tool handlers + dispatch helpers that the gateway
mounts as an in-process ("synthetic") backend, exactly like telegram_mcp:
ONE process, no transport, no second container, no port.

Tools: mail_search / mail_fetch / mail_wait_for.

Why a backend and not a playbook (decision, card t_fbe11d78): a skill had to
have its secret threaded through the skills-ipybox container and its scope
double-checked in policy AND code; it also could not WAIT, so callers burned
agent turns retrying. Here the process holds the IMAP passwords, exposes only
open arguments, and can hold an expectation open until the letter lands.

SCOPE (args, all visible, all non-secret)
  account           mailbox key from the config registry (required)
  from_filter/from  sender domain or full address
  subject_contains  subject substring
  alias/to          recipient address (mail.ru-family temp aliases)
  since             epoch | YYYY-MM-DD | 'YYYY-MM-DD HH:MM' (UTC)
  folder, limit, timeout
A password is NEVER an argument, NEVER returned, NEVER logged: it is read from
the process environment (name declared per account in the config) and every
diagnostic string passes through _redact().

CONFIG (single source of truth, mounted read-only)
  MAIL_CONFIG, default /etc/mcp-gateways/mail.yaml - accounts (host,
  transports, password env var, folders), the allow lists, and the limits.
  Both the gateway gate rules (MAIL_RULES, handed to the compound dispatcher)
  and this module's own re-validation are generated from that ONE document, so
  the two layers cannot drift. Missing file = closed: no accounts, no allow
  list, every call denied with a reason that says so.

TRANSPORT (measured on this VDI, inside the gateway container, 2026-09-25)
  imap.mail.ru  143 + STARTTLS  OK  TLSv1.2  ~0.1s   <- listed FIRST
  imap.mail.ru  993 TLS         OK  TLSv1.2  ~0.1s
  mail.ligastavok.ru 993/143    timeout (no IMAP from this network); 443 open
"""

from __future__ import annotations

import asyncio
import email
import email.header
import email.utils
import imaplib
import os
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional

DEFAULT_CONFIG_PATH = os.environ.get("MAIL_CONFIG", "/etc/mcp-gateways/mail.yaml")

# Falls back to these when MAIL_CONFIG is absent. Deliberately EMPTY accounts
# and EMPTY allow lists: a missing config must deny, never silently widen.
_FALLBACK: Dict[str, Any] = {
    "accounts": {},
    "senders": (),
    "subjects": (),
    "alias_domains": (),
    "limits": {
        "default_timeout": 30,
        "max_timeout": 60,
        "default_limit": 40,
        "max_limit": 200,
        "wait_poll_seconds": 15,
        "wait_max_seconds": 90,
    },
}

# Hard ceiling for wait_for: the caller's tool-call wall is
# MCP_TOOL_TIMEOUT_SECONDS=120 (compose), so a wait MUST resolve below it or
# the caller dies in a transport timeout instead of getting a typed result.
WAIT_CEILING_SECONDS = 100

CR = chr(13)
LF = chr(10)
CRLF = CR + LF

_ACCOUNT_TUPLE_FIELDS = ("transports", "folders")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_config_cache: Optional[Dict[str, Any]] = None


def _coerce_config(raw: Optional[dict]) -> Dict[str, Any]:
    """Normalize the mounted document into the shape the module uses.

    transports/folders arrive from YAML as lists; the transport entries are
    (port, mode) pairs, so they are returned as tuples to keep the comparison
    in _open() exact.
    """
    if not raw:
        return dict(_FALLBACK)
    mail = raw.get("mail") or {}
    accounts: Dict[str, Dict[str, Any]] = {}
    for addr, conf in (mail.get("accounts") or {}).items():
        entry = dict(conf or {})
        for field in _ACCOUNT_TUPLE_FIELDS:
            if field in entry:
                entry[field] = tuple(tuple(v) if isinstance(v, list) else v
                                     for v in entry[field])
        accounts[str(addr).strip().lower()] = entry
    allow = mail.get("allow") or {}
    limits = dict(_FALLBACK["limits"])
    limits.update(mail.get("limits") or {})
    return {
        "accounts": accounts,
        "senders": tuple(str(s).lower() for s in (allow.get("senders") or ())),
        "subjects": tuple(str(s).lower() for s in (allow.get("subjects") or ())),
        "alias_domains": tuple(str(s).lower() for s in (allow.get("alias_domains") or ())),
        "limits": limits,
    }


def config_path() -> str:
    """Resolve MAIL_CONFIG at call time (never at import time)."""
    return os.environ.get("MAIL_CONFIG") or DEFAULT_CONFIG_PATH


def load_config(path: Optional[str] = None, reload: bool = False) -> Dict[str, Any]:
    """Load (and cache) the mail document. Missing/broken file = closed config."""
    global _config_cache
    if _config_cache is not None and not reload and path is None:
        return _config_cache
    target = path or config_path()
    raw = None
    try:
        import yaml
        with open(target, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError:
        raw = None
    except Exception:
        raw = None
    if path is None:
        _config_cache = _coerce_config(raw)
        return _config_cache
    return _coerce_config(raw)


def accounts() -> Dict[str, Dict[str, Any]]:
    return load_config()["accounts"]


def _limits() -> Dict[str, Any]:
    return load_config()["limits"]


# ---------------------------------------------------------------------------
# Credentials - process environment ONLY (never an argument, never a file
# beside the code). The env var per account is declared in the config.
# ---------------------------------------------------------------------------

def _credential(account: str):
    """Return (env_var_name, value_or_None). The value is never logged."""
    conf = accounts().get(account) or {}
    name = conf.get("password_env") or ""
    if not name:
        return "", None
    return name, (os.environ.get(name) or None)


def _secret_env_names():
    return tuple(c.get("password_env") for c in accounts().values() if c.get("password_env"))


def _redact(text):
    """Strip anything credential-shaped out of a diagnostic string.

    Belt and braces: nothing here interpolates a password, but a server error
    line is echoed back to the caller, so scrub it anyway.
    """
    if not isinstance(text, str):
        return text
    text = re.sub(r"(?i)(password|passwd|token|secret)\s*[:=]\s*\S+", r"\1=***", text)
    for name in _secret_env_names():
        val = os.environ.get(name)
        if val and len(val) >= 4:
            text = text.replace(val, "***")
    return text


# ---------------------------------------------------------------------------
# Allow lists - the module re-validates every call even though the gateway
# gate (MAIL_RULES) matches the same fields: a policy edit must not be able to
# silently widen this backend.
# ---------------------------------------------------------------------------

def _sender_allowed(from_filter: str) -> bool:
    """from_filter is a plain address or domain (NOT a regex) - or empty."""
    if not from_filter:
        return True
    token = from_filter.strip().strip("<>").lower()
    if "@" in token:
        token = token.split("@", 1)[1]
    return any(token == d or token.endswith("." + d) for d in load_config()["senders"])


def _subject_allowed(subject_contains: str) -> bool:
    if not subject_contains:
        return True
    low = subject_contains.lower()
    return any(h in low for h in load_config()["subjects"])


def _alias_allowed(alias: str) -> bool:
    """Only mail.ru-family addresses may be used as a To/Delivered-To filter."""
    if not alias:
        return True
    a = alias.strip().strip("<>").lower()
    domains = load_config()["alias_domains"]
    if not domains:
        return False
    return bool(re.fullmatch(
        r"[A-Za-z0-9._%+\-]+@(?:" + "|".join(re.escape(d) for d in domains) + r")",
        a))


# ---------------------------------------------------------------------------
# Extraction contract - field parity with the mail-fetch playbook this ports
# (same regexes, so callers keep the same {verify_link, code} shape).
# ---------------------------------------------------------------------------
VERIFY_LINK_RE = re.compile(
    r"https?://[^\s\"'<>]*github\.com[^\s\"'<>]*(?:confirm|verif)[^\s\"'<>]*",
    re.I)
ANY_VERIFY_LINK_RE = re.compile(
    r"https?://[^\s\"'<>]*(?:confirm|verif)[^\s\"'<>]*", re.I)
CODE_WORD_RE = re.compile(r"(?:code|код)[^0-9]{0,80}(\d{6,10})", re.I)
CODE_LINE_RE = re.compile(r"^\s*(\d{6,10})\s*$", re.M)
ADDRESS_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _hdr(value):
    """Decode a possibly RFC2047-encoded header into plain text."""
    if not value:
        return ""
    out = []
    for part, enc in email.header.decode_header(value):
        if isinstance(part, bytes):
            out.append(part.decode(enc or "utf-8", "replace"))
        else:
            out.append(part)
    return "".join(out).strip()


def _addrs(value):
    return [_hdr(v) for _, v in email.utils.getaddresses([value or ""]) if v]


def _html_to_text(html):
    """Convert HTML to readable text, KEEPING anchor hrefs.

    Detagging alone loses the verify link: in an HTML-only letter (which
    mail.ru produces often) the confirm URL lives ONLY in the href attribute,
    so an anchor is rewritten to <visible text> <href> before any tag is
    dropped.

    Patterns are built with chr(92)/chr(10)/chr(34) rather than escape
    sequences - the convention this module inherited from the playbook it
    ports. Keep it escape-free so later edits stay consistent.
    """
    BS = chr(92)                   # backslash, built at runtime (see note above)
    q = chr(34) + chr(39)          # double/single quote for attribute classes
    anchor_rx = "(?is)<a[^>]*?href=[" + q + "]([^" + q + "]+)[" + q + "][^>]*>(.*?)</a>"
    script_rx = "(?is)<(script|style)[^>]*>.*?</" + BS + "1>"
    br_rx = "(?i)<br" + BS + "s*/?>|</p>"
    tag_rx = "(?s)<[^>]+>"
    ws_rx = "[ " + BS + "t]{2,}"

    html = re.sub(anchor_rx, lambda m: m.group(2) + " " + m.group(1), html)
    html = re.sub(script_rx, " ", html)
    html = re.sub(br_rx, chr(10), html)
    html = re.sub(tag_rx, " ", html)
    for ent, ch in ((chr(38) + "nbsp;", " "), (chr(38) + "amp;", chr(38)),
                    (chr(38) + "lt;", chr(60)), (chr(38) + "gt;", chr(62)),
                    (chr(38) + "quot;", chr(34)), (chr(38) + "#39;", chr(39)),
                    (chr(38) + "#34;", chr(34))):
        html = html.replace(ent, ch)
    return re.sub(ws_rx, " ", html)


def _body_text(msg):
    """Text of the message body; text/plain preferred, HTML as fallback."""
    plain, html = [], []
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_filename():
            continue
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            continue
        if not payload:
            continue
        text = payload.decode(part.get_content_charset() or "utf-8", "replace")
        (plain if ctype == "text/plain" else html).append(text)
    if plain:
        return LF.join(plain)
    return _html_to_text(LF.join(html))


def _extract(text):
    """Return (verify_link, code) - field parity with mail-fetch."""
    link = None
    for rx in (VERIFY_LINK_RE, ANY_VERIFY_LINK_RE):
        m = rx.search(text)
        if m:
            link = m.group(0).rstrip(".,);]")
            break
    code = None
    m = CODE_WORD_RE.search(text)
    if m:
        code = m.group(1)
    else:
        m = CODE_LINE_RE.search(text)
        if m:
            code = m.group(1)
    return link, code


def _parse_since(value):
    """Accept epoch, YYYY-MM-DD or 'YYYY-MM-DD HH:MM' (UTC) - or None."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if re.fullmatch(r"\d{9,}", s):
        return float(s)
    import datetime as _dt
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return _dt.datetime.strptime(s, fmt).replace(
                tzinfo=_dt.timezone.utc).timestamp()
        except ValueError:
            continue
    raise ValueError("bad since: %r (want epoch, YYYY-MM-DD or 'YYYY-MM-DD HH:MM')" % value)


def _msg_ts(msg):
    import datetime as _dt
    try:
        dt = email.utils.parsedate_to_datetime(msg.get("Date"))
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------

def _open(account: str, timeout: int):
    """Connect + TLS. Returns (imap, port, mode).

    Tries the account's ORDERED transports; the first that completes a TLS
    handshake wins. Raises the last error when every entry failed - the caller
    turns that into transport_failed plus the per-port attempt triage.
    """
    cfg = accounts()[account]
    ctx = ssl.create_default_context()
    attempts: List[Dict[str, Any]] = []
    for port, mode in cfg.get("transports", ()):
        started = time.monotonic()
        try:
            if mode == "tls":
                imap = imaplib.IMAP4_SSL(cfg["host"], port, ssl_context=ctx,
                                         timeout=timeout)
            else:
                imap = imaplib.IMAP4(cfg["host"], port, timeout=timeout)
                typ, _ = imap.starttls(ssl_context=ctx)
                if typ != "OK":
                    raise imaplib.IMAP4.error("STARTTLS refused: %s" % (typ,))
            imap.sock.settimeout(timeout)
            attempts.append({"port": port, "mode": mode, "ok": True,
                             "seconds": round(time.monotonic() - started, 2)})
            return imap, port, mode
        except Exception as exc:
            attempts.append({"port": port, "mode": mode, "ok": False,
                             "error": _redact("%s: %s" % (type(exc).__name__, exc))[:160],
                             "seconds": round(time.monotonic() - started, 2)})
    raise socket.error("no usable transport: %s" % (attempts,))


def _fetch_headers(imap, uids):
    """Batch-fetch the filter headers. Returns {uid: {FIELD: value}}."""
    if not uids:
        return {}
    fields = "FROM TO CC DELIVERED-TO X-ORIGINAL-TO SUBJECT DATE"
    out: Dict[str, Dict[str, str]] = {}
    chunk = 25
    for i in range(0, len(uids), chunk):
        batch = uids[i:i + chunk]
        typ, resp = imap.uid("FETCH", ",".join(batch),
                             "(BODY.PEEK[HEADER.FIELDS (%s)])" % fields)
        if typ != "OK":
            continue
        for item in resp:
            if not isinstance(item, tuple):
                continue
            head = item[0] if isinstance(item[0], bytes) else str(item[0]).encode()
            m = re.search(rb"UID\s+(\d+)", head)
            if not m:
                continue
            uid = m.group(1).decode()
            out[uid] = {}
            try:
                msg = email.message_from_bytes(item[1])
            except Exception:
                continue
            for f in fields.split():
                out[uid][f] = _hdr(msg.get(f))
    return out


def _match(headers, alias, from_filter, since):
    """Decide whether a header block is the letter we were asked for."""
    if from_filter:
        token = from_filter.strip().strip("<>").lower()
        if "@" in token:
            token = token.split("@", 1)[1]
        senders = [s.lower() for s in _addrs(headers.get("FROM", ""))]
        if not any(s == token or s.endswith("@" + token) or s.endswith("." + token)
                   for s in senders):
            return False
    if alias:
        a = alias.strip().strip("<>").lower()
        recipients: List[str] = []
        for f in ("DELIVERED-TO", "X-ORIGINAL-TO", "TO", "CC"):
            recipients += [r.lower() for r in _addrs(headers.get(f, ""))]
        if a not in recipients:
            return False
    if since is not None:
        raw = headers.get("DATE", "")
        try:
            import datetime as _dt
            dt = email.utils.parsedate_to_datetime(raw) if raw else None
            if dt is None:
                return True  # undated: keep it, the caller can triage
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_dt.timezone.utc)
            if dt.timestamp() < since:
                return False
        except Exception:
            return True
    return True


# ---------------------------------------------------------------------------
# Scope normalization + one scan pass
# ---------------------------------------------------------------------------

class ScopeError(Exception):
    """A scope refusal carrying the typed reason the tool returns."""

    def __init__(self, payload: Dict[str, Any]):
        super().__init__(payload.get("reason", "denied"))
        self.payload = payload


def _as_int(value, default, low, high):
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def _scope(kw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize + validate the open arguments. Raises ScopeError.

    This is the SECOND gate (the first is the gateway policy built from the
    same config): it re-checks account, sender, subject and alias so a policy
    edit cannot silently widen the backend.
    """
    limits = _limits()
    account = str(kw.get("account") or "").strip().lower()
    alias = str(kw.get("to") or kw.get("alias") or "").strip()
    from_filter = str(kw.get("from_filter") or kw.get("from") or "").strip()
    subject_contains = str(kw.get("subject_contains") or kw.get("subject") or "").strip()
    folder = str(kw.get("folder") or "").strip() or None
    uid = str(kw.get("uid") or "").strip() or None
    since_raw = kw.get("since")
    try:
        since = _parse_since(since_raw)
    except ValueError as exc:
        raise ScopeError({"ok": False, "reason": "bad_since", "error": str(exc)})

    known = sorted(accounts())
    if not account:
        raise ScopeError({"ok": False, "reason": "missing_account",
                          "known_accounts": known})
    if account not in accounts():
        raise ScopeError({"ok": False, "reason": "unknown_account", "account": account,
                          "known_accounts": known,
                          "hint": "an account is added in the mounted mail.yaml "
                                  "(accounts + allow lists), never in the call"})
    allowed_folders = tuple(accounts()[account].get("folders") or ())
    if folder is not None and folder not in allowed_folders:
        raise ScopeError({"ok": False, "reason": "bad_folder", "folder": folder,
                          "allowed": list(allowed_folders)})
    if uid is not None and not re.fullmatch(r"\d{1,12}", uid):
        raise ScopeError({"ok": False, "reason": "bad_uid", "uid": uid})
    if not _sender_allowed(from_filter):
        raise ScopeError({"ok": False, "reason": "denied_from", "from_filter": from_filter,
                          "allowed_domains": list(load_config()["senders"])})
    if not _subject_allowed(subject_contains):
        raise ScopeError({"ok": False, "reason": "denied_subject",
                          "subject_contains": subject_contains,
                          "allowed_hints": list(load_config()["subjects"])})
    if not _alias_allowed(alias):
        raise ScopeError({"ok": False, "reason": "denied_alias", "to": alias})

    return {
        "account": account,
        "alias": alias,
        "from_filter": from_filter,
        "subject_contains": subject_contains,
        "folder": folder,
        "uid": uid,
        "since": since,
        "since_raw": since_raw,
        "limit": _as_int(kw.get("limit"), limits["default_limit"], 1, limits["max_limit"]),
        "timeout": _as_int(kw.get("timeout"), limits["default_timeout"], 5, limits["max_timeout"]),
        "max_matches": limits.get("max_matches", 5),
    }


def _letter_view(headers: Dict[str, str], uid: str, folder: str, msg=None):
    """Build the result entry for one matched letter."""
    view = {
        "folder": folder,
        "uid": uid,
        "from": headers.get("FROM", ""),
        "to": headers.get("TO", "") or headers.get("DELIVERED-TO", ""),
        "delivered_to": headers.get("DELIVERED-TO", "") or headers.get("X-ORIGINAL-TO", ""),
        "subject": headers.get("SUBJECT", ""),
        "date": headers.get("DATE", ""),
        "date_ts": _msg_ts(msg) if msg is not None else None,
        "verify_link": None,
        "code": None,
        "snippet": None,
    }
    return view


def _scan(scope: Dict[str, Any]) -> Dict[str, Any]:
    """One pass over the account's folders. Returns the tool result dict.

    Read-only: every SELECT is readonly and every body fetch uses BODY.PEEK,
    so nothing is ever marked seen or modified. There is no write path in this
    module at all - no delete, no move, no send.
    """
    import datetime as _dt

    started = time.monotonic()
    limits = _limits()
    account = scope["account"]
    env_name, secret = _credential(account)
    if not secret:
        return {"ok": False, "reason": "credential_missing", "account": account,
                "env": env_name, "elapsed_s": 0.0,
                "hint": "operator: add %s to the gateway environment "
                        "(llm-password.env, next to deploy/.env.template), then recreate the "
                        "mcp service. The password never travels through args."
                        % (env_name or "<password_env>",)}

    targets = [scope["folder"]] if scope["folder"] else list(
        accounts()[account].get("folders") or ())
    diag: Dict[str, Any] = {"account": account, "folders": targets,
                            "filters": {"to": scope["alias"] or None,
                                        "from_filter": scope["from_filter"] or None,
                                        "subject_contains": scope["subject_contains"] or None,
                                        "since": scope["since_raw"],
                                        "uid": scope["uid"]},
                            "folder_errors": {}}
    imap = None
    try:
        imap, port, mode = _open(account, scope["timeout"])
        diag["transport"] = {"host": accounts()[account]["host"], "port": port, "mode": mode}
        try:
            imap.login(account, secret)
        except imaplib.IMAP4.error as exc:
            return {"ok": False, "reason": "auth_failed", "account": account,
                    "env": env_name, "diag": diag, "error": _redact(str(exc))[:200]}

        matches: List[Dict[str, Any]] = []
        scanned_total = 0
        max_matches = max(1, int(scope.get("max_matches") or limits.get("max_matches", 5)))
        for tgt in targets:
            typ, data = imap.select(tgt, readonly=True)
            if typ != "OK":
                # never fatal: an account's exact folder name can differ
                diag["folder_errors"][tgt] = _redact(str(data))[:160]
                continue

            if scope["since"] is not None:
                stamp = _dt.datetime.fromtimestamp(
                    scope["since"], _dt.timezone.utc).strftime("%d-%b-%Y")
                typ, data = imap.uid("SEARCH", None, "SINCE", stamp)
            else:
                typ, data = imap.uid("SEARCH", None, "ALL")
            uids = (data[0] or b"").split() if typ == "OK" else []
            diag.setdefault("mailbox_total", {})[tgt] = len(uids)
            uids = [u.decode() for u in uids[-scope["limit"]:]][::-1]  # newest first
            if scope["uid"]:
                if scope["uid"] in uids:
                    uids = [scope["uid"]]
                elif tgt == targets[0]:
                    uids = [scope["uid"]]   # one attempt; IMAP answers BAD if absent
                else:
                    continue

            headers = _fetch_headers(imap, uids)
            diag["headers_fetched"] = diag.get("headers_fetched", 0) + len(headers)
            scanned = 0
            for uid in uids:
                h = headers.get(uid)
                if not h:
                    continue
                scanned += 1
                scanned_total += 1
                if not _match(h, scope["alias"], scope["from_filter"], scope["since"]):
                    continue
                if scope["subject_contains"] and \
                        scope["subject_contains"].lower() not in h.get("SUBJECT", "").lower():
                    continue
                view = _letter_view(h, uid, tgt)
                if len(matches) < max_matches:
                    typ, resp = imap.uid("FETCH", uid, "(BODY.PEEK[])")
                    if typ == "OK":
                        raw = None
                        for item in resp:
                            if isinstance(item, tuple):
                                raw = item[1]
                                break
                        if raw is not None:
                            msg = email.message_from_bytes(raw)
                            body = _body_text(msg)
                            link, code = _extract(body)
                            view["verify_link"] = link
                            view["code"] = code
                            view["snippet"] = re.sub(r"\s+", " ", body)[:400]
                            view["date_ts"] = _msg_ts(msg)
                matches.append(view)
                if len(matches) >= max_matches:
                    break
            diag.setdefault("scanned_per_folder", {})[tgt] = scanned
            if len(matches) >= max_matches:
                break

        out = {"ok": True, "found": bool(matches), "count": len(matches),
               "account": account, "transport": diag.get("transport"),
               "matches": matches, "scanned": scanned_total,
               "elapsed_s": round(time.monotonic() - started, 2), "diag": diag}
        if not matches:
            out["reason"] = "not_found"
        return out

    except (socket.error, imaplib.IMAP4.error, ssl.SSLError, OSError) as exc:
        return {"ok": False, "reason": "transport_failed", "account": account,
                "diag": diag, "elapsed_s": round(time.monotonic() - started, 2),
                "error": _redact("%s: %s" % (type(exc).__name__, exc))[:300]}
    except Exception:  # noqa: BLE001 - report, never raise into the caller
        import traceback
        return {"ok": False, "reason": "error", "account": account, "diag": diag,
                "elapsed_s": round(time.monotonic() - started, 2),
                "error": _redact(traceback.format_exc())[-1200:]}
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

_TOOL_NAMES = ("mail_search", "mail_fetch", "mail_wait_for")

_SCOPE_PROPS = {
    "account": {"type": "string",
                "description": "Mailbox key from the gateway's mail config (see mail_status)."},
    "from_filter": {"type": "string",
                    "description": "Sender domain or full address; must be in the configured allow list."},
    "subject_contains": {"type": "string",
                        "description": "Subject substring; must be in the configured allow list."},
    "alias": {"type": "string",
              "description": "Recipient address of a temp alias (mail.ru family)."},
    "since": {"type": "string",
              "description": "Only letters at/after this time: epoch, YYYY-MM-DD or 'YYYY-MM-DD HH:MM' (UTC)."},
    "folder": {"type": "string",
               "description": "Optional single folder to scan (default: all folders of the account)."},
    "limit": {"type": "integer",
              "description": "Max newest letters to examine per folder (default from config)."},
    "timeout": {"type": "integer",
                "description": "Per-connection socket timeout in seconds (default from config)."},
}


def _describe(message: str, props: Optional[Dict[str, Any]] = None,
             required: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"type": "object", "properties": props or _SCOPE_PROPS,
            "required": required or []}


async def _tool_search(**kw) -> str:
    return await _run(kw, bodies=False)


async def _tool_fetch(**kw) -> str:
    return await _run(kw, bodies=True)


async def _tool_wait(**kw) -> str:
    return await _run(kw, bodies=True, wait=True)


async def _tool_status(**kw) -> str:
    """Report what is wired - never a secret, only names and counts."""
    cfg = load_config()
    accs = cfg["accounts"]
    if not accs:
        return ("mail: NOT CONFIGURED (no accounts in %s) - every call is denied."
                % (config_path(),))
    lines = ["mail: configured (config %s)" % (config_path(),)]
    for addr, conf in sorted(accs.items()):
        name = conf.get("password_env") or "<none>"
        have = "yes" if os.environ.get(name) else "NO"
        lines.append("  %s host=%s transports=%s folders=%s password_env=%s set=%s"
                     % (addr, conf.get("host"), list(conf.get("transports") or ()),
                        list(conf.get("folders") or ()), name, have))
    lines.append("  senders=%s" % (",".join(cfg["senders"]) or "<none>",))
    lines.append("  subjects=%s" % (",".join(cfg["subjects"]) or "<none>",))
    lines.append("  alias_domains=%s" % (",".join(cfg["alias_domains"]) or "<none>",))
    return LF.join(lines)


def _reply(payload: Dict[str, Any]) -> str:
    import json
    return json.dumps(payload, ensure_ascii=False, indent=2)


async def _run(kw: Dict[str, Any], bodies: bool, wait: bool = False) -> str:
    """Shared entry: validate scope, then scan (once, or until a deadline)."""
    try:
        scope = _scope(kw)
    except ScopeError as exc:
        return _reply(exc.payload)
    scope["bodies"] = bodies

    limits = _limits()
    if not wait:
        return _reply(_scan(scope))

    wait_ceiling = min(int(limits.get("wait_max_seconds", 60)), WAIT_CEILING_SECONDS)
    try:
        budget = int(kw.get("timeout") or limits.get("default_wait_seconds", 30))
    except (TypeError, ValueError):
        budget = int(limits.get("default_wait_seconds", 30))
    budget = max(5, min(budget, wait_ceiling))
    poll = max(5, int(limits.get("wait_poll_seconds", 15)))

    started = time.monotonic()
    attempts = 0
    last: Dict[str, Any] = {}
    while True:
        attempts += 1
        last = _scan(scope)
        if last.get("ok") and last.get("found"):
            last["waited_s"] = round(time.monotonic() - started, 2)
            last["attempts"] = attempts
            return _reply(last)
        if not last.get("ok"):
            # a hard failure (transport, credential, auth) is reported at once:
            # waiting cannot fix a missing password or a closed port.
            last["waited_s"] = round(time.monotonic() - started, 2)
            last["attempts"] = attempts
            return _reply(last)
        remaining = budget - (time.monotonic() - started)
        if remaining <= poll:
            break
        await asyncio.sleep(poll)
    last["reason"] = last.get("reason") or "timeout"
    last["timed_out"] = True
    last["waited_s"] = round(time.monotonic() - started, 2)
    last["attempts"] = attempts
    return _reply(last)


TOOL_SPECS = [
    {"name": "mail_search",
     "description": ("List letters in a configured mailbox that match the open filters "
                     "(headers only: from/subject/date/uid). Read-only. Use mail_fetch "
                     "to also get the body-derived verify_link/code."),
     "handler": _tool_search,
     "schema": _describe("")},
    {"name": "mail_fetch",
     "description": ("Find the matching letter AND extract its verify link + numeric code. "
                     "Read-only. Returns {matches:[{folder,uid,from,to,subject,date,"
                     "verify_link,code,snippet}]} - at most the newest few."),
     "handler": _tool_fetch,
     "schema": _describe("")},
    {"name": "mail_wait_for",
     "description": ("Hold an expectation open: poll the mailbox until a matching letter "
                     "arrives, then return the same shape as mail_fetch. Use this instead "
                     "of retry loops after triggering an email (signup confirmations, "
                     "codes). `timeout` is the total wait in seconds, capped below the "
                     "gateway tool wall."),
     "handler": _tool_wait,
     "schema": _describe("", props={**_SCOPE_PROPS,
                                    "timeout": {"type": "integer",
                                                "description": "Total wait in seconds."}})},
    {"name": "mail_status",
     "description": "Mail backend health: configured accounts, their password env NAMES "
                    "and whether each password is present. Never returns a secret.",
     "handler": _tool_status,
     "schema": {"type": "object", "properties": {}}},
]


# ---------------------------------------------------------------------------
# Gate rules - GENERATED from the same mounted config, so the gateway layer and
# the module's own re-validation cannot drift. Field paths are top-level:
# matches_rule() skips a rule when the named field is ABSENT, so the trailing
# per-tool deny is what catches a call with no account at all.
# ---------------------------------------------------------------------------

_ANY_TOOL = "^(?:%s)$" % ("|".join(_TOOL_NAMES),)


def mail_rules() -> List[Dict[str, Any]]:
    """Gate rules for the mail tools, built from the SAME mounted config.

    One document feeds both layers: these rules (the gateway's args-level
    gate) and the module's own _scope() re-validation. Neither hardcodes an
    account or a domain, so the two cannot drift.

    Field paths are top-level (matches_rule looks the field up directly in the
    call arguments). A rule whose field is ABSENT is skipped, which is why the
    trailing per-tool deny carries no scope key: it is the one that catches a
    call with no account at all.

    Patterns are assembled by concatenation, never by %-formatting: the
    address classes contain a literal percent sign ([A-Za-z0-9._%+-]) and a
    format would read '%+' as a conversion.
    """
    cfg = load_config()
    accs = cfg["accounts"]
    if not accs:
        return [{"match": {"tool": _ANY_TOOL}, "action": "deny",
                 "reason": "mail backend is not configured: no accounts in "
                           + config_path() + ". Ask the operator to mount the "
                           "mail config; until then every mail call is denied."}]

    acct_alt = "|".join(re.escape(a) for a in sorted(accs))
    # (?!) never matches, so an empty allow list yields an unsatisfiable
    # pattern instead of a permissive one - closed by construction.
    senders = "|".join(re.escape(d) for d in cfg["senders"]) or r"(?!)not-configured"
    subjects = "|".join(re.escape(s) for s in cfg["subjects"]) or r"(?!)not-configured"
    domains = "|".join(re.escape(d) for d in cfg["alias_domains"]) or r"(?!)not-configured"

    sender_pat = r"(?i)^(?!(?:[A-Za-z0-9._%+-]+@)?(?:[A-Za-z0-9-]+\.)*(?:" + senders + r")$)"
    alias_pat = r"(?i)^(?!(?:[A-Za-z0-9._%+-]+@)(?:" + domains + r")$)"
    subject_pat = r"(?i)^(?!.*(?:" + subjects + r").*)"
    account_pat = r"(?i)^(?:" + acct_alt + r")$"

    rules: List[Dict[str, Any]] = [
        {"match": {"tool": _ANY_TOOL, "from_filter": sender_pat},
         "action": "deny",
         "reason": "mail: sender '${args.from_filter}' is outside the allowed domains."},
        {"match": {"tool": _ANY_TOOL, "from": sender_pat},
         "action": "deny",
         "reason": "mail: sender '${args.from}' is outside the allowed domains."},
        {"match": {"tool": _ANY_TOOL, "to": alias_pat},
         "action": "deny",
         "reason": "mail: recipient filter '${args.to}' is not a configured alias domain."},
        {"match": {"tool": _ANY_TOOL, "alias": alias_pat},
         "action": "deny",
         "reason": "mail: recipient filter '${args.alias}' is not a configured alias domain."},
        {"match": {"tool": _ANY_TOOL, "subject_contains": subject_pat},
         "action": "deny",
         "reason": "mail: subject filter '${args.subject_contains}' is outside the allowed set."},
        {"match": {"tool": _ANY_TOOL, "subject": subject_pat},
         "action": "deny",
         "reason": "mail: subject filter '${args.subject}' is outside the allowed set."},
        # mail_status is health-only (account keys + env var NAMES + whether
        # each password is set): no letter, no secret. It takes no scope
        # argument, and the scope denies are deliberately scoped to the three
        # READ tools, so it neither needs nor inherits one.
        {"match": {"tool": r"^mail_status$"},
         "action": "allow"},
        {"match": {"tool": _ANY_TOOL, "account": account_pat},
         "action": "allow"},
        {"match": {"tool": _ANY_TOOL},
         "action": "deny",
         "reason": "mail: args.account must be one of: " + ", ".join(sorted(accs))
                   + " (got an account outside the allow list, or none at all)."},
        {"match": {"tool": ".*"},
         "action": "deny",
         "reason": "mail exposes only: "
                   + ", ".join(s["name"] for s in TOOL_SPECS) + "."},
    ]
    return rules


# ---------------------------------------------------------------------------
# Synthetic-backend plumbing (same contract as telegram_mcp): the gateway
# mounts these tools as an in-process "virtual backend" with no transport.
# ---------------------------------------------------------------------------

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

    Mirrors policy_proxy.forward()'s return shape so the compound dispatcher
    treats this in-process backend exactly like a remote one.
    """
    for spec in TOOL_SPECS:
        if spec["name"] == tool_name:
            try:
                out = await spec["handler"](**(arguments or {}))
            except Exception as e:
                import traceback
                log_lines = _redact(traceback.format_exc())[-800:]
                return {"error": "mail %s: %s | %s" % (tool_name, e, log_lines)}
            return {"content": [out], "structuredContent": None, "isError": False}
    return {"error": "mail: unknown tool '%s'" % (tool_name,)}


def attach_synthetic_backend(backend_status_cls, backend_config_cls, name: str = "mail"):
    """Build the BackendStatus that makes compounds see the mail tools.

    Nothing to discover over a transport, so the tool list is registered by
    hand with `synthetic = True`; the compound dispatcher then routes calls
    through mail_mcp.forward().
    """
    cfg = backend_config_cls(name=name)
    status = backend_status_cls(name=name, config=cfg, rules=mail_rules())
    status.synthetic = True
    status.healthy = True
    status.tools = local_tools()
    status.tools_count = len(status.tools)
    status.error = None
    return status


def install_mail_tools(server, name: str = "mail") -> None:
    """Register mail_search/fetch/wait_for/status on a MountedServer."""
    del name  # the backend name is carried by the route, not the handlers
    for spec in TOOL_SPECS:
        server.tool(name=spec["name"], description=spec["description"],
                    inputSchema=spec["schema"])(spec["handler"])
