#!/usr/bin/env python3
"""
Policy Proxy — MCP tool call router with per-backend policy enforcement.

Each backend is mounted at its own path:
  /mcp/k8s   -> Kubernetes backend
  /mcp/ssh   -> SSH backend
  /mcp/file  -> File backend

Health endpoint reports per-backend status and returns 503 if any
backend has 0 tools (upstream down). A background watchdog periodically
re-discovers tools from unhealthy backends for automatic recovery.

Supports a "confirm" action that sends an approval request to the operator
via a notification backend (e.g. Telegram) and waits for a response.
"""

import asyncio
import contextlib
import contextvars
import glob
import json
import logging
import os
import re
import shlex
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx
import yaml
import uvicorn
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.routing import Mount, Route
from starlette.responses import JSONResponse

from mcp.client.streamable_http import streamablehttp_client
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp import ClientSession
from mcp.shared.exceptions import McpError

from mcp_gateway.mounted_server import MountedServer
from mcp_gateway.policy_yaml import PolicyLoader

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("mcp-gateway")

# Silence noisy upstream loggers. We keep our own "mcp-gateway" logger at
# INFO and add explicit tool-call logging, so the operator sees exactly what
# tool was called and the result — without the MCP SDK / uvicorn chatter.
for _noisy in ("mcp.server.streamable_http", "mcp.server.lowlevel.server", "uvicorn.access"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

# Fields whose values must never appear in logs (secrets / credentials).
_SENSITIVE_ARG_KEYS = {
    "sudoPassword", "password", "token", "secret", "keyPath",
    "clientHost", "clientIp", "privateKeyPath",
}


def _sanitize_args(arguments: dict) -> dict:
    """Return a copy of arguments with sensitive values redacted for logging."""
    out = {}
    for k, v in arguments.items():
        if k in _SENSITIVE_ARG_KEYS:
            out[k] = "***"
        else:
            out[k] = v
    return out


def _preview(text: str, limit: int = 200) -> str:
    """Truncate a result string for logging."""
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= limit else text[:limit] + "..."

POLICY_DIR = os.environ.get("POLICY_DIR", "/etc/mcp-gateways/policy")
NOTIFICATION_CONFIG_PATH = os.environ.get("NOTIFICATION_CONFIG", "/etc/mcp-gateways/notifications.yaml")

# Maximum retries for backend discovery
MAX_DISCOVERY_RETRIES = int(os.environ.get("MCP_DISCOVERY_RETRIES", "5"))
DISCOVERY_RETRY_DELAY = float(os.environ.get("MCP_DISCOVERY_RETRY_DELAY", "2.0"))

# Watchdog interval for re-discovering unhealthy backends (seconds)
WATCHDOG_INTERVAL = float(os.environ.get("MCP_WATCHDOG_INTERVAL", "30.0"))

# Reverse DNS timeout (seconds)
DNS_TIMEOUT = float(os.environ.get("MCP_DNS_TIMEOUT", "1.0"))


@dataclass
class ClientInfo:
    """Client connection info extracted from the incoming request."""
    ip: str
    host: str


# ContextVar holding per-request client info
_client_info: contextvars.ContextVar[Optional[ClientInfo]] = contextvars.ContextVar("client_info", default=None)

# DNS reverse lookup cache: ip -> hostname
_dns_cache: Dict[str, str] = {}


def _resolve_host(ip: str) -> str:
    """Resolve IP to hostname with caching. Falls back to IP on failure."""
    if ip in _dns_cache:
        return _dns_cache[ip]
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        host = ip
    finally:
        socket.setdefaulttimeout(None)
    _dns_cache[ip] = host
    return host


class ClientInfoMiddleware(BaseHTTPMiddleware):
    """Extracts client IP/Host from each request and stores in ContextVar."""

    async def dispatch(self, request: Request, call_next):
        client = request.client
        ip = client.host if client else "0.0.0.0"
        host = _resolve_host(ip)
        token = _client_info.set(ClientInfo(ip=ip, host=host))
        try:
            response = await call_next(request)
        finally:
            _client_info.reset(token)
        return response


class CORSSupportMiddleware(BaseHTTPMiddleware):
    """Add permissive CORS headers to all responses (browser MCP clients).

    Mirrors the middleware used by vscode-mcp (vscode_mcp/server.py) that was
    required for browser-based MCP clients (e.g. mcp super-assistant).

    Only applied to compound endpoints that opt in via `cors: true`.
    """

    async def dispatch(self, request, call_next):
        # Handle OPTIONS preflight requests
        if request.method == "OPTIONS":
            return JSONResponse(
                {"ok": True},
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age": "86400",
                }
            )

        response = await call_next(request)

        # Add CORS headers to the response
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"

        return response


@dataclass
class BackendConfig:
    name: str
    url: Optional[str] = None
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Optional[Dict[str, str]] = None
    cwd: Optional[str] = None
    transport: str = "http"
    path: str = ""
    keepalive: bool = False
    pass_kwargs_raw: bool = False
    default_deny: str = "Access denied."
    headers: Optional[Dict[str, str]] = None


@dataclass
class BackendStatus:
    """Runtime health status for a backend."""
    name: str
    tools_count: int = 0
    healthy: bool = False
    error: Optional[str] = None
    server: Optional[MountedServer] = None
    config: Optional[BackendConfig] = None
    rules: List[Dict] = field(default_factory=list)


@dataclass
class CompoundConfig:
    """Configuration for a compound MCP endpoint."""
    name: str
    path: str
    backends: List[str]
    description: str = ""
    # Optional MCP prompt-resource bootstrap.
    # This is exposed at the compound endpoint as prompts/list + prompts/get.
    bootstrap_prompt_name: Optional[str] = None
    bootstrap_prompt_text: Optional[str] = None
    # Browser-facing features (for MCP clients running in a web browser,
    # e.g. mcp super-assistant). All default to off to preserve the
    # current security posture.
    # cors: add permissive CORS headers (Access-Control-Allow-Origin: *, etc.)
    cors: bool = False
    # schema: 'full' (default) keeps outputSchema on advertised tools;
    # 'minimal' strips outputSchema (equivalent to vscode-mcp's
    # structured_output=False) for browsers that choke on structured schemas.
    schema: str = "full"
    # allow_browser: allow arbitrary browser origins by disabling DNS
    # rebinding protection (required for browser origins like chrome-extension://
    # or http://localhost:<port> that aren't in the allowlist).
    allow_browser: bool = False


@dataclass
class CompoundStatus:
    """Runtime health status for a compound."""
    name: str
    path: str
    backends_status: Dict[str, BackendStatus] = field(default_factory=dict)
    tools_count: int = 0
    healthy: bool = False
# ---------------------------------------------------------------------------
# Notification / Confirm system
# ---------------------------------------------------------------------------

@dataclass
class NotificationConfig:
    """Global notification configuration loaded from notifications.yaml."""
    timeout: int = 300
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_poll_interval: float = 3.0


@dataclass
class PendingRequest:
    """An approval request awaiting operator response."""
    request_id: str
    event: asyncio.Event = field(default_factory=asyncio.Event)
    approved: Optional[bool] = None
    created_at: float = field(default_factory=time.monotonic)
    message_id: Optional[int] = None
    chat_id: Optional[int] = None


# Global store of pending approval requests: request_id -> PendingRequest
_pending_requests: Dict[str, PendingRequest] = {}

# Global notification config (loaded at startup)
_notification_config: Optional[NotificationConfig] = None


def load_notification_config(path: str) -> Optional[NotificationConfig]:
    """Load global notification configuration from YAML file.

    Returns None if the file doesn't exist (notifications disabled).
    """
    if not os.path.exists(path):
        log.info("No notification config at %s — confirm action disabled", path)
        return None

    try:
        with open(path) as f:
            raw = yaml.load(f, Loader=PolicyLoader)
    except Exception as e:
        log.warning("Failed to load notification config %s: %s", path, e)
        return None

    if not raw:
        return None

    n = raw.get("notifications", {})
    # Resolve ${env:VAR} references for the timeout field too.
    # If the env var is unset, resolve_env_value leaves the template
    # unresolved — fall back to the default instead of crashing.
    try:
        timeout = int(resolve_env_value(str(n.get("timeout", "300"))))
    except (ValueError, TypeError):
        timeout = 300
    cfg = NotificationConfig(timeout=timeout)

    tg = n.get("telegram", {})
    if tg.get("enabled", False):
        cfg.telegram_enabled = True
        cfg.telegram_bot_token = resolve_env_value(tg.get("bot_token", ""))
        cfg.telegram_chat_id = resolve_env_value(tg.get("chat_id", ""))
        cfg.telegram_poll_interval = float(tg.get("poll_interval", 3.0))

    log.info("Loaded notification config: telegram=%s, timeout=%ds",
             cfg.telegram_enabled, cfg.timeout)
    return cfg

# ---------------------------------------------------------------------------
# Telegram backend
# ---------------------------------------------------------------------------

class TelegramBackend:
    """Send approval requests via Telegram Bot API with inline keyboards.

    Uses long-polling (getUpdates) to receive callback_query responses.
    """

    API_BASE = "https://api.telegram.org/bot{token}"

    # Max length of a single argument value shown in the approval message.
    # Telegram messages are limited to 4096 chars; long payloads (e.g. a
    # Confluence page body) must be truncated to keep the message readable
    # and within the limit.
    _MAX_ARG_VALUE_LEN = 200
    _MAX_TOTAL_ARGS_LEN = 1500

    def __init__(self, bot_token: str, chat_id: str, poll_interval: float = 3.0):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.poll_interval = poll_interval
        self._api_base = self.API_BASE.format(token=bot_token)
        self._offset = 0
        self._running = False
        self._client = httpx.AsyncClient(timeout=10.0)

    async def send_approval_request(self, request_id: str, tool_name: str,
                                    arguments: dict, client_info: Optional[ClientInfo],
                                    reason: str, backend_name: str = "") -> bool:
        """Send a message with Approve/Reject buttons. Returns True if sent OK."""
        # Build a readable plain-text summary. No parse_mode is used, so no
        # escaping is needed — any character is safe. Long values (e.g. a
        # Confluence page body) are truncated so the message stays within
        # Telegram's 4096-char limit and remains readable.
        args_parts = []
        for k, v in arguments.items():
            if k not in ("clientHost", "clientIp"):
                raw_val = str(v)
                if len(raw_val) > self._MAX_ARG_VALUE_LEN:
                    raw_val = raw_val[: self._MAX_ARG_VALUE_LEN] + f"... (truncated, {len(str(v))} chars)"
                args_parts.append(f"{k}={raw_val}")
        args_str = ", ".join(args_parts)
        if len(args_str) > self._MAX_TOTAL_ARGS_LEN:
            args_str = args_str[: self._MAX_TOTAL_ARGS_LEN] + "... (truncated)"

        # Build tool display name
        tool_display = f"[{backend_name}] / [{tool_name}]" if backend_name else f"[{tool_name}]"

        text_parts = [
            f"🔐 MCP Approval Required",
            f"Tool: {tool_display}",
            f"Args: {args_str}",
            f"Reason: {reason}",
            f"Status: waiting for approval",
        ]
        if client_info:
            text_parts.append(f"Client: {client_info.host} / {client_info.ip}")

        text = "\n".join(text_parts)

        keyboard = {
            "inline_keyboard": [[
                {"text": "✅ Approve", "callback_data": f"approve:{request_id}"},
                {"text": "❌ Reject", "callback_data": f"reject:{request_id}"},
            ]]
        }

        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "reply_markup": json.dumps(keyboard),
        }

        try:
            r = await self._client.post(f"{self._api_base}/sendMessage", json=payload)
            if r.status_code != 200:
                log.error("Telegram sendMessage failed: %s %s", r.status_code, r.text)
                return False

            # Store message_id and chat_id for later edits
            result = r.json()
            if result.get("ok"):
                msg = result.get("result", {})
                pending = _pending_requests.get(request_id)
                if pending:
                    pending.message_id = msg.get("message_id")
                    pending.chat_id = msg.get("chat", {}).get("id")

            return True
        except Exception as e:
            log.error("Telegram sendMessage error: %s", e)
            return False

    async def poll_loop(self):
        """Background task: poll Telegram for callback_query responses."""
        self._running = True
        while self._running:
            try:
                params = {
                    "offset": self._offset,
                    "timeout": 10,
                    "allowed_updates": ["callback_query"],
                }
                r = await self._client.get(f"{self._api_base}/getUpdates", params=params)
                if r.status_code != 200:
                    await asyncio.sleep(self.poll_interval)
                    continue

                updates = r.json().get("result", [])
                for update in updates:
                    self._offset = update["update_id"] + 1
                    cq = update.get("callback_query")
                    if not cq:
                        continue

                    data = cq.get("data", "")
                    msg = cq.get("message", {})
                    chat = msg.get("chat", {})
                    from_user = cq.get("from", {})

                    # Parse callback data: "approve:<request_id>" or "reject:<request_id>"
                    parts = data.split(":", 1)
                    if len(parts) != 2:
                        continue

                    action, request_id = parts
                    pending = _pending_requests.get(request_id)
                    if not pending:
                        # Unknown/expired request — acknowledge
                        await self._answer_callback(cq["id"], "Request expired or unknown")
                        continue

                    if action == "approve":
                        pending.approved = True
                        await self._answer_callback(cq["id"], "✅ Approved — executing now")
                        # Keep original message but update status and remove buttons
                        original_text = msg.get("text", "")
                        operator_name = from_user.get('first_name', 'Operator')
                        status_text = f"Status: approved by {operator_name}\n"
                        if "Status:" in original_text:
                            updated_text = re.sub(r"Status:.*\n", status_text, original_text)
                        else:
                            updated_text = original_text.rstrip("\n") + "\n\n" + status_text
                        await self._edit_message(chat["id"], msg["message_id"], updated_text, remove_keyboard=True)
                    elif action == "reject":
                        pending.approved = False
                        await self._answer_callback(cq["id"], "❌ Rejected")
                        # Keep original message but update status and remove buttons
                        original_text = msg.get("text", "")
                        operator_name = from_user.get('first_name', 'Operator')
                        status_text = f"Status: declined by {operator_name}\n"
                        if "Status:" in original_text:
                            updated_text = re.sub(r"Status:.*\n", status_text, original_text)
                        else:
                            updated_text = original_text.rstrip("\n") + "\n\n" + status_text
                        await self._edit_message(chat["id"], msg["message_id"], updated_text, remove_keyboard=True)
                    else:
                        continue

                    pending.event.set()

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.warning("Telegram poll error: %s", e)
                await asyncio.sleep(self.poll_interval)

    async def _answer_callback(self, callback_id: str, text: str):
        try:
            await self._client.post(f"{self._api_base}/answerCallbackQuery", json={
                "callback_query_id": callback_id,
                "text": text,
            })
        except Exception:
            pass

    async def _edit_message(self, chat_id: int, message_id: int, text: str, remove_keyboard: bool = False):
        try:
            payload = {
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text,
            }
            if remove_keyboard:
                payload["reply_markup"] = json.dumps({"inline_keyboard": []})
            await self._client.post(f"{self._api_base}/editMessageText", json=payload)
        except Exception:
            pass

    async def edit_request_timeout(self, request_id: str):
        """Edit the approval request message to show timeout status."""
        pending = _pending_requests.get(request_id)
        if not pending or not pending.message_id or not pending.chat_id:
            return

        # Build timeout status message
        timeout_text = (
            f"⏰ Approval Request Timed Out\n"
            f"Request ID: {request_id[:8]}...\n"
            f"Status: timed out\n"
        )

        # Edit the existing message (keep or remove keyboard as needed)
        await self._edit_message(pending.chat_id, pending.message_id, timeout_text, remove_keyboard=True)

    async def shutdown(self):
        self._running = False
        await self._client.aclose()


# Global telegram backend instance (set at startup if enabled)
_telegram_backend: Optional[TelegramBackend] = None


# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------

def _normalize_match_value(value):
    """Normalize a policy match-field value.

    Accepts either a single regex string (passed through unchanged) or a YAML
    sequence. A flat sequence (e.g. from `!concat [*a, *b]` or a literal list)
    is joined into an anchored alternation: `[a, b, c]` → `^(?:a|b|c)$`.

    Nested lists (a bare `[*a, *b]` without `!concat`) are rejected — use
    `!concat` to compose lists from anchors/aliases.
    """
    if isinstance(value, list):
        for v in value:
            if isinstance(v, list):
                raise ValueError(
                    "Nested list in match field without !concat. "
                    "Use '!concat' to merge anchored lists, e.g. binary: !concat [*a, *b]"
                )
        if not value:
            return "(?!x)x"  # empty list: match nothing
        return "^(?:" + "|".join(str(v) for v in value) + ")$"
    return value


def load_backend_policy(path: str) -> Tuple[BackendConfig, List[Dict]]:
    with open(path) as f:
        raw = yaml.load(f, Loader=PolicyLoader)
    br = raw.get("backend", {})
    # Normalize list-valued match fields (anchors/aliases resolved by PyYAML).
    rules = raw.get("rules", [])
    for rule in rules:
        match = rule.get("match")
        if isinstance(match, dict):
            for k, v in match.items():
                match[k] = _normalize_match_value(v)
    return BackendConfig(
        name=br.get("name", "unknown"), url=br.get("url") and resolve_env_value(br["url"]), command=br.get("command"),
        args=br.get("args", []), env=br.get("env"), cwd=br.get("cwd"),
        transport=br.get("transport", "http" if br.get("url") else "stdio"),
        path=br.get("path", ""), keepalive=br.get("keepalive", False),
        pass_kwargs_raw=br.get("pass_kwargs_raw", False),
        default_deny=raw.get("default_deny", "Access denied."),
        headers=br.get("headers"),
    ), rules


def load_all_policies(policy_dir: str) -> List[Tuple[BackendConfig, List[Dict]]]:
    if os.path.isfile(policy_dir):
        return load_legacy_policy(policy_dir)
    backends = []
    for f in sorted(glob.glob(os.path.join(policy_dir, "*.yaml"))):
        try:
            backends.append(load_backend_policy(f))
        except Exception as e:
            log.error("Failed to load %s: %s", f, e)
    return backends


def load_legacy_policy(path: str) -> List[Tuple[BackendConfig, List[Dict]]]:
    with open(path) as f:
        raw = yaml.load(f, Loader=PolicyLoader)
    backends = []
    for name, conf in raw.get("backends", {}).items():
        backends.append((BackendConfig(name=name, url=conf.get("url"), command=conf.get("command"),
            args=conf.get("args", []), path=f"/mcp/{name}"), raw.get("rules", [])))
    return backends


def load_compounds(compounds_path: str, available_backends: Dict[str, BackendConfig]) -> List[CompoundConfig]:
    """Load compound definitions from YAML file.

    Args:
        compounds_path: Path to compounds.yaml
        available_backends: Dict of backend_name -> BackendConfig for validation

    Returns:
        List of CompoundConfig objects
    """
    if not os.path.exists(compounds_path):
        log.info("No compounds config at %s — compounds disabled", compounds_path)
        return []

    try:
        with open(compounds_path) as f:
            raw = yaml.load(f, Loader=PolicyLoader)
    except Exception as e:
        log.warning("Failed to load compounds config %s: %s", compounds_path, e)
        return []

    if not raw or "compounds" not in raw:
        return []

    compounds = []
    for name, conf in raw.get("compounds", {}).items():
        backend_names = conf.get("backends", [])

        # Validate that all referenced backends exist
        invalid_backends = [b for b in backend_names if b not in available_backends]
        if invalid_backends:
            log.warning("Compound '%s' references unknown backends: %s (skipping)",
                       name, invalid_backends)
            continue

        path = conf.get("path", f"/mcp/{name}")
        description = conf.get("description", f"Compound endpoint: {name}")
        bootstrap = conf.get("bootstrap_prompt") or {}
        bootstrap_prompt_name = bootstrap.get("name")
        bootstrap_prompt_text = bootstrap.get("text")

        # Browser-facing features (all default to off).
        schema = conf.get("schema", "full")
        if schema not in ("full", "minimal"):
            log.warning("Compound '%s': unknown schema '%s' (defaulting to 'full')", name, schema)
            schema = "full"

        compounds.append(CompoundConfig(
            name=name,
            path=path,
            backends=backend_names,
            description=description,
            bootstrap_prompt_name=bootstrap_prompt_name,
            bootstrap_prompt_text=bootstrap_prompt_text,
            cors=bool(conf.get("cors", False)),
            schema=schema,
            allow_browser=bool(conf.get("allow_browser", False)),
        ))
        log.info("Loaded compound '%s' with backends: %s (cors=%s, schema=%s, allow_browser=%s)",
                 name, backend_names, bool(conf.get("cors", False)), schema,
                 bool(conf.get("allow_browser", False)))

    return compounds


# ---------------------------------------------------------------------------
# Template resolution
# ---------------------------------------------------------------------------

def resolve_template(template: str, tool_name: str, arguments: dict) -> str:
    def replacer(m):
        fp = m.group(1)
        if fp == "tool": return tool_name
        val = _get_nested(arguments, fp[5:] if fp.startswith("args.") else fp)
        return str(val) if val is not None else m.group(0)
    return re.sub(r'\$\{(.+?)\}', replacer, template)


def resolve_env_value(value: str) -> str:
    """Resolve ${env:VAR_NAME} references to environment variables.

    For example: "${env:SUDO_PASSWORD}" -> os.environ["SUDO_PASSWORD"]
    If the env var is not set, returns the original string.
    """
    def replacer(m):
        var_name = m.group(1)
        return os.environ.get(var_name, m.group(0))
    return re.sub(r'\$\{env:([^}]+)\}', replacer, value)


def resolve_injections(inject: dict) -> dict:
    """Resolve injection values, replacing ${env:VAR} references with env vars.

    For example: {"sudoPassword": "${env:SUDO_PASSWORD}"}
            -> {"sudoPassword": "actual-secret-value"}
    """
    resolved = {}
    for key, value in inject.items():
        if isinstance(value, str):
            resolved[key] = resolve_env_value(value)
        else:
            resolved[key] = value
    return resolved


def _get_nested(d: dict, key: str) -> Any:
    # Handle kwargs JSON string format
    if "kwargs" in d and isinstance(d["kwargs"], str):
        try:
            d = json.loads(d["kwargs"])
        except:
            return None
    for k in key.split("."):
        if isinstance(d, dict) and k in d: d = d[k]
        else: return None
    return d


def matches_rule(rule: dict, tool_name: str, arguments: dict) -> bool:
    spec = rule.get("match", {})
    if not re.search(spec.get("tool", ".*"), tool_name): return False
    for fp, rx in spec.items():
        if fp == "tool": continue
        val = _get_nested(arguments, fp)
        if val is None or not re.search(rx, str(val)): return False
    return True


def _is_http(bc) -> bool:
    return (bc.transport == "http" or bc.url is not None) if isinstance(bc, BackendConfig) else "url" in bc

def _is_stdio(bc) -> bool:
    return (bc.transport == "stdio" and bc.command is not None) if isinstance(bc, BackendConfig) else "url" not in bc


def _build_stdio_params(bc) -> StdioServerParameters:
    cmd, args, env, cwd, ka = (bc.command, bc.args, bc.env, bc.cwd, bc.keepalive) if isinstance(bc, BackendConfig) else (bc["command"], bc.get("args", []), bc.get("env"), bc.get("cwd"), bc.get("keepalive", False))
    if ka:
        w = "import subprocess,sys,os,signal,threading\nsignal.signal(signal.SIGPIPE,signal.SIG_DFL)\ncmd=" + repr([cmd] + args) + "\nproc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)\ndef copy_stdin():\n try:\n  while True:\n   data=os.read(0,4096)\n   if not data:break\n   proc.stdin.write(data)\n   proc.stdin.flush()\n except:pass\ndef copy_stdout():\n try:\n  while True:\n   data=proc.stdout.read(1)\n   if not data:break\n   os.write(1,data)\n except:pass\nth1=threading.Thread(target=copy_stdin,daemon=True)\nth2=threading.Thread(target=copy_stdout,daemon=True)\nth1.start();th2.start()\nproc.wait()\n"
        return StdioServerParameters(command="python3", args=["-c", w], env=env, cwd=cwd)
    return StdioServerParameters(command=cmd, args=args, env=env, cwd=cwd)


async def discover_from_backend(bc) -> Tuple[List, Optional[str]]:
    """Discover tools from a backend. Returns (tools, error_string)."""
    last_error = None
    for attempt in range(1, MAX_DISCOVERY_RETRIES + 1):
        try:
            if _is_http(bc):
                headers = bc.headers if isinstance(bc, BackendConfig) else bc.get("headers")
                async with streamablehttp_client(bc.url, headers=headers) as (r, w, _):
                    async with ClientSession(r, w) as s:
                        await s.initialize()
                        tools = (await s.list_tools()).tools
                        log.info("Discovered %d tools from %s (attempt %d/%d)", len(tools), bc.name, attempt, MAX_DISCOVERY_RETRIES)
                        return tools, None
            elif _is_stdio(bc):
                async with stdio_client(_build_stdio_params(bc)) as (r, w):
                    async with ClientSession(r, w) as s:
                        await s.initialize()
                        tools = (await s.list_tools()).tools
                        log.info("Discovered %d tools from %s (attempt %d/%d)", len(tools), bc.name, attempt, MAX_DISCOVERY_RETRIES)
                        return tools, None
            else:
                return [], f"Backend '{bc.name}': no valid transport"
        except Exception as e:
            last_error = e
            if attempt < MAX_DISCOVERY_RETRIES:
                log.warning("Failed to discover tools from %s (attempt %d/%d): %s. Retrying in %.1fs...",
                           bc.name, attempt, MAX_DISCOVERY_RETRIES, e, DISCOVERY_RETRY_DELAY)
                await asyncio.sleep(DISCOVERY_RETRY_DELAY)
            else:
                log.warning("Failed to discover tools from %s after %d attempts: %s",
                           bc.name, MAX_DISCOVERY_RETRIES, e)

    err_msg = str(last_error) if last_error else "unknown error"
    log.error("Could not discover tools from %s after %d retries: %s", bc.name, MAX_DISCOVERY_RETRIES, err_msg)
    return [], f"Backend '{bc.name}' unavailable: {err_msg}"


async def forward(bc, tool_name, arguments):
    try:
        if _is_http(bc):
            headers = bc.headers if isinstance(bc, BackendConfig) else bc.get("headers")
            async with streamablehttp_client(bc.url, headers=headers) as (r, w, _):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    res = await s.call_tool(tool_name, arguments)
                    return {"content": [c.text if hasattr(c, "text") else str(c) for c in res.content], "isError": res.isError}
        elif _is_stdio(bc):
            pkw = bc.pass_kwargs_raw if isinstance(bc, BackendConfig) else bc.get("pass_kwargs_raw", False)
            ba = arguments if pkw else {k: v for k, v in arguments.items() if k != "kwargs"}
            async with stdio_client(_build_stdio_params(bc)) as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    res = await s.call_tool(tool_name, ba)
                    return {"content": [c.text if hasattr(c, "text") else str(c) for c in res.content], "isError": res.isError}
        return {"error": f"Backend '{bc.name}': no valid transport"}
    except Exception as e:
        msg = _extract_mcp_error_message(e)
        log.error("Backend %s error: %s", bc.name, msg, exc_info=True)
        # Prefer the concrete tool/backend message over ExceptionGroup/TaskGroup wrappers
        # so agents see e.g. "Terminal 'bash' is busy..." instead of junk.
        return {"content": [msg], "isError": True}


def _extract_mcp_error_message(exc: BaseException) -> str:
    """Unwrap McpError / ExceptionGroup to a readable agent-facing message."""
    if isinstance(exc, McpError):
        err = getattr(exc, "error", None)
        if err is not None and getattr(err, "message", None):
            return str(err.message)
        return str(exc)

    # Python 3.11+ ExceptionGroup (and anyio TaskGroup failures)
    exceptions = getattr(exc, "exceptions", None)
    if exceptions:
        parts = [_extract_mcp_error_message(sub) for sub in exceptions]
        # Dedupe while preserving order
        seen = set()
        uniq = []
        for p in parts:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        if len(uniq) == 1:
            return uniq[0]
        if uniq:
            return "; ".join(uniq)

    cause = getattr(exc, "__cause__", None) or getattr(exc, "__context__", None)
    if cause is not None and cause is not exc:
        inner = _extract_mcp_error_message(cause)
        if inner and inner != str(exc):
            return inner

    text = str(exc).strip()
    if text:
        return text
    return f"{type(exc).__name__} (no message)"


def create_allowed_hosts(http_port: int) -> List[str]:
    hosts = set()
    hostname = socket.gethostname()
    for p in [http_port, 8000, 8001, 8002, 8003]:
        hosts.update([f"localhost:{p}", f"127.0.0.1:{p}", f"0.0.0.0:{p}",
                      f"mcp-gateway:{p}", f"picoclaw-agent:{p}", f"{hostname}:{p}"])
    env_hosts = os.environ.get("MCP_ALLOWED_HOSTS", "")
    if env_hosts and env_hosts != "*":
        for h in env_hosts.split(","):
            if h.strip(): hosts.add(h.strip())
    return sorted(hosts)


def make_policy_handler(bc, rules, tool_name, status: BackendStatus):
    """Create a handler function for a tool with policy enforcement.

    The handler checks backend health before forwarding.
    If the backend is down, it returns a clear error message.
    Client info (clientHost, clientIp) is injected from the request context
    so policy rules can match on the calling client's identity.

    Supports actions: allow, deny, inject_argument, confirm.
    """
    async def handler(**kw):
        # Check if backend is healthy before attempting to forward
        if not status.healthy:
            err = status.error or "Backend unavailable (0 tools discovered)"
            log.warning("Tool call %s.%s FAILED (backend unhealthy): %s", bc.name, tool_name, err)
            return f"Error: Backend '{bc.name}' is unavailable: {err}. The upstream MCP server may be down. Please check /health for details."

        # Build a separate merged dict for policy matching only.
        # Client metadata (clientHost, clientIp) comes from the request context
        # and must NOT be injected into the real arguments forwarded to the backend.
        info = _client_info.get()
        policy_kw = dict(kw)  # copy — keeps kw clean for forwarding
        if info is not None:
            policy_kw.setdefault("clientHost", info.host)
            policy_kw.setdefault("clientIp", info.ip)

        tn = tool_name
        injections = {}
        rule_matched = False
        for rule in rules:
            if matches_rule(rule, tn, policy_kw):
                action = rule.get("action", "deny")

                if action == "deny":
                    reason = resolve_template(rule.get("reason", bc.default_deny), tn, policy_kw)
                    log.warning("Tool call %s.%s DENIED: %s (args=%s)",
                                bc.name, tn, reason, _sanitize_args(policy_kw))
                    return f"ACCESS DENIED: {reason}"

                elif action == "inject_argument":
                    injections.update(resolve_injections(rule.get("inject", {})))
                    rule_matched = True
                    break

                elif action == "confirm":
                    # --- Confirm action: ask operator for approval ---
                    if _telegram_backend is None:
                        return "ACCESS DENIED: confirm action requires a notification backend (none configured)"

                    request_id = str(uuid.uuid4())
                    pending = PendingRequest(request_id=request_id)
                    _pending_requests[request_id] = pending

                    # Resolve templates for the messages
                    reason = resolve_template(rule.get("reason", "Operator declined"), tn, policy_kw)
                    pending_template = resolve_template(
                        rule.get("confirm_pending", "⏳ Approval requested for ${tool}."),
                        tn, policy_kw,
                    )
                    denied_template = resolve_template(
                        rule.get("confirm_denied", "ACCESS DENIED: ${reason}"),
                        tn, {**policy_kw, "reason": reason},
                    )
                    timeout_template = resolve_template(
                        rule.get("confirm_timeout", "ACCESS DENIED: Approval request timed out."),
                        tn, policy_kw,
                    )
                    approved_template = rule.get("confirm_approved",
                                                  "✅ Operator approved. Result:\n\n${result}")

                    # Get timeout from rule or global config
                    timeout = rule.get("timeout")
                    if timeout is None and _notification_config is not None:
                        timeout = _notification_config.timeout
                    if timeout is None:
                        timeout = 300

                    # Send approval request via Telegram
                    sent = await _telegram_backend.send_approval_request(
                        request_id=request_id,
                        tool_name=tn,
                        arguments=policy_kw,
                        client_info=info,
                        reason=reason,
                        backend_name=bc.name,
                    )
                    if not sent:
                        _pending_requests.pop(request_id, None)
                        return "ACCESS DENIED: Failed to send approval request to operator"

                    # Wait for operator response with timeout
                    try:
                        await asyncio.wait_for(pending.event.wait(), timeout=timeout)
                    except asyncio.TimeoutError:
                        # Edit the Telegram message to show timed out status
                        await _telegram_backend.edit_request_timeout(request_id)
                        _pending_requests.pop(request_id, None)
                        return timeout_template

                    _pending_requests.pop(request_id, None)

                    if not pending.approved:
                        return denied_template

                    # Operator approved — forward to real backend
                    if injections:
                        kw = {**kw, **injections}

                    result = await forward(bc, tn, kw)
                    if "error" in result:
                        return f"Error: {result['error']}"

                    result_text = result.get("content", [""])[0]
                    # Resolve approved template with ${result}
                    return resolve_template(
                        approved_template, tn,
                        {**policy_kw, "result": result_text},
                    )

                else:
                    # Unknown action — treat as allow
                    rule_matched = True
                    break

        else:
            reason = resolve_template(bc.default_deny, tn, policy_kw)
            return f"ACCESS DENIED: {reason}"

        # Apply argument injections (e.g., sudoPassword from env var)
        if injections:
            kw = {**kw, **injections}

        result = await forward(bc, tn, kw)
        if "error" in result:
            log.error("Tool call %s.%s FAILED: %s (args=%s)",
                      bc.name, tn, result["error"], _sanitize_args(policy_kw))
            return f"Error: {result['error']}"
        out = result.get("content", [""])[0]
        log.info("Tool call %s.%s OK (args=%s) -> %s",
                 bc.name, tn, _sanitize_args(policy_kw), _preview(out))
        return out

    return handler


async def register_backend_tools(server: MountedServer, bc: BackendConfig,
                                 rules: List[Dict], status: BackendStatus) -> int:
    """Discover tools from a backend and register them with policy enforcement.

    Updates the BackendStatus with discovery results.
    Returns the number of tools registered.
    """
    tools, error = await discover_from_backend(bc)
    if error:
        status.healthy = False
        status.tools_count = 0
        status.error = error
        log.warning("No tools registered for %s: %s", bc.name, error)
        return 0

    count = 0
    for t in tools:
        tool_name = t.name
        tool_desc = t.description
        tool_schema = getattr(t, "inputSchema", None) or getattr(t, "input_schema", None)
        handler = make_policy_handler(bc, rules, tool_name, status)
        server.tool(name=tool_name, description=tool_desc, inputSchema=tool_schema)(handler)
        log.info("Registered %s.%s", bc.name, tool_name)
        count += 1

    status.healthy = True
    status.tools_count = count
    status.error = None

    if count == 0:
        log.warning("Backend %s returned no tools (empty list)", bc.name)

    return count


async def discovery_watchdog(backend_statuses: List[BackendStatus]):
    """Background task: periodically re-discover tools from unhealthy backends.

    Runs every WATCHDOG_INTERVAL seconds. For backends that were never healthy
    (0 tools from startup), attempts to discover and register tools.
    For previously healthy backends, tools are already registered — only
    the health status is updated so call forwarding resumes.
    """
    while True:
        await asyncio.sleep(WATCHDOG_INTERVAL)
        for status in backend_statuses:
            if status.healthy:
                continue
            if not status.config or not status.server:
                continue

            log.info("Watchdog: re-discovering tools from %s...", status.name)
            tools, error = await discover_from_backend(status.config)
            if error:
                log.warning("Watchdog: %s still unavailable: %s", status.name, error)
                continue

            # If backend was previously healthy, tools are already registered.
            # Just flip the healthy flag and update count.
            if status.tools_count > 0:
                status.healthy = True
                status.error = None
                log.info("Watchdog: recovered %s — %d tools previously registered, health restored",
                         status.name, status.tools_count)
                continue

            # Backend was never healthy — register tools fresh
            rules = status.rules
            count = 0
            for t in tools:
                tool_name = t.name
                tool_schema = getattr(t, "inputSchema", None) or getattr(t, "input_schema", None)
                handler = make_policy_handler(status.config, rules, tool_name, status)
                status.server.tool(name=tool_name, description=t.description, inputSchema=tool_schema)(handler)
                count += 1

            status.healthy = True
            status.tools_count = count
            status.error = None
            log.info("Watchdog: recovered %s — registered %d tools", status.name, count)


def build_health_handler(backend_statuses: List[BackendStatus]):
    """Build the /health endpoint handler.

    Returns 200 with status "ok" if all backends are healthy.
    Returns 503 with status "degraded" if any backend has 0 tools.
    """
    async def health_endpoint(request):
        all_healthy = all(s.healthy for s in backend_statuses)
        backends_info = []
        for s in backend_statuses:
            entry = {
                "name": s.name,
                "healthy": s.healthy,
                "tools": s.tools_count,
            }
            if s.error:
                entry["error"] = s.error
            backends_info.append(entry)

        if all_healthy:
            return JSONResponse(
                {"status": "ok", "backends": backends_info},
                status_code=200,
            )
        else:
            return JSONResponse(
                {"status": "degraded", "backends": backends_info},
                status_code=503,
            )

    return health_endpoint


async def create_compound_server(compound: CompoundConfig,
                                 backend_status_map: Dict[str, BackendStatus],
                                 http_port: int,
                                 allowed_hosts: List[str]) -> Tuple[Any, CompoundStatus]:
    """Create a compound MCP server that aggregates tools from multiple backends.

    Tools are prefixed with the backend name to avoid collisions.
    Policy enforcement is inherited from the source backend.

    For browser-facing compounds (allow_browser=True), uses MountedServer with
    stateless=True (no session IDs) and DNS rebinding protection disabled,
    matching vscode-mcp's browser behavior so browser-based MCP clients can connect.

    Args:
        compound: Compound configuration
        backend_status_map: Dict of backend_name -> BackendStatus for lookup
        http_port: HTTP port for the server
        allowed_hosts: Allowed hosts for DNS rebinding protection

    Returns:
        Tuple of (MountedServer, CompoundStatus)
    """
    prompts = {}
    if compound.bootstrap_prompt_name and compound.bootstrap_prompt_text:
        prompts[compound.bootstrap_prompt_name] = compound.bootstrap_prompt_text

    # Browser-facing features:
    # - schema 'minimal' strips outputSchema (like vscode-mcp structured_output=False)
    # - allow_browser enables stateless_http=True and disables DNS rebinding
    #   protection so arbitrary browser origins can connect.
    strip_output_schema = compound.schema == "minimal"

    if compound.allow_browser:
        # Browser mode: use stateless HTTP (no session IDs) + disable DNS
        # rebinding protection, matching vscode-mcp's browser behavior.
        server = MountedServer(
            name=compound.name,
            port=http_port,
            allowed_hosts=allowed_hosts,
            prompts=prompts if prompts else None,
            strip_output_schema=strip_output_schema,
            enable_dns_rebinding_protection=False,
            stateless=True,
        )
        compound_status = CompoundStatus(
            name=compound.name,
            path=compound.path,
        )
        log.info("Compound '%s': using stateless HTTP mode for browser clients (cors=%s, schema=%s)",
                 compound.name, compound.cors, compound.schema)
    else:
        # Default: MountedServer with stateful sessions
        server = MountedServer(
            name=compound.name,
            port=http_port,
            allowed_hosts=allowed_hosts,
            prompts=prompts if prompts else None,
            strip_output_schema=strip_output_schema,
            enable_dns_rebinding_protection=not compound.allow_browser,
        )
        compound_status = CompoundStatus(
            name=compound.name,
            path=compound.path,
        )
        if compound.cors or compound.allow_browser or strip_output_schema:
            log.info("Compound '%s': browser features enabled (cors=%s, schema=%s, allow_browser=%s)",
                     compound.name, compound.cors, compound.schema, compound.allow_browser)

    total_tools = 0
    registered_tools = set()

    for backend_name in compound.backends:
        if backend_name not in backend_status_map:
            log.warning("Compound '%s': backend '%s' not found (skipping)",
                       compound.name, backend_name)
            continue

        backend_status = backend_status_map[backend_name]

        # Check if backend is healthy
        if not backend_status.healthy:
            log.warning("Compound '%s': backend '%s' is unhealthy (skipping tools)",
                       compound.name, backend_name)
            compound_status.backends_status[backend_name] = backend_status
            continue

        # Get the backend config and rules
        bc = backend_status.config
        rules = backend_status.rules

        # Discover tools from this backend
        tools, error = await discover_from_backend(bc)
        if error:
            log.warning("Compound '%s': failed to discover tools from '%s': %s",
                       compound.name, backend_name, error)
            compound_status.backends_status[backend_name] = backend_status
            continue

        # Register tools with prefix
        prefix = f"{backend_name}_"
        for t in tools:
            prefixed_name = f"{prefix}{t.name}"

            # Check for collisions
            if prefixed_name in registered_tools:
                log.warning("Compound '%s': tool collision detected: %s (from %s)",
                           compound.name, prefixed_name, backend_name)
                continue

            # Create handler that strips prefix and forwards to backend
            async def make_handler(original_name: str, backend_cfg, backend_rules, backend_st):
                async def handler(**kw):
                    # Check backend health
                    if not backend_st.healthy:
                        log.warning("Tool call %s.%s FAILED (backend unhealthy)", backend_cfg.name, original_name)
                        return f"Error: Backend '{backend_cfg.name}' is unavailable"

                    # Apply policy enforcement
                    info = _client_info.get()
                    policy_kw = dict(kw)
                    if info is not None:
                        policy_kw.setdefault("clientHost", info.host)
                        policy_kw.setdefault("clientIp", info.ip)

                    # Check policy rules
                    injections = {}
                    for rule in backend_rules:
                        if matches_rule(rule, original_name, policy_kw):
                            action = rule.get("action", "deny")

                            if action == "deny":
                                reason = resolve_template(
                                    rule.get("reason", backend_cfg.default_deny),
                                    original_name, policy_kw
                                )
                                log.warning("Tool call %s.%s DENIED: %s (args=%s)",
                                            backend_cfg.name, original_name, reason, _sanitize_args(policy_kw))
                                return f"ACCESS DENIED: {reason}"

                            elif action == "inject_argument":
                                injections.update(resolve_injections(rule.get("inject", {})))
                                break

                            elif action == "confirm":
                                # Confirm action - delegate to backend handler
                                compound_handler = make_policy_handler(
                                    backend_cfg, backend_rules, original_name, backend_st
                                )
                                return await compound_handler(**kw)

                            else:
                                break

                    # Apply injections
                    if injections:
                        kw = {**kw, **injections}

                    # Forward to backend
                    result = await forward(backend_cfg, original_name, kw)
                    if "error" in result:
                        log.error("Tool call %s.%s FAILED: %s (args=%s)",
                                  backend_cfg.name, original_name, result["error"], _sanitize_args(policy_kw))
                        return f"Error: {result['error']}"
                    out = result.get("content", [""])[0]
                    log.info("Tool call %s.%s OK (args=%s) -> %s",
                             backend_cfg.name, original_name, _sanitize_args(policy_kw), _preview(out))
                    return out

                return handler

            handler = await make_handler(t.name, bc, rules, backend_status)
            tool_schema = getattr(t, "inputSchema", None) or getattr(t, "input_schema", None)
            tool_output_schema = getattr(t, "outputSchema", None) or getattr(t, "output_schema", None)
            server.tool(name=prefixed_name, description=t.description,
                        inputSchema=tool_schema, outputSchema=tool_output_schema)(handler)
            registered_tools.add(prefixed_name)
            total_tools += 1

            log.info("Compound '%s': registered %s (from %s)",
                    compound.name, prefixed_name, backend_name)

    compound_status.tools_count = total_tools
    compound_status.healthy = total_tools > 0

    log.info("Created compound '%s' at %s with %d tools from %d backends",
            compound.name, compound.path, total_tools, len(compound.backends))

    return server, compound_status


async def main():
    backends = load_all_policies(POLICY_DIR)
    log.info("Loaded %d backends", len(backends))

    # Load global notification config
    global _notification_config, _telegram_backend
    _notification_config = load_notification_config(NOTIFICATION_CONFIG_PATH)
    if _notification_config and _notification_config.telegram_enabled:
        _telegram_backend = TelegramBackend(
            bot_token=_notification_config.telegram_bot_token,
            chat_id=_notification_config.telegram_chat_id,
            poll_interval=_notification_config.telegram_poll_interval,
        )
        log.info("Telegram notification backend enabled")

    http_host = os.environ.get("POLICY_PROXY_HOST", "0.0.0.0")
    http_port = int(os.environ.get("POLICY_PROXY_PORT", "8000"))
    transport = os.environ.get("POLICY_PROXY_TRANSPORT", "http")

    if transport == "stdio":
        # Fallback: single FastMCP with prefixed tools
        from mcp.server.fastmcp import FastMCP
        srv = FastMCP("mcp-gateway")
        for bc, rules in backends:
            pfx = f"{bc.name}_"
            try:
                tools, _ = await discover_from_backend(bc)
                for t in tools:
                    tn = t.name
                    dummy_status = BackendStatus(name=bc.name, healthy=False)
                    handler = make_policy_handler(bc, rules, tn, dummy_status)

                    tool_schema = getattr(t, "inputSchema", None) or getattr(t, "input_schema", None)
                    @srv.tool(name=f"{pfx}{tn}", description=t.description, inputSchema=tool_schema)
                    async def wrapped_handler(**kw):
                        return await handler(**kw)

                    log.info("Registered %s%s", pfx, tn)
            except Exception as e:
                log.warning("Could not connect to %s: %s", bc.name, e)
        await srv.run_stdio_async()
    else:
        # HTTP mode: each backend at its own path using MountedServer
        backend_statuses: List[BackendStatus] = []
        mounted_servers = []
        allowed_hosts = create_allowed_hosts(http_port)

        # Build backend config map for compound validation
        backend_config_map = {bc.name: bc for bc, _ in backends}

        for bc, rules in backends:
            path = bc.path or f"/mcp/{bc.name}"
            server = MountedServer(name=bc.name, port=http_port, allowed_hosts=allowed_hosts)

            status = BackendStatus(
                name=bc.name,
                server=server,
                config=bc,
                rules=rules,
            )

            # Discover tools from backend and register with policy enforcement
            try:
                await register_backend_tools(server, bc, rules, status)
            except Exception as e:
                status.healthy = False
                status.error = str(e)
                log.warning("Could not connect to %s: %s", bc.name, e)

            backend_statuses.append(status)
            mounted_servers.append(server)
            log.info("Mounted %s at %s (%s, %d tools)", bc.name, path,
                     "healthy" if status.healthy else "unhealthy", status.tools_count)

        # Load and create compound endpoints
        compounds_path = os.environ.get("COMPOUNDS_CONFIG", "/etc/mcp-gateways/compounds.yaml")
        compounds = load_compounds(compounds_path, backend_config_map)

        compound_statuses: List[CompoundStatus] = []
        compound_servers = []

        # Build backend status map for compound creation
        backend_status_map = {s.name: s for s in backend_statuses}

        for compound in compounds:
            try:
                compound_server, compound_status = await create_compound_server(
                    compound, backend_status_map, http_port, allowed_hosts
                )
                compound_statuses.append(compound_status)
                compound_servers.append(compound_server)
                log.info("Created compound '%s' at %s with %d tools",
                        compound.name, compound.path, compound_status.tools_count)
            except Exception as e:
                log.warning("Failed to create compound '%s': %s", compound.name, e)

        # Build routes: /health (with status tracking) + each backend + each compound
        all_routes = [
            Route("/health", endpoint=build_health_handler(backend_statuses)),
        ]

        for path, server in zip(
            [bc.path or f"/mcp/{bc.name}" for bc, _ in backends],
            mounted_servers
        ):
            all_routes.append(Mount(path, app=server.get_app()))

        # Add compound routes
        for compound, server in zip(compounds, compound_servers):
            compound_app = server.get_app()
            # Apply permissive CORS to browser-facing compound endpoints only.
            if compound.cors:
                compound_app.add_middleware(CORSSupportMiddleware)
                log.info("Compound '%s': CORS middleware enabled", compound.name)
            all_routes.append(Mount(compound.path, app=compound_app))
            log.info("Mounted compound '%s' at %s", compound.name, compound.path)

        starlette_app = Starlette(routes=all_routes)
        starlette_app.add_middleware(ClientInfoMiddleware)

        @contextlib.asynccontextmanager
        async def lifespan(app):
            async with contextlib.AsyncExitStack() as stack:
                # Initialize _http_manager (StreamableHTTPSessionManager) for MountedServer
                # instances only. FastMCP browser compounds (_AppWrapper) manage their own
                # transport internally and don't need _http_manager.run().
                for server in mounted_servers + compound_servers:
                    if hasattr(server, "_http_manager"):
                        await stack.enter_async_context(server._http_manager.run())
                # Start discovery watchdog for unhealthy backends
                watchdog_task = asyncio.create_task(discovery_watchdog(backend_statuses))
                # Start Telegram polling if enabled
                telegram_poll_task = None
                if _telegram_backend is not None:
                    telegram_poll_task = asyncio.create_task(_telegram_backend.poll_loop())
                    log.info("Telegram polling started")
                yield
                watchdog_task.cancel()
                try:
                    await watchdog_task
                except asyncio.CancelledError:
                    pass
                if telegram_poll_task is not None:
                    telegram_poll_task.cancel()
                    try:
                        await telegram_poll_task
                    except asyncio.CancelledError:
                        pass
                    await _telegram_backend.shutdown()

        starlette_app.router.lifespan_context = lifespan

        log.info("Starting on %s:%d with %d backends and %d compounds",
                http_host, http_port, len(backends), len(compounds))
        for s in backend_statuses:
            log.info("  %s -> %s (%s, %d tools)", s.name,
                     f"http://{http_host}:{http_port}/{s.name}",
                     "healthy" if s.healthy else "unhealthy", s.tools_count)
        for c in compounds:
            log.info("  compound '%s' -> %s (%d backends)", c.name,
                     f"http://{http_host}:{c.path}", len(c.backends))

        await uvicorn.Server(uvicorn.Config(starlette_app, host=http_host, port=http_port, log_level="warning")).serve()


if __name__ == "__main__":
    asyncio.run(main())