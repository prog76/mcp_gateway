"""OAuth bearer tokens for policy-proxy HTTP backends.

A backend can require OAuth: it answers 401 with an RFC 9728 challenge
(``WWW-Authenticate: Bearer resource_metadata="..."``). This module owns the
token side of that conversation:

* :func:`discover_resource` / :func:`discover_authorization_server` - the two
  metadata hops (RFC 9728 then RFC 8414/OIDC discovery).
* :class:`TokenManager` - one grant per backend URL, persisted on disk (0600),
  refreshed before expiry, guarded by an flock so two gateway workers cannot
  race a refresh.
* :func:`login_link` / :func:`complete_login` - the RFC 8252 loopback flow. The
  gateway never opens a browser itself: the policy layer prints the link, the
  notification channel (Telegram) delivers it, and the operator clicks it. The
  callback listener binds a configured port, so it works wherever the gateway
  can bind and the operator's browser can reach.

The backend-facing API is :meth:`TokenManager.authorization_header`, which
returns the value for the ``Authorization`` header, or ``None`` when this
backend has no grant. Nothing here starts a login implicitly - minting a grant
is an operator action, triggered by a policy rule or an admin call.

The client is assumed PUBLIC (PKCE, no secret): internal IdPs commonly disable
dynamic client registration, and a secret in a policy file buys nothing. A
confidential client later means adding ``client_secret`` to the exchange and
nothing else in this design.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

import httpx


HTTP_TIMEOUT_SECONDS = 30.0
EXPIRY_SKEW_SECONDS = 30
DEFAULT_SCOPES: Tuple[str, ...] = ("openid", "profile", "email")
DEFAULT_CALLBACK_HOST = "0.0.0.0"
DEFAULT_CALLBACK_PORT = 8899
DEFAULT_CALLBACK_PATH = "/callback"


class OAuthError(RuntimeError):
    """The OAuth lane could not produce a usable bearer token."""


class LoginPending(OAuthError):
    """A login was started and the callback has not arrived yet."""


# ---------------------------------------------------------------------------
# Configuration (per backend, from policy YAML)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BackendAuth:
    """The ``auth:`` block of a backend policy.

    Only ``client_id`` is required. ``redirect_port`` is fixed and configured,
    not ephemeral: the gateway is long-lived, and the operator's browser must
    reach the same port for every login.
    """

    client_id: str
    scopes: Tuple[str, ...] = DEFAULT_SCOPES
    callback_host: str = DEFAULT_CALLBACK_HOST
    callback_port: int = DEFAULT_CALLBACK_PORT
    callback_path: str = DEFAULT_CALLBACK_PATH
    login_timeout_seconds: int = 300

    def redirect_uri(self, bound_port: Optional[int] = None) -> str:
        """The loopback redirect the IdP will call (RFC 8252 7.3).

        ``bound_port`` overrides ``callback_port`` for an ephemeral listener
        (``callback_port=0``): the redirect must carry the port actually bound.
        """
        host = self.callback_host
        if host in ("0.0.0.0", "::"):
            # The browser cannot dial the wildcard; it dials loopback on the
            # host that runs the gateway.
            host = "localhost"
        port = self.callback_port if bound_port is None else bound_port
        return f"http://{host}:{port}{self.callback_path}"

    @classmethod
    def from_yaml(cls, raw: Optional[Dict[str, Any]]) -> Optional["BackendAuth"]:
        """Build from a backend policy ``auth:`` block (None = no OAuth)."""
        if not raw:
            return None
        client_id = str(raw.get("client_id") or "").strip()
        if not client_id:
            raise OAuthError("backend auth block present but client_id is empty")
        scopes = raw.get("scopes") or raw.get("scope")
        if isinstance(scopes, str):
            scopes = [s for s in re.split(r"[\s,+]+", scopes) if s]
        return cls(
            client_id=client_id,
            scopes=tuple(str(s) for s in (scopes or DEFAULT_SCOPES)),
            callback_host=str(raw.get("callback_host") or DEFAULT_CALLBACK_HOST),
            callback_port=int(raw.get("callback_port") or DEFAULT_CALLBACK_PORT),
            callback_path=str(raw.get("callback_path") or DEFAULT_CALLBACK_PATH),
            login_timeout_seconds=int(raw.get("login_timeout_seconds") or 300),
        )


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _www_authenticate_field(header: str, field_name: str) -> Optional[str]:
    if not header:
        return None
    match = re.search(rf'{field_name}=(?:"([^"]+)"|([^\s,]+))', header)
    if not match:
        return None
    return match.group(1) or match.group(2)


@dataclass(frozen=True)
class ProtectedResource:
    resource: str
    authorization_servers: Tuple[str, ...]
    scopes_supported: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthorizationServer:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str


def _candidate_resource_metadata_urls(www_auth_url: Optional[str], endpoint: str) -> list:
    urls = []
    if www_auth_url:
        urls.append(www_auth_url)
    parsed = urllib.parse.urlparse(endpoint)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if parsed.path and parsed.path != "/":
        urls.append(f"{origin}/.well-known/oauth-protected-resource{parsed.path}")
    urls.append(f"{origin}/.well-known/oauth-protected-resource")
    return urls


def discover_resource(
    http: httpx.Client, endpoint: str, www_auth_url: Optional[str] = None
) -> ProtectedResource:
    """Resolve RFC 9728 metadata for an MCP endpoint."""
    if www_auth_url is None:
        try:
            response = http.post(
                endpoint,
                json={
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "policy-proxy", "version": "1"},
                    },
                    "jsonrpc": "2.0",
                    "id": 1,
                },
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise OAuthError(f"could not reach {endpoint}: {exc}") from exc
        if response.status_code not in (401, 403):
            raise OAuthError(f"{endpoint} did not challenge (HTTP {response.status_code})")
        www_auth_url = _www_authenticate_field(
            response.headers.get("WWW-Authenticate", ""), "resource_metadata"
        )

    for url in _candidate_resource_metadata_urls(www_auth_url, endpoint):
        try:
            response = http.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError:
            continue
        if response.status_code != 200:
            continue
        try:
            body = response.json()
        except ValueError:
            continue
        servers = tuple(body.get("authorization_servers") or ())
        if not servers:
            continue
        return ProtectedResource(
            resource=str(body.get("resource") or endpoint),
            authorization_servers=servers,
            scopes_supported=tuple(body.get("scopes_supported") or ()),
        )
    raise OAuthError(f"no protected-resource metadata for {endpoint}")


def _candidate_issuer_metadata_urls(issuer: str) -> list:
    issuer = issuer.rstrip("/")
    parsed = urllib.parse.urlparse(issuer)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    urls = [
        f"{issuer}/.well-known/oauth-authorization-server",
        f"{issuer}/.well-known/openid-configuration",
    ]
    if path:
        urls.append(f"{origin}/.well-known/oauth-authorization-server{path}")
        urls.append(f"{origin}/.well-known/openid-configuration{path}")
    return urls


def discover_authorization_server(http: httpx.Client, issuer: str) -> AuthorizationServer:
    """Resolve RFC 8414 / OIDC metadata for an issuer."""
    for url in _candidate_issuer_metadata_urls(issuer):
        try:
            response = http.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError:
            continue
        if response.status_code != 200:
            continue
        try:
            body = response.json()
        except ValueError:
            continue
        if body.get("authorization_endpoint") and body.get("token_endpoint"):
            return AuthorizationServer(
                issuer=str(body.get("issuer") or issuer),
                authorization_endpoint=str(body["authorization_endpoint"]),
                token_endpoint=str(body["token_endpoint"]),
            )
    raise OAuthError(f"no authorization-server metadata for {issuer}")


# ---------------------------------------------------------------------------
# Stored grant
# ---------------------------------------------------------------------------


@dataclass
class StoredTokens:
    access_token: str
    token_type: str = "Bearer"
    refresh_token: Optional[str] = None
    expires_at: Optional[float] = None
    refresh_expires_at: Optional[float] = None
    scopes: Tuple[str, ...] = ()
    resource: str = ""
    issuer: str = ""
    token_endpoint: str = ""
    client_id: str = ""
    obtained_at: float = field(default_factory=time.time)

    def is_valid(self, now: Optional[float] = None) -> bool:
        if not self.access_token:
            return False
        if self.expires_at is None:
            return True
        return (now if now is not None else time.time()) < (
            self.expires_at - EXPIRY_SKEW_SECONDS
        )

    def can_refresh(self, now: Optional[float] = None) -> bool:
        if not self.refresh_token:
            return False
        if self.refresh_expires_at is None:
            return True
        return (now if now is not None else time.time()) < self.refresh_expires_at

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "StoredTokens":
        body = json.loads(raw)
        if "scopes" in body:
            body["scopes"] = tuple(body["scopes"])
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in body.items() if k in known})


def _tokens_from_response(
    response: httpx.Response,
    *,
    resource: str,
    issuer: str,
    token_endpoint: str,
    client_id: str,
    fallback: Optional[StoredTokens] = None,
) -> StoredTokens:
    if response.status_code != 200:
        raise OAuthError(
            f"token request failed ({response.status_code}): {response.text.strip()}"
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise OAuthError("token endpoint returned a non-JSON body") from exc
    access_token = body.get("access_token")
    if not access_token:
        raise OAuthError(f"token response has no access_token: {body}")
    now = time.time()
    expires_in = body.get("expires_in")
    refresh_expires_in = body.get("refresh_expires_in")
    return StoredTokens(
        access_token=str(access_token),
        token_type=str(body.get("token_type") or "Bearer"),
        refresh_token=(
            str(body["refresh_token"]) if body.get("refresh_token")
            else (fallback.refresh_token if fallback else None)
        ),
        expires_at=(float(expires_in) + now) if expires_in is not None else None,
        refresh_expires_at=(
            float(refresh_expires_in) + now if refresh_expires_in is not None else None
        ),
        scopes=tuple(str(body.get("scope") or "").split())
        or (fallback.scopes if fallback else ()),
        resource=resource,
        issuer=issuer,
        token_endpoint=token_endpoint,
        client_id=client_id,
        obtained_at=now,
    )


def generate_pkce() -> Tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode("ascii")
    )
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return verifier, challenge


# ---------------------------------------------------------------------------
# Loopback callback listener
# ---------------------------------------------------------------------------


_SUCCESS_BODY = (
    b"<!doctype html><meta charset=utf-8><title>mcp gateway</title>"
    b"<body style=\"font:16px system-ui;margin:3rem\">"
    b"<h3>Signed in.</h3><p>You can close this tab.</p>"
)


class CallbackListener:
    """Loopback HTTP listener for the authorization redirect.

    Threaded, closes every connection explicitly (``Connection: close``), and
    the FIRST callback wins: a duplicate or hand-pasted request - which often
    carries a truncated query - must never clobber the captured code.
    """

    def __init__(self, host: str, port: int, path: str):
        self._path = path
        self._params: Optional[Dict[str, str]] = None
        self._event = threading.Event()
        try:
            self._server = ThreadingHTTPServer((host, port), self._build_handler())
        except OSError as exc:
            raise OAuthError(f"cannot listen on {host}:{port}: {exc}") from exc
        self._server.daemon_threads = True
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def _build_handler(self) -> type:
        listener = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            # Bound every socket wait: an idle keep-alive connection must not
            # hold a thread until the process exits.
            timeout = 5

            def do_GET(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != listener._path:
                    self._respond(404, b"not found")
                    return
                if listener._params is None:
                    listener._params = dict(urllib.parse.parse_qsl(parsed.query))
                    listener._event.set()
                self._respond(200, _SUCCESS_BODY)

            def _respond(self, status: int, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                # Without this the HTTP/1.1 handler loops back into readline
                # and the connection never closes - browsers hold sockets, and
                # a follow-up client then hangs even though it was answered.
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def log_message(self, *args: Any) -> None:
                """Silence the default per-request stderr log."""

        return _Handler

    def wait(self, timeout_seconds: float) -> Dict[str, str]:
        if not self._event.wait(timeout_seconds):
            raise LoginPending(
                f"no callback within {timeout_seconds:.0f}s - the login link "
                "was not completed"
            )
        return dict(self._params or {})

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Token manager (the backend-facing surface)
# ---------------------------------------------------------------------------


class TokenManager:
    """Grants for HTTP backends, one per backend URL, persisted and refreshed."""

    def __init__(self, cache_dir: Optional[Path] = None):
        override = os.environ.get("GATEWAY_OAUTH_CACHE_DIR")
        self.dir = Path(
            cache_dir or override or Path.home() / ".cache" / "mcp-gateway" / "oauth"
        )
        self._listeners: Dict[str, CallbackListener] = {}
        self._listeners_lock = threading.Lock()

    def path_for(self, endpoint: str) -> Path:
        key = hashlib.sha256(endpoint.rstrip("/").encode("utf-8")).hexdigest()[:16]
        return self.dir / f"{key}.json"

    def load(self, endpoint: str) -> Optional[StoredTokens]:
        path = self.path_for(endpoint)
        if not path.exists():
            return None
        try:
            return StoredTokens.from_json(path.read_text(encoding="utf-8"))
        except (ValueError, TypeError):
            return None

    def save(self, endpoint: str, tokens: StoredTokens) -> Path:
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        path = self.path_for(endpoint)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(tokens.to_json(), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)
        return path

    def delete(self, endpoint: str) -> bool:
        path = self.path_for(endpoint)
        if path.exists():
            path.unlink()
            return True
        return False

    @contextlib.contextmanager
    def lock(self, endpoint: str):
        self.dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.path_for(endpoint).with_suffix(".lock")
        handle = open(lock_path, "w")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    # -- use ---------------------------------------------------------------

    def authorization_header(self, endpoint: str) -> Optional[str]:
        """Value for the ``Authorization`` header, or None if no grant.

        Never starts a login. A backend without a grant sends no header; the
        upstream answers 401, and the policy layer decides to offer the login
        link (that decision needs Telegram, which this module knows nothing
        about).
        """
        tokens = self.load(endpoint)
        if tokens is None:
            return None
        if tokens.is_valid():
            return f"Bearer {tokens.access_token}"
        if not tokens.can_refresh():
            return None
        try:
            with self.lock(endpoint):
                tokens = self.load(endpoint) or tokens
                if tokens.is_valid():
                    return f"Bearer {tokens.access_token}"
                with httpx.Client(
                    timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True
                ) as http:
                    refreshed = self._refresh(http, tokens)
                self.save(endpoint, refreshed)
                return f"Bearer {refreshed.access_token}"
        except (OAuthError, httpx.HTTPError) as exc:
            # Log-and-degrade: the request goes out unauthenticated and the
            # upstream 401 keeps the failure visible at the call site.
            import logging

            logging.getLogger(__name__).warning(
                "oauth: could not refresh the grant for %s: %s", endpoint, exc
            )
            return None

    def _refresh(self, http: httpx.Client, tokens: StoredTokens) -> StoredTokens:
        if not tokens.refresh_token or not tokens.token_endpoint:
            raise OAuthError("stored grant cannot be refreshed")
        response = http.post(
            tokens.token_endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens.refresh_token,
                "client_id": tokens.client_id,
                "resource": tokens.resource,
            },
            headers={"Accept": "application/json"},
        )
        return _tokens_from_response(
            response,
            resource=tokens.resource,
            issuer=tokens.issuer,
            token_endpoint=tokens.token_endpoint,
            client_id=tokens.client_id,
            fallback=tokens,
        )

    # -- login -------------------------------------------------------------

    def login_link(self, endpoint: str, auth: BackendAuth) -> str:
        """Start a login: bind the callback port, return the authorization URL.

        The link is delivered to the operator (Telegram, console, whatever the
        policy layer chooses). Calling this twice for the same endpoint while a
        login is pending returns the SAME link - the existing listener keeps
        waiting, no port is double-bound.
        """
        with self._listeners_lock:
            existing = self._listeners.get(endpoint)
            if existing is not None:
                return existing.authorization_url

        with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True) as http:
            resource = discover_resource(http, endpoint)
            server = discover_authorization_server(
                http, resource.authorization_servers[0]
            )

        scopes = auth.scopes or resource.scopes_supported or DEFAULT_SCOPES
        listener = CallbackListener(
            auth.callback_host, auth.callback_port, auth.callback_path
        )
        verifier, challenge = generate_pkce()
        redirect_uri = auth.redirect_uri(bound_port=listener.port)
        state = secrets.token_urlsafe(24)
        params = {
            "response_type": "code",
            "client_id": auth.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource.resource,
        }
        url = (
            f"{server.authorization_endpoint}?{urllib.parse.urlencode(params)}"
        )
        listener.authorization_url = url
        listener.wait_seconds = auth.login_timeout_seconds
        listener._redirect_uri = redirect_uri
        listener._pkce_verifier = verifier
        listener._expected_state = state
        listener._resource = resource.resource
        listener._issuer = server.issuer
        listener._token_endpoint = server.token_endpoint
        listener._client_id = auth.client_id
        listener._endpoint = endpoint

        with self._listeners_lock:
            # Another thread may have raced us to the same endpoint.
            previous = self._listeners.get(endpoint)
            if previous is not None:
                listener.close()
                return previous.authorization_url
            self._listeners[endpoint] = listener
        return url

    def complete_login(
        self, endpoint: str, timeout_seconds: int = 300
    ) -> StoredTokens:
        """Wait for the callback of a pending login and persist the grant.

        Raises :class:`LoginPending` if the operator has not clicked in time; a
        later call can wait again (the listener keeps running).
        """
        with self._listeners_lock:
            listener = self._listeners.get(endpoint)
        if listener is None:
            raise OAuthError(f"no pending login for {endpoint}")

        try:
            params = listener.wait(timeout_seconds)
        except LoginPending:
            # The listener stays; a later complete_login can still catch up.
            raise

        error = params.get("error")
        if error:
            self._drop_listener(endpoint)
            raise OAuthError(
                f"authorization failed: {error} {params.get('error_description') or ''}".strip()
            )
        returned_state = params.get("state")
        if not returned_state or not secrets.compare_digest(
            returned_state, listener._expected_state
        ):
            # Not fatal to the pending login: the real browser callback may
            # still arrive. But do not accept this code.
            raise OAuthError("state mismatch on callback - code refused")
        code = params.get("code")
        if not code:
            raise OAuthError("callback carried no authorization code")

        # Single-use code: serialize the exchange with the flock so two
        # processes completing the same login cannot double-redeem it.
        with self.lock(endpoint):
            if self.load(endpoint) is not None:
                # Another process already completed this login.
                self._drop_listener(endpoint)
                return self.load(endpoint)
            with httpx.Client(
                timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True
            ) as http:
                tokens = self._exchange(
                    http,
                    code=code,
                    code_verifier=listener._pkce_verifier,
                    token_endpoint=listener._token_endpoint,
                    client_id=listener._client_id,
                    resource=listener._resource,
                    issuer=listener._issuer,
                    endpoint=endpoint,
                )
            self.save(endpoint, tokens)
        self._drop_listener(endpoint)
        return tokens

    def _exchange(
        self,
        http: httpx.Client,
        *,
        code: str,
        code_verifier: str,
        token_endpoint: str,
        client_id: str,
        resource: str,
        issuer: str,
        endpoint: str,
    ) -> StoredTokens:
        # The redirect_uri must match the authorization request exactly.
        listener = self._listeners.get(endpoint)
        redirect_uri = listener._redirect_uri if listener is not None else None
        if not redirect_uri:
            raise OAuthError("listener gone before the code could be exchanged")
        response = http.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": code_verifier,
                "resource": resource,
            },
            headers={"Accept": "application/json"},
        )
        return _tokens_from_response(
            response,
            resource=resource,
            issuer=issuer,
            token_endpoint=token_endpoint,
            client_id=client_id,
        )

    def _drop_listener(self, endpoint: str) -> None:
        with self._listeners_lock:
            listener = self._listeners.pop(endpoint, None)
        if listener is not None:
            with contextlib.suppress(Exception):
                listener.close()

    def status(self, endpoint: str) -> Dict[str, Any]:
        tokens = self.load(endpoint)
        now = time.time()
        if tokens is None:
            return {"endpoint": endpoint, "configured": False, "path": str(self.path_for(endpoint))}
        return {
            "endpoint": endpoint,
            "configured": True,
            "path": str(self.path_for(endpoint)),
            "resource": tokens.resource,
            "issuer": tokens.issuer,
            "client_id": tokens.client_id,
            "valid": tokens.is_valid(now),
            "expires_in": None if tokens.expires_at is None else round(tokens.expires_at - now),
            "refreshable": tokens.can_refresh(now),
            "refresh_expires_in": (
                None
                if tokens.refresh_expires_at is None
                else round(tokens.refresh_expires_at - now)
            ),
        }
