"""Tests for the gateway OAuth lane (gateway/oauth.py) and its wiring.

A fake IdP over real HTTP - the same approach that caught the mcp2cli bugs -
plus direct tests of the policy wiring (auth parsing, bearer attachment,
challenge detection, the once-only login offer).
"""

import base64
import hashlib
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from gateway import oauth
from gateway.oauth import (
    BackendAuth,
    CallbackListener,
    LoginPending,
    OAuthError,
    StoredTokens,
    TokenManager,
    discover_authorization_server,
    discover_resource,
    generate_pkce,
)


RESOURCE_PATH = "/servers/abc123/mcp"


class FakeIdP:
    """Minimal OAuth-protected resource + authorization server on one port."""

    def __init__(self):
        self.requests = []  # (method, path, headers{lower}, form)
        self.access_token = "access-1"
        self.refresh_token = "refresh-1"
        self.expires_in = 300
        self.refresh_expires_in = 1800
        self.seen_verifier = None
        self.seen_challenge = None
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.resource = self.origin + RESOURCE_PATH
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def prm_url(self):
        return self.origin + "/.well-known/oauth-protected-resource" + RESOURCE_PATH

    @property
    def token_url(self):
        return self.origin + "/token"

    @property
    def authorize_url(self):
        return self.origin + "/authorize"

    def _handler(idp):
        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = 5

            @property
            def _headers(self):
                return {k.lower(): v for k, v in self.headers.items()}

            @property
            def _authorized(self):
                return self.headers.get("Authorization") == f"Bearer {idp.access_token}"

            def _send(self, status, body, headers=None):
                payload = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
                self.close_connection = True

            def do_GET(self):  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                idp.requests.append(("GET", self.path, self._headers, {}))
                if parsed.path == RESOURCE_PATH:
                    self._challenge()
                    return
                if parsed.path == "/.well-known/oauth-protected-resource" + RESOURCE_PATH:
                    self._send(200, {
                        "resource": idp.resource,
                        "authorization_servers": [idp.origin],
                        "scopes_supported": ["openid", "profile", "email"],
                    })
                    return
                if parsed.path == "/.well-known/oauth-authorization-server":
                    self._send(200, {
                        "issuer": idp.origin,
                        "authorization_endpoint": idp.authorize_url,
                        "token_endpoint": idp.token_url,
                    })
                    return
                self._send(404, {"error": "not_found"})

            def do_POST(self):  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode()))
                idp.requests.append(("POST", self.path, self._headers, form))
                if parsed.path == RESOURCE_PATH:
                    self._challenge()
                    return
                if parsed.path == "/token":
                    self._token(form)
                    return
                self._send(404, {"error": "not_found"})

            def _challenge(self):
                if self._authorized:
                    self._send(200, {"jsonrpc": "2.0", "id": 1, "result": {}})
                    return
                self._send(
                    401,
                    {"detail": "This server requires OAuth authentication"},
                    {"WWW-Authenticate": 'Bearer resource_metadata="' + idp.prm_url + '"'},
                )

            def _token(self, form):
                if form.get("grant_type") == "authorization_code":
                    if form.get("code") != "GOODCODE":
                        self._send(400, {"error": "invalid_grant"})
                        return
                    idp.seen_verifier = form.get("code_verifier")
                    digest = hashlib.sha256((idp.seen_verifier or "").encode("ascii")).digest()
                    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
                    if computed != idp.seen_challenge:
                        self._send(400, {"error": "invalid_grant", "error_description": "PKCE"})
                        return
                elif form.get("grant_type") == "refresh_token":
                    if form.get("refresh_token") != idp.refresh_token:
                        self._send(400, {"error": "invalid_grant"})
                        return
                    idp.access_token = "access-2"
                else:
                    self._send(400, {"error": "unsupported_grant_type"})
                    return
                self._send(200, {
                    "access_token": idp.access_token,
                    "token_type": "Bearer",
                    "expires_in": idp.expires_in,
                    "refresh_token": idp.refresh_token,
                    "refresh_expires_in": idp.refresh_expires_in,
                    "scope": "openid profile email",
                })

            def log_message(self, *args):
                pass

        return _Handler

    def close(self):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def idp():
    server = FakeIdP()
    yield server
    server.close()


@pytest.fixture
def tokens(tmp_path):
    return TokenManager(tmp_path / "oauth")


def _play_browser(prompt_url, idp, code="GOODCODE", port=None):
    """Act as the browser: fetch the authorization URL, hit the callback."""
    query = urllib.parse.parse_qs(urllib.parse.urlparse(prompt_url).query)
    idp.seen_challenge = query["code_challenge"][0]
    callback = query["redirect_uri"][0]
    httpx.get(callback + "?" + urllib.parse.urlencode({
        "code": code, "state": query["state"][0]
    }), timeout=10)


# -- config -------------------------------------------------------------------


def test_backend_auth_from_yaml_defaults():
    auth = BackendAuth.from_yaml({"client_id": "c"})
    assert auth.client_id == "c"
    assert auth.scopes == ("openid", "profile", "email")
    assert auth.callback_port == 8899
    # Wildcard host renders as loopback: browsers dial localhost.
    assert auth.redirect_uri() == "http://localhost:8899/callback"


def test_backend_auth_fixed_port_and_host():
    auth = BackendAuth.from_yaml({
        "client_id": "c", "callback_host": "127.0.0.1",
        "callback_port": 9321, "callback_path": "/cb",
    })
    assert auth.redirect_uri() == "http://127.0.0.1:9321/cb"


def test_backend_auth_requires_client_id():
    with pytest.raises(OAuthError):
        BackendAuth.from_yaml({"callback_port": 1})
    assert BackendAuth.from_yaml(None) is None


def test_backend_auth_scopes_as_string_or_list():
    assert BackendAuth.from_yaml({"client_id": "c", "scopes": "a b"}).scopes == ("a", "b")
    assert BackendAuth.from_yaml({"client_id": "c", "scopes": ["x"]}).scopes == ("x",)


# -- token manager basics -----------------------------------------------------


def test_authorization_header_none_without_grant(tokens):
    assert tokens.authorization_header("https://host/mcp") is None


def test_store_roundtrip_and_permissions(tokens):
    tokens.save("https://host/mcp", StoredTokens(access_token="a"))
    import os
    import stat

    path = tokens.path_for("https://host/mcp")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert tokens.load("https://host/mcp/").access_token == "a"  # trailing slash ignored


def test_expired_grant_is_refreshed(idp, tokens):
    tokens.save(idp.resource, StoredTokens(
        access_token="stale", refresh_token="refresh-1", expires_at=time.time() - 5,
        refresh_expires_at=time.time() + 1800, token_endpoint=idp.token_url,
        client_id="c", resource=idp.resource, issuer=idp.origin,
    ))
    assert tokens.authorization_header(idp.resource) == "Bearer access-2"


def test_unrefreshable_grant_degrades_to_none(idp, tokens):
    tokens.save("https://host/mcp", StoredTokens(access_token="stale", expires_at=time.time() - 5))
    assert tokens.authorization_header("https://host/mcp") is None
    assert tokens.load("https://host/mcp") is not None  # not deleted


def test_status_reports_expiry(idp, tokens):
    body = tokens.status("https://host/mcp")
    assert body["configured"] is False
    tokens.save(idp.resource, StoredTokens(
        access_token="a", expires_at=time.time() + 300,
        refresh_token="r", refresh_expires_at=time.time() + 1800,
        client_id="c", resource=idp.resource,
    ))
    body = tokens.status(idp.resource)
    assert body["configured"] is True
    assert body["valid"] is True and body["refreshable"] is True
    assert 0 < body["expires_in"] <= 300


# -- the full login loop, Telegram-style: link first, click later -------------


def test_login_link_then_callback_completes(idp, tokens):
    link = tokens.login_link(idp.resource, BackendAuth(client_id="c", callback_port=0))
    assert "response_type=code" in link
    assert "resource=" in link
    _play_browser(link, idp)
    grant = tokens.complete_login(idp.resource, timeout_seconds=10)
    assert grant.access_token == "access-1"
    assert tokens.authorization_header(idp.resource) == "Bearer access-1"


def test_pending_login_survives_late_wait(idp, tokens):
    tokens.login_link(idp.resource, BackendAuth(client_id="c", callback_port=0))
    with pytest.raises(LoginPending):
        tokens.complete_login(idp.resource, timeout_seconds=0.2)
    # The operator finally clicks...
    link = tokens.login_link(idp.resource, BackendAuth(client_id="c", callback_port=0))
    _play_browser(link, idp)
    grant = tokens.complete_login(idp.resource, timeout_seconds=10)
    assert grant.access_token == "access-1"


def test_same_link_returned_while_pending(idp, tokens):
    first = tokens.login_link(idp.resource, BackendAuth(client_id="c", callback_port=0))
    second = tokens.login_link(idp.resource, BackendAuth(client_id="c", callback_port=0))
    assert first == second
    _play_browser(first, idp)
    assert tokens.complete_login(idp.resource, timeout_seconds=10).access_token == "access-1"


def test_pkce_verified_end_to_end(idp, tokens):
    link = tokens.login_link(idp.resource, BackendAuth(client_id="c", callback_port=0))
    _play_browser(link, idp)
    tokens.complete_login(idp.resource, timeout_seconds=10)
    exchange = [r for r in idp.requests if r[0] == "POST" and r[1] == "/token"][0]
    assert exchange[3]["client_id"] == "c"
    assert "client_secret" not in exchange[3]
    assert idp.seen_verifier


def test_bad_state_is_refused(idp, tokens):
    link = tokens.login_link(idp.resource, BackendAuth(client_id="c", callback_port=0))
    query = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
    httpx.get(
        query["redirect_uri"][0] + "?" + urllib.parse.urlencode(
            {"code": "GOODCODE", "state": "forged"}
        ), timeout=10,
    )
    with pytest.raises(OAuthError, match="state mismatch"):
        tokens.complete_login(idp.resource, timeout_seconds=10)
    assert tokens.load(idp.resource) is None


def test_truncated_later_callback_does_not_clobber(idp, tokens):
    """The Anton case: a second request with a partial query must not win."""
    link = tokens.login_link(idp.resource, BackendAuth(client_id="c", callback_port=0))
    query = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
    callback = query["redirect_uri"][0]
    idp.seen_challenge = query["code_challenge"][0]
    httpx.get(callback + "?" + urllib.parse.urlencode(
        {"code": "GOODCODE", "state": query["state"][0]}
    ), timeout=10)
    httpx.get(callback + "?state=st", timeout=10)  # the hand-pasted one
    assert tokens.complete_login(idp.resource, timeout_seconds=10).access_token == "access-1"


# -- discovery ----------------------------------------------------------------


def test_discover_resource_and_server(idp):
    with httpx.Client(timeout=10) as http:
        resource = discover_resource(http, idp.resource)
        assert resource.resource == idp.resource
        server = discover_authorization_server(http, resource.authorization_servers[0])
        assert server.token_endpoint == idp.token_url


# -- listener robustness (the bugs that bit mcp2cli) --------------------------


def test_listener_serves_second_client_while_first_holds_socket():
    listener = CallbackListener("127.0.0.1", 0, "/callback")

    def raw_request(path):
        import socket

        sock = socket.create_connection(("127.0.0.1", listener.port), timeout=4)
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        return sock, sock.recv(200)

    try:
        sock_a, reply_a = raw_request("/callback?code=GOOD&state=st")
        assert b"200 OK" in reply_a
        time.sleep(0.2)
        sock_b, reply_b = raw_request("/callback?state=st")
        assert b"200 OK" in reply_b
        sock_b.close()
        sock_a.close()
        assert listener.wait(5) == {"code": "GOOD", "state": "st"}
    finally:
        listener.close()


def test_listener_port_is_configurable():
    import socket

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    listener = CallbackListener("127.0.0.1", port, "/callback")
    try:
        assert listener.port == port
    finally:
        listener.close()


def test_listener_port_conflict_is_a_clear_error():
    blocker = CallbackListener("127.0.0.1", 0, "/callback")
    try:
        with pytest.raises(OAuthError, match="cannot listen"):
            CallbackListener("127.0.0.1", blocker.port, "/callback")
    finally:
        blocker.close()


# -- policy wiring -------------------------------------------------------------


def test_backend_config_carries_auth(tmp_path):
    """The auth block must survive policy loading into BackendConfig."""
    policy = tmp_path / "k8s-platform.yaml"
    policy.write_text(
        """backend:
  name: k8s-platform
  url: https://mcp-gw-test.example/servers/abc/mcp
  auth:
    client_id: kubernetes-mcp-cursor
    callback_port: 8899
rules:
  - match: { tool: ".*" }
    action: allow
""",
        encoding="utf-8",
    )
    from gateway.policy_proxy import load_backend_policy

    config, rules = load_backend_policy(str(policy))
    assert config.auth is not None
    assert config.auth.client_id == "kubernetes-mcp-cursor"
    assert config.auth.redirect_uri() == "http://localhost:8899/callback"
    assert rules


def test_backend_without_auth_block_has_none(tmp_path):
    policy = tmp_path / "plain.yaml"
    policy.write_text(
        """backend:
  name: plain
  url: https://plain.example/mcp
rules:
  - match: { tool: ".*" }
    action: allow
""",
        encoding="utf-8",
    )
    from gateway.policy_proxy import load_backend_policy

    config, _ = load_backend_policy(str(policy))
    assert config.auth is None


def test_attach_backend_auth_is_noop_for_plain_backends():
    """A backend without auth must pass headers through untouched."""
    from gateway.policy_proxy import BackendConfig, _attach_backend_auth

    bc = BackendConfig(name="plain", url="https://plain.example/mcp")
    assert _attach_backend_auth(bc, None) is None
    original = {"X-Test": "1"}
    assert _attach_backend_auth(bc, original) == original


def test_attach_backend_auth_adds_bearer(idp, tmp_path, monkeypatch):
    """With a grant stored, the bearer is attached to the request headers."""
    monkeypatch.setenv("GATEWAY_OAUTH_CACHE_DIR", str(tmp_path / "oauth"))
    from gateway import policy_proxy

    manager = TokenManager(tmp_path / "oauth")
    monkeypatch.setattr(policy_proxy, "_oauth_tokens", manager)
    manager.save(
        idp.resource,
        StoredTokens(
            access_token="tok-1", expires_at=time.time() + 300,
            resource=idp.resource, client_id="c",
        ),
    )
    bc = policy_proxy.BackendConfig(
        name="k8s-platform", url=idp.resource,
        auth=BackendAuth(client_id="c"),
    )
    merged = policy_proxy._attach_backend_auth(bc, {"X-Test": "1"})
    assert merged["Authorization"] == "Bearer tok-1"
    assert merged["X-Test"] == "1"


def test_oauth_challenged_detects_401_through_wrappers():
    """The MCP SDK wraps transport errors - the status must still be found."""
    from gateway.policy_proxy import _oauth_challenged

    class _Resp:
        status_code = 401

    class _Err(Exception):
        response = _Resp()

    inner = _Err("nope")
    wrapped = ExceptionGroup("unhandled errors", [inner])  # noqa: F821
    assert _oauth_challenged(inner) is True
    assert _oauth_challenged(wrapped) is True
    assert _oauth_challenged(ValueError("bad request 400")) is False
    assert _oauth_challenged(ValueError("something else")) is False


def test_login_offer_runs_once_per_backend(tmp_path, monkeypatch):
    """A broken upstream must not spam the operator chat on every call."""
    from gateway import policy_proxy

    monkeypatch.setattr(policy_proxy, "_oauth_tokens", TokenManager(tmp_path / "oauth"))
    monkeypatch.setattr(policy_proxy, "_oauth_link_offered", set())
    monkeypatch.setattr(policy_proxy, "_telegram_backend", None)

    started = []

    class _Recorder:
        def login_link(self, url, auth):
            started.append(url)
            raise OAuthError("no IdP in this test")

    monkeypatch.setattr(policy_proxy, "_oauth_tokens", _Recorder())
    bc = policy_proxy.BackendConfig(
        name="k8s-platform", url="https://x.example/mcp", auth=BackendAuth(client_id="c")
    )
    policy_proxy._maybe_offer_oauth_login(bc)
    policy_proxy._maybe_offer_oauth_login(bc)
    deadline = time.time() + 5
    while not started and time.time() < deadline:
        time.sleep(0.05)
    assert started == ["https://x.example/mcp"], "login must be attempted exactly once"


def test_login_offer_ignores_plain_backends(tmp_path, monkeypatch):
    from gateway import policy_proxy

    monkeypatch.setattr(policy_proxy, "_oauth_link_offered", set())
    bc = policy_proxy.BackendConfig(name="plain", url="https://plain.example/mcp")
    policy_proxy._maybe_offer_oauth_login(bc)  # must not raise
    assert policy_proxy._oauth_link_offered == set()
