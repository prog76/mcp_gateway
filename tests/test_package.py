#!/usr/bin/env python3
"""
Integration tests for the mcp-gateway pip package.

Verifies:
- The package imports correctly (package-relative imports resolved)
- The core modules (policy_proxy, mounted_server, policy_yaml, validate_policy) load
- The start entrypoint module can be imported and its helpers work
- Policy loading/validation works against sample YAML
- The console script entrypoint is wired correctly
"""

import os
import sys
from pathlib import Path

import pytest
import yaml

# Ensure the package is importable (editable install or source tree)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gateway  # noqa: E402
from gateway import mounted_server  # noqa: E402
from gateway import policy_proxy  # noqa: E402
from gateway import policy_yaml  # noqa: E402
from gateway import validate_policy  # noqa: E402
def test_package_imports():
    """All core modules import cleanly."""
    assert gateway.__version__ == "0.1.0"
    assert gateway.policy_proxy is policy_proxy
    assert hasattr(gateway.policy_proxy, "load_all_policies")
    assert hasattr(gateway.policy_proxy, "MountedServer") or hasattr(
        policy_proxy, "MountedServer"
    )
def test_policy_yaml_concat_tag():
    """The !concat tag works for composing policy match lists."""
    raw = """
    x_a: &a
      - cat
      - ls
    x_b: &b
      - grep
    rules:
      - match:
          tool: ".*"
          binary: !concat [*a, *b]
        action: allow
    """
    data = yaml.load(raw, Loader=policy_yaml.PolicyLoader)
    rules = data["rules"]
    assert rules[0]["match"]["binary"] == ["cat", "ls", "grep"]
def test_policy_yaml_loader():
    """PolicyLoader is a SafeLoader subclass."""
    assert issubclass(policy_yaml.PolicyLoader, yaml.SafeLoader)
def test_validate_policy_per_backend(tmp_path):
    """Validate a minimal per-backend policy file."""
    policy_file = tmp_path / "test-backend.yaml"
    policy_file.write_text(
        """\
backend:
  name: test
  url: "http://localhost:9999/mcp"
  transport: http

default_deny: "Access denied."

rules:
  - match:
      tool: ".*"
    action: allow

  - match:
      tool: ".*"
    action: deny
    reason: "Default deny"
"""
    )

    result = validate_policy.validate_policy(str(policy_file))
    assert result is True
def test_load_all_policies(tmp_path):
    """load_all_policies reads per-backend YAML files from a directory."""
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    (policy_dir / "skills.yaml").write_text(
        """\
backend:
  name: skills
  path: /mcp/skills
  url: "http://localhost:9002/mcp"
  transport: http

default_deny: "Denied."

rules:
  - match:
      tool: ".*"
    action: allow

  - match:
      tool: ".*"
    action: deny
"""
    )

    backends = policy_proxy.load_all_policies(str(policy_dir))
    assert len(backends) == 1
    bc, rules = backends[0]
    assert bc.name == "skills"
    assert bc.url == "http://localhost:9002/mcp"
    assert len(rules) == 2
def test_backend_config_normalization():
    """BackendConfig fields normalize correctly from policy files."""
    bc = policy_proxy.BackendConfig(name="test", transport="http")
    assert bc.name == "test"
    assert bc.default_deny == "Access denied."
    assert bc.pass_kwargs_raw is False
    assert bc.headers is None
def test_resolve_env_value():
    """${env:VAR} resolution works."""
    os.environ["MCP_TEST_ENV_VALUE"] = "hello"
    resolved = policy_proxy.resolve_env_value("value=${env:MCP_TEST_ENV_VALUE}")
    assert resolved == "value=hello"
def test_matches_rule():
    """Policy rules match against tool names and args."""
    rule = {
        "match": {"tool": "^kubectl$", "namespace": "^prod$"},
        "action": "allow",
    }
    assert policy_proxy.matches_rule(rule, "kubectl", {"namespace": "prod"})
    assert not policy_proxy.matches_rule(rule, "kubectl", {"namespace": "dev"})
    assert not policy_proxy.matches_rule(rule, "other", {"namespace": "prod"})

    # Nested field access via dotted path works too
    rule2 = {
        "match": {"tool": ".*", "metadata.namespace": "^prod$"},
        "action": "allow",
    }
    assert policy_proxy.matches_rule(rule2, "any_tool", {"metadata": {"namespace": "prod"}})
    assert not policy_proxy.matches_rule(rule2, "any_tool", {"metadata": {"namespace": "dev"}})
def test_notification_config_env_fallback(tmp_path):
    """Unresolved ${env:VAR} timeout falls back to default 300 instead of crashing."""
    old = os.environ.pop("MCP_APPROVAL_TIMEOUT_SECONDS", None)
    try:
        cfg_path = tmp_path / "notifications.yaml"
        cfg_path.write_text(
            """\
notifications:
  timeout: "${env:MCP_APPROVAL_TIMEOUT_SECONDS}"
  telegram:
    enabled: false
"""
        )
        cfg = policy_proxy.load_notification_config(str(cfg_path))
        assert cfg is not None
        assert cfg.timeout == 300
    finally:
        if old is not None:
            os.environ["MCP_APPROVAL_TIMEOUT_SECONDS"] = old
def test_notification_config_env_resolved(tmp_path):
    """Resolved ${env:VAR} timeout is used."""
    os.environ["MCP_APPROVAL_TIMEOUT_SECONDS"] = "120"
    try:
        cfg_path = tmp_path / "notifications.yaml"
        cfg_path.write_text(
            """\
notifications:
  timeout: "${env:MCP_APPROVAL_TIMEOUT_SECONDS}"
  telegram:
    enabled: false
"""
        )
        cfg = policy_proxy.load_notification_config(str(cfg_path))
        assert cfg is not None
        assert cfg.timeout == 120
    finally:
        os.environ.pop("MCP_APPROVAL_TIMEOUT_SECONDS", None)
def test_mounted_server_importable():
    """MountedServer class is importable."""
    assert hasattr(mounted_server, "MountedServer")
def test_start_entrypoint_helpers():
    """The start module is a pure policy-proxy entrypoint (no child servers)."""
    from gateway import start

    # Background-server supervision was removed: backends run as their own
    # containers, supervised by the orchestrator (docker-compose).
    assert not hasattr(start, "_build_mcp_servers")
    assert not hasattr(start, "ServerProcess")
    assert not hasattr(start, "run_watchdog")
    # The entrypoint still exposes policy validation + the proxy runner.
    assert callable(start.validate_policies)
    assert callable(start.run_proxy_forever)
    assert callable(start.main)
def test_start_main_entrypoint_registered():
    """The console script references gateway.start.main."""
    import importlib.metadata

    entry_points = importlib.metadata.entry_points()
    ep_list = []
    if hasattr(entry_points, "select"):
        ep_list = list(entry_points.select(group="console_scripts"))
    else:
        for eps in entry_points.values():
            ep_list.extend(eps)
    matching = [ep for ep in ep_list if ep.name == "mcp-gateway-start"]
    assert matching, "mcp-gateway-start console script not registered"
    assert matching[0].value == "gateway.start:main"
# ---------------------------------------------------------------------------
# Compound headers: tests for the new compound-level HTTP header feature
# ---------------------------------------------------------------------------

def test_compound_config_has_headers():
    """CompoundConfig supports a headers field (defaults to None)."""
    cc = policy_proxy.CompoundConfig(
        name="test",
        path="/mcp/test",
        backends=["backend1"],
        headers={"X-Custom": "value"},
    )
    assert cc.headers == {"X-Custom": "value"}

    # Default is None
    cc2 = policy_proxy.CompoundConfig(
        name="test2",
        path="/mcp/test2",
        backends=[],
    )
    assert cc2.headers is None
def test_load_compounds_with_headers(tmp_path):
    """load_compounds parses headers from YAML config."""
    compounds_file = tmp_path / "compounds.yaml"
    compounds_file.write_text(
        """\
compounds:
  test:
    path: /mcp/test
    backends: [backend1]
    headers:
      X-Dynamic: "value-${env:TEST_VAR}"
      X-Host: "${clientHost}"
"""
    )
    os.environ["TEST_VAR"] = "resolved"
    try:
        available = {"backend1": policy_proxy.BackendConfig(name="backend1", url="http://localhost:9999")}
        compounds = policy_proxy.load_compounds(str(compounds_file), available)
        assert len(compounds) == 1
        assert compounds[0].headers == {
            "X-Dynamic": "value-${env:TEST_VAR}",
            "X-Host": "${clientHost}",
        }
    finally:
        os.environ.pop("TEST_VAR", None)
def test_load_compounds_headers_type_validation(tmp_path):
    """load_compounds rejects non-mapping headers and warns."""
    compounds_file = tmp_path / "compounds.yaml"
    compounds_file.write_text(
        """\
compounds:
  test:
    path: /mcp/test
    backends: [backend1]
    headers: "not-a-mapping"
"""
    )
    available = {"backend1": policy_proxy.BackendConfig(name="backend1", url="http://localhost:9999")}
    compounds = policy_proxy.load_compounds(str(compounds_file), available)
    assert len(compounds) == 1
    assert compounds[0].headers is None
def test_load_compounds_no_headers():
    """Compounds without headers field get headers=None (backward compat)."""
    cc = policy_proxy.CompoundConfig(name="x", path="/mcp/x", backends=[])
    assert cc.headers is None
def test_resolve_header_refs():
    """_resolve_header_refs resolves ${header:NAME} and ${request_header:NAME}."""
    hr_token = policy_proxy._request_headers.set({
        "X-Client-Host": "my-host",
        "X-Token": "secret123",
    })
    ih_token = policy_proxy._incoming_headers.set({"Authorization": "Bearer abc123"})
    try:
        # ${header:NAME} from _request_headers
        assert policy_proxy._resolve_header_refs("${header:X-Token}") == "secret123"

        # ${request_header:NAME} from _incoming_headers
        assert policy_proxy._resolve_header_refs("${request_header:Authorization}") == "Bearer abc123"

        # Missing header leaves template unchanged
        assert policy_proxy._resolve_header_refs("${header:Nonexistent}") == "${header:Nonexistent}"

        # Multiple refs in one string
        result = policy_proxy._resolve_header_refs(
            "${header:X-Client-Host} sent ${request_header:Authorization}"
        )
        assert result == "my-host sent Bearer abc123"

        # Non-string values pass through
        assert policy_proxy._resolve_header_refs(42) == 42

        # None (empty ContextVar) → empty headers, template left unchanged
        hr_token2 = policy_proxy._request_headers.set(None)
        try:
            assert policy_proxy._resolve_header_refs("${header:X-Token}") == "${header:X-Token}"
        finally:
            policy_proxy._request_headers.reset(hr_token2)
    finally:
        policy_proxy._request_headers.reset(hr_token)
        policy_proxy._incoming_headers.reset(ih_token)
def test_resolve_template_with_header():
    """resolve_template supports ${header:NAME} and ${request_header:NAME}."""
    hr_token = policy_proxy._request_headers.set({"X-User": "bob"})
    ih_token = policy_proxy._incoming_headers.set({"X-Original-Auth": "Bearer xyz"})
    try:
        assert policy_proxy.resolve_template("Hello ${header:X-User}", "tool_name", {}) == "Hello bob"
        assert policy_proxy.resolve_template(
            "Auth: ${request_header:X-Original-Auth}", "tool_name", {}
        ) == "Auth: Bearer xyz"
        # Unknown header leaves template unchanged
        assert policy_proxy.resolve_template(
            "Val: ${header:Missing}", "tool_name", {}
        ) == "Val: ${header:Missing}"
    finally:
        policy_proxy._request_headers.reset(hr_token)
        policy_proxy._incoming_headers.reset(ih_token)
def test_resolve_injections_with_headers():
    """resolve_injections supports ${header:NAME} from _request_headers."""
    hr_token = policy_proxy._request_headers.set({"X-User-ID": "user42"})
    try:
        result = policy_proxy.resolve_injections({"user": "${header:X-User-ID}"})
        assert result["user"] == "user42"
    finally:
        policy_proxy._request_headers.reset(hr_token)
def test_resolve_injections_with_request_header():
    """resolve_injections supports ${request_header:NAME} from _incoming_headers."""
    ih_token = policy_proxy._incoming_headers.set({"Authorization": "Bearer token123"})
    try:
        result = policy_proxy.resolve_injections({"auth": "${request_header:Authorization}"})
        assert result["auth"] == "Bearer token123"
    finally:
        policy_proxy._incoming_headers.reset(ih_token)
def test_resolve_injections_with_client_info():
    """resolve_injections supports ${clientHost} and ${clientIp}."""
    ci_token = policy_proxy._client_info.set(
        policy_proxy.ClientInfo(ip="192.168.1.1", host="myhost")
    )
    try:
        result = policy_proxy.resolve_injections({
            "host": "${clientHost}",
            "ip": "${clientIp}",
        })
        assert result["host"] == "myhost"
        assert result["ip"] == "192.168.1.1"
    finally:
        policy_proxy._client_info.reset(ci_token)
def test_resolve_injections_env_still_works():
    """resolve_injections still resolves ${env:VAR} (backward compat)."""
    os.environ["MCP_TEST_INJECT_ENV"] = "env_value"
    try:
        result = policy_proxy.resolve_injections({"var": "${env:MCP_TEST_INJECT_ENV}"})
        assert result["var"] == "env_value"
    finally:
        os.environ.pop("MCP_TEST_INJECT_ENV", None)
def test_resolve_compound_header_value():
    """_resolve_compound_header_value resolves ${env:VAR}, ${clientHost},
    ${clientIp}, and ${request_header:NAME} — but NOT ${header:NAME}
    (would be circular)."""
    os.environ["TEST_COMPOUND_VAR"] = "env-value"
    ci_token = policy_proxy._client_info.set(
        policy_proxy.ClientInfo(ip="10.0.0.1", host="client.example.com")
    )
    ih_token = policy_proxy._incoming_headers.set({"Authorization": "Bearer xyz"})
    try:
        info = policy_proxy._client_info.get()
        # Env var
        assert policy_proxy._resolve_compound_header_value("${env:TEST_COMPOUND_VAR}", info) == "env-value"
        # Client host
        assert policy_proxy._resolve_compound_header_value("${clientHost}", info) == "client.example.com"
        # Client IP
        assert policy_proxy._resolve_compound_header_value("${clientIp}", info) == "10.0.0.1"
        # Request header (from incoming MCP client request)
        assert policy_proxy._resolve_compound_header_value(
            "${request_header:Authorization}", info
        ) == "Bearer xyz"
        # ${header:NAME} is NOT resolved (would be circular) — left unchanged
        assert policy_proxy._resolve_compound_header_value(
            "${header:SomeHeader}", info
        ) == "${header:SomeHeader}"
        # Non-string values pass through
        assert policy_proxy._resolve_compound_header_value(42, info) == 42
    finally:
        policy_proxy._client_info.reset(ci_token)
        policy_proxy._incoming_headers.reset(ih_token)
        os.environ.pop("TEST_COMPOUND_VAR", None)
def test_resolve_injections_no_context_vars():
    """resolve_injections works with no ContextVars set (backward compat)."""
    # Ensure ContextVars are reset to default
    hr_token = policy_proxy._request_headers.set(None)
    ih_token = policy_proxy._incoming_headers.set(None)
    ci_token = policy_proxy._client_info.set(None)
    try:
        # ${header:NAME} unresolved, ${env:VAR} still works
        os.environ["MCP_TEST_NO_CTX"] = "val"
        try:
            result = policy_proxy.resolve_injections({
                "from_header": "${header:Missing}",
                "from_env": "${env:MCP_TEST_NO_CTX}",
            })
            assert result["from_header"] == "${header:Missing}"
            assert result["from_env"] == "val"
        finally:
            os.environ.pop("MCP_TEST_NO_CTX", None)
    finally:
        policy_proxy._request_headers.reset(hr_token)
        policy_proxy._incoming_headers.reset(ih_token)
        policy_proxy._client_info.reset(ci_token)


# ---------------------------------------------------------------------------
# Structured-content passthrough (outputSchema "no structured output" bug)
#
# Regression for: a proxied tool that advertises an outputSchema fails with
#   "Output validation error: outputSchema defined but no structured output returned"
# because forward() discarded structuredContent from the upstream response and
# MountedServer.call_tool collapsed everything to bare text blocks. A proxy
# must preserve the upstream's structuredContent and return a CallToolResult so
# the SDK does not re-validate (the upstream already validated it).
# ---------------------------------------------------------------------------
import asyncio
import time
import contextlib
from unittest.mock import AsyncMock, MagicMock

from mcp.types import CallToolResult, TextContent


class _FakeCallToolResult:
    """Shape of the MCP SDK's CallToolResult as seen by forward()."""

    def __init__(self, content, structured_content=None, is_error=False):
        self.content = content
        self.structuredContent = structured_content
        self.isError = is_error


async def _run_forward(bc, tool_name, arguments, upstream_result):
    """Call policy_proxy.forward with the network layer faked."""

    @contextlib.asynccontextmanager
    async def fake_http_client(*a, **kw):
        yield (MagicMock(), MagicMock(), None)

    session = MagicMock()
    session.initialize = AsyncMock()
    session.call_tool = AsyncMock(return_value=upstream_result)

    class FakeClientSession:
        def __init__(self, *a, **kw):
            self._s = session

        async def __aenter__(self):
            return self._s

        async def __aexit__(self, *exc):
            return False

    orig_client = policy_proxy.streamablehttp_client
    orig_session = policy_proxy.ClientSession
    policy_proxy.streamablehttp_client = fake_http_client
    policy_proxy.ClientSession = FakeClientSession
    try:
        return await policy_proxy.forward(bc, tool_name, arguments)
    finally:
        policy_proxy.streamablehttp_client = orig_client
        policy_proxy.ClientSession = orig_session


def test_forward_preserves_structured_content():
    """forward() must propagate structuredContent from the upstream response."""
    bc = policy_proxy.BackendConfig(name="gitlab", url="http://gitlab/mcp", transport="http")
    upstream = _FakeCallToolResult(
        content=[TextContent(type="text", text="repo-list")],
        structured_content={"projects": [{"name": "a"}, {"name": "b"}]},
        is_error=False,
    )
    result = asyncio.run(_run_forward(bc, "list_group_projects", {"group_path": "x"}, upstream))
    assert result["content"] == ["repo-list"]
    assert result["structuredContent"] == {"projects": [{"name": "a"}, {"name": "b"}]}
    assert result["isError"] is False


def test_make_policy_handler_returns_calltoolresult_with_structured():
    """With structuredContent present, the policy handler returns a CallToolResult
    (so MountedServer / the SDK pass it through without revalidation)."""
    bc = policy_proxy.BackendConfig(name="gitlab", url="http://gitlab/mcp", transport="http")
    status = policy_proxy.BackendStatus(name="gitlab", healthy=True)
    rules = [{"match": {"tool": ".*"}, "action": "allow"}]
    handler = policy_proxy.make_policy_handler(bc, rules, "list_group_projects", status)

    async def fake_forward(bc, tool_name, arguments):
        return {
            "content": ["repo-list"],
            "structuredContent": {"projects": [{"name": "a"}]},
            "isError": False,
        }

    orig_f = policy_proxy.forward
    policy_proxy.forward = fake_forward
    try:
        out = asyncio.run(handler(group_path="x"))
    finally:
        policy_proxy.forward = orig_f

    assert isinstance(out, CallToolResult)
    assert out.structuredContent == {"projects": [{"name": "a"}]}
    assert out.isError is False
    assert out.content[0].text == "repo-list"


def test_make_policy_handler_wraps_iserror_in_calltoolresult():
    """An error-backed result becomes a CallToolResult flagged isError."""
    bc = policy_proxy.BackendConfig(name="gitlab", url="http://gitlab/mcp", transport="http")
    status = policy_proxy.BackendStatus(name="gitlab", healthy=True)
    rules = [{"match": {"tool": ".*"}, "action": "allow"}]
    handler = policy_proxy.make_policy_handler(bc, rules, "broken", status)

    async def fake_forward(bc, tool_name, arguments):
        return {"content": ["boom"], "isError": True}

    orig_f = policy_proxy.forward
    policy_proxy.forward = fake_forward
    try:
        out = asyncio.run(handler())
    finally:
        policy_proxy.forward = orig_f

    assert isinstance(out, CallToolResult)
    assert out.isError is True
    assert out.content[0].text == "boom"


# ---------------------------------------------------------------------------
# Compound discovery caching: create_compound_server must reuse the tool list
# already cached on BackendStatus.tools (from Phase 1 backend mounting)
# instead of calling discover_from_backend() again for each compound.
# ---------------------------------------------------------------------------


class _FakeTool:
    """Minimal stand-in for an mcp.types.Tool with the attributes
    create_compound_server / register_backend_tools read."""

    def __init__(self, name, description="test tool"):
        self.name = name
        self.description = description
        self.inputSchema = {"type": "object", "properties": {}}
        self.input_schema = self.inputSchema
        self.outputSchema = None
        self.output_schema = None


def test_compound_server_reuses_cached_tools_no_rediscovery():
    """create_compound_server must NOT call discover_from_backend when
    BackendStatus already has cached tools from Phase 1 (backend mounting).

    This is the core optimization: a backend shared across N compounds is
    discovered once at startup, not N+1 times.
    """
    bc = policy_proxy.BackendConfig(
        name="fakebackend",
        url="http://fakebackend:9001/mcp",
        transport="http",
        path="/mcp/fakebackend",
    )

    status = policy_proxy.BackendStatus(
        name="fakebackend",
        healthy=True,
        config=bc,
        rules=[{"match": {"tool": ".*"}, "action": "allow"}],
        tools=[_FakeTool("list_items"), _FakeTool("get_item")],
    )

    backend_status_map = {"fakebackend": status}

    compound = policy_proxy.CompoundConfig(
        name="test_compound",
        path="/mcp/test_compound",
        backends=["fakebackend"],
    )

    # Wrap discover_from_backend to detect any call.
    call_count = {"n": 0}
    original = policy_proxy.discover_from_backend

    async def counting_discover(bc):
        call_count["n"] += 1
        return [], None

    policy_proxy.discover_from_backend = counting_discover
    try:
        server, compound_status = asyncio.run(
            policy_proxy.create_compound_server(
                compound, backend_status_map, 8000, ["localhost"]
            )
        )
    finally:
        policy_proxy.discover_from_backend = original

    # Key assertion: zero re-discovery calls.
    assert call_count["n"] == 0, (
        f"Expected discover_from_backend to be called 0 times, but it was "
        f"called {call_count['n']} times — tools should be reused from cache."
    )

    # Functionality preserved: prefixed tools registered on the compound server.
    assert compound_status.tools_count == 2
    assert compound_status.healthy is True
    registered = [t.name for t in server._tools]
    assert "fakebackend_list_items" in registered
    assert "fakebackend_get_item" in registered


def test_compound_server_skips_unhealthy_backend_no_rediscovery():
    """An unhealthy backend (no cached tools) must be skipped by the compound
    without calling discover_from_backend."""
    bc = policy_proxy.BackendConfig(
        name="downbackend",
        url="http://downbackend:9001/mcp",
        transport="http",
        path="/mcp/downbackend",
    )

    status = policy_proxy.BackendStatus(
        name="downbackend",
        healthy=False,
        config=bc,
        rules=[{"match": {"tool": ".*"}, "action": "deny"}],
        tools=[],
    )

    backend_status_map = {"downbackend": status}

    compound = policy_proxy.CompoundConfig(
        name="test_compound",
        path="/mcp/test_compound",
        backends=["downbackend"],
    )

    call_count = {"n": 0}
    original = policy_proxy.discover_from_backend

    async def counting_discover(bc):
        call_count["n"] += 1
        return [], None

    policy_proxy.discover_from_backend = counting_discover
    try:
        server, compound_status = asyncio.run(
            policy_proxy.create_compound_server(
                compound, backend_status_map, 8000, ["localhost"]
            )
        )
    finally:
        policy_proxy.discover_from_backend = original

    assert call_count["n"] == 0, (
        f"Expected discover_from_backend to be called 0 times for an unhealthy "
        f"backend, but it was called {call_count['n']} times."
    )
    assert compound_status.tools_count == 0
    assert compound_status.healthy is False


def test_confirm_emits_progress_notifications():
    """A confirm-action handler that is blocked awaiting a Telegram decision must
    emit periodic MCP progress notifications to the agent (when a relay is set),
    and stop once the operator approves."""
    bc = policy_proxy.BackendConfig(name="gitlab", url="http://gitlab/mcp", transport="http")
    status = policy_proxy.BackendStatus(name="gitlab", healthy=True)
    rules = [
        {
            "match": {"tool": ".*"},
            "action": "confirm",
            "timeout": 30,
        }
    ]

    progress_calls = []

    async def fake_relay(progress, total, message):
        progress_calls.append((progress, total, message))

    class FakeTelegramBackend:
        async def send_approval_request(self, **kw):
            return True

        async def edit_request_timeout(self, request_id):
            pass

    async def fake_forward(bc, tool_name, arguments):
        return {"content": ["approved-ok"], "structuredContent": None, "isError": False}

    orig_callback = policy_proxy.get_upstream_progress_callback
    orig_tg = policy_proxy._telegram_backend
    orig_forward = policy_proxy.forward
    orig_interval = policy_proxy.PROGRESS_INTERVAL

    async def scenario():
        policy_proxy._telegram_backend = FakeTelegramBackend()
        policy_proxy.get_upstream_progress_callback = lambda: fake_relay
        policy_proxy.forward = fake_forward
        policy_proxy.PROGRESS_INTERVAL = 0.02

        handler = policy_proxy.make_policy_handler(bc, rules, "git", status)
        task = asyncio.create_task(handler(repo="x"))

        # Wait until the confirm branch registers a PendingRequest.
        for _ in range(500):
            if policy_proxy._pending_requests:
                break
            await asyncio.sleep(0.01)
        assert policy_proxy._pending_requests, "confirm never created a pending request"

        _rid, pending = next(iter(policy_proxy._pending_requests.items()))
        # Let the ticker heartbeat a few times while we're "waiting".
        await asyncio.sleep(0.1)
        # Simulate the operator approving in Telegram.
        pending.approved = True
        pending.event.set()
        out = await task
        return out

    try:
        out = asyncio.run(scenario())
    finally:
        policy_proxy.get_upstream_progress_callback = orig_callback
        policy_proxy._telegram_backend = orig_tg
        policy_proxy.forward = orig_forward
        policy_proxy.PROGRESS_INTERVAL = orig_interval
        policy_proxy._pending_requests.clear()

    # We must have received at least one progress notification during the wait.
    assert progress_calls, "expected progress notifications during the Telegram confirm wait"
    for progress, total, message in progress_calls:
        assert total == 30
        assert "approval" in message.lower()
    # The handler resolved with the approved-forward result after approval.
    assert "approved-ok" in out


def _run_confirm(approved, upstream=None, tool="gitlab_create_branch"):
    """Run the confirm branch of make_policy_handler to completion.

    Simulates the operator's Telegram decision (``approved=True/False``) on the
    pending request and returns the handler's result.
    """
    bc = policy_proxy.BackendConfig(name="gitlab", url="http://gitlab/mcp", transport="http")
    status = policy_proxy.BackendStatus(name="gitlab", healthy=True)
    rules = [
        {
            "match": {"tool": ".*"},
            "action": "confirm",
            "timeout": 30,
        }
    ]

    class FakeTelegramBackend:
        async def send_approval_request(self, **kw):
            return True

        async def edit_request_timeout(self, request_id):
            pass

    orig_tg = policy_proxy._telegram_backend
    orig_forward = policy_proxy.forward

    async def fake_forward(bc, tool_name, arguments):
        if upstream is None:
            raise AssertionError("forward() was called without an upstream stub")
        return upstream

    async def scenario():
        policy_proxy._telegram_backend = FakeTelegramBackend()
        policy_proxy.forward = fake_forward
        handler = policy_proxy.make_policy_handler(bc, rules, tool, status)
        task = asyncio.create_task(
            handler(project_path="sysadm/devops/kubernetes/helm/ls-vm-chart",
                    branch="feature/add-initial-chart", ref="main")
        )
        for _ in range(500):
            if policy_proxy._pending_requests:
                break
            await asyncio.sleep(0.01)
        assert policy_proxy._pending_requests, "confirm never created a pending request"
        _rid, pending = next(iter(policy_proxy._pending_requests.items()))
        pending.approved = approved
        pending.event.set()
        return await task

    try:
        return asyncio.run(scenario())
    finally:
        policy_proxy._telegram_backend = orig_tg
        policy_proxy.forward = orig_forward
        policy_proxy._pending_requests.clear()


def test_confirm_approved_preserves_structured_content():
    """Approved confirm for an outputSchema-typed tool must carry the upstream
    structuredContent through to the client.

    Regression for "RuntimeError: Tool gitlab_create_branch has an output schema
    but did not return structured content": the confirm branch used to render
    the approved template to a plain str and drop structuredContent/isError.
    """
    upstream = {
        "content": ["Branch 'feature/add-initial-chart' created"],
        "structuredContent": {
            "name": "feature/add-initial-chart",
            "web_url": "https://gitlab.example/sysadm/devops/kubernetes/helm/ls-vm-chart/-/branches/feature/add-initial-chart",
        },
        "isError": False,
    }
    out = _run_confirm(approved=True, upstream=upstream)
    assert isinstance(out, CallToolResult)
    assert out.isError is False
    assert out.structuredContent == upstream["structuredContent"]
    assert "Operator approved" in out.content[0].text
    assert "created" in out.content[0].text


def test_confirm_approved_upstream_error_keeps_is_error():
    """If the upstream call fails after approval (e.g. a GitLab API error), the
    handler must surface an errored result — the previous plain-string return
    was read as a success and, for outputSchema tools, collapsed into the SDK's
    "did not return structured content" RuntimeError that masked the real error.
    """
    upstream = {
        "content": ["Error: Branch 'main' not found"],
        "structuredContent": None,
        "isError": True,
    }
    out = _run_confirm(approved=True, upstream=upstream)
    assert isinstance(out, CallToolResult)
    assert out.isError is True
    assert "Branch 'main' not found" in out.content[0].text


def test_confirm_denied_returns_error_result():
    """An operator decline must surface as an isError result. A plain string
    would be wrapped by MountedServer as a *successful* result, and for
    outputSchema-typed tools it would trigger the SDK's "did not return
    structured content" RuntimeError instead of showing the decline reason.
    """
    out = _run_confirm(approved=False, upstream=None)
    assert isinstance(out, CallToolResult)
    assert out.isError is True
    assert "ACCESS DENIED" in out.content[0].text


def test_allowance_key_requires_session():
    """_allowance_key returns None when no Mcp-Session-Id is present."""

    assert policy_proxy._allowance_key(None, "gitlab", 0) is None
    assert policy_proxy._allowance_key(policy_proxy.ClientInfo(ip="1.2.3.4", host="h"), "gitlab", 0) is None


def test_allowance_key_binds_session_and_ip():
    """The allowance key binds (session id | client ip), backend name, rule index."""

    token = policy_proxy._incoming_headers.set({"Mcp-Session-Id": "sess-1"})
    try:
        info = policy_proxy.ClientInfo(ip="1.2.3.4", host="h")
        k1 = policy_proxy._allowance_key(info, "gitlab", 2)
        assert k1 == ("1.2.3.4|sess-1", "gitlab", 2)
        # A different session id yields a different key (no cross-session grant).
        k2 = policy_proxy._allowance_key(info, "gitlab", 2)  # same — recheck
        assert k1 == k2
        # Different origin (ip0 changes the key too (prevents spoofing via header only).
        k3 = policy_proxy._allowance_key(policy_proxy.ClientInfo(ip="9.9.9.9", host="h2"), "gitlab", 2)
        assert k1 != k3
    finally:
        policy_proxy._incoming_headers.reset(token)


def test_captured_session_id_header_wins_over_fallback():
    """The middleware-captured header takes priority when both are present."""
    from gateway import mounted_server as _ms

    hdr_tok = policy_proxy._incoming_headers.set({"Mcp-Session-Id": "hdr-session"})
    key_tok = _ms._current_session_key.set("mounted-session")
    try:
        assert policy_proxy._captured_session_id() == "hdr-session"
    finally:
        _ms._current_session_key.reset(key_tok)
        policy_proxy._incoming_headers.reset(hdr_tok)


def test_captured_session_id_falls_back_to_mounted_server_key():
    """Streamable-HTTP handlers run in the MCP SDK's per-session task, where
    HTTP-middleware ContextVars are invisible.  The MountedServer resolves the
    echoed Mcp-Session-Id from the SDK request context; ``_captured_session_id``
    must fall back to it so the confirm gate can offer the 30-minute button."""
    from gateway import mounted_server as _ms

    hdr_tok = policy_proxy._incoming_headers.set(None)
    key_tok = _ms._current_session_key.set("sess-abcd")
    try:
        assert policy_proxy._captured_session_id() == "sess-abcd"
    finally:
        _ms._current_session_key.reset(key_tok)
        policy_proxy._incoming_headers.reset(hdr_tok)


def test_captured_session_id_empty_without_either_source():
    from gateway import mounted_server as _ms

    hdr_tok = policy_proxy._incoming_headers.set(None)
    key_tok = _ms._current_session_key.set("")
    try:
        assert policy_proxy._captured_session_id() == ""
    finally:
        _ms._current_session_key.reset(key_tok)
        policy_proxy._incoming_headers.reset(hdr_tok)


# ---------------------------------------------------------------------------
# Per-session-task capture of incoming headers (policy inject support)
# ---------------------------------------------------------------------------
def test_resolve_injections_uses_session_task_captured_headers():
    """${request_header:NAME} resolves from the MountedServer capture.

    Regression: the middleware-scoped capture is empty inside the MCP SDK's
    per-session task, so the ipybox policy's
    ``kernel_env.MCP_SESSION_ID: ${request_header:Mcp-Session-Id}`` stayed
    verbatim.  ipybox rejected the unresolved value and keyed its kernel on the
    per-call transport session instead, starting a fresh kernel (and a fresh
    confirm-gate session) on every execute_code call — so the "Allow 10 min
    (session)" bypass never matched.
    """
    from gateway import mounted_server as _ms

    hdr_tok = policy_proxy._incoming_headers.set(None)
    cap_tok = _ms._captured_incoming_headers.set({"Mcp-Session-Id": "sess-xyz"})
    try:
        out = policy_proxy.resolve_injections(
            {"kernel_env": {"MCP_SESSION_ID": "${request_header:Mcp-Session-Id}"}}
        )
        assert out["kernel_env"]["MCP_SESSION_ID"] == "sess-xyz"
        # resolve_template (used by match/template rules) sees it too.
        assert policy_proxy.resolve_template(
            "${request_header:Mcp-Session-Id}", "execute_code", {}
        ) == "sess-xyz"
    finally:
        _ms._captured_incoming_headers.reset(cap_tok)
        policy_proxy._incoming_headers.reset(hdr_tok)


def test_resolve_injections_current_request_capture_wins_over_stale_middleware():
    """The per-session current-request capture wins over stale middleware state.

    The middleware capture belongs to *initialize* (no ``Mcp-Session-Id`` yet),
    while the mounted re-capture reads the headers of the *current* tools/call —
    so when both are populated they can disagree and the current request wins.
    """
    from gateway import mounted_server as _ms

    hdr_tok = policy_proxy._incoming_headers.set({"Mcp-Session-Id": "initialize"})
    cap_tok = _ms._captured_incoming_headers.set({"Mcp-Session-Id": "session-task"})
    try:
        assert policy_proxy._incoming_headers_effective() == {"Mcp-Session-Id": "session-task"}
        out = policy_proxy.resolve_injections({"sid": "${request_header:Mcp-Session-Id}"})
        assert out["sid"] == "session-task"
    finally:
        _ms._captured_incoming_headers.reset(cap_tok)
        policy_proxy._incoming_headers.reset(hdr_tok)


def test_resolve_injections_leaves_template_when_no_headers_and_no_client():
    """With no headers and no client info the template stays verbatim."""
    from gateway import mounted_server as _ms

    hdr_tok = policy_proxy._incoming_headers.set(None)
    cap_tok = _ms._captured_incoming_headers.set(None)
    key_tok = _ms._current_session_key.set("")
    ci_tok = policy_proxy._client_info.set(None)
    try:
        out = policy_proxy.resolve_injections({"sid": "${request_header:Mcp-Session-Id}"})
        assert out["sid"] == "${request_header:Mcp-Session-Id}"
    finally:
        policy_proxy._client_info.reset(ci_tok)
        _ms._current_session_key.reset(key_tok)
        _ms._captured_incoming_headers.reset(cap_tok)
        policy_proxy._incoming_headers.reset(hdr_tok)


def test_headerless_client_session_synthesized_from_client_ip():
    """Stateless/browser clients send no session headers: synthesize a stable id.

    Regression: on the /mcp/browser compound (stateless=True) no
    ``Mcp-Session-Id`` is ever issued or echoed, so
    ``${request_header:Mcp-Session-Id}`` stayed the literal template — ipybox
    minted a fresh kernel per call and the confirm gate showed
    ``Session: ${request_header:Mcp-Session-Id}``. The effective headers must
    carry a stable per-client id instead.
    """
    from gateway import mounted_server as _ms

    hdr_tok = policy_proxy._incoming_headers.set(None)
    cap_tok = _ms._captured_incoming_headers.set(None)
    key_tok = _ms._current_session_key.set("")
    ci_tok = policy_proxy._client_info.set(
        policy_proxy.ClientInfo(ip="172.18.0.1", host="U2-2010")
    )
    try:
        assert policy_proxy._incoming_headers_effective() == {
            "Mcp-Session-Id": "clientip-172-18-0-1"
        }
        out = policy_proxy.resolve_injections(
            {"kernel_env": {"MCP_SESSION_ID": "${request_header:Mcp-Session-Id}"}}
        )
        assert out["kernel_env"]["MCP_SESSION_ID"] == "clientip-172-18-0-1"
        assert policy_proxy._captured_session_id() == "clientip-172-18-0-1"
    finally:
        policy_proxy._client_info.reset(ci_tok)
        _ms._current_session_key.reset(key_tok)
        _ms._captured_incoming_headers.reset(cap_tok)
        policy_proxy._incoming_headers.reset(hdr_tok)


def test_headerless_client_session_never_overrides_real_session():
    """A genuine session header always wins over the synthesized client id."""
    hdr_tok = policy_proxy._incoming_headers.set({"Mcp-Session-Id": "real-session"})
    ci_tok = policy_proxy._client_info.set(
        policy_proxy.ClientInfo(ip="172.18.0.1", host="U2-2010")
    )
    try:
        assert policy_proxy._incoming_headers_effective() == {
            "Mcp-Session-Id": "real-session"
        }
        assert policy_proxy._captured_session_id() == "real-session"
    finally:
        policy_proxy._client_info.reset(ci_tok)
        policy_proxy._incoming_headers.reset(hdr_tok)


def test_capture_incoming_headers_respects_allowlist():
    """Only allowlisted header names are captured (no accidental secret capture)."""
    from gateway import mounted_server as _ms

    prev = _ms._incoming_header_capture
    _ms.set_incoming_header_capture(["Mcp-Session-Id"])
    try:
        captured = _ms._capture_incoming_headers({
            "Mcp-Session-Id": "s1",
            "Authorization": "Bearer secret",
            "X-Skill-Bypass": "token",
        })
        assert captured == {"Mcp-Session-Id": "s1"}
    finally:
        _ms.set_incoming_header_capture(prev)


def test_capture_incoming_headers_case_insensitive_and_canonical():
    """A lower-cased inbound header is captured under the canonical policy name."""
    from gateway import mounted_server as _ms

    prev = _ms._incoming_header_capture
    _ms.set_incoming_header_capture(["Mcp-Session-Id", "X-Skill-Bypass"])
    try:
        assert _ms._capture_incoming_headers({"mcp-session-id": "s2"}) == {
            "Mcp-Session-Id": "s2"
        }
        # Nothing captured → None, so callers leave the middleware value alone.
        assert _ms._capture_incoming_headers({"Accept": "application/json"}) is None
        assert _ms._capture_incoming_headers(None) is None
    finally:
        _ms.set_incoming_header_capture(prev)


def test_temp_allow_active_arm_and_expire():
    """Armed temp allowances are active until they expire, then dropped."""

    key = ("ip|sess-1", "gitlab", 0)
    policy_proxy._temp_allowances[key] = time.monotonic() + 60
    assert policy_proxy._temp_allow_active(key) is True
    # Expired entry → inactive,and removed.

    policy_proxy._temp_allowances[key] = time.monotonic() - 1

    assert policy_proxy._temp_allow_active(key) is False
    assert key not in policy_proxy._temp_allowances
    # Unknown key → inactive (no crash).
    assert policy_proxy._temp_allow_active(("ip|nope", "gitlab", 0)) is False
    policy_proxy._temp_allowances.clear()


def test_confirm_branch_bypasses_when_allowance_active():
    """An armed 1-minute session allowance short-circuits a confirm rule: the
    call forwards without asking the operator and without creating a PendingRequest."""
    bc = policy_proxy.BackendConfig(name="gitlab", url="http://gitlab/mcp", transport="http")
    status = policy_proxy.BackendStatus(name="gitlab", healthy=True)
    rules = [
        {"match": {"tool": ".*", "repo": ".*"}, "action": "confirm"},
    ]
    forwarded = []

    async def fake_forward(bc, tool_name, arguments):
        forwarded.append((tool_name, arguments))
        return {"content": ["bypassed-ok"], "structuredContent": None, "isError": False}

    orig_forward = policy_proxy.forward
    t_cli = None
    t_hdr = None
    try:
        policy_proxy.forward = fake_forward
        t_cli = policy_proxy._client_info.set(policy_proxy.ClientInfo(ip="1.2.3.4", host="h"))
        t_hdr = policy_proxy._incoming_headers.set({"Mcp-Session-Id": "sess-1"})

        key = policy_proxy._allowance_key(policy_proxy.ClientInfo(ip="1.2.3.4", host="h"), "gitlab", 0)
        policy_proxy._temp_allowances[key] = time.monotonic() + 60

        handler = policy_proxy.make_policy_handler(bc, rules, "git", status)
        out = asyncio.run(handler(repo="x"))

        # Bypassed: forwarded once, no pending request left, no confirm templates exposed.

        assert forwarded == [("git", {"repo": "x"})]
        assert "bypassed-ok" in out
        assert policy_proxy._pending_requests == {}
    finally:
        policy_proxy.forward = orig_forward
        policy_proxy._client_info.reset(t_cli)
        policy_proxy._incoming_headers.reset(t_hdr)
        policy_proxy._temp_allowances.clear()
        policy_proxy._pending_requests.clear()


# ---------------------------------------------------------------------------
# Regression test for the 2026-09-08 Telegram 404-spam bug.
#
# With an empty/wrong bot token, getUpdates returns 404 forever. The poll
# loop used to log a warning and keep spamming api.telegram.org every 3s
# indefinitely (masking real errors and burning requests). It must instead
# detect the permanent 401/404 and stop.
# ---------------------------------------------------------------------------

import asyncio
from unittest.mock import patch

import httpx


class _MockTransport(httpx.BaseTransport):
    """Return a fixed non-200 for every getUpdates call."""

    def __init__(self, status_code: int):
        self.status_code = status_code
        self.calls = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._respond(request)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return self._respond(request)

    def _respond(self, request: httpx.Request) -> httpx.Response:
        body = b""
        if self.status_code == 404:
            body = b'{"ok":false,"error_code":404,"description":"Not Found"}'
        elif self.status_code == 401:
            body = b'{"ok":false,"error_code":401,"description":"Unauthorized"}'
        return httpx.Response(self.status_code, content=body, request=request)


@pytest.mark.asyncio
async def test_telegram_poll_loop_stops_on_404():
    """A permanent 404 must stop the poll loop, not spam forever."""
    backend = policy_proxy.TelegramBackend(bot_token="bad-token", chat_id="123")
    backend._client = httpx.AsyncClient(transport=_MockTransport(404), timeout=10.0)

    # Run the loop; it should stop itself after the first 404, not spin.
    await asyncio.wait_for(backend.poll_loop(), timeout=5.0)

    assert backend._token_error is True
    assert backend._running is False
    # Only a handful of requests (the one that failed), not an unbounded stream.
    assert backend._client._transport.calls <= 2


@pytest.mark.asyncio
async def test_telegram_poll_loop_stops_on_401():
    """A permanent 401 must also stop the poll loop."""
    backend = policy_proxy.TelegramBackend(bot_token="bad-token", chat_id="123")
    backend._client = httpx.AsyncClient(transport=_MockTransport(401), timeout=10.0)

    await asyncio.wait_for(backend.poll_loop(), timeout=5.0)

    assert backend._token_error is True
    assert backend._running is False
# ---------------------------------------------------------------------------
# Startup wiring contract tests — prevent signature drift between
# install_telegram_tools() and its call site in lifespan().
# ---------------------------------------------------------------------------

def test_install_telegram_tools_signature():
    """install_telegram_tools must accept exactly (server, backend).

    If a contributor adds/removes a parameter to install_telegram_tools
    but forgets to update the call site in policy_proxy.lifespan, this test
    fails — instead of discovering it via a crash-looping container.
    """
    import inspect

    from gateway.telegram_mcp import install_telegram_tools

    sig = inspect.signature(install_telegram_tools)
    params = list(sig.parameters.values())
    assert len(params) == 2, (
        f"install_telegram_tools now takes {len(params)} params "
        f"({[p.name for p in params]}); update the call site in "
        "policy_proxy.lifespan AND this test"
    )
    assert params[0].name == "server"
    assert params[1].name == "backend"


def test_telegram_mount_registered_before_starlette_construction():
    """Regression: the /mcp/telegram Mount must be added to all_routes BEFORE
    Starlette(routes=all_routes) is constructed.

    Starlette's Router copies the routes list (self.routes = list(routes)), so
    a Mount appended inside lifespan() — after construction — never takes
    effect and /mcp/telegram silently 404s. This test fails if anyone moves
    the install_telegram_tools/Mount wiring back below the Starlette(...) call.
    """
    import inspect

    from gateway import policy_proxy

    src = inspect.getsource(policy_proxy.main)
    install_pos = src.find("install_telegram_tools(")
    mount_pos = src.find('"/mcp/telegram"')
    starlette_pos = src.find("starlette_app = Starlette(routes=all_routes)")
    assert install_pos != -1, "install_telegram_tools call vanished from main()"
    assert mount_pos != -1, 'Mount("/mcp/telegram", ...) vanished from main()'
    assert starlette_pos != -1, "Starlette construction vanished from main()"
    assert install_pos < starlette_pos and mount_pos < starlette_pos, (
        "telegram install/Mount wiring must appear BEFORE "
        "Starlette(routes=all_routes) in main() — Router copies the routes "
        "list, so appending inside lifespan() silently 404s /mcp/telegram"
    )


def test_lifespan_starts_telegram_http_manager():
    """The telegram server's StreamableHTTP session manager must be started
    in lifespan together with the other mounted servers.

    Without _http_manager.run() being entered for tg_server, requests to
    /mcp/telegram fail with "Task group is not initialized. Make sure to use
    run()." even when the route itself is registered correctly.
    """
    import inspect

    from gateway import policy_proxy

    src = inspect.getsource(policy_proxy.main)
    lines = src.splitlines()
    idx = next(
        i for i, l in enumerate(lines)
        if "enter_async_context(server._http_manager.run())" in l
    )
    for_line = next(
        l.strip() for l in reversed(lines[:idx])
        if l.strip().startswith("for server in")
    )
    assert "tg_server" in for_line, (
        "the lifespan _http_manager.run() loop must include tg_server — "
        "otherwise /mcp/telegram requests fail with 'Task group is not "
        "initialized'"
    )


def test_poll_loop_ask_dispatch_is_per_update():
    """The generic-ask dispatch must run per update INSIDE the update loop.

    Previously the ask/message dispatch sat AFTER `for update in updates:` and
    read the last update's `cq`/`update`, which (a) raised
    UnboundLocalError('cq') on idle polls with an empty update batch, (b) only
    processed message replies when the LAST update wasn't a callback, and
    (c) re-dispatched ask callbacks that were already handled in-loop.
    """
    import inspect

    from gateway import policy_proxy

    src = inspect.getsource(policy_proxy.TelegramBackend.poll_loop)
    lines = src.splitlines()
    for_idx = next(i for i, l in enumerate(lines) if "for update in updates:" in l)
    loop_indent = len(lines[for_idx]) - len(lines[for_idx].lstrip())
    body_indent = loop_indent + 4
    ask_idx = next(i for i, l in enumerate(lines) if "_try_ask_message" in l)
    assert ask_idx > for_idx, "_try_ask_message dispatch missing from poll_loop"
    assert (len(lines[ask_idx]) - len(lines[ask_idx].lstrip())) == body_indent, (
        "_try_ask_message dispatch must be inside the update loop (body indent)"
    )
    assert not any("_try_ask_message" in l for l in lines[ask_idx + 1:]), (
        "duplicate post-loop ask dispatch — callbacks would be double-dispatched"
    )
    assert "if not cq:" not in src, (
        "post-loop 'if not cq:' block is back — that reads the last update's "
        "cq and raises UnboundLocalError on idle polls"
    )


# ---------------------------------------------------------------------------
# Debug hint: how to read ExceptionGroup tracebacks from lifespan failures
# ---------------------------------------------------------------------------

def test_exceptiongroup_debug_hint_documented():
    """Document the debugging lesson: the REAL error is the innermost exception.

    When lifespan wiring raises, the MCP SDK's StreamableHTTPSessionManager
    wraps it in an ExceptionGroup whose outer frames point at upstream code
    (mcp.server.streamable_http_manager, anyio, contextlib). Grep the traceback
    for the LAST traceback in the group — that's where the actual bug lives.
    """
    # This test exists as living documentation of the debugging approach.
    # The actual validation is that the other two tests above catch the
    # problem before it reaches production.
   


# ---------------------------------------------------------------------------
# Per-rule notify_template for Telegram approval messages
# ---------------------------------------------------------------------------

def _run_confirm_capture(notify_rule=None, global_template="", tool="demo_push", args=None):
    captured = {}
    bc = policy_proxy.BackendConfig(name="demo", url="http://demo/mcp", transport="http")
    status = policy_proxy.BackendStatus(name="demo", healthy=True)
    rule = {"match": {"tool": ".*"}, "action": "confirm", "timeout": 30}
    if notify_rule is not None:
        rule["notify_template"] = notify_rule
    rules = [rule]

    class CapBackend:
        async def send_approval_request(self, **kw):
            captured.update(kw)
            return True

        async def edit_request_timeout(self, request_id):
            pass

    orig_tg = policy_proxy._telegram_backend
    orig_forward = policy_proxy.forward
    orig_cfg = policy_proxy._notification_config

    async def fake_forward(bc, tool_name, arguments):
        return {"content": ["ok"], "structuredContent": None, "isError": False}

    async def scenario():
        policy_proxy._telegram_backend = CapBackend()
        policy_proxy.forward = fake_forward
        policy_proxy._notification_config = policy_proxy.NotificationConfig(
            timeout=30, telegram_template=global_template)
        handler = policy_proxy.make_policy_handler(bc, rules, tool, status)
        task = asyncio.create_task(handler(**(args or {})))
        for _ in range(500):
            if policy_proxy._pending_requests:
                break
            await asyncio.sleep(0.01)
        assert policy_proxy._pending_requests, "confirm never created a pending request"
        _rid, pending = next(iter(policy_proxy._pending_requests.items()))
        pending.approved = True
        pending.event.set()
        return await task

    try:
        out = asyncio.run(scenario())
    finally:
        policy_proxy._telegram_backend = orig_tg
        policy_proxy.forward = orig_forward
        policy_proxy._notification_config = orig_cfg
        policy_proxy._pending_requests.clear()
    return captured, out


def test_notify_template_per_rule_wins():
    cap, _ = _run_confirm_capture(
        notify_rule="push ${args.remote} ${args.branch} (${backend}/${tool})",
        global_template="GLOBAL ${tool}",
        args={"remote": "origin", "branch": "feature/x"},
    )
    assert cap["notify_text"] == "push origin feature/x (demo/demo_push)"


def test_notify_template_global_fallback():
    cap, _ = _run_confirm_capture(
        global_template="GLOBAL ${tool} :: ${reason}",
        args={},
    )
    assert cap["notify_text"] == "GLOBAL demo_push :: Operator declined"


def test_notify_default_empty_when_no_template():
    cap, _ = _run_confirm_capture(args={"remote": "origin"})
    assert cap["notify_text"] == ""


def test_notify_verbatim_body_sent():
    sent = {}
    be = policy_proxy.TelegramBackend("tok", "123")

    class StubResp:
        status_code = 200
        text = "ok"

        def json(self):
            return {"ok": True, "result": {"message_id": 1, "chat": {"id": 123}}}

    class StubClient:
        async def post(self, url, json=None):
            sent.update(json or {})
            return StubResp()

    async def scenario():
        await be._client.aclose()
        be._client = StubClient()
        return await be.send_approval_request(
            "r1", "demo_push", {"a": "b"}, None, "why",
            backend_name="demo", session_id="", notify_text="CUSTOM BODY")

    ok = asyncio.run(scenario())
    assert ok is True
    assert sent["text"] == "CUSTOM BODY"


def test_validate_accepts_notify_template(tmp_path):
    p = tmp_path / "demo.yaml"
    p.write_text(
        'backend:\n  name: demo\nrules:\n'
        '  - match:\n      tool: ".*"\n    action: confirm\n'
        '    notify_template: "push ${args.branch} (${backend}/${tool})"\n'
        '  - match:\n      tool: ".*"\n    action: deny\n    reason: "no"\n'
    )
    assert validate_policy.validate_policy(str(p)) is True
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# confirm-hard (bypass-proof) — kanban t_ccc3cf8a.
# The X-Skill-Bypass token and the operator session allowance must NOT
# short-circuit a confirm-hard rule; a timed-out confirm-hard wait returns
# the typed awaiting_approval outcome instead of an error or a hang.
# ---------------------------------------------------------------------------


def test_skill_bypass_skips_confirm_but_not_confirm_hard(monkeypatch):
    """With a valid X-Skill-Bypass token on /mcp/skills a `confirm` rule
    awaiting_approval result without running the call."""
    token = "sekrit-bypass-token"
    monkeypatch.setenv("SKILLS_BYPASS_TOKEN", token)
    bc = policy_proxy.BackendConfig(name="skills-ipybox", url="http://skills/mcp", transport="http")
    status = policy_proxy.BackendStatus(name="skills-ipybox", healthy=True)
    forwarded = []

    async def fake_forward(bc, tool_name, arguments):
        forwarded.append(tool_name)
        return {"content": ["written"], "structuredContent": {"ok": True}, "isError": False}

    class FakeTG:
        async def send_approval_request(self, **kw):
            return True

        async def edit_request_timeout(self, request_id):
            return None

    orig_forward = policy_proxy.forward
    orig_tg = policy_proxy._telegram_backend
    t_cli = t_path = t_hdr = None
    try:
        policy_proxy.forward = fake_forward
        policy_proxy._telegram_backend = FakeTG()
        t_cli = policy_proxy._client_info.set(policy_proxy.ClientInfo(ip="10.0.0.1", host="h"))
        t_path = policy_proxy._request_path.set("/mcp/skills")
        t_hdr = policy_proxy._incoming_headers.set({"X-Skill-Bypass": token})

        # (1) plain confirm + bypass token -> allowed, no human asked
        h = policy_proxy.make_policy_handler(
            bc, [{"match": {"tool": ".*"}, "action": "confirm"}], "run_skill", status)
        asyncio.run(h(name="probe"))
        assert forwarded == ["run_skill"]
        assert policy_proxy._pending_requests == {}

        # (2) confirm-hard + the SAME token -> waits, then typed non-error
        h = policy_proxy.make_policy_handler(
            bc, [{"match": {"tool": ".*"}, "action": "confirm-hard", "timeout": 1}],
            "write_playbook_script", status)
        out = asyncio.run(h(name="p", filename="a.py", content="c"))
        assert forwarded == ["run_skill"]  # the write did NOT run
        sc = out.structuredContent
        assert sc is not None and sc.get("status") == "awaiting_approval"
        assert sc.get("resolved") is False and sc.get("tool") == "write_playbook_script"
        assert out.isError is False
        assert policy_proxy._pending_requests == {}
    finally:
        policy_proxy.forward = orig_forward
        policy_proxy._telegram_backend = orig_tg
        if t_cli is not None:
            policy_proxy._client_info.reset(t_cli)
        if t_path is not None:
            policy_proxy._request_path.reset(t_path)
        if t_hdr is not None:
            policy_proxy._incoming_headers.reset(t_hdr)
        policy_proxy._pending_requests.clear()


def test_confirm_hard_ignores_session_allowance(monkeypatch):
    """An armed operator session allowance auto-approves a plain `confirm`
    rule but never a `confirm-hard` one."""
    monkeypatch.delenv("SKILLS_BYPASS_TOKEN", raising=False)
    bc = policy_proxy.BackendConfig(name="skills-ipybox", url="http://skills/mcp", transport="http")
    status = policy_proxy.BackendStatus(name="skills-ipybox", healthy=True)
    forwarded = []

    async def fake_forward(bc, tool_name, arguments):
        forwarded.append(tool_name)
        return {"content": ["ok"], "structuredContent": None, "isError": False}

    class FakeTG:
        async def send_approval_request(self, **kw):
            return True

        async def edit_request_timeout(self, request_id):
            return None

    orig_forward = policy_proxy.forward
    orig_tg = policy_proxy._telegram_backend
    orig_allow = dict(policy_proxy._temp_allowances)
    t_cli = t_hdr = None
    try:
        policy_proxy.forward = fake_forward
        policy_proxy._telegram_backend = FakeTG()
        info = policy_proxy.ClientInfo(ip="10.0.0.1", host="h")
        t_cli = policy_proxy._client_info.set(info)
        t_hdr = policy_proxy._incoming_headers.set({"Mcp-Session-Id": "sess-1"})
        key = policy_proxy._allowance_key(info, "skills-ipybox", 0)
        policy_proxy._temp_allowances[key] = time.monotonic() + 60

        # plain confirm: the allowance short-circuits it
        h = policy_proxy.make_policy_handler(
            bc, [{"match": {"tool": ".*"}, "action": "confirm"}], "run_skill", status)
        asyncio.run(h(name="probe"))
        assert forwarded == ["run_skill"]

        # confirm-hard: the same allowance is refused -> waits, typed outcome
        h = policy_proxy.make_policy_handler(
            bc, [{"match": {"tool": ".*"}, "action": "confirm-hard", "timeout": 1}],
            "write_skill_md", status)
        out = asyncio.run(h(name="p", content="c"))
        assert forwarded == ["run_skill"]  # not forwarded
        sc = out.structuredContent
        assert sc is not None and sc.get("status") == "awaiting_approval"
        assert out.isError is False
    finally:
        policy_proxy.forward = orig_forward
        policy_proxy._telegram_backend = orig_tg
        if t_cli is not None:
            policy_proxy._client_info.reset(t_cli)
        if t_hdr is not None:
            policy_proxy._incoming_headers.reset(t_hdr)
        policy_proxy._temp_allowances.clear()
        policy_proxy._temp_allowances.update(orig_allow)
        policy_proxy._pending_requests.clear()


def test_confirm_hard_hides_allow10_button():
    """The Telegram keyboard for a confirm-hard ask offers Approve/Reject
    only - no Allow-10-min button (that grant would be dead weight)."""
    import json as _json
    sent = {}

    class StubResp:
        status_code = 200
        text = "ok"

        def json(self):
            return {"ok": True, "result": {"message_id": 1, "chat": {"id": 123}}}

    class StubClient:
        async def post(self, url, json=None):
            sent.update(json or {})
            return StubResp()

    async def scenario():
        be = policy_proxy.TelegramBackend("tok", "123")
        await be._client.aclose()
        be._client = StubClient()
        ok = await be.send_approval_request(
            "r1", "write_playbook_script", {"a": "b"}, None, "why",
            backend_name="skills-ipybox", session_id="sess-1", notify_text="",
            allow_session_grant=False)
        hard_kb = _json.loads(sent["reply_markup"])
        ok2 = await be.send_approval_request(
            "r2", "write_playbook_script", {"a": "b"}, None, "why",
            backend_name="skills-ipybox", session_id="sess-1", notify_text="")
        normal_kb = _json.loads(sent["reply_markup"])
        return ok, hard_kb, ok2, normal_kb

    ok, hard_kb, ok2, normal_kb = asyncio.run(scenario())
    hard_data = [b["callback_data"] for b in hard_kb["inline_keyboard"][0]]
    normal_data = [b["callback_data"] for b in normal_kb["inline_keyboard"][0]]
    assert ok is True and ok2 is True
    assert any(d.startswith("approve:") for d in hard_data)
    assert any(d.startswith("reject:") for d in hard_data)
    assert not any(d.startswith("allow1m:") for d in hard_data)
    assert any(d.startswith("allow1m:") for d in normal_data)


def test_validate_policy_accepts_confirm_hard(tmp_path):
    """validate_policy must recognise confirm-hard as a known action - an
    unknown action would warn treated-as-allow."""
    p = tmp_path / "hard.yaml"
    rows = [
        "backend:",
        "  name: demo",
        "  url: http://demo/mcp",
        "rules:",
        "  - match:",
        "      tool: .*",
        "    action: confirm-hard",
        "",
    ]
    p.write_text(chr(10).join(rows))
    assert validate_policy.validate_policy(str(p)) is True


def test_unknown_action_is_denied_not_allowed():
    """The catch-all for an unrecognised action is DENY, not allow.
    
    Policy YAML is a live bind mount while the gateway image is not, so an
    action the running gateway does not know (a typo, or a newer action such
    as confirm-hard deployed before its gateway) must fail CLOSED. It used
    to mean allow, which silently made such a rule bypass-free.
    """
    bc = policy_proxy.BackendConfig(name="demo", url="http://demo/mcp", transport="http")
    status = policy_proxy.BackendStatus(name="demo", healthy=True)
    forwarded = []

    async def fake_forward(bc, tool_name, arguments):
        forwarded.append(tool_name)
        return {"content": ["ran"], "structuredContent": None, "isError": False}

    orig_forward = policy_proxy.forward
    try:
        policy_proxy.forward = fake_forward

        # Unknown action -> denied, NOT forwarded.
        h = policy_proxy.make_policy_handler(
            bc, [{"match": {"tool": ".*"}, "action": "confim-hard"}], "dangerous", status)
        out = asyncio.run(h(a=1))
        assert forwarded == [], "unknown action must not forward"
        assert out.isError is True
        assert "ACCESS DENIED" in out.content[0].text

        # Explicit allow still works (it must not rely on the catch-all).
        h = policy_proxy.make_policy_handler(
            bc, [{"match": {"tool": ".*"}, "action": "allow"}], "safe", status)
        asyncio.run(h(a=1))
        assert forwarded == ["safe"]
    finally:
        policy_proxy.forward = orig_forward
