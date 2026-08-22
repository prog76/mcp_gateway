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
    """The start module builds the background MCP server list (no network)."""
    from gateway import start

    # No kubeconfig -> skip k8s
    servers = start._build_mcp_servers("/nonexistent/kubeconfig")
    names = [s["name"] for s in servers]
    assert "k8s" not in names
    assert "netbox" in names
    assert "foxmcp" in names
    # ipybox is NOT a local subprocess — it runs as its own container
    # (http://ipybox:9006) and is health-checked/proxied by the gateway.
    assert "ipybox" not in names
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
