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

import mcp_gateway  # noqa: E402
from mcp_gateway import mounted_server  # noqa: E402
from mcp_gateway import policy_proxy  # noqa: E402
from mcp_gateway import policy_yaml  # noqa: E402
from mcp_gateway import validate_policy  # noqa: E402


def test_package_imports():
    """All core modules import cleanly."""
    assert mcp_gateway.__version__ == "0.1.0"
    assert mcp_gateway.policy_proxy is policy_proxy
    assert hasattr(mcp_gateway.policy_proxy, "load_all_policies")
    assert hasattr(mcp_gateway.policy_proxy, "MountedServer") or hasattr(
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
    from mcp_gateway import start

    # No kubeconfig -> skip k8s
    servers = start._build_mcp_servers("/nonexistent/kubeconfig")
    names = [s["name"] for s in servers]
    assert "k8s" not in names
    assert "netbox" in names
    assert "foxmcp" in names
    assert "skills" in names

    # skills cmd is resolved via shutil.which (may be None on bare CI)
    skills_srv = next(s for s in servers if s["name"] == "skills")
    assert skills_srv["port"] == "9002"


def test_start_main_entrypoint_registered():
    """The console script references mcp_gateway.start.main."""
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
    assert matching[0].value == "mcp_gateway.start:main"