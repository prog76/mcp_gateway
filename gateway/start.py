#!/usr/bin/env python3
"""
gateway.start — Container entrypoint for the policy proxy.

The gateway is a pure policy proxy. Long-running backend MCP servers
(k8s, netbox, browser/secure-fox, ipybox) run as their own containers,
supervised by the orchestrator (docker-compose) — NOT as child processes
of the gateway. Policies reference them by service URL, e.g.
``http://netbox:9004/mcp``.

  1. Read env vars (POLICY_DIR, POLICY_PROXY_PORT, POLICY_PROXY_HOST, ...)
  2. Validate policies if a VALIDATE_POLICY_PATH file is present
  3. Run the policy proxy in the foreground via ``gateway.policy_proxy.main()``

Note: the exec backend (gateway.gateway.exec_mcp_server) is a stdio MCP
server spawned per-request by policy_proxy — that is request-scoped
execution, not daemon supervision, so it remains part of serving a call.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

log = logging.getLogger("mcp-gateway-start")


def _env(key: str, default: str) -> str:
    """Read an env var with a default."""
    return os.environ.get(key, default)


def validate_policies(policy_dir: str, validate_policy_path: str) -> None:
    """Validate each backend policy file (mirrors start.sh Step 1)."""
    log.info("Validating policies in: %s", policy_dir)
    if not os.path.isfile(validate_policy_path):
        log.warning("validate_policy file not found at %s, skipping validation", validate_policy_path)
        return

    if not os.path.isdir(policy_dir):
        log.warning("Policy directory not found at %s", policy_dir)
        return

    for policy_file in sorted(os.listdir(policy_dir)):
        if not policy_file.endswith((".yaml", ".yml")):
            continue
        full_path = os.path.join(policy_dir, policy_file)
        if not os.path.isfile(full_path):
            continue
        log.info("  Validating: %s", full_path)
        try:
            # Import the installed package's validate_policy module.
            from gateway.validate_policy import validate_policy as vp
            valid = vp(full_path)
            if not valid:
                log.warning("Validation had warnings for %s", policy_file)
        except Exception as e:
            log.warning("Validation failed for %s: %s", policy_file, e)


async def run_proxy_forever() -> None:
    """Start the policy proxy (blocking foreground process)."""
    from gateway import policy_proxy
    await policy_proxy.main()


def main() -> int:
    """Entrypoint: validate policies, then run the proxy in the foreground."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    log.info("=== MCP Gateway Starting ===")

    # ------------------------------------------------------------------
    # Configuration (override via environment variables)
    # ------------------------------------------------------------------
    policy_dir = _env("POLICY_DIR", "/etc/mcp-gateways/policy")
    proxy_port = _env("POLICY_PROXY_PORT", "8000")
    proxy_host = _env("POLICY_PROXY_HOST", "0.0.0.0")
    validate_policy_path = _env("VALIDATE_POLICY_PATH", "/opt/validate_policy.py")

    # ------------------------------------------------------------------
    # Step 1: Validate policy files (warnings only)
    # ------------------------------------------------------------------
    validate_policies(policy_dir, validate_policy_path)

    # ------------------------------------------------------------------
    # Step 2: Run Policy Proxy (foreground process)
    # ------------------------------------------------------------------
    log.info("Starting Policy Proxy on %s:%s...", proxy_host, proxy_port)
    try:
        asyncio.run(run_proxy_forever())
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
