#!/usr/bin/env python3
"""
mcp_policy_proxy.start — Container entrypoint that reproduces start.sh behavior.

Starts the background MCP server processes (k8s, netbox, foxmcp, skills), then
runs the policy proxy in the foreground:

  1. Read env vars (POLICY_DIR, KUBECONFIG_PATH, POLICY_PROXY_PORT, ...)
  2. Validate policies if a VALIDATE_POLICY_PATH file is present
  3. Start background MCP servers (skills via the `skills-server` console
     script from the skills-server pip package)
  4. Run a watchdog that restarts dead background servers
  5. Start the policy proxy (foreground) via ``mcp_policy_proxy.policy_proxy.main()``
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional

log = logging.getLogger("policy-proxy-start")


def _env(key: str, default: str) -> str:
    """Read an env var with a default."""
    return os.environ.get(key, default)


def _build_mcp_servers(kubeconfig_path: str) -> List[Dict[str, str]]:
    """Build the list of background MCP servers (name/port/cmd/args)."""
    servers = []
    python = sys.executable

    # k8s — started only if kubeconfig exists
    if os.path.exists(kubeconfig_path):
        servers.append({
            "name": "k8s",
            "port": "9001",
            "cmd": "kubernetes-mcp-server",
            "args": ["--port", "9001", "--kubeconfig", kubeconfig_path],
        })
    else:
        log.warning("Kubeconfig not found at %s, skipping k8s MCP server", kubeconfig_path)

    # netbox — reads NETBOX_URL + NETBOX_TOKEN from environment
    servers.append({
        "name": "netbox",
        "port": "9004",
        "cmd": "netbox-mcp-server",
        "args": ["--transport", "http", "--port", "9004", "--host", "0.0.0.0"],
    })

    # foxmcp — vendored server in this package (WebSocket for extension + MCP)
    servers.append({
        "name": "foxmcp",
        "port": "9005",
        "cmd": python,
        "args": ["-m", "mcp_policy_proxy.foxmcp_server", "--mcp-port", "9005", "--ws-port", "8765"],
    })

    # skills — from the skills-server pip package (console script)
    skills_cmd = shutil.which("skills-server") or "skills-server"
    servers.append({
        "name": "skills",
        "port": "9002",
        "cmd": skills_cmd,
        "args": ["--port", "9002", "--host", "0.0.0.0"],
    })

    return servers


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
            from mcp_policy_proxy.validate_policy import validate_policy as vp
            valid = vp(full_path)
            if not valid:
                log.warning("Validation had warnings for %s", policy_file)
        except Exception as e:
            log.warning("Validation failed for %s: %s", policy_file, e)


class ServerProcess:
    """A background MCP server subprocess with a name/port for logging."""

    def __init__(self, name: str, port: str, cmd: str, args: List[str]):
        self.name = name
        self.port = port
        self.cmd = cmd
        self.args = args
        self.proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            return  # already running
        log.info("Starting %s MCP server on :%s (%s %s)...", self.name, self.port, self.cmd, " ".join(self.args))
        try:
            self.proc = subprocess.Popen(
                [self.cmd] + self.args,
                stdout=subprocess.DEVNULL if os.environ.get("MCP_SERVER_LOG") != "1" else None,
                stderr=None,
            )
        except FileNotFoundError as e:
            log.error("Could not start %s: binary '%s' not found — is it installed?", self.name, self.cmd)
            self.proc = None
            return
        # brief check: verify process is still alive after start
        time.sleep(1)
        if self.proc.poll() is not None:
            log.warning("%s MCP server died immediately after start", self.name)
            self.proc = None

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            log.info("Stopping %s MCP server...", self.name)
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def start_background_servers(servers: List[ServerProcess]) -> None:
    """Start all background MCP servers."""
    for s in servers:
        s.start()


def run_watchdog(servers: List[ServerProcess], stop_event) -> None:
    """Restart any dead background server processes."""
    while not stop_event.is_set():
        time.sleep(5)
        for s in servers:
            if not s.is_alive() and not stop_event.is_set():
                log.warning("Watchdog: %s MCP server died, restarting...", s.name)
                s.start()


async def run_proxy_forever() -> None:
    """Start the policy proxy (blocking foreground process)."""
    from mcp_policy_proxy import policy_proxy
    await policy_proxy.main()


def main() -> int:
    """Entrypoint: start background MCP servers, watchdog, then the proxy."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    log.info("=== MCP Gateway Starting ===")

    # ------------------------------------------------------------------
    # Configuration (override via environment variables)
    # ------------------------------------------------------------------
    policy_dir = _env("POLICY_DIR", "/etc/mcp-gateways/policy")
    kubeconfig_path = _env("KUBECONFIG_PATH", "/root/.kube/k3s.yaml")
    proxy_port = _env("POLICY_PROXY_PORT", "8000")
    proxy_host = _env("POLICY_PROXY_HOST", "0.0.0.0")
    validate_policy_path = _env("VALIDATE_POLICY_PATH", "/opt/validate_policy.py")

    # ------------------------------------------------------------------
    # Step 1: Validate policy files (warnings only)
    # ------------------------------------------------------------------
    validate_policies(policy_dir, validate_policy_path)

    # ------------------------------------------------------------------
    # Step 2: Start background MCP servers
    # ------------------------------------------------------------------
    server_specs = _build_mcp_servers(kubeconfig_path)
    servers = [ServerProcess(s["name"], int(s["port"]), s["cmd"], s["args"]) for s in server_specs]
    start_background_servers(servers)

    # Give servers time to initialize before starting proxy
    time.sleep(2)

    # ------------------------------------------------------------------
    # Step 3: Start generic watchdog for background MCP servers
    # ------------------------------------------------------------------
    import threading
    stop_event = threading.Event()
    watchdog_thread = None
    watchdog_thread = threading.Thread(
        target=run_watchdog, args=(servers, stop_event), daemon=True
    )
    watchdog_thread.start()
    log.info("Watchdog started")

    # ------------------------------------------------------------------
    # Step 4: Start Policy Proxy (foreground process)
    # ------------------------------------------------------------------
    log.info("Starting Policy Proxy on %s:%s...", proxy_host, proxy_port)
    try:
        asyncio.run(run_proxy_forever())
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        if watchdog_thread is not None:
            watchdog_thread.join(timeout=2)
        for s in servers:
            s.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())