#!/usr/bin/env python3
"""
exec_mcp_server — Unified execution backend for the gateway.

A tiny FastMCP stdio server exposing a single ``run`` tool that executes
arbitrary commands via ``subprocess.run``.  Credential environment variables
(SSH_USER, SSH_KEY_PATH, KUBECONFIG, etc.) are injected by the gateway
policy layer — this server reads nothing sensitive on its own.

The ``binary`` argument is the first element of ``command`` and exists
purely so that policy rules can match on a flat string field rather than
a list index (which ``_get_nested`` does not support).

Run modes:
  - stdin/stdout (stdio)          — default, used by the gateway proxy
  - python exec_mcp_server.py     — runs as a stdio child of policy_proxy
"""

import os
import shlex
import subprocess
from typing import Any, Dict, List, Optional

try:
    from fastmcp import FastMCP
except ImportError:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

mcp = FastMCP("exec")


@mcp.tool()
async def run(
    command: List[str],
    binary: str,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
    timeout: int = 60,
    stdin: Optional[str] = None,
) -> str:
    """
    Run a command with optional environment and timeout.

    Args:
        command: Full command as a list of strings (the argv vector).
        binary: The first element of *command* — the binary name.  Provided
            as a separate field so that the gateway policy can match on
            it with a simple regex (list indexing in match fields is not
            supported by the policy engine).
        env: Extra environment variables to merge into the subprocess
            environment (merged on top of os.environ).
        cwd: Working directory for the subprocess.
        timeout: Maximum execution time in seconds.
        stdin: Optional string piped to the subprocess stdout.

    Returns:
        Combined stdout + stderr (stdout first, separated by a header).
    """
    env = env or {}
    run_env = os.environ.copy()
    run_env.update(env)

    try:
        proc = subprocess.run(
            command,
            env=run_env,
            cwd=cwd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = proc.stdout
        if proc.stderr:
            output += "\n--- stderr ---\n" + proc.stderr
        return output
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return f"Error: binary '{binary}' not found"
    except Exception as e:
        return f"Error: {e}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
