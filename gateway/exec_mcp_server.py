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
import subprocess
from typing import Any, Dict, List, Optional

try:
    from fastmcp import FastMCP
    from fastmcp.tools.base import ToolResult
except ImportError:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

from mcp.types import TextContent

mcp = FastMCP("exec")


def _exec_result(base, text, ok, error, exit_code, stdout="", stderr="", timed_out=False):
    """Build a ToolResult: human text in ``content``, machine dict in structuredContent."""
    return ToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=dict(
            base,
            ok=ok,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            error=error,
        ),
    )


@mcp.tool()
async def run(
    command: List[str],
    binary: str,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
    timeout: int = 60,
    stdin: Optional[str] = None,
) -> Any:
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
        A FastMCP ToolResult carrying (a) a human-readable text block in
        ``content`` (stdout, then a ``--- stderr ---`` header if any, then
        errors) and (b) a machine-readable payload in ``structuredContent``:
        {ok, exit_code, stdout, stderr, timed_out, error, command, binary}.
        The text stays human-friendly for agents; automation reads the
        structured dict (exposed as structured_content by mcp_call / mcp2cli).
    """
    env = env or {}
    run_env = os.environ.copy()
    run_env.update(env)

    base = {"command": command, "binary": binary}
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
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        text = stdout
        if stderr:
            text += "\n--- stderr ---\n" + stderr
        return _exec_result(
            base, text,
            ok=proc.returncode == 0,
            error=None,
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
        )
    except subprocess.TimeoutExpired as e:
        # Capture any partial output produced before the kill.
        _o, _s = _extract_exc_output(e)
        return _exec_result(
            base,
            f"Command timed out after {timeout}s",
            ok=False, error=f"Command timed out after {timeout}s",
            exit_code=None, stdout=_o, stderr=_s, timed_out=True,
        )
    except FileNotFoundError:
        return _exec_result(
            base,
            f"Error: binary '{binary}' not found",
            ok=False, error=f"binary '{binary}' not found",
            exit_code=None,
        )
    except Exception as exc:
        return _exec_result(
            base,
            f"Error: {exc}",
            ok=False, error=str(exc),
            exit_code=None,
        )


def _extract_exc_output(exc: Any):
    """Best-effort pull partial stdout/stderr from a TimeoutExpired exception."""
    stdout = ""
    stderr = ""
    _o = getattr(exc, "stdout", None) or ""
    _s = getattr(exc, "stderr", None) or ""
    if _o:
        stdout = _o.decode(errors="replace") if isinstance(_o, bytes) else _o
    if _s:
        stderr = _s.decode(errors="replace") if isinstance(_s, bytes) else _s
    return stdout, stderr


if __name__ == "__main__":
    mcp.run(transport="stdio")
