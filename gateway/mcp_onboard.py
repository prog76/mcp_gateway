#!/usr/bin/env python3
"""
MCP Onboarding Helper

Generates starter policy YAML files for MCP servers.
Connects to an MCP server, discovers tools, and creates a policy file
with proper structure including per-backend catch-all deny rules.

Usage:
    # From HTTP endpoint
    python mcp_onboard.py --url http://localhost:9001/mcp --output k8s.yaml

    # From stdio command
    python mcp_onboard.py --command "ssh-mcp-server --config /etc/ssh.json" --output ssh.yaml

    # With custom prefix
    python mcp_onboard.py --url http://localhost:9001/mcp --prefix "k8s_" --output k8s.yaml
"""

import argparse
import asyncio
import json
import re
import sys
from typing import List, Optional

import yaml
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp import ClientSession


async def discover_http_tools(url: str, headers: Optional[dict] = None) -> tuple:
    """Connect to HTTP MCP server and list tools."""
    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            server_info = session.server_info if hasattr(session, 'server_info') else {}
            return tools_result.tools, server_info


async def discover_stdio_tools(command: str) -> tuple:
    """Connect to stdio MCP server and list tools."""
    # Parse command into parts
    parts = command.split()
    cmd = parts[0]
    args = parts[1:] if len(parts) > 1 else []

    stdio_params = StdioServerParameters(command=cmd, args=args)

    async with stdio_client(stdio_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            server_info = session.server_info if hasattr(session, 'server_info') else {}
            return tools_result.tools, server_info


def sanitize_name(name: str) -> str:
    """Convert tool/server name to valid YAML key."""
    # Replace special characters with underscores
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
    # Remove leading/trailing underscores
    sanitized = sanitized.strip('_')
    return sanitized.lower()


def extract_parameters(tool) -> dict:
    """Extract parameter information from a tool."""
    params = {}
    if hasattr(tool, 'inputSchema') and tool.inputSchema:
        schema = tool.inputSchema
        if isinstance(schema, dict):
            properties = schema.get('properties', {})
            required = schema.get('required', [])
            for param_name, param_info in properties.items():
                params[param_name] = {
                    'type': param_info.get('type', 'string'),
                    'description': param_info.get('description', ''),
                    'required': param_name in required,
                }
    return params


def generate_policy(
    backend_name: str,
    tools: list,
    server_info: dict,
    prefix: str = "",
    path: str = "",
    url: str = "",
    command: str = "",
    transport: str = "http",
    headers: Optional[dict] = None,
) -> dict:
    """Generate a policy YAML structure from discovered tools."""

    # Build backend config
    backend_config = {
        "name": backend_name,
        "prefix": prefix,
        "path": path or f"/mcp/{backend_name}",
    }

    if transport == "http" and url:
        backend_config["url"] = url
        backend_config["transport"] = "http"
        if headers:
            backend_config["headers"] = headers
    elif command:
        parts = command.split()
        backend_config["transport"] = "stdio"
        backend_config["command"] = parts[0]
        if len(parts) > 1:
            backend_config["args"] = parts[1:]

    # Generate tool documentation — clean flat list of comment lines
    tool_doc_lines = []
    tool_names = []
    for tool in tools:
        tool_names.append(tool.name)
        params = extract_parameters(tool)
        param_strs = []
        for pname, pinfo in params.items():
            req = " (required)" if pinfo.get('required') else ""
            param_strs.append(f"{pname}: {pinfo.get('type', 'string')}{req}")

        # Separator before each tool
        tool_doc_lines.append("#")

        # Split description into lines — prefix each non-blank with "#   "
        desc = (tool.description or 'No description').strip()
        desc_lines = []
        for line in desc.split('\n'):
            stripped = line.strip()
            if not stripped:
                desc_lines.append("#")
            else:
                desc_lines.append(f"#   {stripped}")

        # First line: "- toolname: first_line_of_description"
        first = desc_lines[0] if desc_lines else "#   No description"
        tool_doc_lines.append(f"# - {tool.name}: {first[4:]}")

        # Remaining description lines
        for dl in desc_lines[1:]:
            tool_doc_lines.append(dl)

        # Params line
        if param_strs:
            tool_doc_lines.append(f"#   Params: {', '.join(param_strs)}")

    # Build policy structure
    policy = {
        "backend": backend_config,
        "default_deny": f"{backend_name.capitalize()} operation '${{tool}}' denied. No matching policy rule. Contact your operator for access.",
        "rules": [
            {
                "match": {
                    "tool": ".*"
                },
                "action": "deny",
                "reason": "${default_deny}"
            }
        ]
    }

    # Build header as flat list of comment lines
    header_lines = [
        f"# {backend_name.capitalize()} Backend Policy",
        "# Auto-generated by mcp_onboard.py",
        "#",
        f"# Server: {server_info.get('name', 'Unknown')}",
        f"# Version: {server_info.get('version', 'Unknown')}",
        f"# Transport: {transport}",
        f"# Tools discovered: {len(tools)}",
        "#",
        "# Discovered tools:",
    ]
    header_lines.extend(tool_doc_lines)
    header_lines.extend([
        "#",
        "# Available templates: ${tool}, ${args.field}, ${clientHost}, ${clientIp}",
        "#   ${clientHost} — reverse-DNS hostname of the calling client (falls back to IP)",
        "#   ${clientIp}   — IP address of the calling client",
        "#",
        "# TODO: Add your allow/deny rules above the catch-all deny at the end.",
        "# The catch-all deny is required for security.",
    ])
    header = "\n".join(header_lines) + "\n"

    return policy, header


def main():
    parser = argparse.ArgumentParser(
        description="Generate policy YAML for MCP servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url http://localhost:9001/mcp --output k8s.yaml
  %(prog)s --command "ssh-mcp-server --config /etc/ssh.json" --output ssh.yaml
  %(prog)s --url http://localhost:9001/mcp --prefix "k8s_" --output k8s.yaml
        """
    )

    # Connection options (mutually exclusive with --batch)
    conn_group = parser.add_mutually_exclusive_group()
    conn_group.add_argument("--url", help="HTTP URL of MCP server (single server mode)")
    conn_group.add_argument("--command", help="Command to start stdio MCP server (single server mode)")
    conn_group.add_argument("--batch", help="JSON file with array of server definitions (batch mode)")

    # Output options (single server mode)
    parser.add_argument("--output", "-o", default="", help="Output YAML file path (single mode)")
    parser.add_argument("--prefix", default="", help="Tool name prefix (e.g., 'k8s_')")
    parser.add_argument("--path", default="", help="HTTP path (e.g., '/mcp/k8s')")
    parser.add_argument("--name", default="", help="Backend name (auto-detected if not specified)")
    parser.add_argument("--keepalive", action="store_true", help="Enable keepalive for stdio servers")
    parser.add_argument("--headers", default="", help="JSON dict of HTTP headers (e.g., '{\"Auth\":\"token\"}')")
    parser.add_argument("--output-dir", default=".", help="Output directory for batch mode")

    args = parser.parse_args()

    # Parse headers if provided
    headers = None
    if args.headers:
        try:
            headers = json.loads(args.headers)
            if not isinstance(headers, dict):
                print("ERROR: --headers must be a JSON object", file=sys.stderr)
                sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in --headers: {e}", file=sys.stderr)
            sys.exit(1)

    # --- Batch mode ---
    if args.batch:
        with open(args.batch) as f:
            servers = json.load(f)
        if not isinstance(servers, list):
            print("ERROR: batch file must contain a JSON array", file=sys.stderr)
            sys.exit(1)

        print(f"Batch mode: {len(servers)} servers defined")
        for server_def in servers:
            url = server_def.get("url", "")
            name = server_def.get("name", server_def.get("serverName", ""))
            headers_def = server_def.get("headers")
            path_def = server_def.get("path", "")
            output = server_def.get("output", "")
            prefix = server_def.get("prefix", "")

            if not url:
                print(f"  SKIP {name}: no url", file=sys.stderr)
                continue

            if not name:
                # derive from url
                from urllib.parse import urlparse
                netloc = urlparse(url).netloc
                name = netloc.split(".")[0]
            name = sanitize_name(name)

            if not output:
                output = f"{args.output_dir}/{name}.yaml"

            print(f"  Processing {name} ({url})...", end=" ", flush=True)

            try:
                tools, server_info = asyncio.run(discover_http_tools(url, headers=headers_def))
            except Exception as e:
                print(f"FAILED: {e}")
                continue

            print(f"{len(tools)} tools", end="... ", flush=True)
            policy, header = generate_policy(
                backend_name=name,
                tools=tools,
                server_info=server_info,
                prefix=prefix or f"{name}_",
                path=path_def or f"/mcp/{name}",
                url=url,
                transport="http",
                headers=headers_def,
            )

            with open(output, 'w') as f:
                f.write(header)
                yaml.dump(policy, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            print(f"-> {output}")

        print("\nBatch processing complete. Edit each file to add allow rules.")
        return

    # --- Single server mode ---
    if not args.url and not args.command:
        print("ERROR: Specify --url, --command, or --batch", file=sys.stderr)
        sys.exit(1)

    # Discover tools
    print(f"Connecting to MCP server...")

    if args.url:
        print(f"HTTP URL: {args.url}")
        if headers:
            print(f"Headers: {json.dumps(headers, default=str)[:100]}...")
        tools, server_info = asyncio.run(discover_http_tools(args.url, headers=headers))
        transport = "http"
    else:
        print(f"Command: {args.command}")
        tools, server_info = asyncio.run(discover_stdio_tools(args.command))
        transport = "stdio"
        if headers:
            print("WARNING: --headers ignored for stdio transport")

    print(f"Discovered {len(tools)} tools")

    # Determine backend name
    backend_name = args.name
    if not backend_name:
        backend_name = server_info.get('name', 'unknown')
    backend_name = sanitize_name(backend_name)

    print(f"Backend name: {backend_name}")

    # Determine output path
    output_path = args.output or f"{args.output_dir}/{backend_name}.yaml"

    # Generate policy
    policy, header = generate_policy(
        backend_name=backend_name,
        tools=tools,
        server_info=server_info,
        prefix=args.prefix or f"{backend_name}_",
        path=args.path,
        url=args.url or "",
        command=args.command or "",
        transport=transport,
        headers=headers,
    )

    # Write output
    with open(output_path, 'w') as f:
        f.write(header)
        yaml.dump(policy, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    print(f"\nPolicy written to: {output_path}")
    print(f"\nNext steps:")
    print(f"  1. Review the generated policy")
    print(f"  2. Add allow rules for permitted operations")
    print(f"  3. Customize the default_deny message if needed")
    print(f"  4. Test with: POLICY_DIR=<dir> python policy_proxy.py")


if __name__ == "__main__":
    main()
