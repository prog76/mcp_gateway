#!/usr/bin/env python3
"""
MountedServer - An MCP server that can be mounted at a path in a Starlette app.

The server handles requests at the root path ("/") of its mounted location.
So if mounted at "/mcp/k8s", clients connect to "http://host:port/mcp/k8s"
and the server handles the MCP protocol at that path.

Supports both:
- Streamable HTTP (POST to /) — used by modern MCP clients
- Legacy SSE (GET for stream, POST for messages) — used by Cline
"""

import asyncio
import contextlib
import logging
from typing import Any, Optional, List, Callable, Awaitable

import anyio
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from mcp.server import Server as MCPServerSDK
from mcp.server.models import InitializationOptions
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.fastmcp.server import TransportSecuritySettings
from mcp.server.sse import SseServerTransport
import mcp.types as types
from mcp.types import Tool, TextContent

log = logging.getLogger(__name__)


class MountedServer:
    """
    An MCP server that can be mounted at a path in a Starlette app.

    Usage:
        server = MountedServer(name="my-server", port=8000)

        @server.tool(name="my-tool")
        async def my_tool(arg: str) -> str:
            return f"Hello {arg}!"

        # Mount it in another Starlette app
        main_app = Starlette(routes=[
            Mount("/my-server", app=server.get_app()),
        ])

        # Clients connect to http://host:port/my-server
    """

    def __init__(
        self,
        name: str,
        port: int,
        allowed_hosts: Optional[List[str]] = None,
        enable_dns_rebinding_protection: bool = True,
        prompts: Optional[dict[str, str]] = None,
        strip_output_schema: bool = False,
        stateless: bool = False,
        prompt_proxy: Optional[Callable[[str, Optional[str]], Awaitable]] = None,
    ):
        self.name = name
        self.port = port
        self._mcp = MCPServerSDK(name=name)
        self._tools: List[Tool] = []
        self._tool_handlers: dict[str, Callable] = {}
        self._prompts: dict[str, str] = prompts or {}
        # Optional async callable that proxies prompt requests (list/get) to a
        # downstream backend.  Signature: (kind: "list"|"get", name:
        # Optional[str]) -> list[Prompt] | GetPromptResult | None.  When set,
        # prompts/list and prompts/get are delegated to the proxy instead of
        # the static self._prompts path.
        self._prompt_proxy = prompt_proxy
        # When True, the prompt proxy is the exclusive handler; the static
        # self._prompts path is unused.
        self._use_prompt_proxy = prompt_proxy is not None
        # When True, tools are advertised without an outputSchema (equivalent to
        # vscode-mcp's structured_output=False). Some browser-based MCP clients
        # (e.g. mcp super-assistant) fail on structured output schemas.
        self._strip_output_schema = strip_output_schema
        self._stateless = stateless

        if allowed_hosts is None:
            import socket as _socket
            hostname = _socket.gethostname()
            allowed_hosts = []
            for p in [port, 8000, 8001, 8002, 8003]:
                allowed_hosts.extend([
                    f"localhost:{p}", f"127.0.0.1:{p}", f"0.0.0.0:{p}", f"{hostname}:{p}",
                ])

        self._security = TransportSecuritySettings(
            enable_dns_rebinding_protection=enable_dns_rebinding_protection,
            allowed_hosts=allowed_hosts,
        )
        log.info("MountedServer '%s': %d allowed hosts, dns_rebinding=%s, strip_output_schema=%s, stateless=%s",
                 name, len(allowed_hosts), enable_dns_rebinding_protection, strip_output_schema, stateless)

        self._http_manager = StreamableHTTPSessionManager(
            app=self._mcp,
            event_store=None,
            json_response=True,
            stateless=stateless,
            security_settings=self._security,
        )

        # SSE transport for legacy clients (Cline)
        self._sse = SseServerTransport("/messages", security_settings=self._security)

        @self._mcp.list_tools()
        async def list_tools():
            return self._tools

        @self._mcp.call_tool()
        async def call_tool(name: str, arguments: dict):
            handler = self._tool_handlers.get(name)
            if handler is None:
                return [TextContent(type="text", text=f"Unknown tool: {name}")]
            try:
                result = await handler(**arguments)
                if isinstance(result, str):
                    return [TextContent(type="text", text=result)]
                return result if isinstance(result, list) else [TextContent(type="text", text=str(result))]
            except Exception as e:
                log.error("Tool '%s' error: %s", name, e, exc_info=True)
                return [TextContent(type="text", text=f"Error: {e}")]

        # ------------------------------------------------------------
        # Prompts / prompt templates
        # ------------------------------------------------------------
        if self._prompts or self._use_prompt_proxy:
            @self._mcp.list_prompts()
            async def list_prompts(req: types.ListPromptsRequest) -> types.ListPromptsResult:
                if self._use_prompt_proxy and self._prompt_proxy is not None:
                    prompts = await self._prompt_proxy("list", None)
                    return types.ListPromptsResult(prompts=prompts or [])
                # Only return the prompts we were configured with.
                return types.ListPromptsResult(
                    prompts=[
                        types.Prompt(name=prompt_name, description="Bootstrap prompt")
                        for prompt_name in self._prompts.keys()
                    ]
                )

            @self._mcp.get_prompt()
            async def get_prompt(name: str, arguments: dict[str, str] | None = None) -> types.GetPromptResult:
                if self._use_prompt_proxy and self._prompt_proxy is not None:
                    result = await self._prompt_proxy("get", name)
                    if result is None:
                        raise ValueError(f"Unknown prompt: {name}")
                    return result
                if name not in self._prompts:
                    raise ValueError(f"Unknown prompt: {name}")
                prompt_text = self._prompts[name]
                return types.GetPromptResult(
                    description=f"Prompt: {name}",
                    messages=[
                        types.PromptMessage(
                            role="user",
                            content=TextContent(type="text", text=prompt_text),
                        )
                    ],
                )

    def tool(self, name: str, description: str = "", inputSchema: dict = None,
             outputSchema: dict = None):
        def decorator(func):
            if name in self._tool_handlers:
                log.warning("Tool '%s' already registered on '%s', skipping duplicate", name, self.name)
                return func
            tool_kwargs = dict(
                name=name,
                description=description or func.__doc__ or "",
                inputSchema=inputSchema or {"type": "object", "properties": {}},
            )
            # When strip_output_schema is enabled, never advertise an
            # outputSchema (equivalent to vscode-mcp's structured_output=False).
            # Some browser-based MCP clients fail on structured output schemas.
            if outputSchema is not None and not self._strip_output_schema:
                tool_kwargs["outputSchema"] = outputSchema
            self._tools.append(Tool(**tool_kwargs))
            self._tool_handlers[name] = func
            return func
        return decorator

    def get_app(self) -> Starlette:
        """Get the Starlette app for this server. Handles requests at root '/'.

        Routes requests by method and Accept header:
        - GET without text/event-stream → Legacy SSE (for Cline)
        - GET with text/event-stream → Streamable HTTP SSE
        - POST → Streamable HTTP (or SSE message post for legacy)
        """
        async def handle_streamable(scope: Scope, receive: Receive, send: Send):
            await self._http_manager.handle_request(scope, receive, send)

        async def handle_sse_connect(scope: Scope, receive: Receive, send: Send):
            """Handle SSE connection from legacy clients (Cline)."""
            async with self._sse.connect_sse(scope, receive, send) as (read_stream, write_stream):
                # Create a server instance with our tool handlers for this session
                server = MCPServerSDK(self.name)

                # Prompts support (bootstrap prompts) for legacy clients.
                # Without these handlers, Cline can call `prompts/list`, but receives an empty set.
                if self._prompts or self._use_prompt_proxy:
                    @server.list_prompts()
                    async def list_prompts_sse(req: types.ListPromptsRequest) -> types.ListPromptsResult:
                        if self._use_prompt_proxy and self._prompt_proxy is not None:
                            prompts = await self._prompt_proxy("list", None)
                            return types.ListPromptsResult(prompts=prompts or [])
                        return types.ListPromptsResult(
                            prompts=[
                                types.Prompt(name=prompt_name, description="Bootstrap prompt")
                                for prompt_name in self._prompts.keys()
                            ]
                        )

                    @server.get_prompt()
                    async def get_prompt_sse(
                        name: str,
                        arguments: dict[str, str] | None = None,
                    ) -> types.GetPromptResult:
                        if self._use_prompt_proxy and self._prompt_proxy is not None:
                            result = await self._prompt_proxy("get", name)
                            if result is None:
                                raise ValueError(f"Unknown prompt: {name}")
                            return result
                        if name not in self._prompts:
                            raise ValueError(f"Unknown prompt: {name}")
                        prompt_text = self._prompts[name]
                        return types.GetPromptResult(
                            description=f"Prompt: {name}",
                            messages=[
                                types.PromptMessage(
                                    role="user",
                                    content=TextContent(type="text", text=prompt_text),
                                )
                            ],
                        )

                @server.list_tools()
                async def list_tools_sse():
                    return self._tools

                @server.call_tool()
                async def call_tool_sse(name: str, arguments: dict):
                    handler = self._tool_handlers.get(name)
                    if handler is None:
                        return [TextContent(type="text", text=f"Unknown tool: {name}")]
                    try:
                        result = await handler(**arguments)
                        if isinstance(result, str):
                            return [TextContent(type="text", text=result)]
                        return result if isinstance(result, list) else [TextContent(type="text", text=str(result))]
                    except Exception as e:
                        log.error("Tool '%s' error: %s", name, e, exc_info=True)
                        return [TextContent(type="text", text=f"Error: {e}")]

                await server.run(
                    read_stream,
                    write_stream,
                    InitializationOptions(
                        server_name=self.name,
                        server_version="1.0.0",
                        capabilities=types.ServerCapabilities(
                            tools=types.ToolsCapability(listChanged=False),
                            prompts=types.PromptsCapability(listChanged=False),
                        ),
                    ),
                )

        async def handle(scope: Scope, receive: Receive, send: Send):
            if scope["type"] == "http":
                method = scope.get("method", "")
                headers = dict(scope.get("headers", []))
                accept = headers.get(b"accept", b"").decode("utf-8", errors="ignore")

                if method == "GET":
                    # Both SSE and streamable HTTP use GET for SSE streams
                    # Route to SSE transport which handles both
                    await handle_sse_connect(scope, receive, send)
                    return
                elif method == "POST":
                    # Check if this is an SSE message post (has session_id query param)
                    query = scope.get("query_string", b"").decode("utf-8", errors="ignore")
                    if "session_id" in query:
                        # Legacy SSE message post
                        await self._sse.handle_post_message(scope, receive, send)
                        return
            # Default: streamable HTTP
            await handle_streamable(scope, receive, send)

        return Starlette(routes=[Mount("/", app=handle)])
