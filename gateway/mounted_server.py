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
import contextvars
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

# ---------------------------------------------------------------------------
# Upstream progress-relay contextvar
# ---------------------------------------------------------------------------
# When the gateway forwards a tool call to a downstream MCP backend (e.g.
# ipybox's ``execute_code`` which runs ``job_wait`` for up to 300s), that
# backend may emit progress notifications (``ProgressNotification``) on the
# gateway↔backend connection.  Without relay, those notifications are
# swallowed — the gateway's ``forward()`` returns a plain dict and the
# original MCP client never sees them.
#
# The ``call_tool`` handler below (registered on the MCP SDK lowlevel
# ``Server``) checks the incoming request's ``progressToken``.  If the
# client provided one, it builds a relay callback that re-sends progress
# notifications to the *client* (via ``ServerSession.send_progress_notification``)
# and stores it in this contextvar.  ``forward()`` in ``policy_proxy.py``
# picks it up and passes it as ``progress_callback`` to the downstream
# ``ClientSession.call_tool``, which makes the downstream server (ipybox)
# actually emit progress notifications.
#
# Contextvars are inherited by child tasks within the same event loop, so
# the callback set here is visible inside ``forward()`` and its callees.
# ---------------------------------------------------------------------------
UpstreamProgressCallback = Callable[
    [float, Optional[float], Optional[str]], Awaitable[None]
]

_upstream_progress_callback: contextvars.ContextVar[
    Optional[UpstreamProgressCallback]
] = contextvars.ContextVar("upstream_progress_callback", default=None)


def get_upstream_progress_callback() -> Optional[UpstreamProgressCallback]:
    """Return the progress-relay callback set by ``call_tool``, or ``None``."""
    return _upstream_progress_callback.get()

# ---------------------------------------------------------------------------
# Session-key contextvar
# ---------------------------------------------------------------------------
# The incoming tools/call request carries the ``Mcp-Session-Id`` header the
# client echoed back from initialize() (or a client-chosen session name for
# clients like the VS Code extension). The policy confirm gate wants it to
# render the "⏱ Allow 30 min (session)" button and to key the temporary
# allowance.  However, handlers run in the MCP SDK's per-session task, and
# HTTP-middleware ContextVars set in the request dispatch task are NOT visible
# there (only connection-scoped values like client IP survive).  So the
# ``call_tool`` handler below resolves the header directly from the SDK's
# request context and stores it here; ``policy_proxy._captured_session_id()``
# falls back to this when the middleware ContextVar is empty.
# ---------------------------------------------------------------------------
_current_session_key: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_session_key", default=""
)


def get_current_session_key() -> str:
    """Return the ``Mcp-Session-Id`` echoed by the client on this call, or ``""``."""
    return _current_session_key.get()


# ---------------------------------------------------------------------------
# Captured incoming headers (policy-injection support)
# ---------------------------------------------------------------------------
# Policy ``inject_argument`` rules may reference incoming MCP client headers
# via ``${request_header:NAME}`` — e.g. the ipybox policy injects
# ``kernel_env.MCP_SESSION_ID: "${request_header:Mcp-Session-Id}"`` so that
# every call from one agent session lands in the same sandbox kernel (and thus
# reuses one gateway session, which is what makes the "Allow 10 min (session)"
# confirm bypass apply to every call of that session).
#
# Those headers are captured by ``policy_proxy.ClientInfoMiddleware``, whose
# ContextVars are — exactly like the session key above — NOT visible inside the
# MCP SDK's per-session task where tool handlers run.  ``resolve_injections()``
# would therefore see nothing and leave the ``${request_header:...}`` template
# unresolved; ipybox's ``_resolve_session_id()`` rejected such an unresolved
# value and fell back to the per-request transport session id, which churns a
# fresh kernel (and a fresh confirm-gate session) on every call.
#
# ``call_tool`` below re-captures the allowlisted headers from the SDK request
# context and publishes them here; ``policy_proxy`` reads this ContextVar as a
# fallback when its middleware-scoped one is empty.
#
# The allowlist is pushed in by ``policy_proxy`` via
# ``set_incoming_header_capture()`` (single source of truth: the
# ``MCP_REQUEST_HEADER_CAPTURE`` env var) so a policy template can never
# reference a header the operator did not ask to capture.
# ---------------------------------------------------------------------------
_captured_incoming_headers: contextvars.ContextVar[
    Optional[dict]
] = contextvars.ContextVar("captured_incoming_headers", default=None)

_incoming_header_capture: List[str] = []


def set_incoming_header_capture(names: Optional[List[str]]) -> None:
    """Register the allowlist of incoming headers to re-capture per tool call."""
    global _incoming_header_capture
    _incoming_header_capture = [str(n) for n in (names or []) if n]


def get_captured_incoming_headers() -> Optional[dict]:
    """Return the incoming MCP client headers captured for this tool call."""
    return _captured_incoming_headers.get()


def _capture_incoming_headers(request_headers: Any) -> Optional[dict]:
    """Extract the allowlisted headers from an SDK request's header mapping.

    Returns ``None`` when nothing matched (so callers keep the middleware value
    untouched).  Lookup is case-insensitive because the SDK exposes headers as
    a plain mapping, not a case-insensitive ``Headers`` object.
    """
    if request_headers is None:
        return None
    try:
        lower = {str(k).lower(): v for k, v in request_headers.items()}
    except Exception:
        lower = {}
    captured = {}
    # Always capture the stable operator session forwarded by ipybox kernels,
    # even when it is not in the allowlist (it keys the confirm bypass and must
    # survive ipybox kernel idle-reaps). Case-insensitive via the lower map.
    _os = lower.get("x-mcp-operator-session")
    if _os:
        captured["X-MCP-Operator-Session"] = str(_os)
    if _incoming_header_capture:
        for name in _incoming_header_capture:
            val = None
            try:
                val = request_headers.get(name)
            except Exception:
                val = None
            if val is None:
                val = lower.get(name.lower())
            if val:
                captured[name] = str(val)
    return captured or None


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

        # json_response=False (SSE responses) is REQUIRED for progress relay:
        # in JSON mode the SDK discards interim notifications emitted during a
        # tool call and returns only the final response, so progress beats
        # (e.g. keepalives relayed from skills-ipybox / ipybox) would never
        # reach the client.  SSE POST responses carry the interim
        # notifications plus the final response; every client we serve (mcp
        # python lib, mcp2cli, tg-client) sends Accept including text/event-stream.
        self._http_manager = StreamableHTTPSessionManager(
            app=self._mcp,
            event_store=None,
            json_response=False,
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
                return types.CallToolResult(
                    content=[TextContent(type="text", text=f"Unknown tool: {name}")],
                    isError=True,
                )

            # --- Progress relay setup ---
            # Extract the MCP client's progress token from the incoming request
            # context (set by the MCP SDK before calling this handler).  If the
            # client provided a progressToken, build a callback that re-sends
            # progress notifications to the client.  The callback is stored in a
            # contextvar so that forward() (and its callees) can pick it up and
            # pass it as progress_callback to the downstream ClientSession.call_tool,
            # which makes the downstream server (e.g. ipybox) emit progress
            # notifications in the first place.
            callback_token = None
            try:
                rc = self._mcp.request_context
                if rc is not None and rc.meta is not None:
                    progress_token = rc.meta.progressToken
                else:
                    progress_token = None
                client_session = rc.session if rc is not None else None
            except LookupError:
                # No active request context — proceed without relay.
                progress_token = None
                client_session = None
                rc = None

            log.info("PROGRESS-RELAY setup: token=%r", progress_token)
            if progress_token is not None and client_session is not None:
                async def _relay(
                    progress: float,
                    total: Optional[float],
                    message: Optional[str],
                ) -> None:
                    """Relay a progress notification from the backend to the client."""
                    log.info("PROGRESS-RELAY firing progress=%r msg=%r", progress, message)
                    try:
                        await client_session.send_progress_notification(
                            progress_token=progress_token,
                            progress=progress,
                            total=total,
                            message=message,
                            # Tag with the incoming tools/call request id so the
                            # streamable transport routes the notification onto
                            # that request's SSE response stream; without it the
                            # transport drops the notification (no standalone GET
                            # stream association) and the client never sees it.
                            related_request_id=rc.request_id,
                        )
                    except Exception:
                        log.exception("PROGRESS-RELAY send failed")
                        pass

                callback_token = _upstream_progress_callback.set(_relay)

            # --- Session key capture (confirm-gate support) ---
            # Resolve the client's Mcp-Session-Id from the SDK request context
            # (reachable in this task) so the policy confirm gate can offer the
            # "Allow 30 min (session)" button even though HTTP-middleware
            # ContextVars from the request task never reach session tasks.
            #
            # The same context gap applies to the *other* captured incoming
            # headers: policy injections referencing ``${request_header:NAME}``
            # (e.g. ipybox's ``kernel_env.MCP_SESSION_ID``) are resolved in this
            # task, so re-capture the allowlisted headers here too — otherwise
            # the template stays unresolved and downstream kernels key off the
            # per-call transport session instead of the agent's session.
            session_token = None
            headers_token = None
            try:
                session_key = ""
                if rc is not None and getattr(rc, "request", None) is not None:
                    req_headers = rc.request.headers
                    session_key = (req_headers.get("Mcp-Session-Id") or "").strip()
                    captured = _capture_incoming_headers(req_headers)
                    if captured:
                        headers_token = _captured_incoming_headers.set(captured)
                if session_key:
                    session_token = _current_session_key.set(session_key)
            except Exception:
                session_token = None
                headers_token = None

            try:
                result = await handler(**arguments)
                if isinstance(result, types.CallToolResult):
                    return result
                elif isinstance(result, str):
                    return types.CallToolResult(
                        content=[TextContent(type="text", text=result)]
                    )
                return types.CallToolResult(
                    content=result if isinstance(result, list) else [TextContent(type="text", text=str(result))]
                )
            except Exception as e:
                log.error("Tool '%s' error: %s", name, e, exc_info=True)
                return types.CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {e}")],
                    isError=True,
                )
            finally:
                if session_token is not None:
                    _current_session_key.reset(session_token)
                if headers_token is not None:
                    _captured_incoming_headers.reset(headers_token)
                if callback_token is not None:
                    _upstream_progress_callback.reset(callback_token)

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
                        return types.CallToolResult(
                            content=[TextContent(type="text", text=f"Unknown tool: {name}")],
                            isError=True,
                        )
                    try:
                        result = await handler(**arguments)
                        if isinstance(result, types.CallToolResult):
                            return result
                        elif isinstance(result, str):
                            return types.CallToolResult(
                                content=[TextContent(type="text", text=result)]
                            )
                        return types.CallToolResult(
                            content=result if isinstance(result, list) else [TextContent(type="text", text=str(result))]
                        )
                    except Exception as e:
                        log.error("Tool '%s' error: %s", name, e, exc_info=True)
                        return types.CallToolResult(
                            content=[TextContent(type="text", text=f"Error: {e}")],
                            isError=True,
                        )

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
