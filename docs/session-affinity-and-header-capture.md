# Session affinity and incoming-header capture

How `${request_header:NAME}` templates in policy injections reach tool
handlers, why they did not at first, and what the confirm-gate "Allow 10 min
(session)" bypass depends on.

Relevant code: `gateway/mounted_server.py` (capture + re-publish),
`gateway/policy_proxy.py` (`_resolve_header_refs`, `resolve_injections`,
`_incoming_headers_effective`), `gateway/policy_yaml.py` (allowlist source).

## Why this mechanism exists

The ipybox backend policy injects a stable session id into every kernel call:

```yaml
# config/policy/real/ipybox.yaml
rules:
  - action: inject_argument
    inject:
      kernel_env:
        MCP_SESSION_ID: "${request_header:Mcp-Session-Id}"
```

The point is **kernel affinity**: every call from one agent session should land
in the same sandbox kernel, and therefore reuse one gateway session. That is
what makes the session-scoped confirm bypass ("Allow 10 min (session)") apply to
all of a session's calls instead of one call. If affinity breaks, every call
churns a fresh kernel **and** a fresh confirm-gate session.

## The failure mode: ContextVar scope does not cross into handler tasks

`ClientInfoMiddleware` captures incoming request headers into ContextVars. But
MCP tool handlers do **not** run in that middleware's task context — they run
inside the MCP SDK's own per-session task, where those ContextVars are not
visible (the same reason the session key itself needs separate handling).

So `resolve_injections()` saw an empty header map and left the template
**verbatim**: the kernel received the literal string
`${request_header:Mcp-Session-Id}` as its session id. Observed directly:

```python
>>> os.environ['MCP_SESSION_ID']
'${request_header:Mcp-Session-Id}'
```

ipybox's `_resolve_session_id()` detects that unresolved value (via its
`_UNRESOLVED_PREFIX` check) and falls back to a fresh `uuid.uuid4()`, which is
why every call created a new kernel.

> Note the trap in the symptom: it looks like "`resolve_injections` does not
> handle `${request_header:...}`". It does. The template support was never the
> problem — **the header map was empty at resolution time** because of task
> scoping. Fixing the resolver would not have fixed this.

## The fix: re-capture in `call_tool`

Resolution happens per request. Since the middleware-scoped ContextVar is
unavailable in the handler task, `MountedServer.call_tool` re-captures the
allowlisted headers from the SDK request context and publishes them into a
second ContextVar (`_captured_incoming_headers`), which `policy_proxy`
consults as a **fallback** when its own middleware-scoped map is empty
(`_incoming_headers_effective()`).

Priority chain for the effective header map:

1. middleware-captured headers (when in scope)
2. `call_tool` re-capture (`_captured_incoming_headers`)

The same re-capture also carries `X-MCP-Operator-Session`, which keys the
confirm bypass and must survive ipybox kernel idle-reaps. It is captured
always — even when absent from the allowlist — because that bypass depends on
it.

## The allowlist is the security boundary

Headers are captured only if named in `MCP_REQUEST_HEADER_CAPTURE` (pushed into
the server via `set_incoming_header_capture()`). This is deliberate: it is the
single source of truth, and it guarantees **a policy template can never
reference a header the operator did not ask to capture**.

Consequence to remember when debugging: if a template resolves to its literal
self, check the allowlist before suspecting the resolver.

## Template reference

| Template | Resolves against | Typical use |
|---|---|---|
| `${env:VAR}` | gateway environment | static config |
| `${clientHost}` | reverse-DNS of the MCP client | caller identity |
| `${clientIp}` | client IP | caller identity |
| `${request_header:NAME}` | incoming client request headers | session affinity, auth passthrough |
| `${header:NAME}` | effective downstream headers (compound + backend) | policy inject rules referencing compound-set headers |

If a header is not found, the reference is **left unchanged** — it does not
error. That verbatim fallback is exactly how the unresolved-session bug stayed
silent at the gateway layer and only showed up as kernel churn.

## Regression tests to keep

* `${request_header:...}` resolves to the real header value when the header is
  present on the incoming request.
* Resolution works from inside a tool handler (i.e. it does not depend on
  middleware task scope) — this is the regression that caused the bug.
* With the header absent, the reference stays verbatim (documented behaviour,
  not an exception).
* `X-MCP-Operator-Session` is captured even when not in the allowlist.
* A header not in `MCP_REQUEST_HEADER_CAPTURE` is never captured.
