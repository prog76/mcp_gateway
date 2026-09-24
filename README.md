# mcp-gateway

MCP policy proxy with enforcement + compound endpoints.

Adapted from the original `policy-proxy/mcp` package for distribution as an
independent pip package. Depends on `mcp2cli` (via pip) for the shared MCP
client library.

## What this package provides

| Module | Purpose |
|---|---|
| `gateway.policy_proxy` | Core policy enforcement + compound endpoint aggregator (the FastMCP/Starlette app) |
| `gateway.mounted_server` | `MountedServer` — an MCP server mountable at a path in a Starlette app |
| `gateway.policy_yaml` | `PolicyLoader` — SafeLoader extended with a `!concat` tag |
| `gateway.validate_policy` | Policy file validator |
| `gateway.mcp_onboard` | Onboarding helper that generates starter policy YAML from discovered tools |
| `gateway.start` | Container entrypoint that reproduces `start.sh` behavior |

> **secure-fox** (browser control) is a separate package
> (`github.com/prog76/mcp_secure-fox`). It runs as its **own container**
> (reusing this project's image with an entrypoint override) and the gateway
> proxies to it via policy (`deploy/config/policy/real/browser.yaml`,
> `http://browser:9005/mcp`). The gateway never imports it.

## Console script

```
mcp-gateway-start
```

This runs the policy proxy in the foreground. The gateway is a **pure policy
proxy**: long-running backend MCP servers (k8s, netbox, browser/secure-fox,
ipybox) run as their own containers supervised by the orchestrator
(docker-compose), and policies reference them by service URL
(`http://netbox:9004/mcp`, ...). The exec backend is a stdio MCP server
spawned per-request by the proxy — request-scoped execution, not daemon
supervision.

## Environment variables

| Variable | Default |
|---|---|
| `POLICY_DIR` | `/etc/mcp-gateways/policy` |
| `POLICY_PROXY_PORT` | `8000` |
| `POLICY_PROXY_HOST` | `0.0.0.0` |
| `VALIDATE_POLICY_PATH` | `/opt/validate_policy.py` |
| `COMPOUNDS_CONFIG` | `/etc/mcp-gateways/compounds.yaml` |
| `NOTIFICATION_CONFIG` | `/etc/mcp-gateways/notifications.yaml` |
| `MCP_CONFIRM_PROGRESS_INTERVAL` | `5.0` |
| `MCP_REQUEST_HEADER_CAPTURE` | *(empty — disabled)* |
| `MCP_TEMP_ALLOW_SECONDS` | `600` |
| `MCP_CONFIRM_HARD_TIMEOUT_SECONDS` | `90` |

`MCP_CONFIRM_PROGRESS_INTERVAL` — cadence (seconds) for MCP progress
notifications sent to a calling agent while it is blocked on a Telegram
`confirm` approval. Only emitted when the client supplied a `progressToken`.

`MCP_REQUEST_HEADER_CAPTURE` — comma-separated list of incoming HTTP header
names to capture from the MCP client request. Captured headers are available
for compound header resolution via `${request_header:NAME}`. Enables
auth-passthrough (e.g. forwarding the client's `Authorization` header to the
downstream backend).

`MCP_TEMP_ALLOW_SECONDS` — how long a session-scoped confirm bypass stays
armed after the operator clicks the **"⏱ Allow 10 min (session)"** button in a
`confirm` Telegram message. Default `600` (10 minutes).

### 10-minute session confirm bypass

When a `confirm` rule is triggered and a request that carries `Mcp-Session-Id`
(a client-supplied MCP session header, captured via `MCP_REQUEST_HEADER_CAPTURE`),
the operator is offered an extra **"⏱ Allow 10 min (session)"** button next to
Approve / Reject. Clicking it approves **this one call** (like Approve) **and**
arms a long-lived allowance that auto-approves **this exact confirm rule** — the same
`match` spec at the same index on the same backend — for the remaining window,
**scoped to that session and that client connection**. Any other chat/assistant (different
session id or different origin) won't match the allowance and continues to hit the normal
Telegram confirm flow. The bypass is keyed by `(client IP | Mcp-Session-Id,
backend name, rule index)` so the client-supplied header alone can't be spoofed to
inherit another session's grant. Allowances are stored in memory and expire on gateway
restart. No notification is sent to the operator for bypassed calls — the agent just
executes. Logged for audit at INFO level.

### confirm-hard — bypass-proof approval

Policy actions come in two approval flavours (and an unknown action means
DENY since v0.1.38, so spell them exactly):

| action | X-Skill-Bypass token | Allow-10-min (session) grant |
|---|---|---|
| `confirm` | skips the ask | skips the ask |
| `confirm-hard` | **ignored** | **ignored** (button not offered) |

`confirm-hard` opens the normal Telegram approve/reject flow for **every** call —
no token, no session allowance. It exists for callers that are themselves
pre-approved: a skill carrying the bypass token must not be able to approve its
own writes (`write_playbook_script` / `write_skill_md` in skills-ipybox.yaml).

A confirm-hard wait is capped by `MCP_CONFIRM_HARD_TIMEOUT_SECONDS` (default 90,
and never above the rule's own `timeout:`) so it resolves inside the caller's
120s tool-call wall.

### Approval expiry: typed, retryable, and NOT a denial (both tiers)

When a `confirm` or `confirm-hard` wait expires with no operator answer, the
gateway returns a TYPED result instead of the old bare
`ACCESS DENIED: Approval request timed out.` (kanban t_93e4d6c5 — that text
was identical to a policy refusal, which made routing around the gate look
reasonable):

```text
awaiting_approval: <tool> on <backend> is waiting for a human decision in
Telegram (request <id8>...). No answer within <n>s, so the call did NOT run —
this is NOT a denial and no policy refused it. retryable=true: ask the
operator to answer the approval, then retry the same call. <timeout template>
```

plus `structuredContent = {status:"awaiting_approval", backend, tool,
request_id, timeout_seconds, resolved:false, retryable:true}`.

`isError` is **true**, and that is deliberate: tools like `git_push` advertise
an outputSchema whose required fields are the push outcome, and the MCP SDK
client validates `structuredContent` against that schema whenever `isError` is
false — a non-error result would raise a transport-level schema error instead of
reaching the caller (measured, this card's probe). An error result skips that
validation, so the agent sees the `awaiting_approval` text. Agent contract: on
this result RETRY the same call (or wait for the operator's answer) — never
treat it as a refusal, and never look for a bypass.

The default `confirm_timeout` text no longer says `ACCESS DENIED` (a per-rule
`confirm_timeout:` override is still honoured verbatim). On expiry the gateway
also posts a follow-up Telegram message naming the tool (so a missed ask cannot
go unnoticed), and the timeout edit now KEEPS the Approve/Reject buttons — a
late answer is still valid.

## Compound headers → policy injection

Compounds can set HTTP headers for downstream backends, and policy rules can
reference those header values as injected tool arguments. This creates an
end-to-end flow:

1. **Compound sets a header** — the compound's `headers:` block is merged
   with the backend's own headers and sent to the downstream MCP backend.
   Header values support per-request template variables:

   | Template | Resolves to |
   |---|---|
   | `${env:VAR}` | Environment variable value |
   | `${clientHost}` | Reverse-DNS hostname of the MCP client |
   | `${clientIp}` | IP address of the MCP client |
   | `${request_header:NAME}` | A header captured from the incoming MCP client request |

2. **Policy injects the header** — a backend policy rule with `action: inject_argument`
   references the effective header value via `${header:NAME}`:

   ```yaml
   # In a backend policy YAML:
   rules:
     - match: { tool: "^get_jira_issue$" }
       action: inject_argument
       inject:
         caller_host: "${header:X-Client-Host}"
         caller_ip: "${header:X-Client-IP}"
   ```

### Use cases

- **Caller identity**: A compound sets `X-Client-Host: ${clientHost}` so the
  backend knows which client made the call. The policy can inject it as a tool
  argument for audit trails.
- **Auth passthrough**: With `MCP_REQUEST_HEADER_CAPTURE=Authorization`, a
  compound forwards the client's auth header to the backend:
  `X-Forwarded-Auth: ${request_header:Authorization}`.
- **Credential deduplication**: Headers defined once at the compound level
  (or backend level) can be referenced in multiple policy inject rules without
  repeating the secret.

### Example

```yaml
# compounds.yaml
compounds:
  local:
    path: /mcp/local
    headers:
      X-Client-Host: "${clientHost}"
      X-Client-IP: "${clientIp}"
      X-Forwarded-Auth: "${request_header:Authorization}"
    backends: [ipybox, exec]

# Backend policy (e.g. exec.yaml)
rules:
  - match: { tool: "^run$" }
    action: inject_argument
    inject:
      caller_host: "${header:X-Client-Host}"
      caller_ip: "${header:X-Client-IP}"
```

## Compounds proxy prompts from backends

Compound endpoints expose `prompts/list` + `prompts/get` by **proxying** to their
backends: `MountedServer` accepts a single `prompt_proxy(kind, name)` hook, which
`create_compound_server` wires to `forward_prompts()` (merged/deduped for `list`,
first hit for `get`).

```yaml
# compounds.yaml
compounds:
  local:
    path: /mcp/local
    backends: [ipybox, exec]
    headers:
      X-MCP-Endpoint: "http://mcp:8000/mcp/local"
```

| Symbol | Role |
|---|---|
| `prompt_proxy(kind, name)` | `MountedServer` hook delegating `prompts/list` + `prompts/get` to backends |
| `forward_prompts(bc, kind, name)` | proxies a single backend's prompt list/get |

> **Note**: prompt-body templating — e.g. `{{ mcp_list_upstreams() }}` in
> `infra_bootstrap.md` — happens **kernel-side** in the ipybox MCP server, not in
> the gateway. ipybox reads the per-compound `X-MCP-Endpoint` header that the
> gateway forwards, and uses it to call back to the correct compound endpoint.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## Releasing

Manual release flow (the workflow tests/builds/publishes on tag):

1. Bump `version` in `pyproject.toml`, `_version.py`, and `__init__.py`
   (keep them matching).
2. Commit, `git tag vX.Y.Z`, then `git push && git push --tags`.
3. The workflow runs tests and pushes `ghcr.io/prog76/mcp-gateway:vX.Y.Z`.
4. Manually pin the new version in deploy (`.env`: `GATEWAY_VERSION=vX.Y.Z`).
   Packages are installed from git refs, not PyPI.

## Publishing

This tree is the source for `github.com/prog76/mcp_gateway`.
