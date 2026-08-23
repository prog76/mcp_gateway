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
> (`github.com/prog76/mcp_secure-fox`). It is installed into the image and
> launched by its console script `securefox-mcp-server`; the gateway proxies
> to it via policy (`deploy/config/policy/real/browser.yaml`) and does not
> import it.

## Console script

```
mcp-gateway-start
```

This starts the background MCP servers (k8s, netbox, secure-fox) and then
runs the policy proxy in the foreground — the same behavior as the original
`start.sh`. The exec backend is a stdio MCP server spawned on-demand by the
proxy.

## Environment variables

| Variable | Default |
|---|---|
| `POLICY_DIR` | `/etc/mcp-gateways/policy` |
| `KUBECONFIG_PATH` | `/root/.kube/k3s.yaml` |
| `POLICY_PROXY_PORT` | `8000` |
| `POLICY_PROXY_HOST` | `0.0.0.0` |
| `VALIDATE_POLICY_PATH` | `/opt/validate_policy.py` |
| `COMPOUNDS_CONFIG` | `/etc/mcp-gateways/compounds.yaml` |
| `NOTIFICATION_CONFIG` | `/etc/mcp-gateways/notifications.yaml` |
| `MCP_REQUEST_HEADER_CAPTURE` | *(empty — disabled)* |

`MCP_REQUEST_HEADER_CAPTURE` — comma-separated list of incoming HTTP header
names to capture from the MCP client request. Captured headers are available
for compound header resolution via `${request_header:NAME}`. Enables
auth-passthrough (e.g. forwarding the client's `Authorization` header to the
downstream backend).

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
3. The workflow runs tests, publishes the wheel/sdist to PyPI (OIDC trusted
   publishing), and pushes `ghcr.io/prog76/mcp-gateway:vX.Y.Z`.
4. Manually pin the new version in `deploy/Dockerfile` (pip refs / image tag).

## Publishing

This tree is the source for `github.com/prog76/mcp_gateway`.
