# mcp-gateway

MCP policy proxy with enforcement + compound endpoints.

Adapted from the original `policy-proxy/mcp` package for distribution as an
independent pip package. Depends on `mcp2cli` and `skills-server` (via pip)
for the shared MCP client library and the skills MCP server.

## What this package provides

| Module | Purpose |
|---|---|
| `gateway.policy_proxy` | Core policy enforcement + compound endpoint aggregator (the FastMCP/Starlette app) |
| `gateway.mounted_server` | `MountedServer` — an MCP server mountable at a path in a Starlette app |
| `gateway.policy_yaml` | `PolicyLoader` — SafeLoader extended with a `!concat` tag |
| `gateway.validate_policy` | Policy file validator |
| `gateway.mcp_onboard` | Onboarding helper that generates starter policy YAML from discovered tools |
| `gateway.foxmcp_server` | Secure FoxMCP server (browser control via Firefox extension) |
| `gateway.foxmcp_vendored` | Vendored upstream FoxMCP server package |
| `gateway.start` | Container entrypoint that reproduces `start.sh` behavior |

## Console script

```
mcp-gateway-start
```

This starts the background MCP servers (k8s, netbox, foxmcp, skills) and then
runs the policy proxy in the foreground — the same behavior as the original
`start.sh`.

Environment variables:

| Variable | Default |
|---|---|
| `POLICY_DIR` | `/etc/mcp-gateways/policy` |
| `KUBECONFIG_PATH` | `/root/.kube/k3s.yaml` |
| `POLICY_PROXY_PORT` | `8000` |
| `POLICY_PROXY_HOST` | `0.0.0.0` |
| `VALIDATE_POLICY_PATH` | `/opt/validate_policy.py` |
| `COMPOUNDS_CONFIG` | `/etc/mcp-gateways/compounds.yaml` |
| `NOTIFICATION_CONFIG` | `/etc/mcp-gateways/notifications.yaml` |

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## Publishing

This tree is the source for `github.com/prog76/mcp_gateway`.