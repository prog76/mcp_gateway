# AGENTS.md

Guidance for coding agents working in this repository.

## What this is
`gateway` — an MCP **policy proxy**: enforces allow/deny rules per backend and
aggregates backends into compound endpoints. It spawns no long-running child
processes; backend MCP servers run as their own containers (see the `deploy`
repo) and are referenced by service URL in policy YAML.

## Layout
- `gateway/` — package source (`policy_proxy`, `mounted_server`, `policy_yaml`,
  `validate_policy`, `mcp_onboard`, `exec_mcp_server`, `start` entrypoint)
- `tests/` — pytest suite
- `Dockerfile` — base image (gateway + secure-fox packages, chroot tree)
- `.github/workflows/test-publish.yml` — CI: tests on push; on `v*` tags pushes
  `ghcr.io/prog76/mcp-gateway:<tag>`

## Commands
```bash
pip install -e ".[dev]"
python3 -m pytest -v          # from repo root
```

## Conventions
- Pure Python 3.10+, stdlib style; no linter config enforced.
- The gateway must stay independent of specific backends: never add k8s/netbox/
  grafana/secure-fox imports here. Backends are policy entries, not code deps.
- `exec` is a stdio server spawned per-request by `policy_proxy` — that stays.

## Releasing
1. Bump version in `pyproject.toml`, `_version.py`, `__init__.py` (keep equal).
2. Commit, `git tag vX.Y.Z`, `git push && git push --tags`.
3. CI publishes the image; then bump `GATEWAY_VERSION` in the deploy repo `.env`.

See `README.md` for architecture details (compounds, header injection).