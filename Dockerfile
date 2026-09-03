# mcp-gateway BASE image — owned by the gateway project.
#
# Contains ONLY what every gateway deployment needs:
#   - system deps + core python deps
#   - pip-installed packages: gateway (policy proxy + exec stdio server)
#     and secure-fox (browser-control MCP server)
#   - chroot tree for shell_exec
#
# Long-running backend MCP servers (k8s, netbox, grafana) are NOT included:
# they run as their own containers, supervised by the orchestrator, and are
# referenced by policy via service URLs. The `browser` service reuses this
# same image with a command override (`securefox-mcp-server`).
#
# Version pinning: GATEWAY_VERSION / SECUREFOX_VERSION accept a git ref —
# a branch name (e.g. `main`, dev mode) or a tag (`v0.2.0`, pinned release).

FROM python:3.12-slim

ARG SHELL_CHROOT_DIR=/opt/shell-chroot
ARG GATEWAY_VERSION=main
ARG SECUREFOX_VERSION=v0.1.1
ARG MCP2CLI_VERSION=v0.1.1

# ------------------------------------------------------------------
# System dependencies
# ------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    openssh-client \
    git \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------
# Core python deps
# ------------------------------------------------------------------
RUN pip install --no-cache-dir \
    "mcp>=1.28.1,<2" \
    "fastmcp>=3.4.2,<4" \
    "jsonschema>=4.0.0" \
    "pyyaml>=6.0" \
    "httpx>=0.27.0" \
    "websockets>=12.0"

# ------------------------------------------------------------------
# Extracted packages (pip from GitHub).
#   github.com/prog76/mcp_mcp2cli     (shared MCP client library)
#   github.com/prog76/mcp_gateway     (this package)
#   github.com/prog76/mcp_secure-fox  (browser backend, own container)
# ------------------------------------------------------------------
RUN pip install --no-cache-dir --no-binary :all: \
    "mcp2cli @ git+https://github.com/prog76/mcp_mcp2cli.git@${MCP2CLI_VERSION}" \
    "gateway @ git+https://github.com/prog76/mcp_gateway.git@${GATEWAY_VERSION}" \
    "secure-fox @ git+https://github.com/prog76/mcp_secure-fox.git@${SECUREFOX_VERSION}"

# ------------------------------------------------------------------
# Directories
# ------------------------------------------------------------------
RUN mkdir -p /var/mcp/workspace /root/.ssh /root/.kube /root/.sandbox/ssh-keys /opt/tools

# ------------------------------------------------------------------
# Chroot tree for shell_exec
# ------------------------------------------------------------------
RUN mkdir -p "${SHELL_CHROOT_DIR}" \
    && cp -a /bin "${SHELL_CHROOT_DIR}/" \
    && cp -a /lib "${SHELL_CHROOT_DIR}/" \
    && cp -a /lib64 "${SHELL_CHROOT_DIR}/" 2>/dev/null || true \
    && cp -a /usr "${SHELL_CHROOT_DIR}/" \
    && if [ -d /lib/x86_64-linux-gnu ]; then cp -a /lib/x86_64-linux-gnu "${SHELL_CHROOT_DIR}/lib/"; fi \
    && if [ -d /usr/lib/x86_64-linux-gnu ]; then cp -a /usr/lib/x86_64-linux-gnu "${SHELL_CHROOT_DIR}/usr/lib/"; fi \
    && mkdir -p "${SHELL_CHROOT_DIR}/etc/ssl" "${SHELL_CHROOT_DIR}/etc/ssl/certs" \
    && cp -a /etc/ssl/certs "${SHELL_CHROOT_DIR}/etc/ssl/certs" 2>/dev/null || true \
    && cp -a /etc/passwd "${SHELL_CHROOT_DIR}/etc/passwd" 2>/dev/null || true \
    && cp -a /etc/group "${SHELL_CHROOT_DIR}/etc/group" 2>/dev/null || true \
    && cp -a /etc/resolv.conf "${SHELL_CHROOT_DIR}/etc/resolv.conf" 2>/dev/null || true \
    && cp -a /etc/hosts "${SHELL_CHROOT_DIR}/etc/hosts" 2>/dev/null || true \
    && mkdir -p "${SHELL_CHROOT_DIR}/tmp" \
    && chmod 1777 "${SHELL_CHROOT_DIR}/tmp" \
    && mkdir -p "${SHELL_CHROOT_DIR}/var/mcp" \
    && mkdir -p "${SHELL_CHROOT_DIR}/dev" \
    && mknod -m 666 "${SHELL_CHROOT_DIR}/dev/null" c 1 3 \
    && mknod -m 666 "${SHELL_CHROOT_DIR}/dev/zero" c 1 5 \
    && mknod -m 666 "${SHELL_CHROOT_DIR}/dev/urandom" c 1 9 \
    && mknod -m 666 "${SHELL_CHROOT_DIR}/dev/random" c 1 8

EXPOSE 8000

# Entrypoint ships in the mcp-gateway package.
ENTRYPOINT ["mcp-gateway-start"]