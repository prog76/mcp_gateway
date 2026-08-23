# mcp-gateway image — owned by the gateway project.
#
# Base for deploy: system deps + upstream MCP server binaries (k8s, netbox,
# grafana) + core python deps + chroot tree + pip-installed packages:
#   - gateway        (policy_proxy, exec_mcp_server, start entrypoint)
#   - secure-fox     (browser-control MCP server, launched by start.py via
#                     its `securefox-mcp-server` console script; referenced
#                     only through policy, never imported by gateway)
# Nothing is COPYed from a data tree — runtime config is bind-mounted by
# docker-compose in ../deploy.

FROM python:3.12-slim

ARG SHELL_CHROOT_DIR=/opt/shell-chroot

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
# Upstream MCP servers
# ------------------------------------------------------------------
ARG K8S_MCP_VERSION=v0.0.62
RUN curl -fsSL "https://github.com/containers/kubernetes-mcp-server/releases/download/${K8S_MCP_VERSION}/kubernetes-mcp-server-linux-amd64" \
    -o /usr/local/bin/kubernetes-mcp-server \
    && chmod +x /usr/local/bin/kubernetes-mcp-server

ARG NETBOX_MCP_VERSION=v1.2.0
RUN pip install --no-cache-dir git+https://github.com/netboxlabs/netbox-mcp-server.git@${NETBOX_MCP_VERSION}

ARG GRAFANA_MCP_VERSION=v0.17.2
RUN curl -fsSL "https://github.com/grafana/mcp-grafana/releases/download/${GRAFANA_MCP_VERSION}/mcp-grafana_Linux_x86_64.tar.gz" \
    -o /tmp/mcp-grafana.tar.gz \
    && tar -xzf /tmp/mcp-grafana.tar.gz -C /usr/local/bin \
    && chmod +x /usr/local/bin/mcp-grafana

# ------------------------------------------------------------------
# Core python deps
# ------------------------------------------------------------------
RUN pip install --no-cache-dir \
    fastmcp>=2.0.0 \
    jsonschema>=4.0.0 \
    pyyaml>=6.0 \
    httpx>=0.27.0 \
    websockets>=12.0

# ------------------------------------------------------------------
# Extracted packages (pip from GitHub).
#   github.com/prog76/mcp_mcp2cli    (shared MCP client library)
#   github.com/prog76/mcp_gateway    (this package)
#   github.com/prog76/mcp_secure-fox (browser backend, console-script launched)
#
# Pin exact tags here when consuming released versions, e.g.
#   "gateway @ git+https://github.com/prog76/mcp_gateway.git@vX.Y.Z"
# ------------------------------------------------------------------
RUN pip install --no-cache-dir --no-binary :all: \
    "mcp2cli @ git+https://github.com/prog76/mcp_mcp2cli.git" \
    "gateway @ git+https://github.com/prog76/mcp_gateway.git" \
    "secure-fox @ git+https://github.com/prog76/mcp_secure-fox.git"

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

EXPOSE 8000 9001 9002 9003 9004 9005 8765

# Entrypoint ships in the mcp-gateway package.
ENTRYPOINT ["mcp-gateway-start"]