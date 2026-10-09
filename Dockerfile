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
# mcp2cli is pinned transitively via the dependency declared in pyproject.toml
# (so a single spec is the source of truth and pip never sees a conflict).

ARG PYTHON_SLIM_BASE=python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f
FROM ${PYTHON_SLIM_BASE}

# ------------------------------------------------------------------
# System dependencies -- CANONICAL APT PREAMBLE (byte-identical across
# images so the apt layer is shared). Order matters: keep it verbatim.
# ------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*
# ------------------------------------------------------------------
# Core python deps
# ------------------------------------------------------------------
# Shared layers -- byte-identical across images so BuildKit reuses them.
# TRACK A (gateway/sandbox/secure-fox): fastmcp 3.x, mcp 1.x. Frozen from
# the live mcp-gateway container (pip freeze, 2026-10).
RUN pip install --no-cache-dir httpx==0.28.1
RUN pip install --no-cache-dir PyYAML==6.0.3
RUN pip install --no-cache-dir websockets==17.1
RUN pip install --no-cache-dir fastmcp==3.4.7
RUN pip install --no-cache-dir mcp==1.30.0
RUN pip install --no-cache-dir jsonschema==4.26.0

ARG SHELL_CHROOT_DIR=/opt/shell-chroot
ARG GATEWAY_VERSION=main
ARG SECUREFOX_VERSION=v0.1.5

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------
# kubectl + virtctl (used by the exec backend for k8s/kubevirt ops)
# ------------------------------------------------------------------
ARG KUBECTL_VERSION=1.32.0
RUN curl -fsSL "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
        -o /usr/local/bin/kubectl && \
    chmod +x /usr/local/bin/kubectl

ARG VIRTCTL_VERSION=v1.4.0
RUN curl -fsSL "https://github.com/kubevirt/kubevirt/releases/download/${VIRTCTL_VERSION}/virtctl-${VIRTCTL_VERSION}-linux-amd64" \
        -o /usr/local/bin/virtctl && \
    chmod +x /usr/local/bin/virtctl

# ------------------------------------------------------------------
# pexpect — needed for virtctl console interaction via exec backend
# ------------------------------------------------------------------
RUN pip install --no-cache-dir pexpect

# ------------------------------------------------------------------
# Extracted packages (pip from GitHub).
#   github.com/prog76/mcp_gateway     (this package)
#   github.com/prog76/mcp_secure-fox  (browser backend, own container)
# mcp2cli is pulled in transitively by gateway (pinned in pyproject.toml).
# ------------------------------------------------------------------
RUN pip install --no-cache-dir --no-binary :all: \
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
