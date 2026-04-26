# Censprobe Solo — Dockerfile
# Runs all probe tests from the server's perspective.
#
# Solo never opens a VPN listener and never speaks any tunnel protocol
# (protocols.run_protocol_tests is called with control_endpoints=None and
# returns INCONCLUSIVE). VPN binaries (sing-box / xray / hysteria /
# amneziawg-go / openvpn / wireguard-tools) live only in the client and
# listener images.

FROM python:3.12-slim

# Install system dependencies. Only what the Python code actually needs:
#   git + openssh-client + curl/wget — for git pull/push over SSH+HTTPS
#   ca-certificates — TLS to httpx targets
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy probe-core and solo packages
COPY packages/probe-core /tmp/probe-core
COPY packages/solo /tmp/solo

# Install packages
RUN pip install --no-cache-dir \
    /tmp/probe-core \
    /tmp/solo

# Build-time fallback committer identity. git_io.py reads
# CENSPROBE_GIT_EMAIL / CENSPROBE_GIT_NAME at runtime and overrides
# this when invoking git, so operators can keep their own identity
# without rebuilding the image.
ARG CENSPROBE_GIT_EMAIL=noreply@censprobe.local
ARG CENSPROBE_GIT_NAME=censprobe-bot
RUN git config --global user.email "${CENSPROBE_GIT_EMAIL}" && \
    git config --global user.name "${CENSPROBE_GIT_NAME}" && \
    git config --global init.defaultBranch main && \
    git config --global pull.rebase true && \
    git config --global --add safe.directory '*'

# SSH known hosts for GitHub.
# Also seed a writable copy at /tmp/censprobe_known_hosts — /root/.ssh is
# typically bind-mounted read-only from the host, which prevents SSH from
# appending accept-new entries and can break git over SSH.
RUN mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null && \
    ssh-keyscan github.com > /tmp/censprobe_known_hosts 2>/dev/null && \
    chmod 0644 /tmp/censprobe_known_hosts

# Entrypoint
ENTRYPOINT ["python", "-m", "censprobe_solo.main"]
