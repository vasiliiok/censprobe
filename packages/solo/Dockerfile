# Censprobe Solo — Dockerfile
# Runs all probe tests from the server's perspective.
#
# Solo never opens a VPN listener and never speaks any tunnel protocol
# (protocols.run_protocol_tests is called with control_endpoints=None and
# returns INCONCLUSIVE). VPN binaries (sing-box / xray / hysteria /
# amneziawg-go / openvpn / wireguard-tools) live only in the client and
# listener images.

FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget openssh-client iputils-ping dnsutils \
    net-tools tcpdump iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install scapy dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy probe-core and solo packages
COPY packages/probe-core /tmp/probe-core
COPY packages/solo /tmp/solo

# Install packages
RUN pip install --no-cache-dir \
    /tmp/probe-core \
    /tmp/solo

# Configure git for commits
RUN git config --global user.email "starvasyaa@gmail.com" && \
    git config --global user.name "censprobe-bot" && \
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
