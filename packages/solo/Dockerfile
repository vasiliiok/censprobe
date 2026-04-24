# Censprobe Solo — Dockerfile
# Runs all probe tests from the server's perspective

FROM python:3.12-slim

# Install system dependencies
# build-essential + golang-go for amneziawg-{tools,go} source builds.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget openssh-client iputils-ping dnsutils \
    net-tools tcpdump iproute2 ca-certificates libssl-dev \
    wireguard-tools iptables openssl openvpn unzip \
    build-essential libmnl-dev pkg-config golang-go \
    && rm -rf /var/lib/apt/lists/*

# Install scapy dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# ── sing-box (Shadowsocks 2022 inbound) ──────────────────────────────────────
ARG SINGBOX_VERSION=1.9.4
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then SINGBOX_ARCH=amd64; \
    elif [ "$ARCH" = "arm64" ]; then SINGBOX_ARCH=arm64; \
    else SINGBOX_ARCH=amd64; fi && \
    curl -fsSL -o /tmp/sing-box.tar.gz \
      "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SINGBOX_ARCH}.tar.gz" && \
    tar -xzf /tmp/sing-box.tar.gz -C /tmp && \
    mv /tmp/sing-box-${SINGBOX_VERSION}-linux-${SINGBOX_ARCH}/sing-box /usr/local/bin/sing-box && \
    chmod +x /usr/local/bin/sing-box && \
    rm -rf /tmp/sing-box*

# ── xray-core (VLESS+Reality inbound) ────────────────────────────────────────
ARG XRAY_VERSION=1.8.13
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then XRAY_ARCH=64; \
    elif [ "$ARCH" = "arm64" ]; then XRAY_ARCH=arm64-v8a; \
    else XRAY_ARCH=64; fi && \
    curl -fsSL -o /tmp/xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip" && \
    unzip -q /tmp/xray.zip -d /tmp/xray && \
    mv /tmp/xray/xray /usr/local/bin/xray && \
    chmod +x /usr/local/bin/xray && \
    rm -rf /tmp/xray*

# ── hysteria 2 (QUIC/UDP inbound) ────────────────────────────────────────────
ARG HYSTERIA_VERSION=2.5.2
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then HY_ARCH=amd64; \
    elif [ "$ARCH" = "arm64" ]; then HY_ARCH=arm64; \
    else HY_ARCH=amd64; fi && \
    curl -fsSL -o /usr/local/bin/hysteria \
      "https://github.com/apernet/hysteria/releases/download/app%2Fv${HYSTERIA_VERSION}/hysteria-linux-${HY_ARCH}" && \
    chmod +x /usr/local/bin/hysteria

# ── AmneziaWG (userspace, amneziawg-go) ──────────────────────────────────────
# See listener Dockerfile for rationale.
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools.git /tmp/awg-tools && \
    make -C /tmp/awg-tools/src -j"$(nproc)" && \
    make -C /tmp/awg-tools/src install && \
    rm -rf /tmp/awg-tools && \
    git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go.git /tmp/awg-go && \
    cd /tmp/awg-go && make && \
    install -m 0755 amneziawg-go /usr/local/bin/amneziawg-go && \
    rm -rf /tmp/awg-go /root/.cache/go-build /root/go

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

# SSH known hosts for GitHub
RUN mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null

# Entrypoint
ENTRYPOINT ["python", "-m", "censprobe_solo.main"]
