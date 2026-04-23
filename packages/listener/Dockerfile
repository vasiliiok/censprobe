# Censprobe Listener — Dockerfile (M5)
# Installs all VPN binaries needed for handshake testing.

FROM python:3.12-slim AS base

# System tools + VPN protocol binaries (Debian packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client curl wget iproute2 net-tools \
    wireguard-tools iptables openssl openvpn \
    ca-certificates unzip \
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
# Installed from source or official release — using shell script installer
RUN curl -fsSL https://raw.githubusercontent.com/amnezia-vpn/amneziawg-go/master/install.sh \
    -o /tmp/awg-install.sh 2>/dev/null && \
    if [ -f /tmp/awg-install.sh ]; then \
        sh /tmp/awg-install.sh 2>/dev/null || true; \
    fi; \
    rm -f /tmp/awg-install.sh; \
    # If awg-quick not found, create a stub that falls back to wg-quick
    if ! command -v awg-quick >/dev/null 2>&1; then \
        printf '#!/bin/sh\nwg-quick "$@"\n' > /usr/local/bin/awg-quick && \
        chmod +x /usr/local/bin/awg-quick; \
    fi

# ── Python packages ───────────────────────────────────────────────────────────
WORKDIR /workspace

COPY packages/probe-core /tmp/probe-core
COPY packages/listener /tmp/listener

RUN pip install --no-cache-dir /tmp/probe-core /tmp/listener

# ── Git config ────────────────────────────────────────────────────────────────
RUN git config --global user.email "starvasyaa@gmail.com" && \
    git config --global user.name "censprobe-bot" && \
    git config --global pull.rebase true && \
    mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null

ENTRYPOINT ["python", "-m", "censprobe_listener.main"]
