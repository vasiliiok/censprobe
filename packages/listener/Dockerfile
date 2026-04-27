# Censprobe Listener — Dockerfile
# Installs all VPN binaries needed for handshake testing.
#
# Multi-stage build: Stage 1 compiles amneziawg-tools (awg, awg-quick) and
# amneziawg-go using Go + build-essential. Those toolchains are ~600 MB and
# serve no runtime purpose, so only the three resulting binaries are copied
# into the final image.

# ── Stage 1: build AmneziaWG tools and userspace implementation ──────────────
FROM golang:1.24-bookworm AS awg-builder

# GOTOOLCHAIN=auto: if amneziawg-go's go.mod requires a newer patch than the
# base image ships, Go downloads it automatically instead of aborting.
ENV GOTOOLCHAIN=auto

# build-essential: C compiler for amneziawg-tools (awg.c + libmnl).
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential libmnl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build amneziawg-tools → /usr/local/bin/awg + awg-quick.
# A wg-quick fallback is NOT acceptable: vanilla wg rejects the obfuscation
# directives (Jc/Jmin/Jmax/S1/S2/H1-H4) with "Line unrecognized", so AWG
# would be silently non-functional while reporting success.
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools.git /tmp/awg-tools && \
    make -C /tmp/awg-tools/src -j"$(nproc)" && \
    make -C /tmp/awg-tools/src install && \
    rm -rf /tmp/awg-tools

# Build amneziawg-go → /usr/local/bin/amneziawg-go.
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go.git /tmp/awg-go && \
    cd /tmp/awg-go && make && \
    install -m 0755 amneziawg-go /usr/local/bin/amneziawg-go && \
    rm -rf /tmp/awg-go /root/.cache/go-build /root/go

# ── Stage 2: runtime image ───────────────────────────────────────────────────
FROM python:3.12-slim

# Runtime tools only — no Go, no build-essential.
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

# ── AmneziaWG — compiled in Stage 1, only binaries copied ────────────────────
# awg-quick first attempts kernel mode (`ip link add type amneziawg`); on
# failure it falls back to ${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}.
# We pin the value explicitly so the fallback is deterministic and immune
# to a future upstream rename of the default. Containers run without the
# kernel module loaded, so the userspace path is mandatory.
COPY --from=awg-builder \
    /usr/local/bin/awg \
    /usr/local/bin/awg-quick \
    /usr/local/bin/amneziawg-go \
    /usr/local/bin/

ENV WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go

# ── Python packages ───────────────────────────────────────────────────────────
WORKDIR /workspace

COPY packages/probe-core /tmp/probe-core
COPY packages/listener /tmp/listener

RUN pip install --no-cache-dir /tmp/probe-core /tmp/listener

# ── Git config ────────────────────────────────────────────────────────────────
# safe.directory '*' is required because /workspace is bind-mounted from
# the host with different ownership; git 2.35+ aborts with "detected
# dubious ownership" otherwise.
ARG CENSPROBE_GIT_EMAIL=noreply@censprobe.local
ARG CENSPROBE_GIT_NAME=censprobe-bot
RUN git config --global user.email "${CENSPROBE_GIT_EMAIL}" && \
    git config --global user.name "${CENSPROBE_GIT_NAME}" && \
    git config --global pull.rebase true && \
    git config --global --add safe.directory '*' && \
    mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null && \
    ssh-keyscan github.com > /tmp/censprobe_known_hosts 2>/dev/null && \
    chmod 0644 /tmp/censprobe_known_hosts

ENTRYPOINT ["python", "-m", "censprobe_listener.main"]
