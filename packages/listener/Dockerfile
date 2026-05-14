# Censprobe Listener — Dockerfile
# Installs all VPN binaries needed for handshake testing.
#
# Multi-stage build: Stage 1 compiles amneziawg-tools (awg, awg-quick) and
# amneziawg-go using Go + build-essential. Those toolchains are ~600 MB and
# serve no runtime purpose, so only the three resulting binaries are copied
# into the final image.

# ── Stage 1: build AmneziaWG tools and userspace implementation ──────────────
FROM golang@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS awg-builder

# GOTOOLCHAIN=auto: if amneziawg-go's go.mod requires a newer patch than the
# base image ships, Go downloads it automatically instead of aborting.
ENV GOTOOLCHAIN=auto

# build-essential: C compiler for amneziawg-tools (awg.c + libmnl).
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libmnl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# AmneziaWG upstream commits — pinned so a future force-push or breaking
# change to master can't silently switch the build to a different tree.
# Bump these explicitly when the maintainers tag a new release.
ARG AWG_TOOLS_COMMIT=5d6179a6d0842e98dfb349c28cf1bd8e4b9d1079
ARG AWG_GO_COMMIT=12a012205e3c444be02aba91a840455f74c127e1

# Build amneziawg-tools → /usr/local/bin/awg + awg-quick.
# A wg-quick fallback is NOT acceptable: vanilla wg rejects the obfuscation
# directives (Jc/Jmin/Jmax/S1/S2/H1-H4) with "Line unrecognized", so AWG
# would be silently non-functional while reporting success.
RUN git clone https://github.com/amnezia-vpn/amneziawg-tools.git /tmp/awg-tools && \
    git -C /tmp/awg-tools checkout "${AWG_TOOLS_COMMIT}" && \
    make -C /tmp/awg-tools/src -j"$(nproc)" && \
    install -m 0755 /tmp/awg-tools/src/wg /usr/local/bin/awg && \
    install -m 0755 /tmp/awg-tools/src/wg-quick/linux.bash /usr/local/bin/awg-quick && \
    rm -rf /tmp/awg-tools

# Build amneziawg-go → /usr/local/bin/amneziawg-go.
# hadolint ignore=DL3003
RUN git clone https://github.com/amnezia-vpn/amneziawg-go.git /tmp/awg-go && \
    git -C /tmp/awg-go checkout "${AWG_GO_COMMIT}" && \
    cd /tmp/awg-go && make && \
    install -m 0755 amneziawg-go /usr/local/bin/amneziawg-go && \
    rm -rf /tmp/awg-go /root/.cache/go-build /root/go

# Build mtg (MTProto-proxy) → /usr/local/bin/mtg.
# mtg has no Makefile; the upstream Dockerfile uses `go build` directly.
# Pinned to v2.1.7 (releases tagged in the repo) so a future force-push or
# breaking change to master can't silently switch the build to a different tree.
ARG MTG_COMMIT=269852a4f1287ef10762a0d27b1f2605532804c1
# hadolint ignore=DL3003
RUN git clone https://github.com/9seconds/mtg.git /tmp/mtg && \
    git -C /tmp/mtg checkout "${MTG_COMMIT}" && \
    cd /tmp/mtg && \
    CGO_ENABLED=0 go build \
        -trimpath \
        -mod=readonly \
        -ldflags="-extldflags '-static' -s -w -X 'main.version=${MTG_COMMIT}'" \
        -tags netgo \
        -o mtg && \
    install -m 0755 mtg /usr/local/bin/mtg && \
    rm -rf /tmp/mtg /root/.cache/go-build /root/go

# ── Stage: build TelegramMessenger/MTProxy (original C MTProxy) ──────────────
# Built in its own stage because it needs a C toolchain + libssl-dev + zlib1g-dev,
# which we don't want lingering in the final runtime image. The resulting
# /usr/local/bin/mtproto-proxy is statically friendly enough that copying it
# into the runtime image with libssl3 + zlib1g installed at apt-time is enough.
FROM debian:bookworm-slim AS mtproxy-orig-builder

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    libssl-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Pin upstream MTProxy commit. ``cafc3380…`` is the master HEAD as of
# this image build; bump explicitly when re-syncing.
ARG MTPROXY_ORIG_COMMIT=cafc3380a81671579ce366d0594b9a8e450827e9
# hadolint ignore=DL3003
RUN git clone https://github.com/TelegramMessenger/MTProxy.git /tmp/mtproxy && \
    git -C /tmp/mtproxy checkout "${MTPROXY_ORIG_COMMIT}" && \
    cd /tmp/mtproxy && make && \
    install -m 0755 objs/bin/mtproto-proxy /usr/local/bin/mtproto-proxy && \
    rm -rf /tmp/mtproxy

# Telegram cloud topology files — required runtime artifacts. Per upstream
# README they "may change occasionally; update once per day". Baked at
# image-build time; refresh via a rebuild on the cadence the operator chooses.
# ADD (instead of curl) keeps the build-time TLS guarantee inside Docker's own
# fetcher and avoids the curl-redirect-to-http hotspot (sonar docker:S6506).
ADD https://core.telegram.org/getProxySecret /usr/local/share/mtproxy-orig/proxy-secret
ADD https://core.telegram.org/getProxyConfig /usr/local/share/mtproxy-orig/proxy-multi.conf

# ── Stage 2: runtime image ───────────────────────────────────────────────────
FROM python@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Runtime tools only — no Go, no build-essential, no git/openssh-client:
# the listener never pushes or pulls anything from a remote — operators
# run `git push` from the host when ready to publish reports.
#
# libssl3 + zlib1g are required at runtime by the original C
# mtproto-proxy binary (compiled in mtproxy-orig-builder stage above).
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    iptables \
    libssl3 \
    net-tools \
    openssl \
    openvpn \
    unzip \
    util-linux \
    wget \
    wireguard-tools \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*
# util-linux is load-bearing here, not just convenience: it provides the
# ``setpriv`` binary that ``censprobe_core._privsep.with_privsep`` wraps
# every tunnel-binary spawn (xray / sing-box / hysteria / mtg) with so
# an RCE inside those parsers can't inherit the listener's root + NET_ADMIN
# bounding set. The privsep helper falls back to a no-op when setpriv is
# missing, which would silently re-introduce the CVE surface; explicit
# install here closes that gap. Pinned to whatever debian:stable ships
# — setpriv's CLI is stable across versions, no version constraint
# needed.

# ── sing-box (Shadowsocks 2022 inbound) ──────────────────────────────────────
ARG SINGBOX_VERSION=1.9.4
ARG SINGBOX_SHA256_AMD64=b2fac8322e036d81bf4e0a145987e02d8e0173a5249c0c51a3cde0d33f78c76c
ARG SINGBOX_SHA256_ARM64=9e9a07643e479961e34909ed6d73010eb9e657f3163369e5bc87b2d18f0a034e
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then SINGBOX_ARCH=amd64; SHA256="${SINGBOX_SHA256_AMD64}"; \
    elif [ "$ARCH" = "arm64" ]; then SINGBOX_ARCH=arm64; SHA256="${SINGBOX_SHA256_ARM64}"; \
    else SINGBOX_ARCH=amd64; SHA256="${SINGBOX_SHA256_AMD64}"; fi && \
    curl -fsSL -o /tmp/sing-box.tar.gz \
      "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SINGBOX_ARCH}.tar.gz" && \
    echo "${SHA256}  /tmp/sing-box.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/sing-box.tar.gz -C /tmp && \
    mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-${SINGBOX_ARCH}/sing-box" /usr/local/bin/sing-box && \
    chmod +x /usr/local/bin/sing-box && \
    rm -rf /tmp/sing-box*

# ── xray-core (VLESS+Reality inbound) ────────────────────────────────────────
ARG XRAY_VERSION=1.8.13
ARG XRAY_SHA256_AMD64=2e4514670c001380992cc8de351fd9c7c73c8040f4b789c0108645a7ce0ab0e6
ARG XRAY_SHA256_ARM64=9249fe318fb6cc72d091abd773177e2e2c602be1828339d6b4e9183d2fc8ec49
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then XRAY_ARCH=64; SHA256="${XRAY_SHA256_AMD64}"; \
    elif [ "$ARCH" = "arm64" ]; then XRAY_ARCH=arm64-v8a; SHA256="${XRAY_SHA256_ARM64}"; \
    else XRAY_ARCH=64; SHA256="${XRAY_SHA256_AMD64}"; fi && \
    curl -fsSL -o /tmp/xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip" && \
    echo "${SHA256}  /tmp/xray.zip" | sha256sum -c - && \
    unzip -q /tmp/xray.zip -d /tmp/xray && \
    mv /tmp/xray/xray /usr/local/bin/xray && \
    chmod +x /usr/local/bin/xray && \
    rm -rf /tmp/xray*

# ── hysteria 2 (QUIC/UDP inbound) ────────────────────────────────────────────
ARG HYSTERIA_VERSION=2.5.2
ARG HYSTERIA_SHA256_AMD64=3a1a9a46bfbcd2adfd0825dd59d51a26a884b9a9917a8e83a6161cb260bcaed9
ARG HYSTERIA_SHA256_ARM64=917037c193281eff067d017ecc958bfeeb8f94673feae8fed122795a2400e0c4
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then HY_ARCH=amd64; SHA256="${HYSTERIA_SHA256_AMD64}"; \
    elif [ "$ARCH" = "arm64" ]; then HY_ARCH=arm64; SHA256="${HYSTERIA_SHA256_ARM64}"; \
    else HY_ARCH=amd64; SHA256="${HYSTERIA_SHA256_AMD64}"; fi && \
    curl -fsSL -o /usr/local/bin/hysteria \
      "https://github.com/apernet/hysteria/releases/download/app%2Fv${HYSTERIA_VERSION}/hysteria-linux-${HY_ARCH}" && \
    echo "${SHA256}  /usr/local/bin/hysteria" | sha256sum -c - && \
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
    /usr/local/bin/mtg \
    /usr/local/bin/

# ── Original Telegram MTProxy (C) — binary + cloud topology files ────────────
# proxy-secret + proxy-multi.conf are required positional/argv inputs to the
# C binary; they're baked at image build time and refreshed on rebuild.
COPY --from=mtproxy-orig-builder \
    /usr/local/bin/mtproto-proxy \
    /usr/local/bin/
COPY --from=mtproxy-orig-builder \
    /usr/local/share/mtproxy-orig \
    /usr/local/share/mtproxy-orig

ENV WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go

# ── Python packages ───────────────────────────────────────────────────────────
WORKDIR /workspace

COPY packages/probe-core /tmp/probe-core
COPY packages/listener /tmp/listener

RUN pip install --no-cache-dir /tmp/probe-core /tmp/listener

ENTRYPOINT ["python", "-m", "censprobe_listener.main"]
