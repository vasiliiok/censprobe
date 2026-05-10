# Censprobe Sync — Dockerfile
#
# Multi-stage: stage 1 fetches the rclone Go binary (verified by upstream
# SHA-256), stage 2 is python:3.11-slim runtime with probe-core + sync
# wheels installed. Sync ships ONLY rclone — no VPN tooling, no openssl
# subprocess wrappers, just one HTTP-serving Go static binary.

# ── Stage 1: fetch rclone binary ─────────────────────────────────────────────
FROM debian:bookworm-slim AS rclone-fetcher

# pipefail so the ``echo SHA  file | sha256sum -c -`` step below fails the
# whole stage if either side errors. Without this, a failed sha256sum would
# still let the unzip+install steps run on an unverified blob.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Pinned to a specific upstream rclone release. Bumping requires updating
# both checksums (linux-amd64 and linux-arm64) — sourced from
# https://downloads.rclone.org/v${VERSION}/SHA256SUMS.
ARG RCLONE_VERSION=1.69.3
ARG RCLONE_SHA256_AMD64=14c841f24de6dfb5b914900b345b02e6a00278ad20e7502041d856a4f1d4e221
ARG RCLONE_SHA256_ARM64=c23f03c11931b2dd4c6ccc091a11ec508f1ca936cc8916ac69669be5b433941c

RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then RCLONE_ARCH=amd64; SHA256="${RCLONE_SHA256_AMD64}"; \
    elif [ "$ARCH" = "arm64" ]; then RCLONE_ARCH=arm64; SHA256="${RCLONE_SHA256_ARM64}"; \
    else RCLONE_ARCH=amd64; SHA256="${RCLONE_SHA256_AMD64}"; fi && \
    curl -fsSL -o /tmp/rclone.zip \
      "https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-${RCLONE_ARCH}.zip" && \
    echo "${SHA256}  /tmp/rclone.zip" | sha256sum -c - && \
    unzip -q /tmp/rclone.zip -d /tmp && \
    install -m 0755 "/tmp/rclone-v${RCLONE_VERSION}-linux-${RCLONE_ARCH}/rclone" /usr/local/bin/rclone && \
    rm -rf /tmp/rclone*

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# rclone needs no runtime deps beyond ca-certificates (TLS to public IP
# echoes during serve-side detect_external_ip; rclone uses CA bundle
# from the system store when --ca-cert isn't passed, which is the
# pull-side path during the initial cert fetch we do in Python). The
# rclone binary itself is fully static.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rclone-fetcher /usr/local/bin/rclone /usr/local/bin/rclone

WORKDIR /tmp
COPY packages/probe-core /tmp/probe-core
COPY packages/sync /tmp/sync
RUN pip install --no-cache-dir /tmp/probe-core /tmp/sync && \
    rm -rf /tmp/probe-core /tmp/sync

ENTRYPOINT ["python", "-m", "censprobe_sync.main"]
