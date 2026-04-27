# Censprobe Solo — Dockerfile
#
# Solo runs all probe tests from the server's perspective. It never opens a
# VPN listener and never speaks any tunnel protocol (protocols.run_protocol_tests
# is called with control_endpoints=None → INCONCLUSIVE). VPN binaries live only
# in the client and listener images.
#
# Multi-stage build: the first stage compiles curl against BoringSSL so that
# TLS ECH probing (_test_ech in modules/tls.py) actually works.
#
# Why BoringSSL and not mainline OpenSSL?
#   curl's ECH support (--enable-ech, USE_ECH) is written against the
#   BoringSSL API (SSL_set1_ech_config_list, SSL_set_enable_ech_grease).
#   Mainline OpenSSL has not merged ECH as of 2025; community forks (sftcd)
#   use different function names that are incompatible with curl's ECH code.
#   BoringSSL is the only SSL library where 'curl -V | grep ECH' works on Linux.

# ── Stage 1: curl-ech ────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252 AS curl-ech-builder

# BoringSSL main branch commit (pinned for reproducibility).
ARG BORINGSSL_COMMIT=151cf73e7e8f939424d19b2a5b0575787c721297
ARG CURL_VERSION=8.12.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build golang-go \
    wget ca-certificates pkg-config zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Build BoringSSL (static libs only).
# curl's ECH support requires:
#   SSL_set1_ech_config_list, SSL_set_enable_ech_grease,
#   SSL_ech_set1_server_names, SSL_ech_get1_status, SSL_ech_accepted
# All of these exist in BoringSSL.
RUN set -eux; \
    wget -q "https://github.com/google/boringssl/archive/${BORINGSSL_COMMIT}.tar.gz" \
         -O /tmp/boringssl.tar.gz; \
    tar -xzf /tmp/boringssl.tar.gz -C /tmp; \
    mkdir -p /tmp/boringssl-${BORINGSSL_COMMIT}/build; \
    cd /tmp/boringssl-${BORINGSSL_COMMIT}/build; \
    cmake -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=0 \
        ..; \
    ninja ssl crypto; \
    mkdir -p /opt/boringssl/lib/pkgconfig; \
    find . -name 'libssl.a' -o -name 'libcrypto.a' | xargs cp -t /opt/boringssl/lib/; \
    cp -r /tmp/boringssl-${BORINGSSL_COMMIT}/include /opt/boringssl/; \
    printf 'Name: OpenSSL\nDescription: BoringSSL\nVersion: 3.0.0\nLibs: -L/opt/boringssl/lib -lssl -lcrypto -lpthread\nCflags: -I/opt/boringssl/include\n' \
        > /opt/boringssl/lib/pkgconfig/openssl.pc; \
    rm -rf /tmp/boringssl*

# Build curl, statically linked against BoringSSL, with ECH enabled.
# LIBS: -lpthread needed by BoringSSL's static libcrypto.
# --without-libpsl / --without-libidn2: keep the build self-contained.
# --disable-*: strip protocols the probe doesn't need; keeps the binary small.
RUN set -eux; \
    wget -q "https://curl.se/download/curl-${CURL_VERSION}.tar.gz" \
         -O /tmp/curl.tar.gz; \
    tar -xzf /tmp/curl.tar.gz -C /tmp; \
    cd /tmp/curl-${CURL_VERSION}; \
    PKG_CONFIG_PATH="/opt/boringssl/lib/pkgconfig" \
    LIBS="-lstdc++ -lpthread" \
    ./configure \
        --prefix=/opt/curl-ech \
        --with-openssl=/opt/boringssl \
        --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt \
        --without-libpsl \
        --without-libidn2 \
        --disable-shared \
        --enable-ech \
        --disable-ldap --disable-ldaps \
        --disable-rtsp --disable-dict \
        --disable-telnet --disable-tftp \
        --disable-pop3 --disable-imap \
        --disable-smtp --disable-gopher \
        --disable-mqtt \
        --disable-manual; \
    make -j"$(nproc)"; \
    make install; \
    rm -rf /tmp/curl*

# Guard: fail the build if ECH didn't make it into the binary, rather than
# silently shipping a curl-ech that always returns INCONCLUSIVE at runtime.
RUN /opt/curl-ech/bin/curl -V \
    && /opt/curl-ech/bin/curl -V | grep -i "Features:" | grep -iq " ECH "

# ── Stage 2: runtime image ───────────────────────────────────────────────────
FROM python:3.12-slim@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3

# Install system dependencies. Only what the Python code actually needs:
#   git + openssh-client + curl/wget — for git pull/push over SSH+HTTPS
#   ca-certificates — TLS to httpx targets
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Drop the ECH-capable curl alongside the system curl. The probe code
# (_curl_supports_ech in modules/tls.py) checks "curl-ech" first and only
# falls back to "curl" if curl-ech is absent or lacks the ECH feature flag.
COPY --from=curl-ech-builder /opt/curl-ech/bin/curl /usr/local/bin/curl-ech

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
