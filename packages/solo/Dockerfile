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
FROM debian@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252 AS curl-ech-builder

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# BoringSSL main branch commit (pinned for reproducibility).
ARG BORINGSSL_COMMIT=151cf73e7e8f939424d19b2a5b0575787c721297
ARG CURL_VERSION=8.12.0

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    golang-go \
    ninja-build \
    pkg-config \
    wget \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Build BoringSSL (static libs only).
# curl's ECH support requires:
#   SSL_set1_ech_config_list, SSL_set_enable_ech_grease,
#   SSL_ech_set1_server_names, SSL_ech_get1_status, SSL_ech_accepted
# All of these exist in BoringSSL.
# hadolint ignore=DL3003
RUN set -eux; \
    wget -q "https://github.com/google/boringssl/archive/${BORINGSSL_COMMIT}.tar.gz" \
         -O /tmp/boringssl.tar.gz; \
    tar -xzf /tmp/boringssl.tar.gz -C /tmp; \
    mkdir -p "/tmp/boringssl-${BORINGSSL_COMMIT}/build"; \
    cd "/tmp/boringssl-${BORINGSSL_COMMIT}/build"; \
    cmake -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=0 \
        ..; \
    ninja ssl crypto; \
    mkdir -p /opt/boringssl/lib/pkgconfig; \
    find . \( -name 'libssl.a' -o -name 'libcrypto.a' \) -print0 \
        | xargs -0 cp -t /opt/boringssl/lib/; \
    cp -r "/tmp/boringssl-${BORINGSSL_COMMIT}/include" /opt/boringssl/; \
    printf 'Name: OpenSSL\nDescription: BoringSSL\nVersion: 3.0.0\n' \
        > /opt/boringssl/lib/pkgconfig/openssl.pc; \
    printf 'Libs: -L/opt/boringssl/lib -lssl -lcrypto -lpthread\n' \
        >> /opt/boringssl/lib/pkgconfig/openssl.pc; \
    printf 'Cflags: -I/opt/boringssl/include\n' \
        >> /opt/boringssl/lib/pkgconfig/openssl.pc; \
    rm -rf /tmp/boringssl*

# Build curl, statically linked against BoringSSL, with ECH enabled.
# LIBS: -lpthread needed by BoringSSL's static libcrypto.
# --without-libpsl / --without-libidn2: keep the build self-contained.
# --disable-*: strip protocols the probe doesn't need; keeps the binary small.
# hadolint ignore=DL3003
RUN set -eux; \
    wget -q "https://curl.se/download/curl-${CURL_VERSION}.tar.gz" \
         -O /tmp/curl.tar.gz; \
    tar -xzf /tmp/curl.tar.gz -C /tmp; \
    cd "/tmp/curl-${CURL_VERSION}"; \
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
FROM python@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3

# Install system dependencies. Only what the Python code actually needs:
#   curl + wget — used by probe modules at runtime (curl-ech is added below)
#   ca-certificates — TLS to httpx targets
# No git or openssh-client: the container never pushes or pulls anything
# from a remote — operators run `git push` from the host on demand.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
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

ENTRYPOINT ["python", "-m", "censprobe_solo.main"]
