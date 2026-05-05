# Censprobe Dashboard Sync-API
FROM python@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install probe-core + sync-api from local copies (monorepo). Wipe the
# build copies afterwards so they don't bloat the image — the wheels are
# already installed under site-packages. The user is created in the same
# RUN so Sonar S7031 doesn't flag two consecutive RUN layers.
COPY packages/probe-core /tmp/probe-core
COPY packages/dashboard/sync-api /tmp/sync-api
RUN pip install --no-cache-dir /tmp/probe-core /tmp/sync-api \
    && rm -rf /tmp/probe-core /tmp/sync-api \
    && groupadd -r --gid 10001 syncapi \
    && useradd -r --uid 10001 --gid 10001 -M syncapi

# Run as a dedicated non-root user. sync-api only needs read access to
# /workspace (mounted RO at runtime via docker-compose) plus an outbound
# connection to Postgres — no privileged operations, no caps, no host
# networking. Dropping root removes the entire post-RCE privilege-
# escalation path through this container.
#
# python:3.12-slim already ships a system user named `sync` (the
# legacy /bin/sync utility). Pick a distinct name to avoid the
# useradd collision. UID 1000 is a common host-side default, so use
# 10001 instead — out of the ranges any host operator is likely
# claiming.
USER syncapi

EXPOSE 8080
CMD ["uvicorn", "sync_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
