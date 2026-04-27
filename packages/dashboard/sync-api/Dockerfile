# Censprobe Dashboard Sync-API
FROM python:3.12-slim@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install probe-core + sync-api from local copies (monorepo). Wipe the
# build copies afterwards so they don't bloat the image — the wheels are
# already installed under site-packages.
COPY packages/probe-core /tmp/probe-core
COPY packages/dashboard/sync-api /tmp/sync-api
RUN pip install --no-cache-dir /tmp/probe-core /tmp/sync-api \
    && rm -rf /tmp/probe-core /tmp/sync-api

EXPOSE 8080
CMD ["uvicorn", "sync_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
