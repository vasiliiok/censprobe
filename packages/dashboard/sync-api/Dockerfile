# Censprobe Dashboard Sync-API — Dockerfile (M3)
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY packages/probe-core /tmp/probe-core
COPY packages/dashboard/sync-api /tmp/sync-api
RUN pip install --no-cache-dir /tmp/probe-core /tmp/sync-api
RUN mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null
EXPOSE 8080
CMD ["uvicorn", "sync_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
