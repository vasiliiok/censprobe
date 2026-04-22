# Censprobe Reporter — Dockerfile (M7)
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY packages/probe-core /tmp/probe-core
COPY packages/reporter /tmp/reporter
RUN pip install --no-cache-dir /tmp/probe-core /tmp/reporter
ENTRYPOINT ["python", "-m", "reporter.main"]
