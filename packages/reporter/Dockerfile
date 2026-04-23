# Censprobe Reporter — Dockerfile (M7)
FROM python:3.12-slim

# WeasyPrint deps (fonts + Pango + Cairo for PDF rendering)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf2.0-0 \
    libffi-dev shared-mime-info fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY packages/probe-core /tmp/probe-core
COPY packages/reporter /tmp/reporter

RUN pip install --no-cache-dir /tmp/probe-core /tmp/reporter

# Copy templates so they're accessible from the package
COPY packages/reporter/templates /tmp/reporter/templates

ENTRYPOINT ["censprobe-report"]
