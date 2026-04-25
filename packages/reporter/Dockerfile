# Censprobe Reporter — Dockerfile (M7)
# Pin to bookworm: trixie renamed libgdk-pixbuf2.0-0 → libgdk-pixbuf-2.0-0,
# so the unpinned `python:3.12-slim` tag (which now points at trixie) breaks
# this apt-get with "Package 'libgdk-pixbuf2.0-0' has no installation
# candidate". Pinning keeps the WeasyPrint dep set stable across releases.
FROM python:3.12-slim-bookworm

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
