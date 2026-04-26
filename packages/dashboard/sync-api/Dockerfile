# Censprobe Dashboard Sync-API
FROM python:3.12-slim

# git + openssh-client are required by sync_api → probe-core.git_io which
# shells out to `git pull --rebase` over SSH (deploy key mounted from host).
RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install probe-core + sync-api from local copies (monorepo). Wipe the
# build copies afterwards so they don't bloat the image — the wheels are
# already installed under site-packages.
COPY packages/probe-core /tmp/probe-core
COPY packages/dashboard/sync-api /tmp/sync-api
RUN pip install --no-cache-dir /tmp/probe-core /tmp/sync-api \
    && rm -rf /tmp/probe-core /tmp/sync-api

# - safe.directory='*': /workspace is bind-mounted from the host with
#   a different UID, and recent git refuses to operate on such repos.
# - /tmp/censprobe_known_hosts: probe-core.git_io points
#   GIT_SSH_COMMAND -o UserKnownHostsFile here so accept-new works
#   even when ~/.ssh is mounted read-only.
RUN git config --global --add safe.directory '*' && \
    mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null && \
    ssh-keyscan github.com > /tmp/censprobe_known_hosts 2>/dev/null && \
    chmod 0644 /tmp/censprobe_known_hosts

EXPOSE 8080
CMD ["uvicorn", "sync_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
