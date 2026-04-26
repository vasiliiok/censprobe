# Censprobe Control — Dockerfile (M2)
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client curl wget net-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY packages/probe-core /tmp/probe-core
COPY packages/control /tmp/control
RUN pip install --no-cache-dir /tmp/probe-core /tmp/control

# Build-time fallback committer identity. git_io.py reads
# CENSPROBE_GIT_EMAIL / CENSPROBE_GIT_NAME from the runtime env and
# overrides this when invoking git, so operators can keep their own
# identity without rebuilding the image.
ARG CENSPROBE_GIT_EMAIL=noreply@censprobe.local
ARG CENSPROBE_GIT_NAME=censprobe-bot
RUN git config --global user.email "${CENSPROBE_GIT_EMAIL}" && \
    git config --global user.name "${CENSPROBE_GIT_NAME}" && \
    git config --global pull.rebase true && \
    git config --global --add safe.directory '*' && \
    mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null && \
    ssh-keyscan github.com > /tmp/censprobe_known_hosts 2>/dev/null && \
    chmod 0644 /tmp/censprobe_known_hosts
ENTRYPOINT ["python", "-m", "censprobe_control.main"]
