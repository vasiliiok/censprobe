# Censprobe Control — Dockerfile (M2)
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client curl wget net-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY packages/probe-core /tmp/probe-core
COPY packages/control /tmp/control
RUN pip install --no-cache-dir "/tmp/probe-core[control]" /tmp/control
RUN git config --global user.email "starvasyaa@gmail.com" && \
    git config --global user.name "censprobe-bot" && \
    git config --global pull.rebase true && \
    git config --global --add safe.directory '*' && \
    mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null && \
    ssh-keyscan github.com > /tmp/censprobe_known_hosts 2>/dev/null && \
    chmod 0644 /tmp/censprobe_known_hosts
ENTRYPOINT ["python", "-m", "censprobe_control.main"]
