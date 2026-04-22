# Censprobe Listener — Dockerfile (M5)
# Implemented in Milestone M5

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client curl wget iproute2 net-tools \
    wireguard-tools iptables \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY packages/probe-core /tmp/probe-core
COPY packages/listener /tmp/listener

RUN pip install --no-cache-dir /tmp/probe-core /tmp/listener

RUN git config --global user.email "starvasyaa@gmail.com" && \
    git config --global user.name "censprobe-bot" && \
    git config --global pull.rebase true && \
    mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null

ENTRYPOINT ["python", "-m", "censprobe_listener.main"]
