# Censprobe Solo — Dockerfile
# Runs all probe tests from the server's perspective

FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    openssh-client \
    iputils-ping \
    dnsutils \
    net-tools \
    tcpdump \
    iproute2 \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install scapy dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create workspace directory
WORKDIR /workspace

# Copy probe-core and solo packages
COPY packages/probe-core /tmp/probe-core
COPY packages/solo /tmp/solo

# Install packages
RUN pip install --no-cache-dir \
    /tmp/probe-core \
    /tmp/solo

# Configure git for commits
RUN git config --global user.email "starvasyaa@gmail.com" && \
    git config --global user.name "censprobe-bot" && \
    git config --global init.defaultBranch main && \
    git config --global pull.rebase true

# SSH known hosts for GitHub
RUN mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null

# Entrypoint
ENTRYPOINT ["python", "-m", "censprobe_solo.main"]
