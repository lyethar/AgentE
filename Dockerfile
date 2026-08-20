# syntax=docker/dockerfile:1
#
# AgentE — reproducible, clone-and-run image.
#
# Multi-stage:
#   1. go-builder  — compiles the Go tools + massdns into /go/bin
#   2. final       — python:3.10-slim runtime with chromium/node/git,
#                    pip + npm + git-clone tools, gowitness, nuclei templates
#
# Build:
#   docker build -t agente .
# Override a pinned version at build time, e.g.:
#   docker build --build-arg NUCLEI_VERSION=v3.3.7 -t agente .
#
# Nothing secret is baked in — API keys are supplied at run time via --env-file.

############################  builder  ############################
FROM golang:1.22-bookworm AS go-builder

# Pinned versions for reproducible builds (override via --build-arg).
ARG SUBFINDER_VERSION=v2.6.6
ARG PUREDNS_VERSION=v2.1.1
ARG HTTPX_VERSION=v1.6.9
ARG NUCLEI_VERSION=v3.3.7
ARG GOSPIDER_VERSION=v1.1.6
ARG KATANA_VERSION=v1.1.0
ARG MASSDNS_REF=master

# NOTE: do NOT set CGO_ENABLED=0 — katana's go-tree-sitter dependency is a CGO
# (C-backed) library and fails to build without cgo. The builder and the final
# runtime are both Debian bookworm (glibc), so dynamically-linked binaries copied
# from here run fine in the slim runtime.
ENV GOBIN=/go/bin

# ProjectDiscovery + community Go tools.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
 && go install -v github.com/d3mondev/puredns/v2@${PUREDNS_VERSION} \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
 && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
 && go install -v github.com/jaeles-project/gospider@${GOSPIDER_VERSION} \
 && go install -v github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}

# massdns — puredns shells out to it for high-throughput DNS resolution.
# Without it, Stage 2 (puredns resolve) fails. Build from source into /go/bin.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git make gcc libc-dev \
 && git clone --depth 1 --branch ${MASSDNS_REF} https://github.com/blechschmidt/massdns /tmp/massdns \
 && make -C /tmp/massdns \
 && cp /tmp/massdns/bin/massdns /go/bin/massdns \
 && rm -rf /tmp/massdns /var/lib/apt/lists/*

#############################  final  #############################
FROM python:3.10-slim-bookworm AS final

# gowitness release binary (pinned). A checksum can be enforced by passing
# GOWITNESS_SHA256; when empty the download proceeds with a warning.
ARG GOWITNESS_VERSION=3.0.5
ARG GOWITNESS_SHA256=""
ARG TARGETARCH=amd64

# tools/bin holds the git-clone wrappers; put it (and /usr/local/bin) first.
ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/app/tools/bin:/usr/local/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Point ProjectDiscovery/gowitness at the system chromium.
    CHROME_PATH="/usr/bin/chromium" \
    GOWITNESS_CHROME_PATH="/usr/bin/chromium"

# System deps: chromium (gowitness screenshots), node/npm (prettier),
# git (install_tools.py clone), plus TLS roots and fetch/unzip helpers.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      chromium \
      nodejs \
      npm \
      git \
      ca-certificates \
      curl \
      unzip \
 && rm -rf /var/lib/apt/lists/*

# Go tools + massdns from the builder stage.
COPY --from=go-builder /go/bin/ /usr/local/bin/

WORKDIR /app

# Python deps first (better layer caching). requirements.txt = AgentE's own deps;
# the second install adds the pip-ecosystem recon tools.
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt \
 && pip install \
      subscraper \
      bbot \
      dnsgen \
      waymore \
      semgrep \
      tavily-python \
 && pip check || true
# NOTE: cloud_enum is intentionally NOT pip-installed — the PyPI "cloud-enum"
# package is an empty placeholder. The real tool is cloned by install_tools.py
# below (it is a MANAGED_TOOLS git-clone entry).

# Prettier (optional JS beautifier used by Stage 5).
RUN npm install -g prettier

# gowitness (Stage 3 screenshots). Pinned + optional checksum verification.
RUN set -eux; \
    url="https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/gowitness-${GOWITNESS_VERSION}-linux-${TARGETARCH}"; \
    curl -fsSL -o /usr/local/bin/gowitness "$url"; \
    if [ -n "${GOWITNESS_SHA256}" ]; then \
      echo "${GOWITNESS_SHA256}  /usr/local/bin/gowitness" | sha256sum -c -; \
    else \
      echo "WARNING: GOWITNESS_SHA256 not set — skipping checksum verification"; \
    fi; \
    chmod +x /usr/local/bin/gowitness; \
    gowitness version

# AgentE source (kept after the dependency layers so code edits don't bust them).
COPY . .

# Ensure the entrypoint is executable regardless of the source checkout's file
# mode (e.g. cloned on Windows where the +x bit may be lost).
RUN chmod +x entrypoint.sh

# git-clone tools: pycroburst, linkedin2username, gitminer3 → tools/bin/.
RUN python install_tools.py || true

# Pre-pull nuclei templates so the first scan isn't blocked on a fetch.
# Non-fatal: the build may run offline; templates update again at first run.
RUN nuclei -update-templates || true

# gowitness report server (Stage 3) listens here.
EXPOSE 7171

ENTRYPOINT ["./entrypoint.sh"]
# Default to the pre-flight check so `docker run agente` is a safe no-op that
# proves every tool resolves. Override with a real target, e.g. `-d example.com`.
CMD ["--check-tools"]
