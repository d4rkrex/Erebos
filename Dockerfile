# Erebos: Batteries-included pentest Docker image.
#
# Includes all tools needed for autonomous scanning:
#   nmap, nuclei, nikto, sqlmap, ffuf, hydra, httpx, subfinder, dnsx,
#   naabu, assetfinder, gau, dnsutils, whois
#
# Multi-stage build to keep final image lean (target < 1 GB).
#
# Usage:
#   docker compose up                     # MCP server mode (default)
#   docker compose run --rm erebos scan <target> --phase recon
#   docker compose run --rm erebos engage <target>
#
# For the lightweight MCP-only image see Dockerfile.mcp.

# ── Stage 1: Go tool binaries ───────────────────────────────────────
FROM golang:1.25-bookworm AS go-builder

# nuclei v3 — vulnerability scanner
ARG NUCLEI_VERSION=3.3.7
RUN GOBIN=/go/tools go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v${NUCLEI_VERSION}

# ffuf — directory / parameter brute-forcing
ARG FFUF_VERSION=2.1.0
RUN GOBIN=/go/tools go install -v github.com/ffuf/ffuf/v2@v${FFUF_VERSION}

# ── ProjectDiscovery recon tools ────────────────────────────────────
# httpx — HTTP probing (live hosts, status codes, tech fingerprinting)
RUN GOBIN=/go/tools go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# subfinder — passive subdomain enumeration
RUN GOBIN=/go/tools go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# dnsx — DNS resolution and validation
RUN GOBIN=/go/tools go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# naabu — fast port scanning
RUN GOBIN=/go/tools go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# ── Other recon tools ───────────────────────────────────────────────
# assetfinder — subdomain discovery (passive)
RUN GOBIN=/go/tools go install -v github.com/tomnomnom/assetfinder@latest

# gau — passive URL collection (AlienVault, Wayback, Common Crawl)
RUN GOBIN=/go/tools go install -v github.com/lc/gau/v2/cmd/gau@latest

# waybackurls — historical URL mining from Wayback Machine
RUN GOBIN=/go/tools go install -v github.com/tomnomnom/waybackurls@latest

# katana — active web crawling and spidering
RUN GOBIN=/go/tools go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# gobuster — directory/DNS brute-force
RUN GOBIN=/go/tools go install -v github.com/OJ/gobuster/v3@latest

# ── Stage 2: Python application build ───────────────────────────────
FROM python:3.11-slim-bookworm AS py-builder

WORKDIR /build

# Build-time deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./

# Install runtime dependencies into a prefix we can copy later
RUN pip install --no-cache-dir --prefix=/install \
    click>=8.1.7 \
    rich>=13.7.0 \
    pydantic>=2.5.0 \
    pydantic-settings>=2.1.0 \
    pyyaml>=6.0.1 \
    python-ulid>=3.0.0 \
    jinja2>=3.1.3 \
    python-dotenv>=1.0.0 \
    networkx>=3.0 \
    requests>=2.31.0 \
    httpx>=0.27.0 \
    textual>=0.52.0 \
    starlette>=0.37 \
    uvicorn>=0.29 \
    sse-starlette>=1.8 \
    semgrep>=1.67.0 \
    arjun>=2.2.5 \
    dirsearch>=0.4.3

# ── Stage 3: Runtime image ──────────────────────────────────────────
FROM python:3.11-slim-bookworm

LABEL maintainer="Erebos AppSec <appsec@erebos.com>" \
      description="Erebos autonomous pentest toolkit" \
      version="1.0.0"

# ── System pentest tools ────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        sqlmap \
        hydra \
        tmux \
        curl \
        wget \
        ca-certificates \
        dnsutils \
        whois \
        git \
        procps \
        perl \
        libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# nikto — not in bookworm repos; install from upstream
ARG NIKTO_VERSION=2.5.0
RUN git clone --depth 1 --branch ${NIKTO_VERSION} \
        https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# ── Python packages from builder ────────────────────────────────────
COPY --from=py-builder /install /usr/local

# ── Go binaries from builder (AFTER python to avoid shim overwrite) ─
COPY --from=go-builder /go/tools/nuclei /usr/local/bin/nuclei
COPY --from=go-builder /go/tools/ffuf   /usr/local/bin/ffuf
COPY --from=go-builder /go/tools/httpx  /usr/local/bin/httpx
COPY --from=go-builder /go/tools/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /go/tools/dnsx   /usr/local/bin/dnsx
COPY --from=go-builder /go/tools/naabu  /usr/local/bin/naabu
COPY --from=go-builder /go/tools/assetfinder /usr/local/bin/assetfinder
COPY --from=go-builder /go/tools/gau    /usr/local/bin/gau

# ── Application user ────────────────────────────────────────────────
RUN groupadd -g 1000 erebos && \
    useradd -u 1000 -g 1000 -m -s /bin/bash erebos

# ── Directories ─────────────────────────────────────────────────────
RUN mkdir -p /data /run/secrets && \
    chown erebos:erebos /data /run/secrets

# ── Application code ────────────────────────────────────────────────
WORKDIR /app
COPY pyproject.toml README.md ./
COPY erebos/ ./erebos/
COPY config.yaml.example ./config.yaml.example

COPY templates/nuclei /app/templates/nuclei

RUN chown -R erebos:erebos /app && \
    pip install --no-cache-dir poetry-core && \
    pip install --no-cache-dir --no-deps -e .

# ── Switch to non-root user ─────────────────────────────────────────
USER erebos

# Update nuclei templates on first build (as erebos user)
RUN nuclei -update-templates -silent 2>/dev/null || true

# ── Metadata ─────────────────────────────────────────────────────────
VOLUME ["/data"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://127.0.0.1:8443/health || exit 1

STOPSIGNAL SIGTERM

ENTRYPOINT ["python", "-m", "erebos"]
CMD ["mcp-serve", "--port", "8443"]
