# Deployment Guide

## Target Server: erebos-server

Erebos deploys to `erebos-server.local` at `/erebos/erebos/`.

### Prerequisites

- SSH access configured in `~/.ssh/config` (no credentials needed)
- Docker and Docker Compose installed on target

### Deploy

```bash
# Connect
ssh erebos-server

# Navigate to deploy path
cd /erebos/erebos

# Pull latest
git pull origin main

# Deploy with Docker Compose
docker compose up -d --build

# Verify
docker compose ps
curl -s http://localhost:5100/health
```

### First-time Setup

```bash
ssh erebos-server
sudo mkdir -p /erebos/erebos
sudo chown $USER:$USER /erebos/erebos
cd /erebos/erebos
git clone git@github.com:d4rkrex/Erebos.git .
cp .env.example .env
# Edit .env with real values
nano .env
docker compose up -d --build
```

### Environment Variables

Copy `.env.example` to `.env` and fill in:
- `VT_STRIKE_SSE_TOKEN`: Generate with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`
- `VT_STRIKE_IP_ALLOWLIST`: Comma-separated IPs allowed to connect
- LLM keys: At least one of OPENAI/OPENROUTER/GROQ for exploit inference

### Security Notes

- The server binds to `127.0.0.1` by default (loopback only)
- For remote access, use a reverse proxy (Caddy/nginx) with TLS
- Never expose port 5100 directly to the internet
- The token is the ONLY auth barrier — use a strong random value
- Docker runs as non-root with dropped capabilities

### Monitoring

```bash
# Logs
docker compose logs -f erebos

# Health
curl http://localhost:5100/health

# Restart
docker compose restart erebos
```

### Updating

```bash
ssh erebos-server
cd /erebos/erebos
git pull origin main
docker compose up -d --build
```
