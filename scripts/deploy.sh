#!/usr/bin/env bash
set -euo pipefail

# Erebos Deploy Script
# Usage: ./scripts/deploy.sh [host] [path]
# Default: erebos-server /erebos/vt-strike

HOST="${1:-erebos-server}"
DEPLOY_PATH="${2:-/erebos/vt-strike}"

echo "🚀 Deploying Erebos v1.0 to ${HOST}:${DEPLOY_PATH}"

# Check connectivity
echo "→ Checking connectivity..."
ssh "${HOST}" "hostname" || { echo "❌ Cannot reach ${HOST}. Check VPN/SSH config."; exit 1; }

# Create directory
echo "→ Creating directory..."
ssh "${HOST}" "mkdir -p ${DEPLOY_PATH}"

# Rsync project (exclude sensitive/unnecessary files)
echo "→ Syncing files..."
rsync -avz --delete \
  --exclude='.env' \
  --exclude='__pycache__' \
  --exclude='.vtspec/' \
  --exclude='.git/' \
  --exclude='secrets/' \
  --exclude='*.pyc' \
  --exclude='.mypy_cache/' \
  --exclude='.pytest_cache/' \
  --exclude='inspirations/' \
  --exclude='dist/' \
  --exclude='build/' \
  "$(dirname "$(dirname "$(readlink -f "$0")")")/" \
  "${HOST}:${DEPLOY_PATH}/"

# Install on remote
echo "→ Installing dependencies..."
ssh "${HOST}" "cd ${DEPLOY_PATH} && pip3 install -e . 2>&1 | tail -5"

# Verify installation
echo "→ Verifying..."
ssh "${HOST}" "cd ${DEPLOY_PATH} && python3 -m erebos --help | head -5"

# Check if Docker is available for MCP server mode
ssh "${HOST}" "which docker >/dev/null 2>&1 && echo '→ Docker available. To start MCP server: cd ${DEPLOY_PATH} && docker compose up -d' || echo '→ Docker not found. Use CLI mode: erebos scan <target>'"

echo ""
echo "✅ Erebos v1.0 deployed to ${HOST}:${DEPLOY_PATH}"
echo ""
echo "Quick start:"
echo "  ssh ${HOST}"
echo "  cd ${DEPLOY_PATH}"
echo "  python3 -m erebos scan <target> --phases recon"
echo "  python3 -m erebos engage <target> --profile quick-scan"
