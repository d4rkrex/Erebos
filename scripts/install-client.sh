#!/usr/bin/env bash
set -euo pipefail

# Erebos Client Installer
# Sets up Erebos as an MCP tool for coding agents (Claude Code, Copilot, OpenCode)
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/d4rkrex/Erebos/main/scripts/install-client.sh | bash
#   # or
#   ./scripts/install-client.sh [OPTIONS]
#
# Options:
#   --agent claude|copilot|opencode|all   Configure for specific agent (default: all)
#   --remote <url>                         Use remote SSE server instead of local
#   --token <token>                        Bearer token for remote SSE auth
#   --with-burp                            Also configure Burp Suite MCP server
#   --target <domain>                      Add initial target to allowlist
#   --help                                 Show this help

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }
step()  { echo -e "${CYAN}[→]${NC} $1"; }

# Defaults
AGENT="all"
REMOTE_URL=""
TOKEN=""
WITH_BURP=false
INITIAL_TARGET=""

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --agent)      AGENT="$2"; shift 2 ;;
        --remote)     REMOTE_URL="$2"; shift 2 ;;
        --token)      TOKEN="$2"; shift 2 ;;
        --with-burp)  WITH_BURP=true; shift ;;
        --target)     INITIAL_TARGET="$2"; shift 2 ;;
        --help|-h)
            sed -n '3,16p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) error "Unknown option: $1" ;;
    esac
done

echo ""
echo "  ╦  ╦╔╦╗┌─┐┌┬┐┬─┐┬┬┌─┌─┐  Client Setup"
echo "  ╚╗╔╝ ║ └─┐ │ ├┬┘│├┴┐├┤   MCP Agent Installer"
echo "   ╚╝  ╩ └─┘ ┴ ┴└─┴┴ ┴└─┘"
echo ""

# ── Step 1: Check prerequisites ──────────────────────────────────────
step "Checking prerequisites..."

has() { command -v "$1" &>/dev/null; }

if ! has python3; then
    error "Python 3.10+ is required. Install from https://python.org"
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 10 ]]; then
    error "Python 3.10+ required (found $PY_VERSION)"
fi

info "Python $PY_VERSION ✓"

# ── Step 2: Install Erebos Python package ──────────────────────────
step "Installing Erebos..."

if has erebos; then
    info "Erebos already installed ($(erebos --version 2>/dev/null || echo 'unknown version'))"
else
    if has pipx; then
        info "Installing with pipx..."
        pipx install git+https://github.com/d4rkrex/Erebos.git
    elif has pip3; then
        info "Installing with pip..."
        pip3 install --user git+https://github.com/d4rkrex/Erebos.git
    elif has pip; then
        pip install --user git+https://github.com/d4rkrex/Erebos.git
    else
        error "No pip/pipx found. Install Python package manager first."
    fi
fi

# Verify
if ! has erebos; then
    warn "erebos not found in PATH. You may need to add ~/.local/bin to PATH:"
    warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# ── Step 3: Build MCP config ─────────────────────────────────────────
step "Configuring MCP server..."

# Determine MCP config based on local vs remote
if [[ -n "$REMOTE_URL" ]]; then
    # Remote SSE mode
    MCP_CONFIG=$(cat <<EOF
{
  "mcpServers": {
    "erebos": {
      "type": "sse",
      "url": "${REMOTE_URL}/sse",
      "headers": {
        "Authorization": "Bearer ${TOKEN}"
      }
    }
  }
}
EOF
)
else
    # Local stdio mode
    EREBOS_PATH=$(which erebos 2>/dev/null || echo "erebos")
    MCP_CONFIG=$(cat <<EOF
{
  "mcpServers": {
    "erebos": {
      "command": "${EREBOS_PATH}",
      "args": ["mcp-serve"]
    }
  }
}
EOF
)
fi

# Add Burp Suite MCP if requested
if $WITH_BURP; then
    step "Adding Burp Suite MCP configuration..."

    # Check for Java (required by Burp MCP proxy)
    if ! has java; then
        warn "Java not found. Burp Suite MCP requires Java on PATH."
        warn "Install: https://adoptium.net"
    fi

    BURP_PROXY_JAR="${HOME}/.local/share/burp-mcp/mcp-proxy-all.jar"

    if [[ ! -f "$BURP_PROXY_JAR" ]]; then
        info "Downloading Burp MCP proxy..."
        mkdir -p "$(dirname "$BURP_PROXY_JAR")"
        # Clone and build the proxy jar
        TMPDIR=$(mktemp -d)
        if has git && has java; then
            git clone --depth 1 https://github.com/PortSwigger/mcp-server.git "$TMPDIR/burp-mcp" 2>/dev/null
            if [[ -f "$TMPDIR/burp-mcp/gradlew" ]]; then
                (cd "$TMPDIR/burp-mcp" && ./gradlew embedProxyJar -q 2>/dev/null) && \
                    cp "$TMPDIR/burp-mcp/build/libs/mcp-proxy-all.jar" "$BURP_PROXY_JAR" 2>/dev/null
            fi
        fi
        rm -rf "$TMPDIR"

        if [[ ! -f "$BURP_PROXY_JAR" ]]; then
            warn "Could not build Burp MCP proxy automatically."
            warn "Manual setup: https://github.com/PortSwigger/mcp-server"
            BURP_PROXY_JAR="/path/to/mcp-proxy-all.jar"
        fi
    fi

    # Merge Burp config into MCP_CONFIG
    MCP_CONFIG=$(echo "$MCP_CONFIG" | python3 -c "
import json, sys
cfg = json.load(sys.stdin)
cfg['mcpServers']['burpsuite'] = {
    'type': 'stdio',
    'command': 'java',
    'args': ['-jar', '${BURP_PROXY_JAR}', '--sse-url', 'http://127.0.0.1:9876']
}
json.dump(cfg, sys.stdout, indent=2)
")
    info "Burp Suite MCP configured (connects to Burp on localhost:9876)"
fi

# ── Step 4: Install for agents ────────────────────────────────────────
install_for_claude() {
    local config_dir="${HOME}/.claude"
    mkdir -p "$config_dir"

    local mcp_file="$config_dir/mcp.json"
    if [[ -f "$mcp_file" ]]; then
        # Merge with existing config
        python3 -c "
import json
with open('$mcp_file') as f: existing = json.load(f)
new = json.loads('''$MCP_CONFIG''')
existing.setdefault('mcpServers', {}).update(new.get('mcpServers', {}))
with open('$mcp_file', 'w') as f: json.dump(existing, f, indent=2)
"
        info "Updated $mcp_file (merged with existing config)"
    else
        echo "$MCP_CONFIG" > "$mcp_file"
        info "Created $mcp_file"
    fi
}

install_for_copilot() {
    # Copilot reads .mcp.json from the project root (already exists in repo)
    # For global config, write to ~/.config/github-copilot/
    local config_dir="${HOME}/.config/github-copilot"
    mkdir -p "$config_dir"

    local mcp_file="$config_dir/mcp.json"
    if [[ -f "$mcp_file" ]]; then
        python3 -c "
import json
with open('$mcp_file') as f: existing = json.load(f)
new = json.loads('''$MCP_CONFIG''')
existing.setdefault('mcpServers', {}).update(new.get('mcpServers', {}))
with open('$mcp_file', 'w') as f: json.dump(existing, f, indent=2)
"
        info "Updated $mcp_file"
    else
        echo "$MCP_CONFIG" > "$mcp_file"
        info "Created $mcp_file"
    fi
}

install_for_opencode() {
    # OpenCode reads from .opencode/mcp.json or project .mcp.json
    local config_dir="${HOME}/.opencode"
    mkdir -p "$config_dir"

    local mcp_file="$config_dir/mcp.json"
    if [[ -f "$mcp_file" ]]; then
        python3 -c "
import json
with open('$mcp_file') as f: existing = json.load(f)
new = json.loads('''$MCP_CONFIG''')
existing.setdefault('mcpServers', {}).update(new.get('mcpServers', {}))
with open('$mcp_file', 'w') as f: json.dump(existing, f, indent=2)
"
        info "Updated $mcp_file"
    else
        echo "$MCP_CONFIG" > "$mcp_file"
        info "Created $mcp_file"
    fi
}

case "$AGENT" in
    claude)    install_for_claude ;;
    copilot)   install_for_copilot ;;
    opencode)  install_for_opencode ;;
    all)
        install_for_claude
        install_for_copilot
        install_for_opencode
        ;;
    *) error "Unknown agent: $AGENT (use: claude, copilot, opencode, all)" ;;
esac

# ── Step 5: Configure initial target ─────────────────────────────────
if [[ -n "$INITIAL_TARGET" ]]; then
    step "Adding target to allowlist..."
    if has erebos; then
        erebos allowlist add "$INITIAL_TARGET"
        info "Target '$INITIAL_TARGET' added to allowlist"
    else
        warn "erebos not in PATH. Add target manually: erebos allowlist add $INITIAL_TARGET"
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────
echo ""
info "═══════════════════════════════════════════════════════════════"
info "  Erebos client installed successfully!"
info "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Next steps:"
echo ""
echo "    1. Add a target to the allowlist:"
echo "       erebos allowlist add target.com"
echo ""
echo "    2. From your coding agent, use:"
echo "       @erebos fleet-scan target.com"
echo ""
if $WITH_BURP; then
echo "    3. Start Burp Suite with MCP extension loaded"
echo "       (Extension listens on http://127.0.0.1:9876)"
echo ""
fi
echo "  Docs: https://github.com/d4rkrex/Erebos/blob/main/docs/mcp-integration.md"
echo ""
