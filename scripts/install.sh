#!/usr/bin/env bash
set -euo pipefail

# Erebos Installer
# Installs Python package + required security tools

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif command -v sw_vers &>/dev/null; then
        OS="macos"
    else
        OS="unknown"
    fi
    echo "$OS"
}

# Check if command exists
has() { command -v "$1" &>/dev/null; }

# Install Go tools
install_go_tools() {
    if ! has go; then
        warn "Go not found. Installing Go tools requires Go 1.21+."
        warn "Install Go from https://go.dev/dl/ then re-run this script."
        return 1
    fi

    info "Installing nuclei..."
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

    info "Installing subfinder..."
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

    info "Installing katana..."
    go install github.com/projectdiscovery/katana/cmd/katana@latest

    info "Installing httpx..."
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest

    info "Installing dnsx..."
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

    info "Installing naabu..."
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

    info "Installing alterx..."
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest

    info "Installing assetfinder..."
    go install github.com/tomnomnom/assetfinder@latest

    info "Installing gau..."
    go install github.com/lc/gau/v2/cmd/gau@latest

    info "Installing waybackurls..."
    go install github.com/tomnomnom/waybackurls@latest

    info "Installing kxss..."
    go install github.com/Emoe/kxss@latest

    info "Installing dalfox..."
    go install github.com/hahwul/dalfox/v2@latest
}

# Install system packages
install_system_tools() {
    local os=$(detect_os)

    case "$os" in
        kali|debian|ubuntu)
            info "Detected $os — using apt"
            sudo apt update -qq
            sudo apt install -y nmap nikto gobuster ffuf wpscan dirsearch
            # arjun and bxss via pip
            pip install arjun bxss 2>/dev/null || true
            ;;
        fedora|rhel|centos)
            info "Detected $os — using dnf"
            sudo dnf install -y nmap nikto
            pip install arjun bxss 2>/dev/null || true
            ;;
        arch|manjaro)
            info "Detected $os — using pacman"
            sudo pacman -Sy --noconfirm nmap nikto
            pip install arjun bxss 2>/dev/null || true
            ;;
        macos)
            info "Detected macOS — using brew"
            if ! has brew; then
                error "Homebrew not found. Install from https://brew.sh"
            fi
            brew install nmap nikto gobuster ffuf wpscan
            pip install arjun bxss dirsearch 2>/dev/null || true
            ;;
        *)
            warn "Unknown OS ($os). Install manually: nmap, nikto, gobuster, ffuf, wpscan, dirsearch, arjun"
            ;;
    esac
}

# Install Python package
install_python() {
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local project_dir="$(dirname "$script_dir")"

    cd "$project_dir"

    if has pipx; then
        info "Installing with pipx (global command)..."
        pipx install -e . --force
        info "'erebos' is now available globally"
    elif has poetry; then
        info "Installing with Poetry..."
        poetry install
        # Create symlink for global access
        local venv_bin
        venv_bin="$(poetry env info -e 2>/dev/null)/bin/erebos" || true
        if [ -f "$venv_bin" ]; then
            local link_dir="$HOME/.local/bin"
            mkdir -p "$link_dir"
            ln -sf "$venv_bin" "$link_dir/erebos"
            info "'erebos' linked to $link_dir/erebos"
            info "Ensure $link_dir is in your PATH"
        else
            info "Run 'poetry shell' to activate, or use 'poetry run erebos'"
        fi
    elif has pip3; then
        info "Installing with pip (editable)..."
        pip3 install -e .
    elif has pip; then
        info "Installing with pip (editable)..."
        pip install -e .
    else
        error "Neither pipx, poetry, nor pip found. Install Python 3.10+ first."
    fi
}

# Verify installation
verify() {
    echo ""
    info "Verifying installation..."
    echo ""

    local tools=("erebos" "nmap" "nuclei" "subfinder" "httpx")
    local optional=("katana" "nikto" "gobuster" "ffuf" "dnsx" "naabu" "assetfinder" "gau" "waybackurls" "alterx" "kxss" "dalfox" "wpscan" "dirsearch" "arjun")
    local all_ok=true

    for tool in "${tools[@]}"; do
        if has "$tool"; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool (REQUIRED)"
            all_ok=false
        fi
    done

    for tool in "${optional[@]}"; do
        if has "$tool"; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${YELLOW}○${NC} $tool (optional)"
        fi
    done

    echo ""
    if $all_ok; then
        info "All required tools installed!"
        echo ""
        echo "  Next steps:"
        echo "    erebos allowlist add <your-target>"
        echo "    erebos scan <your-target> --fleet"
    else
        warn "Some required tools are missing. Fix above issues and re-run."
    fi
}

# Main
main() {
    echo ""
    echo "  ╦  ╦╔╦╗┌─┐┌┬┐┬─┐┬┬┌─┌─┐  ╦  ┬┌┬┐┌─┐"
    echo "  ╚╗╔╝ ║ └─┐ │ ├┬┘│├┴┐├┤   ║  │ │ ├┤ "
    echo "   ╚╝  ╩ └─┘ ┴ ┴└─┴┴ ┴└─┘  ╩═╝┴ ┴ └─┘"
    echo ""

    local skip_tools=false
    local skip_python=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tools-only)  skip_python=true; shift ;;
            --python-only) skip_tools=true; shift ;;
            --verify)      verify; exit 0 ;;
            -h|--help)
                echo "Usage: install.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --tools-only   Only install security tools (skip Python)"
                echo "  --python-only  Only install Python package (skip tools)"
                echo "  --verify       Check what's installed"
                echo "  -h, --help     Show this help"
                exit 0
                ;;
            *) error "Unknown option: $1" ;;
        esac
    done

    if ! $skip_python; then
        info "=== Installing Erebos Python package ==="
        install_python
        echo ""
    fi

    if ! $skip_tools; then
        info "=== Installing system security tools ==="
        install_system_tools
        echo ""

        info "=== Installing Go-based tools ==="
        install_go_tools || true
        echo ""
    fi

    verify
}

main "$@"
