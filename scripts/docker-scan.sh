#!/usr/bin/env bash
# Run a Erebos scan via Docker.
#
# Usage:
#   ./scripts/docker-scan.sh <target> [--phase recon|vuln-scan|exploit]
#
# Examples:
#   ./scripts/docker-scan.sh example.com --phase recon
#   ./scripts/docker-scan.sh 10.0.0.1 --phase vuln-scan
#   ./scripts/docker-scan.sh example.com engage

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target> [erebos args...]"
    echo ""
    echo "Examples:"
    echo "  $0 example.com --phase recon"
    echo "  $0 example.com engage"
    exit 1
fi

COMPOSE_FILE="$(cd "$(dirname "$0")/.." && pwd)/docker-compose.yaml"

# Default subcommand is 'scan' unless the first positional arg is a known command
FIRST_ARG="${1:-}"
KNOWN_COMMANDS="scan engage mcp-serve status report fleet"

if echo "$KNOWN_COMMANDS" | grep -qw "$FIRST_ARG"; then
    docker compose -f "$COMPOSE_FILE" run --rm erebos "$@"
else
    docker compose -f "$COMPOSE_FILE" run --rm erebos scan "$@"
fi
