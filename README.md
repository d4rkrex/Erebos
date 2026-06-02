# Erebos

Autonomous pentest orchestration agent with parallel multi-agent fleet scanning, hybrid exploitation, and MCP integration for code agents.

## Overview

Erebos orchestrates security tools through two execution modes:

- **Classic Mode** — Sequential phase scanning (recon → vuln-scan → exploit → report)
- **Fleet Mode** — 5 parallel agents with inter-agent finding correlation

## Features

- **Fleet orchestration** — Parallel agents (Recon, VulnScan, Exploit, CodeAudit, Reporter)
- **Finding correlation** — Cross-agent signal analysis with priority scoring (0-100)
- **Hybrid exploitation** — YAML templates + LLM cascade (Copilot → Claude → OpenRouter → DeepSeek)
- **Authenticated scanning** — Inject auth headers/cookies/profiles; auto-harvest credentials from findings
- **OSINT mode** — Passive-first recon (subfinder, gau, waybackurls, dnsx) before active scanning
- **MCP server** — Expose tools via JSON-RPC 2.0 for Copilot CLI / Claude Code / OpenCode
- **Agent skill** — Invoke as a skill from any code agent (see `SKILL.md`)
- **Code-aware scanning** — Pass `--repo` for source-code-guided exploitation
- **Pentest reports** — Correlation-aware markdown reports with priority-sorted findings
- **Per-scan isolation** — Each scan gets its own FindingsBus and storage directory
- **Allowlist enforcement** — All targets validated before any tool execution
- **Rate limiting** — Token-bucket per-agent + per-tool throttling
- **Log integrity** — HMAC-SHA256 tamper detection on all scan logs

## Requirements

- Python 3.10+
- Security tools: `nmap`, `nuclei`, `subfinder` (minimum for fleet mode)
- Optional: `katana`, `nikto`, `gobuster`, `ffuf` for comprehensive profiles
- Optional: MCP client for code-agent integration

## Installation

```bash
cd Erebos
poetry install

# Or with pip
pip install -e .
```

## Quick Start

```bash
# Configure allowlist (REQUIRED before any scan)
erebos allowlist add example.com

# Classic sequential scan
erebos scan example.com

# Fleet mode — 5 parallel agents with correlation
erebos scan example.com --fleet

# Fleet with code-aware exploitation
erebos scan example.com --fleet --repo ~/target-app

# Quiet mode (JSON output only)
erebos scan example.com --fleet --quiet

# MCP server for code agents
erebos mcp-serve

# Dry run to see what would happen
erebos scan example.com --dry-run
```

## Configuration

Erebos loads configuration from multiple sources in the following priority order:

1. **Built-in defaults** - Defined in the code
2. **Repo-local config** (`./config.yaml`) - Project-specific defaults
3. **User config** (`~/.erebos/config.yaml`) - **HIGHEST PRIORITY**

### Config Merging Behavior

- **Scalar values** (like `rate_limit`, `concurrency`): User config overrides repo config
- **Lists** (like `security.allowlist`): Merged from both configs, with duplicates removed
- **Profiles**: Deep merged - user profiles can extend or override repo profiles

**Example**: If repo config has `allowlist: [host1.com]` and user config has `allowlist: [host2.com]`, 
the final allowlist will be `[host1.com, host2.com]`.

### Config File Locations

Create `~/.erebos/config.yaml` to set your personal preferences:

```bash
mkdir -p ~/.erebos
cat > ~/.erebos/config.yaml << 'EOF'
security:
  allowlist:
    - "my-test-server.com"
    - "192.168.1.0/24"
  rate_limit: 20

execution:
  concurrency: 5
  enable_intelligent_error_handler: true
  error_handler_fallback_chains_path: ./erebos/config/fallback_chains.yaml
EOF
```

The repo-local `config.yaml` can define defaults that are shared across the team,
while `~/.erebos/config.yaml` lets each user customize their settings without 
modifying the repo file.

### Allowlist

By default, Erebos requires targets to be in the allowlist:

```bash
# Add a target
erebos allowlist add example.com
erebos allowlist add 192.168.1.0/24

# List allowlist
erebos allowlist list

# Remove a target
erebos allowlist remove example.com
```

### Profiles

Choose a scan profile:

| Profile | Description |
|---------|-------------|
| `minimal` | Quick scan with basic tools |
| `standard` | Balanced scan (recommended) |
| `comprehensive` | Full scan with all tools |
| `web-only` | Web-focused assessment |
| `vuln-focused` | Vulnerability scanning only |

```bash
erebos scan example.com --profile comprehensive
```

Generate a lightweight profile without running the full scan flow:

```bash
erebos target-profile https://scanme.nmap.org
erebos target-profile https://scanme.nmap.org --format json --no-save
```

### TargetProfile Feature Flag

Target profiling is enabled by default and can be disabled if you need strict backward-compatible recon behavior:

```yaml
ai:
  enable_target_profile: false
```

When enabled, recon stores a `target_profile` artifact in scan state and includes a short summary in markdown reports.

### IntelligentErrorHandler Feature Flag

Intelligent fallback and graceful degradation are disabled by default to preserve legacy execution behavior.

```yaml
execution:
  enable_intelligent_error_handler: true
  error_handler_fallback_chains_path: ./erebos/config/fallback_chains.yaml
```

When enabled, Erebos classifies tool failures, retries timeout/network conditions, and falls back to configured alternatives where available. Recovery events are persisted in scan state and reflected in markdown reports.

### IntelligentDecisionEngine Feature Flag

AI-guided tool selection is disabled by default to preserve legacy scan behavior.

```yaml
ai:
  enable_intelligent_decisions: true
  decision_default_threshold: 0.70
  decision_stealth_threshold: 0.85
  decision_aggressive_threshold: 0.60
  decision_max_latency_ms: 50.0
```

When enabled, Erebos uses `TargetProfile` plus scan mode (`minimal` -> stealth, `standard` -> normal, `comprehensive` -> aggressive) to rank tools, optimize parameters, and persist recommendation audits in scan state.

### Custom Fallback Chains

The default fallback configuration lives at `erebos/config/fallback_chains.yaml` and can be overridden with a custom file:

```yaml
fallback_chains:
  network_scanning:
    primary: masscan
    alternatives: [rustscan, nmap]
    max_retries: 3
    retry_delay: 1.0
    strategies:
      PERMISSION_DENIED: FALLBACK
      TIMEOUT: RETRY
    tool_strategies:
      masscan:
        PARSE_FAILURE: FALLBACK
```

### Phases

Run specific phases:

```bash
erebos scan example.com --phase=recon
erebos scan example.com --phase=vuln-scan
erebos scan example.com --phase=all
```

### Transport

Erebos supports two transport modes:

1. **CLI** (default): Execute tools locally via subprocess
2. **MCP**: Execute tools via Model Context Protocol

```bash
# CLI is default - tools run locally
erebos scan example.com  # Uses CLI transport

# MCP requires MCP server
# Set in config.yaml:
# execution:
#   transport: mcp
#   mcp_server_command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
```

## Commands

| Command | Description |
|---------|-------------|
| `erebos scan <target>` | Run a pentest scan (add `--fleet` for multi-agent) |
| `erebos scan <target> --fleet` | Fleet mode with parallel agents |
| `erebos scan <target> --osint` | Include passive OSINT recon (gau, waybackurls, dnsx) |
| `erebos scan <target> --osint-only` | OSINT-only mode (passive recon, no active scanning) |
| `erebos scan <target> --base-path /api/` | Restrict scan scope to a path prefix (white-hat) |
| `erebos scan <target> --auth-header "..."` | Inject auth header (e.g. `Authorization: Bearer ey...`) |
| `erebos scan <target> --auth-cookie "..."` | Inject session cookie (e.g. `session_id=abc123`) |
| `erebos scan <target> --auth-profile ./auth.yaml` | Load credentials from YAML profile (chmod 600) |
| `erebos dashboard` | Launch TUI dashboard (live terminal UI) |
| `erebos dashboard --web` | Launch web dashboard (browser, localhost:8484) |
| `erebos mcp-serve` | Start MCP stdio server for code agents |
| `erebos status` | Show scan status |
| `erebos report` | Generate report |
| `erebos target-profile <target>` | Build a lightweight TargetProfile |
| `erebos allowlist add\|remove\|list` | Manage allowlist |
| `erebos config get\|set` | Manage config |
| `erebos abort` | Abort a scan |
| `erebos tools` | Check available tools |
| `erebos migrate` | Migrate storage to subdirectory structure |

## Storage Structure

Erebos uses a subdirectory-based storage structure for better organization:

```
erebos-storage/
├── {scan_id}/
│   ├── state.json          # Scan state, findings, phase artifacts
│   └── raw/                 # Raw tool outputs
│       ├── nmap_fast_20240320T120000.xml
│       ├── nmap_full_20240320T150000.xml
│       ├── nuclei_20240320T160000.json
│       └── nikto_20240320T170000.txt
```

### Key Features

- **Subdirectory per scan**: Each scan has its own directory for isolation
- **Raw output preservation**: All tool outputs saved to `raw/` subdirectory
- **Command logging**: Full command history with timestamps and exit codes
- **Recovery logging**: IntelligentErrorHandler fallback events saved in `phase_artifacts.fallback_events`
- **Finding deduplication**: Prevents duplicate findings by (title, URL, tool) tuple
- **Backward compatibility**: Can read legacy flat-file format

### Dual Nmap Strategy

The `comprehensive` profile uses a dual nmap strategy for maximum port coverage:

1. **Fast scan first** (`nmap -F`): Scans top ~100 ports in ~2 minutes for early feedback
2. **Full scan after** (`nmap -p-`): Scans all 65535 ports in ~30 minutes for complete coverage
3. **Intelligent merge**: Combines results, preferring full scan data for overlapping ports

Port discovery metrics are tracked and logged for visibility.

### Migration Guide

If you have existing scans in the legacy flat-file format, migrate them to the new structure:

```bash
# Dry run to see what would be migrated
erebos migrate --dry-run

# Migrate all scans
erebos migrate

# Rollback if needed (within same session)
erebos migrate --rollback
```

**Migration process**:
1. Creates subdirectory for each scan (`{scan_id}/`)
2. Moves `{scan_id}_state.json` → `{scan_id}/state.json`
3. Moves `{scan_id}_findings.json` → merged into `state.json`
4. Creates `raw/` subdirectory (empty, for future outputs)
5. Keeps original files as backup until confirmed working

**Note**: Migration is non-destructive. Original flat files are preserved.

## Integration

### MCP (Code Agents)

Erebos exposes its tools via MCP with two transports:

**Stdio** (local, default):

```json
{
  "mcpServers": {
    "erebos": {
      "command": "python3",
      "args": ["-m", "erebos", "mcp-serve"]
    }
  }
}
```

**SSE HTTP** (remote / Docker):

```json
{
  "mcpServers": {
    "erebos": {
      "type": "sse",
      "url": "http://localhost:5100/sse",
      "headers": {
        "Authorization": "Bearer <VT_STRIKE_SSE_TOKEN>"
      }
    }
  }
}
```

Tools: `fleet-scan`, `scan`, `get-report`, `list-findings`

See [docs/mcp-integration.md](docs/mcp-integration.md) for full details.

### Agent Skill

Erebos works as a code-agent skill. See `SKILL.md` for triggers and usage.

### Fleet Pattern from Code Agent

```
User → Code Agent → MCP fleet-scan → Erebos spawns 5 agents → Report returned
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Host Layer (Copilot CLI / Claude Code / OpenCode)             │
├────────────────────────────────────────────────────────────────┤
│  CLI (Click + Rich)          │  MCP Server (JSON-RPC stdio)   │
├────────────────────────────────────────────────────────────────┤
│  Fleet Orchestrator                                            │
│  ┌────────┐ ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌────────┐│
│  │ Recon  │ │ VulnScan │ │ Exploit │ │CodeAudit │ │Reporter││
│  └───┬────┘ └────┬─────┘ └────┬────┘ └────┬─────┘ └───┬────┘│
│      └────────────┴────────────┴───────────┴────────────┘     │
│                    FindingsBus (JSONL)                          │
│                         │                                      │
│              CorrelationEngine + PriorityScorer                 │
├────────────────────────────────────────────────────────────────┤
│  Tool Executor    │  Parsers (nmap, nuclei, subfinder)         │
│  (allowlist +     │  → Canonical Finding model                 │
│   sanitization)   │                                            │
├────────────────────────────────────────────────────────────────┤
│  Exploit Engine (Templates + LLM Cascade + RepoAnalyzer)       │
├────────────────────────────────────────────────────────────────┤
│  Storage (scan state, findings, reports)                       │
└────────────────────────────────────────────────────────────────┘
```

See [docs/architecture.md](docs/architecture.md) for the full component diagram.

## Development

```bash
# Install
poetry install

# Tests
poetry run pytest tests/unit
poetry run pytest tests/integration

# Lint + format
poetry run ruff check erebos tests
poetry run black --check erebos tests
poetry run mypy erebos
```

CI runs automatically on GitHub Actions — see `.github/workflows/ci.yml`.

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | Full system architecture and data flow |
| [docs/fleet-mode.md](docs/fleet-mode.md) | Fleet scanning, agents, correlation |
| [docs/mcp-integration.md](docs/mcp-integration.md) | MCP server setup (stdio + SSE) for code agents |
| [docs/exploitation.md](docs/exploitation.md) | Hybrid exploitation engine |
| [docs/security.md](docs/security.md) | Security controls reference |
| [docs/configuration.md](docs/configuration.md) | All config options |
| [docs/deployment.md](docs/deployment.md) | Docker deployment and server setup |

## Deployment

### Docker Quick-Start

```bash
cp .env.example .env
# Edit .env with your API keys and a secure SSE token
docker compose up -d --build
curl http://localhost:5100/health
```

See [docs/deployment.md](docs/deployment.md) for full deployment instructions, server setup, and monitoring.

## License

MIT License - See LICENSE file for details.

## Security Note

Erebos is designed for **authorized security assessments only**. Always ensure you have proper authorization before scanning any target. The allowlist enforcement exists to prevent accidental out-of-scope scanning.
