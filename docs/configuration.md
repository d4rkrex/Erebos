# Configuration

## Config File Locations

| Priority | Location | Purpose |
|----------|----------|---------|
| 1 (highest) | `~/.erebos/config.yaml` | User preferences |
| 2 | `./config.yaml` | Project/team defaults |
| 3 (lowest) | Built-in defaults | Sensible fallbacks |

Lists are merged (union). Scalars use highest-priority value.

## Full Configuration Reference

```yaml
# Security
security:
  allowlist:
    - "example.com"
    - "*.example.com"
    - "10.0.0.0/8"
  rate_limit: 30              # requests/minute (max: 60)

# Execution
execution:
  concurrency: 3              # parallel tool processes
  transport: cli              # cli | mcp
  mcp_server_command: []      # MCP server command if transport=mcp
  enable_intelligent_error_handler: false
  error_handler_fallback_chains_path: ./erebos/config/fallback_chains.yaml

# Fleet mode
fleet:
  max_agents: 5               # parallel agents (max: 10)
  timeout_per_agent: 300      # seconds before agent killed
  rate_limit_per_minute: 30   # operations/minute

# AI features
ai:
  enable_target_profile: true
  enable_intelligent_decisions: false
  decision_default_threshold: 0.70
  decision_stealth_threshold: 0.85
  decision_aggressive_threshold: 0.60
  decision_max_latency_ms: 50.0

# LLM cascade (for exploit generation)
llm:
  providers:
    - name: copilot
      enabled: true
      priority: 1
    - name: claude
      enabled: true
      priority: 2
    - name: openrouter
      enabled: false
      priority: 3
    - name: deepseek
      enabled: false
      priority: 4
  max_tokens_per_scan: 50000
  budget_usd: 1.00

# Reporting
reporting:
  output_dir: ./erebos-reports
  format: markdown            # markdown (only option currently)
  max_findings: 200           # cap in report

# Storage
storage:
  base_dir: ./erebos-storage
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `EREBOS_ALLOWLIST` | Comma-separated allowlist (merged with config) |
| `EREBOS_CONFIG` | Custom config file path |
| `EREBOS_STORAGE_DIR` | Override storage directory |
| `EREBOS_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `GITHUB_COPILOT_API_KEY` | Copilot LLM API key (or auto-resolved from `gh auth token`) |
| `ANTHROPIC_API_KEY` | Claude API key for exploit generation |
| `OPENROUTER_API_KEY` | OpenRouter API key (multi-model fallback) |
| `DEEPSEEK_API_KEY` | DeepSeek API key (OpenAI-compatible, model: `deepseek-chat`) |

## Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `minimal` | Fast scan, top 100 ports | Quick check, stealth |
| `standard` | Balanced coverage | Default assessment |
| `comprehensive` | Full port + dual nmap | Thorough pentest |
| `web-only` | HTTP-focused tools | Web app assessment |
| `vuln-focused` | Skip recon, run nuclei | Known targets |

```bash
erebos scan target.com --profile comprehensive
```

## Allowlist Management

```bash
# Add targets
erebos allowlist add example.com
erebos allowlist add "*.staging.example.com"
erebos allowlist add 192.168.0.0/16

# List current allowlist
erebos allowlist list

# Remove targets
erebos allowlist remove example.com
```

## Fleet Config via CLI

```bash
# Fleet with custom timeout
erebos scan target.com --fleet --timeout 600

# Fleet with repos for code audit
erebos scan target.com --fleet --repo ~/app1 --repo ~/app2

# Fleet quiet mode (JSON output only)
erebos scan target.com --fleet --quiet

# OSINT mode (passive recon first, then active)
erebos scan target.com --fleet --osint

# OSINT-only mode (passive recon only, no active tools)
erebos scan target.com --fleet --osint-only

# Authenticated scanning
erebos scan target.com --fleet --auth-header "Authorization: Bearer ey..."
erebos scan target.com --fleet --auth-cookie "session_id=abc123; PHPSESSID=xyz"
erebos scan target.com --fleet --auth-profile ./auth.yaml
```
