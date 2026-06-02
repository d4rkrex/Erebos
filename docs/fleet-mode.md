# Fleet Mode

Fleet mode launches 5 parallel agents for autonomous penetration testing.

## Quick Start

```bash
# Configure allowlist first
erebos allowlist add example.com
erebos allowlist add "*.example.com"

# Run fleet scan
erebos scan example.com --fleet

# With source repos for code-aware exploitation
erebos scan example.com --fleet --repo ./backend-api --repo ./auth-service

# OSINT mode (passive recon first)
erebos scan example.com --fleet --osint

# OSINT-only (no active scanning)
erebos scan example.com --fleet --osint-only

# Authenticated scanning
erebos scan example.com --fleet --auth-header "Authorization: Bearer ey..."
erebos scan example.com --fleet --auth-cookie "session_id=abc123"

# Quiet mode (JSON only, no live display)
erebos scan example.com --fleet --quiet
```

## Agents

| Agent | Tools | Output | Runs |
|-------|-------|--------|------|
| **Recon** | Passive: subfinder, assetfinder, gau, waybackurls, dnsx. Active: nmap, httpx, naabu, katana | Ports, subdomains, URLs | First (parallel) |
| **Vuln Scan** | nuclei, dalfox, wpscan, kxss, bxss, nikto | CVE/CWE findings | After recon targets available |
| **Exploit** | templates (16 CWEs), LLM cascade | PoC evidence | After vuln findings |
| **Code Audit** | RepoAnalyzer | Auth gaps, patterns | First (parallel, needs --repo) |
| **Reporter** | CorrelationEngine | Prioritized report (target-filtered) | Last (after all agents) |

## Live Display

Fleet mode shows a Rich live table:

```
🐝 Fleet Status
┌──────────────┬───────────┬──────────┬──────────┐
│ Role         │ Status    │ Findings │ Duration │
├──────────────┼───────────┼──────────┼──────────┤
│ recon        │ completed │        8 │ 12.3s    │
│ vuln-scan    │ running   │        3 │ 45.1s    │
│ exploit      │ pending   │        0 │          │
│ code-audit   │ completed │        2 │  5.2s    │
│ reporter     │ pending   │        0 │          │
└──────────────┴───────────┴──────────┴──────────┘
```

## Correlation

The Reporter agent runs a correlation engine that cross-references findings:

- **Multi-signal boost**: Same vulnerability found by 2+ agents → priority increase
- **Source diversity**: Only counts unique roles (same role twice ≠ extra signal)
- **Auth gap amplification**: Code audit confirms missing auth + vuln scan finds IDOR → critical priority

### Priority Score Formula

```
Score = severity(0-40) + correlation(0-40) + exploitability(0-25) → max 100

Severity:  CRITICAL=40  HIGH=30  MEDIUM=20  LOW=10
Correlation:  +20 per extra signal (cap +40)
Exploitability:  template_available=+15  auth_gap=+10
```

## Report Output

Fleet generates a markdown pentest report at `./erebos-reports/`:

```markdown
# 🔒 Penetration Test Report

> ⚠️ CONFIDENTIAL — This report contains sensitive information...

## Executive Summary
- Total findings: 12
- Critical: 2, High: 3, Medium: 5, Low: 2

## Findings (by priority)
| # | Priority | Severity | Title | CVE/CWE | Signals |
|---|----------|----------|-------|---------|---------|
| 1 | 95 | 🔴 CRITICAL | SQLi Auth Bypass | CVE-2023-1234 | 🔗×3 |
...

## Remediation Priorities
1. SQL Injection Auth Bypass (🔗×3)
   - Patch: CVE-2023-1234
   - Fix pattern: CWE-89
```

## Configuration

```yaml
# In ~/.erebos/config.yaml
fleet:
  max_agents: 5         # Max parallel agents (hard cap: 10)
  timeout_per_agent: 300  # Seconds before agent is killed
  rate_limit_per_minute: 30  # Max operations/minute (hard cap: 60)
```

## Timeout Handling

- Each agent has a configurable timeout (default: 300s)
- Timed-out agents are cancelled via `asyncio.wait_for()`
- Fleet continues with remaining agents
- Timed-out agent appears as "failed" in summary

## Code-Aware Scanning

Pass `--repo` to enable code-audit agent:

```bash
erebos scan api.example.com --fleet --repo ~/repos/my-api
```

The code-audit agent:
1. Scans for auth gap patterns (missing middleware)
2. Finds unsafe input handling (eval, exec, SQL concat)
3. Detects hardcoded credentials
4. Cross-references with vuln-scan findings for priority boost

## OSINT Mode

OSINT mode changes how the Recon agent operates:

| Flag | Behavior |
|------|----------|
| `--osint` | Runs passive tools first (subfinder, gau, waybackurls, dnsx, assetfinder), then active (nmap, httpx, naabu, katana) |
| `--osint-only` | Runs ONLY passive tools — no active scanning, no port scans |

Passive tools never touch the target directly — they query third-party data sources (OTX, Wayback Machine, CommonCrawl, DNS records).

## Authenticated Scanning

Fleet mode supports injecting authentication into all tool invocations:

```bash
# Single header
erebos scan target.com --fleet --auth-header "Authorization: Bearer ey..."

# Session cookie
erebos scan target.com --fleet --auth-cookie "session_id=abc; PHPSESSID=xyz"

# YAML credential profile (chmod 600)
erebos scan target.com --fleet --auth-profile ./auth.yaml
```

Auth context is propagated to:
- All recon tools (for authenticated endpoint discovery)
- Nuclei/dalfox (for testing behind auth walls)
- Exploit templates (for authenticated PoC generation)
- MCP tool calls (`auth_header`/`auth_cookie` params)

## Per-Scan Isolation

Each fleet scan creates an isolated storage directory:

```
erebos-storage/
├── target.com-20240320T120000/
│   ├── state.json
│   ├── findings-bus.jsonl    # Isolated bus for this scan
│   └── raw/
└── target.com-20240321T090000/
    ├── state.json
    ├── findings-bus.jsonl    # Separate bus — no cross-contamination
    └── raw/
```

The Reporter agent also filters findings by target domain before including them in the report, preventing any cross-target data leakage.
