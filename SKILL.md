---
name: erebos
description: >
  Autonomous pentest orchestrator with fleet mode. Launches parallel agents
  (recon, vuln-scan, exploit, code-audit, reporter) against authorized targets.
  Produces prioritized, correlated vulnerability reports.
license: MIT
metadata:
  author: d4rkrex
  version: "1.0"
triggers:
  - "pentest"
  - "scan target"
  - "fleet scan"
  - "vulnerability scan"
  - "recon"
  - "exploit"
  - "find vulnerabilities"
  - "security scan"
  - "attack surface"
---

# Erebos — Pentest Orchestrator Skill

## ⚠️ PREREQUISITE: Allowlist Configuration

**Before using Erebos, you MUST configure the target allowlist.**
Erebos will REFUSE to scan any target not explicitly authorized.

```bash
erebos allowlist add example.com
erebos allowlist add "*.example.com"
```

This is a security control (EP-01) — it cannot be bypassed.

## What It Does

Erebos is an autonomous penetration testing orchestrator that:

1. **Recon** — Discovers attack surface (nmap ports, subfinder/assetfinder subdomains, httpx probing, naabu port scan, gau/waybackurls passive URLs, dnsx validation, alterx permutations)
2. **Vuln Scan** — Identifies vulnerabilities (nuclei templates, dalfox XSS, wpscan WordPress, kxss/bxss reflected/blind XSS)
3. **Exploit** — Attempts exploitation (template-based + LLM-generated)
4. **Code Audit** — Analyzes source repos for auth gaps and vuln patterns
5. **Report** — Correlates findings and generates prioritized pentest report

All agents run in parallel with inter-agent correlation.

## Usage

### Fleet Scan (Recommended)

```bash
# Full autonomous scan with all agents
erebos scan example.com --fleet

# With source code for code-aware exploitation
erebos scan example.com --fleet --repo ./backend-api --repo ./auth-service

# Quiet mode (JSON output only)
erebos scan example.com --fleet --quiet
```

### Via MCP (from code agents)

Register in your agent config:
```json
{"erebos": {"command": "erebos", "args": ["mcp-serve"]}}
```

Then invoke tools:
- `fleet-scan` — Full parallel fleet scan
- `scan` — Single-phase scan
- `get-report` — Latest report
- `list-findings` — Query findings

### Single Phase

```bash
erebos scan example.com --phase recon
erebos scan example.com --phase vuln-scan
erebos scan example.com --phase exploit
```

## Multi-Agent Orchestration

When invoked as a fleet, Erebos spawns 5 parallel agents:

| Agent | Purpose | Tools | Output |
|-------|---------|-------|--------|
| Recon | Attack surface discovery | nmap, subfinder, httpx, dnsx, assetfinder, naabu, gau, waybackurls, alterx | Ports, subdomains, live hosts, historical URLs |
| Vuln Scan | Vulnerability detection | nuclei, dalfox, wpscan, kxss, bxss | CVE/CWE findings, XSS, WordPress vulns |
| Exploit | Proof-of-concept | templates, LLM | Exploitation evidence |
| Code Audit | Source code analysis | AST grep | Auth gaps, patterns |
| Reporter | Correlation + report | internal | Markdown report |

### Correlation

Findings from multiple agents are cross-referenced:
- Same vulnerability found by vuln-scan AND code-audit = **priority boost**
- Priority score: severity(0-40) + correlation(0-40) + exploitability(0-25)
- Top findings surface first in the report

## For Code Agent Orchestrators

If you're a code agent (copilot-cli, claude-code, opencode) wanting to orchestrate Erebos:

### Option A: MCP Tool Call
```
Call tool: fleet-scan
Parameters: { "target": "example.com", "repos": ["./api"] }
```

### Option B: CLI Subprocess
```bash
erebos scan example.com --fleet --quiet | jq .
```

### Option C: Sub-Agent Dispatch
Launch sub-agents for each role. Each agent runs independently:

```
# Agent 1: Recon
erebos scan example.com --phase recon --quiet

# Agent 2: Vuln Scan (after recon)
erebos scan example.com --phase vuln-scan --quiet

# Agent 3: Code Audit (parallel with vuln-scan)
# Uses --repo for source-aware analysis

# Agent 4: Exploit (after vuln-scan)
erebos scan example.com --phase exploit --quiet

# Agent 5: Report
erebos report example.com
```

## Output

Fleet scan produces:
- **Live table** (terminal) — Agent progress, findings count, duration
- **JSON summary** (--quiet) — Machine-readable results
- **Markdown report** (./erebos-reports/) — Full pentest report with:
  - Executive summary
  - Severity distribution
  - Prioritized findings with CVE/CWE
  - Evidence and remediation
  - Correlation badges

## When NOT to Use

- Target not in allowlist → configure first
- No network access to target → code-audit only mode
- Production systems without authorization → get written permission first
- Compliance-only scans → use dedicated compliance tools instead
