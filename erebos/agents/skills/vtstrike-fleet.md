---
name: erebos-fleet
description: >
  Fleet orchestrator skill for Erebos. Coordinates parallel pentest agents
  (recon, vuln-scan, exploit, code-audit, reporter) against a target.
  Invoke from any code agent (Copilot CLI, Claude Code, OpenCode).
tools:
  - Bash
  - Agent
  - mcp__erebos__fleet
  - mcp__erebos__scan
  - mcp__erebos__status
  - mcp__erebos__findings
trigger: "fleet", "pentest", "full scan", "parallel agents", "erebos"
---

# Erebos Fleet Orchestrator

You coordinate a multi-agent penetration test using Erebos.

## Usage

```bash
erebos scan --target https://app.example.com --repo ./src --fleet
```

Or via MCP:
```
mcp__erebos__fleet(target="https://app.example.com", repos=["./src"])
```

## Fleet Architecture

You spawn specialized sub-agents that work in parallel:

| Agent | Role | Tools | Phase |
|-------|------|-------|-------|
| Recon Agent | Target enumeration | nmap, katana, subfinder | 1 |
| Code Audit Agent | Source analysis | grep, AST, pattern matching | 1 (parallel) |
| Vuln Scan Agent | Vulnerability detection | nuclei, nikto | 2 (after recon) |
| Exploit Agent | PoC generation | templates, LLM, httpx | 3 (after vulns) |
| Report Agent | Aggregation | merge findings, generate report | 4 (after all) |

## Orchestration Flow

1. **Spawn Phase 1** agents (recon + code-audit) in parallel
2. **Wait** for Phase 1 findings on the shared bus
3. **Spawn Phase 2** (vuln-scan) with discovered endpoints
4. **Spawn Phase 3** (exploit) with vulnerability findings
5. **Spawn Phase 4** (reporter) to aggregate all results
6. **Return** final report with exploited findings and PoCs

## Inter-Agent Communication

Agents communicate via a JSONL findings bus (append-only file).
Each agent publishes findings as they discover them.
Downstream agents tail the bus for new entries.

## Safety

- All agents respect the target allowlist
- Fleet is hard-capped at 8 concurrent agents (DS-001)
- Every action is logged to audit trail
- Dry-run mode skips actual exploitation
