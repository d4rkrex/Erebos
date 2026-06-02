# Erebos — Product Requirements Document

**Version:** 1.0  
**Date:** 2025-05-28  
**Owner:** Erebos AppSec  
**Status:** Draft

---

## 1. Problem Statement

Erebos's application security team needs to run recurring penetration tests against internal and client-facing services. Today this is done manually or with fragmented scripts. The problems:

1. **Tool sprawl** — 15+ CLI tools (nmap, nuclei, subfinder, gau, etc.) must be installed, configured, and invoked manually.
2. **No correlation** — Findings from different tools live in isolation; there's no cross-signal scoring.
3. **No agent integration** — Coding agents (Copilot, Claude Code) cannot invoke pentesting as part of their workflow.
4. **Environment dependency** — Each pentester must install Go tools, Python libs, and system packages locally.
5. **No audit trail** — There's no chain-of-custody for what was scanned, when, and what was found.

## 2. Product Vision

**Erebos is an autonomous pentest orchestrator** that:
- Exposes security scanning as an **MCP tool** consumable by any AI coding agent
- Runs tools inside a **Docker container** (zero local install required)
- Correlates findings across tools using a **multi-agent fleet** architecture
- Supports both **remote execution** (Docker on OKE/VM) and **local execution** (for offline/air-gapped)
- Provides **real-time observability** via TUI and web dashboard

## 3. Target Users

| Persona | How they use Erebos |
|---------|----------------------|
| **Coding Agent** (Copilot, Claude) | Calls `fleet-scan` via MCP during code review or PR validation |
| **AppSec Engineer** | Runs CLI directly or monitors dashboard during pentest engagements |
| **DevSecOps Pipeline** | Triggers scans in CI/CD via MCP or CLI in Docker |
| **Red Team Operator** | Uses `--base-path` scoped engagements with full exploit chain |

## 4. Use Cases

### UC-1: Agent-Driven Security Scan (Primary)
A coding agent detects a new API endpoint in a PR. It invokes Erebos's MCP `fleet-scan` tool against the staging environment. Erebos runs recon → vuln-scan → exploit phases remotely in Docker, returns prioritized findings to the agent, which then suggests code fixes.

### UC-2: Scheduled Pentest
AppSec schedules weekly fleet scans against `*.erebos.com`. Results feed into the findings dashboard. Trends are tracked over time.

### UC-3: White-Hat Scoped Engagement
External auditor scans only `/api/v2/` of a target using `--base-path`. Erebos constrains all tools to that path prefix.

### UC-4: Local Development Scan
Developer runs `erebos scan localhost:3000 --fleet` with tools installed via Homebrew. No Docker required.

### UC-5: CI/CD Gate
GitHub Action runs Erebos in Docker against staging after deploy. If critical findings > 0, pipeline fails.

## 5. Architecture (Current State)

```
┌─────────────────────────────────────────────────────────┐
│                    Erebos CLI                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Classic Mode │  │  Fleet Mode  │  │  MCP Server   │  │
│  │ (sequential) │  │ (5 parallel) │  │ (JSON-RPC 2.0)│  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬───────┘  │
│         │                 │                   │          │
│  ┌──────▼─────────────────▼───────────────────▼───────┐ │
│  │              Tool Executor (sandbox)                 │ │
│  │  • Allowlist validation (EP-01)                     │ │
│  │  • Rate limiting (D-01)                             │ │
│  │  • stdout cap 10MB, timeout 10min                   │ │
│  │  • No shell=True, binary allowlist                  │ │
│  └──────┬─────────────────────────────────────────────┘ │
│         │                                                │
│  ┌──────▼──────────────────────────────────────────────┐│
│  │                    Parsers                           ││
│  │  nmap│nuclei│subfinder│gau│httpx│katana│ffuf│...    ││
│  └──────┬──────────────────────────────────────────────┘│
│         │                                                │
│  ┌──────▼──────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  Findings   │  │  Correlation │  │   Reporting   │  │
│  │  (JSONL bus)│  │  Engine      │  │  (MD/HTML/JSON)│  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 6. Execution Modes

### 6.1 Local Mode (tools on host)
```bash
erebos scan target.com --fleet
```
- Tools must be installed locally
- Good for: development, air-gapped environments

### 6.2 Docker Mode (tools in container)
```bash
docker compose run --rm erebos scan target.com --fleet
```
- All tools bundled in image (~800MB)
- Good for: CI/CD, standardized environments

### 6.3 Remote MCP Mode (tools on remote host)
```json
// .mcp.json
{
  "erebos": {
    "command": "ssh",
    "args": ["erebos-server", "docker", "exec", "-i", "erebos", "python", "-m", "erebos", "mcp-stdio"]
  }
}
```
- Agent connects via SSH → Docker exec → MCP stdio
- Good for: coding agents, centralized scanning infrastructure

## 7. Tool Inventory

### Recon (Passive + Active)
| Tool | Purpose | Docker | Local Optional |
|------|---------|--------|----------------|
| subfinder | Passive subdomain enumeration | ✅ | ✅ |
| assetfinder | Subdomain discovery (passive) | ✅ | ✅ |
| gau | Passive URL collection (OTX, Wayback, CommonCrawl) | ✅ | ✅ |
| waybackurls | Historical URL mining | ❌ | ✅ |
| httpx | HTTP probing, tech fingerprinting | ✅ | ✅ |
| dnsx | DNS resolution and validation | ✅ | ✅ |
| naabu | Fast SYN port scanning | ✅ | ✅ |
| nmap | Port scanning, service detection | ✅ | ✅ |
| katana | Active web crawling | ❌ | ✅ |

### Discovery
| Tool | Purpose | Docker | Local Optional |
|------|---------|--------|----------------|
| ffuf | Directory/parameter brute-forcing | ✅ | ✅ |
| dirsearch | Directory brute-force | ❌ | ✅ |
| arjun | Hidden HTTP parameter discovery | ❌ | ✅ |
| gobuster | Dir/DNS/VHost brute-force | ❌ | ✅ |

### Vulnerability Scanning
| Tool | Purpose | Docker | Local Optional |
|------|---------|--------|----------------|
| nuclei | Template-based vuln scanning | ✅ | ✅ |
| nikto | Web server misconfiguration | ✅ | ✅ |
| sqlmap | SQL injection testing | ✅ | ✅ |

### Exploitation
| Tool | Purpose | Docker | Local Optional |
|------|---------|--------|----------------|
| DAST Engine | Template + LLM-generated payloads | ✅ (built-in) | ✅ |
| hydra | Brute-force authentication | ✅ | ❌ |

## 8. Security Controls

| ID | Control | Description |
|----|---------|-------------|
| EP-01 | Allowlist | Target must be explicitly authorized before any scan |
| T-01 | Transport sandbox | No shell=True, binary path validation, arg sanitization |
| D-01 | Rate limiting | Token-bucket per-tool (20 req/s), global budget (5000 DAST) |
| R-01 | Audit logging | HMAC-SHA256 chain integrity on all scan actions |
| DOS-01 | Budget caps | Hard limits on requests, subprocess count (4), timeout (10min) |
| INJ-02 | Template sandbox | DAST templates validated before execution |
| S-01 | Auth model | Stdio = local trust; SSE = bearer token required |

## 9. Current Gaps (vs. Vision)

| # | Gap | Impact | Priority |
|---|-----|--------|----------|
| G-1 | ReconRole only executes 5/12 tools | Poor attack surface coverage | High |
| G-2 | No `docker-compose.yml` for easy deployment | Must build image manually | High |
| G-3 | Missing tools in Dockerfile (waybackurls, katana, arjun, gobuster, dirsearch) | Incomplete scanning | Medium |
| G-4 | No remote scan status streaming | Agent can't monitor long scans | Medium |
| G-5 | Classic mode doesn't use ToolExecutor | No safety controls in classic path | Medium |
| G-6 | No findings persistence across scans | Can't track trends | Low |
| G-7 | No CI/CD Docker action | Manual integration required | Low |
| G-8 | Erebos AI platform not integrated | Two separate products | Future |

## 10. Success Metrics

| Metric | Target |
|--------|--------|
| Tools executed in fleet scan | ≥10 (currently 3) |
| Time to first finding | < 60 seconds |
| Agent integration latency (MCP call → first result) | < 5 seconds |
| False positive rate | < 20% |
| Docker image size | < 1 GB |
| Zero local install required for agent use | Yes (Docker only) |

## 11. Non-Goals (v1)

- Web UI beyond monitoring (no scan management UI — use CLI/MCP)
- Multi-tenant access control (single-team tool)
- Paid vulnerability databases (only free/open-source tools)
- Windows support
- Integration with erebos-ai platform (separate phase)
