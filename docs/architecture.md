# Architecture

## System Overview

Erebos is a CLI-based pentest orchestration tool with two execution modes:

1. **Classic Mode** — Sequential phase-based scanning (recon → vuln-scan → exploit → report)
2. **Fleet Mode** — Parallel multi-agent scanning with inter-agent correlation

```
┌────────────────────────────────────────────────────────────────────┐
│  Host Layer (Copilot CLI / Claude Code / OpenCode / MCP Client)    │
├────────────────────────────────────────────────────────────────────┤
│  CLI Commands (Click + Rich)                                       │
│  - scan (--fleet / --phase / --quiet / --osint / --osint-only)     │
│  - scan (--auth-header / --auth-cookie / --auth-profile)           │
│  - dashboard (--web / --host / --port)                             │
│  - mcp-serve (JSON-RPC stdio server)                               │
│  - allowlist, status, report, tools                                │
├────────────────────────────────────────────────────────────────────┤
│  Fleet Orchestrator                                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │
│  │  Recon   │ │ VulnScan │ │ Exploit  │ │CodeAudit │ │Reporter│ │
│  │  Agent   │ │  Agent   │ │  Agent   │ │  Agent   │ │ Agent  │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘ │
│       │             │            │             │            │      │
│  ┌────▼─────────────▼────────────▼─────────────▼────────────▼───┐ │
│  │                    FindingsBus (JSONL)                         │ │
│  └───────────────────────────┬───────────────────────────────────┘ │
│                              │                                     │
│  ┌───────────────────────────▼───────────────────────────────────┐ │
│  │              Correlation Engine + Priority Scorer               │ │
│  └───────────────────────────┬───────────────────────────────────┘ │
│                              │                                     │
│  ┌───────────────────────────▼───────────────────────────────────┐ │
│  │               Fleet Report Builder (Markdown)                  │ │
│  └────────────────────────────────────────────────────────────────┘ │
├────────────────────────────────────────────────────────────────────┤
│  Tool Executor (subprocess)     │  Parsers (nmap, nuclei, httpx,   │
│  - Allowlist validation         │   dnsx, naabu, subfinder, gau,   │
│  - Argument sanitization        │   waybackurls, assetfinder,      │
│  - Output capping (10MB)        │   alterx, dalfox, wpscan, kxss,  │
│  - Concurrency semaphore        │   bxss, arjun, dirsearch, etc.)  │
│                                 │  - Canonical Finding model        │
│                                 │  - CVE/CWE extraction            │
│                                 │  - Evidence preservation         │
├────────────────────────────────────────────────────────────────────┤
│  Exploit Engine                                                    │
│  - Template Engine (16 CWE templates with checksum verification)   │
│  - LLM Cascade (Copilot → Claude → OpenRouter → DeepSeek)         │
│  - Repo Analyzer (code-context-aware exploitation)                 │
├────────────────────────────────────────────────────────────────────┤
│  Security Layer                                                    │
│  - AllowlistValidator            - HMAC Log Integrity              │
│  - Rate Limiter (token bucket)   - Role Verification (S-01)       │
│  - Agent Timeout                 - Bus Message Validation          │
├────────────────────────────────────────────────────────────────────┤
│  Storage                                                           │
│  - ScanStateManager              - FindingStore                    │
│  - FindingsBus (inter-agent)     - Reports (./erebos-reports/)   │
└────────────────────────────────────────────────────────────────────┘
```

## Module Structure

```
erebos/
├── cli/                    # Click commands + Rich display
│   └── commands.py         # scan, mcp-serve, allowlist, dashboard, etc.
├── dashboard/              # Real-time monitoring (TUI + Web)
│   ├── models.py           # DashboardSnapshot, SeverityCounts, AgentStatusView
│   ├── data_layer.py       # Read-only API over FindingStore/ScanState/Bus
│   ├── cli.py              # Click command registration
│   ├── tui/app.py          # Textual TUI with live panels
│   └── web/                # Starlette + SSE web dashboard
│       ├── server.py       # API routes + SSE (localhost:8484)
│       └── static/         # HTML + Alpine.js + CSS
├── agents/                 # Fleet mode orchestration
│   ├── orchestrator.py     # FleetOrchestrator + FleetConfig
│   ├── base.py             # FindingsBus, AgentMessage, AgentRole
│   ├── correlation.py      # CorrelationEngine + PriorityScorer
│   ├── tool_executor.py    # Secure subprocess wrapper
│   ├── mcp_stdio.py        # MCP JSON-RPC 2.0 server
│   ├── log_integrity.py    # HMAC-SHA256 segment signing
│   └── roles/              # Agent role implementations
│       ├── recon.py        # Passive: subfinder, assetfinder, gau, waybackurls, dnsx
│       │                   # Active: nmap, httpx, naabu, katana
│       ├── vuln_scan.py    # nuclei, dalfox, wpscan, kxss, bxss, nikto
│       ├── exploit.py      # templates + LLM
│       ├── reporter.py     # correlation + target-filtered report generation
│       └── __init__.py
├── core/                   # Domain models + orchestration
│   ├── finding.py          # Finding, Severity, Phase, Evidence
│   ├── orchestrator.py     # Classic mode orchestrator
│   ├── decision_engine.py  # AI-guided tool selection
│   └── target_profile.py   # Target fingerprinting
├── exploits/               # Exploit engine
│   ├── runner.py           # ExploitRunner (template + LLM, auth-aware)
│   ├── template_engine.py  # YAML templates with integrity check
│   ├── llm_cascade.py      # Multi-provider LLM fallback (Copilot, Claude, OpenRouter, DeepSeek)
│   └── repo_analyzer.py    # Source code vuln pattern matching
├── auth/                   # Authenticated scanning
│   ├── __init__.py         # AuthContext, AuthCredential, AuthManager
│   └── harvester.py        # CredentialHarvester (extract creds from findings)
├── parsers/                # Tool output normalization
│   ├── base.py             # Parser ABC → List[Finding]
│   ├── nmap.py             # XML + text format
│   ├── nuclei.py           # JSON (CVE/CWE extraction)
│   ├── subfinder.py        # Line-separated subdomains
│   ├── httpx.py            # JSON-lines HTTP probing
│   ├── dnsx.py             # DNS resolution output
│   ├── assetfinder.py      # Line-based subdomain discovery
│   ├── naabu.py            # Port scan (JSON/plain)
│   ├── gau.py              # Passive URL collection
│   ├── waybackurls.py      # Wayback Machine URLs
│   ├── alterx.py           # Subdomain permutations
│   ├── arjun.py            # Hidden parameter discovery
│   ├── dirsearch.py        # Directory brute-force
│   ├── dalfox.py           # XSS findings (JSON-lines)
│   ├── wpscan.py           # WordPress vulnerabilities
│   ├── kxss.py             # Reflected parameter detection
│   ├── bxss.py             # Blind XSS callbacks
│   └── ...                 # amass, dirb, ffuf, gobuster, etc.
├── reporting/              # Report generation
│   ├── fleet_report.py     # FleetReportBuilder (correlation-aware)
│   └── markdown.py         # MarkdownReportBuilder (classic)
├── security/               # Security controls
│   └── allowlist.py        # AllowlistValidator
├── storage/                # Persistence
│   ├── state_manager.py    # Scan state CRUD
│   └── finding_store.py    # Finding persistence
├── config/                 # Configuration
│   └── settings.py         # Pydantic settings model
└── enrichment/             # Target enrichment
    └── http_probe.py       # HTTP service detection
```

## Data Flow

### Fleet Mode

```
1. User: erebos scan target --fleet
2. CLI validates allowlist → creates FleetConfig with per-scan bus path
3. FleetOrchestrator spawns 5 AgentWorkers (parallel) with isolated FindingsBus
4. Each worker:
   a. Acquires rate-limit token
   b. Executes role-specific logic (with auth context if provided)
   c. Tool output → Parser → Finding model
   d. Publishes findings to per-scan FindingsBus
5. Reporter waits for other agents, then:
   a. Filters findings by target domain (prevents cross-contamination)
   b. CorrelationEngine groups findings by target|title
   c. PriorityScorer computes 0-100 score
   d. FleetReportBuilder generates markdown
6. Report saved to ./erebos-reports/ (chmod 600)
```

### Dashboard (Real-time Monitoring)

```
┌─────────────────────────────────────────────────────┐
│  erebos scan --fleet (writes)                      │
│                                                      │
│  FindingsBus ──►  bus.jsonl (append-only JSONL)      │
│  ScanStateManager ──► state.json                     │
│  FindingStore ──► findings.json                      │
│                                                      │
│  ════════════ shared filesystem ══════════════════    │
│                                                      │
│  DashboardDataLayer (reads, polling)                 │
│       │                                              │
│       ├── TUI (Textual) ← erebos dashboard         │
│       │   Refresh: 500ms                             │
│       │   Panels: Agents, Findings, Progress, Log    │
│       │                                              │
│       └── Web (Starlette+SSE) ← erebos dashboard --web
│           Port: localhost:8484                        │
│           Push: SSE every 2s (snapshot + bus events)  │
│           Frontend: Alpine.js + htmx                 │
│                                                      │
│  Security: bind 127.0.0.1 (ID-01), SSE cap 10 (DoS-01)
└─────────────────────────────────────────────────────┘
```

### Finding Priority Score

```
Score = severity_weight + correlation_boost + exploitability_bonus

severity_weight:
  CRITICAL = 40, HIGH = 30, MEDIUM = 20, LOW = 10, INFO = 0

correlation_boost:
  +20 per additional independent signal (capped at +40)
  Source diversity: same role twice = 1 signal, not 2

exploitability_bonus:
  template_available = +15
  auth_gap_confirmed = +10

Maximum score: 100 (capped)
```

## Security Controls

| Control | Location | Purpose |
|---------|----------|---------|
| Allowlist validation | ToolExecutor, VulnScanRole | Prevent out-of-scope scanning |
| Argument sanitization | ToolExecutor._validate_argument() | Prevent command injection |
| Path validation | ToolExecutor._validate_target() | Prevent path traversal |
| Output capping | ToolExecutor (10MB) | Prevent memory exhaustion |
| Rate limiting | FleetOrchestrator (token bucket) | Temporal DoS prevention |
| Agent timeout | FleetOrchestrator (asyncio.wait_for) | Prevent hung agents |
| Role verification | FindingsBus.publish() (S-01) | Prevent role spoofing |
| Log integrity | LogIntegrity (HMAC-SHA256) | Tamper detection |
| Template checksum | TemplateEngine (SHA-256) | Detect template tampering |
| Report permissions | FleetReportBuilder (chmod 600) | Prevent data leakage |
| MCP size limit | MCPStdioServer (1MB) | Prevent DoS via large requests |
| Correlation cap | CorrelationEngine (500 findings) | Prevent O(n²) processing |
