# Erebos PRD

## Product Requirements Document

---

## 1. Executive Summary

**Erebos** es un agente de pentesting modular y plugin-first diseñado para integrarse en **OpenCode** y **Copilot CLI**. Orquesta herramientas de seguridad de Kali Linux por fases (recon, discovery, vuln-scan, validation, reporting), ejecutándolas via CLI o MCP, y genera reportes Markdown con sugerencias de explotación manual.

### Value Proposition

- **Plugin-first**: Se integra como custom agent en OpenCode/Copilot CLI
- **Orquestación por fases**: Ejecución estructurada de tools de pentest
- **Reportes accionables**: Markdown con sugerencias Burp/Python/curl
- **Seguridad por diseño**: Allowlist, rate limiting, kill switch

---

## 2. Current Implementation Status

### 2.1 What Was Built (MVP)

| Component | Files | Description |
|-----------|-------|-------------|
| **Core Models** | `finding.py`, `phase_agent.py` | Finding model, Phase enum, Scan profiles |
| **Orquestación** | `orchestrator.py` | PhaseStateMachine con pause/resume/abort |
| **Tool Integration** | `cli_adapter.py`, `mcp_adapter.py`, `tool_discovery.py` | Transporte CLI + MCP con fallback |
| **Parsers** | `nuclei.py`, `nikto.py`, `katana.py` | Normalización de outputs |
| **Seguridad** | `scope.py`, `rate_limit.py` | Allowlist, RateLimiter, ConcurrencyLimiter |
| **Reporting** | `markdown.py` | MarkdownReportBuilder con severity sorting |
| **CLI** | `commands.py`, `main.py` | Click-based commands + shell completion |
| **Host Integration** | `opencode.py`, `copilot.py` | Adapters para ambos hosts |
| **Tests** | 14+ tests | Unit + Integration |

### 2.2 Metrics

- **Tasks Completed**: 56/56 (100%)
- **Files Created**: 35+
- **Tests**: 53/54 passing
- **Spec Compliance**: 18/18 scenarios (100%)

### 2.3 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Erebos                          │
├─────────────────────────────────────────────────────────────┤
│  Host Layer                                                │
│  ┌─────────────┐  ┌─────────────┐                         │
│  │  OpenCode   │  │  Copilot    │                         │
│  │  Adapter    │  │  Adapter    │                         │
│  └──────┬──────┘  └──────┬──────┘                         │
│         │                │                                 │
│  ┌──────┴────────────────┴──────┐                          │
│  │     CLI Commands Layer       │                          │
│  │  scan, status, report, etc  │                          │
│  └──────────────┬───────────────┘                          │
│                 │                                           │
│  ┌──────────────┴───────────────┐                          │
│  │   Orchestration Layer        │                          │
│  │  PhaseStateMachine           │                          │
│  │  ReconAgent, VulnScanAgent   │                          │
│  │  ReportingAgent              │                          │
│  └──────────────┬───────────────┘                          │
│                 │                                           │
│  ┌──────────────┴───────────────┐                          │
│  │   Execution Layer            │                          │
│  │  ┌─────────┐  ┌─────────┐    │                          │
│  │  │CLI      │  │MCP      │    │                          │
│  │  │Adapter  │  │Adapter  │    │                          │
│  │  └────┬────┘  └────┬────┘    │                          │
│  │       │            │         │                          │
│  │  ┌────┴────────────┴────┐    │                          │
│  │  │   Tool Discovery     │    │                          │
│  │  │   katana, nuclei...  │    │                          │
│  │  └──────────────────────┘    │                          │
│  └──────────────┬───────────────┘                          │
│                 │                                           │
│  ┌──────────────┴───────────────┐                          │
│  │   Parsers Layer              │                          │
│  │  katana → Finding[]           │                          │
│  │  nuclei  → Finding[]          │                          │
│  │  nikto   → Finding[]          │                          │
│  └──────────────┬───────────────┘                          │
│                 │                                           │
│  ┌──────────────┴───────────────┐                          │
│  │   Reporting Layer             │                          │
│  │  MarkdownReportBuilder       │                          │
│  └────────────────────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Phase Execution Flow

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   RECON  │───▶│ DISCOVERY │───▶│ VULN-SCAN│───▶│VALIDATION│───▶│ REPORTING│
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │               │
  katana         ffuf/gobuster   nuclei/nikto    manual check   markdown
  nmap                                sqlmap                          html
```

---

## 4. Roadmap: Recommendations for Future Iterations

### 4.1 Priority Matrix

| Priority | Item | Rationale | Effort |
|----------|------|-----------|--------|
| **HIGH** | Sub-agentes especializados por fase | El diseño contempla `ReconAgent`, `VulnScanAgent`, `ReportingAgent` - ya creados pero pueden expandirse con más lógica de decisión | Medium |
| **HIGH** | Más parsers | Añadir: `sqlmap`, `nmap`, `dirb`, `gobuster`, `ffuf` | Medium |
| **MEDIUM** | MCP Server real | El STDIO mode está creado pero no hay server MCP de Kali corriendo | High |
| **MEDIUM** | Reportes HTML | Además de Markdown, un HTML interactivo sería útil | Low |
| **MEDIUM** | Plugin real de OpenCode/Copilot | Los stubs existen, falta el binding real al CLI del host | Medium |
| **LOW** | Shodan/Censys integration | Enrichment de findings con OSINT | Medium |
| **LOW** | AI-powered exploitation suggestions | Usar LLM para sugerir explotación basada en findings | High |
| **LOW** | Video walkthrough con Remotion | Generar videos del scan flow | Low |

### 4.2 Detailed Recommendations

#### HIGH PRIORITY

**H1: Expand Sub-Agents**

- **Current**: `ReconAgent`, `VulnScanAgent`, `ReportingAgent` existen como stubs
- **Recommended**:
  - `ReconAgent`: Añadir lógica de enumeración de subdominios con múltiples tools
  - `VulnScanAgent`: Añadir priorización de vulnerabilidades por CVSS
  - `ReportingAgent`: Enrichment con CVE references, CWEs

**H2: Add More Parsers**

| Tool | Parser Status | Output Format |
|------|---------------|---------------|
| sqlmap | Not implemented | Text/JSON |
| nmap | Not implemented | XML/JSON |
| dirb | Not implemented | Text |
| gobuster | Not implemented | Text/JSON |
| ffuf | Not implemented | JSON |

#### MEDIUM PRIORITY

**M1: MCP Server Integration**

- **Current**: STDIO mode implementado, pero sin server MCP real
- **Recommended**: Integrar con `kali-mcp` o crear wrapper que levante el server

**M2: HTML Reports**

- **Current**: Solo Markdown
- **Recommended**: Añadir `HtmlReportBuilder` con:
  - Finding cards por severidad
  - Gráficos de distribución de vulnerabilidades
  - Export a PDF

**M3: OpenCode/Copilot Plugin Binding**

- **Current**: Stubs en `hosts/opencode.py` y `hosts/copilot.py`
- **Recommended**: Registrar como plugin real en cada CLI

#### LOW PRIORITY

**L1: OSINT Enrichment**

- Integrar Shodan API para enrichment de IPs
- Integrar Censys para datos de exposure
- Integrar VirusTotal para reputation checking

**L2: AI-Powered Suggestions**

- Usar LLM (local o API) para generar suggestions de explotación
- Basado en: finding type + context → suggestions con payloads

**L3: Remotion Videos**

- Usar skill `remotion` para generar videos del scan flow
- Demo para marketing/documentation

---

## 5. Security Considerations

### 5.1 Implemented Controls

- ✅ **Allowlist**: Solo targets autorizados
- ✅ **Rate Limiting**: Throttling por tool
- ✅ **Concurrency Limits**: Max parallel executions
- ✅ **Kill Switch**: Abort global
- ✅ **Dry-run mode**: Preview sin ejecución

### 5.2 Future Security Needs

- Audit logging persistente
- Session encryption
- Scope validation por fase

---

## 6. Acceptance Criteria (Current)

| AC | Description | Status |
|----|-------------|--------|
| AC-001 | Orquestación por fases | ✅ |
| AC-002 | katana + nuclei + nikto | ✅ |
| AC-003 | CLI + MCP transporte | ✅ |
| AC-004 | Allowlist + dry-run | ✅ |
| AC-005 | Markdown reportes | ✅ |
| AC-006 | Host integration stubs | ✅ |

---

## 7. Tech Stack

- **Language**: Python 3.10+
- **Package Manager**: Poetry
- **CLI**: Click
- **Config**: Pydantic + YAML
- **Testing**: pytest

---

## 8. File Structure

```
erebos/
├── __init__.py
├── core/
│   ├── __init__.py
│   ├── finding.py          # Finding model, Severity, Phase enums
│   ├── orchestrator.py     # PhaseStateMachine, KillSwitch
│   ├── phase_agent.py      # ReconAgent, VulnScanAgent, ReportingAgent
│   └── scan_profile.py     # Profile definitions
├── config/
│   ├── __init__.py
│   └── settings.py         # Pydantic settings
├── storage/
│   ├── __init__.py
│   └── scan_state.py      # ScanState, FindingStore
├── executors/
│   ├── __init__.py
│   ├── base.py            # Transport abstraction
│   ├── cli_adapter.py    # CLI execution
│   ├── mcp_adapter.py    # MCP transport
│   ├── tool_discovery.py # Tool availability
│   └── retry.py          # Exponential backoff
├── parsers/
│   ├── __init__.py
│   ├── base.py           # Parser abstraction
│   ├── nuclei.py         # Nuclei JSON parser
│   ├── nikto.py         # Nikto text parser
│   └── katana.py        # Katana URL parser
├── reporting/
│   ├── __init__.py
│   └── markdown.py      # MarkdownReportBuilder
├── security/
│   ├── __init__.py
│   ├── scope.py         # AllowlistValidator
│   └── rate_limit.py   # RateLimiter, ConcurrencyLimiter
├── cli/
│   ├── __init__.py
│   ├── commands.py      # Click commands
│   └── main.py          # Entry point
├── hosts/
│   ├── __init__.py
│   ├── opencode.py      # OpenCode adapter
│   └── copilot.py      # Copilot CLI adapter
tests/
├── __init__.py
├── conftest.py
├── unit/
│   ├── test_orchestrator.py
│   ├── test_parsers.py
│   └── test_config.py
└── integration/
    ├── test_scan_flow.py
    ├── test_cli.py
    └── test_allowlist.py
```

---

## 9. Next Steps

1. **Expand parsers**: sqlmap, nmap, ffuf
2. **Enhance sub-agents**: Lógica de decisión por fase
3. **HTML reporting**: Dashboard interactivo
4. **Plugin binding**: Registrar en OpenCode/Copilot
5. **MCP integration**: Server real

---

*Document Version: 1.0*
*Last Updated: 2026-03-17*
