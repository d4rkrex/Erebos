# Argos & Veriscan Integration Roadmap

## Argos Integration (Multi-Agent Cybersec Ops Platform)

### What Argos Is
- Autonomous multi-agent cybersecurity operations platform
- 3-layer governance model with human-in-the-loop (HITL) approval gates
- Agents: Overseer, Pentester, VulnTracker, Auditor, Warden
- MCP catalog with 8+ servers, 50+ tools
- REST API on :8880, WebSocket for real-time events, Vault DB

### Integration Points

1. **Add Erebos to Argos MCP catalog** (`argos-core/src/argos/mcp/catalog.yaml`):
   ```yaml
   - name: erebos-mcp
     description: "Erebos pentest fleet scanning and exploitation"
     category: security-scanner
     install_command: "erebos mcp-serve"
     tools_count: 4
     status: active
     transport: sse
     trust_level: 8
   ```

2. **Grant Pentester agent capability** (TOML manifest):
   ```toml
   [capabilities]
   allowed_tools = ["erebos.fleet-scan", "erebos.list-findings", "erebos.get-report"]
   ```

3. **Workflow**: Overseer delegates "pentest_fleet" → Pentester agent calls Erebos MCP → findings stored via `vault_record_finding` → High/Critical → VulnTracker → Jira

### Data Model Mapping (Erebos → Argos)
| Erebos Finding | Argos Vulnerability |
|---|---|
| `tool` | `source_tool` |
| `severity` | `severity` (same enum) |
| `title` | `title` |
| `cve`/`cves` | `external_vuln_id` |
| `cvss` | `cvss_score` |
| `cwe` | `cwe` |
| `exploitation_status` | `reachable_status` |

---

## Veriscan Integration (Security Gate Dashboard)

### What Veriscan Is
- Security Gate Dashboard for Erebos component releases
- Tracks versions across bimestral releases
- Manages security gate verdicts (pass/fail/warning)
- Correlates Jira VTPR tickets, SAST/SCA scans, merge activity
- FastAPI on :7777, MCP on :5100, PostgreSQL 16

### Integration Points

1. **Erebos → Veriscan scan results** (`POST /api/scan-results/notify`):
   ```json
   {
     "component_id": "<component>",
     "scan_type": "pentest",
     "findings_critical": 2,
     "findings_high": 5,
     "findings_medium": 12,
     "gate_passed": false
   }
   ```

2. **Veriscan → Erebos target feed**: Components with `security_gate = "fail"` become priority targets for fleet-scan.

3. **Security Funnel integration**: Ingest Erebos results as `signal_type = "erebos_pentest"` into SecurityFunnelEvent table.

4. **MCP bus config** for orchestrating agent:
   ```json
   {
     "mcpServers": {
       "veriscan": { "type": "sse", "url": "http://localhost:5100/sse" },
       "erebos": { "command": "erebos", "args": ["mcp-serve"] }
     }
   }
   ```

### Workflow
```
veriscan.list_components(gate="fail") → pick targets
→ erebos.fleet-scan(target) → collect findings
→ veriscan.set_security_gate(component, verdict) based on results
```

---

## Combined Architecture

```
┌────────────────────────────────────────────────────────┐
│  Agent (Claude/Copilot) — MCP Bus                       │
├──────────┬──────────────┬──────────────┬───────────────┤
│  Argos   │  Erebos   │  Veriscan    │  Burp Suite   │
│  :8880   │  :8443       │  :5100       │  :9876        │
├──────────┼──────────────┼──────────────┼───────────────┤
│ Govern   │ Pentest      │ Gate/Track   │ Manual proxy  │
│ Delegate │ Fleet scan   │ Dashboard    │ Exploit       │
│ Approve  │ Exploit      │ Jira sync    │ Collaborator  │
└──────────┴──────────────┴──────────────┴───────────────┘
```

## Implementation Priority

1. **Quick win**: Erebos → Veriscan bridge (webhook adapter, ~100 LOC)
2. **Medium**: Register Erebos in Argos catalog + Pentester agent config
3. **Full**: Bidirectional flow with Veriscan feeding targets + Argos governance gates

## Files to Modify

### For Argos integration:
- `~/repos/Argos/argos-core/src/argos/mcp/catalog.yaml` — add erebos entry
- `~/repos/Argos/argos-core/src/argos/agents/pentester.py` — add fleet-scan capability
- Create: `~/repos/Argos/argos-core/src/argos/mcp/erebos_bridge.py`

### For Veriscan integration:
- Create: `~/repos/Erebos/erebos/integrations/veriscan.py` — webhook adapter
- `~/repos/veriscan/backend/app/routers/scan_results.py` — accept pentest scan type
- `~/repos/veriscan/mcp/server.py` — add `trigger_pentest` tool
