# Argos ↔ Erebos Integration Report

> **Internal document** — Not for publication. Analysis of how to integrate Erebos as an MCP
> server consumed by Argos agents.

## Executive Summary

Argos already has full MCP infrastructure (registry, client, SSE transport, tool discovery). Erebos already has an MCP SSE server. Integration is **trivial** — register Erebos as an external MCP server in Argos catalog and grant the `pentester` agent access.

**Effort estimate**: ~2 hours of config + 1 agent manifest update.

---

## Architecture Match

```
┌──────────────────────────────────────────────────────────────────────┐
│ Argos (erebos-server)                                                 │
│                                                                       │
│  Overseer Agent                                                       │
│       │ delegates "pentest target X"                                  │
│       ▼                                                               │
│  Pentester Agent                                                      │
│       │ calls MCP tool: erebos-mcp/fleet_scan                       │
│       ▼                                                               │
│  MCPClient (SSE transport)                                            │
│       │ POST http://localhost:5100/mcp                                 │
│       │ Authorization: Bearer <token>                                  │
│       ▼                                                               │
├──────────────────────────────────────────────────────────────────────┤
│ Erebos MCP SSE Server (Docker, same host)                          │
│       │ dispatches fleet_scan                                          │
│       ▼                                                               │
│  Fleet Orchestrator → nuclei, nmap, nikto, subfinder, httpx           │
│       │                                                               │
│       ▼                                                               │
│  Returns: findings[] with correlation scores                          │
└──────────────────────────────────────────────────────────────────────┘
```

Both run on `erebos-server.local` at `/erebos/`. Communication is localhost SSE (no TLS needed for loopback).

---

## Integration Steps

### Step 1: Register Erebos in Argos MCP Catalog

**File**: `argos-core/src/argos/mcp/catalog.yaml`

```yaml
- name: erebos-mcp
  description: "Erebos autonomous pentest orchestrator with fleet mode"
  category: offensive-security
  transport: sse
  url: "http://localhost:5100/sse"
  status: active
  trust_level: 7
  required_env:
    - VT_STRIKE_SSE_TOKEN
  tools:
    - fleet_scan
    - single_scan
    - list_tools
    - scan_status
```

### Step 2: Register in MCP Registry

**File**: `argos-core/src/argos/mcp/registry.py`

Add to server definitions:

```python
"erebos-mcp": {
    "module": None,  # external server
    "aliases": frozenset({"erebos-mcp", "erebos", "erebos"}),
    "port": None,
    "url": os.getenv("EREBOS_MCP_URL", "http://localhost:5100/sse"),
}
```

### Step 3: Set Transport Environment Variable

**File**: Argos `.env` or docker-compose environment:

```env
MCP_TRANSPORT_EREBOS_MCP=protocol
EREBOS_MCP_URL=http://erebos:5100/sse
VT_STRIKE_SSE_TOKEN=<shared-secret>
```

### Step 4: Grant Pentester Agent Access

**File**: `argos-core/src/argos/agents/manifests/pentester.toml`

```toml
[tool_policy]
allow = [
    "scan-orchestrator-mcp/*",
    "vault-mcp/get_*",
    "erebos-mcp/*",          # ← ADD THIS
]
```

### Step 5: Docker Network (if both containerized)

If both Argos and Erebos run in Docker on the same host, create a shared network:

```yaml
# argos docker-compose.yaml
services:
  argos-api:
    networks:
      - argos-internal
      - appsec-shared   # ← shared with erebos

networks:
  appsec-shared:
    external: true
    name: appsec-shared
```

```yaml
# erebos docker-compose.yaml
services:
  erebos:
    networks:
      - erebos-internal
      - appsec-shared   # ← shared with argos

networks:
  appsec-shared:
    external: true
    name: appsec-shared
```

Create the shared network: `docker network create appsec-shared`

---

## Usage Flow

### From Argos UI (Syndicate)

1. User navigates to Agents → Pentester → hires if not active
2. User sends chat: "Scan vippinn.com for vulnerabilities"
3. Overseer classifies intent → delegates to Pentester
4. Pentester's governance pipeline checks: `erebos-mcp/fleet_scan` is in allow list ✅
5. MCPClient calls Erebos SSE endpoint:
   ```json
   {
     "jsonrpc": "2.0",
     "method": "tools/call",
     "params": {
       "name": "fleet_scan",
       "arguments": {
         "target": "vippinn.com",
         "mode": "fleet"
       }
     }
   }
   ```
6. Erebos runs fleet (recon → vuln-scan → exploit → code-audit → report)
7. Returns findings with correlation scores
8. Pentester formats results → returns to Overseer → displayed in UI

### From Argos API (Programmatic)

```bash
curl -X POST http://erebos-server:8880/api/v2/agents/pentester/task \
  -H "Authorization: Bearer $ARGOS_TOKEN" \
  -d '{"intent": "pentest", "target": "192.168.1.100", "tool": "erebos-mcp/fleet_scan"}'
```

### From Argos Chat (Slack/UI)

```
@argos scan 192.168.1.100 with erebos full fleet
```

---

## Agent Manifest for Dedicated Erebos Agent (Optional)

For a dedicated "striker" agent that ONLY uses Erebos:

**File**: `argos-core/src/argos/agents/manifests/striker.toml`

```toml
[agent]
name = "striker"
version = "1.0.0"
description = "Autonomous pentest agent backed by Erebos fleet orchestration"
model = "gpt-4.1"
trust_level = 7
capabilities = ["scan_execute", "scan_read", "vault_read"]
delegations = []

[tool_policy]
allow = ["erebos-mcp/*", "vault-mcp/get_*"]
deny = ["*"]

[resource_limits]
tokens_per_hour = 50000
max_concurrent_tasks = 2

[scheduling]
enabled = false
```

---

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Token exposure | Store in Argos vault, inject via env |
| Lateral movement | Erebos in isolated Docker network |
| Over-delegation | Governance L1 checks tool_policy |
| Resource exhaustion | Erebos has rate limits + connection caps |
| Target validation | Erebos enforces allowlist server-side |

---

## What's Already Compatible

| Feature | Argos Side | Erebos Side | Status |
|---------|-----------|---------------|--------|
| MCP SSE transport | MCPClient with SSE | MCPSSEServer | ✅ Ready |
| Tool discovery | `list_tools` call | Responds to `tools/list` | ✅ Ready |
| Bearer auth | Sends token in header | Validates with hmac.compare_digest | ✅ Ready |
| Health monitoring | MCPRegistry health checks | GET /health returns "ok" | ✅ Ready |
| JSON-RPC protocol | Standard MCP SDK | Standard MCP protocol | ✅ Ready |

---

## Gaps / Future Work

1. **Streaming results**: Erebos fleet scans take 5-15 minutes. Argos should poll scan_status or subscribe to SSE events for progress updates.
2. **Finding ingestion**: Argos should import Erebos findings into its PostgreSQL findings table for dashboard display.
3. **Scheduling**: Argos scheduler could trigger periodic Erebos scans on a cron.
4. **HITL gate**: For high-severity exploits, Erebos could emit an approval request that goes through Argos governance L3 (human-in-the-loop).

---

## Conclusion

Integration is **plug-and-play**. Both systems speak MCP over SSE. The only work is:
1. Add catalog entry (5 lines YAML)
2. Add registry entry (5 lines Python)
3. Set 2 env vars
4. Add 1 line to pentester manifest

No code changes needed on Erebos side. Argos already supports external MCP servers natively.
