# Burp Suite MCP Integration

Erebos can work alongside **Burp Suite's MCP Server** plugin to combine automated scanning with interactive proxy-based testing.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Coding Agent (Claude Code / Copilot / OpenCode)             │
│                                                              │
│  MCP Clients:                                                │
│    ├── erebos   → autonomous fleet scanning                │
│    └── burpsuite  → interactive proxy + manual testing       │
└──────┬───────────────────────────────┬──────────────────────┘
       │ stdio/SSE                     │ stdio (java proxy)
       ▼                               ▼
┌──────────────┐              ┌──────────────────┐
│  Erebos   │              │  Burp Suite Pro  │
│  MCP Server  │              │  MCP Extension   │
│  :8443       │              │  :9876           │
└──────────────┘              └──────────────────┘
```

## Setup

### Prerequisites

- Burp Suite Professional (or Community with limitations)
- Java 17+ on PATH
- PortSwigger MCP extension: [github.com/PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server)

### 1. Install Burp MCP Extension

```bash
git clone https://github.com/PortSwigger/mcp-server.git
cd mcp-server
./gradlew embedProxyJar
# Output: build/libs/burp-mcp-all.jar + mcp-proxy-all.jar
```

Load `burp-mcp-all.jar` in Burp → Extensions → Add (Java type).

### 2. Configure Agent

Add both MCPs to your agent config:

```json
{
  "mcpServers": {
    "erebos": {
      "command": "erebos",
      "args": ["mcp-serve"]
    },
    "burpsuite": {
      "type": "stdio",
      "command": "java",
      "args": ["-jar", "/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    }
  }
}
```

Or use the automated installer:

```bash
./scripts/install-client.sh --with-burp --agent claude
```

### 3. Verify

```bash
# Burp MCP health (requires Burp running with extension)
curl -s http://127.0.0.1:9876/health

# Erebos health
erebos mcp-serve &
curl -s http://127.0.0.1:8443/health
```

## Use Cases

### 1. Automated Recon → Manual Exploitation

```
Agent workflow:
1. @erebos fleet-scan target.com          → finds SQLi on /api/users?id=1
2. @burpsuite send_to_repeater              → send the vulnerable request to Burp Repeater
3. Human manually crafts exploit in Burp    → confirms SQLi, extracts data
4. @erebos list-findings --severity high  → documents finding with evidence
```

**Value**: Erebos does broad automated recon, Burp handles surgical manual testing.

### 2. Burp Crawl + Erebos Vuln Scan

```
Agent workflow:
1. @burpsuite start_crawl target.com        → Burp crawls with browser
2. @burpsuite get_sitemap                   → export discovered endpoints
3. Feed endpoints to Erebos context
4. @erebos scan target.com --phase vuln-scan  → nuclei/dalfox on Burp-discovered paths
```

**Value**: Burp's browser-based crawler finds JS-rendered endpoints that passive tools miss.

### 3. Collaborator-Powered Blind Testing

```
Agent workflow:
1. @burpsuite generate_collaborator_payload → get unique Burp Collaborator URL
2. @erebos scan target.com --phase vuln-scan  → bxss/dalfox inject collaborator payloads
3. @burpsuite check_collaborator_interactions   → verify OOB callbacks
```

**Value**: Burp Collaborator provides out-of-band detection that confirms blind vulns found by Erebos tools.

### 4. Authenticated Scanning via Burp Session

```
Agent workflow:
1. Human logs into app through Burp proxy
2. @burpsuite get_cookies                   → extract session tokens
3. Pass cookies to Erebos scan context
4. @erebos scan target.com --phase vuln-scan  → authenticated nuclei/arjun scan
```

**Value**: Burp handles complex auth flows (MFA, CSRF tokens), Erebos scans the authenticated surface.

### 5. Continuous Pentest Pipeline

```
Agent workflow:
1. @erebos fleet-scan staging.target.com  → nightly automated scan
2. For each HIGH/CRITICAL finding:
   a. @burpsuite send_to_intruder           → set up targeted attack
   b. @burpsuite run_intruder_attack        → validate with payloads
   c. @burpsuite get_intruder_results       → collect evidence
3. @erebos get-report                     → correlated report with manual validation
```

**Value**: Full pipeline from automated discovery to manual confirmation.

## Burp MCP Tools Reference

| Tool | Description |
|------|-------------|
| `send_to_repeater` | Send request to Burp Repeater |
| `send_to_intruder` | Send request to Burp Intruder |
| `start_crawl` | Start Burp crawler on target |
| `get_sitemap` | Export site map entries |
| `generate_collaborator_payload` | Create unique Collaborator URL |
| `check_collaborator_interactions` | Check for OOB callbacks |
| `get_proxy_history` | Get intercepted requests |
| `get_cookies` | Extract cookies from session |
| `run_active_scan` | Launch Burp active scanner on URL |
| `get_scan_results` | Retrieve Burp scanner findings |

## Combined MCP Config (Full Setup)

```json
{
  "mcpServers": {
    "erebos": {
      "command": "erebos",
      "args": ["mcp-serve"],
      "env": {
        "EREBOS_ALLOWLIST": "target.com,*.target.com"
      }
    },
    "burpsuite": {
      "type": "stdio",
      "command": "java",
      "args": ["-jar", "~/.local/share/burp-mcp/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    }
  }
}
```

## Security Notes

- Burp MCP binds to `127.0.0.1:9876` by default (loopback only)
- Erebos allowlist still enforced — Burp data doesn't bypass it
- Collaborator payloads are unique per session — no data leakage between engagements
- Both MCPs support bearer token auth for remote deployments
