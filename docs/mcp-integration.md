# MCP Integration

Erebos exposes its tools via a Model Context Protocol (MCP) JSON-RPC 2.0 stdio server, allowing any code agent (Copilot CLI, Claude Code, OpenCode) to invoke scans programmatically.

## Available MCP Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `fleet-scan` | Full fleet scan with correlation | `target`, `repos[]`, `profile`, `auth_header`, `auth_cookie` |
| `scan` | Single-phase scan | `target`, `phase`, `profile`, `auth_header`, `auth_cookie` |
| `get-report` | Retrieve scan report | `scan_id` |
| `list-findings` | List findings with filters | `scan_id`, `severity`, `phase` |

## Setup

### 1. Register with your code agent

Add to your `.mcp.json` (auto-generated):

```json
{
  "mcpServers": {
    "erebos": {
      "command": "python3",
      "args": ["-m", "erebos", "mcp-serve"],
      "env": {
        "EREBOS_ALLOWLIST": "example.com,*.example.com"
      }
    }
  }
}
```

### 2. Configure allowlist (REQUIRED)

**EP-01 Prerequisite**: MCP server refuses to start without an active allowlist.

```bash
erebos allowlist add example.com
erebos allowlist add "10.0.0.0/8"
```

### 2b. LLM Provider Keys (Optional, for exploit generation)

| Variable | Provider | Notes |
|----------|----------|-------|
| `GITHUB_COPILOT_API_KEY` | Copilot | Auto-resolves from `gh auth token` if unset |
| `ANTHROPIC_API_KEY` | Claude | Direct Anthropic API |
| `OPENROUTER_API_KEY` | OpenRouter | Multi-model fallback |
| `DEEPSEEK_API_KEY` | DeepSeek | OpenAI-compatible at `api.deepseek.com` |

### 3. Start MCP server

```bash
# Direct start (for testing)
erebos mcp-serve

# Or via MCP client (automatic from .mcp.json)
```

## Using from Code Agents

### Copilot CLI

```
@erebos fleet-scan example.com --repos ~/my-app
@erebos get-report --scan-id abc123
```

### Claude Code / OpenCode

The agent reads `.mcp.json` and exposes Erebos tools automatically. Use the `/fleet` pattern:

```
/fleet scan example.com with all agents
```

This triggers the agent to use the `fleet-scan` MCP tool internally.

## Agent Skill Mode

Erebos is also available as an **agent skill** (see `SKILL.md`):

```bash
# In Copilot CLI or any agent that supports skills
# The agent can use these triggers:
# - "pentest target X"
# - "fleet scan X with repos"
# - "security assessment of X"
```

### Multi-Agent Fleet Pattern

When a code agent invokes `fleet-scan`, Erebos internally spawns 5 parallel sub-agents (same process). The code agent sees a single tool call that returns a complete pentest report:

```
Code Agent                  Erebos MCP
   │                            │
   ├─── fleet-scan(target) ────►│
   │                            ├──► Recon Agent
   │                            ├──► VulnScan Agent
   │                            ├──► Exploit Agent
   │                            ├──► CodeAudit Agent
   │    (waiting for result)    ├──► Reporter Agent
   │                            │
   │◄── report.md ─────────────┤
   │                            │
```

## Protocol Details

### Transport

- **Transport**: stdio (stdin/stdout)
- **Protocol**: JSON-RPC 2.0
- **Message limit**: 1 MB per request

### Request Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "fleet-scan",
    "arguments": {
      "target": "example.com",
      "repos": ["~/my-app"],
      "profile": "comprehensive",
      "auth_header": "Authorization: Bearer ey...",
      "auth_cookie": "session_id=abc123"
    }
  }
}
```

### Scan Isolation

Each MCP scan creates an isolated FindingsBus scoped by `scan_id`. Findings from one scan never leak into another. The reporter also filters results by the requested target domain.

### Response Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "# Fleet Scan Report\n..."
      }
    ]
  }
}
```

## SSE HTTP Transport

In addition to stdio, Erebos supports **Server-Sent Events (SSE)** transport for remote MCP access over HTTP. This is the recommended transport for Docker deployments and external agent connections.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /mcp` | POST | JSON-RPC 2.0 request endpoint |
| `GET /sse` | GET | SSE stream for server-initiated messages |
| `GET /health` | GET | Health check (returns `{"status": "ok"}`) |

### Docker Deployment

The SSE server is the default entrypoint in Docker:

```bash
# Build and start
docker compose up -d --build

# Verify
curl http://localhost:5100/health
```

### Configuration

Configure via environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `VT_STRIKE_SSE_TOKEN` | *(required)* | Bearer token for authentication |
| `VT_STRIKE_SSE_HOST` | `127.0.0.1` | Bind address |
| `VT_STRIKE_SSE_PORT` | `5100` | Listen port |
| `VT_STRIKE_IP_ALLOWLIST` | *(empty)* | Comma-separated allowed IPs |
| `VT_STRIKE_TLS_CERT` | *(empty)* | Path to TLS certificate |
| `VT_STRIKE_TLS_KEY` | *(empty)* | Path to TLS private key |

### Connecting from External Agents

Register the SSE endpoint in your agent's `.mcp.json`:

```json
{
  "mcpServers": {
    "erebos": {
      "type": "sse",
      "url": "http://localhost:5100/sse",
      "headers": {
        "Authorization": "Bearer <VT_STRIKE_SSE_TOKEN>"
      }
    }
  }
}
```

Or connect from a remote host (requires reverse proxy with TLS for production):

```json
{
  "mcpServers": {
    "erebos": {
      "type": "sse",
      "url": "https://erebos-server.local/sse",
      "headers": {
        "Authorization": "Bearer <VT_STRIKE_SSE_TOKEN>"
      }
    }
  }
}
```

### Security Considerations

- **Token auth**: Every request must include a valid `Authorization: Bearer <token>` header
- **IP allowlist**: Optionally restrict connections to known IPs via `VT_STRIKE_IP_ALLOWLIST`
- **TLS**: For production, always terminate TLS via a reverse proxy or set `VT_STRIKE_TLS_CERT`/`VT_STRIKE_TLS_KEY`
- **Loopback default**: The server binds to `127.0.0.1` by default — only loopback connections are accepted unless you change the bind address

## Security

| Control | Description |
|---------|-------------|
| Allowlist enforcement | All targets validated before execution |
| MCP request size limit | 1 MB max (prevents memory DoS) |
| No shell expansion | Arguments pass directly to tools |
| Rate limiting | Same token-bucket as fleet mode |
| Audit log | All MCP calls logged with HMAC integrity |
| SSE token auth | Bearer token required for HTTP transport |
| IP allowlist | Optional IP-based access control for SSE |
