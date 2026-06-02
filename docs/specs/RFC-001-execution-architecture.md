# RFC-001: Erebos Execution Architecture

**Status:** Proposed  
**Date:** 2025-05-28  
**Author:** AppSec Team  

---

## Summary

Define the dual execution model for Erebos: **local** (tools on host) vs. **remote** (tools in Docker, consumed via MCP). The system should transparently switch between both without code changes.

## Motivation

Currently Erebos assumes tools are installed locally. If a tool isn't found, it's silently skipped. This leads to:
- Inconsistent results across machines
- 12+ Go tools that must be individually installed
- No way for a remote coding agent to use the full tool suite

The Docker image already bundles all tools, and `.mcp.json` already points to remote execution. But there's no **formal contract** between the CLI, the executor, and the transport layer.

## Proposal

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      Consumer Layer                            │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │   CLI    │  │ Coding Agent │  │  CI/CD (GitHub Action) │  │
│  └────┬─────┘  └──────┬───────┘  └───────────┬───────────┘  │
│       │                │                       │              │
│       └────────────────┼───────────────────────┘              │
│                        │                                      │
│                 ┌──────▼──────┐                               │
│                 │ MCP Protocol │  (JSON-RPC 2.0 stdio/SSE)   │
│                 └──────┬──────┘                               │
└────────────────────────┼─────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────┐
│                    Execution Layer                             │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Transport Resolver                          │ │
│  │                                                         │ │
│  │  if docker_available AND prefer_remote:                 │ │
│  │      → DockerTransport (exec into running container)    │ │
│  │  elif tool_in_path:                                     │ │
│  │      → LocalTransport (subprocess)                      │ │
│  │  else:                                                  │ │
│  │      → skip with warning                               │ │
│  └────────────┬────────────────────────┬───────────────────┘ │
│               │                        │                      │
│  ┌────────────▼──────────┐  ┌──────────▼───────────────────┐ │
│  │   LocalTransport      │  │   DockerTransport            │ │
│  │                       │  │                              │ │
│  │ • subprocess.run()    │  │ • docker exec <container>    │ │
│  │ • Binary in PATH or   │  │ • All tools pre-installed    │ │
│  │   ALLOWED_TOOL_DIRS   │  │ • Shared /data volume        │ │
│  │ • 10MB stdout cap     │  │ • Same safety invariants     │ │
│  │ • 10min timeout       │  │ • Network: host or bridge    │ │
│  └───────────────────────┘  └──────────────────────────────┘ │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Tool Container (Docker)                     │ │
│  │                                                         │ │
│  │  /usr/local/bin/                                        │ │
│  │    nuclei, nmap, subfinder, httpx, dnsx, naabu,        │ │
│  │    assetfinder, gau, ffuf, nikto, sqlmap, hydra,       │ │
│  │    katana, waybackurls, gobuster, dirsearch, arjun     │ │
│  │                                                         │ │
│  │  /app/ → Erebos Python code                         │ │
│  │  /data/ → findings, reports, state (volume mount)       │ │
│  └─────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

### Transport Resolution Strategy

```python
class TransportResolver:
    """Decides whether to run a tool locally or in Docker."""

    def resolve(self, tool_name: str) -> Transport:
        # 1. User forced local? Use local.
        if self.config.force_local:
            return LocalTransport(tool_name)

        # 2. Docker container running? Use it (all tools available).
        if self._docker_container_running():
            return DockerTransport(tool_name, container=self.container_name)

        # 3. Tool available locally? Use local.
        if self._tool_in_path(tool_name):
            return LocalTransport(tool_name)

        # 4. Docker available but container not running? Start it.
        if self._docker_available() and self.config.auto_start_container:
            self._start_container()
            return DockerTransport(tool_name, container=self.container_name)

        # 5. Nothing available — skip.
        raise ToolNotAvailableError(tool_name)
```

### Configuration

```yaml
# ~/.erebos/config.yaml
execution:
  mode: auto          # auto | local | docker | remote
  container: erebos  # Docker container name
  auto_start: true    # Start container if not running
  remote_host: null   # SSH host for remote execution (null = local Docker)

  # Override per tool (e.g., always use local nmap)
  overrides:
    nmap: local
```

### Docker Compose (New)

```yaml
# docker-compose.yml
services:
  erebos:
    build: .
    container_name: erebos
    restart: unless-stopped
    volumes:
      - ./erebos-data:/data
      - ./config.yaml:/app/config.yaml:ro
    network_mode: host          # Scan targets on host network
    environment:
      - EREBOS_ALLOWLIST=${EREBOS_ALLOWLIST:-}
    healthcheck:
      test: ["CMD", "python", "-m", "erebos", "health"]
      interval: 30s
    # MCP server mode (default)
    command: ["mcp-serve", "--port", "8443"]

  # Optional: standalone MCP stdio mode for agents
  erebos-mcp:
    build: .
    container_name: erebos-mcp
    profiles: ["mcp"]
    stdin_open: true
    volumes:
      - ./erebos-data:/data
    network_mode: host
    entrypoint: ["python", "-m", "erebos", "mcp-stdio"]
```

### MCP Integration Pattern

For a coding agent (Copilot CLI, Claude Code):

```json
// .mcp.json — Local Docker
{
  "erebos": {
    "command": "docker",
    "args": ["exec", "-i", "erebos", "python", "-m", "erebos", "mcp-stdio"]
  }
}

// .mcp.json — Remote (OKE / VM)
{
  "erebos": {
    "command": "ssh",
    "args": ["erebos-server", "docker", "exec", "-i", "erebos", "python", "-m", "erebos", "mcp-stdio"]
  }
}
```

### Deployment Options

| Option | Where tools run | Latency | Setup |
|--------|----------------|---------|-------|
| Local (bare metal) | Host machine | Lowest | Install 15+ tools |
| Local Docker | Docker on host | Low | `docker compose up` |
| Remote VM | Docker on erebos-server | Medium | SSH + Docker |
| OKE (Kubernetes) | Pod on OKE cluster | Medium | Helm chart / deployment |

### OKE Deployment (Future)

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: erebos
  namespace: appsec
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: erebos
          image: registry.gitlab.erebos.net/appsec/erebos:latest
          ports:
            - containerPort: 8443
          volumeMounts:
            - name: data
              mountPath: /data
          resources:
            requests: { cpu: "500m", memory: "1Gi" }
            limits: { cpu: "2", memory: "4Gi" }
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: erebos-data
```

## Implementation Plan

### Phase 1: Docker-First (1-2 days)
- [ ] Create `docker-compose.yml` 
- [ ] Add missing tools to Dockerfile (waybackurls, katana, arjun, gobuster, dirsearch)
- [ ] Complete ReconRole `_run_*` methods for all registered tools
- [ ] Test full fleet scan inside Docker

### Phase 2: Transport Resolver (2-3 days)
- [ ] Implement `TransportResolver` class
- [ ] Implement `DockerTransport` (docker exec)
- [ ] Config: `execution.mode` in settings
- [ ] CLI flag: `--execution-mode local|docker|auto`

### Phase 3: MCP Hardening (1-2 days)
- [ ] Streaming progress over MCP (scan status updates)
- [ ] `mcp-stdio` → proper tool registration with discoverable schemas
- [ ] Health endpoint for container readiness

### Phase 4: OKE Deployment (Future)
- [ ] Helm chart or K8s manifests
- [ ] Persistent volume for findings across restarts
- [ ] NetworkPolicy to restrict egress to allowlisted targets

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Default execution mode | `auto` (Docker if available, else local) | Zero-config for agents |
| Container networking | `host` mode | Tools need to reach arbitrary targets |
| Findings persistence | Volume mount `/data` | Survives container restart |
| MCP transport | stdio (primary) + SSE (optional) | stdio is simplest for agents |
| Image registry | `registry.gitlab.erebos.net/appsec/erebos` | Internal registry |

## Security Considerations

- Docker container runs as non-root (`erebos:1000`)
- Host network mode needed for scanning — no container escape risk (no privileged)
- Allowlist still enforced inside container (EP-01)
- SSH key required for remote execution (no password auth)
- MCP stdio has no auth (local trust model per S-01)

## Open Questions

1. Should the Docker image also serve the web dashboard (port 8484)?
2. Should findings persist in a database (PostgreSQL via erebos-ai) or stay as JSONL files?
3. Should OKE deployment use a Job (per-scan) or a long-running Deployment (MCP server)?
