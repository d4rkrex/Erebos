# Security Controls

Erebos implements defense-in-depth security controls across all layers.

## Threat Model

Primary risks for a pentest orchestration tool:
- **Out-of-scope scanning** → Legal liability
- **Command injection** → Host compromise
- **Agent spoofing** → Corrupted results
- **Resource exhaustion** → DoS against orchestrator
- **Log tampering** → Cover tracks

## Controls Summary

| ID | Control | Layer | Threat Mitigated |
|----|---------|-------|-----------------|
| EP-01 | Allowlist prerequisite | CLI / MCP | Out-of-scope scanning |
| S-01 | Role verification | FindingsBus | Agent impersonation |
| D-01 | Correlation cap (500) | CorrelationEngine | O(n²) DoS |
| T-01 | Parser error isolation | Role wrappers | Cascading failures |
| RL-01 | Rate limiter | ToolExecutor | Temporal DoS |
| LI-01 | HMAC log integrity | LogIntegrity | Tamper detection |
| TC-01 | Template checksum | TemplateEngine | Payload tampering |
| TO-01 | Agent timeout | FleetOrchestrator | Hung agents |
| AC-01 | Arg sanitization | ToolExecutor | Command injection |
| OC-01 | Output cap (10MB) | ToolExecutor | Memory exhaustion |
| FP-01 | File permissions (600) | FleetReportBuilder | Data leakage |
| MC-01 | Request size (1MB) | MCPStdioServer | MCP DoS |
| ID-01 | Localhost-only bind | Dashboard Web | Information disclosure |
| DoS-01 | SSE connection cap (10) | Dashboard Web | Connection exhaustion |
| BI-01 | Per-scan bus isolation | FindingsBus | Cross-target contamination |
| TF-01 | Reporter target filter | ReporterRole | Cross-target data leakage |
| I-01 | Sensitive header stripping | ExploitRunner | Credential exposure in evidence |
| AUTH-01 | Auth context isolation | AuthManager | Credential scope enforcement |

## Dashboard Security

The web dashboard (`erebos dashboard --web`) exposes scan findings via HTTP.

### Controls

- **ID-01**: Default bind to `127.0.0.1` only. If `--host 0.0.0.0` is used, a CLI warning is emitted advising the user of network exposure risk.
- **DoS-01**: SSE connections capped at 10 concurrent. Stale connections auto-close after 60s inactivity. Returns HTTP 429 when limit exceeded.

### Design Decisions

- Dashboard is **read-only** — no write operations to scan state (Erebos-Spec DS-001)
- No authentication required for localhost access (single-user tool)
- CORS allows all origins (acceptable since localhost-only by default)

## Allowlist (EP-01)

The allowlist is the **primary safety control**. No tool execution proceeds without target validation.

### How it works

```python
# Every tool invocation passes through:
AllowlistValidator.validate(target)  # raises AllowlistError if not allowed
```

### Allowlist sources

1. Config file: `~/.erebos/config.yaml` → `security.allowlist[]`
2. CLI: `erebos allowlist add <target>`
3. Environment: `EREBOS_ALLOWLIST=a.com,b.com`

### What's validated

- Domain names (exact match)
- Wildcard domains (`*.example.com`)
- IP addresses (single)
- CIDR ranges (`10.0.0.0/8`)
- URLs (hostname extracted and validated)

## Role Verification (S-01)

Every message on the FindingsBus includes a `sender_role` field. The bus verifies that the agent actually holds the declared role before accepting the message. This prevents:
- A compromised agent publishing findings as another role
- Correlation boost gaming (fake multi-source signals)

## Rate Limiting (RL-01)

Token-bucket rate limiter with configurable fill rate:

```
rate_limit_per_minute: 30  (default, hard cap: 60)
```

Applied at ToolExecutor level — every subprocess invocation consumes a token. Prevents:
- Overwhelming target infrastructure
- Triggering WAF/IPS rate bans
- Exhausting orchestrator resources

## Log Integrity (LI-01)

HMAC-SHA256 signing of log segments:

```python
log_integrity = LogIntegrity(secret=os.urandom(32))
signed = log_integrity.sign(log_entry)
# Later:
assert log_integrity.verify(signed)  # detects tampering
```

Segments are chained — modifying any entry breaks all subsequent verifications.

## Template Integrity (TC-01)

Exploit templates include a `checksum` field:

```yaml
checksum: sha256:e3b0c44298fc1c149afbf4c8996fb924...
```

On load, the template content (minus checksum field) is hashed and compared. Mismatches raise `TemplateIntegrityError` and abort the exploit.

## Agent Timeout (TO-01)

```python
await asyncio.wait_for(agent_coroutine, timeout=config.timeout_per_agent)
```

Default: 300 seconds. Prevents indefinitely-hung agents from blocking fleet completion.

## Argument Sanitization (AC-01)

ToolExecutor validates every argument before passing to subprocess:
- No shell metacharacters (`;`, `|`, `&`, `` ` ``, `$()`)
- No path traversal (`../`, symlinks outside scope)
- Target must be in allowlist
- Arguments passed as list (never shell=True)

## Report Permissions (FP-01)

```python
os.chmod(report_path, 0o600)  # Owner read/write only
```

Pentest reports contain sensitive finding data and are restricted to the user who ran the scan.

## Per-Scan Bus Isolation (BI-01)

Each fleet scan creates an isolated FindingsBus file:

```
erebos-storage/{target}-{timestamp}/findings-bus.jsonl
```

This prevents cross-target contamination — findings from a previous scan of Target A never appear in a scan of Target B. The bus file is scoped by `scan_id` in MCP mode and by `{target}-{timestamp}` in CLI mode.

## Reporter Target Filtering (TF-01)

The Reporter agent filters all findings by the requested target domain before including them in the report. `_finding_matches_target()` checks payload fields (`target`, `host`, `url`, `injectable_url`) for the target domain. Findings with no target fields (e.g., code-audit) are included by default.

## Sensitive Header Stripping (I-01)

The ExploitRunner strips sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`) from evidence payloads before persistence. This prevents credential leakage in reports and stored findings.

## Auth Context Isolation (AUTH-01)

Authentication credentials (headers, cookies, profiles) are:
- Scoped strictly to the allowlisted target domain
- Never forwarded to out-of-scope hosts discovered during recon
- Stripped from evidence before storage (see I-01)
- Not logged in plaintext in audit logs
