# Erebos Fleet Agent Definitions

This directory contains role definitions for code-agent orchestrators that
want to dispatch Erebos roles as parallel sub-agents.

## Architecture

```
Orchestrator (you)
├── Recon Agent      → nmap, subfinder → ports, subdomains
├── Vuln Scan Agent  → nuclei → CVE/CWE findings
├── Exploit Agent    → templates + LLM → PoC evidence
├── Code Audit Agent → repo analysis → auth gaps, patterns
└── Reporter Agent   → correlation → prioritized report
```

## Dispatch Pattern

1. Launch Recon + Code Audit in parallel (independent)
2. Wait for Recon results
3. Launch Vuln Scan (uses recon targets)
4. Launch Exploit (uses vuln-scan findings)
5. Launch Reporter (aggregates all)

## Roles

See individual files:
- [recon.md](roles/recon.md)
- [vuln-scan.md](roles/vuln-scan.md)
- [exploit.md](roles/exploit.md)
- [code-audit.md](roles/code-audit.md)
- [reporter.md](roles/reporter.md)
