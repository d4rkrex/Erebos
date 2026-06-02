# Vuln Scan Agent

## Purpose
Identify vulnerabilities using template scanners, XSS testing, and CMS auditing.

## Tools
- `nuclei` — Template-based vulnerability scanner (CVEs, misconfigs, DAST)
- `nikto` — Web server vulnerability scanner
- `sqlmap` — SQL injection detection and exploitation
- `dalfox` — XSS scanner (reflected + stored, context-aware)
- `wpscan` — WordPress security auditing (plugins, themes, core)
- `kxss` — Reflected parameter detection (filter bypass check)
- `bxss` — Blind XSS testing with callback server

## Input
- Target + recon-discovered subdomains/ports/URLs

## Output
Findings with:
- CVE/CWE identifiers
- Severity (critical/high/medium/low)
- Evidence URL and payload
- Suggested remediation

## Invocation
```bash
erebos scan <target> --phase vuln-scan --quiet
```

## Dependencies
- Recon (for subdomain/port/URL targets)
