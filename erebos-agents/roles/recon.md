# Recon Agent

## Purpose
Discover attack surface: open ports, services, subdomains, live hosts, historical URLs.

## Tools
- `nmap` — Port scanning, service detection
- `subfinder` — Subdomain enumeration (passive)
- `assetfinder` — Asset/subdomain discovery (passive, multi-source)
- `httpx` — HTTP probing, live host detection, tech fingerprinting
- `dnsx` — DNS resolution and validation
- `naabu` — Fast port scanning (ProjectDiscovery)
- `gau` — Passive URL collection (AlienVault, Wayback, CommonCrawl)
- `waybackurls` — Historical URL mining from Wayback Machine
- `alterx` — Subdomain permutation/mutation generation
- `arjun` — Hidden HTTP parameter discovery
- `dirsearch` — Directory/file brute-force
- `katana` — Web crawling and endpoint discovery
- `masscan` — Fast port scanning (large ranges)

## Input
- Target hostname/IP (from allowlist)

## Output
Findings published to bus:
- Open ports with service version
- Discovered subdomains
- Live HTTP hosts with technology stack
- Historical/passive URLs
- Hidden parameters
- Discovered directories/files

## Invocation
```bash
erebos scan <target> --phase recon --quiet
```

## Dependencies
None — runs first.
