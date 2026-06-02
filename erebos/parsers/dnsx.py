"""dnsx parser — line-based DNS resolution output from ProjectDiscovery dnsx."""

from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class DnsxParser(Parser):
    """Parser for dnsx output.

    dnsx outputs resolved domains as lines:
      subdomain.example.com [A] [1.2.3.4]
    Or with -resp flag:
      subdomain.example.com [A] [1.2.3.4]
    Plain mode (no flags): one domain per line.
    JSON mode (-json): JSON-lines with host, resolver, a, aaaa, cname, etc.
    """

    tool_name = "dnsx"

    def can_parse(self, output: str) -> bool:
        """Check if output is dnsx format."""
        if not output.strip():
            return False
        lines = [l.strip() for l in output.strip().split("\n") if l.strip()]
        if not lines:
            return False
        # dnsx lines contain domain names, possibly with [TYPE] [IP] markers
        domain_count = sum(1 for l in lines[:10] if "." in l and not l.startswith("{"))
        return domain_count >= 1

    def parse(self, output: str) -> List[Finding]:
        """Parse dnsx output into Finding models."""
        import json

        findings: List[Finding] = []
        if not output.strip():
            return findings

        seen: set = set()

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Try JSON-lines format first
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    a_records = data.get("a", [])
                    cname_records = data.get("cname", [])
                    if host and host not in seen:
                        seen.add(host)
                        desc_parts = [f"Resolved host: {host}"]
                        if a_records:
                            desc_parts.append(f"A: {', '.join(a_records)}")
                        if cname_records:
                            desc_parts.append(f"CNAME: {', '.join(cname_records)}")
                        findings.append(Finding(
                            tool="dnsx",
                            severity=Severity.INFO,
                            title=f"DNS resolved: {host}",
                            description="; ".join(desc_parts),
                            evidence=FindingEvidence(url=host, output=line[:1000]),
                            phase_found=Phase.RECON,
                        ))
                    continue
                except (json.JSONDecodeError, ValueError):
                    pass

            # Plain text: "subdomain.example.com [A] [1.2.3.4]" or just "subdomain.example.com"
            parts = line.split()
            domain = parts[0] if parts else ""
            if not domain or "." not in domain or domain in seen:
                continue
            seen.add(domain)

            # Extract record type and IP if present (format: [TYPE] [VALUE])
            record_type = ""
            record_value = ""
            for part in parts[1:]:
                stripped = part.strip("[]")
                if stripped in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"):
                    record_type = stripped
                elif stripped and record_type:
                    record_value = stripped

            desc = f"dnsx resolved {domain}"
            if record_type:
                desc += f" ({record_type}: {record_value})"

            findings.append(Finding(
                tool="dnsx",
                severity=Severity.INFO,
                title=f"DNS resolved: {domain}",
                description=desc,
                evidence=FindingEvidence(url=domain, output=line[:500]),
                phase_found=Phase.RECON,
            ))

        return findings
