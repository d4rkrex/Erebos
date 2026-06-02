"""httpx parser — JSON-lines output from ProjectDiscovery httpx."""

import json
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class HttpxParser(Parser):
    """Parser for httpx JSON-lines output (live host probing).

    httpx -json outputs one JSON object per line with fields:
    url, status_code, title, webserver, tech, content_length, host, port, etc.
    """

    tool_name = "httpx"

    def can_parse(self, output: str) -> bool:
        """Check if output is httpx JSON-lines format."""
        if not output.strip():
            return False
        first_line = output.strip().split("\n")[0].strip()
        try:
            data = json.loads(first_line)
            return isinstance(data, dict) and ("url" in data or "host" in data)
        except (json.JSONDecodeError, ValueError):
            return False

    def parse(self, output: str) -> List[Finding]:
        """Parse httpx JSON-lines into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        seen_urls: set = set()

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = data.get("url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            status_code = data.get("status_code", 0)
            title = data.get("title", "")
            webserver = data.get("webserver", "")
            tech = data.get("tech", [])
            host = data.get("host", "")
            port = data.get("port", "")

            tech_str = ", ".join(tech) if isinstance(tech, list) else str(tech)
            desc_parts = [f"Status: {status_code}"]
            if title:
                desc_parts.append(f"Title: {title}")
            if webserver:
                desc_parts.append(f"Server: {webserver}")
            if tech_str:
                desc_parts.append(f"Tech: {tech_str}")

            finding = Finding(
                tool="httpx",
                severity=Severity.INFO,
                title=f"Live host: {url}",
                description=f"httpx confirmed live host. {'; '.join(desc_parts)}",
                evidence=FindingEvidence(
                    url=url,
                    http_banner=webserver or None,
                    output=line[:2000],
                ),
                phase_found=Phase.RECON,
            )
            findings.append(finding)

        return findings
