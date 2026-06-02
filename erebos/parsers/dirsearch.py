"""dirsearch parser — text and JSON output for directory/file brute-force."""

import json
import re
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class DirsearchParser(Parser):
    """Parser for dirsearch output.

    dirsearch outputs in multiple formats:
    - Plain text: STATUS  SIZE  URL  REDIRECT
      200   1234  /admin/
      301    512  /api/ -> /api/v1/
    - JSON (-o json): array of {status, url, content-length, redirect}
    """

    tool_name = "dirsearch"

    # Regex for dirsearch plain text output lines
    _LINE_RE = re.compile(
        r"^\s*(\d{3})\s+(\d+[KMG]?B?)\s+(.+?)(?:\s+->\s+(.+))?$"
    )

    def can_parse(self, output: str) -> bool:
        """Check if output is dirsearch format."""
        if not output.strip():
            return False
        stripped = output.strip()

        # Try JSON array
        if stripped.startswith("["):
            try:
                data = json.loads(stripped)
                if isinstance(data, list) and data:
                    return "status" in data[0] or "url" in data[0]
            except (json.JSONDecodeError, ValueError, IndexError):
                pass

        # Try plain text format
        lines = stripped.split("\n")
        match_count = sum(1 for l in lines[:30] if self._LINE_RE.match(l.strip()))
        return match_count >= 1

    def parse(self, output: str) -> List[Finding]:
        """Parse dirsearch output into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        stripped = output.strip()

        # Try JSON format first
        if stripped.startswith("["):
            try:
                data = json.loads(stripped)
                return self._parse_json(data)
            except (json.JSONDecodeError, ValueError):
                pass

        # Plain text format
        return self._parse_text(stripped)

    def _parse_json(self, data: list) -> List[Finding]:
        """Parse JSON array format."""
        findings: List[Finding] = []
        seen: set = set()

        for entry in data:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url", "")
            status = entry.get("status", 0)
            redirect = entry.get("redirect", "")

            if not url or url in seen:
                continue
            seen.add(url)

            severity = self._severity_from_status(status, url)
            findings.append(self._build_finding(url, status, redirect, severity))

        return findings

    def _parse_text(self, output: str) -> List[Finding]:
        """Parse plain text format."""
        findings: List[Finding] = []
        seen: set = set()

        for line in output.split("\n"):
            match = self._LINE_RE.match(line.strip())
            if not match:
                continue

            status = int(match.group(1))
            url = match.group(3).strip()
            redirect = (match.group(4) or "").strip()

            if not url or url in seen:
                continue
            seen.add(url)

            severity = self._severity_from_status(status, url)
            findings.append(self._build_finding(url, status, redirect, severity))

        return findings

    @staticmethod
    def _severity_from_status(status: int, url: str) -> Severity:
        """Determine severity based on status code and path."""
        sensitive_patterns = (
            "/admin", "/debug", "/.env", "/.git", "/config",
            "/backup", ".bak", ".sql", "/phpinfo", "/wp-admin",
        )
        url_lower = url.lower()
        has_sensitive = any(p in url_lower for p in sensitive_patterns)

        if status == 200 and has_sensitive:
            return Severity.MEDIUM
        if status == 200:
            return Severity.LOW
        if status in (301, 302, 307, 308):
            return Severity.INFO
        return Severity.INFO

    @staticmethod
    def _build_finding(url: str, status: int, redirect: str, severity: Severity) -> Finding:
        """Build a Finding from parsed data."""
        desc = f"dirsearch found {url} (HTTP {status})"
        if redirect:
            desc += f" → {redirect}"

        return Finding(
            tool="dirsearch",
            severity=severity,
            title=f"Directory: {url} [{status}]",
            description=desc,
            evidence=FindingEvidence(
                url=url,
                output=f"Status: {status}" + (f", Redirect: {redirect}" if redirect else ""),
            ),
            phase_found=Phase.DISCOVERY,
        )
