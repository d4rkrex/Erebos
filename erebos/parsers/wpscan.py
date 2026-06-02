"""wpscan parser — JSON output for WordPress security auditing."""

import json
from typing import List, Optional

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class WpscanParser(Parser):
    """Parser for wpscan JSON output (WordPress vulnerability scanner).

    wpscan --format json outputs a large JSON object with:
    - version.vulnerabilities[]
    - main_theme.vulnerabilities[]
    - plugins.{name}.vulnerabilities[]
    - interesting_findings[]
    """

    tool_name = "wpscan"

    def can_parse(self, output: str) -> bool:
        """Check if output is wpscan JSON format."""
        if not output.strip():
            return False
        try:
            data = json.loads(output.strip())
            return isinstance(data, dict) and (
                "version" in data
                or "main_theme" in data
                or "plugins" in data
                or "interesting_findings" in data
                or "target_url" in data
            )
        except (json.JSONDecodeError, ValueError):
            return False

    def parse(self, output: str) -> List[Finding]:
        """Parse wpscan JSON output into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        try:
            data = json.loads(output.strip())
        except json.JSONDecodeError:
            return findings

        # Parse WordPress version vulnerabilities
        version_info = data.get("version", {})
        if isinstance(version_info, dict):
            vulns = version_info.get("vulnerabilities", [])
            wp_version = version_info.get("number", "unknown")
            for vuln in vulns:
                f = self._vuln_to_finding(vuln, f"WordPress {wp_version}")
                if f:
                    findings.append(f)

        # Parse theme vulnerabilities
        theme_info = data.get("main_theme", {})
        if isinstance(theme_info, dict):
            theme_name = theme_info.get("slug", "unknown-theme")
            for vuln in theme_info.get("vulnerabilities", []):
                f = self._vuln_to_finding(vuln, f"Theme: {theme_name}")
                if f:
                    findings.append(f)

        # Parse plugin vulnerabilities
        plugins = data.get("plugins", {})
        if isinstance(plugins, dict):
            for plugin_name, plugin_data in plugins.items():
                if not isinstance(plugin_data, dict):
                    continue
                for vuln in plugin_data.get("vulnerabilities", []):
                    f = self._vuln_to_finding(vuln, f"Plugin: {plugin_name}")
                    if f:
                        findings.append(f)

        # Parse interesting findings (info-level)
        interesting = data.get("interesting_findings", [])
        for item in interesting:
            if not isinstance(item, dict):
                continue
            url = item.get("url", "")
            entry_type = item.get("type", "")
            desc = item.get("to_s", item.get("description", ""))
            if url or desc:
                findings.append(Finding(
                    tool="wpscan",
                    severity=Severity.INFO,
                    title=f"WP Info: {entry_type or desc[:50]}",
                    description=f"wpscan interesting finding: {desc}",
                    evidence=FindingEvidence(url=url, output=desc[:500]),
                    phase_found=Phase.VULN_SCAN,
                ))

        return findings

    def _vuln_to_finding(self, vuln: dict, component: str) -> Optional[Finding]:
        """Convert a wpscan vulnerability entry to a Finding."""
        if not isinstance(vuln, dict):
            return None

        title = vuln.get("title", "Unknown vulnerability")
        vuln_type = vuln.get("vuln_type", "")
        fixed_in = vuln.get("fixed_in", "")

        # Extract CVEs from references
        references = vuln.get("references", {})
        cves: List[str] = []
        if isinstance(references, dict):
            cve_list = references.get("cve", [])
            cves = [f"CVE-{c}" if not c.startswith("CVE-") else c for c in cve_list]

        # Determine severity from vuln_type
        severity = Severity.HIGH
        if vuln_type in ("AUTHBYPASS", "RCE", "SQLI"):
            severity = Severity.CRITICAL
        elif vuln_type in ("XSS", "CSRF"):
            severity = Severity.MEDIUM

        desc = f"wpscan found vulnerability in {component}: {title}"
        if fixed_in:
            desc += f". Fixed in version {fixed_in}."

        return Finding(
            tool="wpscan",
            severity=severity,
            title=f"WP Vuln: {title[:80]}",
            description=desc,
            cves=cves,
            cve=cves[0] if cves else None,
            cwe=self._vuln_type_to_cwe(vuln_type),
            suggested_fix=f"Update to version {fixed_in}" if fixed_in else None,
            evidence=FindingEvidence(
                output=json.dumps(vuln, indent=2)[:1500],
            ),
            phase_found=Phase.VULN_SCAN,
        )

    @staticmethod
    def _vuln_type_to_cwe(vuln_type: str) -> Optional[str]:
        """Map wpscan vuln_type to CWE."""
        mapping = {
            "RCE": "CWE-94",
            "SQLI": "CWE-89",
            "XSS": "CWE-79",
            "CSRF": "CWE-352",
            "AUTHBYPASS": "CWE-287",
            "LFI": "CWE-22",
            "SSRF": "CWE-918",
            "IDOR": "CWE-639",
        }
        return mapping.get(vuln_type.upper())
