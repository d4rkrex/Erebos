"""Ffuf parser for JSON output."""

import json
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class FfufParser(Parser):
    """Parser for Ffuf (Fast Fuzzer) JSON output."""

    tool_name = "ffuf"

    SEVERITY_MAP = {
        "200": Severity.HIGH,
        "301": Severity.MEDIUM,
        "302": Severity.MEDIUM,
        "401": Severity.MEDIUM,
        "403": Severity.LOW,
        "404": Severity.INFO,
        "500": Severity.HIGH,
    }

    def can_parse(self, output: str) -> bool:
        """Check if output is Ffuf JSON format."""
        try:
            data = json.loads(output)
            # Ffuf JSON has "results" array and "results" contains objects with "status" field
            if isinstance(data, dict) and "results" in data:
                return True
            return False
        except json.JSONDecodeError:
            return False

    def parse(self, output: str) -> List[Finding]:
        """Parse Ffuf JSON output into Finding models."""
        findings = []

        try:
            data = json.loads(output)
            results = data.get("results", [])

            for result in results:
                url = result.get("url", "")
                status = result.get("status", 0)
                length = result.get("length", 0)
                words = result.get("words", 0)
                lines = result.get("lines", 0)
                content_type = result.get("content-type", "")
                redirect_location = result.get("redirectlocation", "")

                # Determine severity from status code
                status_str = str(status)
                severity = self.SEVERITY_MAP.get(status_str, Severity.MEDIUM)

                # Build title
                title = f"Ffuf: {status} - {url}"

                # Build description
                description = f"Ffuf discovered endpoint with status {status}"
                if length:
                    description += f", length {length}"
                if content_type:
                    description += f", type: {content_type}"
                if redirect_location:
                    description += f", redirects to: {redirect_location}"

                # Create finding
                finding = Finding(
                    tool="ffuf",
                    severity=severity,
                    title=title[:100],
                    description=description,
                    evidence=FindingEvidence(
                        url=url,
                        output=json.dumps(
                            {
                                "status": status,
                                "length": length,
                                "words": words,
                                "lines": lines,
                                "content-type": content_type,
                                "redirect": redirect_location,
                            }
                        ),
                    ),
                    phase_found=Phase.RECON,
                )
                findings.append(finding)

            # Parse statistics if available
            stats = data.get("stats", [])
            if stats:
                # Add a summary finding
                total_results = len(results)
                total_time = sum(s.get("duration", 0) for s in stats)

                finding = Finding(
                    tool="ffuf",
                    severity=Severity.INFO,
                    title=f"Ffuf Scan Complete: {total_results} results",
                    description=f"Ffuf scan completed in {total_time}ms with {total_results} findings",
                    evidence=FindingEvidence(
                        output=json.dumps(stats),
                    ),
                    phase_found=Phase.RECON,
                )
                findings.append(finding)

        except json.JSONDecodeError:
            pass

        return findings
