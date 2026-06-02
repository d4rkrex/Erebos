"""Main ingestion orchestrator.

Detects format, parses findings, sanitizes, validates scope, and injects into FactGraph.

VT-Spec R1: External Findings Ingestion
VT-Spec INJ-01: Sanitize at parse time
VT-Spec SCOPE-01: AllowlistValidator on ALL URLs
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Type

from erebos.agents.fact_graph import Fact, FactGraph, FactType
from erebos.core.finding import Finding
from erebos.ingestion.base import FindingsParser, IngestResult
from erebos.ingestion.burp_parser import BurpParser
from erebos.ingestion.csv_parser import CSVParser
from erebos.ingestion.fortify_parser import FortifyParser
from erebos.ingestion.native_parser import NativeParser
from erebos.ingestion.sarif_parser import SARIFParser
from erebos.ingestion.semgrep_parser import SemgrepParser
from erebos.security.scope import AllowlistValidator

logger = logging.getLogger(__name__)

# Format hint to parser mapping
_FORMAT_HINTS: Dict[str, Type[FindingsParser]] = {
    "sarif": SARIFParser,
    "fortify": FortifyParser,
    "fpr": FortifyParser,
    "burp": BurpParser,
    "semgrep": SemgrepParser,
    "csv": CSVParser,
    "native": NativeParser,
    "erebos": NativeParser,
}


class FindingsIngester:
    """Main ingestion orchestrator.

    VT-Spec SCOPE-01: All ingested finding URLs MUST pass AllowlistValidator
    before being added to FactGraph. Reject out-of-scope findings.
    """

    def __init__(
        self,
        allowlist: List[str],
        fact_graph: Optional[FactGraph] = None,
    ):
        # VT-Spec SCOPE-01: AllowlistValidator on all ingested finding URLs
        self._validator = AllowlistValidator(allowlist)
        self._fact_graph = fact_graph
        self._parsers: List[FindingsParser] = [
            SARIFParser(),
            FortifyParser(),
            BurpParser(),
            SemgrepParser(),
            NativeParser(),
            CSVParser(),  # CSV last since detection is more permissive
        ]

    def ingest(
        self, file_path: Path, format_hint: Optional[str] = None
    ) -> IngestResult:
        """Parse file and inject findings into FactGraph.

        VT-Spec R1: Accept findings from external scanners and normalize.
        VT-Spec INJ-01: Sanitization happens at parser level.
        VT-Spec SCOPE-01: URL validation happens here after parsing.
        """
        content = file_path.read_bytes()
        return self.ingest_bytes(content, format_hint=format_hint)

    def ingest_bytes(
        self, content: bytes, format_hint: Optional[str] = None
    ) -> IngestResult:
        """Parse bytes content and inject findings into FactGraph."""
        result = IngestResult()

        # Step 1: Detect or resolve parser
        parser = self._resolve_parser(content, format_hint)
        if not parser:
            logger.warning("Could not detect format for ingested content")
            result.format_detected = "unknown"
            return result

        result.format_detected = parser.format_name

        # Step 2: Parse to Finding objects (INJ-01 sanitization happens inside parsers)
        findings = parser.parse(content)
        result.total_parsed = len(findings)

        # Step 3: Validate URLs against allowlist (SCOPE-01)
        accepted, rejected = self._validate_scope(findings)
        result.accepted = len(accepted)
        result.rejected = len(rejected)
        result.findings = accepted

        # Extract source tool from first finding
        if accepted:
            result.source_tool = accepted[0].tool

        # Step 4: Inject into FactGraph if available
        if self._fact_graph and accepted:
            self._inject_into_graph(accepted)

        logger.info(
            "Ingestion complete: format=%s, total=%d, accepted=%d, rejected=%d",
            result.format_detected,
            result.total_parsed,
            result.accepted,
            result.rejected,
        )

        return result

    def _resolve_parser(
        self, content: bytes, format_hint: Optional[str] = None
    ) -> Optional[FindingsParser]:
        """Resolve parser using format hint or auto-detection."""
        # Try format hint first
        if format_hint:
            hint_lower = format_hint.lower().strip()
            parser_cls = _FORMAT_HINTS.get(hint_lower)
            if parser_cls:
                return parser_cls()
            logger.warning("Unknown format hint '%s', falling back to auto-detect", format_hint)

        # Auto-detect format
        for parser in self._parsers:
            try:
                if parser.detect(content):
                    return parser
            except Exception as e:
                logger.debug("Parser %s detection failed: %s", parser.format_name, e)
                continue

        return None

    def _validate_scope(
        self, findings: List[Finding]
    ) -> tuple[List[Finding], List[Finding]]:
        """Validate all finding URLs against allowlist.

        VT-Spec SCOPE-01: Every finding URL must pass AllowlistValidator.is_allowed(url).
        Reject findings with out-of-scope URLs (log warning, skip finding).
        If no URL on finding, it's allowed (SAST findings may not have URLs).
        """
        accepted: List[Finding] = []
        rejected: List[Finding] = []

        for finding in findings:
            url = self._extract_url(finding)

            if url is None:
                # VT-Spec SCOPE-01: No URL means allowed (SAST findings)
                accepted.append(finding)
            elif self._validator.is_allowed(url):
                accepted.append(finding)
            else:
                # VT-Spec SCOPE-01: Reject and log out-of-scope findings
                logger.warning(
                    "SCOPE-01: Rejected finding '%s' — target '%s' not in allowlist",
                    finding.title,
                    url,
                )
                rejected.append(finding)

        return accepted, rejected

    def _extract_url(self, finding: Finding) -> Optional[str]:
        """Extract the primary URL from a finding for scope validation."""
        # Check target first
        if finding.target and "://" in finding.target:
            return finding.target

        # Check evidence URL
        if finding.evidence and finding.evidence.url and "://" in finding.evidence.url:
            return finding.evidence.url

        # No URL found (SAST/file-path based findings)
        return None

    def _inject_into_graph(self, findings: List[Finding]) -> None:
        """Inject accepted findings into FactGraph as vulnerability facts."""
        for finding in findings:
            fact = Fact(
                fact_type=FactType.VULNERABILITY,
                data={
                    "title": finding.title,
                    "severity": finding.severity,
                    "tool": finding.tool,
                    "target": finding.target or "",
                    "description": finding.description[:500],  # FactGraph limit
                    "cwe": finding.cwe or "",
                    "finding_id": finding.id,
                },
                source_agent="ingestion",
                confidence=0.8,  # External findings have lower confidence
            )
            self._fact_graph.add_fact(fact)
