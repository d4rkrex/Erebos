"""Fortify FPR (ZIP containing audit.fvdl XML) parser.

VT-Spec R8: Fortify FPR format support.
VT-Spec INJ-01: All fields sanitized at parse time.
"""

from __future__ import annotations

import io
import logging
import zipfile
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

from erebos.core.finding import (
    Finding,
    FindingEvidence,
    Phase,
    Severity,
)
from erebos.ingestion.base import (
    MAX_DESCRIPTION_LENGTH,
    MAX_EVIDENCE_LENGTH,
    MAX_TITLE_LENGTH,
    FindingsParser,
    sanitize_text,
)

logger = logging.getLogger(__name__)

# Fortify severity mapping
_SEVERITY_MAP: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}

# FVDL namespace
_NS = {"fvdl": "xmlns://www.fortifysoftware.com/schema/fvdl"}


class FortifyParser(FindingsParser):
    """Parser for Fortify FPR files (ZIP containing audit.fvdl XML)."""

    @property
    def format_name(self) -> str:
        return "fortify"

    def detect(self, content: bytes) -> bool:
        """Detect FPR format by checking for ZIP magic + audit.fvdl inside."""
        # ZIP magic bytes: PK\x03\x04
        if not content[:4] == b"PK\x03\x04":
            return False
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                names = zf.namelist()
                return any("audit.fvdl" in n.lower() for n in names)
        except (zipfile.BadZipFile, Exception):
            return False

    def parse(self, content: bytes) -> List[Finding]:
        """Parse Fortify FPR ZIP into Finding objects.

        VT-Spec INJ-01: All text fields sanitized before creating Findings.
        """
        findings: List[Finding] = []

        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                fvdl_content = self._find_and_read_fvdl(zf)
                if not fvdl_content:
                    logger.warning("No audit.fvdl found in FPR archive")
                    return []
        except (zipfile.BadZipFile, Exception) as e:
            logger.warning("Failed to open FPR archive: %s", e)
            return []

        try:
            root = ET.fromstring(fvdl_content)
        except ET.ParseError as e:
            logger.warning("Failed to parse audit.fvdl XML: %s", e)
            return []

        # Parse vulnerabilities
        vulns = root.findall(".//{xmlns://www.fortifysoftware.com/schema/fvdl}Vulnerability")
        if not vulns:
            # Try without namespace
            vulns = root.findall(".//Vulnerability")

        for vuln in vulns:
            finding = self._parse_vulnerability(vuln)
            if finding:
                findings.append(finding)

        return findings

    def _find_and_read_fvdl(self, zf: zipfile.ZipFile) -> Optional[bytes]:
        """Find and read audit.fvdl from the ZIP."""
        for name in zf.namelist():
            if "audit.fvdl" in name.lower():
                return zf.read(name)
        return None

    @staticmethod
    def _find_elem(parent: ET.Element, tag: str, ns: str) -> Optional[ET.Element]:
        """Find child element with or without namespace."""
        elem = parent.find(f"{{{ns}}}{tag}")
        if elem is None:
            elem = parent.find(tag)
        return elem

    def _parse_vulnerability(self, vuln: ET.Element) -> Optional[Finding]:
        """Parse a single Fortify Vulnerability element."""
        ns = "xmlns://www.fortifysoftware.com/schema/fvdl"

        # Extract ClassInfo
        class_info = self._find_elem(vuln, "ClassInfo", ns)
        instance_info = self._find_elem(vuln, "InstanceInfo", ns)
        analysis_info = self._find_elem(vuln, "AnalysisInfo", ns)

        title = "Unknown Vulnerability"
        description = ""
        severity = Severity.MEDIUM
        cwe: Optional[str] = None
        target: Optional[str] = None

        if class_info is not None:
            type_elem = self._find_elem(class_info, "Type", ns)
            if type_elem is not None and type_elem.text:
                title = type_elem.text

            subtype_elem = self._find_elem(class_info, "Subtype", ns)
            if subtype_elem is not None and subtype_elem.text:
                title = f"{title}: {subtype_elem.text}"

            # Severity from ClassInfo
            sev_elem = self._find_elem(class_info, "DefaultSeverity", ns)
            if sev_elem is not None and sev_elem.text:
                severity = _SEVERITY_MAP.get(
                    sev_elem.text.lower().strip(), Severity.MEDIUM
                )

            # Kingdom from ClassInfo
            cwe_elem = self._find_elem(class_info, "Kingdom", ns)
            if cwe_elem is not None and cwe_elem.text:
                description = f"Kingdom: {cwe_elem.text}"

        if instance_info is not None:
            conf_elem = self._find_elem(instance_info, "Confidence", ns)
            if conf_elem is not None and conf_elem.text:
                description += f" | Confidence: {conf_elem.text}"

        # Try to extract source file location
        if analysis_info is not None:
            source_loc = analysis_info.find(f".//{{{ns}}}SourceLocation")
            if source_loc is None:
                source_loc = analysis_info.find(".//SourceLocation")
            if source_loc is not None:
                path = source_loc.get("path", "")
                line = source_loc.get("line", "")
                target = f"{path}:{line}" if line else path

        # VT-Spec INJ-01: Sanitize all fields at parse time
        title = sanitize_text(title, MAX_TITLE_LENGTH)
        description = sanitize_text(description, MAX_DESCRIPTION_LENGTH)

        evidence = FindingEvidence(
            output=sanitize_text(target, MAX_EVIDENCE_LENGTH) if target else None,
        )

        return Finding(
            tool="fortify",
            severity=severity,
            title=title,
            description=description,
            target=target,
            evidence=evidence,
            cwe=cwe,
            phase_found=Phase.VULN_SCAN,
        )
