"""Finding Correlator — correlates DAST and SAST findings.

When the same vulnerability is detected by both dynamic (nuclei, dalfox) and
static (semgrep) analysis, confidence in the finding increases significantly.
This module identifies correlated findings and boosts their scores.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from erebos.core.finding import Finding

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    """Result of correlating a DAST finding with SAST findings."""

    dast_finding: Finding
    correlated_sast: List[Finding] = field(default_factory=list)
    correlation_score: float = 0.0  # 0.0 = no correlation, 1.0 = strong match
    correlation_reasons: List[str] = field(default_factory=list)

    @property
    def is_correlated(self) -> bool:
        """Whether this finding has cross-validation from SAST."""
        return self.correlation_score >= 0.5

    @property
    def confidence_boost(self) -> float:
        """Additional confidence from cross-validation (0.0 - 0.3)."""
        return min(self.correlation_score * 0.3, 0.3)


class FindingCorrelator:
    """Correlates findings between DAST and SAST results.

    Correlation signals:
    1. Same CWE class (strongest signal)
    2. Same target endpoint/file
    3. Same vulnerability type (by title/description keywords)
    4. URL path matches source file path
    """

    # CWE groups that are considered equivalent
    _CWE_EQUIVALENCE = {
        "sql_injection": {"CWE-89", "CWE-564"},
        "xss": {"CWE-79", "CWE-80"},
        "command_injection": {"CWE-78", "CWE-77"},
        "path_traversal": {"CWE-22", "CWE-23", "CWE-36"},
        "ssrf": {"CWE-918"},
        "xxe": {"CWE-611"},
        "deserialization": {"CWE-502"},
        "auth_bypass": {"CWE-287", "CWE-288"},
    }

    def __init__(self):
        # Build reverse lookup: CWE -> group name
        self._cwe_to_group: Dict[str, str] = {}
        for group, cwes in self._CWE_EQUIVALENCE.items():
            for cwe in cwes:
                self._cwe_to_group[cwe] = group

    def correlate(
        self,
        dast_findings: List[Finding],
        sast_findings: List[Finding],
    ) -> List[CorrelationResult]:
        """Correlate DAST findings against SAST findings.

        For each DAST finding, checks if any SAST finding covers the
        same vulnerability — providing cross-validation.
        """
        results = []

        for dast in dast_findings:
            correlated = []
            reasons = []
            score = 0.0

            for sast in sast_findings:
                match_score, match_reasons = self._compute_match(dast, sast)
                if match_score > 0:
                    correlated.append(sast)
                    reasons.extend(match_reasons)
                    score = max(score, match_score)

            results.append(
                CorrelationResult(
                    dast_finding=dast,
                    correlated_sast=correlated,
                    correlation_score=min(score, 1.0),
                    correlation_reasons=reasons,
                )
            )

        correlated_count = sum(1 for r in results if r.is_correlated)
        logger.info(
            f"Correlation: {correlated_count}/{len(results)} DAST findings "
            f"have SAST cross-validation"
        )

        return results

    def _compute_match(self, dast: Finding, sast: Finding) -> Tuple[float, List[str]]:
        """Compute match score between a DAST and SAST finding."""
        score = 0.0
        reasons: List[str] = []

        # 1. CWE match (strongest signal: 0.6)
        if dast.cwe and sast.cwe:
            dast_cwe = dast.cwe.split(":")[0] if ":" in dast.cwe else dast.cwe
            sast_cwe = sast.cwe.split(":")[0] if ":" in sast.cwe else sast.cwe

            if dast_cwe == sast_cwe:
                score += 0.6
                reasons.append(f"Same CWE: {dast_cwe}")
            elif self._cwe_to_group.get(dast_cwe) and self._cwe_to_group.get(
                dast_cwe
            ) == self._cwe_to_group.get(sast_cwe):
                score += 0.5
                reasons.append(f"Same CWE group: {self._cwe_to_group[dast_cwe]}")

        # 2. URL path ↔ file path correlation (0.3)
        if dast.evidence and dast.evidence.url and sast.target:
            url_path = self._extract_url_path(dast.evidence.url)
            file_path = sast.target
            if self._paths_correlate(url_path, file_path):
                score += 0.3
                reasons.append(f"Path correlation: {url_path} ↔ {file_path}")

        # 3. Keyword overlap in title/description (0.2)
        keyword_overlap = self._keyword_overlap(dast, sast)
        if keyword_overlap >= 2:
            score += 0.2
            reasons.append(f"Keyword overlap ({keyword_overlap} terms)")
        elif keyword_overlap == 1:
            score += 0.1

        return score, reasons

    def _extract_url_path(self, url: str) -> str:
        """Extract meaningful path segments from URL."""
        # Strip protocol and domain
        if "://" in url:
            url = url.split("://", 1)[1]
        if "/" in url:
            url = url.split("/", 1)[1]
        # Strip query params
        if "?" in url:
            url = url.split("?", 1)[0]
        return url

    def _paths_correlate(self, url_path: str, file_path: str) -> bool:
        """Check if a URL path correlates with a source file path.

        e.g., /api/users/login → routes/users.js or controllers/userController.js
        """
        # Extract meaningful segments
        url_parts = set(p.lower() for p in url_path.split("/") if p and len(p) > 2)
        file_parts = set(
            p.lower().replace(".js", "").replace(".ts", "").replace(".py", "")
            for p in file_path.replace("\\", "/").split("/")
            if p and len(p) > 2
        )

        # At least one meaningful segment overlap
        overlap = url_parts & file_parts
        return len(overlap) > 0

    def _keyword_overlap(self, dast: Finding, sast: Finding) -> int:
        """Count overlapping security keywords between findings."""
        security_keywords = {
            "injection",
            "sql",
            "xss",
            "script",
            "command",
            "exec",
            "traversal",
            "path",
            "redirect",
            "ssrf",
            "xxe",
            "deserializ",
            "auth",
            "bypass",
            "upload",
            "csrf",
            "cookie",
            "session",
        }

        dast_text = f"{dast.title} {dast.description}".lower()
        sast_text = f"{sast.title} {sast.description}".lower()

        dast_keywords = {kw for kw in security_keywords if kw in dast_text}
        sast_keywords = {kw for kw in security_keywords if kw in sast_text}

        return len(dast_keywords & sast_keywords)
