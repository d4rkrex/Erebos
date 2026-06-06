"""Validation stages A-D for finding exploitability assessment.

Each stage implements a verdict protocol: given a Finding plus optional
source context, return a StageVerdict (PASS, FAIL, UNCERTAIN).
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from erebos.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class StageVerdict(str, Enum):
    """Result of a single validation stage."""

    PASS = "pass"  # Finding is likely valid/exploitable at this stage
    FAIL = "fail"  # Finding is NOT valid at this stage (short-circuit)
    UNCERTAIN = "uncertain"  # Cannot determine; proceed to next stage


@dataclass
class StageResult:
    """Output from one validation stage."""

    stage: str
    verdict: StageVerdict
    confidence: float  # 0.0 - 1.0
    reasoning: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceContext:
    """Source code context for SAST-originated findings."""

    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    function_name: Optional[str] = None
    entry_points: List[str] = field(default_factory=list)
    data_flow: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    language: Optional[str] = None


class ValidationStage(ABC):
    """Abstract base for a validation stage."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stage identifier (e.g., 'A', 'B', 'C', 'D')."""
        ...

    @abstractmethod
    def evaluate(
        self,
        finding: Finding,
        source_context: Optional[SourceContext] = None,
    ) -> StageResult:
        """Evaluate a finding at this stage."""
        ...


# --- Known false-positive patterns by tool ---

# Nuclei patterns that are almost always informational/FP
_NUCLEI_FP_PATTERNS = [
    r"tech-detect",
    r"http-missing-security-headers",
    r"options-method",
    r"robots-txt",
    r"sitemap-detect",
    r"waf-detect",
    r"favicon-detect",
    r"wordpress-detect",
    r"email-disclosure",
]

# Titles that are typically informational noise
_INFO_NOISE_TITLES = [
    r"(?i)server\s+header",
    r"(?i)x-powered-by",
    r"(?i)directory\s+listing",
    r"(?i)robots\.txt",
    r"(?i)sitemap.*found",
    r"(?i)options\s+method",
    r"(?i)cors\s+misconfiguration",  # Often FP without validation
]

# Semgrep rules known to have high FP rate without context
_SEMGREP_HIGH_FP_RULES = [
    "generic.secrets.gitleaks",
    "javascript.lang.security.audit.detect-non-literal-regexp",
    "python.lang.security.audit.exec-used",
]


class StageA_PatternValidity(ValidationStage):
    """Stage A: Is this a real vulnerability pattern or tool noise?

    Deterministic checks (no LLM needed):
    - Is the finding from a known-noisy template/rule?
    - Does the severity match the actual risk?
    - Is there enough evidence to even consider it?
    - Is it a duplicate/variant of another finding?
    """

    @property
    def name(self) -> str:
        return "A"

    def evaluate(
        self,
        finding: Finding,
        source_context: Optional[SourceContext] = None,
    ) -> StageResult:
        # Check for known FP patterns by tool
        if finding.tool == "nuclei":
            return self._evaluate_nuclei(finding)
        elif finding.tool == "semgrep":
            return self._evaluate_semgrep(finding, source_context)
        elif finding.tool in ("nmap", "httpx"):
            return self._evaluate_recon_tool(finding)
        else:
            # Unknown tool — pass through with medium confidence
            return StageResult(
                stage=self.name,
                verdict=StageVerdict.PASS,
                confidence=0.5,
                reasoning=f"Tool '{finding.tool}' not in FP database; passing through",
            )

    def _evaluate_nuclei(self, finding: Finding) -> StageResult:
        """Evaluate nuclei findings against known FP patterns."""
        # Check template ID patterns
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()

        for pattern in _NUCLEI_FP_PATTERNS:
            if re.search(pattern, title_lower) or re.search(pattern, desc_lower):
                return StageResult(
                    stage=self.name,
                    verdict=StageVerdict.FAIL,
                    confidence=0.9,
                    reasoning=f"Matched known FP pattern: {pattern}",
                    evidence={"matched_pattern": pattern},
                )

        for pattern in _INFO_NOISE_TITLES:
            if re.search(pattern, finding.title):
                return StageResult(
                    stage=self.name,
                    verdict=StageVerdict.FAIL,
                    confidence=0.85,
                    reasoning=f"Title matches informational noise: {pattern}",
                    evidence={"matched_pattern": pattern},
                )

        # INFO severity from nuclei is almost always noise
        if finding.severity == Severity.INFO:
            return StageResult(
                stage=self.name,
                verdict=StageVerdict.FAIL,
                confidence=0.8,
                reasoning="INFO severity nuclei findings are typically informational",
            )

        # Has evidence? If no URL/payload, suspicious
        if not finding.evidence.url and not finding.evidence.payload:
            return StageResult(
                stage=self.name,
                verdict=StageVerdict.UNCERTAIN,
                confidence=0.4,
                reasoning="No URL or payload evidence provided",
            )

        return StageResult(
            stage=self.name,
            verdict=StageVerdict.PASS,
            confidence=0.7,
            reasoning="Nuclei finding passes basic pattern validity",
        )

    def _evaluate_semgrep(
        self, finding: Finding, source_context: Optional[SourceContext]
    ) -> StageResult:
        """Evaluate semgrep findings."""
        # Check for known high-FP rules
        for rule in _SEMGREP_HIGH_FP_RULES:
            if rule in finding.title or rule in finding.description:
                return StageResult(
                    stage=self.name,
                    verdict=StageVerdict.UNCERTAIN,
                    confidence=0.4,
                    reasoning=f"Rule '{rule}' has known high FP rate; needs deeper analysis",
                    evidence={"rule_id": rule},
                )

        # If we have source context with sanitizers, flag for Stage B
        if source_context and source_context.sanitizers:
            return StageResult(
                stage=self.name,
                verdict=StageVerdict.PASS,
                confidence=0.6,
                reasoning="Pattern valid but sanitizers detected; needs reachability check",
                evidence={"sanitizers": source_context.sanitizers},
            )

        return StageResult(
            stage=self.name,
            verdict=StageVerdict.PASS,
            confidence=0.7,
            reasoning="Semgrep finding passes pattern validity",
        )

    def _evaluate_recon_tool(self, finding: Finding) -> StageResult:
        """Recon tools (nmap, httpx) produce info, not vulns directly."""
        if finding.severity in (Severity.INFO, Severity.LOW):
            return StageResult(
                stage=self.name,
                verdict=StageVerdict.FAIL,
                confidence=0.85,
                reasoning="Recon-tool INFO/LOW findings are reconnaissance data, not vulnerabilities",
            )
        return StageResult(
            stage=self.name,
            verdict=StageVerdict.PASS,
            confidence=0.6,
            reasoning="Recon finding with elevated severity; may indicate real issue",
        )


class StageB_Reachability(ValidationStage):
    """Stage B: Can an attacker reach the vulnerable code/endpoint?

    Checks:
    - Is the endpoint publicly accessible?
    - Are there authentication barriers?
    - Does the code path require special conditions?
    - Is there a data flow from entry point to sink?
    """

    @property
    def name(self) -> str:
        return "B"

    def evaluate(
        self,
        finding: Finding,
        source_context: Optional[SourceContext] = None,
    ) -> StageResult:
        # For DAST findings (nuclei, etc.) - endpoint was already reached
        if finding.tool in ("nuclei", "dalfox", "sqlmap", "nikto"):
            return self._evaluate_dast_reachability(finding)

        # For SAST findings - need source context
        if source_context:
            return self._evaluate_sast_reachability(finding, source_context)

        # No context available — uncertain
        return StageResult(
            stage=self.name,
            verdict=StageVerdict.UNCERTAIN,
            confidence=0.3,
            reasoning="No source context available to assess reachability",
        )

    def _evaluate_dast_reachability(self, finding: Finding) -> StageResult:
        """DAST findings hit a live endpoint — reachability is proven."""
        if finding.evidence.url:
            return StageResult(
                stage=self.name,
                verdict=StageVerdict.PASS,
                confidence=0.9,
                reasoning="DAST finding with URL evidence — endpoint was reached",
                evidence={"url": finding.evidence.url},
            )
        return StageResult(
            stage=self.name,
            verdict=StageVerdict.PASS,
            confidence=0.7,
            reasoning="DAST tool confirmed reachability during scan",
        )

    def _evaluate_sast_reachability(self, finding: Finding, ctx: SourceContext) -> StageResult:
        """Assess code-level reachability from source context."""
        score = 0.5  # Base score

        # Has entry points? (routes, handlers, exported functions)
        if ctx.entry_points:
            score += 0.2
            evidence = {"entry_points": ctx.entry_points}
        else:
            evidence = {}

        # Has data flow from source to sink?
        if ctx.data_flow:
            score += 0.2
            evidence["data_flow_length"] = len(ctx.data_flow)

        # Sanitizers reduce confidence
        if ctx.sanitizers:
            score -= 0.3
            evidence["sanitizers"] = ctx.sanitizers

        # Internal/private functions are harder to reach
        if ctx.function_name and ctx.function_name.startswith("_"):
            score -= 0.15
            evidence["private_function"] = True

        # Determine verdict from score
        if score >= 0.7:
            verdict = StageVerdict.PASS
        elif score <= 0.3:
            verdict = StageVerdict.FAIL
        else:
            verdict = StageVerdict.UNCERTAIN

        return StageResult(
            stage=self.name,
            verdict=verdict,
            confidence=min(score, 1.0),
            reasoning=f"Reachability score: {score:.2f}",
            evidence=evidence,
        )


class StageC_Exploitability(ValidationStage):
    """Stage C: Does a concrete attack path exist?

    Checks:
    - Can we construct a working payload?
    - Are there input validation/WAF barriers?
    - Does the vulnerability class have known exploit techniques?
    - For SAST: is there an unsanitized path from source to sink?
    """

    @property
    def name(self) -> str:
        return "C"

    # CWE classes with well-known exploit patterns
    _HIGHLY_EXPLOITABLE_CWES = {
        "CWE-89",  # SQL Injection
        "CWE-78",  # OS Command Injection
        "CWE-94",  # Code Injection
        "CWE-502",  # Deserialization
        "CWE-611",  # XXE
        "CWE-918",  # SSRF
        "CWE-22",  # Path Traversal
        "CWE-434",  # File Upload
    }

    _MODERATE_CWES = {
        "CWE-79",  # XSS
        "CWE-352",  # CSRF
        "CWE-287",  # Authentication Bypass
        "CWE-862",  # Missing Authorization
        "CWE-200",  # Information Disclosure
    }

    def evaluate(
        self,
        finding: Finding,
        source_context: Optional[SourceContext] = None,
    ) -> StageResult:
        evidence: Dict[str, Any] = {}
        score = 0.5

        # CWE-based exploitability assessment
        if finding.cwe:
            cwe_id = finding.cwe.split(":")[0] if ":" in finding.cwe else finding.cwe
            if cwe_id in self._HIGHLY_EXPLOITABLE_CWES:
                score += 0.3
                evidence["cwe_exploitability"] = "high"
            elif cwe_id in self._MODERATE_CWES:
                score += 0.15
                evidence["cwe_exploitability"] = "moderate"

        # Has CVE? Known vulns are more likely exploitable
        if finding.cve or finding.cves:
            score += 0.2
            evidence["has_cve"] = True

        # Evidence of payload/output suggests tool confirmed something
        if finding.evidence.payload:
            score += 0.15
            evidence["has_payload"] = True
        if finding.evidence.output:
            score += 0.1
            evidence["has_output"] = True

        # SAST context: unsanitized path = exploitable
        if source_context:
            if source_context.data_flow and not source_context.sanitizers:
                score += 0.25
                evidence["unsanitized_flow"] = True
            elif source_context.sanitizers:
                # Sanitizers present — check if they're complete
                score -= 0.2
                evidence["sanitized"] = True

        # Severity correlation
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            score += 0.1

        # Determine verdict
        if score >= 0.7:
            verdict = StageVerdict.PASS
        elif score <= 0.35:
            verdict = StageVerdict.FAIL
        else:
            verdict = StageVerdict.UNCERTAIN

        return StageResult(
            stage=self.name,
            verdict=verdict,
            confidence=min(max(score, 0.0), 1.0),
            reasoning=f"Exploitability score: {score:.2f}",
            evidence=evidence,
        )


class StageD_Practicality(ValidationStage):
    """Stage D: Is exploitation realistic in the deployment context?

    Final gate — filters out findings that are technically valid but
    practically unexploitable:
    - Test/dev code only
    - Requires unrealistic preconditions
    - Already mitigated at network/infrastructure level
    - Severity doesn't justify the complexity
    """

    @property
    def name(self) -> str:
        return "D"

    # Path patterns indicating test/dev code
    _TEST_PATTERNS = [
        r"test[s]?/",
        r"spec[s]?/",
        r"__test__",
        r"\.test\.",
        r"\.spec\.",
        r"mock[s]?/",
        r"fixture[s]?/",
        r"example[s]?/",
        r"demo/",
        r"sample[s]?/",
    ]

    def evaluate(
        self,
        finding: Finding,
        source_context: Optional[SourceContext] = None,
    ) -> StageResult:
        evidence: Dict[str, Any] = {}

        # Check if finding is in test/dev code
        if source_context and source_context.file_path:
            for pattern in self._TEST_PATTERNS:
                if re.search(pattern, source_context.file_path):
                    return StageResult(
                        stage=self.name,
                        verdict=StageVerdict.FAIL,
                        confidence=0.85,
                        reasoning=f"Finding in test/dev path: {source_context.file_path}",
                        evidence={"test_path_pattern": pattern},
                    )

        # Check target URL for test indicators
        if finding.evidence.url:
            url = finding.evidence.url.lower()
            if any(ind in url for ind in ["localhost", "127.0.0.1", "test.", "dev.", "staging."]):
                evidence["test_target"] = True
                # Not automatic FAIL — user may be testing against dev intentionally

        # High/Critical with CVE and evidence = very practical
        if (
            finding.severity in (Severity.CRITICAL, Severity.HIGH)
            and (finding.cve or finding.cves)
            and finding.evidence.payload
        ):
            return StageResult(
                stage=self.name,
                verdict=StageVerdict.PASS,
                confidence=0.9,
                reasoning="High severity + CVE + payload = practically exploitable",
                evidence=evidence,
            )

        # Medium+ with good evidence = practical
        if finding.severity != Severity.INFO and (finding.evidence.url or finding.evidence.payload):
            return StageResult(
                stage=self.name,
                verdict=StageVerdict.PASS,
                confidence=0.7,
                reasoning="Evidence supports practical exploitability",
                evidence=evidence,
            )

        # Low confidence fallthrough
        return StageResult(
            stage=self.name,
            verdict=StageVerdict.UNCERTAIN,
            confidence=0.5,
            reasoning="Insufficient context to assess practicality",
            evidence=evidence,
        )
