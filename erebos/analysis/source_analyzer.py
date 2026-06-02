"""White-hat mode: analyze source code to inform exploitation.

VT-Spec R3, R9: Source code analysis pipeline.
VT-Spec EXEC-01: Semgrep custom rules gated behind trust flag.
VT-Spec INJ-03: Relative paths in output by default.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from erebos.analysis.correlator import CorrelatedFinding, FindingCorrelator
from erebos.analysis.payload_advisor import PayloadAdvisor, PayloadHint, SanitizerInfo
from erebos.analysis.route_extractor import RouteExtractor, RouteInfo
from erebos.analysis.semgrep_runner import SastFinding, SemgrepRunner

logger = logging.getLogger(__name__)


class SourceAnalysisResult(BaseModel):
    """Result of source code analysis pipeline."""

    framework: str = "unknown"  # detected framework
    routes: List[RouteInfo] = Field(default_factory=list)
    sast_findings: List[SastFinding] = Field(default_factory=list)
    sanitizers: List[SanitizerInfo] = Field(default_factory=list)
    defenses: List[str] = Field(default_factory=list)  # e.g., ["CSP", "CORS", "rate-limiting"]
    payload_hints: List[PayloadHint] = Field(default_factory=list)
    correlated_findings: List[CorrelatedFinding] = Field(default_factory=list)


class SourceAnalyzer:
    """White-hat mode: analyze source code to inform exploitation.

    VT-Spec EXEC-01: Semgrep custom rules require explicit trust_rules flag.
    VT-Spec INJ-03: All output paths are relative.

    Pipeline:
    1. Detect framework (Flask, Express, Spring, Django, FastAPI)
    2. Extract routes → map to URLs
    3. Run Semgrep → get SAST findings
    4. Identify sanitizers/defenses in use
    5. Generate payload hints
    6. Return enrichment data for FactGraph
    """

    # Defense detection patterns
    _DEFENSE_PATTERNS: Dict[str, List[str]] = {
        "CSP": ["content-security-policy", "helmet.contentSecurityPolicy", "csp_header"],
        "CORS": ["cors(", "Access-Control-Allow-Origin", "@CrossOrigin"],
        "rate-limiting": [
            "rate_limit", "RateLimiter", "express-rate-limit",
            "throttle", "@Throttle",
        ],
        "CSRF": ["csrf", "CSRFProtect", "csurf", "@csrf_exempt"],
        "WAF": ["ModSecurity", "cloudflare", "waf"],
        "HSTS": ["Strict-Transport-Security", "hsts"],
    }

    def __init__(
        self,
        source_path: Path,
        allowlist: Optional[List[str]] = None,
        trust_rules: bool = False,
    ):
        self._source_path = source_path
        self._allowlist = allowlist or []
        self._route_extractor = RouteExtractor()
        # VT-Spec EXEC-01: trust flag explicitly passed
        self._semgrep = SemgrepRunner(trust_custom_rules=trust_rules)
        self._correlator = FindingCorrelator()
        self._payload_advisor = PayloadAdvisor()

    def analyze(
        self,
        custom_rules: Optional[Path] = None,
        dast_targets: Optional[List[str]] = None,
    ) -> SourceAnalysisResult:
        """Full source analysis pipeline.

        Args:
            custom_rules: Optional path to custom Semgrep rules (EXEC-01 gated).
            dast_targets: Optional list of DAST target URLs for correlation.
        """
        logger.info("Starting source analysis on %s", self._source_path)

        # Step 1: Detect framework
        framework = self._route_extractor.detect_framework(self._source_path) or "unknown"
        logger.info("Detected framework: %s", framework)

        # Step 2: Extract routes
        routes = self._route_extractor.extract(self._source_path, framework if framework != "unknown" else None)
        logger.info("Extracted %d routes", len(routes))

        # Step 3: Run Semgrep
        sast_findings = self._semgrep.run(self._source_path, custom_rules=custom_rules)
        logger.info("Semgrep found %d findings", len(sast_findings))

        # Step 4: Detect sanitizers and defenses
        content_map = self._read_source_files()
        sanitizers = self._payload_advisor.detect_sanitizers(self._source_path, content_map)
        defenses = self._detect_defenses(content_map)
        logger.info("Detected %d sanitizers, %d defenses", len(sanitizers), len(defenses))

        # Step 5: Generate payload hints
        payload_hints = self._payload_advisor.advise(framework, sanitizers)

        # Step 6: Correlate SAST with DAST (if targets provided)
        correlated: List[CorrelatedFinding] = []
        if dast_targets and sast_findings:
            correlated = self._correlator.correlate(sast_findings, dast_targets, routes)

        result = SourceAnalysisResult(
            framework=framework,
            routes=routes,
            sast_findings=sast_findings,
            sanitizers=sanitizers,
            defenses=defenses,
            payload_hints=payload_hints,
            correlated_findings=correlated,
        )

        logger.info(
            "Source analysis complete: %d routes, %d findings, %d hints",
            len(routes),
            len(sast_findings),
            len(payload_hints),
        )
        return result

    def _read_source_files(self) -> Dict[str, str]:
        """Read source files for sanitizer/defense detection.

        VT-Spec INJ-03: Only relative paths as keys.
        """
        content_map: Dict[str, str] = {}
        extensions = (".py", ".js", ".ts", ".java", ".kt", ".rb", ".php")

        for ext in extensions:
            for f in self._source_path.rglob(f"*{ext}"):
                rel = f.relative_to(self._source_path)
                parts = rel.parts
                if any(
                    p in parts
                    for p in ("node_modules", "venv", ".venv", ".git", "__pycache__", "dist")
                ):
                    continue
                try:
                    content_map[str(rel)] = f.read_text(errors="ignore")
                except OSError:
                    continue

        return content_map

    def _detect_defenses(self, content_map: Dict[str, str]) -> List[str]:
        """Detect security defenses in source code."""
        detected: List[str] = []

        all_content = "\n".join(content_map.values())
        for defense, patterns in self._DEFENSE_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in all_content.lower():
                    detected.append(defense)
                    break

        return detected
