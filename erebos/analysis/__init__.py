"""White-Hat Source Analysis Module.

VT-Spec R3, R9: Source code analysis for informed exploitation.
Runs Semgrep SAST, extracts routes, correlates with DAST findings.
"""

from erebos.analysis.correlator import CorrelatedFinding, FindingCorrelator
from erebos.analysis.payload_advisor import PayloadAdvisor, PayloadHint
from erebos.analysis.route_extractor import RouteExtractor, RouteInfo
from erebos.analysis.semgrep_runner import SemgrepRunner
from erebos.analysis.source_analyzer import SourceAnalysisResult, SourceAnalyzer

__all__ = [
    "SourceAnalyzer",
    "SourceAnalysisResult",
    "RouteExtractor",
    "RouteInfo",
    "SemgrepRunner",
    "FindingCorrelator",
    "CorrelatedFinding",
    "PayloadAdvisor",
    "PayloadHint",
]
