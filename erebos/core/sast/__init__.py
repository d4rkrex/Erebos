"""SAST (Static Application Security Testing) integration.

Provides Semgrep-based source code scanning with:
- Custom rule sets for common vulnerability patterns
- Finding correlation between DAST and SAST results
- Source context extraction for validation pipeline
- Coverage tracking
"""

from erebos.core.sast.scanner import SastScanner, SastFinding, SastResult
from erebos.core.sast.correlator import FindingCorrelator, CorrelationResult
from erebos.core.sast.sarif import SarifGenerator
from erebos.core.sast.incremental import IncrementalScanner

__all__ = [
    "SastScanner",
    "SastFinding",
    "SastResult",
    "IncrementalScanner",
    "FindingCorrelator",
    "CorrelationResult",
    "SarifGenerator",
]
