"""External findings ingestion layer.

Accepts findings from external scanners (SARIF, Fortify, Burp, Semgrep, CSV, native)
and normalizes them into the FactGraph.

VT-Spec R1, R8: External Findings Ingestion & Format Normalization
VT-Spec INJ-01: All fields sanitized at parse time
VT-Spec SCOPE-01: All URLs validated against AllowlistValidator
"""

from erebos.ingestion.base import FindingsParser, IngestResult
from erebos.ingestion.burp_parser import BurpParser
from erebos.ingestion.csv_parser import CSVParser
from erebos.ingestion.fortify_parser import FortifyParser
from erebos.ingestion.ingester import FindingsIngester
from erebos.ingestion.native_parser import NativeParser
from erebos.ingestion.sarif_parser import SARIFParser
from erebos.ingestion.semgrep_parser import SemgrepParser

__all__ = [
    "FindingsParser",
    "IngestResult",
    "FindingsIngester",
    "SARIFParser",
    "FortifyParser",
    "BurpParser",
    "SemgrepParser",
    "CSVParser",
    "NativeParser",
]
