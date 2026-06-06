"""Evidence chain builder — links related findings into attack narratives.

Groups findings by target/path, CWE escalation patterns, and temporal proximity
to construct complete attack chains (Recon → Vuln → Exploit).
"""

from erebos.core.chains.builder import ChainBuilder, EvidenceChain, ChainLink

__all__ = ["ChainBuilder", "EvidenceChain", "ChainLink"]
