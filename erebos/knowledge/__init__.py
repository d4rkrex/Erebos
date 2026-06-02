"""Knowledge package for Erebos Phase 3: Skills & Knowledge.

Provides knowledge graph, observation store, and artifact management.
"""

from __future__ import annotations

from erebos.knowledge.graph import KnowledgeGraph
from erebos.knowledge.observations import ObservationStore
from erebos.knowledge.artifacts import ArtifactRef, ArtifactStore

__all__ = [
    "ArtifactRef",
    "ArtifactStore",
    "KnowledgeGraph",
    "ObservationStore",
]
