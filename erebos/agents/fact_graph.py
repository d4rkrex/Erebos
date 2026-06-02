"""Typed knowledge graph for inter-agent communication."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class FactType(str, Enum):
    """Types of facts in the knowledge graph."""

    ENDPOINT = "endpoint"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    EXPLOIT_RESULT = "exploit_result"
    AUTH_TOKEN = "auth_token"
    TECHNOLOGY = "technology"
    CONFIGURATION = "configuration"


class EdgeType(str, Enum):
    """Typed relationships between facts."""

    DISCOVERED_AT = "discovered_at"
    EXPLOITED_VIA = "exploited_via"
    REQUIRES_AUTH = "requires_auth"
    HAS_PARAM = "has_param"
    LEADS_TO = "leads_to"
    MITIGATED_BY = "mitigated_by"


class Fact(BaseModel):
    """A single observed truth in the knowledge graph."""

    id: str = Field(default_factory=lambda: f"fact-{uuid4().hex[:12]}")
    fact_type: FactType
    data: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_agent: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    exploited: bool = False


class FactEdge(BaseModel):
    """A typed relationship between two facts."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FactGraph:
    """In-memory typed knowledge graph with JSONL persistence.

    Security controls:
    - Facts are sanitized before storage (no raw credentials)
    - All mutations logged
    - Confidence tracking for quality control
    """

    MAX_DATA_VALUE_LENGTH = 500
    CREDENTIAL_PLACEHOLDER = "[REDACTED-ref:{fact_id}]"

    def __init__(self, persist_path: Optional[Path] = None):
        self._facts: Dict[str, Fact] = {}
        self._edges: List[FactEdge] = []
        self._persist_path = persist_path
        if persist_path and persist_path.exists():
            self._load()

    def add_fact(self, fact: Fact, sanitize: bool = True) -> Fact:
        """Add a fact to the graph. Sanitizes by default."""
        if sanitize:
            fact = self._sanitize_fact(fact)
        self._facts[fact.id] = fact
        self._persist_append(fact)
        logger.debug("[FACT_GRAPH] added fact %s (%s)", fact.id, fact.fact_type.value)
        return fact

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[FactEdge]:
        """Add a typed edge between two facts."""
        if source_id not in self._facts or target_id not in self._facts:
            logger.warning("Cannot add edge: missing fact %s or %s", source_id, target_id)
            return None
        edge = FactEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            metadata=metadata or {},
        )
        self._edges.append(edge)
        logger.debug(
            "[FACT_GRAPH] added edge %s -> %s (%s)",
            source_id,
            target_id,
            edge_type.value,
        )
        return edge

    def mark_exploited(self, fact_id: str) -> None:
        """Mark a vulnerability fact as exploited."""
        if fact_id in self._facts:
            self._facts[fact_id].exploited = True
            logger.debug("[FACT_GRAPH] marked exploited %s", fact_id)

    def get_facts(
        self,
        fact_type: Optional[FactType] = None,
        min_confidence: float = 0.0,
    ) -> List[Fact]:
        """Get facts filtered by type and minimum confidence."""
        results = []
        for fact in self._facts.values():
            if fact_type and fact.fact_type != fact_type:
                continue
            if fact.confidence < min_confidence:
                continue
            results.append(fact)
        return results

    def get_linked(self, fact_id: str, edge_type: Optional[EdgeType] = None) -> List[Fact]:
        """Get facts linked to a given fact via edges."""
        linked_ids: Set[str] = set()
        for edge in self._edges:
            if edge.source_id == fact_id:
                if edge_type is None or edge.edge_type == edge_type:
                    linked_ids.add(edge.target_id)
            elif edge.target_id == fact_id:
                if edge_type is None or edge.edge_type == edge_type:
                    linked_ids.add(edge.source_id)
        return [self._facts[fid] for fid in linked_ids if fid in self._facts]

    def get_unexploited_vulns(self) -> List[Fact]:
        """Get vulnerability facts that haven't been exploited yet."""
        return [
            fact
            for fact in self._facts.values()
            if fact.fact_type == FactType.VULNERABILITY and not fact.exploited
        ]

    def get_credentials(self) -> List[Fact]:
        """Get credential facts (values are redacted, only references)."""
        return [fact for fact in self._facts.values() if fact.fact_type == FactType.CREDENTIAL]

    def count_by_type(self) -> Dict[str, int]:
        """Count facts grouped by type."""
        counts: Dict[str, int] = {}
        for fact in self._facts.values():
            counts[fact.fact_type.value] = counts.get(fact.fact_type.value, 0) + 1
        return counts

    def get_fact(self, fact_id: str) -> Optional[Fact]:
        """Get a single fact by ID."""
        return self._facts.get(fact_id)

    def summary_for_llm(self, max_facts: int = 50) -> str:
        """Generate a text summary suitable for LLM context.

        Security: All values are already sanitized at ingestion time.
        """
        counts = self.count_by_type()
        lines = [f"FactGraph: {len(self._facts)} facts, {len(self._edges)} edges"]
        lines.append(f"Types: {json.dumps(counts)}")
        lines.append("")

        priority_facts = sorted(
            self._facts.values(),
            key=lambda fact: (-fact.confidence, fact.timestamp.isoformat()),
        )
        for fact in priority_facts[:max_facts]:
            lines.append(
                f"[{fact.fact_type.value}] conf={fact.confidence:.1f} "
                f"agent={fact.source_agent} data={json.dumps(fact.data, default=str)[:200]}"
            )

        return "\n".join(lines)

    def _sanitize_fact(self, fact: Fact) -> Fact:
        """Sanitize fact data before storage."""
        sanitized_data: Dict[str, Any] = {}
        for key, value in fact.data.items():
            if isinstance(value, str):
                value = re.sub(r"<[^>]+>", "", value)
                if len(value) > self.MAX_DATA_VALUE_LENGTH:
                    value = value[: self.MAX_DATA_VALUE_LENGTH] + "...[truncated]"
                if fact.fact_type == FactType.CREDENTIAL and key in {
                    "password",
                    "secret",
                    "token_value",
                    "api_key",
                    "private_key",
                }:
                    value = self.CREDENTIAL_PLACEHOLDER.format(fact_id=fact.id)
            sanitized_data[key] = value

        fact.data = sanitized_data
        return fact

    def _persist_append(self, fact: Fact) -> None:
        """Append fact to JSONL file."""
        if not self._persist_path:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        with self._persist_path.open("a", encoding="utf-8") as handle:
            handle.write(fact.model_dump_json() + "\n")

    def _load(self) -> None:
        """Load facts from JSONL file."""
        if not self._persist_path or not self._persist_path.exists():
            return
        try:
            for line in self._persist_path.read_text(encoding="utf-8").strip().splitlines():
                if line.strip():
                    fact = Fact.model_validate_json(line)
                    self._facts[fact.id] = fact
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("Failed to load FactGraph from %s: %s", self._persist_path, exc)

    def clear(self) -> None:
        """Clear all facts and edges (for testing)."""
        self._facts.clear()
        self._edges.clear()
        logger.debug("[FACT_GRAPH] cleared graph")
