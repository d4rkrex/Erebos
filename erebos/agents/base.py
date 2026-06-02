"""Agent base models and FindingsBus for inter-agent communication.

VT-Spec DS-001: Max concurrency controls for agents.
VT-Spec RE-001: All agent actions logged.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional

if TYPE_CHECKING:
    from erebos.agents.fact_graph import FactGraph

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# VT-Spec DS-001: Hard cap on concurrent agents
MAX_FLEET_AGENTS = 8


class AgentRole(str, Enum):
    """Specialized agent roles in the fleet."""

    RECON = "recon"
    VULN_SCAN = "vuln-scan"
    WEB_DISCOVERY = "web-discovery"
    EXPLOIT = "exploit"
    CODE_AUDIT = "code-audit"
    REPORTER = "reporter"
    ORCHESTRATOR = "orchestrator"


class AgentStatus(str, Enum):
    """Agent lifecycle status."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class AgentMessage(BaseModel):
    """A message published to the FindingsBus by an agent."""

    id: str
    role: AgentRole
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message_type: str  # "finding", "status", "request", "result"
    payload: Dict[str, Any] = Field(default_factory=dict)


class FindingsBus:
    """JSONL file-based inter-agent communication bus.

    Agents publish findings/messages and subscribe to updates.
    VT-Spec RE-001: All messages are logged with timestamps.

    Design: append-only JSONL — no locking needed, agents can tail.
    """

    def __init__(self, path: Path, fact_graph: Optional["FactGraph"] = None):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._last_read_pos = 0
        self._fact_graph = fact_graph

    @property
    def path(self) -> Path:
        return self._path

    @property
    def graph(self) -> Optional["FactGraph"]:
        return self._fact_graph

    def publish(self, message: AgentMessage, sender_role: Optional[AgentRole] = None) -> None:
        """Publish a message to the bus (append-only).

        VT-Spec S-01: Validates message role matches sender's actual role.
        """
        # S-01: Role verification — message must claim sender's own role
        if sender_role is not None and message.role != sender_role:
            logger.warning(
                f"S-01: Bus message rejected — claimed role {message.role.value} "
                f"but sender is {sender_role.value}"
            )
            return

        line = message.model_dump_json() + "\n"
        with open(self._path, "a") as f:
            f.write(line)
        logger.debug(f"[BUS] {message.role.value} published: {message.message_type}")

        if self._fact_graph and message.message_type in {"finding", "attack_surface", "auth_token"}:
            try:
                self._publish_to_graph(message)
            except Exception as exc:  # pragma: no cover - additive compatibility
                logger.warning("Failed to publish message %s to FactGraph: %s", message.id, exc)

    def _publish_to_graph(self, message: AgentMessage) -> None:
        """Convert AgentMessage instances into FactGraph facts."""
        from erebos.agents.fact_graph import Fact, FactType

        payload = message.payload
        fact_type_map = {
            "endpoint": FactType.ENDPOINT,
            "vulnerability": FactType.VULNERABILITY,
            "credential": FactType.CREDENTIAL,
            "exploit_result": FactType.EXPLOIT_RESULT,
            "auth_token": FactType.AUTH_TOKEN,
        }

        def add_fact(fact_type: FactType, data: Dict[str, Any]) -> None:
            if not self._fact_graph:
                return
            fact = Fact(
                fact_type=fact_type,
                data=data,
                confidence=data.get("confidence", payload.get("confidence", 0.8)),
                source_agent=message.role.value,
                timestamp=message.timestamp,
            )
            self._fact_graph.add_fact(fact)

        if message.message_type == "attack_surface":
            for endpoint in payload.get("endpoints", []):
                if isinstance(endpoint, dict):
                    add_fact(FactType.ENDPOINT, endpoint)
            return

        if message.message_type == "auth_token":
            add_fact(FactType.AUTH_TOKEN, payload)
            return

        fact_type = FactType.VULNERABILITY
        payload_type = payload.get("type")
        if payload_type in fact_type_map:
            fact_type = fact_type_map[payload_type]
        elif payload.get("message_type") == "attack_surface" or "endpoint" in str(
            payload.get("message_type", "")
        ):
            fact_type = FactType.ENDPOINT
        elif "endpoint" in payload:
            fact_type = FactType.ENDPOINT

        add_fact(fact_type, payload)

    def subscribe(
        self,
        roles: Optional[List[AgentRole]] = None,
        message_types: Optional[List[str]] = None,
        since: Optional[datetime] = None,
    ) -> Iterator[AgentMessage]:
        """Read messages from the bus, optionally filtered.

        Args:
            roles: Only return messages from these roles
            message_types: Only return these message types
            since: Only return messages after this timestamp
        """
        if not self._path.exists():
            return

        with open(self._path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = AgentMessage.model_validate_json(line)
                    if roles and msg.role not in roles:
                        continue
                    if message_types and msg.message_type not in message_types:
                        continue
                    if since and msg.timestamp < since:
                        continue
                    yield msg
                except (json.JSONDecodeError, ValueError):
                    continue

    def tail(
        self,
        roles: Optional[List[AgentRole]] = None,
        message_types: Optional[List[str]] = None,
    ) -> List[AgentMessage]:
        """Read only NEW messages since last tail() call."""
        messages: List[AgentMessage] = []
        if not self._path.exists():
            return messages

        with open(self._path, "r") as f:
            f.seek(self._last_read_pos)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = AgentMessage.model_validate_json(line)
                    if roles and msg.role not in roles:
                        continue
                    if message_types and msg.message_type not in message_types:
                        continue
                    messages.append(msg)
                except (json.JSONDecodeError, ValueError):
                    continue
            self._last_read_pos = f.tell()

        return messages

    def count(self, message_type: Optional[str] = None) -> int:
        """Count total messages (or messages of a specific type)."""
        count = 0
        if not self._path.exists():
            return 0
        with open(self._path, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                if message_type:
                    try:
                        msg = AgentMessage.model_validate_json(line)
                        if msg.message_type == message_type:
                            count += 1
                    except (json.JSONDecodeError, ValueError):
                        continue
                else:
                    count += 1
        return count

    def clear(self) -> None:
        """Clear all messages (for testing or new scan)."""
        if self._path.exists():
            self._path.unlink()
        self._last_read_pos = 0
