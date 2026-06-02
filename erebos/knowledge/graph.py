"""Knowledge Graph for Erebos (REQ-004).

Tracks hosts, services, vulnerabilities, credentials, and attack paths.

# VT-Spec T-SKG-03 HIGH: Separate instance per engagement, validate engagement_id
# VT-Spec T-SKG-07 HIGH: Store credential HASHES only, never plaintext
# VT-Spec T-SKG-08 MEDIUM: Max 10000 nodes, 50000 edges
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional

try:
    import networkx as nx
except ImportError:
    nx = None  # type: ignore[assignment]

from erebos.core.models import Observation, ObservationType

logger = logging.getLogger(__name__)

# VT-Spec T-SKG-08: Default graph size limits
DEFAULT_MAX_NODES = 10000
DEFAULT_MAX_EDGES = 50000

# VT-Spec T-SKG-03: Engagement ID validation pattern (no path traversal)
ENGAGEMENT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")


class GraphLimitExceeded(Exception):
    """Raised when graph size limits are exceeded."""

    pass


def _validate_engagement_id(engagement_id: str) -> None:
    """Validate engagement_id to prevent path traversal.

    # VT-Spec T-SKG-03 HIGH: Reject ../ and / in engagement IDs
    """
    if not engagement_id:
        raise ValueError("VT-Spec T-SKG-03: engagement_id cannot be empty")
    if ".." in engagement_id or "/" in engagement_id or "\\" in engagement_id:
        raise ValueError(
            f"VT-Spec T-SKG-03: engagement_id contains path traversal characters: {engagement_id!r}"
        )
    if not ENGAGEMENT_ID_PATTERN.match(engagement_id):
        raise ValueError(
            f"VT-Spec T-SKG-03: engagement_id invalid format: {engagement_id!r}"
        )


class KnowledgeGraph:
    """Engagement-scoped knowledge graph tracking attack surface.

    # VT-Spec T-SKG-03 HIGH: Separate instance per engagement
    # VT-Spec T-SKG-07 HIGH: Credentials stored as hashes only
    # VT-Spec T-SKG-08 MEDIUM: Node/edge limits enforced
    """

    def __init__(
        self,
        engagement_id: str,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_edges: int = DEFAULT_MAX_EDGES,
    ) -> None:
        # VT-Spec T-SKG-03: Validate engagement_id
        _validate_engagement_id(engagement_id)

        self._engagement_id = engagement_id
        self._max_nodes = max_nodes
        self._max_edges = max_edges

        if nx is None:
            raise ImportError("networkx is required for KnowledgeGraph")

        self._graph: nx.DiGraph = nx.DiGraph()

    @property
    def engagement_id(self) -> str:
        return self._engagement_id

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def _check_node_limit(self) -> None:
        """VT-Spec T-SKG-08: Reject additions beyond node limit."""
        if self._graph.number_of_nodes() >= self._max_nodes:
            raise GraphLimitExceeded(
                f"VT-Spec T-SKG-08: Maximum nodes ({self._max_nodes}) exceeded"
            )

    def _check_edge_limit(self) -> None:
        """VT-Spec T-SKG-08: Reject additions beyond edge limit."""
        if self._graph.number_of_edges() >= self._max_edges:
            raise GraphLimitExceeded(
                f"VT-Spec T-SKG-08: Maximum edges ({self._max_edges}) exceeded"
            )

    def add_host(
        self, ip: str, hostname: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add a host node to the graph."""
        if not self._graph.has_node(ip):
            self._check_node_limit()

        attrs = {"type": "host", "hostname": hostname or "", **(metadata or {})}
        self._graph.add_node(ip, **attrs)

    def add_service(
        self, host: str, port: int, service: str, version: Optional[str] = None
    ) -> None:
        """Add a service node connected to a host."""
        service_id = f"{host}:{port}"

        if not self._graph.has_node(service_id):
            self._check_node_limit()

        self._graph.add_node(
            service_id,
            type="service",
            host=host,
            port=port,
            service=service,
            version=version or "",
        )

        # Add edge from host to service
        if not self._graph.has_edge(host, service_id):
            self._check_edge_limit()
        self._graph.add_edge(host, service_id, relation="has_service")

        # Ensure host exists
        if not self._graph.has_node(host):
            self._check_node_limit()
            self._graph.add_node(host, type="host")

    def add_vulnerability(
        self, host: str, port: int, vuln_id: str, severity: str
    ) -> None:
        """Add a vulnerability node connected to a service."""
        service_id = f"{host}:{port}"
        vuln_node = f"vuln:{vuln_id}@{service_id}"

        if not self._graph.has_node(vuln_node):
            self._check_node_limit()

        self._graph.add_node(
            vuln_node,
            type="vulnerability",
            vuln_id=vuln_id,
            severity=severity,
            host=host,
            port=port,
        )

        if not self._graph.has_edge(service_id, vuln_node):
            self._check_edge_limit()
        self._graph.add_edge(service_id, vuln_node, relation="has_vulnerability")

    def add_credential(self, host: str, username: str, credential_hash: str) -> None:
        """Add a credential node (hash only, never plaintext).

        # VT-Spec T-SKG-07 HIGH: Store HASH only, never plaintext.
        The caller must hash the credential before passing to this method.
        """
        cred_node = f"cred:{username}@{host}"

        if not self._graph.has_node(cred_node):
            self._check_node_limit()

        # VT-Spec T-SKG-07: Only store hash, never plaintext
        self._graph.add_node(
            cred_node,
            type="credential",
            username=username,
            credential_hash=credential_hash,
            host=host,
        )

        if not self._graph.has_edge(host, cred_node):
            self._check_edge_limit()
        self._graph.add_edge(host, cred_node, relation="has_credential")

    def add_access(self, host: str, level: str, via: str) -> None:
        """Record access achieved on a host."""
        access_node = f"access:{level}@{host}"

        if not self._graph.has_node(access_node):
            self._check_node_limit()

        self._graph.add_node(
            access_node,
            type="access",
            level=level,
            via=via,
            host=host,
        )

        if not self._graph.has_edge(host, access_node):
            self._check_edge_limit()
        self._graph.add_edge(host, access_node, relation="has_access")

    def get_attack_paths(self, source: str, target: str) -> List[List[str]]:
        """Find all simple paths between source and target nodes."""
        if not self._graph.has_node(source) or not self._graph.has_node(target):
            return []

        try:
            # Limit path search to prevent combinatorial explosion
            paths = list(nx.all_simple_paths(self._graph, source, target, cutoff=10))
            return paths
        except nx.NetworkXError:
            return []

    def get_hosts(self) -> List[Dict[str, Any]]:
        """Get all host nodes with their attributes."""
        hosts = []
        for node, data in self._graph.nodes(data=True):
            if data.get("type") == "host":
                hosts.append({"ip": node, **data})
        return hosts

    def get_services(self, host: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get service nodes, optionally filtered by host."""
        services = []
        for node, data in self._graph.nodes(data=True):
            if data.get("type") == "service":
                if host and data.get("host") != host:
                    continue
                services.append({"id": node, **data})
        return services

    def get_vulnerabilities(self, host: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get vulnerability nodes, optionally filtered by host."""
        vulns = []
        for node, data in self._graph.nodes(data=True):
            if data.get("type") == "vulnerability":
                if host and data.get("host") != host:
                    continue
                vulns.append({"id": node, **data})
        return vulns

    def enrich_from_observations(self, observations: List[Observation]) -> None:
        """Enrich the knowledge graph from observations."""
        for obs in observations:
            try:
                self._process_observation(obs)
            except GraphLimitExceeded:
                logger.warning(
                    "VT-Spec T-SKG-08: Graph limit reached, skipping remaining observations"
                )
                break

    def _process_observation(self, obs: Observation) -> None:
        """Process a single observation into graph nodes/edges."""
        data = obs.data

        if obs.observation_type == ObservationType.PORT_OPEN:
            host = data.get("host", obs.target_id or "unknown")
            port = data.get("port")
            service = data.get("service", "unknown")
            if host and port:
                self.add_host(host)
                self.add_service(host, int(port), service)

        elif obs.observation_type == ObservationType.SERVICE_DETECTED:
            host = data.get("host", obs.target_id or "unknown")
            port = data.get("port")
            service = data.get("service", "unknown")
            version = data.get("version")
            if host and port:
                self.add_host(host)
                self.add_service(host, int(port), service, version)

        elif obs.observation_type == ObservationType.VULNERABILITY_FOUND:
            host = data.get("host", obs.target_id or "unknown")
            port = data.get("port", 0)
            vuln_id = data.get("cve_id") or data.get("vuln_id", "unknown")
            severity = data.get("severity", "unknown")
            if host:
                self.add_host(host)
                self.add_vulnerability(host, int(port), vuln_id, severity)

        elif obs.observation_type == ObservationType.CREDENTIAL_FOUND:
            host = data.get("host", obs.target_id or "unknown")
            username = data.get("username", "unknown")
            # VT-Spec T-SKG-07: Hash credential before storing
            raw_cred = data.get("credential", "")
            cred_hash = hashlib.sha256(raw_cred.encode()).hexdigest() if raw_cred else ""
            if host and username:
                self.add_host(host)
                self.add_credential(host, username, cred_hash)

        elif obs.observation_type == ObservationType.ACCESS_GAINED:
            host = data.get("host", obs.target_id or "unknown")
            level = data.get("level", "unknown")
            via = data.get("via", "unknown")
            if host:
                self.add_host(host)
                self.add_access(host, level, via)
