"""Inference engine for smart recon decisions."""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from erebos.core.decision_engine import DecisionContext, DecisionResult, IntelligentDecisionEngine
from erebos.core.finding import Phase, ScanMode
from erebos.core.target_profile import TargetProfile, TargetProfiler, TargetType
from erebos.enrichment.cve_service import CveRecord
from erebos.enrichment.http_probe import HttpProbeResult

if TYPE_CHECKING:
    from erebos.parsers.nmap import NmapScanResult

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """A single inference rule that triggers an action."""

    trigger: str
    action: str
    params: Dict[str, object] = field(default_factory=dict)
    priority: int = 50


RuleRegistry = List[Rule]


# ---------------------------------------------------------------------------
# Default inference rules (sorted by priority ascending)
# ---------------------------------------------------------------------------

DEFAULT_RULES: RuleRegistry = [
    # OS detected → OS-specific CVE lookup (priority 5)
    Rule(
        trigger="os_detected",
        action="os_cve_lookup",
        params={},
        priority=5,
    ),
    # Service version detected → CVE lookup (priority 10)
    Rule(
        trigger="service_version_detected",
        action="cve_lookup",
        params={},
        priority=10,
    ),
    # CVE found → ExploitDB search (priority 20)
    Rule(
        trigger="cve_found",
        action="exploitdb_search",
        params={},
        priority=20,
    ),
    # Any open port → HTTP probe (priority 30)
    Rule(
        trigger="port_open",
        action="http_probe",
        params={},
        priority=30,
    ),
    # HTTP service detected → nuclei scan (priority 40)
    Rule(
        trigger="http_service_detected",
        action="nuclei_scan",
        params={},
        priority=40,
    ),
]


@dataclass
class InferenceDecision:
    """Decision emitted by the InferenceEngine."""

    trigger: str
    action: str
    params: Dict[str, object] = field(default_factory=dict)
    priority: int = 50


class InferenceEngine:
    """Rule-based inference engine for reconnaissance decisions.

    Reads structured NmapScanResult data and emits ordered InferenceDecision
    objects based on configurable rules. Decisions are sorted by priority.
    """

    def __init__(self, rules: Optional[RuleRegistry] = None):
        """Initialize the inference engine.

        Args:
            rules: Custom rule registry. Uses DEFAULT_RULES if None.
        """
        self._rules: RuleRegistry = sorted(rules or DEFAULT_RULES, key=lambda r: r.priority)

    _tool_to_action: Dict[str, str] = {
        "nmap": "run_nmap",
        "nmap-advanced": "run_nmap",
        "nuclei": "nuclei_scan",
        "nuclei-wordpress": "nuclei_scan",
        "nikto": "run_nikto",
        "katana": "run_katana",
        "ffuf": "run_ffuf",
        "sqlmap": "run_sqlmap",
        "gobuster": "run_gobuster",
        "dirb": "run_dirb",
        "masscan": "run_masscan",
        "wpscan": "run_wpscan",
        "arjun": "run_arjun",
        "swagger-analyzer": "run_swagger_analyzer",
    }

    def infer(self, nmap_result: NmapScanResult) -> List[InferenceDecision]:
        """Analyze nmap scan result and emit inference decisions.

        Evaluates rules for:
        - OS detection
        - Service version detection
        - Open port detection

        Args:
            nmap_result: Structured nmap scan result.

        Returns:
            Sorted list of InferenceDecision objects (by priority).
        """
        decisions: List[InferenceDecision] = []

        # OS detected
        for os_match in nmap_result.os_matches:
            if os_match.name and os_match.accuracy >= 70:
                decisions.append(
                    InferenceDecision(
                        trigger="os_detected",
                        action="os_cve_lookup",
                        params={"os_name": os_match.name, "accuracy": os_match.accuracy},
                        priority=5,
                    )
                )
                break  # Emit at most one OS decision per scan

        # Service version detected (CPE available)
        seen_cpes: set = set()
        for port in nmap_result.ports:
            if port.cpe and port.cpe not in seen_cpes:
                seen_cpes.add(port.cpe)
                decisions.append(
                    InferenceDecision(
                        trigger="service_version_detected",
                        action="cve_lookup",
                        params={
                            "product": port.product,
                            "version": port.version,
                            "cpe": port.cpe,
                            "host": port.host,
                        },
                        priority=10,
                    )
                )
            elif port.product and port.version:
                # No CPE but product+version known
                decisions.append(
                    InferenceDecision(
                        trigger="service_version_detected",
                        action="cve_lookup",
                        params={
                            "product": port.product,
                            "version": port.version,
                            "cpe": "",
                            "host": port.host,
                        },
                        priority=10,
                    )
                )

        # Any open port → HTTP probe
        for port in nmap_result.ports:
            if port.state not in ("closed",):
                decisions.append(
                    InferenceDecision(
                        trigger="port_open",
                        action="http_probe",
                        params={"host": port.host, "port": port.port, "protocol": port.protocol},
                        priority=30,
                    )
                )

        # Sort by priority (ascending) before returning
        decisions.sort(key=lambda d: d.priority)
        return decisions

    def process_cve_results(self, cves: List[CveRecord]) -> List[InferenceDecision]:
        """Emit decisions based on CVE lookup results.

        Triggers ExploitDB search for each discovered CVE.

        Args:
            cves: List of CveRecord from CveService.

        Returns:
            List of InferenceDecision for exploitdb_search actions.
        """
        decisions: List[InferenceDecision] = []

        if not cves:
            return decisions

        cve_ids = [cve.cve_id for cve in cves if cve.cve_id]
        if cve_ids:
            decisions.append(
                InferenceDecision(
                    trigger="cve_found",
                    action="exploitdb_search",
                    params={"cve_ids": cve_ids, "count": len(cve_ids)},
                    priority=20,
                )
            )

        decisions.sort(key=lambda d: d.priority)
        return decisions

    def process_http_probe(self, result: HttpProbeResult) -> List[InferenceDecision]:
        """Emit decisions based on HTTP probe result.

        Triggers nuclei scan when HTTP service is detected.

        Args:
            result: HttpProbeResult from HttpProbeService.

        Returns:
            List of InferenceDecision for nuclei_scan action.
        """
        decisions: List[InferenceDecision] = []

        if result.is_http:
            params: Dict[str, object] = {"is_https": result.is_https}
            if result.status_code:
                params["status_code"] = result.status_code
            if result.server_banner:
                params["server_banner"] = result.server_banner
            if result.redirect_url:
                params["redirect_url"] = result.redirect_url

            decisions.append(
                InferenceDecision(
                    trigger="http_service_detected",
                    action="nuclei_scan",
                    params=params,
                    priority=40,
                )
            )

        return decisions

    def recommend_tools_for_phase(self, context: dict) -> Optional[DecisionResult]:
        """Return a DecisionEngine result for the current phase context."""
        if not context.get("enable_intelligent_decisions", False):
            logger.info("Intelligent decisions disabled")
            return None

        try:
            decision_context = DecisionContext.from_dict(context)
            if not decision_context.available_tools:
                decision_context.available_tools = list(context.get("available_tools", []))
            engine = IntelligentDecisionEngine(
                default_threshold=float(context.get("decision_default_threshold", 0.70)),
                stealth_threshold=float(context.get("decision_stealth_threshold", 0.85)),
                aggressive_threshold=float(context.get("decision_aggressive_threshold", 0.60)),
                max_decision_latency_ms=float(context.get("decision_max_latency_ms", 50.0)),
            )
            return engine.select_tools(decision_context)
        except Exception as exc:
            logger.warning(
                "DecisionEngine unavailable, falling back to rule-based selection: %s", exc
            )
            return None

    def process_decision_result(
        self,
        result: DecisionResult,
        context: dict,
    ) -> List[InferenceDecision]:
        """Convert a DecisionEngine result into inference decisions."""
        decisions: List[InferenceDecision] = [
            InferenceDecision(
                trigger="decision_made",
                action="log_decision",
                params={
                    "tool_count": len(result.selected_tools),
                    "skipped_count": len(result.excluded_tools),
                    "reasoning": result.reasoning,
                    "latency_ms": result.decision_latency_ms,
                },
                priority=1,
            )
        ]

        context["decision_result"] = result.to_dict()
        for recommendation in result.selected_tools:
            decisions.append(
                InferenceDecision(
                    trigger="tool_recommended",
                    action=self._tool_to_action.get(recommendation.tool_name, "run_tool"),
                    params={
                        "tool": recommendation.tool_name,
                        "effectiveness": recommendation.effectiveness_score,
                        "parameters": list(recommendation.parameters),
                        "priority": recommendation.priority,
                    },
                    priority=recommendation.priority + 50,
                )
            )

        decisions.sort(key=lambda item: item.priority)
        return decisions

    @staticmethod
    def phase_context_from_runtime(
        phase: Phase,
        target: str,
        available_tools: List[str],
        context: dict,
    ) -> dict:
        """Build DecisionContext-compatible input from phase runtime data."""
        payload = copy.deepcopy(context)
        payload["phase"] = phase.value
        payload["target"] = target
        payload["available_tools"] = list(available_tools)
        payload.setdefault("scan_mode", ScanMode.NORMAL.value)
        return payload

    def infer_for_profile(
        self,
        target: str,
        nmap_result: NmapScanResult,
        http_results: Dict[Tuple[str, int], HttpProbeResult],
        profile: Optional[TargetProfile] = None,
    ) -> List[InferenceDecision]:
        """Emit profile-aware decisions for downstream phases.

        Decisions are derived from an existing TargetProfile when available,
        otherwise an inline profile is created from the current recon signals.
        """
        active_profile = profile or TargetProfiler().create_profile(
            target, nmap_result, http_results
        )
        if active_profile is None:
            return []

        decisions: List[InferenceDecision] = []
        tech_names = {technology.name.lower() for technology in active_profile.technologies}
        db_services = [
            service.service
            for service in active_profile.services
            if service.service.lower() in {"mysql", "postgresql", "mongodb", "redis"}
        ]

        cms_name = next(
            (name for name in ["wordpress", "drupal", "joomla"] if name in tech_names),
            None,
        )
        if cms_name:
            decisions.append(
                InferenceDecision(
                    trigger="cms_detected",
                    action="nuclei_tag_scan",
                    params={"cms": cms_name, "tags": ["cms", cms_name]},
                    priority=35,
                )
            )

        if active_profile.target_type == TargetType.API_ENDPOINT:
            decisions.append(
                InferenceDecision(
                    trigger="api_endpoint_detected",
                    action="nuclei_tag_scan",
                    params={"target_type": active_profile.target_type.value, "tags": ["api"]},
                    priority=36,
                )
            )

        if active_profile.target_type == TargetType.CONTAINER:
            decisions.append(
                InferenceDecision(
                    trigger="container_runtime_exposed",
                    action="nuclei_tag_scan",
                    params={"tags": ["docker", "kubernetes", "exposure"]},
                    priority=32,
                )
            )

        if db_services:
            decisions.append(
                InferenceDecision(
                    trigger="database_exposed",
                    action="flag_high_risk",
                    params={
                        "services": sorted(set(db_services)),
                        "risk_level": active_profile.risk_level.value,
                        "attack_surface_score": active_profile.attack_surface_score,
                    },
                    priority=25,
                )
            )

        if active_profile.attack_surface_score >= 6.0:
            decisions.append(
                InferenceDecision(
                    trigger="high_attack_surface",
                    action="flag_high_risk",
                    params={
                        "risk_level": active_profile.risk_level.value,
                        "attack_surface_score": active_profile.attack_surface_score,
                        "target_type": active_profile.target_type.value,
                    },
                    priority=28,
                )
            )

        decisions.sort(key=lambda d: d.priority)
        return decisions
