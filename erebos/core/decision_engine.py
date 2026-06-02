"""Intelligent tool selection and parameter optimization."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import logging
import shlex
import time
from typing import Any, Dict, Iterable, List, Optional, Protocol, runtime_checkable

import yaml

from erebos.core.finding import Phase, ScanMode
from erebos.core.target_profile import RiskLevel, TargetType

logger = logging.getLogger(__name__)

TOOL_EFFECTIVENESS_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "tool_effectiveness.yaml"
)


@runtime_checkable
class TargetProfileProtocol(Protocol):
    """Structural protocol for target profile input."""

    target: str
    target_type: Any
    technologies: List[Any]
    services: List[Any]
    attack_surface_score: float
    risk_level: Any
    confidence: float


@dataclass(frozen=True)
class ToolRecommendation:
    """Recommendation for a single tool execution."""

    tool_name: str
    effectiveness_score: float
    parameters: List[str]
    reasoning: str
    phase: str
    priority: int


@dataclass
class DecisionContext:
    """Runtime context used for tool selection.

    VT-Spec AUTH-03: Includes auth_state and discovered_forms so the engine
    can reason about whether authenticated scanning is needed.
    """

    target: str
    phase: Phase
    mode: ScanMode
    available_tools: List[str]
    target_profile: Optional[TargetProfileProtocol] = None
    findings: List[Any] = field(default_factory=list)
    discovered_urls: List[str] = field(default_factory=list)
    discovered_services: List[str] = field(default_factory=list)
    # VT-Spec AUTH-03: Auth awareness for decision making
    has_auth: bool = False
    auth_type: Optional[str] = None  # "bearer", "cookie", "none"
    discovered_forms: List[Dict[str, Any]] = field(default_factory=list)
    # Endpoints that require authentication (returned 401/403 without session)
    protected_endpoints: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionContext":
        phase_value = data.get("phase", Phase.RECON.value)
        mode_value = data.get("scan_mode", ScanMode.NORMAL.value)
        target = str(data.get("target") or data.get("current_target") or "")
        urls = [str(item) for item in data.get("urls", []) if item]

        return cls(
            target=target or (urls[0] if urls else ""),
            phase=Phase(phase_value),
            mode=ScanMode(mode_value),
            available_tools=[str(item) for item in data.get("available_tools", []) if item],
            target_profile=data.get("target_profile"),
            findings=list(data.get("findings", [])),
            discovered_urls=[str(item) for item in data.get("discovered_urls", urls) if item],
            discovered_services=[
                str(item) for item in data.get("discovered_services", []) if item is not None
            ],
        )


@dataclass
class DecisionResult:
    """Full output from IntelligentDecisionEngine."""

    target: str
    target_type: str
    context_mode: ScanMode
    selected_tools: List[ToolRecommendation]
    excluded_tools: List[Dict[str, Any]] = field(default_factory=list)
    optimization_applied: List[str] = field(default_factory=list)
    decision_latency_ms: float = 0.0
    confidence: float = 0.0
    reasoning: str = ""

    def is_empty(self) -> bool:
        return not self.selected_tools

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "context_mode": self.context_mode.value,
            "selected_tools": [
                {
                    "tool_name": item.tool_name,
                    "effectiveness_score": item.effectiveness_score,
                    "parameters": list(item.parameters),
                    "reasoning": item.reasoning,
                    "phase": item.phase,
                    "priority": item.priority,
                }
                for item in self.selected_tools
            ],
            "excluded_tools": list(self.excluded_tools),
            "optimization_applied": list(self.optimization_applied),
            "decision_latency_ms": self.decision_latency_ms,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }


class EffectivenessRatings:
    """Tool effectiveness ratings with file-backed overrides."""

    DEFAULT_RATINGS: Dict[str, Dict[str, float]] = {
        "web_application": {
            "nuclei": 0.95,
            "gobuster": 0.90,
            "ffuf": 0.90,
            "sqlmap": 0.88,
            "nikto": 0.85,
            "xsstrike": 0.82,
            "katana": 0.80,
            "dirb": 0.75,
            "wapiti": 0.70,
        },
        "network_host": {
            "nmap": 0.97,
            "nmap-advanced": 0.95,
            "masscan": 0.92,
            "rustscan": 0.90,
            "amap": 0.80,
            "ping": 0.60,
        },
        "api_endpoint": {
            "nuclei": 0.90,
            "ffuf": 0.88,
            "sqlmap": 0.85,
            "swagger-analyzer": 0.85,
            "arjun": 0.80,
            "soapui": 0.75,
        },
        "wordpress": {
            "wpscan": 0.95,
            "nuclei-wordpress": 0.80,
            "droopescan": 0.75,
            "nikto": 0.70,
            "wpseku": 0.65,
        },
        "cloud_service": {
            "cloud_enum": 0.90,
            "nmap": 0.75,
            "awscli-checker": 0.70,
            "cloudmapper": 0.65,
        },
        "unknown": {
            "nmap": 0.80,
            "nuclei": 0.80,
            "katana": 0.72,
        },
    }
    RATING_SOURCES = ["historical", "community", "documentation", "expert"]
    _cache: Dict[str, Dict[str, float]] = {}
    _config_loaded = False

    @classmethod
    def _ensure_loaded(cls) -> None:
        if cls._config_loaded:
            return
        cls._config_loaded = True

        merged = {key: dict(value) for key, value in cls.DEFAULT_RATINGS.items()}
        if TOOL_EFFECTIVENESS_PATH.exists():
            try:
                with TOOL_EFFECTIVENESS_PATH.open("r", encoding="utf-8") as handle:
                    data = yaml.safe_load(handle) or {}
                effectiveness_map = data.get("effectiveness_map", {})
                for target_type, ratings in effectiveness_map.items():
                    current = merged.setdefault(str(target_type), {})
                    if isinstance(ratings, dict):
                        for tool, score in ratings.items():
                            current[str(tool)] = cls._clamp_score(score)
            except Exception as exc:
                logger.warning("Failed to load tool effectiveness config: %s", exc)

        cls._cache = merged

    @classmethod
    def get_for_type(cls, target_type: str) -> Dict[str, float]:
        cls._ensure_loaded()
        normalized = str(target_type or "unknown")
        ratings = cls._cache.get(normalized)
        if ratings is None:
            ratings = cls._cache.get("unknown") or cls.DEFAULT_RATINGS["unknown"]
        return dict(ratings)

    @classmethod
    def update_from_historical(
        cls,
        target_type: str,
        tool: str,
        success_rate: float,
        sample_size: int = 10,
    ) -> None:
        cls._ensure_loaded()
        normalized_type = str(target_type or "unknown")
        ratings = cls._cache.setdefault(normalized_type, {})
        current = cls._clamp_score(ratings.get(tool, 0.5))
        target = cls._clamp_score(success_rate)
        weight = min(max(sample_size, 1), 50) / 50.0
        ratings[tool] = (current * (1.0 - weight)) + (target * weight)

    @classmethod
    def clear_cache(cls) -> None:
        cls._cache = {}
        cls._config_loaded = False

    @staticmethod
    def _clamp_score(value: Any) -> float:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = 0.0
        return max(0.0, min(1.0, numeric))


class ParameterOptimizer:
    """Generate mode-aware and technology-aware parameters."""

    COMMON_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888]
    COMMON_API_PORTS = [80, 443, 8080, 8443, 3000, 5000]
    PARAMETER_TEMPLATES: Dict[str, Dict[str, str]] = {
        "nuclei": {
            "default": "-rl 50 -c 10 -timeout 10",
            "stealth": "-rl 10 -c 2 -timeout 30 -jitter",
            "aggressive": "-rl 200 -c 20 -timeout 5",
            "web_application": "-tags vulnerability,cms",
            "wordpress": "-tags wordpress,vulnerability",
            "api_endpoint": '-tags api,exposure -H "Content-Type: application/json"',
        },
        "nmap": {
            "default": "-sV -sC",
            "stealth": "-sS -T2 -Pn",
            "aggressive": "-sS -sV -sC -T5 -p-",
            "web_application": "-p 80,443,8080,8443",
            "network_host": "-O -p- -T4",
        },
        "nikto": {
            "default": "-Tuning 1,2,3",
            "stealth": "-Tuning 1 -maxtime 30m",
            "aggressive": "-Tuning 1,2,3,4,5,6,7,8,9,0 -maxtime 4h",
        },
        "ffuf": {
            "default": "-mc 200,204,301 -fc 404",
            "stealth": "-mc 200 -rate 10 -timeout 10",
            "aggressive": "-mc 200,204,301,400,401,403 -rate 200",
            "api_endpoint": '-mc 200,204,301,400,401,403 -H "Content-Type: application/json"',
        },
        "sqlmap": {
            "default": "--risk 2 --level 2 --batch",
            "stealth": "--risk 1 --level 1 --batch --delay 2",
            "aggressive": "--risk 3 --level 5 --batch --threads 10",
        },
        "wpscan": {
            "default": "--enumerate vp",
            "stealth": "--stealthy --enumerate vp",
            "aggressive": "--enumerate vp,vt,u --plugins-detection aggressive",
        },
        "masscan": {
            "default": "--rate 1000 -p1-10000",
            "stealth": "--rate 50 -p80,443,22,21",
            "aggressive": "--rate 10000 -p1-65535",
        },
    }

    @classmethod
    def optimize(cls, tool: str, context: DecisionContext) -> List[str]:
        params: List[str] = []
        profile = context.target_profile
        mode_key = context.mode.value
        target_type = _target_type_value(profile)
        technologies = _technology_names(profile)

        base_template = cls.PARAMETER_TEMPLATES.get(tool, {}).get("default")
        if base_template:
            params.extend(_tokenize_cli_arguments(base_template))

        mode_template = cls.PARAMETER_TEMPLATES.get(tool, {}).get(mode_key)
        if mode_template:
            params = _tokenize_cli_arguments(mode_template)

        type_template = cls.PARAMETER_TEMPLATES.get(tool, {}).get(target_type)
        if type_template:
            params.extend(_tokenize_cli_arguments(type_template))

        params.extend(cls._technology_overrides(tool, technologies, context.target))
        params.extend(cls._risk_adjustments(tool, profile, context.mode))
        return _normalize_cli_arguments(params)

    @classmethod
    def get_parameter_string(cls, tool: str, context: DecisionContext) -> str:
        return " ".join(cls.optimize(tool, context))

    @classmethod
    def _technology_overrides(cls, tool: str, technologies: set[str], target: str) -> List[str]:
        params: List[str] = []
        if "wordpress" in technologies:
            if tool == "wpscan":
                params.extend(["--url", target, "--enumerate", "vp"])
            elif tool == "nuclei":
                params.extend(["-tags", "wordpress,vulnerability"])
        if any(item in technologies for item in {"api", "graphql", "rest", "fastapi"}):
            if tool == "ffuf":
                params.extend(["-H", "Content-Type: application/json"])
            elif tool == "nuclei":
                params.extend(["-tags", "api,exposure"])
        if "nginx" in technologies and tool == "nikto":
            params.extend(["-Tuning", "1,2,3", "-_port", "80,443,8080"])
        if "apache" in technologies and tool == "nikto":
            params.extend(["-Tuning", "1,2,3", "-_port", "80,443"])
        if "mysql" in technologies and tool == "nmap":
            params.extend(["-p", "3306", "--script", "mysql-enum,mysql-info"])
        if "ssh" in technologies and tool == "nmap":
            params.extend(["-p", "22", "--script", "ssh2-enum-algos,sshv1"])
        return params

    @classmethod
    def _risk_adjustments(
        cls,
        tool: str,
        profile: Optional[TargetProfileProtocol],
        mode: ScanMode,
    ) -> List[str]:
        risk_level = _risk_level_value(profile)
        params: List[str] = []

        if tool in {"nuclei", "ffuf"}:
            if risk_level == RiskLevel.CRITICAL.value or mode == ScanMode.AGGRESSIVE:
                params.extend(["-rl", "200", "-c", "20", "-timeout", "3"])
            elif risk_level == RiskLevel.LOW.value or mode == ScanMode.STEALTH:
                params.extend(["-rl", "20", "-c", "5", "-timeout", "30"])
        if tool == "masscan":
            if mode == ScanMode.AGGRESSIVE:
                params.extend(["--rate", "10000"])
            elif mode == ScanMode.STEALTH:
                params.extend(["--rate", "50"])
        return params


class ContextAdapter:
    """Encapsulate mode and phase behavior for tool selection."""

    PHASE_PRIORITY: Dict[Phase, List[str]] = {
        Phase.RECON: ["nuclei", "nmap", "katana"],
        Phase.DISCOVERY: ["nmap", "masscan", "rustscan", "amap"],
        Phase.VULN_SCAN: ["nuclei", "sqlmap", "nikto", "wpscan"],
        Phase.VALIDATION: ["sqlmap", "nuclei"],
        Phase.REPORTING: [],
    }
    NOISY_TOOLS = {"masscan", "nikto"}
    STEALTH_PASSIVE_PREFERRED = {"nuclei", "katana", "nmap"}
    MODE_LIMITS = {
        ScanMode.STEALTH: 3,
        ScanMode.NORMAL: 5,
        ScanMode.AGGRESSIVE: 10,
    }

    @classmethod
    def phase_weight(cls, phase: Phase, tool: str) -> float:
        priority = cls.PHASE_PRIORITY.get(phase, [])
        if tool not in priority:
            return 0.0
        return (len(priority) - priority.index(tool)) / 100.0

    @classmethod
    def apply_mode_rules(
        cls, recommendations: List[ToolRecommendation], context: DecisionContext
    ) -> List[ToolRecommendation]:
        tools = recommendations
        if context.mode == ScanMode.STEALTH:
            tools = [item for item in tools if item.tool_name not in cls.NOISY_TOOLS]
            preferred = [item for item in tools if item.tool_name in cls.STEALTH_PASSIVE_PREFERRED]
            tools = preferred or tools

        limit = cls.MODE_LIMITS.get(context.mode, 5)
        return tools[:limit]

    @classmethod
    def technology_specific_activation(
        cls,
        ratings: Dict[str, float],
        technologies: Iterable[str],
        target_type: str,
    ) -> Dict[str, float]:
        boosted = dict(ratings)
        techs = {item.lower() for item in technologies}
        if "wordpress" in techs or target_type == "wordpress":
            boosted["wpscan"] = max(boosted.get("wpscan", 0.0), 0.95)
            boosted["nuclei-wordpress"] = max(boosted.get("nuclei-wordpress", 0.0), 0.80)
            if "droopescan" in boosted:
                boosted["droopescan"] = min(boosted["droopescan"], 0.70)
        if any(item in techs for item in {"api", "graphql", "rest", "openapi", "swagger"}):
            boosted["arjun"] = max(boosted.get("arjun", 0.0), 0.80)
            boosted["swagger-analyzer"] = max(boosted.get("swagger-analyzer", 0.0), 0.85)
            if "dirb" in boosted:
                boosted["dirb"] = min(boosted["dirb"], 0.50)
        return boosted


class IntelligentDecisionEngine:
    """Select and optimize tools based on profile context."""

    STEALTH_MIN_EFFECTIVENESS = 0.85
    NORMAL_MIN_EFFECTIVENESS = 0.70
    AGGRESSIVE_MIN_EFFECTIVENESS = 0.60

    def __init__(
        self,
        default_threshold: float = NORMAL_MIN_EFFECTIVENESS,
        stealth_threshold: float = STEALTH_MIN_EFFECTIVENESS,
        aggressive_threshold: float = AGGRESSIVE_MIN_EFFECTIVENESS,
        max_decision_latency_ms: float = 50.0,
    ):
        self.default_threshold = default_threshold
        self.stealth_threshold = stealth_threshold
        self.aggressive_threshold = aggressive_threshold
        self.max_decision_latency_ms = max_decision_latency_ms

    def select_tools(self, context: DecisionContext) -> DecisionResult:
        start = time.perf_counter()
        profile = context.target_profile
        if profile is None:
            result = self._fallback_decision(context)
            result.decision_latency_ms = (time.perf_counter() - start) * 1000
            return result

        technologies = _technology_names(profile)
        target_type = self._resolve_effectiveness_target_type(profile, technologies)
        ratings = EffectivenessRatings.get_for_type(target_type)
        if target_type == "wordpress":
            base_web_ratings = EffectivenessRatings.get_for_type(TargetType.WEB_APPLICATION.value)
            for tool, score in base_web_ratings.items():
                ratings.setdefault(tool, score)
        ratings = ContextAdapter.technology_specific_activation(ratings, technologies, target_type)
        threshold = self._threshold_for_context(context, profile)

        recommendations: List[ToolRecommendation] = []
        excluded_tools: List[Dict[str, Any]] = []
        optimizations: List[str] = []

        for tool, score in sorted(ratings.items(), key=lambda item: item[1], reverse=True):
            available = not context.available_tools or tool in context.available_tools
            if not available:
                excluded_tools.append({"tool": tool, "reason": "not available", "score": score})
                continue
            if score < threshold:
                excluded_tools.append(
                    {"tool": tool, "reason": f"below threshold {threshold:.2f}", "score": score}
                )
                continue
            if not self._is_tool_applicable(tool, context, technologies):
                excluded_tools.append({"tool": tool, "reason": "not applicable", "score": score})
                continue

            params = ParameterOptimizer.optimize(tool, context)
            if params:
                optimizations.append(f"{tool}:{' '.join(params)}")
            recommendation = ToolRecommendation(
                tool_name=tool,
                effectiveness_score=score,
                parameters=params,
                reasoning=self._build_reason(tool, score, target_type, technologies, context),
                phase=context.phase.value,
                priority=self._calculate_priority(tool, score, context, technologies),
            )
            recommendations.append(recommendation)

        recommendations.sort(
            key=lambda item: (item.priority, -item.effectiveness_score, item.tool_name)
        )
        recommendations = ContextAdapter.apply_mode_rules(recommendations, context)
        latency = (time.perf_counter() - start) * 1000
        if latency > self.max_decision_latency_ms:
            logger.warning(
                "Decision engine latency exceeded budget: %.2fms > %.2fms",
                latency,
                self.max_decision_latency_ms,
            )

        result = DecisionResult(
            target=context.target,
            target_type=target_type,
            context_mode=context.mode,
            selected_tools=recommendations,
            excluded_tools=excluded_tools,
            optimization_applied=optimizations,
            decision_latency_ms=latency,
            confidence=float(getattr(profile, "confidence", 0.0) or 0.0),
            reasoning=self._generate_reasoning(
                recommendations, excluded_tools, context, target_type
            ),
        )
        return result

    def _resolve_effectiveness_target_type(
        self, profile: TargetProfileProtocol, technologies: set[str]
    ) -> str:
        target_type = _target_type_value(profile)
        if "wordpress" in technologies:
            return "wordpress"
        return target_type

    def _threshold_for_context(
        self, context: DecisionContext, profile: TargetProfileProtocol
    ) -> float:
        confidence = float(getattr(profile, "confidence", 0.0) or 0.0)
        if context.mode == ScanMode.STEALTH:
            threshold = self.stealth_threshold
        elif context.mode == ScanMode.AGGRESSIVE:
            threshold = self.aggressive_threshold
        else:
            threshold = self.default_threshold
        if confidence < 0.3:
            threshold = max(threshold, self.default_threshold)
        return threshold

    def _is_tool_applicable(
        self, tool: str, context: DecisionContext, technologies: set[str]
    ) -> bool:
        target_type = _target_type_value(context.target_profile)
        if context.mode == ScanMode.STEALTH and tool in ContextAdapter.NOISY_TOOLS:
            return False
        if target_type == TargetType.NETWORK_HOST.value and tool in {"sqlmap", "gobuster", "dirb"}:
            return False
        if target_type == TargetType.API_ENDPOINT.value and tool in {"dirb", "nikto"}:
            return False
        if "wordpress" in technologies and tool == "droopescan":
            return False
        return True

    def _calculate_priority(
        self,
        tool: str,
        score: float,
        context: DecisionContext,
        technologies: set[str],
    ) -> int:
        boost = ContextAdapter.phase_weight(context.phase, tool)
        if "wordpress" in technologies and tool == "wpscan":
            boost += 0.10
        if self._has_critical_cves(context) and tool in {"nuclei", "sqlmap", "log4j-scan"}:
            boost += 0.08
        adjusted = min(1.0, score + boost)
        return max(1, int((1.0 - adjusted) * 100) + 1)

    def _has_critical_cves(self, context: DecisionContext) -> bool:
        for finding in context.findings:
            cvss = getattr(finding, "cvss", None)
            if cvss is not None and float(cvss) >= 9.0:
                return True
        return False

    def _fallback_decision(self, context: DecisionContext) -> DecisionResult:
        fallback_tools = [
            tool
            for tool in context.available_tools
            if tool in {"nmap", "nuclei", "nikto", "katana", "sqlmap", "ffuf"}
        ]
        selected = [
            ToolRecommendation(
                tool_name=tool,
                effectiveness_score=0.70,
                parameters=[],
                reasoning="Fallback selection without TargetProfile",
                phase=context.phase.value,
                priority=index + 1,
            )
            for index, tool in enumerate(fallback_tools)
        ]
        return DecisionResult(
            target=context.target,
            target_type="unknown",
            context_mode=context.mode,
            selected_tools=selected,
            excluded_tools=[],
            optimization_applied=[],
            confidence=0.0,
            reasoning="Fallback: target profile unavailable, using general-purpose tools.",
        )

    def _build_reason(
        self,
        tool: str,
        score: float,
        target_type: str,
        technologies: set[str],
        context: DecisionContext,
    ) -> str:
        notes = [f"effectiveness {score:.2f} for {target_type}"]
        if technologies:
            matching = [
                item
                for item in ("wordpress", "api", "nginx", "apache", "mysql")
                if item in technologies
            ]
            if matching:
                notes.append(f"tech-aware: {', '.join(matching)}")
        if context.mode == ScanMode.STEALTH:
            notes.append("stealth-compatible")
        return f"{tool}: {'; '.join(notes)}"

    def _generate_reasoning(
        self,
        recommendations: List[ToolRecommendation],
        excluded_tools: List[Dict[str, Any]],
        context: DecisionContext,
        target_type: str,
    ) -> str:
        selected = ", ".join(item.tool_name for item in recommendations) or "none"
        excluded = ", ".join(item["tool"] for item in excluded_tools[:5]) or "none"
        return (
            f"target_type={target_type} mode={context.mode.value} "
            f"selected=[{selected}] excluded=[{excluded}]"
        )


def _target_type_value(profile: Optional[TargetProfileProtocol]) -> str:
    if profile is None:
        return "unknown"
    value = getattr(profile, "target_type", "unknown")
    return str(getattr(value, "value", value) or "unknown")


def _risk_level_value(profile: Optional[TargetProfileProtocol]) -> str:
    if profile is None:
        return RiskLevel.INFORMATIONAL.value
    value = getattr(profile, "risk_level", RiskLevel.INFORMATIONAL.value)
    return str(getattr(value, "value", value) or RiskLevel.INFORMATIONAL.value)


def _technology_names(profile: Optional[TargetProfileProtocol]) -> set[str]:
    if profile is None:
        return set()
    names: set[str] = set()
    for technology in list(getattr(profile, "technologies", []) or []):
        name = getattr(technology, "name", technology)
        if name:
            names.add(str(name).lower())
    return names


def _tokenize_cli_arguments(value: str) -> List[str]:
    return shlex.split(value)


def _normalize_cli_arguments(values: List[str]) -> List[str]:
    grouped: List[tuple[Optional[str], ...]] = []
    index = 0

    while index < len(values):
        token = values[index]
        next_token = values[index + 1] if index + 1 < len(values) else None

        if token.startswith("-"):
            if next_token is not None and not next_token.startswith("-"):
                grouped.append((token, next_token))
                index += 2
                continue

            grouped.append((token,))
            index += 1
            continue

        grouped.append((None, token))
        index += 1

    seen_flags: set[str] = set()
    normalized_groups: List[tuple[Optional[str], ...]] = []

    for group in reversed(grouped):
        flag = group[0]
        if flag is None:
            normalized_groups.append(group)
            continue

        if flag in seen_flags:
            continue

        seen_flags.add(flag)
        normalized_groups.append(group)

    normalized_groups.reverse()

    result: List[str] = []
    for group in normalized_groups:
        if group[0] is None:
            result.append(group[1])
        else:
            result.extend(group)

    return result
