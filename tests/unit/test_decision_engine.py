"""Unit tests for IntelligentDecisionEngine."""

from dataclasses import dataclass, field
import time

from erebos.core.decision_engine import (
    ContextAdapter,
    DecisionContext,
    EffectivenessRatings,
    IntelligentDecisionEngine,
    ParameterOptimizer,
)
from erebos.core.finding import Finding, Phase, ScanMode, Severity
from erebos.core.target_profile import RiskLevel, TargetType


@dataclass
class MockTechnology:
    name: str


@dataclass
class MockProfile:
    target: str = "https://example.com"
    target_type: TargetType = TargetType.WEB_APPLICATION
    technologies: list = field(default_factory=list)
    services: list = field(default_factory=list)
    attack_surface_score: float = 5.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    confidence: float = 0.8


class TestEffectivenessRatings:
    def teardown_method(self):
        EffectivenessRatings.clear_cache()

    def test_get_for_type_returns_expected_map(self):
        ratings = EffectivenessRatings.get_for_type("web_application")

        assert ratings["nuclei"] == 0.95
        assert ratings["sqlmap"] == 0.88

    def test_update_from_historical_is_weighted(self):
        EffectivenessRatings.clear_cache()
        before = EffectivenessRatings.get_for_type("web_application")["nikto"]

        EffectivenessRatings.update_from_historical("web_application", "nikto", 1.0, sample_size=50)

        after = EffectivenessRatings.get_for_type("web_application")["nikto"]
        assert after > before


class TestParameterOptimizer:
    def test_wordpress_parameters_include_specific_overrides(self):
        context = DecisionContext(
            target="https://blog.example.com",
            target_profile=MockProfile(
                technologies=[MockTechnology("WordPress")],
                risk_level=RiskLevel.HIGH,
            ),
            phase=Phase.VULN_SCAN,
            mode=ScanMode.NORMAL,
            available_tools=["wpscan", "nuclei"],
        )

        params = ParameterOptimizer.optimize("wpscan", context)

        assert "--url" in params
        assert "--enumerate" in params

    def test_stealth_nuclei_parameters_are_conservative(self):
        context = DecisionContext(
            target="https://example.com",
            target_profile=MockProfile(risk_level=RiskLevel.LOW),
            phase=Phase.VULN_SCAN,
            mode=ScanMode.STEALTH,
            available_tools=["nuclei"],
        )

        params = ParameterOptimizer.optimize("nuclei", context)

        assert "-rl" in params
        assert "20" in params or "10" in params
        assert "30" in params

    def test_nuclei_parameters_preserve_flag_value_pairs(self):
        context = DecisionContext(
            target="https://example.com",
            target_profile=MockProfile(target_type=TargetType.WEB_APPLICATION),
            phase=Phase.VULN_SCAN,
            mode=ScanMode.NORMAL,
            available_tools=["nuclei"],
        )

        params = ParameterOptimizer.optimize("nuclei", context)

        assert params == ["-rl", "50", "-c", "10", "-timeout", "10", "-tags", "vulnerability,cms"]

    def test_api_parameters_keep_quoted_header_value_together(self):
        context = DecisionContext(
            target="https://api.example.com",
            target_profile=MockProfile(
                target_type=TargetType.API_ENDPOINT,
                technologies=[MockTechnology("API")],
            ),
            phase=Phase.VULN_SCAN,
            mode=ScanMode.NORMAL,
            available_tools=["nuclei"],
        )

        params = ParameterOptimizer.optimize("nuclei", context)

        assert params.count("-H") == 1
        assert "Content-Type: application/json" in params


class TestDecisionEngine:
    def test_wordpress_selection_prioritizes_wordpress_tools(self):
        engine = IntelligentDecisionEngine()
        context = DecisionContext(
            target="https://blog.example.com",
            target_profile=MockProfile(technologies=[MockTechnology("WordPress")]),
            phase=Phase.VULN_SCAN,
            mode=ScanMode.NORMAL,
            available_tools=["nuclei", "wpscan", "nikto", "sqlmap"],
        )

        result = engine.select_tools(context)

        assert result.selected_tools[0].tool_name == "wpscan"
        assert any(
            item.tool_name == "nuclei-wordpress" or item.tool_name == "nuclei"
            for item in result.selected_tools
        )

    def test_stealth_mode_skips_noisy_tools(self):
        engine = IntelligentDecisionEngine()
        context = DecisionContext(
            target="https://example.com",
            target_profile=MockProfile(),
            phase=Phase.RECON,
            mode=ScanMode.STEALTH,
            available_tools=["nuclei", "nikto", "masscan", "gobuster"],
        )

        result = engine.select_tools(context)
        selected_tools = [item.tool_name for item in result.selected_tools]

        assert "nikto" not in selected_tools
        assert "masscan" not in selected_tools

    def test_aggressive_network_mode_selects_multiple_network_tools(self):
        engine = IntelligentDecisionEngine()
        context = DecisionContext(
            target="10.0.0.0/24",
            target_profile=MockProfile(target_type=TargetType.NETWORK_HOST),
            phase=Phase.DISCOVERY,
            mode=ScanMode.AGGRESSIVE,
            available_tools=["nmap", "nmap-advanced", "masscan", "rustscan", "ping"],
        )

        result = engine.select_tools(context)
        selected_tools = [item.tool_name for item in result.selected_tools]

        assert "masscan" in selected_tools
        assert "rustscan" in selected_tools
        assert "nmap-advanced" in selected_tools

    def test_missing_profile_falls_back_safely(self):
        engine = IntelligentDecisionEngine()
        context = DecisionContext(
            target="https://example.com",
            target_profile=None,
            phase=Phase.RECON,
            mode=ScanMode.NORMAL,
            available_tools=["nmap", "nuclei"],
        )

        result = engine.select_tools(context)

        assert not result.is_empty()
        assert "Fallback" in result.reasoning

    def test_decision_latency_is_under_budget(self):
        engine = IntelligentDecisionEngine(max_decision_latency_ms=50.0)
        context = DecisionContext(
            target="https://example.com",
            target_profile=MockProfile(),
            phase=Phase.RECON,
            mode=ScanMode.NORMAL,
            available_tools=["nuclei", "gobuster", "ffuf", "sqlmap", "nikto"],
        )

        started = time.perf_counter()
        result = engine.select_tools(context)
        elapsed_ms = (time.perf_counter() - started) * 1000

        assert result.decision_latency_ms < 50.0
        assert elapsed_ms < 50.0

    def test_critical_cve_boosts_exploitation_capable_tools(self):
        engine = IntelligentDecisionEngine()
        context = DecisionContext(
            target="https://example.com",
            target_profile=MockProfile(),
            phase=Phase.VULN_SCAN,
            mode=ScanMode.NORMAL,
            available_tools=["nuclei", "sqlmap", "nikto"],
            findings=[
                Finding(
                    tool="nuclei",
                    severity=Severity.CRITICAL,
                    title="Critical issue",
                    description="Test",
                    phase_found=Phase.RECON,
                    cvss=10.0,
                )
            ],
        )

        result = engine.select_tools(context)

        assert result.selected_tools[0].tool_name in {"nuclei", "sqlmap"}


class TestContextAdapter:
    def test_wordpress_activation_boosts_wordpress_tools(self):
        boosted = ContextAdapter.technology_specific_activation(
            {"nuclei": 0.9}, ["wordpress"], "web_application"
        )

        assert boosted["wpscan"] == 0.95
        assert boosted["nuclei-wordpress"] == 0.80
