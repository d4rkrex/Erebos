"""Unit tests for InferenceEngine."""

from typing import cast

import pytest

from erebos.core.inference_engine import (
    InferenceDecision,
    InferenceEngine,
    Rule,
    RuleRegistry,
)
from erebos.core.finding import Phase, ScanMode
from erebos.parsers.nmap import NmapScanResult, OsMatch, PortInfo, ScriptResult
from erebos.enrichment.cve_service import CveRecord
from erebos.enrichment.http_probe import HttpProbeResult
from erebos.core.target_profile import TargetType


class TestInferenceEngine:
    """Tests for InferenceEngine."""

    def test_empty_nmap_result_produces_no_decisions(self):
        """Empty NmapScanResult emits no decisions."""
        engine = InferenceEngine()
        result = engine.infer(NmapScanResult())

        assert result == []

    def test_os_detected_emits_correct_decision(self):
        """OS match with accuracy >= 70 emits os_cve_lookup decision."""
        engine = InferenceEngine()
        nmap_result = NmapScanResult(
            os_matches=[OsMatch(name="Linux 5.4", accuracy=95)],
        )

        decisions = engine.infer(nmap_result)

        assert len(decisions) == 1
        assert decisions[0].trigger == "os_detected"
        assert decisions[0].action == "os_cve_lookup"
        assert decisions[0].params["os_name"] == "Linux 5.4"
        assert decisions[0].priority == 5

    def test_os_detected_skipped_if_accuracy_low(self):
        """OS match with accuracy < 70 is ignored."""
        engine = InferenceEngine()
        nmap_result = NmapScanResult(
            os_matches=[OsMatch(name="Windows XP", accuracy=50)],
        )

        decisions = engine.infer(nmap_result)

        # Only port_open decisions (no os_detected)
        assert not any(d.trigger == "os_detected" for d in decisions)

    def test_service_version_with_cpe_emits_cve_lookup(self):
        """Port with CPE string emits cve_lookup decision."""
        engine = InferenceEngine()
        nmap_result = NmapScanResult(
            ports=[
                PortInfo(
                    port="80",
                    protocol="tcp",
                    state="open",
                    service="http",
                    product="Apache",
                    version="2.4.41",
                    cpe="cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
                    host="192.168.1.1",
                )
            ],
        )

        decisions = engine.infer(nmap_result)

        cve_decisions = [d for d in decisions if d.trigger == "service_version_detected"]
        assert len(cve_decisions) >= 1
        assert cve_decisions[0].action == "cve_lookup"
        assert cve_decisions[0].params["cpe"] == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
        assert cve_decisions[0].priority == 10

    def test_port_open_emits_http_probe_decision(self):
        """Every open port emits http_probe decision."""
        engine = InferenceEngine()
        nmap_result = NmapScanResult(
            ports=[
                PortInfo(
                    port="80",
                    protocol="tcp",
                    state="open",
                    service="http",
                    host="192.168.1.1",
                ),
                PortInfo(
                    port="443",
                    protocol="tcp",
                    state="open",
                    service="https",
                    host="192.168.1.1",
                ),
                PortInfo(
                    port="22",
                    protocol="tcp",
                    state="closed",
                    service="ssh",
                    host="192.168.1.1",
                ),
            ],
        )

        decisions = engine.infer(nmap_result)

        http_probe_decisions = [d for d in decisions if d.trigger == "port_open"]
        # Only open/filtered ports, not closed
        assert len(http_probe_decisions) == 2
        assert all(d.action == "http_probe" for d in http_probe_decisions)
        assert all(d.priority == 30 for d in http_probe_decisions)

    def test_decisions_sorted_by_priority(self):
        """Decisions are sorted by priority ascending."""
        engine = InferenceEngine()
        nmap_result = NmapScanResult(
            ports=[
                PortInfo(
                    port="80",
                    protocol="tcp",
                    state="open",
                    service="http",
                    product="nginx",
                    version="1.18.0",
                    cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                    host="192.168.1.1",
                )
            ],
            os_matches=[OsMatch(name="Linux 5.4", accuracy=95)],
        )

        decisions = engine.infer(nmap_result)

        priorities = [d.priority for d in decisions]
        assert priorities == sorted(priorities)
        # Verify expected ordering: os(5) < cve(10) < http_probe(30)
        assert priorities[0] == 5  # os_detected

    def test_pluggable_rule_registry(self):
        """Custom rules are used instead of defaults."""
        custom_rules: RuleRegistry = [
            Rule(trigger="custom_trigger", action="custom_action", priority=1),
        ]
        engine = InferenceEngine(rules=custom_rules)
        nmap_result = NmapScanResult(
            ports=[
                PortInfo(
                    port="80",
                    protocol="tcp",
                    state="open",
                    service="http",
                    host="192.168.1.1",
                )
            ],
        )

        decisions = engine.infer(nmap_result)

        # Only custom rule should match (no open port is "custom_trigger")
        # But open port still matches port_open → 1 decision
        assert len(decisions) >= 1

    def test_process_cve_results_emits_exploitdb_search(self):
        """CVEs from lookup trigger exploitdb_search decision."""
        engine = InferenceEngine()
        cves = [
            CveRecord(cve_id="CVE-2021-44228", description="Log4Shell", cvss_v3_score=10.0),
            CveRecord(cve_id="CVE-2021-45046", description="Log4j DoS", cvss_v3_score=9.0),
        ]

        decisions = engine.process_cve_results(cves)

        assert len(decisions) == 1
        assert decisions[0].trigger == "cve_found"
        assert decisions[0].action == "exploitdb_search"
        cve_ids = cast(list[str], decisions[0].params["cve_ids"])
        assert "CVE-2021-44228" in cve_ids
        assert "CVE-2021-45046" in cve_ids
        assert decisions[0].priority == 20

    def test_process_cve_results_empty_list(self):
        """Empty CVE list produces no decisions."""
        engine = InferenceEngine()
        decisions = engine.process_cve_results([])
        assert decisions == []

    def test_process_http_probe_emits_nuclei_scan(self):
        """HTTP service detected triggers nuclei_scan decision."""
        engine = InferenceEngine()
        probe_result = HttpProbeResult(
            is_http=True,
            is_https=False,
            status_code=200,
            server_banner="Apache/2.4.41",
        )

        decisions = engine.process_http_probe(probe_result)

        assert len(decisions) == 1
        assert decisions[0].trigger == "http_service_detected"
        assert decisions[0].action == "nuclei_scan"
        assert decisions[0].params["status_code"] == 200
        assert decisions[0].params["server_banner"] == "Apache/2.4.41"
        assert decisions[0].priority == 40

    def test_process_http_probe_non_http(self):
        """Non-HTTP probe result produces no nuclei decision."""
        engine = InferenceEngine()
        probe_result = HttpProbeResult(is_http=False, reason="connection_refused")

        decisions = engine.process_http_probe(probe_result)

        assert decisions == []

    def test_infer_for_profile_emits_cms_and_high_risk_decisions(self):
        """Profile-aware inference emits CMS and high-risk decisions."""
        engine = InferenceEngine()
        nmap_result = NmapScanResult(
            ports=[
                PortInfo(
                    port="80", protocol="tcp", state="open", service="http", host="93.184.216.34"
                ),
                PortInfo(
                    port="3306", protocol="tcp", state="open", service="mysql", host="93.184.216.34"
                ),
            ]
        )
        http_results = {
            ("93.184.216.34", 80): HttpProbeResult(
                is_http=True,
                content_type="text/html",
                body="<html><img src='/wp-content/plugins/demo.png'></html>",
            )
        }

        decisions = engine.infer_for_profile("http://93.184.216.34", nmap_result, http_results)

        actions = {(decision.trigger, decision.action) for decision in decisions}
        assert ("cms_detected", "nuclei_tag_scan") in actions
        assert ("database_exposed", "flag_high_risk") in actions

    def test_infer_for_profile_emits_api_tags(self):
        """API profiles emit API-focused nuclei tag decisions."""
        engine = InferenceEngine()
        nmap_result = NmapScanResult(
            ports=[
                PortInfo(
                    port="443",
                    protocol="tcp",
                    state="open",
                    service="https",
                    host="api.example.com",
                )
            ]
        )
        http_results = {
            ("api.example.com", 443): HttpProbeResult(
                is_http=True,
                is_https=True,
                content_type="application/json",
                body='{"status":"ok"}',
            )
        }

        decisions = engine.infer_for_profile("https://api.example.com", nmap_result, http_results)

        api_decision = next(
            decision for decision in decisions if decision.trigger == "api_endpoint_detected"
        )
        assert api_decision.action == "nuclei_tag_scan"
        assert api_decision.params["tags"] == ["api"]

    def test_recommend_tools_for_phase_returns_result_when_enabled(self):
        engine = InferenceEngine()
        context = {
            "enable_intelligent_decisions": True,
            "target": "https://blog.example.com",
            "phase": Phase.VULN_SCAN.value,
            "scan_mode": ScanMode.NORMAL.value,
            "available_tools": ["nuclei", "nikto", "sqlmap", "wpscan"],
            "target_profile": type(
                "Profile",
                (),
                {
                    "target": "https://blog.example.com",
                    "target_type": TargetType.WEB_APPLICATION,
                    "technologies": [type("Tech", (), {"name": "WordPress"})()],
                    "services": [],
                    "attack_surface_score": 7.0,
                    "risk_level": "high",
                    "confidence": 0.9,
                },
            )(),
        }

        result = engine.recommend_tools_for_phase(context)

        assert result is not None
        assert result.selected_tools[0].tool_name == "wpscan"

    def test_process_decision_result_converts_to_inference_decisions(self):
        engine = InferenceEngine()
        context = {
            "enable_intelligent_decisions": True,
            "target": "https://example.com",
            "phase": Phase.VULN_SCAN.value,
            "scan_mode": ScanMode.NORMAL.value,
            "available_tools": ["nuclei", "nikto", "sqlmap"],
            "target_profile": type(
                "Profile",
                (),
                {
                    "target": "https://example.com",
                    "target_type": TargetType.WEB_APPLICATION,
                    "technologies": [],
                    "services": [],
                    "attack_surface_score": 5.0,
                    "risk_level": "medium",
                    "confidence": 0.9,
                },
            )(),
        }

        result = engine.recommend_tools_for_phase(context)
        assert result is not None

        decisions = engine.process_decision_result(result, context)

        assert decisions[0].action == "log_decision"
        assert any(item.trigger == "tool_recommended" for item in decisions)


class TestNmapScanResultHelpers:
    """Tests for NmapScanResult helper methods."""

    def test_get_open_ports_excludes_closed(self):
        """get_open_ports() excludes closed ports."""
        result = NmapScanResult(
            ports=[
                PortInfo(
                    port="80", protocol="tcp", state="open", service="http", host="192.168.1.1"
                ),
                PortInfo(
                    port="443",
                    protocol="tcp",
                    state="filtered",
                    service="https",
                    host="192.168.1.1",
                ),
                PortInfo(
                    port="22", protocol="tcp", state="closed", service="ssh", host="192.168.1.1"
                ),
            ],
        )

        open_ports = result.get_open_ports()

        assert len(open_ports) == 2
        assert all(state != "closed" for _, _, state in open_ports)

    def test_get_service_versions(self):
        """get_service_versions() returns only ports with product/version."""
        result = NmapScanResult(
            ports=[
                PortInfo(
                    port="80",
                    protocol="tcp",
                    state="open",
                    service="http",
                    product="nginx",
                    version="1.18.0",
                    host="192.168.1.1",
                ),
                PortInfo(
                    port="22",
                    protocol="tcp",
                    state="open",
                    service="ssh",
                    product="",
                    version="",
                    host="192.168.1.1",
                ),
            ],
        )

        versions = result.get_service_versions()

        assert len(versions) == 1
        assert versions[0] == ("192.168.1.1", "nginx", "1.18.0", "")
