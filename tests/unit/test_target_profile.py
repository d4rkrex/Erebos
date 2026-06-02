"""Unit tests for TargetProfile and technology detection."""

from dataclasses import dataclass
from typing import Dict, Generator, List, Optional
from unittest.mock import patch

from erebos.core.finding import Phase
from erebos.core.phase_agent import ReconAgent
from erebos.core.target_profile import RiskLevel, TargetProfiler, TargetType, Technology
from erebos.detection.attack_surface import AttackSurfaceScorer
from erebos.detection.technology_detector import ContentPatternDetector, HttpHeaderDetector
from erebos.enrichment.http_probe import HttpProbeResult
from erebos.executors.base import ToolResult, Transport
from erebos.parsers.nmap import NmapParser, NmapScanResult, PortInfo
from erebos.storage.scan_state import ScanState
from erebos.core.orchestrator import Orchestrator
from erebos.core.scan_profile import get_profile


class DummyTransport(Transport):
    def execute(
        self,
        tool: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = 300,
    ) -> ToolResult:
        return ToolResult(tool=tool, exit_code=0, stdout="", stderr="", duration_seconds=0.0)

    def stream(
        self,
        tool: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
    ) -> Generator[str, None, None]:
        yield ""

    def available(self) -> bool:
        return True


class TestTechnologyDetectors:
    def test_http_header_detector_extracts_server_and_powered_by(self):
        detector = HttpHeaderDetector()
        result = detector.detect_from_http(
            HttpProbeResult(
                is_http=True,
                headers={"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1.2", "cf-ray": "abc"},
            )
        )

        names = {tech.name for tech in result}
        assert "nginx" in names
        assert "PHP" in names
        assert "Cloudflare" in names

    def test_content_pattern_detector_extracts_wordpress_and_react(self):
        detector = ContentPatternDetector()
        result = detector.detect_from_http(
            HttpProbeResult(
                is_http=True,
                body="<html><script>__REACT_DEVTOOLS_GLOBAL_HOOK__</script><img src='/wp-content/plugins/x.png'></html>",
            )
        )

        names = {tech.name for tech in result}
        assert "WordPress" in names
        assert "React" in names


class TestTargetProfiler:
    def test_profile_round_trip_serialization(self):
        profiler = TargetProfiler()
        profile = profiler.create_profile(
            "https://example.com/admin",
            NmapScanResult(
                ports=[
                    PortInfo(
                        port="443",
                        protocol="tcp",
                        state="open",
                        service="https",
                        product="nginx",
                        version="1.18.0",
                        cpe="cpe:/a:nginx:nginx:1.18.0",
                        host="93.184.216.34",
                        hostname="example.com",
                    )
                ]
            ),
            {
                (
                    "example.com",
                    443,
                ): HttpProbeResult(
                    is_http=True,
                    is_https=True,
                    headers={
                        "server": "nginx/1.18.0",
                        "strict-transport-security": "max-age=31536000",
                        "content-security-policy": "default-src 'self'",
                    },
                    content_type="text/html",
                    body="<html>hello</html>",
                )
            },
        )

        assert profile is not None

        restored = type(profile).from_dict(profile.to_dict())

        assert restored.target == "https://example.com/admin"
        assert restored.host == "example.com"
        assert restored.scheme == "https"
        assert restored.target_type == TargetType.WEB_APPLICATION

    def test_api_target_classification(self):
        profiler = TargetProfiler()
        profile = profiler.create_profile(
            "https://api.example.com/health",
            NmapScanResult(
                ports=[PortInfo(port="443", protocol="tcp", state="open", service="https")]
            ),
            {
                (
                    "api.example.com",
                    443,
                ): HttpProbeResult(
                    is_http=True,
                    is_https=True,
                    content_type="application/json",
                    body='{"status":"ok"}',
                )
            },
        )

        assert profile is not None

        assert profile.target_type == TargetType.API_ENDPOINT
        assert profile.target_type_confidence >= 0.7

    def test_ip_with_port_parsing(self):
        profiler = TargetProfiler()
        profile = profiler.create_profile(
            "http://192.168.1.1:8080",
            NmapScanResult(
                ports=[PortInfo(port="8080", protocol="tcp", state="open", service="http")]
            ),
            {
                ("192.168.1.1", 8080): HttpProbeResult(
                    is_http=True, content_type="text/html", body="<html></html>"
                )
            },
        )

        assert profile is not None
        assert profile.host == "192.168.1.1"
        assert profile.port == 8080
        assert profile.scheme == "http"

    def test_cloud_service_detection(self):
        profiler = TargetProfiler()
        profile = profiler.create_profile(
            "ec2-54-1-2-3.compute.amazonaws.com", NmapScanResult(), {}
        )

        assert profile is not None
        assert profile.target_type == TargetType.CLOUD_SERVICE
        assert profile.target_type_confidence >= 0.6

    def test_network_host_and_container_classification(self):
        profiler = TargetProfiler()
        network_profile = profiler.create_profile(
            "10.0.0.5",
            NmapScanResult(
                ports=[PortInfo(port="22", protocol="tcp", state="open", service="ssh")]
            ),
            {},
        )
        container_profile = profiler.create_profile(
            "10.0.0.6",
            NmapScanResult(
                ports=[PortInfo(port="2375", protocol="tcp", state="open", service="docker")]
            ),
            {},
        )

        assert network_profile is not None
        assert container_profile is not None
        assert network_profile.target_type == TargetType.NETWORK_HOST
        assert container_profile.target_type == TargetType.CONTAINER

    def test_service_model_parsing_from_nmap(self):
        profile = TargetProfiler().create_profile(
            "192.168.1.10",
            NmapScanResult(
                ports=[
                    PortInfo(
                        port="22",
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        product="OpenSSH",
                        version="8.2",
                        cpe="cpe:/a:openbsd:openssh:8.2",
                    )
                ]
            ),
            {},
        )

        assert profile is not None
        assert profile.services[0].port == 22
        assert profile.services[0].service == "ssh"
        assert profile.services[0].version == "8.2"
        assert profile.services[0].confidence >= 0.9

    def test_attack_surface_scoring_low_and_high(self):
        profiler = TargetProfiler()
        low_profile = profiler.create_profile(
            "https://example.com",
            NmapScanResult(
                ports=[
                    PortInfo(
                        port="443", protocol="tcp", state="open", service="https", product="nginx"
                    )
                ]
            ),
            {
                (
                    "example.com",
                    443,
                ): HttpProbeResult(
                    is_http=True,
                    is_https=True,
                    headers={
                        "strict-transport-security": "max-age=31536000",
                        "content-security-policy": "default-src 'self'",
                    },
                    content_type="text/html",
                    body="<html>ok</html>",
                )
            },
        )
        high_profile = profiler.create_profile(
            "http://93.184.216.34",
            NmapScanResult(
                ports=[
                    PortInfo(
                        port="22", protocol="tcp", state="open", service="ssh", host="93.184.216.34"
                    ),
                    PortInfo(
                        port="80",
                        protocol="tcp",
                        state="open",
                        service="http",
                        host="93.184.216.34",
                    ),
                    PortInfo(
                        port="443",
                        protocol="tcp",
                        state="open",
                        service="https",
                        host="93.184.216.34",
                    ),
                    PortInfo(
                        port="3306",
                        protocol="tcp",
                        state="open",
                        service="mysql",
                        cpe="cpe:/a:oracle:mysql:5.7",
                        host="93.184.216.34",
                    ),
                ]
            ),
            {
                (
                    "93.184.216.34",
                    80,
                ): HttpProbeResult(
                    is_http=True, content_type="text/html", body="<html>hello</html>"
                )
            },
        )

        assert low_profile is not None
        assert high_profile is not None

        assert low_profile.attack_surface_score <= 2.0
        assert high_profile.attack_surface_score >= 6.0
        assert high_profile.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}

    def test_confidence_uses_multiple_signals(self):
        profiler = TargetProfiler()
        profile = profiler.create_profile(
            "https://example.com",
            NmapScanResult(
                ports=[
                    PortInfo(
                        port="443",
                        protocol="tcp",
                        state="open",
                        service="https",
                        product="nginx",
                        version="1.18.0",
                        cpe="cpe:/a:nginx:nginx:1.18.0",
                        host="93.184.216.34",
                    )
                ]
            ),
            {
                (
                    "example.com",
                    443,
                ): HttpProbeResult(
                    is_http=True,
                    is_https=True,
                    headers={"server": "nginx/1.18.0"},
                    content_type="text/html",
                    body="<html></html>",
                )
            },
        )

        assert profile is not None

        assert profile.confidence >= 0.7

    def test_low_confidence_profile_without_signals(self):
        profile = TargetProfiler().create_profile("example.com", NmapScanResult(), {})

        assert profile is not None
        assert profile.confidence <= 0.3

    def test_incremental_update_recalculates_score_and_metadata(self):
        profiler = TargetProfiler()
        original = profiler.create_profile(
            "https://example.com",
            NmapScanResult(
                ports=[PortInfo(port="443", protocol="tcp", state="open", service="https")]
            ),
            {
                ("example.com", 443): HttpProbeResult(
                    is_http=True, is_https=True, content_type="text/html", body="<html></html>"
                )
            },
            completed_phases=["recon"],
        )

        assert original is not None
        updated = profiler.update_profile(
            original,
            NmapScanResult(
                ports=[
                    PortInfo(port="443", protocol="tcp", state="open", service="https"),
                    PortInfo(
                        port="3306",
                        protocol="tcp",
                        state="open",
                        service="mysql",
                        cpe="cpe:/a:oracle:mysql:5.7",
                    ),
                ]
            ),
            {
                ("example.com", 443): HttpProbeResult(
                    is_http=True, is_https=True, content_type="text/html", body="<html></html>"
                )
            },
            completed_phase="discovery",
        )

        assert updated.attack_surface_score >= original.attack_surface_score
        assert "discovery" in updated.metadata["scan_phases_completed"]
        assert updated.updated_at >= original.created_at

    def test_model_dump_json_round_trip(self):
        profile = TargetProfiler().create_profile(
            "https://example.com",
            NmapScanResult(
                ports=[PortInfo(port="443", protocol="tcp", state="open", service="https")]
            ),
            {
                ("example.com", 443): HttpProbeResult(
                    is_http=True, is_https=True, content_type="text/html", body="<html></html>"
                )
            },
        )

        assert profile is not None
        restored = type(profile).model_validate_json(profile.model_dump_json())
        assert restored.target == profile.target
        assert restored.target_type == profile.target_type

    def test_plugin_loading_via_entry_points(self, monkeypatch):
        from erebos.core.target_profile import Technology as PluginTechnology

        @dataclass
        class MockEntryPoint:
            name: str = "custom-detector"

            def load(self):
                class CustomDetector:
                    name = "custom-detector"

                    def detect_from_nmap(self, nmap_result):
                        return []

                    def detect_from_http(self, http_result):
                        return [
                            PluginTechnology(
                                name="CustomTech",
                                confidence=0.95,
                                source="plugin",
                                category="plugin",
                            )
                        ]

                return CustomDetector

        class MockEntryPoints:
            def select(self, **kwargs):
                if kwargs.get("group") == "erebos.technology_detectors":
                    return [MockEntryPoint()]
                return []

        monkeypatch.setattr(
            "erebos.core.target_profile.metadata.entry_points", lambda: MockEntryPoints()
        )

        profile = TargetProfiler().create_profile(
            "https://example.com",
            NmapScanResult(),
            {
                ("example.com", 443): HttpProbeResult(
                    is_http=True, content_type="text/html", body="<html></html>"
                )
            },
        )

        assert profile is not None
        assert any(technology.name == "CustomTech" for technology in profile.technologies)


class TestAttackSurfaceScorer:
    def test_classify_risk_thresholds(self):
        scorer = AttackSurfaceScorer()

        assert scorer.classify_risk(8.0) == RiskLevel.CRITICAL
        assert scorer.classify_risk(6.0) == RiskLevel.HIGH
        assert scorer.classify_risk(4.0) == RiskLevel.MEDIUM
        assert scorer.classify_risk(2.0) == RiskLevel.LOW
        assert scorer.classify_risk(1.0) == RiskLevel.INFORMATIONAL


class TestTargetProfileIntegration:
    def test_scan_state_round_trip_includes_target_profile(self):
        state = ScanState(scan_id="scan-1", target="example.com")
        state.target_profile = TargetProfiler().create_profile(
            "https://example.com",
            NmapScanResult(
                ports=[PortInfo(port="443", protocol="tcp", state="open", service="https")]
            ),
            {
                (
                    "example.com",
                    443,
                ): HttpProbeResult(
                    is_http=True, is_https=True, content_type="text/html", body="<html></html>"
                )
            },
        )

        restored = ScanState.from_dict(state.to_dict())

        assert restored.target_profile is not None
        assert restored.phase_artifacts["target_profile"]["target"] == "https://example.com"

    def test_recon_inference_persists_target_profile_to_scan_state(self, tmp_path):
        xml_path = tmp_path / "nmap.xml"
        xml_path.write_text(
            "<?xml version='1.0'?><nmaprun><host><address addr='93.184.216.34'/><ports><port protocol='tcp' portid='80'><state state='open'/><service name='http' product='nginx' version='1.18.0'><cpe>cpe:/a:nginx:nginx:1.18.0</cpe></service></port></ports></host></nmaprun>"
        )
        state = ScanState(scan_id="scan-1", target="example.com")
        agent = ReconAgent(
            DummyTransport(), {"nmap": NmapParser()}, scan_state=state, storage_dir=tmp_path
        )

        with (
            patch("erebos.enrichment.cve_service.CveService.lookup_cpe", return_value=[]),
            patch(
                "erebos.enrichment.exploit_db.ExploitDbService.get_exploits_for_cve",
                return_value=[],
            ),
            patch(
                "erebos.enrichment.http_probe.HttpProbeService.probe_batch",
                return_value={
                    (
                        "93.184.216.34",
                        80,
                    ): HttpProbeResult(
                        is_http=True,
                        headers={"server": "nginx/1.18.0"},
                        content_type="text/html",
                        body="<html><title>Example</title></html>",
                    )
                },
            ),
        ):
            agent._run_inference(
                "https://example.com",
                {"nmap_xml_path": str(xml_path), "enable_target_profile": True},
                [],
            )

        assert state.target_profile is not None
        assert (
            state.phase_artifacts["target_profile"]["target_type"]
            == TargetType.WEB_APPLICATION.value
        )
        assert state.phase_artifacts["profile_inference"]["evaluated"] is True
        assert state.phase_artifacts["profile_inference"]["decision_count"] == 0

    def test_recon_inference_stores_profile_inference_artifacts(self, tmp_path):
        xml_path = tmp_path / "nmap.xml"
        xml_path.write_text(
            "<?xml version='1.0'?><nmaprun><host><address addr='93.184.216.34'/><ports><port protocol='tcp' portid='80'><state state='open'/><service name='http' product='Apache' version='2.4.41'><cpe>cpe:/a:apache:http_server:2.4.41</cpe></service></port><port protocol='tcp' portid='3306'><state state='open'/><service name='mysql' product='MySQL' version='5.7'><cpe>cpe:/a:oracle:mysql:5.7</cpe></service></port></ports></host></nmaprun>"
        )
        state = ScanState(scan_id="scan-2", target="93.184.216.34")
        agent = ReconAgent(
            DummyTransport(), {"nmap": NmapParser()}, scan_state=state, storage_dir=tmp_path
        )

        with (
            patch("erebos.enrichment.cve_service.CveService.lookup_cpe", return_value=[]),
            patch(
                "erebos.enrichment.exploit_db.ExploitDbService.get_exploits_for_cve",
                return_value=[],
            ),
            patch(
                "erebos.enrichment.http_probe.HttpProbeService.probe_batch",
                return_value={
                    ("93.184.216.34", 80): HttpProbeResult(
                        is_http=True,
                        headers={"server": "Apache/2.4.41"},
                        content_type="text/html",
                        body="<html><img src='/wp-content/plugins/demo.png'></html>",
                    )
                },
            ),
        ):
            agent._run_inference(
                "http://93.184.216.34",
                {"nmap_xml_path": str(xml_path), "enable_target_profile": True},
                [],
            )

        assert state.phase_artifacts["profile_inference"]["high_risk"] is True
        assert "cms" in state.phase_artifacts["profile_inference"]["nuclei_tags"]
        assert any(finding.tool == "target-profile" for finding in agent.findings)


class TestTargetProfileOrchestration:
    def test_orchestrator_context_includes_profile_inference_tags(self, tmp_path):
        profile = get_profile("standard")
        orchestrator = Orchestrator(
            target="example.com",
            profile=profile,
            transport=DummyTransport(),
            parsers={},
            storage_dir=tmp_path,
            scan_id="scan-ctx",
        )
        assert orchestrator.current_scan_state is not None
        orchestrator.current_scan_state.phase_artifacts["profile_inference"] = {
            "nuclei_tags": ["cms", "wordpress"],
            "high_risk": True,
        }

        context = orchestrator._build_phase_context(Phase.VULN_SCAN)

        assert context["nuclei_tags"] == ["cms", "wordpress"]
        assert context["profile_high_risk"] is True
