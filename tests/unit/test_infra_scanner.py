"""Unit tests for infrastructure scanner module.

Tests network template parsing, service matching, CVE enrichment,
and the full scan pipeline.
"""

import asyncio
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from erebos.scanners.cve_enricher import CVEEnricher, CVEInfo, KNOWN_CVES
from erebos.scanners.infra_scanner import (
    InfraScanner,
    NetworkProbeExecutor,
    ProbeResult,
)
from erebos.scanners.network_template import (
    NetworkInput,
    NetworkMatcher,
    NetworkTemplate,
    NetworkTemplateParser,
)
from erebos.scanners.service_matcher import ServiceInfo, ServiceMatcher


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_tcp_template_yaml() -> str:
    """Sample nuclei TCP network template YAML."""
    return """
id: CVE-2014-1843
info:
  name: Titan FTP Server < 10.40 - Traversal
  severity: medium
  description: Titan FTP directory traversal vulnerability.
  classification:
    cve-id: CVE-2014-1843
  tags: cve,cve2014,network,ftp,titan-ftp,tcp
tcp:
  - inputs:
      - data: "00000000"
        type: hex
    host:
      - "{{Hostname}}"
    port: 21
    read-size: 1024
    matchers:
      - type: word
        words:
          - "Titan FTP"
"""


@pytest.fixture
def sample_rdp_template_yaml() -> str:
    """Sample RDP detection template."""
    return """
id: rdp-detection
info:
  name: Windows Remote Desktop Protocol - Detect
  severity: info
  tags: network,windows,rdp,detect,detection,tcp
tcp:
  - inputs:
      - data: "0300002a25e00000000000"
        type: hex
    host:
      - "{{Hostname}}"
    port: 3389
    read-size: 2048
    matchers:
      - type: word
        encoding: hex
        words:
          - "030000130ed"
"""


@pytest.fixture
def sample_redis_template_yaml() -> str:
    """Sample Redis detection template."""
    return """
id: redis-unauth
info:
  name: Redis Unauthorized Access
  severity: high
  tags: network,redis,unauth,tcp
tcp:
  - inputs:
      - data: "PING\\r\\n"
        type: text
    host:
      - "{{Hostname}}"
    port: 6379
    read-size: 512
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "+PONG"
      - type: word
        words:
          - "redis"
        negative: true
"""


@pytest.fixture
def ftp_service() -> ServiceInfo:
    return ServiceInfo(
        host="192.168.1.100",
        port=21,
        protocol="tcp",
        service="ftp",
        product="Titan FTP",
        version="10.30",
    )


@pytest.fixture
def redis_service() -> ServiceInfo:
    return ServiceInfo(
        host="10.0.0.5",
        port=6379,
        protocol="tcp",
        service="redis",
        product="Redis",
        version="5.0.7",
    )


@pytest.fixture
def ssh_service() -> ServiceInfo:
    return ServiceInfo(
        host="10.0.0.1",
        port=22,
        protocol="tcp",
        service="ssh",
        product="OpenSSH",
        version="7.9p1",
    )


@pytest.fixture
def parser() -> NetworkTemplateParser:
    return NetworkTemplateParser()


@pytest.fixture
def matcher() -> ServiceMatcher:
    return ServiceMatcher()


@pytest.fixture
def enricher() -> CVEEnricher:
    return CVEEnricher()


# ---------------------------------------------------------------------------
# Network Template YAML Parsing
# ---------------------------------------------------------------------------


class TestNetworkTemplateParser:
    """Test nuclei network template YAML parsing."""

    def test_parse_tcp_template(self, parser: NetworkTemplateParser, sample_tcp_template_yaml: str):
        """Test parsing a standard TCP network template."""
        template = parser.parse_yaml_content(sample_tcp_template_yaml)
        assert template is not None
        assert template.id == "CVE-2014-1843"
        assert template.name == "Titan FTP Server < 10.40 - Traversal"
        assert template.severity == "medium"
        assert template.protocol == "tcp"
        assert template.port == 21
        assert template.cve_id == "CVE-2014-1843"
        assert "ftp" in template.tags
        assert len(template.inputs) == 1
        assert template.inputs[0].type == "hex"
        assert template.inputs[0].data == "00000000"
        assert len(template.matchers) == 1
        assert template.matchers[0].type == "word"
        assert "Titan FTP" in template.matchers[0].words

    def test_parse_rdp_template(self, parser: NetworkTemplateParser, sample_rdp_template_yaml: str):
        """Test parsing RDP template with hex encoding matcher."""
        template = parser.parse_yaml_content(sample_rdp_template_yaml)
        assert template is not None
        assert template.id == "rdp-detection"
        assert template.port == 3389
        assert template.matchers[0].encoding == "hex"

    def test_parse_matchers_condition(self, parser: NetworkTemplateParser, sample_redis_template_yaml: str):
        """Test parsing template with matchers-condition: and."""
        template = parser.parse_yaml_content(sample_redis_template_yaml)
        assert template is not None
        assert template.matchers_condition == "and"
        assert len(template.matchers) == 2
        # Second matcher is negative
        assert template.matchers[1].negative is True

    def test_parse_non_network_template(self, parser: NetworkTemplateParser):
        """Test that HTTP-only templates return None."""
        http_template = """
id: some-http-vuln
info:
  name: Some HTTP Vulnerability
  severity: high
  tags: http,vuln
http:
  - method: GET
    path:
      - "/admin"
"""
        result = parser.parse_yaml_content(http_template)
        assert result is None

    def test_parse_invalid_yaml(self, parser: NetworkTemplateParser):
        """Test graceful handling of invalid YAML."""
        result = parser.parse_yaml_content("not: valid: yaml: {{{{")
        assert result is None

    def test_infer_service_from_tags(self, parser: NetworkTemplateParser, sample_tcp_template_yaml: str):
        """Test service inference from template tags."""
        template = parser.parse_yaml_content(sample_tcp_template_yaml)
        assert template is not None
        assert template.target_service == "ftp"

    def test_infer_service_from_port(self, parser: NetworkTemplateParser):
        """Test service inference from port when no matching tags."""
        yaml_content = """
id: test-template
info:
  name: Test
  severity: info
  tags: network,tcp,custom
tcp:
  - inputs:
      - data: "test"
    port: 3306
    read-size: 256
    matchers:
      - type: word
        words:
          - "mysql"
"""
        template = parser.parse_yaml_content(yaml_content)
        assert template is not None
        assert template.target_service == "mysql"

    def test_inj02_reject_forbidden_scheme(self, parser: NetworkTemplateParser):
        """VT-Spec INJ-02: Reject templates with file:// schemes in inputs."""
        yaml_content = """
id: malicious-template
info:
  name: Malicious
  severity: high
  tags: network,tcp
tcp:
  - inputs:
      - data: "file:///etc/passwd"
        type: text
    port: 80
    read-size: 1024
    matchers:
      - type: word
        words:
          - "root"
"""
        template = parser.parse_yaml_content(yaml_content)
        # Template should either be None or have the input rejected
        if template is not None:
            # If template parsed, the inputs should be empty (rejected)
            assert len(template.inputs) == 0

    def test_inj02_reject_shell_chars_in_id(self, parser: NetworkTemplateParser):
        """VT-Spec INJ-02: Reject template IDs with shell metacharacters."""
        yaml_content = """
id: "test;rm -rf /"
info:
  name: Malicious ID
  severity: high
  tags: network,tcp
tcp:
  - inputs:
      - data: "test"
    port: 80
    read-size: 256
    matchers:
      - type: word
        words:
          - "ok"
"""
        template = parser.parse_yaml_content(yaml_content)
        assert template is None

    def test_dos01_cap_inputs(self, parser: NetworkTemplateParser):
        """VT-Spec DOS-01: Cap max inputs per template to 50."""
        # Generate template with 100 inputs
        inputs_yaml = "\n".join([f'      - data: "input{i}"' for i in range(100)])
        yaml_content = f"""
id: many-inputs
info:
  name: Many Inputs
  severity: info
  tags: network,tcp
tcp:
  - inputs:
{inputs_yaml}
    port: 80
    read-size: 256
    matchers:
      - type: word
        words:
          - "ok"
"""
        template = parser.parse_yaml_content(yaml_content)
        assert template is not None
        assert len(template.inputs) <= 50

    def test_load_directory(self, parser: NetworkTemplateParser, tmp_path: Path):
        """Test loading templates from a directory."""
        # Create test templates
        (tmp_path / "test1.yaml").write_text("""
id: test1
info:
  name: Test 1
  severity: info
  tags: network,tcp
tcp:
  - inputs:
      - data: "hello"
    port: 80
    read-size: 256
    matchers:
      - type: word
        words:
          - "world"
""")
        (tmp_path / "test2.yaml").write_text("""
id: test2
info:
  name: Test 2
  severity: high
  tags: network,tcp,ssh
tcp:
  - inputs:
      - data: "SSH-2.0-test"
    port: 22
    read-size: 256
    matchers:
      - type: word
        words:
          - "SSH"
""")
        templates = parser.load_directory(tmp_path)
        assert len(templates) == 2
        ids = {t.id for t in templates}
        assert "test1" in ids
        assert "test2" in ids


# ---------------------------------------------------------------------------
# Service Matcher
# ---------------------------------------------------------------------------


class TestServiceMatcher:
    """Test matching templates to detected services."""

    def test_port_based_matching(self, matcher: ServiceMatcher, ftp_service: ServiceInfo):
        """Test matching by port number."""
        template = NetworkTemplate(
            id="ftp-test", name="FTP Test", port=21, protocol="tcp"
        )
        matches = matcher.match([template], [ftp_service])
        assert len(matches) == 1
        assert matches[0] == (template, ftp_service)

    def test_no_match_wrong_port(self, matcher: ServiceMatcher, ftp_service: ServiceInfo):
        """Test no match when port differs."""
        template = NetworkTemplate(
            id="ssh-test", name="SSH Test", port=22, protocol="tcp"
        )
        matches = matcher.match([template], [ftp_service])
        assert len(matches) == 0

    def test_tag_based_matching(self, matcher: ServiceMatcher, redis_service: ServiceInfo):
        """Test matching by service tag."""
        template = NetworkTemplate(
            id="redis-test",
            name="Redis Test",
            protocol="tcp",
            port=None,
            tags=["network", "redis", "tcp"],
            target_service="redis",
        )
        matches = matcher.match([template], [redis_service])
        assert len(matches) == 1

    def test_product_based_matching(self, matcher: ServiceMatcher):
        """Test matching by product name in tags."""
        service = ServiceInfo(
            host="10.0.0.1", port=8080, protocol="tcp", product="elasticsearch"
        )
        template = NetworkTemplate(
            id="elastic-test",
            name="Elasticsearch Test",
            protocol="tcp",
            tags=["network", "elasticsearch"],
        )
        matches = matcher.match([template], [service])
        assert len(matches) == 1

    def test_protocol_mismatch_no_match(self, matcher: ServiceMatcher, redis_service: ServiceInfo):
        """Test no match when protocol differs."""
        template = NetworkTemplate(
            id="redis-udp", name="Redis UDP", port=6379, protocol="udp"
        )
        matches = matcher.match([template], [redis_service])
        assert len(matches) == 0

    def test_multiple_services_multiple_templates(self, matcher: ServiceMatcher):
        """Test matching multiple templates against multiple services."""
        services = [
            ServiceInfo(host="10.0.0.1", port=21, protocol="tcp", service="ftp"),
            ServiceInfo(host="10.0.0.1", port=22, protocol="tcp", service="ssh"),
            ServiceInfo(host="10.0.0.1", port=6379, protocol="tcp", service="redis"),
        ]
        templates = [
            NetworkTemplate(id="ftp-t", name="FTP", port=21, protocol="tcp"),
            NetworkTemplate(id="ssh-t", name="SSH", port=22, protocol="tcp"),
            NetworkTemplate(id="http-t", name="HTTP", port=80, protocol="tcp"),
        ]
        matches = matcher.match(templates, services)
        assert len(matches) == 2  # FTP and SSH match, HTTP doesn't
        matched_ids = {t.id for t, _ in matches}
        assert "ftp-t" in matched_ids
        assert "ssh-t" in matched_ids
        assert "http-t" not in matched_ids

    def test_service_alias_matching(self, matcher: ServiceMatcher):
        """Test that service aliases match correctly."""
        service = ServiceInfo(
            host="10.0.0.1", port=445, protocol="tcp", service="microsoft-ds"
        )
        template = NetworkTemplate(
            id="smb-test",
            name="SMB Test",
            protocol="tcp",
            target_service="smb",
            tags=["smb"],
        )
        matches = matcher.match([template], [service])
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# CVE Enricher
# ---------------------------------------------------------------------------


class TestCVEEnricher:
    """Test CVE enrichment with built-in database."""

    def test_enrich_redis_service(self, enricher: CVEEnricher, redis_service: ServiceInfo):
        """Test CVE enrichment for Redis with known vulnerable version."""
        cves = enricher.enrich([redis_service])
        assert len(cves) > 0
        cve_ids = [c.cve_id for c in cves]
        assert "CVE-2022-0543" in cve_ids

    def test_enrich_ssh_service(self, enricher: CVEEnricher, ssh_service: ServiceInfo):
        """Test CVE enrichment for OpenSSH."""
        cves = enricher.enrich([ssh_service])
        assert len(cves) > 0
        cve_ids = [c.cve_id for c in cves]
        assert "CVE-2021-41617" in cve_ids

    def test_enrich_no_product(self, enricher: CVEEnricher):
        """Test that services without product info return no CVEs."""
        service = ServiceInfo(host="10.0.0.1", port=8080, protocol="tcp")
        cves = enricher.enrich([service])
        assert len(cves) == 0

    def test_enrich_unknown_product(self, enricher: CVEEnricher):
        """Test that unknown products return no CVEs."""
        service = ServiceInfo(
            host="10.0.0.1", port=9999, protocol="tcp", product="UnknownSoftware", version="1.0"
        )
        cves = enricher.enrich([service])
        assert len(cves) == 0

    def test_enrich_patched_version(self, enricher: CVEEnricher):
        """Test that patched versions return no CVEs."""
        service = ServiceInfo(
            host="10.0.0.1", port=6379, protocol="tcp", product="Redis", version="7.0.0"
        )
        cves = enricher.enrich([service])
        assert len(cves) == 0  # 7.0.0 > 6.2.7 (patched)

    def test_vulnx_unavailable_fallback(self, enricher: CVEEnricher):
        """Test graceful fallback when vulnx is not available."""
        # vulnx won't be available in test environment
        assert enricher.vulnx_available is False
        # Should still return results from built-in DB
        service = ServiceInfo(
            host="10.0.0.1", port=6379, protocol="tcp", product="Redis", version="5.0.0"
        )
        cves = enricher.enrich([service])
        assert len(cves) > 0

    def test_enrich_only_critical_high(self, enricher: CVEEnricher):
        """Test that only critical/high severity CVEs are returned."""
        service = ServiceInfo(
            host="10.0.0.1", port=6379, protocol="tcp", product="Redis", version="5.0.0"
        )
        cves = enricher.enrich([service])
        for cve in cves:
            assert cve.severity in ("critical", "high")

    def test_product_normalization(self, enricher: CVEEnricher):
        """Test that product name aliases are resolved."""
        # "OpenSSH" should normalize to "openssh"
        service = ServiceInfo(
            host="10.0.0.1", port=22, protocol="tcp", product="OpenSSH", version="7.5"
        )
        cves = enricher.enrich([service])
        assert len(cves) > 0

    def test_version_comparison(self, enricher: CVEEnricher):
        """Test version comparison with complex version strings."""
        # "8.2p1" should clean to "8.2" and be < "8.8"
        assert enricher._is_version_affected("8.2p1", "8.8") is True
        assert enricher._is_version_affected("9.0", "8.8") is False
        assert enricher._is_version_affected("8.8", "8.8") is False


# ---------------------------------------------------------------------------
# Network Probe Executor
# ---------------------------------------------------------------------------


class TestNetworkProbeExecutor:
    """Test network probe execution with mocked sockets."""

    @pytest.fixture
    def executor(self) -> NetworkProbeExecutor:
        return NetworkProbeExecutor()

    def test_word_matcher_positive(self, executor: NetworkProbeExecutor):
        """Test that word matcher correctly identifies response."""
        template = NetworkTemplate(
            id="test",
            name="Test",
            protocol="tcp",
            port=21,
            inputs=[NetworkInput(data="hello", type="text")],
            matchers=[NetworkMatcher(type="word", words=["Titan FTP"])],
        )
        matched, details = executor._check_matchers(template, "220 Titan FTP Server Ready")
        assert matched is True
        assert "word_match" in details

    def test_word_matcher_negative(self, executor: NetworkProbeExecutor):
        """Test that word matcher rejects non-matching response."""
        template = NetworkTemplate(
            id="test",
            name="Test",
            protocol="tcp",
            port=21,
            matchers=[NetworkMatcher(type="word", words=["Titan FTP"])],
        )
        matched, _ = executor._check_matchers(template, "220 vsftpd 3.0.3 Ready")
        assert matched is False

    def test_regex_matcher(self, executor: NetworkProbeExecutor):
        """Test regex matcher against response."""
        template = NetworkTemplate(
            id="test",
            name="Test",
            protocol="tcp",
            port=22,
            matchers=[NetworkMatcher(type="regex", regex=[r"SSH-\d\.\d-OpenSSH_(\d+\.\d+)"])],
        )
        matched, details = executor._check_matchers(template, "SSH-2.0-OpenSSH_8.2p1")
        assert matched is True
        assert "regex_match" in details

    def test_dsl_contains_matcher(self, executor: NetworkProbeExecutor):
        """Test DSL contains() function evaluation."""
        template = NetworkTemplate(
            id="test",
            name="Test",
            protocol="tcp",
            port=80,
            matchers=[NetworkMatcher(type="dsl", dsl=["contains(raw, 'check_mk')"])],
        )
        matched, _ = executor._check_matchers(template, "<<<check_mk>>>\nVersion: 2.1.0")
        assert matched is True

    def test_matchers_condition_and(self, executor: NetworkProbeExecutor):
        """Test matchers with AND condition (all must match)."""
        template = NetworkTemplate(
            id="test",
            name="Test",
            protocol="tcp",
            port=80,
            matchers_condition="and",
            matchers=[
                NetworkMatcher(type="word", words=["check_mk"]),
                NetworkMatcher(type="word", words=["Version"]),
            ],
        )
        # Both present
        matched, _ = executor._check_matchers(template, "<<<check_mk>>>\nVersion: 2.1.0")
        assert matched is True

        # Only one present
        matched, _ = executor._check_matchers(template, "<<<check_mk>>>")
        assert matched is False

    def test_negative_matcher(self, executor: NetworkProbeExecutor):
        """Test negative matcher (match when word is NOT present)."""
        template = NetworkTemplate(
            id="test",
            name="Test",
            protocol="tcp",
            port=6379,
            matchers=[NetworkMatcher(type="word", words=["AUTH required"], negative=True)],
        )
        # Word not present = negative match succeeds
        matched, _ = executor._check_matchers(template, "+PONG")
        assert matched is True

        # Word present = negative match fails
        matched, _ = executor._check_matchers(template, "-NOAUTH AUTH required")
        assert matched is False

    def test_probe_with_mock_socket(self, executor: NetworkProbeExecutor):
        """Test probe execution with mocked socket."""
        template = NetworkTemplate(
            id="ftp-test",
            name="FTP Test",
            protocol="tcp",
            port=21,
            inputs=[NetworkInput(data="00000000", type="hex")],
            read_size=1024,
            matchers=[NetworkMatcher(type="word", words=["Titan FTP"])],
        )
        target = ServiceInfo(host="192.168.1.1", port=21, protocol="tcp")

        # Mock at the sync level to avoid event loop issues
        with patch.object(executor, "_send_probe_sync", return_value="220 Titan FTP Server v10.30 Ready"):
            result = asyncio.run(executor.execute(template, target, timeout=5.0))

        assert result.matched is True
        assert result.template_id == "ftp-test"
        assert "Titan FTP" in result.response_data

    def test_probe_budget_exhaustion(self, executor: NetworkProbeExecutor):
        """VT-Spec DOS-01: Test that probe budget is enforced."""
        executor._probes_executed = NetworkProbeExecutor.MAX_PROBES_PER_SCAN

        template = NetworkTemplate(id="test", name="Test", protocol="tcp", port=80)
        target = ServiceInfo(host="10.0.0.1", port=80, protocol="tcp")

        result = asyncio.run(executor.execute(template, target))
        assert result.matched is False
        assert "budget_exhausted" in result.matcher_details

    def test_probe_connection_error(self, executor: NetworkProbeExecutor):
        """Test graceful handling of connection errors."""
        template = NetworkTemplate(
            id="test",
            name="Test",
            protocol="tcp",
            port=80,
            inputs=[NetworkInput(data="GET / HTTP/1.0\r\n\r\n", type="text")],
            matchers=[NetworkMatcher(type="word", words=["HTTP"])],
        )
        target = ServiceInfo(host="10.0.0.1", port=80, protocol="tcp")

        with patch.object(executor, "_send_probe_sync", side_effect=ConnectionRefusedError("Connection refused")):
            result = asyncio.run(executor.execute(template, target, timeout=5.0))

        assert result.matched is False
        assert "connection_error" in result.matcher_details


# ---------------------------------------------------------------------------
# Full Pipeline: InfraScanner
# ---------------------------------------------------------------------------


class TestInfraScanner:
    """Test full InfraScanner pipeline."""

    @pytest.fixture
    def scanner(self, tmp_path: Path) -> InfraScanner:
        """Create scanner with test template directory."""
        templates_dir = tmp_path / "templates"
        templates_dir.mkdir()
        # Create test templates
        (templates_dir / "ftp-vuln.yaml").write_text("""
id: test-ftp-vuln
info:
  name: Test FTP Vulnerability
  severity: high
  tags: network,ftp,tcp
  classification:
    cve-id: CVE-2014-1843
tcp:
  - inputs:
      - data: "00000000"
        type: hex
    port: 21
    read-size: 1024
    matchers:
      - type: word
        words:
          - "Titan FTP"
""")
        (templates_dir / "redis-unauth.yaml").write_text("""
id: redis-unauth
info:
  name: Redis Unauthorized Access
  severity: high
  tags: network,redis,tcp
tcp:
  - inputs:
      - data: "PING\\r\\n"
        type: text
    port: 6379
    read-size: 512
    matchers:
      - type: word
        words:
          - "+PONG"
""")
        return InfraScanner(templates_dir=templates_dir)

    def test_load_templates(self, scanner: InfraScanner):
        """Test template loading from directory."""
        templates = scanner.load_templates()
        assert len(templates) == 2
        assert scanner.templates_loaded == 2

    def test_scan_without_probes(self, scanner: InfraScanner, ftp_service: ServiceInfo):
        """Test scan pipeline with probes disabled (matching + CVE only)."""
        findings = asyncio.run(scanner.scan([ftp_service], execute_probes=False))
        # Should get at least one potential match from template matching
        assert len(findings) >= 1
        # Check finding structure
        for f in findings:
            assert f.tool in ("infra-scanner", "cve-enricher")
            assert f.target is not None

    def test_scan_with_mock_probes(self, scanner: InfraScanner):
        """Test full scan pipeline with mocked network probes."""
        service = ServiceInfo(
            host="192.168.1.100",
            port=21,
            protocol="tcp",
            service="ftp",
            product="Titan FTP",
            version="10.30",
        )

        with patch.object(
            scanner._executor, "_send_probe_sync",
            return_value="220 Titan FTP Server v10.30 Ready",
        ):
            findings = asyncio.run(scanner.scan([service], execute_probes=True))

        # Should have confirmed finding from probe + CVE enrichment findings
        confirmed = [f for f in findings if "[Confirmed]" in f.title]
        assert len(confirmed) >= 1
        assert confirmed[0].tool == "infra-scanner"

    def test_scan_cve_enrichment(self, scanner: InfraScanner, redis_service: ServiceInfo):
        """Test that CVE enrichment produces findings."""
        findings = asyncio.run(scanner.scan([redis_service], execute_probes=False))
        cve_findings = [f for f in findings if f.tool == "cve-enricher"]
        assert len(cve_findings) > 0
        assert any("CVE-2022-0543" in (f.cve or "") for f in cve_findings)

    def test_scan_empty_services(self, scanner: InfraScanner):
        """Test scan with no services returns no findings."""
        findings = asyncio.run(scanner.scan([], execute_probes=False))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Integration: nmap service → template match → finding
# ---------------------------------------------------------------------------


class TestNmapIntegration:
    """Test integration between nmap parser output and InfraScanner."""

    def test_port_info_to_service_info_conversion(self):
        """Test converting nmap PortInfo to ServiceInfo for scanning."""
        from erebos.parsers.nmap import PortInfo

        port_info = PortInfo(
            port="6379",
            protocol="tcp",
            state="open",
            service="redis",
            product="Redis",
            version="5.0.7",
            host="10.0.0.5",
        )

        # Convert PortInfo to ServiceInfo
        service = ServiceInfo(
            host=port_info.host,
            port=int(port_info.port),
            protocol=port_info.protocol,
            service=port_info.service,
            product=port_info.product,
            version=port_info.version,
        )

        assert service.host == "10.0.0.5"
        assert service.port == 6379
        assert service.service == "redis"
        assert service.product == "Redis"
        assert service.version == "5.0.7"

    def test_nmap_parse_to_scanner_pipeline(self):
        """Test full pipeline: nmap XML → ServiceInfo → template match."""
        from erebos.parsers.nmap import NmapParser

        nmap_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5"/>
    <hostnames><hostname name="redis-server"/></hostnames>
    <ports>
      <port portid="6379" protocol="tcp">
        <state state="open"/>
        <service name="redis" product="Redis" version="5.0.7"/>
      </port>
      <port portid="22" protocol="tcp">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.9p1"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

        parser = NmapParser()
        result = parser.parse(nmap_xml)

        # Convert to ServiceInfo list
        services = []
        for port_info in result.ports:
            if port_info.state == "open":
                services.append(
                    ServiceInfo(
                        host=port_info.host,
                        port=int(port_info.port),
                        protocol=port_info.protocol,
                        service=port_info.service,
                        product=port_info.product,
                        version=port_info.version,
                    )
                )

        assert len(services) == 2

        # Match against templates
        matcher = ServiceMatcher()
        templates = [
            NetworkTemplate(
                id="redis-test",
                name="Redis Unauth",
                protocol="tcp",
                port=6379,
                matchers=[NetworkMatcher(type="word", words=["+PONG"])],
            ),
            NetworkTemplate(
                id="ssh-test",
                name="SSH Version",
                protocol="tcp",
                port=22,
                matchers=[NetworkMatcher(type="regex", regex=[r"SSH-\d"])],
            ),
        ]
        matches = matcher.match(templates, services)
        assert len(matches) == 2

        # Verify CVE enrichment works
        enricher = CVEEnricher()
        cves = enricher.enrich(services)
        # Redis 5.0.7 should trigger CVE-2022-0543
        cve_ids = [c.cve_id for c in cves]
        assert "CVE-2022-0543" in cve_ids
        # OpenSSH 7.9p1 should trigger CVE-2021-41617
        assert "CVE-2021-41617" in cve_ids
