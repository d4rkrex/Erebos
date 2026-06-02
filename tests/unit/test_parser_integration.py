"""Tests for parser integration in fleet roles.

Verifies that ReconRole and VulnScanRole delegate to canonical parsers
and handle malformed output gracefully (T-01).
"""

from __future__ import annotations

from unittest.mock import MagicMock


from erebos.agents.base import FindingsBus
from erebos.agents.roles.recon import ReconRole
from erebos.agents.roles.vuln_scan import VulnScanRole


# --- Sample tool outputs ---

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - example.com">
<host starttime="1704067200" endtime="1704067210">
<address addr="93.184.216.34" addrtype="ipv4"/>
<hostnames><hostname name="example.com" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.19.0"/>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="https" product="nginx" version="1.19.0"/>
</port>
<port protocol="tcp" portid="22">
<state state="filtered" reason="no-response"/>
<service name="ssh"/>
</port>
</ports>
</host>
</nmaprun>"""

SAMPLE_NUCLEI_JSON = """{"template-id":"sqli-auth-bypass","info":{"name":"SQL Injection Auth Bypass","severity":"high","description":"Authentication bypass via SQL injection","cve-id":"CVE-2023-1234","cwe":"CWE-89","reference":"https://example.com/fix"},"matched-at":"http://example.com/login","host":"example.com","extracted-results":["admin' OR 1=1--"]}
{"template-id":"xss-reflected","info":{"name":"Reflected XSS","severity":"medium","description":"Reflected cross-site scripting","cwe":"CWE-79"},"matched-at":"http://example.com/search?q=test","host":"example.com"}"""

SAMPLE_SUBFINDER_OUTPUT = """api.example.com
admin.example.com
dev.example.com
staging.example.com"""


class TestReconParserIntegration:
    """REQ-01/REQ-02: ReconRole uses NmapParser and SubfinderParser."""

    def _make_role(self, tmp_path) -> ReconRole:
        executor = MagicMock()
        bus = FindingsBus(tmp_path / "bus.jsonl")
        return ReconRole(
            executor=executor,
            bus=bus,
            agent_id="test-recon",
            target="example.com",
        )

    def test_parse_nmap_xml_produces_findings(self, tmp_path):
        """AC-01.1/AC-01.2: NmapParser produces findings with service info."""
        role = self._make_role(tmp_path)
        findings = role._parse_nmap_output(SAMPLE_NMAP_XML)

        # Should find open ports (not filtered/closed)
        assert len(findings) >= 2
        titles = [f.title for f in findings]
        # Should include port/service info from parser
        assert any("80" in t or "http" in t for t in titles)

    def test_parse_nmap_with_service_version(self, tmp_path):
        """AC-01.2: Findings include service version from NmapParser."""
        role = self._make_role(tmp_path)
        findings = role._parse_nmap_output(SAMPLE_NMAP_XML)

        # NmapParser includes product/version in description
        assert len(findings) >= 1
        descriptions = " ".join(f.description for f in findings)
        assert "nginx" in descriptions or "1.19" in descriptions or "http" in descriptions

    def test_parse_nmap_malformed_returns_empty(self, tmp_path):
        """AC-01.3 / T-01: Malformed output returns empty, doesn't crash."""
        role = self._make_role(tmp_path)
        findings = role._parse_nmap_output("THIS IS NOT XML AT ALL <broken>")
        assert findings == []

    def test_parse_subfinder_produces_findings(self, tmp_path):
        """AC-02.1/AC-02.2: SubfinderParser produces canonical findings."""
        role = self._make_role(tmp_path)
        findings = role._parse_subfinder_output(SAMPLE_SUBFINDER_OUTPUT)

        assert len(findings) == 4
        # SubfinderParser stores subdomain in evidence.url
        evidence_urls = [f.evidence.url if f.evidence else "" for f in findings]
        assert "api.example.com" in evidence_urls
        assert "admin.example.com" in evidence_urls

    def test_parse_subfinder_empty_returns_empty(self, tmp_path):
        """T-01: Empty subfinder output returns empty list."""
        role = self._make_role(tmp_path)
        findings = role._parse_subfinder_output("")
        assert findings == []


class TestVulnScanParserIntegration:
    """REQ-03: VulnScanRole uses NucleiParser."""

    def _make_role(self, tmp_path) -> VulnScanRole:
        executor = MagicMock()
        bus = FindingsBus(tmp_path / "bus.jsonl")
        return VulnScanRole(
            executor=executor,
            bus=bus,
            agent_id="test-vuln",
            target="example.com",
            allowlist=["example.com"],
        )

    def test_parse_nuclei_json_produces_findings(self, tmp_path):
        """AC-03.1/AC-03.2: NucleiParser produces findings with CVE/CWE."""
        role = self._make_role(tmp_path)
        findings = role._parse_nuclei_output(SAMPLE_NUCLEI_JSON)

        assert len(findings) == 2

        # First finding: SQL injection with CVE
        sqli = findings[0]
        assert "SQL Injection" in sqli.title
        assert sqli.severity in ("HIGH", "high")
        assert sqli.cve == "CVE-2023-1234"
        assert sqli.cwe == "CWE-89"

        # Second finding: XSS with CWE
        xss = findings[1]
        assert "XSS" in xss.title
        assert xss.severity in ("MEDIUM", "medium")
        assert xss.cwe == "CWE-79"

    def test_parse_nuclei_includes_evidence(self, tmp_path):
        """AC-03.2: Findings include evidence URL."""
        role = self._make_role(tmp_path)
        findings = role._parse_nuclei_output(SAMPLE_NUCLEI_JSON)

        sqli = findings[0]
        assert sqli.evidence is not None
        assert "login" in sqli.evidence.url

    def test_parse_nuclei_includes_suggested_fix(self, tmp_path):
        """AC-03.2: Findings include suggested_fix from reference."""
        role = self._make_role(tmp_path)
        findings = role._parse_nuclei_output(SAMPLE_NUCLEI_JSON)

        sqli = findings[0]
        assert sqli.suggested_fix is not None

    def test_parse_nuclei_malformed_returns_empty(self, tmp_path):
        """AC-03.3 / T-01: Malformed output returns empty, doesn't crash."""
        role = self._make_role(tmp_path)
        findings = role._parse_nuclei_output("NOT JSON {{{broken")
        assert findings == []

    def test_parse_nuclei_empty_returns_empty(self, tmp_path):
        """T-01: Empty output returns empty list."""
        role = self._make_role(tmp_path)
        findings = role._parse_nuclei_output("")
        assert findings == []
