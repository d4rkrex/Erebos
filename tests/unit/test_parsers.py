"""Unit tests for parsers."""

import json

import pytest

from erebos.core.finding import Finding, Phase, Severity
from erebos.parsers import get_parser_for_tool, auto_detect_parser
from erebos.parsers.amass import AmassParser
from erebos.parsers.subfinder import SubfinderParser
from erebos.parsers.masscan import MasscanParser
from erebos.parsers.nuclei import NucleiParser
from erebos.parsers.nikto import NiktoParser
from erebos.parsers.katana import KatanaParser
from erebos.parsers.nmap import NmapParser
from erebos.parsers.ffuf import FfufParser
from erebos.parsers.gobuster import GobusterParser
from erebos.parsers.sqlmap import SqlmapParser
from erebos.parsers.dirb import DirbParser


class TestNucleiParser:
    """Tests for NucleiParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = NucleiParser()

    def test_parse_valid_json(self):
        """Test parsing valid nuclei JSON output."""
        # Sample nuclei JSON output
        nuclei_output = json.dumps(
            [
                {
                    "template-id": "sql-injection",
                    "info": {
                        "name": "SQL Injection",
                        "severity": "critical",
                        "description": "SQL Injection detected",
                    },
                    "matched-at": "http://example.com/page?id=1",
                    "type": "http",
                },
                {
                    "template-id": "xss",
                    "info": {
                        "name": "Cross-Site Scripting",
                        "severity": "high",
                        "description": "XSS vulnerability",
                    },
                    "matched-at": "http://example.com/search?q=test",
                    "type": "http",
                },
            ]
        )

        findings = self.parser.parse(nuclei_output)

        assert len(findings) == 2
        assert findings[0].tool == "nuclei"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].title == "SQL Injection"
        assert findings[0].evidence.url == "http://example.com/page?id=1"

        assert findings[1].severity == Severity.HIGH
        assert findings[1].title == "Cross-Site Scripting"

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse("")
        assert len(findings) == 0

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON returns empty list."""
        findings = self.parser.parse("not valid json")
        assert len(findings) == 0

    def test_can_parse_json(self):
        """Test can_parse detects JSON format."""
        # Valid nuclei JSON
        assert self.parser.can_parse('[{"info": {"name": "test"}}]') is True

        # Invalid
        assert self.parser.can_parse("not json") is False

    def test_parse_jsonl_output(self):
        """Test parsing JSONL nuclei output."""
        nuclei_output = "\n".join(
            [
                json.dumps(
                    {
                        "template-id": "tech-detect",
                        "info": {"name": "Tech Detect", "severity": "info"},
                        "matched-at": "https://example.com",
                    }
                ),
                json.dumps(
                    {
                        "template-id": "xss",
                        "info": {"name": "Cross-Site Scripting", "severity": "high"},
                        "matched-at": "https://example.com/search?q=test",
                    }
                ),
            ]
        )

        findings = self.parser.parse(nuclei_output)

        assert len(findings) == 2
        assert findings[1].severity == Severity.HIGH


class TestNiktoParser:
    """Tests for NiktoParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = NiktoParser()

    def test_parse_text_output(self):
        """Test parsing nikto text output."""
        # Sample nikto output
        nikto_output = """+ Target: http://example.com
+ Server: Apache/2.4.41
+ Retrieved x-powered-by header: PHP/7.4
+ OSVDB-3268: /icons/README: Directory indexing found.
+ OSVDB-637: /phpmyadmin/: phpMyAdmin directory found."""

        findings = self.parser.parse(nikto_output)

        assert len(findings) > 0
        assert any(f.tool == "nikto" for f in findings)

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse("")
        assert len(findings) == 0

    def test_help_output_is_not_treated_as_scan_results(self):
        """Test nikto help text is ignored."""
        nikto_output = """   Options:\n       -Format+           Save file (-o) format:\n       -host+             Target host/URL"""

        assert self.parser.can_parse(nikto_output) is False
        assert self.parser.parse(nikto_output) == []


class TestKatanaParser:
    """Tests for KatanaParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = KatanaParser()

    def test_parse_json_output(self):
        """Test parsing katana JSON output."""
        katana_output = json.dumps(
            [
                {"url": "http://example.com/page1", "source": "href"},
                {"url": "http://example.com/page2", "source": "form"},
                {"url": "http://example.com/page3", "source": "javascript"},
            ]
        )

        findings = self.parser.parse(katana_output)

        assert len(findings) == 3
        assert all(f.tool == "katana" for f in findings)
        assert all(f.evidence.url for f in findings)

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse("")
        assert len(findings) == 0


class TestFindingModel:
    """Tests for Finding model."""

    def test_finding_creation(self):
        """Test creating a Finding."""
        finding = Finding(
            tool="nuclei",
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="SQL Injection vulnerability",
            evidence={"url": "http://example.com"},
            phase_found="recon",
        )

        assert finding.tool == "nuclei"
        assert finding.severity == Severity.CRITICAL
        assert finding.id is not None

    def test_finding_serialization(self):
        """Test Finding can be serialized to JSON."""
        finding = Finding(
            tool="nuclei",
            severity=Severity.HIGH,
            title="XSS",
            description="Cross-site scripting",
            phase_found="vuln-scan",
        )

        data = finding.model_dump(mode="json")

        assert data["tool"] == "nuclei"
        assert data["severity"] == "HIGH"
        assert "id" in data


class TestNmapParser:
    """Tests for NmapParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = NmapParser()

    def test_parse_xml_output(self):
        """Test parsing nmap XML output."""
        nmap_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.41"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

        findings = self.parser.parse_to_findings(nmap_xml)

        assert len(findings) == 2
        assert all(f.tool == "nmap" for f in findings)
        assert all(f.severity != Severity.INFO for f in findings)

    def test_parse_text_output(self):
        """Test parsing nmap text output."""
        nmap_text = """Starting Nmap 7.91
Host: 192.168.1.1 (router.local)
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
22/tcp   closed ssh"""

        findings = self.parser.parse_to_findings(nmap_text)

        assert len(findings) >= 2
        assert any(f.tool == "nmap" for f in findings)

    def test_can_parse_xml(self):
        """Test can_parse detects XML format."""
        xml_output = '<?xml version="1.0"?><nmaprun><host></host></nmaprun>'
        assert self.parser.can_parse(xml_output) is True

    def test_can_parse_text(self):
        """Test can_parse detects text format."""
        text_output = """Nmap scan report
Host: 192.168.1.1
PORT STATE SERVICE
 80/tcp open http"""
        assert self.parser.can_parse(text_output) is True

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse_to_findings("")
        assert len(findings) == 0


class TestFfufParser:
    """Tests for FfufParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = FfufParser()

    def test_parse_json_output(self):
        """Test parsing ffuf JSON output."""
        ffuf_output = json.dumps(
            {
                "results": [
                    {
                        "url": "http://example.com/admin",
                        "status": 200,
                        "length": 1234,
                        "words": 100,
                        "lines": 50,
                        "content-type": "text/html",
                    },
                    {
                        "url": "http://example.com/login",
                        "status": 301,
                        "length": 0,
                        "words": 0,
                        "lines": 0,
                        "content-type": "text/html",
                        "redirectlocation": "http://example.com/login/",
                    },
                    {
                        "url": "http://example.com/nothing",
                        "status": 404,
                        "length": 0,
                        "words": 0,
                        "lines": 0,
                    },
                ],
                "stats": [{"duration": 1000}],
            }
        )

        findings = self.parser.parse(ffuf_output)

        assert len(findings) >= 3
        assert all(f.tool == "ffuf" for f in findings)
        assert findings[0].severity == Severity.HIGH
        assert findings[1].severity == Severity.MEDIUM

    def test_can_parse_json(self):
        """Test can_parse detects JSON format."""
        json_output = json.dumps({"results": []})
        assert self.parser.can_parse(json_output) is True

    def test_can_parse_invalid(self):
        """Test can_parse rejects invalid output."""
        assert self.parser.can_parse("not json") is False

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse("")
        assert len(findings) == 0


class TestGobusterParser:
    """Tests for GobusterParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = GobusterParser()

    def test_parse_text_output(self):
        """Test parsing gobuster text output."""
        gobuster_output = """/admin                   (Status: 200) [Size: 1234]
/login                  (Status: 301) [Size: 185]
/api                   (Status: 403) [Size: 0]
/hidden                (Status: 404) [Size: 0]"""

        findings = self.parser.parse(gobuster_output)

        assert len(findings) == 4
        assert all(f.tool == "gobuster" for f in findings)

    def test_parse_json_output(self):
        """Test parsing gobuster JSON output."""
        gobuster_output = json.dumps(
            {
                "result": [
                    {
                        "url": "http://example.com/admin",
                        "statuscode": 200,
                        "length": 1234,
                        "type": "dir",
                    },
                    {"url": "http://example.com/api", "statuscode": 403, "length": 0},
                ]
            }
        )

        findings = self.parser.parse(gobuster_output)

        assert len(findings) == 2
        assert all(f.tool == "gobuster" for f in findings)

    def test_can_parse_text(self):
        """Test can_parse detects text format."""
        text_output = "/admin (Status: 200) [Size: 1234]"
        assert self.parser.can_parse(text_output) is True

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse("")
        assert len(findings) == 0


class TestSqlmapParser:
    """Tests for SqlmapParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = SqlmapParser()

    def test_parse_text_output(self):
        """Test parsing sqlmap text output."""
        sqlmap_output = """Parameter: id (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - OR boolean-based blind - OR
    Payload: id=1' OR '1'='1
---
Parameter: name (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (BENCHMARK)
    Payload: name=test' AND SLEEP(5)--"""

        findings = self.parser.parse(sqlmap_output)

        assert len(findings) >= 2
        assert all(f.tool == "sqlmap" for f in findings)
        assert all(f.severity in [Severity.HIGH, Severity.CRITICAL] for f in findings)

    def test_parse_json_output(self):
        """Test parsing sqlmap JSON output."""
        sqlmap_output = json.dumps(
            {
                "data": [
                    {
                        "parameter": "id",
                        "type": "union-based",
                        "title": "Generic UNION SELECT",
                        "payload": "id=1 UNION SELECT 1,2,3--",
                        "cwe_id": "CWE-89",
                        "cve_id": "CVE-2021-1234",
                    }
                ]
            }
        )

        findings = self.parser.parse(sqlmap_output)

        assert len(findings) >= 1
        assert findings[0].tool == "sqlmap"
        assert findings[0].cwe == "CWE-89"

    def test_can_parse_text(self):
        """Test can_parse detects text format."""
        text_output = "Parameter: id\nType: boolean-based blind\nTitle: Test"
        assert self.parser.can_parse(text_output) is True

    def test_can_parse_json(self):
        """Test can_parse detects JSON format."""
        json_output = json.dumps({"data": []})
        assert self.parser.can_parse(json_output) is True

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse("")
        assert len(findings) == 0


class TestDirbParser:
    """Tests for DirbParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = DirbParser()

    def test_parse_text_output(self):
        """Test parsing dirb text output."""
        dirb_output = """+ http://example.com/admin (CODE:200|SIZE:1234)
+ http://example.com/login (CODE:302|SIZE:0)
+ http://example.com/nothing (CODE:404|SIZE:0)
==> DIRECTORY: http://example.com/images/
==> FILE: http://example.com/readme.txt"""

        findings = self.parser.parse(dirb_output)

        assert len(findings) == 5
        assert all(f.tool == "dirb" for f in findings)

    def test_can_parse_output(self):
        """Test can_parse detects DIRB format."""
        dirb_output = "+ http://example.com/admin (CODE:200|SIZE:1234)"
        assert self.parser.can_parse(dirb_output) is True

    def test_can_parse_directory(self):
        """Test can_parse detects directory format."""
        dirb_output = "==> DIRECTORY: http://example.com/admin/"
        assert self.parser.can_parse(dirb_output) is True

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse("")
        assert len(findings) == 0


class TestAmassParser:
    """Tests for AmassParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = AmassParser()

    def test_parse_json_list_output(self):
        """Test parsing amass JSON list output."""
        amass_output = json.dumps(
            [
                {
                    "name": "sub.example.com",
                    "domain": "example.com",
                    "type": "A",
                    "source": "dnsdumpster",
                    "timestamp": "2024-01-01T00:00:00Z",
                },
                {
                    "name": "api.example.com",
                    "domain": "example.com",
                    "type": "A",
                    "source": "virustotal",
                },
                {
                    "name": "www.example.com",
                    "domain": "example.com",
                    "type": "CNAME",
                    "source": "passive",
                },
            ]
        )

        findings = self.parser.parse(amass_output)

        assert len(findings) == 3
        assert all(f.tool == "amass" for f in findings)
        assert findings[0].title == "Subdomain: sub.example.com"
        assert findings[0].evidence.url == "sub.example.com"
        assert findings[0].severity == Severity.INFO
        # CNAME records get LOW severity
        assert findings[2].severity == Severity.LOW

    def test_parse_single_dict_output(self):
        """Test parsing a single amass JSON record."""
        amass_output = json.dumps(
            {
                "name": "sub.example.com",
                "domain": "example.com",
                "type": "A",
                "source": "crtsh",
            }
        )

        findings = self.parser.parse(amass_output)

        assert len(findings) == 1
        assert findings[0].tool == "amass"
        assert findings[0].title == "Subdomain: sub.example.com"

    def test_can_parse_json(self):
        """Test can_parse detects JSON format."""
        json_output = json.dumps([{"name": "sub.example.com", "domain": "example.com"}])
        assert self.parser.can_parse(json_output) is True

    def test_can_parse_invalid(self):
        """Test can_parse rejects invalid output."""
        assert self.parser.can_parse("not json") is False
        assert self.parser.can_parse("") is False

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse("")
        assert len(findings) == 0

    def test_parse_with_extra_fields(self):
        """Test parsing amass output with extra fields."""
        amass_output = json.dumps(
            [
                {
                    "name": "cdn.example.com",
                    "domain": "example.com",
                    "type": "A",
                    "source": "dnsdumpster",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "extra": "ignored",
                },
            ]
        )

        findings = self.parser.parse(amass_output)

        assert len(findings) == 1
        assert findings[0].tool == "amass"


class TestSubfinderParser:
    """Tests for SubfinderParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = SubfinderParser()

    def test_parse_line_output(self):
        """Test parsing subfinder line-separated output."""
        subfinder_output = """sub1.example.com
sub2.example.com
sub3.example.com
api.example.com
www.example.com"""

        findings = self.parser.parse(subfinder_output)

        assert len(findings) == 5
        assert all(f.tool == "subfinder" for f in findings)
        assert all(f.severity == Severity.INFO for f in findings)
        assert findings[0].title == "Subdomain: sub1.example.com"
        assert findings[0].evidence.url == "sub1.example.com"

    def test_parse_with_info_lines(self):
        """Test parsing subfinder output with info/warning lines."""
        subfinder_output = """[WRN] No sources available for this domain
sub1.example.com
sub2.example.com
[ERR] Some error message
sub3.example.com"""

        findings = self.parser.parse(subfinder_output)

        # Should parse only subdomain lines, skip [WRN] and [ERR] lines
        assert len(findings) == 3
        assert all(f.tool == "subfinder" for f in findings)

    def test_can_parse(self):
        """Test can_parse detects subdomain format."""
        output = "sub.example.com\napi.example.com"
        assert self.parser.can_parse(output) is True

    def test_can_parse_with_comments(self):
        """Test can_parse handles comment lines."""
        output = "# This is a comment\nsub.example.com"
        assert self.parser.can_parse(output) is True

    def test_can_parse_invalid(self):
        """Test can_parse rejects invalid output."""
        assert self.parser.can_parse("") is False
        assert self.parser.can_parse("http://example.com") is False

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse("")
        assert len(findings) == 0

    def test_deduplication(self):
        """Test that duplicate subdomains are removed."""
        subfinder_output = """sub.example.com
sub.example.com
api.example.com
api.example.com"""

        findings = self.parser.parse(subfinder_output)

        # Should have only 2 unique subdomains
        assert len(findings) == 2


class TestMasscanParser:
    """Tests for MasscanParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = MasscanParser()

    def test_parse_json_output(self):
        """Test parsing masscan JSON output."""
        masscan_output = json.dumps(
            {
                "services": [
                    {
                        "ip": "192.168.1.1",
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": {"name": "http"},
                    },
                    {
                        "ip": "192.168.1.1",
                        "port": 443,
                        "protocol": "tcp",
                        "state": "open",
                        "service": {"name": "https"},
                    },
                    {
                        "ip": "192.168.1.1",
                        "port": 22,
                        "protocol": "tcp",
                        "state": "closed",
                        "service": {"name": "ssh"},
                    },
                ]
            }
        )

        findings = self.parser.parse(masscan_output)

        # Should have 2 findings (80 and 443), not 22 (closed)
        assert len(findings) == 2
        assert all(f.tool == "masscan" for f in findings)
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence.url == "192.168.1.1:80"

    def test_parse_json_list_format(self):
        """Test parsing masscan JSON as direct list."""
        masscan_output = json.dumps(
            [
                {
                    "ip": "10.0.0.1",
                    "port": 8080,
                    "protocol": "tcp",
                    "state": "open",
                    "service": {"name": "http-proxy"},
                },
            ]
        )

        findings = self.parser.parse(masscan_output)

        assert len(findings) == 1
        assert findings[0].tool == "masscan"
        assert findings[0].evidence.url == "10.0.0.1:8080"

    def test_parse_grepable_output(self):
        """Test parsing masscan grepable output."""
        masscan_output = """# masscan 1.0 (protocol "masscan/" "1.0")
# target: file: (inherited)
#:ip----proto-port---state-----service-----version-----
192.168.1.1:tcp:80:open:http:Apache/2.4.41
192.168.1.1:tcp:443:open:https::
192.168.1.1:tcp:22:closed:ssh:OpenSSH/8.0"""

        findings = self.parser.parse(masscan_output)

        assert len(findings) == 2
        assert all(f.tool == "masscan" for f in findings)
        assert findings[0].severity == Severity.HIGH
        assert findings[1].severity == Severity.HIGH

    def test_can_parse_json(self):
        """Test can_parse detects JSON format."""
        json_output = json.dumps({"services": []})
        assert self.parser.can_parse(json_output) is True

    def test_can_parse_grepable(self):
        """Test can_parse detects grepable format."""
        # Note: SubfinderParser would also match this, but auto_detect_parser
        # checks MasscanParser before SubfinderParser.
        grepable_output = "# masscan 1.0\n192.168.1.1:tcp:80:open:http"
        assert self.parser.can_parse(grepable_output) is True

    def test_can_parse_invalid(self):
        """Test can_parse rejects invalid output."""
        assert self.parser.can_parse("") is False
        assert self.parser.can_parse("not masscan output") is False

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = self.parser.parse("")
        assert len(findings) == 0

    def test_filtered_port_state(self):
        """Test that filtered ports get MEDIUM severity."""
        masscan_output = json.dumps(
            {
                "services": [
                    {
                        "ip": "192.168.1.1",
                        "port": 12345,
                        "protocol": "udp",
                        "state": "open|filtered",
                        "service": {},
                    },
                ]
            }
        )

        findings = self.parser.parse(masscan_output)

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestParserRegistry:
    """Tests for parser registry functions."""

    def test_get_parser_for_amass(self):
        """Test get_parser_for_tool returns AmassParser."""
        parser = get_parser_for_tool("amass")
        assert parser is not None
        assert isinstance(parser, AmassParser)
        assert parser.tool_name == "amass"

    def test_get_parser_for_subfinder(self):
        """Test get_parser_for_tool returns SubfinderParser."""
        parser = get_parser_for_tool("subfinder")
        assert parser is not None
        assert isinstance(parser, SubfinderParser)
        assert parser.tool_name == "subfinder"

    def test_get_parser_for_masscan(self):
        """Test get_parser_for_tool returns MasscanParser."""
        parser = get_parser_for_tool("masscan")
        assert parser is not None
        assert isinstance(parser, MasscanParser)
        assert parser.tool_name == "masscan"

    def test_get_parser_for_unknown(self):
        """Test get_parser_for_tool returns None for unknown tool."""
        parser = get_parser_for_tool("nonexistent")
        assert parser is None

    def test_get_parser_case_insensitive(self):
        """Test get_parser_for_tool is case-insensitive."""
        parser = get_parser_for_tool("AMASS")
        assert parser is not None
        assert isinstance(parser, AmassParser)

    def test_auto_detect_amass(self):
        """Test auto_detect_parser detects Amass JSON."""
        output = json.dumps([{"name": "sub.example.com", "domain": "example.com"}])
        parser = auto_detect_parser(output)
        assert parser is not None
        assert isinstance(parser, AmassParser)

    def test_auto_detect_subfinder(self):
        """Test auto_detect_parser detects plain domain-list output.

        Both DnsxParser and SubfinderParser handle plain domain lists.
        DnsxParser has higher priority in detection order — either is correct.
        """
        from erebos.parsers.dnsx import DnsxParser

        output = "sub.example.com\napi.example.com"
        parser = auto_detect_parser(output)
        assert parser is not None
        assert isinstance(parser, (SubfinderParser, DnsxParser))

    def test_auto_detect_masscan_json(self):
        """Test auto_detect_parser detects Masscan JSON."""
        output = json.dumps({"services": []})
        parser = auto_detect_parser(output)
        assert parser is not None
        assert isinstance(parser, MasscanParser)

    def test_auto_detect_masscan_grepable(self):
        """Test auto_detect_parser detects Masscan grepable."""
        output = "# masscan 1.0\n192.168.1.1:tcp:80:open:http"
        parser = auto_detect_parser(output)
        assert parser is not None
        assert isinstance(parser, MasscanParser)

    def test_auto_detect_unknown(self):
        """Test auto_detect_parser returns None for unknown format."""
        parser = auto_detect_parser("completely unknown output format xyz")
        assert parser is None
