"""Tests for the external findings ingestion layer.

Tests cover:
- SARIF parsing (happy path)
- Fortify FPR parsing (happy path)
- Burp XML parsing (happy path)
- CSV parsing
- Auto-detection of format
- INJ-01: HTML stripping in descriptions
- SCOPE-01: Out-of-scope URL rejection
- Large file handling (10k findings perf)
"""

from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from erebos.core.finding import Finding, Phase, Severity
from erebos.ingestion.base import sanitize_text
from erebos.ingestion.burp_parser import BurpParser
from erebos.ingestion.csv_parser import CSVParser
from erebos.ingestion.fortify_parser import FortifyParser
from erebos.ingestion.ingester import FindingsIngester
from erebos.ingestion.native_parser import NativeParser
from erebos.ingestion.sarif_parser import SARIFParser
from erebos.ingestion.semgrep_parser import SemgrepParser


# ============================================================================
# Test fixtures / helpers
# ============================================================================


def _make_sarif(results=None, tool_name="test-tool", rules=None):
    """Build a SARIF 2.1 JSON bytes object."""
    if results is None:
        results = [
            {
                "ruleId": "security/sql-injection",
                "level": "error",
                "message": {"text": "SQL injection vulnerability detected"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/app.py"},
                            "region": {"startLine": 42},
                        }
                    }
                ],
            }
        ]
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool_name, "rules": rules or []}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif).encode("utf-8")


def _make_fortify_fpr(vulnerabilities_xml: str = "") -> bytes:
    """Build a minimal Fortify FPR (ZIP with audit.fvdl)."""
    if not vulnerabilities_xml:
        vulnerabilities_xml = """<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl">
  <Vulnerabilities>
    <Vulnerability>
      <ClassInfo>
        <Type>SQL Injection</Type>
        <Subtype>Blind</Subtype>
        <DefaultSeverity>High</DefaultSeverity>
        <Kingdom>Input Validation</Kingdom>
      </ClassInfo>
      <InstanceInfo>
        <Confidence>5.0</Confidence>
      </InstanceInfo>
      <AnalysisInfo>
        <SourceLocation path="src/db.py" line="55"/>
      </AnalysisInfo>
    </Vulnerability>
  </Vulnerabilities>
</FVDL>"""

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("audit.fvdl", vulnerabilities_xml)
    return buf.getvalue()


def _make_burp_xml(issues_xml: str = "") -> bytes:
    """Build Burp Suite XML content."""
    if not issues_xml:
        issues_xml = """<?xml version="1.0" encoding="UTF-8"?>
<issues>
  <issue>
    <serialNumber>12345</serialNumber>
    <type>1049600</type>
    <name>SQL injection</name>
    <host ip="10.0.0.1">https://target.example.com</host>
    <path>/api/users</path>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueDetail>The parameter 'id' is vulnerable to SQL injection.</issueDetail>
    <remediationBackground>Use parameterized queries.</remediationBackground>
  </issue>
</issues>"""
    return issues_xml.encode("utf-8")


def _make_semgrep_json(results=None) -> bytes:
    """Build Semgrep JSON output."""
    if results is None:
        results = [
            {
                "check_id": "python.lang.security.audit.dangerous-system-call",
                "path": "src/utils.py",
                "start": {"line": 10, "col": 1},
                "end": {"line": 10, "col": 40},
                "extra": {
                    "severity": "ERROR",
                    "message": "Dangerous system call detected",
                    "lines": "os.system(user_input)",
                    "metadata": {"cwe": ["CWE-78"]},
                },
            }
        ]
    data = {"results": results, "errors": []}
    return json.dumps(data).encode("utf-8")


def _make_csv() -> bytes:
    """Build a generic CSV."""
    return b"url,vuln_type,severity,description\nhttps://target.example.com/login,XSS,high,Reflected XSS in search parameter\nhttps://target.example.com/api,SQLi,critical,SQL injection in id param\n"


def _make_native_json() -> bytes:
    """Build Erebos native JSON."""
    data = {
        "findings": [
            {
                "tool": "erebos",
                "severity": "HIGH",
                "title": "Open Redirect",
                "description": "Open redirect via url parameter",
                "target": "https://target.example.com/redirect",
                "phase_found": "vuln-scan",
            }
        ]
    }
    return json.dumps(data).encode("utf-8")


# ============================================================================
# SARIF Parser Tests
# ============================================================================


class TestSARIFParser:
    """Test SARIF 2.1 parsing."""

    def test_detect_sarif(self):
        content = _make_sarif()
        parser = SARIFParser()
        assert parser.detect(content) is True

    def test_detect_non_sarif(self):
        parser = SARIFParser()
        assert parser.detect(b'{"key": "value"}') is False

    def test_parse_happy_path(self):
        content = _make_sarif()
        parser = SARIFParser()
        findings = parser.parse(content)

        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "test-tool"
        assert f.severity == Severity.HIGH
        assert "SQL injection" in f.description
        assert f.target == "src/app.py"
        assert f.phase_found == Phase.VULN_SCAN

    def test_parse_multiple_results(self):
        results = [
            {
                "ruleId": "rule1",
                "level": "error",
                "message": {"text": "Finding 1"},
                "locations": [],
            },
            {
                "ruleId": "rule2",
                "level": "warning",
                "message": {"text": "Finding 2"},
                "locations": [],
            },
            {
                "ruleId": "rule3",
                "level": "note",
                "message": {"text": "Finding 3"},
                "locations": [],
            },
        ]
        content = _make_sarif(results=results)
        findings = SARIFParser().parse(content)

        assert len(findings) == 3
        assert findings[0].severity == Severity.HIGH
        assert findings[1].severity == Severity.MEDIUM
        assert findings[2].severity == Severity.LOW


# ============================================================================
# Fortify FPR Parser Tests
# ============================================================================


class TestFortifyParser:
    """Test Fortify FPR parsing."""

    def test_detect_fpr(self):
        content = _make_fortify_fpr()
        parser = FortifyParser()
        assert parser.detect(content) is True

    def test_detect_non_fpr(self):
        parser = FortifyParser()
        assert parser.detect(b"not a zip file") is False

    def test_parse_happy_path(self):
        content = _make_fortify_fpr()
        parser = FortifyParser()
        findings = parser.parse(content)

        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "fortify"
        assert f.severity == Severity.HIGH
        assert "SQL Injection" in f.title
        assert f.phase_found == Phase.VULN_SCAN


# ============================================================================
# Burp XML Parser Tests
# ============================================================================


class TestBurpParser:
    """Test Burp Suite XML parsing."""

    def test_detect_burp(self):
        content = _make_burp_xml()
        parser = BurpParser()
        assert parser.detect(content) is True

    def test_detect_non_burp(self):
        parser = BurpParser()
        assert parser.detect(b"<html><body>Not burp</body></html>") is False

    def test_parse_happy_path(self):
        content = _make_burp_xml()
        parser = BurpParser()
        findings = parser.parse(content)

        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "burp"
        assert f.severity == Severity.HIGH
        assert "SQL injection" in f.title
        assert f.target == "https://target.example.com/api/users"
        assert f.suggested_fix is not None
        assert "parameterized" in f.suggested_fix


# ============================================================================
# CSV Parser Tests
# ============================================================================


class TestCSVParser:
    """Test generic CSV parsing."""

    def test_detect_csv(self):
        content = _make_csv()
        parser = CSVParser()
        assert parser.detect(content) is True

    def test_detect_non_csv(self):
        parser = CSVParser()
        assert parser.detect(b'{"json": true}') is False

    def test_parse_happy_path(self):
        content = _make_csv()
        parser = CSVParser()
        findings = parser.parse(content)

        assert len(findings) == 2
        assert findings[0].title == "XSS"
        assert findings[0].severity == Severity.HIGH
        assert findings[1].title == "SQLi"
        assert findings[1].severity == Severity.CRITICAL


# ============================================================================
# Semgrep Parser Tests
# ============================================================================


class TestSemgrepParser:
    """Test Semgrep JSON parsing."""

    def test_detect_semgrep(self):
        content = _make_semgrep_json()
        parser = SemgrepParser()
        assert parser.detect(content) is True

    def test_parse_happy_path(self):
        content = _make_semgrep_json()
        parser = SemgrepParser()
        findings = parser.parse(content)

        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "semgrep"
        assert f.severity == Severity.HIGH
        assert "dangerous-system-call" in f.title
        assert f.cwe == "CWE-78"


# ============================================================================
# Native Parser Tests
# ============================================================================


class TestNativeParser:
    """Test Erebos native JSON parsing."""

    def test_detect_native(self):
        content = _make_native_json()
        parser = NativeParser()
        assert parser.detect(content) is True

    def test_parse_happy_path(self):
        content = _make_native_json()
        parser = NativeParser()
        findings = parser.parse(content)

        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "erebos"
        assert f.severity == Severity.HIGH
        assert f.title == "Open Redirect"


# ============================================================================
# Format Auto-Detection Tests
# ============================================================================


class TestAutoDetection:
    """Test format auto-detection in FindingsIngester."""

    def test_detect_sarif(self):
        ingester = FindingsIngester(allowlist=["*.example.com"])
        result = ingester.ingest_bytes(_make_sarif())
        assert result.format_detected == "sarif"

    def test_detect_burp(self):
        ingester = FindingsIngester(allowlist=["*.example.com"])
        result = ingester.ingest_bytes(_make_burp_xml())
        assert result.format_detected == "burp"

    def test_detect_semgrep(self):
        ingester = FindingsIngester(allowlist=["*.example.com"])
        result = ingester.ingest_bytes(_make_semgrep_json())
        assert result.format_detected == "semgrep"

    def test_detect_csv(self):
        ingester = FindingsIngester(allowlist=["*.example.com"])
        result = ingester.ingest_bytes(_make_csv())
        assert result.format_detected == "csv"

    def test_detect_native(self):
        ingester = FindingsIngester(allowlist=["*.example.com"])
        result = ingester.ingest_bytes(_make_native_json())
        assert result.format_detected == "native"

    def test_format_hint_overrides_detection(self):
        ingester = FindingsIngester(allowlist=["*.example.com"])
        # Use CSV content but hint as CSV explicitly
        result = ingester.ingest_bytes(_make_csv(), format_hint="csv")
        assert result.format_detected == "csv"

    def test_unknown_format(self):
        ingester = FindingsIngester(allowlist=["*.example.com"])
        result = ingester.ingest_bytes(b"random binary data \x00\x01\x02")
        assert result.format_detected == "unknown"
        assert result.total_parsed == 0


# ============================================================================
# Security: INJ-01 — HTML Stripping Tests
# ============================================================================


class TestINJ01Sanitization:
    """VT-Spec INJ-01: Sanitize all ingested finding fields at parse time."""

    def test_strip_html_tags(self):
        result = sanitize_text("<b>bold</b> text <i>italic</i>")
        assert "<b>" not in result
        assert "<i>" not in result
        assert "bold" in result
        assert "italic" in result

    def test_strip_script_tags(self):
        result = sanitize_text('Before <script>alert("xss")</script> After')
        assert "<script>" not in result
        assert "alert" not in result
        assert "Before" in result
        assert "After" in result

    def test_strip_event_handlers(self):
        result = sanitize_text('Text onerror="alert(1)" more')
        assert "onerror" not in result
        assert "alert" not in result

    def test_strip_javascript_uri(self):
        result = sanitize_text("Click javascript:alert(1) here")
        assert "javascript:" not in result

    def test_remove_null_bytes(self):
        result = sanitize_text("hello\x00world")
        assert "\x00" not in result
        assert "helloworld" in result

    def test_remove_control_characters(self):
        result = sanitize_text("test\x01\x02\x03data")
        assert "\x01" not in result
        assert "testdata" in result

    def test_truncate_long_text(self):
        long_text = "A" * 5000
        result = sanitize_text(long_text, max_length=200)
        assert len(result) == 200

    def test_sarif_with_malicious_description(self):
        """INJ-01: Malicious content in SARIF should be stripped."""
        results = [
            {
                "ruleId": "test",
                "level": "error",
                "message": {
                    "text": '<script>alert("xss")</script>SQL injection found <img onerror="hack()" src=x>'
                },
                "locations": [],
            }
        ]
        content = _make_sarif(results=results)
        findings = SARIFParser().parse(content)

        assert len(findings) == 1
        desc = findings[0].description
        assert "<script>" not in desc
        assert "alert" not in desc
        assert "<img" not in desc
        assert "onerror" not in desc
        assert "SQL injection found" in desc

    def test_burp_with_malicious_name(self):
        """INJ-01: Malicious content in Burp XML should be stripped."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<issues>
  <issue>
    <name>&lt;script&gt;alert(1)&lt;/script&gt;XSS</name>
    <host>https://target.example.com</host>
    <path>/test</path>
    <severity>High</severity>
    <confidence>Certain</confidence>
  </issue>
</issues>"""
        findings = BurpParser().parse(xml.encode("utf-8"))
        assert len(findings) == 1
        assert "<script>" not in findings[0].title
        assert "alert" not in findings[0].title


# ============================================================================
# Security: SCOPE-01 — Allowlist Validation Tests
# ============================================================================


class TestSCOPE01AllowlistValidation:
    """VT-Spec SCOPE-01: All ingested finding URLs must pass AllowlistValidator."""

    def test_accept_in_scope_findings(self):
        """Findings with in-scope URLs are accepted."""
        ingester = FindingsIngester(allowlist=["target.example.com"])
        result = ingester.ingest_bytes(_make_burp_xml())
        assert result.accepted == 1
        assert result.rejected == 0

    def test_reject_out_of_scope_findings(self):
        """Findings with out-of-scope URLs are rejected."""
        ingester = FindingsIngester(allowlist=["safe.example.com"])
        # Burp XML has target.example.com which is NOT in allowlist
        result = ingester.ingest_bytes(_make_burp_xml())
        assert result.accepted == 0
        assert result.rejected == 1

    def test_sast_findings_without_url_allowed(self):
        """SAST findings without URLs are always allowed (no scope to check)."""
        ingester = FindingsIngester(allowlist=["safe.example.com"])
        # SARIF findings have file paths, not URLs
        result = ingester.ingest_bytes(_make_sarif())
        assert result.accepted == 1
        assert result.rejected == 0

    def test_wildcard_allowlist(self):
        """Wildcard allowlist entries match subdomains."""
        ingester = FindingsIngester(allowlist=["*.example.com"])
        result = ingester.ingest_bytes(_make_burp_xml())
        assert result.accepted == 1

    def test_csv_out_of_scope_rejected(self):
        """CSV findings with out-of-scope URLs are rejected."""
        ingester = FindingsIngester(allowlist=["other-domain.com"])
        result = ingester.ingest_bytes(_make_csv())
        # CSV has target.example.com which is NOT in allowlist
        assert result.rejected == 2
        assert result.accepted == 0

    def test_mixed_scope_results(self):
        """Mix of in-scope and out-of-scope findings."""
        csv_content = b"url,vuln_type,severity,description\nhttps://allowed.com/x,XSS,high,Test\nhttps://forbidden.com/y,SQLi,high,Test\n"
        ingester = FindingsIngester(allowlist=["allowed.com"])
        result = ingester.ingest_bytes(csv_content)
        assert result.accepted == 1
        assert result.rejected == 1


# ============================================================================
# Performance: Large File Handling (NF1: 10k findings < 5s)
# ============================================================================


class TestPerformance:
    """Test ingestion performance with large finding sets."""

    def test_10k_sarif_findings_performance(self):
        """NF1: 10,000 findings should process in under 5 seconds."""
        results = []
        for i in range(10_000):
            results.append(
                {
                    "ruleId": f"rule-{i}",
                    "level": "warning",
                    "message": {"text": f"Finding number {i}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"src/file{i}.py"},
                                "region": {"startLine": i},
                            }
                        }
                    ],
                }
            )

        content = _make_sarif(results=results)
        ingester = FindingsIngester(allowlist=["*.example.com"])

        start = time.time()
        result = ingester.ingest_bytes(content)
        elapsed = time.time() - start

        assert result.total_parsed == 10_000
        assert result.accepted == 10_000  # SAST findings, no URL to check
        assert elapsed < 5.0, f"Ingestion took {elapsed:.2f}s, expected < 5s"


# ============================================================================
# FactGraph Integration Tests
# ============================================================================


class TestFactGraphIntegration:
    """Test that findings are injected into FactGraph."""

    def test_inject_findings_into_fact_graph(self):
        """Accepted findings should be added to FactGraph as vulnerability facts."""
        from erebos.agents.fact_graph import FactGraph, FactType

        graph = FactGraph()
        ingester = FindingsIngester(
            allowlist=["target.example.com"], fact_graph=graph
        )
        result = ingester.ingest_bytes(_make_burp_xml())

        assert result.accepted == 1
        # Check that a fact was added
        facts = graph.get_facts(fact_type=FactType.VULNERABILITY)
        assert len(facts) == 1
        assert facts[0].data["tool"] == "burp"
        assert facts[0].source_agent == "ingestion"

    def test_rejected_findings_not_in_fact_graph(self):
        """Rejected findings should NOT be added to FactGraph."""
        from erebos.agents.fact_graph import FactGraph, FactType

        graph = FactGraph()
        ingester = FindingsIngester(
            allowlist=["other-domain.com"], fact_graph=graph
        )
        result = ingester.ingest_bytes(_make_burp_xml())

        assert result.rejected == 1
        facts = graph.get_facts(fact_type=FactType.VULNERABILITY)
        assert len(facts) == 0
