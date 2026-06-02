"""Tests for markdown reporting with recovery metadata."""

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.reporting.markdown import MarkdownReportBuilder


def test_markdown_report_includes_recovery_metadata(tmp_path):
    finding = Finding(
        tool="rustscan",
        severity=Severity.INFO,
        title="Recovered Port Scan",
        description="Port scan completed via fallback tool.",
        evidence=FindingEvidence(url="https://example.com:443"),
        phase_found=Phase.RECON,
        degraded=True,
        fallback_source="rustscan",
    )
    builder = MarkdownReportBuilder(
        target="example.com",
        scan_id="scan-1",
        phase_artifacts={
            "tool_status": [
                {
                    "phase": "vuln-scan",
                    "tool": "sqlmap",
                    "status": "success",
                    "exit_code": 0,
                    "fallback_source": None,
                    "error_types": [],
                    "message": "",
                },
                {
                    "phase": "vuln-scan",
                    "tool": "nikto",
                    "status": "skipped",
                    "exit_code": 75,
                    "fallback_source": "skip",
                    "error_types": ["timeout"],
                    "message": "Coverage skipped after recovery exhaustion: timed out",
                },
            ],
            "fallback_events": [
                {
                    "tool": "masscan",
                    "fallback_tool": "rustscan",
                    "error_type": "permission_denied",
                    "recovery_strategy": "fallback",
                    "success": True,
                }
            ],
        },
    )

    report_path = builder.build([finding], output_dir=str(tmp_path))
    content = report_path.read_text()

    assert "Recovery Summary" in content
    assert "Degraded Findings" in content
    assert "Vulnerability Scan Coverage" in content
    assert "status=`skipped`" in content
    assert "`sqlmap` status=`success`" in content
    assert "Fallback Source:" in content
    assert "rustscan" in content


def test_markdown_report_dast_section(tmp_path):
    """DAST findings are grouped into a dedicated section by stage."""
    dast_finding_fast = Finding(
        tool="dast-injection",
        severity=Severity.CRITICAL,
        title="SQL Injection Auth Bypass at /rest/user/login",
        description="SQL injection via auth bypass, token extracted for further tests.",
        target="https://target/rest/user/login",
        evidence=FindingEvidence(
            url="https://target/rest/user/login",
            payload="' OR 1=1 --",
            output='{"authentication":{"token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig123"}}',
            http_banner="POST",
        ),
        phase_found=Phase.VULN_SCAN,
    )
    dast_finding_api = Finding(
        tool="api-security",
        severity=Severity.HIGH,
        title="Potential IDOR at /Products/1",
        description="IDOR allows access to other users' products via token reuse.",
        target="https://target/api/Products/1",
        evidence=FindingEvidence(
            url="https://target/api/Products/1",
            payload='{"id": 999}',
            output='{"id":999,"name":"secret product","price":0}',
            http_banner="GET",
        ),
        phase_found=Phase.VULN_SCAN,
    )
    # Standard non-DAST finding
    standard_finding = Finding(
        tool="nikto",
        severity=Severity.LOW,
        title="Server Version Disclosure",
        description="The server discloses version info.",
        evidence=FindingEvidence(url="https://target/"),
        phase_found=Phase.RECON,
    )

    builder = MarkdownReportBuilder(
        target="target",
        scan_id="scan-dast-1",
        phase_artifacts={
            "dast_attack_chains": [
                {
                    "source": "JWT extracted from auth bypass",
                    "usage": "authenticated API testing",
                    "finding_count": 16,
                }
            ]
        },
    )

    report_path = builder.build(
        [dast_finding_fast, dast_finding_api, standard_finding], output_dir=str(tmp_path)
    )
    content = report_path.read_text()

    # DAST section exists
    assert "## DAST Findings (2 total)" in content

    # Attack Chain subsection
    assert "### Attack Chain" in content
    assert "🔗 JWT extracted from auth bypass → used for authenticated API testing (16 findings)" in content

    # Stage groupings
    assert "### Stage: Fast Scan (1 findings)" in content
    assert "### Stage: API Security (1 findings)" in content

    # Severity badges
    assert "🔴 CRITICAL" in content
    assert "🟠 HIGH" in content

    # JWT token redaction in evidence
    assert "eyJ" not in content
    assert "[REDACTED]" in content

    # Standard finding still in its normal section, not in DAST section
    assert "Server Version Disclosure" in content
    assert "## LOW Findings (1)" in content

    # Evidence truncation (these are short, so no truncation, but check presence)
    assert "**Payload:**" in content
    assert "**Response:**" in content

    # Total count includes DAST findings
    assert "**Total Findings:** 3" in content


def test_markdown_report_dast_evidence_truncation(tmp_path):
    """DAST evidence output is truncated to 200 chars."""
    long_output = "A" * 500
    dast_finding = Finding(
        tool="nuclei-dast",
        severity=Severity.MEDIUM,
        title="XSS Reflected",
        description="Reflected XSS in search parameter.",
        target="https://target/search",
        evidence=FindingEvidence(
            url="https://target/search?q=<script>",
            payload="<script>alert(1)</script>",
            output=long_output,
        ),
        phase_found=Phase.VULN_SCAN,
    )

    builder = MarkdownReportBuilder(target="target", scan_id="scan-trunc")
    report_path = builder.build([dast_finding], output_dir=str(tmp_path))
    content = report_path.read_text()

    # Output should be truncated - the full 500 chars should NOT appear
    assert long_output not in content
    # The truncated version (200 chars + ellipsis) should appear
    assert "A" * 200 + "…" in content
    assert "### Stage: Nuclei Deep Scan (1 findings)" in content
