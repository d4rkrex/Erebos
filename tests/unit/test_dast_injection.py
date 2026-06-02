"""Unit tests for DastInjectionExecutor."""

import asyncio

import pytest
import respx

from erebos.executors.dast_injection import (
    DastInjectionExecutor,
    InjectionType,
    _SQLI_REGEX_PATTERNS,
)
from erebos.core.finding import Phase, Severity


# ---------------------------------------------------------------------------
# Helper to run async executor tests synchronously
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine in a new event loop (compatible with pytest sync)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# 1. test_sqli_regex_detection
# ---------------------------------------------------------------------------


def test_sqli_regex_detection():
    """Response containing MySQL error string -> SQLi detected via regex."""
    error_body = "You have an error in your SQL syntax near 'x' at line 1 in MySQL server"

    executor = DastInjectionExecutor(
        timeout=5.0,
        max_concurrent=1,
        injection_types=[InjectionType.SQLI],
    )

    with respx.mock(assert_all_mocked=False) as mock:
        mock.route(host="target.local").respond(200, text=error_body)

        findings = _run(executor.run(
            target="http://target.local/search",
            parameters=["q"],
            login_endpoints=[],
            traversal_paths=[],
        ))

    sqli_findings = [f for f in findings if f.cwe == "CWE-89"]
    assert len(sqli_findings) >= 1
    assert any("SQL Injection" in f.title for f in sqli_findings)
    assert sqli_findings[0].severity == Severity.HIGH
    assert sqli_findings[0].phase_found == Phase.VULN_SCAN


# ---------------------------------------------------------------------------
# 2. test_sqli_sqlite_detection
# ---------------------------------------------------------------------------


def test_sqli_sqlite_detection():
    """Response with SQLITE_ERROR or SequelizeDatabaseError -> detected."""
    for error_text in ["SQLITE_ERROR: no such table", "SequelizeDatabaseError: column not found"]:
        executor = DastInjectionExecutor(
            timeout=5.0,
            max_concurrent=1,
            injection_types=[InjectionType.SQLI],
        )

        with respx.mock(assert_all_mocked=False) as mock:
            mock.route(host="target.local").respond(200, text=error_text)

            findings = _run(executor.run(
                target="http://target.local/api",
                parameters=["id"],
                login_endpoints=[],
                traversal_paths=[],
            ))

        sqli_findings = [f for f in findings if f.cwe == "CWE-89"]
        assert len(sqli_findings) >= 1, f"Expected detection for: {error_text}"


# ---------------------------------------------------------------------------
# 3. test_sqli_no_false_positive
# ---------------------------------------------------------------------------


def test_sqli_no_false_positive():
    """Normal response 'Welcome to the app' -> no SQLi detection."""
    normal_body = "Welcome to the app. Everything is working fine."

    executor = DastInjectionExecutor(
        timeout=5.0,
        max_concurrent=1,
        injection_types=[InjectionType.SQLI],
    )

    with respx.mock(assert_all_mocked=False) as mock:
        # Return identical responses for all requests (defeats boolean-blind too)
        mock.route(host="target.local").respond(200, text=normal_body)

        findings = _run(executor.run(
            target="http://target.local/page",
            parameters=["q"],
            login_endpoints=[],
            traversal_paths=[],
        ))

    sqli_findings = [f for f in findings if f.cwe == "CWE-89"]
    assert len(sqli_findings) == 0, f"False positive detected: {sqli_findings}"


# ---------------------------------------------------------------------------
# 4. test_auth_bypass_detects_jwt
# ---------------------------------------------------------------------------


def test_auth_bypass_detects_jwt():
    """POST /login returning JWT token -> auth bypass Finding created."""
    jwt_response = '{"authentication":{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"}}'

    executor = DastInjectionExecutor(
        timeout=5.0,
        max_concurrent=1,
        injection_types=[InjectionType.AUTH_BYPASS],
    )

    with respx.mock(assert_all_mocked=False) as mock:
        mock.route(method="POST", host="target.local").respond(200, text=jwt_response)

        findings = _run(executor.run(
            target="http://target.local",
            parameters=[],
            login_endpoints=["/login"],
        ))

    assert len(findings) >= 1
    bypass_finding = findings[0]
    assert "Auth Bypass" in bypass_finding.title
    assert bypass_finding.severity == Severity.CRITICAL
    assert bypass_finding.phase_found == Phase.VULN_SCAN
    assert bypass_finding.evidence.url == "http://target.local/login"
    assert "eyJ" in bypass_finding.evidence.output


# ---------------------------------------------------------------------------
# 5. test_auth_bypass_no_jwt
# ---------------------------------------------------------------------------


def test_auth_bypass_no_jwt():
    """POST /login returning 401 -> no auth bypass finding."""
    executor = DastInjectionExecutor(
        timeout=5.0,
        max_concurrent=1,
        injection_types=[InjectionType.AUTH_BYPASS],
    )

    with respx.mock(assert_all_mocked=False) as mock:
        mock.route(method="POST", host="target.local").respond(
            401, text='{"error":"Invalid credentials"}'
        )

        findings = _run(executor.run(
            target="http://target.local",
            parameters=[],
            login_endpoints=["/login"],
        ))

    assert len(findings) == 0


# ---------------------------------------------------------------------------
# 6. test_path_traversal_detection
# ---------------------------------------------------------------------------


def test_path_traversal_detection():
    """Response to null-byte path containing 'root:x:0' -> traversal detected."""
    passwd_content = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    ) * 2

    executor = DastInjectionExecutor(
        timeout=5.0,
        max_concurrent=1,
        injection_types=[InjectionType.TRAVERSAL],
    )

    with respx.mock(assert_all_mocked=False) as mock:
        mock.route(host="target.local").respond(200, text=passwd_content)

        findings = _run(executor.run(
            target="http://target.local",
            parameters=["file"],
            traversal_paths=["/ftp/file%2500.md"],
        ))

    traversal_findings = [f for f in findings if f.cwe == "CWE-22"]
    assert len(traversal_findings) >= 1
    assert any("Path Traversal" in f.title for f in traversal_findings)
    assert traversal_findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# 7. test_xss_detection
# ---------------------------------------------------------------------------


def test_xss_detection():
    """Response containing reflected XSS payload -> XSS detected."""
    xss_body = '<html><body>Search results for: <script>alert(1)</script></body></html>'

    executor = DastInjectionExecutor(
        timeout=5.0,
        max_concurrent=1,
        injection_types=[InjectionType.XSS],
    )

    with respx.mock(assert_all_mocked=False) as mock:
        mock.route(host="target.local").respond(200, text=xss_body)

        findings = _run(executor.run(
            target="http://target.local/search",
            parameters=["q"],
        ))

    xss_findings = [f for f in findings if f.cwe == "CWE-79"]
    assert len(xss_findings) >= 1
    assert any("XSS" in f.title or "Cross-Site" in f.title for f in xss_findings)
    assert xss_findings[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# 8. test_injection_types_filter
# ---------------------------------------------------------------------------


def test_injection_types_filter():
    """Only specified injection_types are tested; others are skipped."""
    # Configure executor with ONLY XSS - SQL errors in response should NOT trigger findings
    executor = DastInjectionExecutor(
        timeout=5.0,
        max_concurrent=1,
        injection_types=[InjectionType.XSS],  # Only XSS
    )

    sql_error_body = "You have an error in your SQL syntax near 'x' - MySQL"

    with respx.mock(assert_all_mocked=False) as mock:
        mock.route(host="target.local").respond(200, text=sql_error_body)

        findings = _run(executor.run(
            target="http://target.local/search",
            parameters=["q"],
            login_endpoints=[],
            traversal_paths=[],
        ))

    # No SQLi findings since only XSS type is enabled
    sqli_findings = [f for f in findings if f.cwe == "CWE-89"]
    assert len(sqli_findings) == 0

    # XSS won't match either since response doesn't contain XSS markers
    xss_findings = [f for f in findings if f.cwe == "CWE-79"]
    assert len(xss_findings) == 0


# ---------------------------------------------------------------------------
# Regex pattern unit tests (pure logic, no HTTP)
# ---------------------------------------------------------------------------


class TestSqliRegexPatterns:
    """Direct tests for _SQLI_REGEX_PATTERNS without HTTP mocking."""

    def test_mysql_syntax_error(self):
        text = "You have an error in your SQL syntax near '' at line 1 in MySQL server"
        assert any(p.search(text) for p in _SQLI_REGEX_PATTERNS)

    def test_postgresql_error(self):
        text = "PostgreSQL query failed: ERROR: unterminated quoted string"
        assert any(p.search(text) for p in _SQLI_REGEX_PATTERNS)

    def test_oracle_error(self):
        text = "ORA-01756: quoted string not properly terminated"
        assert any(p.search(text) for p in _SQLI_REGEX_PATTERNS)

    def test_sqlite_error(self):
        text = "SQLITE_ERROR: near 'DROP': syntax error"
        assert any(p.search(text) for p in _SQLI_REGEX_PATTERNS)

    def test_sequelize_error(self):
        text = "SequelizeDatabaseError: column 'x' does not exist"
        assert any(p.search(text) for p in _SQLI_REGEX_PATTERNS)

    def test_clean_response_no_match(self):
        text = "Welcome to our application. Search results below."
        assert not any(p.search(text) for p in _SQLI_REGEX_PATTERNS)

    def test_dynamic_sql_error(self):
        text = "Dynamic SQL Error: unexpected token"
        assert any(p.search(text) for p in _SQLI_REGEX_PATTERNS)
