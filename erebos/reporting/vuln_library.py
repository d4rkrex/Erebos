"""Vulnerability library with CWE-keyed templates for report enrichment.

Provides standardized descriptions, remediations, and CVSS scores for common
vulnerability types. Inspired by VulnForce's vulnerability library pattern.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from erebos.core.finding import Finding


@dataclass
class VulnTemplate:
    """Reusable vulnerability template keyed by CWE."""

    cwe: str
    title: str
    description: str
    remediation: str
    severity_default: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_base: float
    owasp_category: str  # e.g., "A03:2021 Injection"
    wstg_id: Optional[str] = None  # e.g., "WSTG-INPV-05"
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


# Core vulnerability templates
_TEMPLATES: Dict[str, VulnTemplate] = {
    "CWE-89": VulnTemplate(
        cwe="CWE-89",
        title="SQL Injection",
        description=(
            "The application constructs SQL queries using user-supplied input without "
            "proper sanitization or parameterization. An attacker can inject arbitrary SQL "
            "commands to read, modify, or delete database contents."
        ),
        remediation=(
            "1. Use parameterized queries (prepared statements) for ALL database interactions.\n"
            "2. Apply input validation with allowlists for expected formats.\n"
            "3. Use an ORM that handles query parameterization.\n"
            "4. Apply least-privilege database accounts.\n"
            "5. Enable WAF rules for SQL injection patterns."
        ),
        severity_default="HIGH",
        cvss_base=8.6,
        owasp_category="A03:2021 Injection",
        wstg_id="WSTG-INPV-05",
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        tags=["injection", "database", "input-validation"],
    ),
    "CWE-79": VulnTemplate(
        cwe="CWE-79",
        title="Cross-Site Scripting (XSS)",
        description=(
            "The application includes user-supplied data in web page output without proper "
            "encoding or validation. An attacker can inject client-side scripts to steal "
            "session tokens, redirect users, or modify page content."
        ),
        remediation=(
            "1. Apply context-aware output encoding (HTML, JS, URL, CSS contexts).\n"
            "2. Implement Content-Security-Policy headers.\n"
            "3. Use modern frameworks with built-in XSS protection (React, Angular).\n"
            "4. Validate and sanitize input on the server side.\n"
            "5. Use HttpOnly and Secure flags on session cookies."
        ),
        severity_default="MEDIUM",
        cvss_base=6.1,
        owasp_category="A03:2021 Injection",
        wstg_id="WSTG-INPV-01",
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        tags=["injection", "client-side", "xss"],
    ),
    "CWE-22": VulnTemplate(
        cwe="CWE-22",
        title="Path Traversal",
        description=(
            "The application uses user-supplied input to construct file paths without "
            "proper validation. An attacker can traverse directory boundaries to access "
            "arbitrary files on the server, including sensitive configuration and credentials."
        ),
        remediation=(
            "1. Validate file paths against a strict allowlist of permitted directories.\n"
            "2. Use canonicalization to resolve paths before validation.\n"
            "3. Run the application with minimal file system permissions.\n"
            "4. Implement chroot or container isolation.\n"
            "5. Never pass user input directly to file system APIs."
        ),
        severity_default="HIGH",
        cvss_base=7.5,
        owasp_category="A01:2021 Broken Access Control",
        wstg_id="WSTG-INPV-09",
        references=[
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
        tags=["file-access", "path-traversal", "lfi"],
    ),
    "CWE-78": VulnTemplate(
        cwe="CWE-78",
        title="OS Command Injection",
        description=(
            "The application passes user-supplied data to system shell commands without "
            "proper sanitization. An attacker can execute arbitrary operating system "
            "commands with the privileges of the application."
        ),
        remediation=(
            "1. Avoid calling OS commands from application code entirely.\n"
            "2. If unavoidable, use language-native APIs instead of shell commands.\n"
            "3. Use subprocess with shell=False and argument lists.\n"
            "4. Apply strict input validation (alphanumeric allowlists).\n"
            "5. Run the application in a sandboxed environment."
        ),
        severity_default="CRITICAL",
        cvss_base=9.8,
        owasp_category="A03:2021 Injection",
        wstg_id="WSTG-INPV-12",
        references=[
            "https://owasp.org/www-community/attacks/Command_Injection",
        ],
        tags=["injection", "rce", "command-injection"],
    ),
    "CWE-639": VulnTemplate(
        cwe="CWE-639",
        title="Insecure Direct Object Reference (IDOR)",
        description=(
            "The application exposes internal object references (IDs, keys) in API "
            "endpoints without verifying that the requesting user is authorized to access "
            "the referenced object. Attackers can enumerate and access other users' data."
        ),
        remediation=(
            "1. Implement object-level authorization checks on every request.\n"
            "2. Use indirect references (UUIDs) instead of sequential IDs.\n"
            "3. Verify resource ownership in the authorization middleware.\n"
            "4. Log and alert on access pattern anomalies.\n"
            "5. Apply row-level security at the database level."
        ),
        severity_default="HIGH",
        cvss_base=7.5,
        owasp_category="A01:2021 Broken Access Control",
        wstg_id="WSTG-ATHZ-04",
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
        tags=["authorization", "idor", "bola", "api"],
    ),
    "CWE-915": VulnTemplate(
        cwe="CWE-915",
        title="Mass Assignment",
        description=(
            "The API binds client-provided data to internal object properties without "
            "filtering. Attackers can modify privileged fields (role, permissions, balance) "
            "that should not be user-assignable."
        ),
        remediation=(
            "1. Use explicit allowlists for bindable properties.\n"
            "2. Never bind request data directly to database models.\n"
            "3. Use DTOs/schemas that define exactly which fields are writable.\n"
            "4. Implement server-side property filtering.\n"
            "5. Test with privileged field injection in CI/CD."
        ),
        severity_default="HIGH",
        cvss_base=7.2,
        owasp_category="A04:2021 Insecure Design",
        wstg_id=None,
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
        ],
        tags=["api", "mass-assignment", "privilege-escalation"],
    ),
    "CWE-200": VulnTemplate(
        cwe="CWE-200",
        title="Information Exposure",
        description=(
            "The application exposes sensitive information to actors not authorized to "
            "access it. This includes debug information, stack traces, internal paths, "
            "or schema details exposed via error messages or introspection endpoints."
        ),
        remediation=(
            "1. Disable debug mode and verbose error messages in production.\n"
            "2. Disable GraphQL introspection in production.\n"
            "3. Implement custom error handlers that return generic messages.\n"
            "4. Remove server version headers.\n"
            "5. Review API responses for unintended data leakage."
        ),
        severity_default="MEDIUM",
        cvss_base=5.3,
        owasp_category="A05:2021 Security Misconfiguration",
        wstg_id="WSTG-INFO-02",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
        ],
        tags=["information-disclosure", "misconfiguration"],
    ),
    "CWE-347": VulnTemplate(
        cwe="CWE-347",
        title="JWT Signature Bypass",
        description=(
            "The application does not properly verify JWT token signatures, accepting "
            "tokens with algorithm 'none' or weak signing keys. Attackers can forge valid "
            "tokens to impersonate any user."
        ),
        remediation=(
            "1. Always validate JWT signatures with strong algorithms (RS256, ES256).\n"
            "2. Reject tokens with alg:none.\n"
            "3. Use an allowlist of accepted algorithms.\n"
            "4. Implement token expiration and rotation.\n"
            "5. Use a well-maintained JWT library."
        ),
        severity_default="CRITICAL",
        cvss_base=9.1,
        owasp_category="A07:2021 Identification and Authentication Failures",
        wstg_id="WSTG-SESS-10",
        references=[
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
        tags=["authentication", "jwt", "token", "crypto"],
    ),
    "CWE-770": VulnTemplate(
        cwe="CWE-770",
        title="Missing Rate Limiting",
        description=(
            "The API does not implement rate limiting on sensitive endpoints, enabling "
            "brute-force attacks on authentication, credential stuffing, and resource "
            "exhaustion."
        ),
        remediation=(
            "1. Implement rate limiting on authentication endpoints.\n"
            "2. Use progressive delays (exponential backoff) after failed attempts.\n"
            "3. Implement account lockout after N failed attempts.\n"
            "4. Add CAPTCHA after suspicious patterns.\n"
            "5. Monitor and alert on abnormal request volumes."
        ),
        severity_default="MEDIUM",
        cvss_base=5.3,
        owasp_category="A04:2021 Insecure Design",
        wstg_id="WSTG-BUSL-05",
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        ],
        tags=["rate-limiting", "brute-force", "dos", "api"],
    ),
    "CWE-918": VulnTemplate(
        cwe="CWE-918",
        title="Server-Side Request Forgery (SSRF)",
        description=(
            "The application makes HTTP requests to URLs derived from user input without "
            "proper validation. Attackers can access internal services, cloud metadata "
            "endpoints, or exfiltrate data via the server."
        ),
        remediation=(
            "1. Validate and sanitize all user-supplied URLs.\n"
            "2. Block requests to RFC1918, loopback, and link-local addresses.\n"
            "3. Use allowlists for permitted destination hosts.\n"
            "4. Disable HTTP redirects or validate redirect targets.\n"
            "5. Use network segmentation to isolate application servers."
        ),
        severity_default="HIGH",
        cvss_base=7.5,
        owasp_category="A10:2021 Server-Side Request Forgery",
        wstg_id="WSTG-INPV-19",
        references=[
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        ],
        tags=["ssrf", "network", "internal-access"],
    ),
}


def get_template(cwe: str) -> Optional[VulnTemplate]:
    """Look up a vulnerability template by CWE ID."""
    return _TEMPLATES.get(cwe)


def get_all_templates() -> Dict[str, VulnTemplate]:
    """Return all vulnerability templates."""
    return _TEMPLATES.copy()


def enrich_finding(finding: "Finding") -> "Finding":
    """Enrich a finding with vulnerability library data if CWE matches."""
    if not finding.cwe:
        return finding

    template = get_template(finding.cwe)
    if not template:
        return finding

    # Enrich with suggested fix from library if not already set
    if not finding.suggested_fix:
        finding.suggested_fix = template.remediation

    # Set CVSS if not already scored
    if finding.cvss is None:
        finding.cvss = template.cvss_base

    return finding


def get_templates_by_owasp(category: str) -> List[VulnTemplate]:
    """Find all templates matching an OWASP category."""
    return [t for t in _TEMPLATES.values() if category.lower() in t.owasp_category.lower()]


def get_templates_by_tag(tag: str) -> List[VulnTemplate]:
    """Find all templates matching a tag."""
    return [t for t in _TEMPLATES.values() if tag in t.tags]
