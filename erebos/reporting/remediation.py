"""CWE-based remediation playbook for Erebos reporting.

VT-Spec R6: Professional Reporting — remediation section grouped by CWE.
"""

from __future__ import annotations

from typing import Dict, List, Optional


# Top 20+ CWEs with remediation guidance
REMEDIATION_DB: Dict[str, Dict[str, object]] = {
    "CWE-89": {
        "title": "SQL Injection",
        "short": "Use parameterized queries/prepared statements",
        "detailed": (
            "Replace all dynamic SQL construction with parameterized queries or "
            "prepared statements. Use an ORM where possible. Apply input validation "
            "as defense-in-depth. Never concatenate user input into SQL strings."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ],
    },
    "CWE-79": {
        "title": "Cross-Site Scripting (XSS)",
        "short": "Encode output contextually; use CSP headers",
        "detailed": (
            "Apply context-appropriate output encoding (HTML entity, JavaScript, URL, CSS). "
            "Use a templating engine with auto-escaping enabled. Implement Content-Security-Policy "
            "headers to mitigate impact. Sanitize HTML input with a proven library (DOMPurify)."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ],
    },
    "CWE-78": {
        "title": "OS Command Injection",
        "short": "Avoid shell commands; use language APIs with strict input validation",
        "detailed": (
            "Avoid executing OS commands with user-controlled input. Use language-native "
            "APIs instead of shell commands. If shell execution is required, use allowlists "
            "for arguments and never pass raw user input. Use subprocess with shell=False."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
        ],
    },
    "CWE-22": {
        "title": "Path Traversal",
        "short": "Canonicalize paths and validate against allowlist",
        "detailed": (
            "Resolve file paths to their canonical form and verify they remain within "
            "the expected directory. Use allowlists of permitted filenames. Never use "
            "user input directly in file path construction."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
        ],
    },
    "CWE-287": {
        "title": "Improper Authentication",
        "short": "Implement multi-factor authentication and secure session management",
        "detailed": (
            "Use proven authentication frameworks. Implement MFA for sensitive operations. "
            "Enforce strong password policies. Use secure session tokens with proper "
            "expiration. Protect against brute force with rate limiting and account lockout."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
        ],
    },
    "CWE-862": {
        "title": "Missing Authorization",
        "short": "Enforce authorization checks on every request",
        "detailed": (
            "Implement authorization checks at the controller/handler level for every "
            "endpoint. Use role-based or attribute-based access control. Deny by default. "
            "Verify object-level authorization (IDOR prevention)."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
        ],
    },
    "CWE-200": {
        "title": "Information Exposure",
        "short": "Remove sensitive data from error messages and responses",
        "detailed": (
            "Configure custom error pages that do not expose stack traces, database "
            "errors, or internal paths. Sanitize API responses to exclude internal "
            "identifiers. Implement proper logging that separates user-visible and "
            "internal error details."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
        ],
    },
    "CWE-352": {
        "title": "Cross-Site Request Forgery (CSRF)",
        "short": "Implement anti-CSRF tokens on all state-changing operations",
        "detailed": (
            "Use synchronizer token pattern or double-submit cookie for CSRF protection. "
            "Verify Origin/Referer headers. Use SameSite cookie attribute. Require "
            "re-authentication for sensitive operations."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
        ],
    },
    "CWE-918": {
        "title": "Server-Side Request Forgery (SSRF)",
        "short": "Validate and restrict outbound request destinations",
        "detailed": (
            "Allowlist permitted domains/IPs for outbound requests. Block requests to "
            "internal/private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, "
            "192.168.0.0/16, 169.254.0.0/16). Disable HTTP redirects or validate "
            "redirect targets. Use a network-level egress firewall."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
        ],
    },
    "CWE-502": {
        "title": "Deserialization of Untrusted Data",
        "short": "Avoid native deserialization; use safe data formats (JSON)",
        "detailed": (
            "Never deserialize untrusted data with native serialization (pickle, Java "
            "ObjectInputStream). Use JSON or other safe formats. If native deserialization "
            "is required, implement strict type allowlists and integrity checks."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
        ],
    },
    "CWE-611": {
        "title": "XML External Entity (XXE) Injection",
        "short": "Disable external entity processing in XML parsers",
        "detailed": (
            "Disable DTD processing and external entity resolution in all XML parsers. "
            "Use defusedxml in Python. Prefer JSON over XML where possible. If XML is "
            "required, use the most restrictive parser configuration available."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
        ],
    },
    "CWE-434": {
        "title": "Unrestricted File Upload",
        "short": "Validate file type, size, and store outside webroot",
        "detailed": (
            "Validate file extensions against an allowlist. Check MIME types and magic "
            "bytes. Limit file sizes. Store uploads outside the webroot. Generate random "
            "filenames. Scan uploaded files for malware. Set proper Content-Type headers "
            "when serving."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
        ],
    },
    "CWE-319": {
        "title": "Cleartext Transmission of Sensitive Data",
        "short": "Enforce TLS/HTTPS for all sensitive communications",
        "detailed": (
            "Enforce HTTPS with HSTS headers (min 1 year, includeSubDomains). Use "
            "TLS 1.2+ with strong cipher suites. Redirect all HTTP to HTTPS. Mark "
            "cookies as Secure. Use certificate pinning for mobile apps."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
        ],
    },
    "CWE-306": {
        "title": "Missing Authentication for Critical Function",
        "short": "Require authentication for all sensitive endpoints",
        "detailed": (
            "Identify all critical functions and enforce authentication. Use middleware "
            "or decorators to ensure no endpoint is accidentally exposed. Implement "
            "defense in depth with network-level access controls."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
        ],
    },
    "CWE-269": {
        "title": "Improper Privilege Management",
        "short": "Apply principle of least privilege; review role assignments",
        "detailed": (
            "Implement least privilege for all accounts and services. Regularly audit "
            "role assignments. Separate admin and user contexts. Use time-limited "
            "elevated privileges. Log all privilege escalation events."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html"
        ],
    },
    "CWE-94": {
        "title": "Code Injection",
        "short": "Never execute user-controlled code; use sandboxing",
        "detailed": (
            "Avoid eval(), exec(), and similar dynamic code execution with user input. "
            "If dynamic execution is required, use a sandboxed interpreter with strict "
            "resource limits. Validate all input against strict schemas."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
        ],
    },
    "CWE-798": {
        "title": "Hard-coded Credentials",
        "short": "Use environment variables or secrets management",
        "detailed": (
            "Remove all hard-coded credentials from source code. Use environment "
            "variables, vault services (HashiCorp Vault, AWS Secrets Manager), or "
            "configuration management for secrets. Rotate credentials regularly."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
        ],
    },
    "CWE-522": {
        "title": "Insufficiently Protected Credentials",
        "short": "Hash passwords with bcrypt/argon2; encrypt at rest",
        "detailed": (
            "Hash passwords using bcrypt, scrypt, or Argon2id with appropriate cost "
            "factors. Never store plaintext passwords. Encrypt sensitive credentials "
            "at rest. Use TLS for credential transmission. Implement proper key management."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
        ],
    },
    "CWE-732": {
        "title": "Incorrect Permission Assignment",
        "short": "Restrict file/directory permissions to minimum required",
        "detailed": (
            "Set restrictive file permissions (e.g., 0600 for secrets, 0755 for "
            "executables). Avoid world-readable/writable files. Use umask to set "
            "default restrictive permissions. Audit file permissions regularly."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
        ],
    },
    "CWE-601": {
        "title": "Open Redirect",
        "short": "Validate redirect targets against allowlist",
        "detailed": (
            "Validate all redirect URLs against an allowlist of permitted domains. "
            "Never redirect to user-controlled URLs without validation. Use relative "
            "redirects where possible. Display a warning page for external redirects."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
        ],
    },
}


def get_remediation(cwe: Optional[str]) -> Optional[Dict[str, object]]:
    """Look up remediation guidance for a CWE identifier.

    Args:
        cwe: CWE identifier (e.g., "CWE-89" or "89")

    Returns:
        Remediation dict with title, short, detailed, references, or None.
    """
    if not cwe:
        return None

    # Normalize CWE format
    cwe_normalized = cwe.upper().strip()
    if not cwe_normalized.startswith("CWE-"):
        cwe_normalized = f"CWE-{cwe_normalized}"

    return REMEDIATION_DB.get(cwe_normalized)


def get_remediation_grouped(cwes: List[str]) -> Dict[str, Dict[str, object]]:
    """Get remediation guidance grouped by CWE.

    Args:
        cwes: List of CWE identifiers found in findings.

    Returns:
        Dict mapping CWE to remediation data (only for known CWEs).
    """
    result: Dict[str, Dict[str, object]] = {}
    for cwe in set(cwes):
        remediation = get_remediation(cwe)
        if remediation:
            cwe_key = cwe.upper().strip()
            if not cwe_key.startswith("CWE-"):
                cwe_key = f"CWE-{cwe_key}"
            result[cwe_key] = remediation
    return result
