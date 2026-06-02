"""Credential harvester — detects credentials in findings and injects into AuthContext.

Monitors the findings bus for credential-related findings:
- Exposed .env files, config dumps
- Default credentials detected
- SQL injection data exfiltration with user tables
- API keys in responses

VT-Spec AUTH-02: Harvested creds only used against same target (allowlist-bound).
VT-Spec AUTH-03: LLM decides whether to pivot with harvested creds.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

from erebos.auth import AuthContext, AuthCredential, AuthType
from erebos.core.finding import Finding

logger = logging.getLogger(__name__)

# Patterns that indicate credential discovery
CREDENTIAL_PATTERNS = [
    # Bearer tokens (JWT, OAuth)
    re.compile(r"(?:Bearer|token)[:\s=]+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)", re.I),
    # API keys (common formats)
    re.compile(r"(?:api[_-]?key|apikey)[:\s=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?", re.I),
    # Basic auth in URLs
    re.compile(r"https?://([^:]+):([^@]+)@", re.I),
    # Password patterns in .env or config
    re.compile(r"(?:password|passwd|pwd)[:\s=]+['\"]?([^\s'\"]+)['\"]?", re.I),
    # Session cookies
    re.compile(r"(?:session_id|sessionid|PHPSESSID|JSESSIONID)[=:]([A-Za-z0-9\-_]{16,})", re.I),
]

# Finding titles that typically contain credentials
CREDENTIAL_FINDING_TITLES = [
    "exposed-env",
    "default-login",
    "default-credential",
    "admin-panel",
    "git-config",
    "htpasswd",
    "wp-config",
    "database-credential",
    "api-key-exposure",
    "token-exposure",
]


class CredentialHarvester:
    """Scans findings for credential material and injects into AuthContext.

    The harvester is called after each tool execution phase. It parses
    finding descriptions and evidence for credential patterns, then
    registers them in the shared AuthContext for use by subsequent tools.
    """

    def __init__(self, auth_context: AuthContext):
        self._auth = auth_context
        self._seen_creds: set = set()  # dedup by hash of cred value

    def process_finding(self, finding: Finding) -> List[AuthCredential]:
        """Examine a finding for credential material.

        Returns list of newly harvested credentials (empty if none found).
        """
        harvested: List[AuthCredential] = []
        target = finding.target or ""

        # Check title relevance
        description = (finding.description or "") + " " + (finding.evidence.output or "")

        # Try each credential pattern
        for pattern in CREDENTIAL_PATTERNS:
            for match in pattern.finditer(description):
                cred = self._match_to_credential(pattern, match)
                if cred and self._is_new(cred):
                    self._auth.add_harvested(cred, target)
                    harvested.append(cred)
                    logger.info(
                        "Harvested %s credential from finding: %s",
                        cred.auth_type.value,
                        finding.title,
                    )

        return harvested

    def process_findings(self, findings: List[Finding]) -> List[AuthCredential]:
        """Process multiple findings, return all newly harvested credentials."""
        all_harvested: List[AuthCredential] = []
        for finding in findings:
            all_harvested.extend(self.process_finding(finding))
        return all_harvested

    def _match_to_credential(
        self, pattern: re.Pattern, match: re.Match
    ) -> Optional[AuthCredential]:
        """Convert a regex match to an AuthCredential."""
        groups = match.groups()

        # JWT / Bearer token
        if "Bearer" in pattern.pattern or "token" in pattern.pattern:
            if groups:
                return AuthCredential(
                    auth_type=AuthType.BEARER,
                    token=groups[0],
                )

        # API key
        if "api" in pattern.pattern.lower() and "key" in pattern.pattern.lower():
            if groups:
                return AuthCredential(
                    auth_type=AuthType.API_KEY,
                    header_name="X-API-Key",
                    token=groups[0],
                )

        # Basic auth in URL (user:pass@host)
        if "@" in pattern.pattern:
            if len(groups) >= 2:
                return AuthCredential(
                    auth_type=AuthType.BASIC,
                    username=groups[0],
                    password=groups[1],
                )

        # Password field
        if "password" in pattern.pattern.lower() or "passwd" in pattern.pattern.lower():
            if groups:
                return AuthCredential(
                    auth_type=AuthType.BASIC,
                    username="admin",  # default assumption, LLM can refine
                    password=groups[0],
                )

        # Session cookie
        if "session" in pattern.pattern.lower() or "PHPSESSID" in pattern.pattern:
            if groups:
                cookie_name = "session_id"
                # Try to extract actual cookie name from match
                full_match = match.group(0)
                for name in ["PHPSESSID", "JSESSIONID", "session_id", "sessionid"]:
                    if name.lower() in full_match.lower():
                        cookie_name = name
                        break
                return AuthCredential(
                    auth_type=AuthType.COOKIE,
                    cookies={cookie_name: groups[0]},
                )

        return None

    def _is_new(self, cred: AuthCredential) -> bool:
        """Check if this credential has already been harvested (dedup)."""
        # Create a hashable key from the credential
        key_parts = [cred.auth_type.value]
        if cred.token:
            key_parts.append(cred.token[:32])
        if cred.username:
            key_parts.append(cred.username)
        if cred.password:
            key_parts.append(cred.password[:16])
        if cred.cookies:
            key_parts.append(str(sorted(cred.cookies.items())))
        key = "|".join(key_parts)

        if key in self._seen_creds:
            return False
        self._seen_creds.add(key)
        return True
