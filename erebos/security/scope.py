"""Scope enforcement - allowlist validation."""

import ipaddress
import re
from typing import List, Optional
from urllib.parse import urlparse


class AllowlistValidator:
    """Validates targets against allowlist.

    VT-Spec T-01: This is a critical security boundary.
    Used by ScopedHttpClient to validate EVERY URL before sending requests.
    """

    def __init__(self, allowlist: Optional[List[str]] = None):
        self._allowlist = allowlist if allowlist is not None else []

    def add(self, target: str) -> None:
        """Add a target to the allowlist."""
        if target not in self._allowlist:
            self._allowlist.append(target)

    def remove(self, target: str) -> None:
        """Remove a target from the allowlist."""
        if target in self._allowlist:
            self._allowlist.remove(target)

    @property
    def allowlist(self) -> List[str]:
        """Get the allowlist."""
        return self._allowlist

    def is_allowed(self, target: str) -> bool:
        """Check if a target is allowed.

        VT-Spec T-01: This method is called on EVERY URL before HTTP request.
        """
        # Extract domain/IP from various input formats
        parsed = self._parse_target(target)
        if not parsed:
            return False

        domain = parsed["domain"]
        ip = parsed["ip"]

        # Security: CIDR ranges are not allowed in allowlist
        # Only exact domains and wildcards are permitted
        for entry in self._allowlist:
            if "/" in entry:
                continue  # Skip CIDR entries

            # Normalize entry for comparison
            entry_lower = entry.lower().strip()

            # Handle wildcard domains
            if entry_lower.startswith("*."):
                wildcard_suffix = entry_lower[2:]
                if domain and (
                    domain == wildcard_suffix
                    or domain.endswith("." + wildcard_suffix)
                ):
                    return True
                # Also check if IP matches wildcard
                if ip and (ip == wildcard_suffix or ip.endswith("." + wildcard_suffix)):
                    return True

            # Handle exact domain match
            if domain and (domain == entry_lower or domain == entry_lower.replace("*.", "")):
                return True

            # Handle IP match
            if ip and ip == entry_lower:
                return True

        return False

    def _parse_target(self, target: str) -> Optional[dict]:
        """Parse a target string into domain and IP."""
        # Handle URLs
        if "://" in target:
            parsed = urlparse(target)
            # Extract hostname without port for matching
            hostname = (parsed.hostname or "").lower()
            return {"domain": hostname, "ip": None}

        # Handle host:port format
        if ":" in target and not target.startswith("["):
            # Strip port number
            host_part = target.rsplit(":", 1)[0]
            target = host_part

        target = target.lower().strip()

        # Handle IP addresses
        try:
            ipaddress.ip_address(target)
            return {"domain": None, "ip": target}
        except ValueError:
            pass

        # Handle plain domain
        return {"domain": target, "ip": None}

    def validate_or_raise(self, target: str) -> None:
        """Validate target or raise ValueError."""
        if not self.is_allowed(target):
            raise ValueError(
                f"Target '{target}' is not in allowlist. Add it with 'erebos allowlist add {target}'"
            )
