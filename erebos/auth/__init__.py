"""Authentication context for authenticated scanning.

Supports:
- Static credentials (bearer tokens, cookies, basic auth, API keys)
- Login-flow credentials (form login with token extraction and refresh)
- Credential harvesting (discovered creds from scanning, LLM-guided pivot)

VT-Spec AUTH-01: Credentials never logged to findings/reports.
VT-Spec AUTH-02: Harvested creds only used against same target (allowlist-bound).
"""

from __future__ import annotations

import logging
import os
import re
import stat
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AuthType(str, Enum):
    """Supported authentication types."""

    BEARER = "bearer"
    COOKIE = "cookie"
    BASIC = "basic"
    API_KEY = "api_key"
    FORM_LOGIN = "form_login"
    CUSTOM_HEADER = "custom_header"


class AuthCredential(BaseModel):
    """A single credential (static or harvested)."""

    auth_type: AuthType
    # For bearer/api_key
    token: Optional[str] = None
    # For basic/form_login
    username: Optional[str] = None
    password: Optional[str] = None
    # For cookie
    cookies: Dict[str, str] = Field(default_factory=dict)
    # For custom_header
    header_name: Optional[str] = None
    header_value: Optional[str] = None
    # For form_login
    login_url: Optional[str] = None
    login_method: str = "POST"
    login_fields: Dict[str, str] = Field(default_factory=dict)
    extract_pattern: Optional[str] = None
    inject_as: str = "header"  # "header" or "cookie"
    refresh_interval: int = 0  # seconds, 0 = no refresh
    # Metadata
    source: str = "user"  # "user" | "harvested"
    target_scope: Optional[str] = None  # domain this cred is valid for


class AuthContext:
    """Shared authentication context consumed by all tool adapters.

    Provides tool-specific argument generation for injecting auth into
    different security tools (nuclei, sqlmap, httpx, etc.)

    VT-Spec AUTH-01: Never serialize credentials to findings or reports.
    VT-Spec AUTH-02: Harvested creds validated against allowlist before use.
    """

    def __init__(self, allowlist: Optional[List[str]] = None):
        self._static_creds: List[AuthCredential] = []
        self._harvested_creds: List[AuthCredential] = []
        self._active_sessions: Dict[str, str] = {}  # token_name → token_value
        self._allowlist = [h.lower().strip() for h in (allowlist or [])]

    @property
    def has_auth(self) -> bool:
        """Whether any credentials are available."""
        return bool(self._static_creds or self._harvested_creds or self._active_sessions)

    @property
    def all_credentials(self) -> List[AuthCredential]:
        """All available credentials (static + harvested)."""
        return self._static_creds + self._harvested_creds

    def add_static(self, cred: AuthCredential) -> None:
        """Add a user-provided credential."""
        cred.source = "user"
        self._static_creds.append(cred)

    def add_harvested(self, cred: AuthCredential, target: str) -> None:
        """Add a credential discovered during scanning.

        VT-Spec AUTH-02: Only accepts creds for in-scope targets.
        """
        if not self._is_in_scope(target):
            logger.warning(
                "Rejecting harvested credential for out-of-scope target: %s", target
            )
            return
        cred.source = "harvested"
        cred.target_scope = target
        self._harvested_creds.append(cred)
        logger.info(
            "Harvested credential added: type=%s target=%s", cred.auth_type.value, target
        )

    def set_active_session(self, name: str, value: str) -> None:
        """Store an active session token (e.g., after login flow)."""
        self._active_sessions[name] = value

    # ── Tool-specific argument builders ──────────────────────────────

    def get_headers(self) -> Dict[str, str]:
        """Get auth headers for HTTP requests."""
        headers: Dict[str, str] = {}
        for cred in self.all_credentials:
            if cred.auth_type == AuthType.BEARER:
                headers["Authorization"] = f"Bearer {cred.token}"
            elif cred.auth_type == AuthType.BASIC and cred.username and cred.password:
                import base64

                encoded = base64.b64encode(
                    f"{cred.username}:{cred.password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {encoded}"
            elif cred.auth_type == AuthType.API_KEY and cred.header_name:
                headers[cred.header_name] = cred.token or ""
            elif cred.auth_type == AuthType.CUSTOM_HEADER and cred.header_name:
                headers[cred.header_name] = cred.header_value or ""
        # Active session tokens
        for name, value in self._active_sessions.items():
            headers[name] = value
        return headers

    def get_cookies(self) -> Dict[str, str]:
        """Get auth cookies."""
        cookies: Dict[str, str] = {}
        for cred in self.all_credentials:
            if cred.auth_type == AuthType.COOKIE:
                cookies.update(cred.cookies)
        return cookies

    def get_cookie_string(self) -> str:
        """Get cookies as a single header string."""
        cookies = self.get_cookies()
        if not cookies:
            return ""
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def nuclei_args(self) -> List[str]:
        """Generate nuclei-compatible auth arguments."""
        args: List[str] = []
        headers = self.get_headers()
        for name, value in headers.items():
            args.extend(["-H", f"{name}: {value}"])
        cookie_str = self.get_cookie_string()
        if cookie_str:
            args.extend(["-H", f"Cookie: {cookie_str}"])
        return args

    def httpx_args(self) -> List[str]:
        """Generate httpx-compatible auth arguments."""
        args: List[str] = []
        headers = self.get_headers()
        for name, value in headers.items():
            args.extend(["-H", f"{name}: {value}"])
        cookie_str = self.get_cookie_string()
        if cookie_str:
            args.extend(["-H", f"Cookie: {cookie_str}"])
        return args

    def sqlmap_args(self) -> List[str]:
        """Generate sqlmap-compatible auth arguments."""
        args: List[str] = []
        headers = self.get_headers()
        if headers:
            header_str = "\\n".join(f"{k}: {v}" for k, v in headers.items())
            args.extend(["--headers", header_str])
        cookie_str = self.get_cookie_string()
        if cookie_str:
            args.extend(["--cookie", cookie_str])
        return args

    def dalfox_args(self) -> List[str]:
        """Generate dalfox-compatible auth arguments."""
        args: List[str] = []
        headers = self.get_headers()
        for name, value in headers.items():
            args.extend(["-H", f"{name}: {value}"])
        cookie_str = self.get_cookie_string()
        if cookie_str:
            args.extend(["--cookie", cookie_str])
        return args

    def katana_args(self) -> List[str]:
        """Generate katana-compatible auth arguments."""
        args: List[str] = []
        headers = self.get_headers()
        for name, value in headers.items():
            args.extend(["-H", f"{name}: {value}"])
        return args

    def generic_header_args(self, flag: str = "-H") -> List[str]:
        """Generic header injection for any tool supporting -H flag."""
        args: List[str] = []
        headers = self.get_headers()
        for name, value in headers.items():
            args.extend([flag, f"{name}: {value}"])
        cookie_str = self.get_cookie_string()
        if cookie_str:
            args.extend([flag, f"Cookie: {cookie_str}"])
        return args

    # ── Internal ─────────────────────────────────────────────────────

    def _is_in_scope(self, target: str) -> bool:
        """Check if target is covered by allowlist."""
        target_lower = target.lower().strip()
        for entry in self._allowlist:
            if entry.startswith("*."):
                suffix = entry[2:]
                if target_lower == suffix or target_lower.endswith("." + suffix):
                    return True
            elif target_lower == entry:
                return True
        return False


# ── Profile loader ───────────────────────────────────────────────────────


ENV_VAR_PATTERN = re.compile(r"\{\{ENV:([A-Z_][A-Z0-9_]*)\}\}")


def _interpolate_env(value: str) -> str:
    """Replace {{ENV:VAR_NAME}} placeholders with environment variable values."""

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        env_value = os.environ.get(var_name)
        if env_value is None:
            raise ValueError(
                f"Environment variable '{var_name}' not set (required by auth profile)"
            )
        return env_value

    return ENV_VAR_PATTERN.sub(_replace, value)


def _interpolate_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively interpolate env vars in a dict."""
    result: Dict[str, Any] = {}
    for key, value in d.items():
        if isinstance(value, str):
            result[key] = _interpolate_env(value)
        elif isinstance(value, dict):
            result[key] = _interpolate_dict(value)
        else:
            result[key] = value
    return result


def load_auth_profile(path: Path) -> List[AuthCredential]:
    """Load authentication credentials from a YAML profile.

    VT-Spec AUTH-01: File must have restrictive permissions (owner-only).
    Supports {{ENV:VAR}} interpolation for secrets.

    Raises:
        PermissionError: If file permissions are too open (not 600/400).
        FileNotFoundError: If profile path doesn't exist.
        ValueError: If profile format is invalid or env var missing.
    """
    if not path.exists():
        raise FileNotFoundError(f"Auth profile not found: {path}")

    # VT-Spec AUTH-01: Enforce restrictive file permissions
    file_stat = path.stat()
    mode = file_stat.st_mode
    if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
        raise PermissionError(
            f"Auth profile '{path}' has insecure permissions "
            f"(mode {oct(mode)}). Run: chmod 600 {path}"
        )

    raw = yaml.safe_load(path.read_text())
    if raw is None:
        return []

    # Support single credential or list
    profiles = raw if isinstance(raw, list) else [raw]
    credentials: List[AuthCredential] = []

    for profile in profiles:
        profile = _interpolate_dict(profile)
        auth_type = AuthType(profile["type"])

        if auth_type == AuthType.BEARER:
            credentials.append(AuthCredential(
                auth_type=AuthType.BEARER,
                token=profile["token"],
            ))
        elif auth_type == AuthType.COOKIE:
            credentials.append(AuthCredential(
                auth_type=AuthType.COOKIE,
                cookies=profile.get("cookies", {}),
            ))
        elif auth_type == AuthType.BASIC:
            credentials.append(AuthCredential(
                auth_type=AuthType.BASIC,
                username=profile["username"],
                password=profile["password"],
            ))
        elif auth_type == AuthType.API_KEY:
            credentials.append(AuthCredential(
                auth_type=AuthType.API_KEY,
                header_name=profile.get("header", "X-API-Key"),
                token=profile["key"],
            ))
        elif auth_type == AuthType.FORM_LOGIN:
            credentials.append(AuthCredential(
                auth_type=AuthType.FORM_LOGIN,
                login_url=profile["url"],
                login_method=profile.get("method", "POST"),
                login_fields=profile.get("fields", {}),
                username=profile.get("fields", {}).get("username"),
                password=profile.get("fields", {}).get("password"),
                extract_pattern=profile.get("extract", {}).get("token"),
                inject_as=profile.get("inject_as", "header"),
                refresh_interval=profile.get("refresh_interval", 0),
            ))
        elif auth_type == AuthType.CUSTOM_HEADER:
            credentials.append(AuthCredential(
                auth_type=AuthType.CUSTOM_HEADER,
                header_name=profile["header"],
                header_value=profile["value"],
            ))

    return credentials
