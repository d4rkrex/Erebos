"""Unit tests for erebos.auth — AuthContext, credential harvesting, profile loading."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from erebos.auth import (
    AuthContext,
    AuthCredential,
    AuthType,
    load_auth_profile,
)
from erebos.auth.harvester import CredentialHarvester
from erebos.core.finding import Finding, Phase, Severity


class TestAuthContext:
    """Test AuthContext credential management and tool arg generation."""

    def test_has_auth_empty(self):
        ctx = AuthContext()
        assert ctx.has_auth is False

    def test_has_auth_with_static(self):
        ctx = AuthContext()
        ctx.add_static(AuthCredential(auth_type=AuthType.BEARER, token="abc"))
        assert ctx.has_auth is True

    def test_bearer_headers(self):
        ctx = AuthContext()
        ctx.add_static(AuthCredential(auth_type=AuthType.BEARER, token="mytoken123"))
        headers = ctx.get_headers()
        assert headers["Authorization"] == "Bearer mytoken123"

    def test_basic_auth_headers(self):
        ctx = AuthContext()
        ctx.add_static(AuthCredential(
            auth_type=AuthType.BASIC,
            username="admin",
            password="secret",
        ))
        headers = ctx.get_headers()
        import base64
        expected = base64.b64encode(b"admin:secret").decode()
        assert headers["Authorization"] == f"Basic {expected}"

    def test_cookie_string(self):
        ctx = AuthContext()
        ctx.add_static(AuthCredential(
            auth_type=AuthType.COOKIE,
            cookies={"session_id": "abc123", "csrf": "xyz"},
        ))
        cookie_str = ctx.get_cookie_string()
        assert "session_id=abc123" in cookie_str
        assert "csrf=xyz" in cookie_str

    def test_api_key_header(self):
        ctx = AuthContext()
        ctx.add_static(AuthCredential(
            auth_type=AuthType.API_KEY,
            header_name="X-API-Key",
            token="key123",
        ))
        headers = ctx.get_headers()
        assert headers["X-API-Key"] == "key123"

    def test_nuclei_args(self):
        ctx = AuthContext()
        ctx.add_static(AuthCredential(auth_type=AuthType.BEARER, token="tok"))
        args = ctx.nuclei_args()
        assert "-H" in args
        assert "Authorization: Bearer tok" in args

    def test_nuclei_args_with_cookies(self):
        ctx = AuthContext()
        ctx.add_static(AuthCredential(
            auth_type=AuthType.COOKIE,
            cookies={"sid": "val"},
        ))
        args = ctx.nuclei_args()
        assert "-H" in args
        assert any("Cookie: sid=val" in a for a in args)

    def test_sqlmap_args(self):
        ctx = AuthContext()
        ctx.add_static(AuthCredential(
            auth_type=AuthType.COOKIE,
            cookies={"session": "x"},
        ))
        args = ctx.sqlmap_args()
        assert "--cookie" in args
        assert "session=x" in args

    def test_custom_header(self):
        ctx = AuthContext()
        ctx.add_static(AuthCredential(
            auth_type=AuthType.CUSTOM_HEADER,
            header_name="X-Custom",
            header_value="my-value",
        ))
        headers = ctx.get_headers()
        assert headers["X-Custom"] == "my-value"


class TestAuthContextHarvesting:
    """Test credential harvesting with allowlist enforcement."""

    def test_harvested_cred_in_scope(self):
        ctx = AuthContext(allowlist=["*.example.com", "example.com"])
        cred = AuthCredential(auth_type=AuthType.BEARER, token="harvested_tok")
        ctx.add_harvested(cred, "api.example.com")
        assert len(ctx.all_credentials) == 1
        assert ctx.all_credentials[0].source == "harvested"

    def test_harvested_cred_out_of_scope_rejected(self):
        ctx = AuthContext(allowlist=["example.com"])
        cred = AuthCredential(auth_type=AuthType.BEARER, token="evil_tok")
        ctx.add_harvested(cred, "evil.com")
        assert len(ctx.all_credentials) == 0

    def test_active_session_in_headers(self):
        ctx = AuthContext()
        ctx.set_active_session("Authorization", "Bearer refreshed_tok")
        headers = ctx.get_headers()
        assert headers["Authorization"] == "Bearer refreshed_tok"


class TestCredentialHarvester:
    """Test automatic credential extraction from findings."""

    def _make_finding(self, title: str, description: str, target: str = "example.com") -> Finding:
        return Finding(
            id="test-1",
            title=title,
            description=description,
            severity=Severity.HIGH,
            phase_found=Phase.VULN_SCAN,
            target=target,
            tool="nuclei",
        )

    def test_harvest_bearer_token(self):
        ctx = AuthContext(allowlist=["example.com"])
        harvester = CredentialHarvester(ctx)
        finding = self._make_finding(
            "exposed-env",
            "Found .env: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
        )
        harvested = harvester.process_finding(finding)
        assert len(harvested) == 1
        assert harvested[0].auth_type == AuthType.BEARER
        assert "eyJhbG" in harvested[0].token

    def test_harvest_password(self):
        ctx = AuthContext(allowlist=["example.com"])
        harvester = CredentialHarvester(ctx)
        finding = self._make_finding(
            "exposed-config",
            "database config: password=SuperSecret123!",
        )
        harvested = harvester.process_finding(finding)
        assert len(harvested) == 1
        assert harvested[0].auth_type == AuthType.BASIC
        assert harvested[0].password == "SuperSecret123!"

    def test_harvest_session_cookie(self):
        ctx = AuthContext(allowlist=["example.com"])
        harvester = CredentialHarvester(ctx)
        finding = self._make_finding(
            "session-leak",
            "Found: PHPSESSID=abc123def456ghij789klmno",
        )
        harvested = harvester.process_finding(finding)
        assert len(harvested) == 1
        assert harvested[0].auth_type == AuthType.COOKIE
        assert "PHPSESSID" in harvested[0].cookies

    def test_harvest_dedup(self):
        ctx = AuthContext(allowlist=["example.com"])
        harvester = CredentialHarvester(ctx)
        finding = self._make_finding(
            "exposed-env",
            "password=same_password\npassword=same_password",
        )
        harvested = harvester.process_finding(finding)
        # Should deduplicate
        assert len(harvested) == 1

    def test_harvest_out_of_scope_rejected(self):
        ctx = AuthContext(allowlist=["example.com"])
        harvester = CredentialHarvester(ctx)
        finding = self._make_finding(
            "exposed-env",
            "password=secret123",
            target="evil.com",
        )
        harvester.process_finding(finding)
        # Credential should be found but rejected by AuthContext
        assert len(ctx.all_credentials) == 0


class TestAuthProfileLoader:
    """Test YAML auth profile loading."""

    def _write_profile(self, content: str, mode: int = 0o600) -> Path:
        """Write a temp profile file with given permissions."""
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        f.write(content)
        f.close()
        os.chmod(f.name, mode)
        return Path(f.name)

    def test_load_bearer_profile(self):
        path = self._write_profile("type: bearer\ntoken: my-jwt-token-here")
        try:
            creds = load_auth_profile(path)
            assert len(creds) == 1
            assert creds[0].auth_type == AuthType.BEARER
            assert creds[0].token == "my-jwt-token-here"
        finally:
            path.unlink()

    def test_load_basic_auth_profile(self):
        path = self._write_profile("type: basic\nusername: admin\npassword: s3cret")
        try:
            creds = load_auth_profile(path)
            assert len(creds) == 1
            assert creds[0].auth_type == AuthType.BASIC
            assert creds[0].username == "admin"
            assert creds[0].password == "s3cret"
        finally:
            path.unlink()

    def test_load_cookie_profile(self):
        content = "type: cookie\ncookies:\n  session_id: abc123\n  csrf: xyz"
        path = self._write_profile(content)
        try:
            creds = load_auth_profile(path)
            assert len(creds) == 1
            assert creds[0].cookies == {"session_id": "abc123", "csrf": "xyz"}
        finally:
            path.unlink()

    def test_load_multiple_creds(self):
        content = """
- type: bearer
  token: tok1
- type: cookie
  cookies:
    sid: val
"""
        path = self._write_profile(content)
        try:
            creds = load_auth_profile(path)
            assert len(creds) == 2
        finally:
            path.unlink()

    def test_env_interpolation(self):
        path = self._write_profile("type: bearer\ntoken: '{{ENV:TEST_AUTH_TOKEN}}'")
        try:
            with patch.dict(os.environ, {"TEST_AUTH_TOKEN": "resolved_token"}):
                creds = load_auth_profile(path)
                assert creds[0].token == "resolved_token"
        finally:
            path.unlink()

    def test_env_interpolation_missing_var_raises(self):
        path = self._write_profile("type: bearer\ntoken: '{{ENV:NONEXISTENT_VAR_XYZ}}'")
        try:
            with pytest.raises(ValueError, match="not set"):
                load_auth_profile(path)
        finally:
            path.unlink()

    def test_insecure_permissions_rejected(self):
        path = self._write_profile("type: bearer\ntoken: secret", mode=0o644)
        try:
            with pytest.raises(PermissionError, match="insecure permissions"):
                load_auth_profile(path)
        finally:
            path.unlink()

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_auth_profile(Path("/nonexistent/auth.yaml"))
