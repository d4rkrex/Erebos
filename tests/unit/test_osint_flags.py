"""Unit tests for --osint and --osint-only flag behavior at FleetConfig level.

Tests cover:
- FleetConfig.osint_mode property
- osint_only overrides roles to [RECON, REPORTER]
- EP-01: allowlist enforcement on discovered subdomains
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from erebos.agents.base import AgentRole
from erebos.agents.orchestrator import FleetConfig


class TestFleetConfigOsintMode:
    """Test FleetConfig osint_mode behavior."""

    def test_osint_mode_none_keeps_all_roles(self):
        """Default mode keeps full aggressive pipeline."""
        cfg = FleetConfig(
            target="example.com",
            allowlist=["example.com"],
            osint_mode="none",
        )
        assert AgentRole.RECON in cfg.roles
        assert AgentRole.VULN_SCAN in cfg.roles
        assert AgentRole.EXPLOIT in cfg.roles
        assert cfg.osint_mode == "none"

    def test_osint_mode_full_keeps_all_roles(self):
        """osint_mode=full keeps all roles (passive + active)."""
        cfg = FleetConfig(
            target="example.com",
            allowlist=["example.com"],
            osint_mode="full",
        )
        assert AgentRole.RECON in cfg.roles
        assert AgentRole.VULN_SCAN in cfg.roles
        assert cfg.osint_mode == "full"

    def test_osint_mode_only_restricts_roles(self):
        """osint_mode=only overrides roles to [RECON, REPORTER] only."""
        cfg = FleetConfig(
            target="example.com",
            allowlist=["example.com"],
            osint_mode="only",
        )
        assert AgentRole.RECON in cfg.roles
        assert AgentRole.REPORTER in cfg.roles
        assert AgentRole.VULN_SCAN not in cfg.roles
        assert AgentRole.EXPLOIT not in cfg.roles
        assert AgentRole.WEB_DISCOVERY not in cfg.roles

    def test_osint_mode_only_ignores_profile(self):
        """osint_mode=only overrides even aggressive profile."""
        cfg = FleetConfig(
            target="example.com",
            allowlist=["example.com"],
            profile="aggressive",
            osint_mode="only",
        )
        # Should still be restricted despite aggressive profile
        assert len(cfg.roles) == 2
        assert AgentRole.EXPLOIT not in cfg.roles


class TestAllowlistEnforcementOnDiscoveredHosts:
    """Test EP-01: discovered subdomains filtered by allowlist."""

    def test_exact_match_allowed(self):
        """Exact hostname in allowlist passes."""
        from erebos.security.scope import AllowlistValidator

        validator = AllowlistValidator(["api.example.com", "example.com"])
        assert validator.is_allowed("api.example.com") is True

    def test_wildcard_match_allowed(self):
        """Wildcard *.example.com matches subdomains."""
        from erebos.security.scope import AllowlistValidator

        validator = AllowlistValidator(["*.example.com", "example.com"])
        assert validator.is_allowed("api.example.com") is True
        assert validator.is_allowed("deep.sub.example.com") is True

    def test_unrelated_domain_blocked(self):
        """Subdomain of different domain is blocked."""
        from erebos.security.scope import AllowlistValidator

        validator = AllowlistValidator(["example.com", "*.example.com"])
        assert validator.is_allowed("evil.com") is False
        assert validator.is_allowed("example.com.evil.com") is False

    def test_target_auto_added_to_allowlist(self):
        """FleetConfig auto-adds target to allowlist."""
        cfg = FleetConfig(
            target="scan.example.com",
            allowlist=["*.example.com"],
        )
        assert "scan.example.com" in cfg.allowlist
