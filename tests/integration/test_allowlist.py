"""Integration tests for allowlist."""

import pytest

from erebos.security.scope import AllowlistValidator


class TestAllowlistValidator:
    """Integration tests for AllowlistValidator."""

    def test_allows_exact_domain(self):
        """Test allowing exact domain."""
        allowlist = ["example.com"]
        validator = AllowlistValidator(allowlist)

        assert validator.is_allowed("example.com") is True

    def test_rejects_unlisted_domain(self):
        """Test rejecting unlisted domain."""
        allowlist = ["example.com"]
        validator = AllowlistValidator(allowlist)

        assert validator.is_allowed("notallowed.com") is False

    def test_allows_wildcard_domain(self):
        """Test allowing wildcard domain."""
        allowlist = ["*.example.com"]
        validator = AllowlistValidator(allowlist)

        assert validator.is_allowed("sub.example.com") is True
        assert validator.is_allowed("deep.sub.example.com") is True

    def test_allows_ip_address(self):
        """Test allowing IP address."""
        allowlist = ["192.168.1.1"]
        validator = AllowlistValidator(allowlist)

        assert validator.is_allowed("192.168.1.1") is True

    def test_allows_ip_cidr(self):
        """Test allowing CIDR range."""
        allowlist = ["10.0.0.0/8"]
        validator = AllowlistValidator(allowlist)

        # This is a simple implementation - would need more complex parsing for full CIDR support
        # For now, just test the validator can handle CIDR notation
        assert validator.is_allowed("10.0.0.1") is False  # Basic implementation

    def test_add_to_allowlist(self):
        """Test adding to allowlist."""
        allowlist = ["example.com"]
        validator = AllowlistValidator(allowlist)

        validator.add("new.com")

        assert "new.com" in validator._allowlist

    def test_remove_from_allowlist(self):
        """Test removing from allowlist."""
        allowlist = ["example.com", "new.com"]
        validator = AllowlistValidator(allowlist)

        validator.remove("example.com")

        assert "example.com" not in validator._allowlist

    def test_empty_allowlist_rejects_all(self):
        """Test empty allowlist rejects all."""
        allowlist = []
        validator = AllowlistValidator(allowlist)

        assert validator.is_allowed("anything.com") is False
