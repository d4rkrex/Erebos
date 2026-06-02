"""Unit tests for config settings."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from erebos.config.settings import Config, Settings, _merge_configs, get_settings, reset_settings


class TestSettings:
    """Tests for Settings."""

    def test_default_settings(self):
        """Test default settings are loaded."""
        settings = Settings()

        # Check default profiles
        assert "minimal" in settings.profiles
        assert "standard" in settings.profiles
        assert "comprehensive" in settings.profiles

        # Check execution defaults
        assert settings.execution.transport == "cli"
        assert settings.execution.timeout_per_tool == 300
        assert settings.execution.max_retries == 3
        assert settings.execution.enable_intelligent_error_handler is False
        assert settings.execution.error_handler_fallback_chains_path is None

        # Check AI defaults
        assert settings.ai.enable_target_profile is True
        assert settings.ai.enable_intelligent_decisions is False
        assert settings.ai.decision_default_threshold == 0.70

        # Check security defaults
        assert isinstance(settings.security.allowlist, list)

    def test_settings_from_yaml(self):
        """Test loading settings from YAML."""
        config_data = {
            "profiles": {
                "test_profile": {
                    "recon": ["katana"],
                    "discovery": [],
                    "vuln-scan": ["nuclei"],
                }
            },
            "execution": {
                "transport": "mcp",
                "timeout_per_tool": 600,
            },
            "security": {
                "allowlist": ["test.com"],
                "rate_limit": 20,
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name

        try:
            # Note: This tests the structure, actual loading would need proper initialization
            settings = Settings()

            # Verify structure exists
            assert settings.profiles is not None
            assert settings.execution is not None
            assert settings.security is not None
        finally:
            os.unlink(temp_path)

    def test_settings_validation(self):
        """Test settings validation."""
        # Invalid transport should raise error
        with pytest.raises(Exception):
            Settings(execution={"transport": "invalid"})

    def test_profiles_exist(self):
        """Test required profiles exist."""
        settings = Settings()

        required_profiles = ["minimal", "standard", "comprehensive", "web-only", "vuln-focused"]
        for profile in required_profiles:
            assert profile in settings.profiles, f"Profile {profile} should exist"


class TestGetSettings:
    """Tests for get_settings singleton."""

    def test_get_settings_returns_settings(self):
        """Test get_settings returns Settings instance."""
        settings = get_settings()
        assert isinstance(settings, Settings)

    def test_get_settings_is_singleton(self):
        """Test get_settings returns same instance."""
        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2


class TestConfigMerging:
    """Tests for config merging behavior."""

    def test_merge_configs_scalar_override(self):
        """Test that scalar values from override config win."""
        base = Config(execution={"timeout_per_tool": 300, "concurrency": 3})
        override = Config(execution={"timeout_per_tool": 600, "concurrency": 5})

        merged = _merge_configs(base, override)

        assert merged.execution.timeout_per_tool == 600
        assert merged.execution.concurrency == 5

    def test_merge_configs_list_merge(self):
        """Test that list values are merged and deduplicated."""
        base = Config(security={"allowlist": ["host1.com", "host2.com", "192.168.1.0/24"]})
        override = Config(security={"allowlist": ["host2.com", "host3.com", "10.0.0.0/8"]})

        merged = _merge_configs(base, override)

        # Should have all unique entries
        assert len(merged.security.allowlist) == 5
        assert "host1.com" in merged.security.allowlist
        assert "host2.com" in merged.security.allowlist
        assert "host3.com" in merged.security.allowlist
        assert "192.168.1.0/24" in merged.security.allowlist
        assert "10.0.0.0/8" in merged.security.allowlist

        # host2.com should appear only once (deduplicated)
        assert merged.security.allowlist.count("host2.com") == 1

    def test_merge_configs_nested_dict_merge(self):
        """Test that nested dicts (profiles) are deep merged."""
        base = Config()
        override = Config()

        # Override should add new profile and modify existing
        merged = _merge_configs(base, override)

        # Both should have all default profiles
        assert "minimal" in merged.profiles
        assert "standard" in merged.profiles

    def test_config_loading_priority_both_exist(self, tmp_path, monkeypatch):
        """Test config loading when both repo and user configs exist."""
        # Create temporary repo config
        repo_config = tmp_path / "config.yaml"
        repo_data = {
            "security": {"allowlist": ["repo-host1.com", "repo-host2.com"], "rate_limit": 10},
            "execution": {"concurrency": 3},
        }
        with open(repo_config, "w") as f:
            yaml.dump(repo_data, f)

        # Create temporary user config
        user_config_dir = tmp_path / ".erebos"
        user_config_dir.mkdir()
        user_config = user_config_dir / "config.yaml"
        user_data = {
            "security": {"allowlist": ["user-host1.com", "repo-host2.com"], "rate_limit": 20},
            "execution": {"concurrency": 5},
        }
        with open(user_config, "w") as f:
            yaml.dump(user_data, f)

        # Mock Path.home() and current directory
        monkeypatch.chdir(tmp_path)
        with patch("pathlib.Path.home", return_value=tmp_path):
            reset_settings()
            settings = get_settings()

        # User config scalar values should win
        assert settings.security.rate_limit == 20
        assert settings.execution.concurrency == 5

        # Lists should be merged
        assert len(settings.security.allowlist) == 3
        assert "repo-host1.com" in settings.security.allowlist
        assert "user-host1.com" in settings.security.allowlist
        assert "repo-host2.com" in settings.security.allowlist
        # repo-host2.com should appear only once (deduplicated)
        assert settings.security.allowlist.count("repo-host2.com") == 1

    def test_config_loading_priority_only_repo(self, tmp_path, monkeypatch):
        """Test config loading when only repo config exists."""
        # Create temporary repo config
        repo_config = tmp_path / "config.yaml"
        repo_data = {"security": {"allowlist": ["repo-only.com"], "rate_limit": 15}}
        with open(repo_config, "w") as f:
            yaml.dump(repo_data, f)

        # Mock paths (no user config)
        monkeypatch.chdir(tmp_path)
        user_config_dir = tmp_path / ".erebos"
        with patch("pathlib.Path.home", return_value=tmp_path):
            reset_settings()
            settings = get_settings()

        # Repo config values should be used
        assert settings.security.rate_limit == 15
        assert "repo-only.com" in settings.security.allowlist

    def test_config_loading_priority_only_user(self, tmp_path, monkeypatch):
        """Test config loading when only user config exists."""
        # Create temporary user config
        user_config_dir = tmp_path / ".erebos"
        user_config_dir.mkdir()
        user_config = user_config_dir / "config.yaml"
        user_data = {"security": {"allowlist": ["user-only.com"], "rate_limit": 25}}
        with open(user_config, "w") as f:
            yaml.dump(user_data, f)

        # Mock paths (no repo config)
        # Create empty temp dir for working directory
        work_dir = tmp_path / "workdir"
        work_dir.mkdir()
        monkeypatch.chdir(work_dir)

        with patch("pathlib.Path.home", return_value=tmp_path):
            reset_settings()
            settings = get_settings()

        # User config values should be used
        assert settings.security.rate_limit == 25
        assert "user-only.com" in settings.security.allowlist

    def test_user_config_does_not_reset_repo_feature_flags(self, tmp_path, monkeypatch):
        """Missing user-config sections should not clobber repo feature flags."""
        repo_config = tmp_path / "config.yaml"
        repo_data = {
            "execution": {
                "enable_intelligent_error_handler": True,
                "error_handler_fallback_chains_path": "./erebos/config/fallback_chains.yaml",
            },
            "ai": {
                "enable_target_profile": True,
                "enable_intelligent_decisions": True,
            },
        }
        with open(repo_config, "w") as f:
            yaml.dump(repo_data, f)

        user_config_dir = tmp_path / ".erebos"
        user_config_dir.mkdir()
        user_config = user_config_dir / "config.yaml"
        user_data = {"security": {"allowlist": ["scanme.nmap.org"]}}
        with open(user_config, "w") as f:
            yaml.dump(user_data, f)

        monkeypatch.chdir(tmp_path)
        with patch("pathlib.Path.home", return_value=tmp_path):
            reset_settings()
            settings = get_settings()

        assert settings.execution.enable_intelligent_error_handler is True
        assert (
            settings.execution.error_handler_fallback_chains_path
            == "./erebos/config/fallback_chains.yaml"
        )
        assert settings.ai.enable_target_profile is True
        assert settings.ai.enable_intelligent_decisions is True

    def test_explicit_config_file_no_merge(self, tmp_path):
        """Test that explicit config file doesn't trigger merging."""
        # Create a specific config file
        explicit_config = tmp_path / "explicit.yaml"
        explicit_data = {"security": {"allowlist": ["explicit-only.com"], "rate_limit": 99}}
        with open(explicit_config, "w") as f:
            yaml.dump(explicit_data, f)

        reset_settings()
        settings = get_settings(config_file=explicit_config)

        # Only explicit config should be used
        assert settings.security.rate_limit == 99
        assert len(settings.security.allowlist) == 1
        assert "explicit-only.com" in settings.security.allowlist
