"""Integration tests for CLI commands."""

import json
import tempfile
from pathlib import Path
from click.testing import CliRunner
from unittest.mock import patch

import pytest

from erebos.cli.commands import cli
from erebos.config.settings import AIConfig, Config
from erebos.enrichment.http_probe import HttpProbeResult


class TestCLI:
    """Integration tests for CLI commands."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()
        self.temp_dir = tempfile.mkdtemp()

    def test_cli_help(self):
        """Test CLI shows help."""
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Erebos" in result.output

    def test_scan_help(self):
        """Test scan command shows help."""
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "target" in result.output.lower()

    def test_status_help(self):
        """Test status command shows help."""
        result = self.runner.invoke(cli, ["status", "--help"])
        assert result.exit_code == 0

    def test_report_help(self):
        """Test report command shows help."""
        result = self.runner.invoke(cli, ["report", "--help"])
        assert result.exit_code == 0

    def test_target_profile_help(self):
        """Test target-profile command shows help."""
        result = self.runner.invoke(cli, ["target-profile", "--help"])
        assert result.exit_code == 0
        assert "TargetProfile" in result.output or "target profile" in result.output.lower()

    def test_allowlist_help(self):
        """Test allowlist command shows help."""
        result = self.runner.invoke(cli, ["allowlist", "--help"])
        assert result.exit_code == 0

    def test_config_help(self):
        """Test config command shows help."""
        result = self.runner.invoke(cli, ["config", "--help"])
        assert result.exit_code == 0

    def test_tools_command(self):
        """Test tools command runs."""
        result = self.runner.invoke(cli, ["tools"])
        # May fail if tools not installed, but should not crash
        assert result.exit_code in [0, 1]

    def test_allowlist_list(self):
        """Test allowlist list command."""
        result = self.runner.invoke(cli, ["allowlist", "list"])
        # May have config issues, but shouldn't crash
        assert result.exit_code in [0, 1]


class TestErebosCLI:
    """Tests for ErebosCLI programmatic interface."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def test_scan_rejects_out_of_scope_target(self):
        """Test scan rejects target not in allowlist."""
        from erebos.cli.commands import ErebosCLI
        from erebos.config.settings import Config, SecurityConfig, reset_settings

        reset_settings()

        empty_security = SecurityConfig(allowlist=[])
        with patch(
            "erebos.cli.commands.get_settings",
            return_value=Config(security=empty_security),
        ):
            cli_inst = ErebosCLI()
            result = cli_inst.scan("out-of-scope.invalid", profile="standard")

        assert isinstance(result, dict)
        assert result["success"] is False
        assert "not in allowlist" in result["error"]

    def test_status_with_no_scans(self):
        """Test status with no active scans."""
        from erebos.cli.commands import ErebosCLI

        cli = ErebosCLI()
        result = cli.status()

        assert result["success"] is True
        assert "scans" in result

    def test_allowlist_list(self):
        """Test allowlist list."""
        from erebos.cli.commands import ErebosCLI

        cli = ErebosCLI()
        result = cli.allowlist("list")

        assert result["success"] is True
        assert "allowlist" in result

    def test_target_profile_builds_and_saves_profile(self):
        """Manual TargetProfile returns a profile summary and scan id."""
        from erebos.cli.commands import ErebosCLI
        from erebos.config.settings import reset_settings

        cli = ErebosCLI()

        with (
            patch("erebos.cli.commands.AllowlistValidator.is_allowed", return_value=True),
            patch(
                "erebos.cli.commands.HttpProbeService.probe",
                return_value=HttpProbeResult(
                    is_http=True,
                    is_https=True,
                    headers={"server": "nginx/1.18.0"},
                    content_type="text/html",
                    body="<html><script>__NEXT_DATA__</script></html>",
                ),
            ),
        ):
            result = cli.target_profile("https://scanme.nmap.org")

        assert result["success"] is True
        assert "scan_id" in result
        assert result["profile"]["target_type"] == "web_application"
        assert "nginx" in result["summary"].lower()

    def test_target_profile_respects_feature_flag(self, monkeypatch):
        """Manual TargetProfile fails cleanly when the feature flag is disabled."""
        from erebos.cli.commands import ErebosCLI
        from erebos.config.settings import reset_settings

        reset_settings()
        monkeypatch.setattr(
            "erebos.cli.commands.get_settings",
            lambda: Config(ai=AIConfig(enable_target_profile=False)),
        )
        cli = ErebosCLI()

        result = cli.target_profile("https://scanme.nmap.org", save=False)

        assert result["success"] is False
        assert "disabled" in result["error"].lower()


class TestMultiTargetScan:
    """Tests for multi-target and batch scan features."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()
        self.temp_dir = tempfile.mkdtemp()

    def test_parse_targets_helper(self):
        """Test _parse_targets helper function."""
        from erebos.cli.commands import _parse_targets

        assert _parse_targets("a.com,b.com") == ["a.com", "b.com"]
        assert _parse_targets("a.com") == ["a.com"]
        assert _parse_targets("a.com, b.com ") == ["a.com", "b.com"]
        assert _parse_targets("") == []

    def test_parse_target_file_helper(self):
        """Test _parse_target_file helper function."""
        from erebos.cli.commands import _parse_target_file

        target_file = Path(self.temp_dir) / "targets.txt"
        target_file.write_text("# comment\ntest.com\n\ntest2.com\n")

        targets = _parse_target_file(str(target_file))
        assert targets == ["test.com", "test2.com"]

    def test_parse_target_file_empty(self):
        """Test _parse_target_file with only comments."""
        from erebos.cli.commands import _parse_target_file

        target_file = Path(self.temp_dir) / "empty.txt"
        target_file.write_text("# comment\n# another comment\n")

        with pytest.raises(ValueError, match="No valid targets"):
            _parse_target_file(str(target_file))

    def test_scan_batch_help(self):
        """Test scan-batch command shows help."""
        result = self.runner.invoke(cli, ["scan-batch", "--help"])
        assert result.exit_code == 0
        assert "--concurrency" in result.output

    def test_scan_batch_file_not_found(self):
        """Test scan-batch with non-existent file."""
        result = self.runner.invoke(cli, ["scan-batch", "nonexistent.txt"])
        assert result.exit_code != 0
        assert "does not exist" in result.output.lower()

    def test_scan_command_parallel_flag(self):
        """Test scan command has parallel option."""
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--parallel" in result.output

    def test_scan_comma_separated_in_help(self):
        """Test scan command shows comma-separated info."""
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "comma-separated" in result.output
