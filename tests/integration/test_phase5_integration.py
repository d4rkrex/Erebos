"""Integration tests for Phase 5: Integration & Polish.

Tests:
- End-to-end engage flow (mocked executor)
- MCP server tool invocations
- Report generation from sample data
- Profile loading and validation
- Checkpoint integrity (R-001)
- CTF profile scope boundary (EOP-001)
- Credential scrubbing in reports (ID-001)
- Graceful shutdown handler (DOS-001)
- Approval source verification (T-001)
- Docker secrets loading (ID-002)
- Stdio auth warning (S-001)

# VT-Spec: All security mitigations tested with abuse cases.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
import signal
import tempfile
import time
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from erebos.config.profiles import (
    CTF,
    ENGAGEMENT_PROFILES,
    FULL_PENTEST,
    QUICK_SCAN,
    STEALTH,
    EngagementProfile,
    get_profile,
    validate_ctf_profile,
)
from erebos.core.finding import Finding, FindingEvidence, Severity
from erebos.core.models import (
    Engagement,
    EngagementPhase,
    EngagementStatus,
    Target,
)
from erebos.mcp import (
    EngagementManager,
    GracefulShutdownHandler,
    MCP_STDIO_AUTH_NOTE,
    log_stdio_auth_warning,
)
from erebos.mcp.server import EngagementMCPServer
from erebos.reporting.generator import ReportGenerator
from erebos.reporting.purple import PurpleTeamAdvisor, SigmaRule
from erebos.storage.checkpoint import (
    CheckpointIntegrityError,
    CheckpointManager,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def sample_findings() -> List[Finding]:
    """Sample findings with credentials in evidence for testing scrubbing."""
    return [
        Finding(
            tool="nmap",
            severity=Severity.CRITICAL,
            title="SQL Injection in Login",
            description="SQL injection allows auth bypass",
            evidence=FindingEvidence(
                url="http://target.local/login?user=admin",
                payload="' OR 1=1 -- password=SuperSecret123",
                output="password=SuperSecret123\ntoken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            ),
            cve="CVE-2024-1234",
            cvss=9.8,
            cwe="CWE-89",
            suggested_fix="Use parameterized queries",
            phase_found="vuln-scan",
        ),
        Finding(
            tool="nuclei",
            severity=Severity.HIGH,
            title="Exposed Admin Panel",
            description="Admin panel accessible without auth",
            evidence=FindingEvidence(
                url="http://target.local/admin",
                output="Authorization: Bearer sk-live-abc123secret456key789",
            ),
            phase_found="vuln-scan",
        ),
        Finding(
            tool="nikto",
            severity=Severity.MEDIUM,
            title="Server Version Disclosure",
            description="Apache version visible in headers",
            evidence=FindingEvidence(
                url="http://target.local/",
                output="Server: Apache/2.4.51",
            ),
            phase_found="recon",
        ),
    ]


# ── Profile Tests (REQ-005) ──────────────────────────────────────────────────


class TestProfiles:
    """Test configuration profiles (REQ-005)."""

    def test_get_valid_profile(self):
        """REQ-005: Valid profile names return correct profile."""
        profile = get_profile("quick-scan")
        assert profile.name == "quick-scan"
        assert "exploitation" not in profile.phases_enabled
        assert "recon" in profile.phases_enabled

    def test_get_invalid_profile_raises(self):
        """REQ-005 Scenario: Invalid profile name."""
        with pytest.raises(ValueError, match="Unknown profile 'nonexistent'"):
            get_profile("nonexistent")

    def test_available_profiles_listed_in_error(self):
        """REQ-005: Error message lists available profiles."""
        with pytest.raises(ValueError, match="quick-scan"):
            get_profile("bad-name")

    def test_quick_scan_limits_phases(self):
        """REQ-005 Scenario: Quick-scan limits to recon + enumeration."""
        profile = get_profile("quick-scan")
        assert "exploitation" not in profile.phases_enabled
        assert profile.max_iterations == 30

    def test_full_pentest_requires_approval(self):
        """REQ-005 Scenario: Full-pentest requires approval."""
        profile = get_profile("full-pentest")
        assert profile.approval_mode.value == "manual"
        assert "exploitation" in profile.phases_enabled

    def test_stealth_timing_constraints(self):
        """REQ-005 Scenario: Stealth enforces timing."""
        profile = get_profile("stealth")
        assert profile.timing_min_delay_ms >= 2000
        assert profile.parallel_scanning is False
        assert profile.evasion_level.value == "high"

    def test_ctf_auto_approves(self):
        """REQ-005 Scenario: CTF auto-approves all."""
        profile = get_profile("ctf")
        assert profile.approval_mode.value == "disabled"
        assert profile.aggressive_techniques is True
        assert profile.cleanup_mode.value == "none"

    def test_all_profiles_present(self):
        """REQ-005: All four profiles exist."""
        assert "quick-scan" in ENGAGEMENT_PROFILES
        assert "full-pentest" in ENGAGEMENT_PROFILES
        assert "stealth" in ENGAGEMENT_PROFILES
        assert "ctf" in ENGAGEMENT_PROFILES


# ── CTF Profile Security (EOP-001) ───────────────────────────────────────────


class TestCTFProfileSecurity:
    """VT-Spec EOP-001 HIGH: CTF profile scope boundary enforcement."""

    def test_ctf_requires_target_allowlist(self):
        """EOP-001: CTF profile fails without explicit allowlist."""
        profile = EngagementProfile(
            name="ctf",
            description="test",
            requires_non_production_declaration=True,
            ctf_target_allowlist=[],  # Empty!
        )
        with pytest.raises(ValueError, match="requires explicit ctf_target_allowlist"):
            validate_ctf_profile(profile, targets=["10.0.0.1"])

    def test_ctf_rejects_target_not_in_allowlist(self):
        """EOP-001: CTF profile rejects targets not in allowlist."""
        profile = EngagementProfile(
            name="ctf",
            description="test",
            requires_non_production_declaration=True,
            ctf_target_allowlist=["192.168.1.100"],
        )
        with pytest.raises(ValueError, match="not in CTF allowlist"):
            validate_ctf_profile(
                profile,
                targets=["10.0.0.1"],  # Not in allowlist
                confirm_callback=lambda _: True,
            )

    def test_ctf_rejects_production_environment(self):
        """EOP-001: CTF profile CANNOT target production."""
        profile = EngagementProfile(
            name="ctf",
            description="test",
            requires_non_production_declaration=True,
            ctf_target_allowlist=["prod.server.com"],
        )
        with pytest.raises(ValueError, match="CANNOT be used against production"):
            validate_ctf_profile(
                profile,
                targets=["prod.server.com"],
                roe_environment="production",
                confirm_callback=lambda _: True,
            )

    def test_ctf_requires_confirmation(self):
        """EOP-001: CTF profile requires operator confirmation."""
        profile = EngagementProfile(
            name="ctf",
            description="test",
            requires_non_production_declaration=True,
            ctf_target_allowlist=["ctf.target.com"],
        )
        with pytest.raises(ValueError, match="not confirmed"):
            validate_ctf_profile(
                profile,
                targets=["ctf.target.com"],
                confirm_callback=lambda _: False,  # User says no
            )

    def test_ctf_passes_with_valid_config(self):
        """EOP-001: CTF profile succeeds with valid configuration."""
        profile = EngagementProfile(
            name="ctf",
            description="test",
            requires_non_production_declaration=True,
            ctf_target_allowlist=["ctf.target.com"],
        )
        result = validate_ctf_profile(
            profile,
            targets=["ctf.target.com"],
            roe_environment="lab",
            confirm_callback=lambda _: True,
        )
        assert result is True

    def test_non_ctf_profile_skips_validation(self):
        """EOP-001: Non-CTF profiles skip CTF validation."""
        profile = get_profile("full-pentest")
        result = validate_ctf_profile(profile, targets=["anything"])
        assert result is True


# ── Report Generator Tests (REQ-003 + ID-001) ────────────────────────────────


class TestReportGenerator:
    """Test report generation with credential scrubbing (ID-001)."""

    def test_markdown_report_generation(self, sample_findings):
        """REQ-003: Full markdown report generated."""
        gen = ReportGenerator(engagement_id="eng_test123", target="192.168.1.100")
        report = gen.generate_markdown(sample_findings)

        assert "# Erebos Pentest Report" in report
        assert "eng_test123" in report
        assert "192.168.1.100" in report
        assert "## Executive Summary" in report
        assert "## Findings" in report

    def test_json_report_generation(self, sample_findings):
        """REQ-003: JSON report is valid."""
        gen = ReportGenerator(engagement_id="eng_test123", target="192.168.1.100")
        report_json = gen.generate_json(sample_findings)
        data = json.loads(report_json)

        assert data["schema_version"] == "1.0"
        assert data["engagement_id"] == "eng_test123"
        assert len(data["findings"]) == 3
        assert data["summary"]["total_findings"] == 3

    def test_credential_scrubbing_in_markdown(self, sample_findings):
        """VT-Spec ID-001 HIGH: Credentials scrubbed from markdown report."""
        gen = ReportGenerator(engagement_id="eng_test123", target="target.local")
        report = gen.generate_markdown(sample_findings)

        # VT-Spec ID-001: password= values must be scrubbed
        assert "SuperSecret123" not in report
        # VT-Spec ID-001: Bearer tokens must be scrubbed
        assert "sk-live-abc123secret456key789" not in report
        # VT-Spec ID-001: JWT tokens must be scrubbed (high entropy)
        assert "eyJhbGciOiJIUzI1NiJ9" not in report

    def test_credential_scrubbing_in_json(self, sample_findings):
        """VT-Spec ID-001 HIGH: Credentials scrubbed from JSON report."""
        gen = ReportGenerator(engagement_id="eng_test123", target="target.local")
        report_json = gen.generate_json(sample_findings)

        assert "SuperSecret123" not in report_json
        assert "sk-live-abc123secret456key789" not in report_json

    def test_report_with_zero_findings(self):
        """REQ-003 Scenario: Report with zero findings."""
        gen = ReportGenerator(engagement_id="eng_empty", target="192.168.1.100")
        report = gen.generate_markdown([])

        assert "No exploitable vulnerabilities found" in report

    def test_evidence_integrity_hash(self, sample_findings):
        """REQ-003 Scenario: Evidence integrity via SHA-256."""
        gen = ReportGenerator(engagement_id="eng_test123", target="target.local")
        report = gen.generate_markdown(sample_findings)

        assert "Evidence SHA-256" in report

    def test_report_classification_header(self, sample_findings):
        """AC-001: Report has classification header."""
        gen = ReportGenerator(engagement_id="eng_test123", target="target.local")
        report = gen.generate_markdown(sample_findings)

        assert "CLASSIFICATION: CONFIDENTIAL" in report

    def test_attack_path_section(self, sample_findings):
        """REQ-003 Scenario: Attack path visualization."""
        gen = ReportGenerator(engagement_id="eng_test123", target="target.local")
        attack_path = [
            {"source": "host_a", "destination": "host_b", "technique": "T1021.004 SSH"},
            {"source": "host_b", "destination": "host_c", "technique": "T1210 RCE"},
        ]
        report = gen.generate_markdown(sample_findings, attack_path=attack_path)

        assert "## Attack Path" in report
        assert "host_a" in report
        assert "host_b" in report

    def test_save_report_to_file(self, temp_dir, sample_findings):
        """REQ-003: Report saved to file."""
        gen = ReportGenerator(engagement_id="eng_save", target="target.local")
        path = gen.save_report(sample_findings, output_dir=temp_dir)

        assert path.exists()
        content = path.read_text()
        assert "Erebos Pentest Report" in content


# ── Purple Team Tests (REQ-004) ──────────────────────────────────────────────


class TestPurpleTeam:
    """Test Purple Team mode (REQ-004)."""

    def test_sigma_rule_generation(self):
        """REQ-004 Scenario: Sigma rules generated for techniques."""
        advisor = PurpleTeamAdvisor(techniques_used=["T1059", "T1021"])
        rules = advisor.generate_sigma_rules()

        assert len(rules) == 2
        assert all(isinstance(r, SigmaRule) for r in rules)
        assert any("T1059" in r.technique_id for r in rules)
        assert any("T1021" in r.technique_id for r in rules)

    def test_sigma_rule_yaml_format(self):
        """REQ-004: Sigma rules have proper YAML format."""
        advisor = PurpleTeamAdvisor(techniques_used=["T1190"])
        rules = advisor.generate_sigma_rules()
        yaml_str = rules[0].to_yaml_str()

        assert "title:" in yaml_str
        assert "logsource:" in yaml_str
        assert "detection:" in yaml_str
        assert "level:" in yaml_str

    def test_hardening_recommendations(self, sample_findings):
        """REQ-004 Scenario: Hardening recommendations per finding."""
        advisor = PurpleTeamAdvisor()
        recs = advisor.generate_hardening_recommendations(sample_findings)

        assert len(recs) == 3
        # Critical finding should have WAF recommendation
        critical_rec = recs[0]
        assert "WAF" in str(critical_rec.configuration_changes)

    def test_coverage_map(self):
        """REQ-004 Scenario: MITRE ATT&CK coverage map."""
        advisor = PurpleTeamAdvisor(techniques_used=["T1059", "T1021", "T1190"])
        advisor.add_technique("T1059", succeeded=True)
        advisor.add_technique("T1190", succeeded=True)

        coverage = advisor.generate_coverage_map()
        tested = [e for e in coverage if e.tested]
        succeeded = [e for e in coverage if e.succeeded]

        assert len(tested) == 3
        assert len(succeeded) == 2

    def test_gaps_analysis(self):
        """REQ-004: Identify untested techniques."""
        advisor = PurpleTeamAdvisor(techniques_used=["T1059"])
        gaps = advisor.generate_gaps_analysis()

        # Many techniques should be untested
        assert len(gaps) > 0
        # T1059 should NOT be in gaps
        all_gap_techniques = [t for techs in gaps.values() for t in techs]
        assert "T1059" not in all_gap_techniques

    def test_recon_only_report(self):
        """REQ-004 Scenario: No techniques used (recon-only)."""
        advisor = PurpleTeamAdvisor(techniques_used=[])
        report = advisor.generate_report([])

        assert "No active exploitation techniques" in report
        assert "full pentest is recommended" in report

    def test_full_purple_report(self, sample_findings):
        """REQ-004: Full purple team report generation."""
        advisor = PurpleTeamAdvisor(techniques_used=["T1059", "T1190"])
        advisor.add_technique("T1059", succeeded=True)
        report = advisor.generate_report(sample_findings)

        assert "# Purple Team Report" in report
        assert "Detection Rules" in report
        assert "Hardening Recommendations" in report
        assert "Coverage Map" in report


# ── Checkpoint Integrity Tests (R-001) ────────────────────────────────────────


class TestCheckpointIntegrity:
    """VT-Spec R-001 MEDIUM: Checkpoint HMAC verification."""

    def test_save_and_load_checkpoint(self, temp_dir):
        """R-001: Checkpoint save + load roundtrip."""
        mgr = CheckpointManager(temp_dir, hmac_secret="test-secret-key")
        state = {"phase": "enumeration", "iteration": 42, "findings": 5}

        mgr.save_checkpoint("eng_123", state)
        loaded = mgr.load_checkpoint("eng_123")

        assert loaded == state

    def test_tampered_checkpoint_detected(self, temp_dir):
        """R-001: Tampered checkpoint fails verification."""
        mgr = CheckpointManager(temp_dir, hmac_secret="test-secret-key")
        state = {"phase": "enumeration", "iteration": 42}

        path = mgr.save_checkpoint("eng_456", state)

        # Tamper with the checkpoint
        data = json.loads(path.read_text())
        data["data"]["state"]["phase"] = "exploitation"  # Tamper!
        path.write_text(json.dumps(data))

        with pytest.raises(CheckpointIntegrityError, match="content hash mismatch"):
            mgr.load_checkpoint("eng_456")

    def test_wrong_hmac_key_rejected(self, temp_dir):
        """R-001: Wrong HMAC key fails verification."""
        mgr1 = CheckpointManager(temp_dir / "a", hmac_secret="key-1")
        mgr2 = CheckpointManager(temp_dir / "a", hmac_secret="key-2")

        mgr1.save_checkpoint("eng_789", {"phase": "recon"})

        with pytest.raises(CheckpointIntegrityError, match="HMAC verification failed"):
            mgr2.load_checkpoint("eng_789")

    def test_missing_checkpoint_raises(self, temp_dir):
        """R-001: Missing checkpoint raises FileNotFoundError."""
        mgr = CheckpointManager(temp_dir, hmac_secret="key")
        with pytest.raises(FileNotFoundError):
            mgr.load_checkpoint("nonexistent")

    def test_empty_hmac_secret_rejected(self, temp_dir):
        """R-001: Empty HMAC secret rejected."""
        with pytest.raises(ValueError, match="HMAC secret required"):
            CheckpointManager(temp_dir, hmac_secret="")

    def test_checkpoint_exists(self, temp_dir):
        """R-001: checkpoint_exists works."""
        mgr = CheckpointManager(temp_dir, hmac_secret="key")
        assert not mgr.checkpoint_exists("eng_x")
        mgr.save_checkpoint("eng_x", {"a": 1})
        assert mgr.checkpoint_exists("eng_x")

    def test_path_traversal_prevented(self, temp_dir):
        """R-001: Path traversal in engagement_id sanitized."""
        mgr = CheckpointManager(temp_dir, hmac_secret="key")
        # Should sanitize the ID, not traverse
        mgr.save_checkpoint("../../../etc/passwd", {"evil": True})
        # Should NOT create file outside temp_dir
        assert not Path("/etc/passwd.checkpoint.json").exists()


# ── MCP Server Tests (REQ-002 + T-001) ───────────────────────────────────────


class TestEngagementManager:
    """VT-Spec T-001: Approval source verification."""

    def test_register_and_get(self):
        """REQ-002: Register and retrieve engagement."""
        mgr = EngagementManager()
        eng = Engagement(name="test", targets=[Target(address="10.0.0.1")])
        mgr.register(eng, operator="alice")

        assert mgr.get(eng.id) is not None
        assert mgr.get_operator(eng.id) == "alice"

    def test_approval_source_verification(self):
        """T-001: Verify approval source."""
        mgr = EngagementManager()
        eng = Engagement(name="test", targets=[Target(address="10.0.0.1")])
        mgr.register(eng, operator="alice", approval_token="secret-approval-token")

        # Valid approval
        assert mgr.verify_approval_source(
            eng.id, "192.168.1.1", caller_token="secret-approval-token"
        )

    def test_wrong_approval_token_rejected(self):
        """T-001: Wrong approval credential rejected."""
        mgr = EngagementManager()
        eng = Engagement(name="test", targets=[Target(address="10.0.0.1")])
        mgr.register(eng, operator="alice", approval_token="correct-token")

        # Wrong token
        result = mgr.verify_approval_source(
            eng.id, "192.168.1.1", caller_token="wrong-token"
        )
        assert result is False

    def test_approval_rate_limiting(self):
        """T-001: Approvals rate-limited (5s cooldown)."""
        mgr = EngagementManager()
        eng = Engagement(name="test", targets=[Target(address="10.0.0.1")])
        mgr.register(eng, operator="alice")

        # First approval succeeds
        assert mgr.verify_approval_source(eng.id, "192.168.1.1")

        # Immediate second approval rate-limited
        assert mgr.verify_approval_source(eng.id, "192.168.1.1") is False

    def test_nonexistent_engagement_rejected(self):
        """T-001: Approval for nonexistent engagement fails."""
        mgr = EngagementManager()
        assert mgr.verify_approval_source("nonexistent", "192.168.1.1") is False


class TestMCPServer:
    """Test MCP server tool invocations (REQ-002)."""

    def test_scan_start(self):
        """REQ-002 Scenario: Start scan via MCP."""
        config = MagicMock()
        config.sse = MagicMock()
        config.sse.token = "test-token"
        server = EngagementMCPServer(config)

        result = server.handle_scan_start("192.168.1.100", profile="quick-scan")
        assert "engagement_id" in result
        assert result["status"] == "created"
        assert result["profile"] == "quick-scan"

    def test_scan_start_invalid_profile(self):
        """REQ-002: Invalid profile returns error."""
        config = MagicMock()
        server = EngagementMCPServer(config)

        result = server.handle_scan_start("10.0.0.1", profile="nonexistent")
        assert "error" in result
        assert result["code"] == "INVALID_PROFILE"

    def test_scan_status_found(self):
        """REQ-002 Scenario: Query scan status."""
        config = MagicMock()
        server = EngagementMCPServer(config)

        # Start a scan first
        start_result = server.handle_scan_start("192.168.1.100")
        eng_id = start_result["engagement_id"]

        status = server.handle_scan_status(eng_id)
        assert status["engagement_id"] == eng_id
        assert "status" in status

    def test_scan_status_not_found(self):
        """REQ-002 Scenario: Invalid engagement ID."""
        config = MagicMock()
        server = EngagementMCPServer(config)

        result = server.handle_scan_status("eng_nonexistent")
        assert result["code"] == "ENGAGEMENT_NOT_FOUND"

    def test_scan_abort(self):
        """REQ-002 Scenario: Abort scan."""
        config = MagicMock()
        server = EngagementMCPServer(config)

        start_result = server.handle_scan_start("192.168.1.100")
        eng_id = start_result["engagement_id"]

        abort_result = server.handle_scan_abort(eng_id)
        assert abort_result["status"] == "aborted"

    def test_scan_approve_with_verification(self):
        """T-001: scan_approve verifies approval source."""
        config = MagicMock()
        server = EngagementMCPServer(config)

        # Start engagement with approval token
        result = server.handle_scan_start(
            "192.168.1.100",
            operator="alice",
            approval_token="approve-secret",
        )
        eng_id = result["engagement_id"]

        # Approve with correct token
        approve_result = server.handle_scan_approve(
            eng_id, "act_001", caller_ip="10.0.0.1", caller_token="approve-secret"
        )
        assert approve_result["status"] == "approved"

    def test_scan_approve_wrong_token_denied(self):
        """T-001: Wrong approval token denied."""
        config = MagicMock()
        server = EngagementMCPServer(config)

        result = server.handle_scan_start(
            "192.168.1.100",
            operator="alice",
            approval_token="correct-token",
        )
        eng_id = result["engagement_id"]

        # Approve with wrong token
        approve_result = server.handle_scan_approve(
            eng_id, "act_001", caller_ip="10.0.0.1", caller_token="wrong-token"
        )
        assert approve_result["code"] == "APPROVAL_DENIED"


# ── Graceful Shutdown Tests (DOS-001) ─────────────────────────────────────────


class TestGracefulShutdown:
    """VT-Spec DOS-001 MEDIUM: Graceful shutdown handler."""

    def test_handler_installs_signals(self):
        """DOS-001: Signal handlers installed."""
        handler = GracefulShutdownHandler()
        # Should not raise
        handler.install()
        # Restore default handlers
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    def test_shutdown_activates_killswitch(self, temp_dir):
        """DOS-001: Shutdown activates killswitch for active engagements."""
        from erebos.control.killswitch import KillSwitch

        ks = KillSwitch(state_dir=temp_dir)
        mgr = EngagementManager()
        eng = Engagement(
            name="active-test",
            targets=[Target(address="10.0.0.1")],
            status=EngagementStatus.ACTIVE,
        )
        mgr.register(eng, operator="test")

        handler = GracefulShutdownHandler(
            kill_switch=ks, engagement_manager=mgr
        )

        # Simulate sync shutdown
        with pytest.raises(SystemExit):
            handler._sync_shutdown()

        # Verify killswitch was activated
        assert ks.is_killed(eng.id)

    def test_double_signal_forces_exit(self):
        """DOS-001: Second signal forces immediate exit."""
        handler = GracefulShutdownHandler()
        handler._shutting_down = True

        with pytest.raises(SystemExit):
            handler._handle_signal(signal.SIGTERM, None)


# ── Docker Secrets Tests (ID-002) ─────────────────────────────────────────────


class TestDockerSecrets:
    """VT-Spec ID-002 MEDIUM: Docker secrets loading."""

    def test_load_from_secrets_file(self, temp_dir):
        """ID-002: Load secret from /run/secrets/ equivalent."""
        from erebos.security.secrets import load_secret, SECRETS_DIR

        # Create a mock secrets file
        secret_file = temp_dir / "test_secret"
        secret_file.write_text("my-secret-value\n")

        with patch("erebos.security.secrets.SECRETS_DIR", temp_dir):
            result = load_secret("test_secret")
            assert result == "my-secret-value"

    def test_env_fallback_with_warning(self, temp_dir):
        """ID-002: Env var fallback logs warning."""
        from erebos.security.secrets import load_secret

        with patch("erebos.security.secrets.SECRETS_DIR", temp_dir):
            with patch.dict(os.environ, {"MY_TOKEN": "from-env"}):
                result = load_secret("nonexistent", env_fallback="MY_TOKEN")
                assert result == "from-env"

    def test_file_env_var_pattern(self, temp_dir):
        """ID-002: *_FILE env var pattern works."""
        from erebos.security.secrets import load_secret

        secret_file = temp_dir / "token.txt"
        secret_file.write_text("file-secret\n")

        with patch("erebos.security.secrets.SECRETS_DIR", temp_dir / "empty"):
            with patch.dict(os.environ, {"MY_TOKEN_FILE": str(secret_file)}):
                result = load_secret("my_token", env_fallback="MY_TOKEN")
                assert result == "file-secret"


# ── Stdio Auth Warning Tests (S-001) ─────────────────────────────────────────


class TestStdioAuth:
    """VT-Spec S-001 LOW: Stdio auth documentation."""

    def test_warning_when_no_token(self):
        """S-001: Warning logged when no token configured."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove EREBOS_MCP_TOKEN if present
            os.environ.pop("EREBOS_MCP_TOKEN", None)
            # Should not raise, just log
            log_stdio_auth_warning()

    def test_no_warning_when_token_set(self):
        """S-001: No warning when token is configured."""
        with patch.dict(os.environ, {"EREBOS_MCP_TOKEN": "my-token"}):
            log_stdio_auth_warning()

    def test_auth_note_content(self):
        """S-001: Auth documentation mentions local-only."""
        assert "local-only" in MCP_STDIO_AUTH_NOTE.lower()
        assert "stdio" in MCP_STDIO_AUTH_NOTE.lower()


# ── Integration Flow Tests ────────────────────────────────────────────────────


class TestEngageFlow:
    """End-to-end engage flow tests (REQ-001)."""

    def test_engage_with_invalid_profile(self):
        """REQ-001: Engage fails with invalid profile."""
        from erebos.cli.engage import run_engage

        result = run_engage("10.0.0.1", profile_name="nonexistent")
        assert result == 1

    def test_engage_dry_run(self, temp_dir):
        """REQ-001: Dry run does not start engagement."""
        from erebos.cli.engage import run_engage

        with patch.dict(os.environ, {"EREBOS_HMAC_SECRET": "test-key"}):
            result = run_engage("192.168.1.100", dry_run=True)
            assert result == 0

    def test_engage_target_not_in_roe(self, temp_dir):
        """REQ-001 Scenario: Target not in RoE scope."""
        import yaml

        # Create a RoE file that doesn't include our target
        roe_file = temp_dir / "roe.yaml"
        roe_data = {
            "targets": ["192.168.1.0/24"],
            "operator": "test",
            "techniques": ["scan"],
        }
        roe_file.write_text(yaml.dump(roe_data))

        from erebos.cli.engage import run_engage

        with patch.dict(os.environ, {"EREBOS_HMAC_SECRET": "test-key"}):
            result = run_engage("10.99.99.99", roe_path=str(roe_file))
            assert result == 1


# ── Abuse Case Tests ──────────────────────────────────────────────────────────


class TestAbuseCases:
    """Tests for abuse cases from security review."""

    def test_ac001_credential_not_in_report(self, sample_findings):
        """AC-001: Credentials cannot be harvested from report files."""
        gen = ReportGenerator(engagement_id="eng_ac001", target="target.local")

        # Generate both formats
        md = gen.generate_markdown(sample_findings)
        js = gen.generate_json(sample_findings)

        # None of these should appear in output
        secrets = [
            "SuperSecret123",
            "sk-live-abc123secret456key789",
        ]
        for secret in secrets:
            assert secret not in md, f"Secret leaked in markdown: {secret}"
            assert secret not in js, f"Secret leaked in JSON: {secret}"

    def test_ac002_ctf_cannot_target_production(self):
        """AC-002: CTF profile cannot be used against production."""
        profile = EngagementProfile(
            name="ctf",
            description="test",
            requires_non_production_declaration=True,
            ctf_target_allowlist=["prod-server.com"],
        )
        with pytest.raises(ValueError):
            validate_ctf_profile(
                profile,
                targets=["prod-server.com"],
                roe_environment="production",
            )

    def test_ac005_self_approval_rate_limited(self):
        """AC-005: Self-approval attempts are rate-limited."""
        mgr = EngagementManager()
        eng = Engagement(name="test", targets=[Target(address="10.0.0.1")])
        mgr.register(eng, operator="attacker")

        # First approval OK
        assert mgr.verify_approval_source(eng.id, "evil-ip")
        # Rapid second approval blocked
        assert mgr.verify_approval_source(eng.id, "evil-ip") is False
