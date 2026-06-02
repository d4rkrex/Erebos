"""Integration tests for storage migration command."""

import json
import pytest
from pathlib import Path
from erebos.cli.commands import migrate_storage
from erebos.storage.scan_state import ScanStateManager
from erebos.core.finding import Finding, Severity, Phase


@pytest.fixture
def legacy_scans(tmp_path):
    """Create legacy flat file structure for testing migration."""
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()

    # Create 3 legacy scans with flat structure
    scan_ids = ["scan_001", "scan_002", "scan_003"]
    for scan_id in scan_ids:
        # Create legacy state file: {scan_id}_state.json
        state_file = scans_dir / f"{scan_id}_state.json"
        state_data = {
            "scan_id": scan_id,
            "target": "192.168.1.100",
            "profile_name": "comprehensive",
            "status": "completed",
            "start_time": "2026-03-20T10:00:00",
            "end_time": "2026-03-20T12:00:00",
            "current_phase": "REPORTING",
            "phase_artifacts": {"commands": []},
        }
        state_file.write_text(json.dumps(state_data, indent=2))

        # Create legacy findings file: {scan_id}_findings.json
        findings_file = scans_dir / f"{scan_id}_findings.json"
        findings_data = [
            {
                "id": f"finding_{scan_id}_1",
                "title": "Open SSH Port",
                "severity": "INFO",
                "phase": "RECON",
                "tool_name": "nmap",
                "timestamp": "2026-03-20T10:30:00",
                "evidence": {"url": "http://192.168.1.100:22"},
            }
        ]
        findings_file.write_text(json.dumps(findings_data, indent=2))

    return scans_dir, scan_ids


def test_migrate_dry_run(legacy_scans, capsys):
    """Test migration dry-run mode does not modify files."""
    scans_dir, scan_ids = legacy_scans

    # Run migration in dry-run mode
    migrate_storage(str(scans_dir), dry_run=True, rollback=False)

    # Verify no files were moved
    for scan_id in scan_ids:
        # Legacy files should still exist
        assert (scans_dir / f"{scan_id}_state.json").exists()
        assert (scans_dir / f"{scan_id}_findings.json").exists()

        # Subdirectories should NOT be created
        assert not (scans_dir / scan_id).exists()

    # Verify dry-run was logged
    captured = capsys.readouterr()
    assert "DRY RUN" in captured.out or "would migrate" in captured.out.lower()


def test_migrate_execution(legacy_scans):
    """Test migration execution creates subdirectories and moves files."""
    scans_dir, scan_ids = legacy_scans

    # Run actual migration
    migrate_storage(str(scans_dir), dry_run=False, rollback=False)

    # Verify files were moved to subdirectories
    for scan_id in scan_ids:
        scan_subdir = scans_dir / scan_id

        # Subdirectory should exist
        assert scan_subdir.exists()
        assert scan_subdir.is_dir()

        # Files should be in subdirectory
        assert (scan_subdir / "state.json").exists()
        assert (scan_subdir / "findings.json").exists()

        # Raw directory should be created
        assert (scan_subdir / "raw").exists()
        assert (scan_subdir / "raw").is_dir()

        # Legacy flat files should be removed
        assert not (scans_dir / f"{scan_id}_state.json").exists()
        assert not (scans_dir / f"{scan_id}_findings.json").exists()


def test_migrate_rollback(legacy_scans):
    """Test migration rollback restores flat structure."""
    scans_dir, scan_ids = legacy_scans

    # First, migrate to subdirectories
    migrate_storage(str(scans_dir), dry_run=False, rollback=False)

    # Verify migration succeeded
    for scan_id in scan_ids:
        assert (scans_dir / scan_id / "state.json").exists()

    # Now rollback
    migrate_storage(str(scans_dir), dry_run=False, rollback=True)

    # Verify files are back in flat structure
    for scan_id in scan_ids:
        # Legacy flat files should be restored
        assert (scans_dir / f"{scan_id}_state.json").exists()
        assert (scans_dir / f"{scan_id}_findings.json").exists()

        # Subdirectories should be removed
        assert not (scans_dir / scan_id).exists()


def test_migrate_partial_failure(tmp_path):
    """Test migration continues with other scans when one fails."""
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()

    # Create two valid scans
    for scan_id in ["scan_001", "scan_003"]:
        state_file = scans_dir / f"{scan_id}_state.json"
        state_data = {
            "scan_id": scan_id,
            "target": "192.168.1.100",
            "profile_name": "comprehensive",
            "status": "completed",
        }
        state_file.write_text(json.dumps(state_data, indent=2))

    # Create one malformed scan (invalid JSON)
    scan_002_state = scans_dir / "scan_002_state.json"
    scan_002_state.write_text("{ invalid json }")

    # Run migration - should fail on scan_002 but continue with others
    # This should exit with code 1, but we're testing in-process
    migrate_storage(str(scans_dir), dry_run=False, rollback=False)

    # Verify scan_001 and scan_003 were migrated successfully
    assert (scans_dir / "scan_001" / "state.json").exists()
    assert (scans_dir / "scan_003" / "state.json").exists()

    # scan_002 might be partially migrated (file moved but invalid)
    # The key requirement is that the process continued despite the error


def test_migrate_skip_already_migrated(tmp_path):
    """Test migration skips scans already in subdirectory format."""
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()

    # Create one legacy scan
    scan_001_state = scans_dir / "scan_001_state.json"
    scan_001_state.write_text(
        json.dumps(
            {
                "scan_id": "scan_001",
                "target": "192.168.1.100",
                "profile_name": "quick",
                "status": "completed",
            }
        )
    )

    # Create one already-migrated scan (in subdirectory)
    scan_002_dir = scans_dir / "scan_002"
    scan_002_dir.mkdir()
    (scan_002_dir / "state.json").write_text(
        json.dumps(
            {
                "scan_id": "scan_002",
                "target": "192.168.1.101",
                "profile_name": "quick",
                "status": "completed",
            }
        )
    )

    # Run migration
    migrate_storage(str(scans_dir), dry_run=False, rollback=False)

    # Verify scan_001 was migrated
    assert (scans_dir / "scan_001" / "state.json").exists()

    # Verify scan_002 was not touched (still in subdirectory)
    assert (scans_dir / "scan_002" / "state.json").exists()
    assert not (scans_dir / "scan_002_state.json").exists()


def test_migrate_preserves_data(legacy_scans):
    """Test migration preserves state.json and findings.json content."""
    scans_dir, scan_ids = legacy_scans

    # Read original data before migration
    original_data = {}
    for scan_id in scan_ids:
        state_file = scans_dir / f"{scan_id}_state.json"
        findings_file = scans_dir / f"{scan_id}_findings.json"
        original_data[scan_id] = {
            "state": json.loads(state_file.read_text()),
            "findings": json.loads(findings_file.read_text()),
        }

    # Run migration
    migrate_storage(str(scans_dir), dry_run=False, rollback=False)

    # Verify data is preserved in new location
    for scan_id in scan_ids:
        new_state_file = scans_dir / scan_id / "state.json"
        new_findings_file = scans_dir / scan_id / "findings.json"

        new_state = json.loads(new_state_file.read_text())
        new_findings = json.loads(new_findings_file.read_text())

        # Content should be identical
        assert new_state == original_data[scan_id]["state"]
        assert new_findings == original_data[scan_id]["findings"]
