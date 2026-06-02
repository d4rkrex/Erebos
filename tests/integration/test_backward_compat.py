"""Integration tests for backward compatibility with legacy flat storage structure."""

import json
import pytest
from pathlib import Path
from erebos.storage.scan_state import ScanStateManager


@pytest.fixture
def storage_manager(tmp_path):
    """Create a storage manager with a temporary storage directory."""
    storage_dir = tmp_path / "scans"
    storage_dir.mkdir()
    manager = ScanStateManager(str(storage_dir))
    return manager, storage_dir


def test_read_legacy_flat_structure(storage_manager, caplog):
    """Test loading scans from legacy flat file structure."""
    manager, storage_dir = storage_manager

    # Create legacy flat files
    scan_id = "legacy_scan_001"
    state_file = storage_dir / f"{scan_id}_state.json"

    # Legacy state.json structure (Note: profile not profile_name)
    state_data = {
        "scan_id": scan_id,
        "target": "192.168.1.100",
        "profile": "quick",
        "current_phase": "idle",
        "started_at": "2026-03-20T10:00:00",
        "updated_at": "2026-03-20T11:00:00",
        "findings": [],
        "phase_artifacts": {},
    }
    state_file.write_text(json.dumps(state_data, indent=2))

    # Load the scan using ScanStateManager
    state = manager.load_state(scan_id)

    # Verify state loaded successfully
    assert state is not None
    assert state.scan_id == scan_id
    assert state.target == "192.168.1.100"
    assert state.profile == "quick"
    assert state.current_phase == "idle"

    # Verify deprecation warning was logged
    assert any(
        "legacy" in record.message.lower() or "deprecated" in record.message.lower()
        for record in caplog.records
    )


def test_new_scans_use_subdirectories(storage_manager):
    """Test that create_scan() creates subdirectory structure."""
    manager, storage_dir = storage_manager

    # Create a new scan (Note: create_scan generates its own scan_id)
    state = manager.create_scan(target="192.168.1.200", profile="comprehensive")
    scan_id = state.scan_id

    # Save the state
    manager.save_state(state)

    # Verify subdirectory structure exists
    scan_dir = storage_dir / scan_id
    assert scan_dir.exists()
    assert scan_dir.is_dir()

    # Verify files are in subdirectory
    assert (scan_dir / "state.json").exists()
    assert (scan_dir / "raw").exists()
    assert (scan_dir / "raw").is_dir()

    # Verify legacy flat files do NOT exist
    assert not (storage_dir / f"{scan_id}_state.json").exists()


def test_mixed_storage_formats(storage_manager, caplog):
    """Test reading scans from mixed legacy and new formats."""
    manager, storage_dir = storage_manager

    # Create 3 legacy scans with flat structure
    legacy_ids = ["legacy_001", "legacy_002", "legacy_003"]
    for scan_id in legacy_ids:
        state_file = storage_dir / f"{scan_id}_state.json"
        state_data = {
            "scan_id": scan_id,
            "target": f"192.168.1.{legacy_ids.index(scan_id) + 10}",
            "profile": "quick",
            "current_phase": "idle",
            "findings": [],
            "phase_artifacts": {},
        }
        state_file.write_text(json.dumps(state_data))

    # Create 2 new scans with subdirectory structure
    new_states = []
    for i in range(2):
        state = manager.create_scan(target=f"192.168.1.{100 + i}", profile="comprehensive")
        manager.save_state(state)
        new_states.append(state)

    new_ids = [s.scan_id for s in new_states]

    # Load all legacy scans
    for scan_id in legacy_ids:
        state = manager.load_state(scan_id)
        assert state is not None
        assert state.scan_id == scan_id

    # Load all new scans
    for scan_id in new_ids:
        state = manager.load_state(scan_id)
        assert state is not None
        assert state.scan_id == scan_id

    # Verify deprecation warnings only for legacy scans
    deprecation_logs = [
        record
        for record in caplog.records
        if "legacy" in record.message.lower() or "deprecated" in record.message.lower()
    ]
    # Should have at least one warning per legacy scan loaded
    assert len(deprecation_logs) >= len(legacy_ids)


def test_load_state_fallback_mechanism(tmp_path):
    """Test that load_state tries subdirectory first, then falls back to flat."""
    storage_dir = tmp_path / "scans"
    storage_dir.mkdir()
    manager = ScanStateManager(str(storage_dir))

    scan_id = "test_fallback"

    # Create ONLY legacy flat file (no subdirectory)
    legacy_state = storage_dir / f"{scan_id}_state.json"
    legacy_state.write_text(
        json.dumps(
            {
                "scan_id": scan_id,
                "target": "192.168.1.50",
                "profile": "quick",
                "current_phase": "idle",
                "findings": [],
                "phase_artifacts": {},
            }
        )
    )

    # Load should work via fallback
    state = manager.load_state(scan_id)
    assert state is not None
    assert state.scan_id == scan_id
    assert state.target == "192.168.1.50"


def test_load_state_prefers_subdirectory(tmp_path):
    """Test that load_state prefers subdirectory over legacy flat when both exist."""
    storage_dir = tmp_path / "scans"
    storage_dir.mkdir()
    manager = ScanStateManager(str(storage_dir))

    scan_id = "test_both_formats"

    # Create legacy flat file with target A
    legacy_state = storage_dir / f"{scan_id}_state.json"
    legacy_state.write_text(
        json.dumps(
            {
                "scan_id": scan_id,
                "target": "192.168.1.OLD",  # Old data
                "profile": "quick",
                "current_phase": "idle",
                "findings": [],
                "phase_artifacts": {},
            }
        )
    )

    # Create subdirectory file with target B (newer)
    scan_dir = storage_dir / scan_id
    scan_dir.mkdir()
    new_state = scan_dir / "state.json"
    new_state.write_text(
        json.dumps(
            {
                "scan_id": scan_id,
                "target": "192.168.1.NEW",  # New data
                "profile": "comprehensive",
                "current_phase": "idle",
                "findings": [],
                "phase_artifacts": {},
            }
        )
    )

    # Load should prefer subdirectory version
    state = manager.load_state(scan_id)
    assert state is not None
    assert state.target == "192.168.1.NEW"  # Should load the new format
    assert state.profile == "comprehensive"


def test_backward_compat_with_findings(tmp_path):
    """Test backward compatibility for loading findings from legacy structure."""
    storage_dir = tmp_path / "scans"
    storage_dir.mkdir()
    manager = ScanStateManager(str(storage_dir))

    scan_id = "legacy_with_findings"

    # Create legacy state file with findings embedded
    state_file = storage_dir / f"{scan_id}_state.json"
    state_file.write_text(
        json.dumps(
            {
                "scan_id": scan_id,
                "target": "192.168.1.100",
                "profile": "quick",
                "current_phase": "idle",
                "findings": [
                    {
                        "id": "finding_001",
                        "title": "Open HTTP Port",
                        "severity": "INFO",
                        "phase": "RECON",
                        "tool_name": "nmap",
                        "timestamp": "2026-03-20T10:30:00",
                        "evidence": {"url": "http://192.168.1.100:80"},
                    },
                    {
                        "id": "finding_002",
                        "title": "Open HTTPS Port",
                        "severity": "INFO",
                        "phase": "RECON",
                        "tool_name": "nmap",
                        "timestamp": "2026-03-20T10:31:00",
                        "evidence": {"url": "https://192.168.1.100:443"},
                    },
                ],
                "phase_artifacts": {},
            }
        )
    )

    # Load state
    state = manager.load_state(scan_id)
    assert state is not None

    # Verify findings were loaded from embedded structure
    assert len(state.findings) == 2
    assert state.findings[0]["title"] == "Open HTTP Port"
    assert state.findings[1]["title"] == "Open HTTPS Port"
