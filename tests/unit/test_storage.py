"""Unit tests for storage layer."""

import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from erebos.core.finding import Finding, FindingEvidence, Severity, Phase
from erebos.storage.scan_state import ScanState, FindingStore, ScanStateManager


class TestScanStateManager:
    """Tests for ScanStateManager."""

    def test_create_scan_subdirectory(self, tmp_path):
        """Test that create_scan creates subdirectory structure with state.json and raw/ directory."""
        # Arrange
        storage_dir = tmp_path / "storage"
        manager = ScanStateManager(storage_dir)
        target = "example.com"
        profile = "minimal"

        # Act
        state = manager.create_scan(target=target, profile=profile)

        # Assert
        scan_dir = storage_dir / state.scan_id
        assert scan_dir.exists(), f"Scan directory {scan_dir} should exist"
        assert scan_dir.is_dir(), "Scan directory should be a directory"

        state_file = scan_dir / "state.json"
        assert state_file.exists(), f"State file {state_file} should exist"

        raw_dir = scan_dir / "raw"
        assert raw_dir.exists(), f"Raw directory {raw_dir} should exist"
        assert raw_dir.is_dir(), "Raw directory should be a directory"

        # Verify state object has correct structure
        assert state.scan_id is not None
        assert state.target == target
        assert state.profile == profile

    def test_load_state_fallback(self, tmp_path):
        """Test backward-compatible load_state with fallback to legacy flat file structure."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        manager = ScanStateManager(storage_dir)
        scan_id = "legacy456"

        # Create legacy flat file structure
        legacy_state_file = storage_dir / f"{scan_id}_state.json"
        legacy_data = {
            "scan_id": scan_id,
            "target": "legacy.com",
            "profile": "standard",
            "current_phase": "completed",
            "started_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "findings": [],
            "phase_artifacts": {"commands": []},
        }
        with open(legacy_state_file, "w") as f:
            json.dump(legacy_data, f)

        # Act - expect deprecation warning
        with patch("logging.Logger.warning") as mock_warning:
            state = manager.load_state(scan_id)

            # Assert deprecation warning was logged
            mock_warning.assert_called_once()
            warning_message = mock_warning.call_args[0][0]
            assert "deprecated" in warning_message.lower() or "legacy" in warning_message.lower()

        # Assert state loaded successfully
        assert state is not None
        assert state.scan_id == scan_id
        assert state.target == "legacy.com"
        assert state.profile == "standard"
        assert state.current_phase == "completed"


class TestScanState:
    """Tests for ScanState."""

    def test_log_command(self):
        """Test that log_command appends command entry to phase_artifacts['commands']."""
        # Arrange
        state = ScanState(scan_id="cmd-test", target="example.com", profile="minimal")

        # Act
        start_time = datetime.now(timezone.utc)
        state.log_command(
            tool="nmap",
            args=["-F", "example.com"],
            exit_code=0,
            duration=10.5,
            output_file=Path("nmap_fast_20260320.xml"),
        )

        # Assert
        assert "commands" in state.phase_artifacts
        assert len(state.phase_artifacts["commands"]) == 1

        cmd_entry = state.phase_artifacts["commands"][0]
        assert cmd_entry["tool"] == "nmap"
        assert cmd_entry["args"] == ["-F", "example.com"]
        assert cmd_entry["command"] == "nmap -F example.com"
        assert cmd_entry["exit_code"] == 0
        assert cmd_entry["duration_seconds"] == 10.5
        assert cmd_entry["output_file"] == "nmap_fast_20260320.xml"
        assert "timestamp" in cmd_entry

        # Verify timestamp is recent (within last 5 seconds)
        cmd_timestamp = datetime.fromisoformat(cmd_entry["timestamp"])
        # Ensure both datetimes have timezone info for comparison
        if cmd_timestamp.tzinfo is None:
            cmd_timestamp = cmd_timestamp.replace(tzinfo=timezone.utc)
        assert (cmd_timestamp - start_time).total_seconds() < 5

    def test_save_raw_output(self, tmp_path):
        """Test that save_raw_output writes file to {scan_id}/raw/{tool}_{variant}_{timestamp}.{ext}."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        scan_id = "raw-test"

        state = ScanState(scan_id=scan_id, target="example.com", profile="minimal")

        content = "<?xml version='1.0'?>\n<nmaprun>test data</nmaprun>"

        # Act
        output_path = state.save_raw_output(
            storage_dir=storage_dir, tool="nmap", content=content, format="xml", variant="fast"
        )

        # Assert
        assert output_path is not None
        assert isinstance(output_path, Path)
        assert output_path.exists()

        raw_dir = storage_dir / scan_id / "raw"
        assert output_path.parent == raw_dir

        # Verify filename format: {tool}_{variant}_{timestamp}.{ext}
        filename = output_path.name
        assert filename.startswith("nmap_fast_")
        assert filename.endswith(".xml")

        # Verify content
        with open(output_path, "r") as f:
            saved_content = f.read()
        assert saved_content == content

    def test_save_raw_output_large_file(self, tmp_path):
        """Test streaming write logic for large outputs (>10MB)."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        scan_id = "large-file"

        state = ScanState(scan_id=scan_id, target="example.com", profile="minimal")

        # Create 12MB content (larger than 10MB threshold)
        chunk_size = 1024 * 1024  # 1MB
        content = "X" * (12 * chunk_size)

        # Act
        output_path = state.save_raw_output(
            storage_dir=storage_dir, tool="nmap", content=content, format="xml", variant="full"
        )

        # Assert
        assert output_path.exists()
        file_size = output_path.stat().st_size
        assert file_size == len(content)

        # Verify content integrity
        with open(output_path, "r") as f:
            saved_content = f.read()
        assert saved_content == content

    def test_fallback_events_round_trip(self, tmp_path):
        """Test fallback events persist through scan state save/load."""
        storage_dir = tmp_path / "storage"
        manager = ScanStateManager(storage_dir)
        state = manager.create_scan(target="example.com", profile="minimal")

        state.log_fallback_event(
            {
                "tool": "masscan",
                "fallback_tool": "rustscan",
                "error_type": "permission_denied",
                "recovery_strategy": "fallback",
                "success": True,
                "duration_seconds": 0.4,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "category": "network_scanning",
            }
        )
        manager.save_state(state)

        restored = manager.load_state(state.scan_id)
        assert restored is not None
        events = restored.get_fallback_events()
        assert len(events) == 1
        assert events[0]["tool"] == "masscan"
        assert events[0]["fallback_tool"] == "rustscan"


class TestFindingStore:
    """Tests for FindingStore."""

    def test_finding_deduplication(self, tmp_path):
        """Test that adding the same finding twice results in only one saved."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        store = FindingStore(storage_dir)
        scan_id = "dedup-test"

        finding = Finding(
            title="SQL Injection Vulnerability",
            description="Found SQL injection",
            severity=Severity.CRITICAL,
            tool="nuclei",
            phase_found=Phase.VULN_SCAN,
            evidence=FindingEvidence(
                url="https://example.com/login", output="SQL injection detected"
            ),
        )

        # Act - add same finding twice
        result1 = store.add_finding(scan_id, finding)
        result2 = store.add_finding(scan_id, finding)

        # Assert
        assert result1 is True, "First add should succeed"
        assert result2 is False, "Second add should be rejected as duplicate"

        # Verify only one finding saved
        findings = store.get_findings(scan_id)
        assert len(findings) == 1
        assert findings[0].title == "SQL Injection Vulnerability"

    def test_dedup_different_url(self, tmp_path):
        """Test that same title+tool but different URL is not deduplicated."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        store = FindingStore(storage_dir)
        scan_id = "dedup-url"

        finding1 = Finding(
            title="XSS Vulnerability",
            description="Found XSS",
            severity=Severity.HIGH,
            tool="nuclei",
            phase_found=Phase.VULN_SCAN,
            evidence=FindingEvidence(url="https://example.com/page1", output="XSS detected"),
        )

        finding2 = Finding(
            title="XSS Vulnerability",
            description="Found XSS",
            severity=Severity.HIGH,
            tool="nuclei",
            phase_found=Phase.VULN_SCAN,
            evidence=FindingEvidence(
                url="https://example.com/page2",  # Different URL
                output="XSS detected",
            ),
        )

        # Act
        result1 = store.add_finding(scan_id, finding1)
        result2 = store.add_finding(scan_id, finding2)

        # Assert - both should succeed (not duplicates)
        assert result1 is True
        assert result2 is True

        findings = store.get_findings(scan_id)
        assert len(findings) == 2

    def test_dedup_different_tool(self, tmp_path):
        """Test that same title+URL but different tool is not deduplicated."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        store = FindingStore(storage_dir)
        scan_id = "dedup-tool"

        url = "https://example.com/api"

        finding1 = Finding(
            title="API Endpoint Exposed",
            description="Found exposed API",
            severity=Severity.MEDIUM,
            tool="nuclei",
            phase_found=Phase.DISCOVERY,
            evidence=FindingEvidence(url=url, output="API found by nuclei"),
        )

        finding2 = Finding(
            title="API Endpoint Exposed",
            description="Found exposed API",
            severity=Severity.MEDIUM,
            tool="nmap",  # Different tool
            phase_found=Phase.DISCOVERY,
            evidence=FindingEvidence(url=url, output="API found by nmap"),
        )

        # Act
        result1 = store.add_finding(scan_id, finding1)
        result2 = store.add_finding(scan_id, finding2)

        # Assert - both should succeed (not duplicates)
        assert result1 is True
        assert result2 is True

        findings = store.get_findings(scan_id)
        assert len(findings) == 2

        # Verify both tools are present
        tools = {f.tool for f in findings}
        assert tools == {"nuclei", "nmap"}
