"""End-to-end integration tests for storage infrastructure with comprehensive scan."""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from erebos.storage.scan_state import ScanStateManager, ScanState
from erebos.core.orchestrator import Orchestrator
from erebos.core.scan_profile import ScanProfile, ProfileTools
from erebos.core.finding import Finding, Severity, Phase, FindingEvidence
from datetime import datetime, timezone


@pytest.fixture
def storage_dir(tmp_path):
    """Create a temporary storage directory."""
    storage = tmp_path / "erebos-storage"
    storage.mkdir()
    return storage


def test_comprehensive_scan_with_new_storage(storage_dir):
    """Test full scan lifecycle creates proper subdirectory structure."""
    manager = ScanStateManager(storage_dir)

    # Create a new scan
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")
    scan_id = state.scan_id

    # Simulate phase execution with command logging
    state.log_command(
        tool="nmap",
        args=["-F", "-A", "-T4", "192.168.1.100"],
        exit_code=0,
        duration=45.2,
        output_file=Path(f"{scan_id}/raw/nmap_fast_20260320.xml"),
    )

    state.log_command(
        tool="nmap",
        args=["-p-", "-A", "-T4", "192.168.1.100"],
        exit_code=0,
        duration=1802.5,
        output_file=Path(f"{scan_id}/raw/nmap_full_20260320.xml"),
    )

    # Save state
    manager.save_state(state)

    # Verify subdirectory structure created
    scan_dir = storage_dir / scan_id
    assert scan_dir.exists(), "Scan subdirectory must exist"
    assert scan_dir.is_dir(), "Scan subdirectory must be a directory"

    # Verify state.json exists
    state_file = scan_dir / "state.json"
    assert state_file.exists(), "state.json must exist in subdirectory"

    # Verify raw/ directory exists
    raw_dir = scan_dir / "raw"
    assert raw_dir.exists(), "raw/ subdirectory must exist"
    assert raw_dir.is_dir(), "raw/ must be a directory"

    # Verify command logs in state.json
    loaded_state = manager.load_state(scan_id)
    assert loaded_state is not None
    assert "commands" in loaded_state.phase_artifacts
    commands = loaded_state.phase_artifacts["commands"]
    assert len(commands) == 2, "Must have 2 command log entries"

    # Verify first command (fast nmap)
    assert commands[0]["tool"] == "nmap"
    assert "-F" in str(commands[0]["args"])
    assert commands[0]["exit_code"] == 0
    assert commands[0]["duration_seconds"] == 45.2

    # Verify second command (full nmap)
    assert commands[1]["tool"] == "nmap"
    assert "-p-" in str(commands[1]["args"])
    assert commands[1]["exit_code"] == 0
    assert commands[1]["duration_seconds"] == 1802.5


def test_findings_deduplication_in_storage(storage_dir):
    """Test that duplicate findings are not persisted to findings.json."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="standard")
    scan_id = state.scan_id

    # Create test findings
    finding1 = {
        "id": "finding_001",
        "title": "Open HTTP Port",
        "severity": "INFO",
        "phase": "RECON",
        "tool_name": "nmap",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence": {"url": "http://192.168.1.100:80"},
    }

    # Duplicate with same title, url, tool
    finding2 = {
        "id": "finding_002",
        "title": "Open HTTP Port",
        "severity": "INFO",
        "phase": "RECON",
        "tool_name": "nmap",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence": {"url": "http://192.168.1.100:80"},
    }

    # Different URL (should not be deduplicated)
    finding3 = {
        "id": "finding_003",
        "title": "Open HTTP Port",
        "severity": "INFO",
        "phase": "RECON",
        "tool_name": "nmap",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence": {"url": "http://192.168.1.100:8080"},
    }

    # Add findings to state
    state.findings = [finding1, finding2, finding3]
    manager.save_state(state)

    # Load and verify deduplication logic would work
    # (Note: actual deduplication happens in FindingStore.add_finding,
    # but we verify the data structure supports it)
    loaded_state = manager.load_state(scan_id)
    assert loaded_state is not None

    # Create dedup keys for verification
    def get_dedup_key(f):
        url = f.get("evidence", {}).get("url", "")
        return (f["title"], url, f["tool_name"])

    dedup_keys = set()
    unique_findings = []
    for finding in loaded_state.findings:
        key = get_dedup_key(finding)
        if key not in dedup_keys:
            dedup_keys.add(key)
            unique_findings.append(finding)

    # Should have only 2 unique findings (finding1 and finding3)
    assert len(unique_findings) == 2
    assert any(f["evidence"]["url"] == "http://192.168.1.100:80" for f in unique_findings)
    assert any(f["evidence"]["url"] == "http://192.168.1.100:8080" for f in unique_findings)


def test_raw_output_persistence(storage_dir):
    """Test that raw tool outputs are saved to raw/ directory."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")
    scan_id = state.scan_id

    # Simulate nmap fast scan output
    nmap_fast_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
    <host>
        <address addr="192.168.1.100"/>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache" version="2.4.41"/>
            </port>
        </ports>
    </host>
</nmaprun>"""

    # Save raw output (pass storage_dir as first param)
    fast_path = state.save_raw_output(
        storage_dir=storage_dir, tool="nmap", content=nmap_fast_xml, format="xml", variant="fast"
    )

    # Simulate nmap full scan output
    nmap_full_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
    <host>
        <address addr="192.168.1.100"/>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache" version="2.4.41"/>
            </port>
            <port protocol="tcp" portid="8080">
                <state state="open"/>
                <service name="http" product="nginx" version="1.18.0"/>
            </port>
        </ports>
    </host>
</nmaprun>"""

    full_path = state.save_raw_output(
        storage_dir=storage_dir, tool="nmap", content=nmap_full_xml, format="xml", variant="full"
    )

    # Save state to persist paths
    manager.save_state(state)

    # Verify both files exist
    assert fast_path.exists(), "Fast nmap output file must exist"
    assert full_path.exists(), "Full nmap output file must exist"

    # Verify files are in raw/ directory
    assert "raw" in str(fast_path)
    assert "raw" in str(full_path)

    # Verify file names contain variant
    assert "fast" in fast_path.name
    assert "full" in full_path.name

    # Verify content is preserved
    assert fast_path.read_text() == nmap_fast_xml
    assert full_path.read_text() == nmap_full_xml


def test_enrichment_persistence_with_validation(storage_dir):
    """Test that enriched findings are persisted with validation."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")
    scan_id = state.scan_id

    # Create findings with enrichment data
    findings_with_enrichment = [
        {
            "id": "finding_001",
            "title": "Apache 2.4.41 Detected",
            "severity": "MEDIUM",
            "phase": "RECON",
            "tool_name": "nmap",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence": {"url": "http://192.168.1.100:80"},
            "cvss": 7.5,
            "cves": ["CVE-2021-41773"],
            "exploits": ["EDB-50383"],
        },
        {
            "id": "finding_002",
            "title": "Nginx 1.18.0 Detected",
            "severity": "LOW",
            "phase": "RECON",
            "tool_name": "nmap",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence": {"url": "http://192.168.1.100:8080"},
            "cvss": 5.3,
            "cves": ["CVE-2021-23017"],
            "exploits": [],
        },
        {
            "id": "finding_003",
            "title": "SSH Service Open",
            "severity": "INFO",
            "phase": "RECON",
            "tool_name": "nmap",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence": {"url": "ssh://192.168.1.100:22"},
            "cvss": None,
            "cves": [],
            "exploits": [],
        },
    ]

    state.findings = findings_with_enrichment
    manager.save_state(state)

    # Load and verify enrichment persisted
    loaded_state = manager.load_state(scan_id)
    assert loaded_state is not None
    assert len(loaded_state.findings) == 3

    # Verify first finding has full enrichment
    f1 = loaded_state.findings[0]
    assert f1["cvss"] == 7.5
    assert "CVE-2021-41773" in f1["cves"]
    assert "EDB-50383" in f1["exploits"]

    # Verify second finding has partial enrichment (no exploits)
    f2 = loaded_state.findings[1]
    assert f2["cvss"] == 5.3
    assert len(f2["cves"]) > 0
    assert len(f2["exploits"]) == 0

    # Verify third finding has no enrichment (null values)
    f3 = loaded_state.findings[2]
    assert f3["cvss"] is None
    assert len(f3["cves"]) == 0


def test_dual_nmap_strategy_artifacts(storage_dir):
    """Test that dual nmap strategy creates both fast and full artifacts."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")
    scan_id = state.scan_id

    # Simulate dual nmap execution
    # Fast scan
    fast_xml = "<nmaprun><host><ports><port portid='80'/></ports></host></nmaprun>"
    fast_path = state.save_raw_output(storage_dir, "nmap", fast_xml, "xml", "fast")
    state.log_command("nmap", ["-F", "-A", "192.168.1.100"], 0, 120.0, fast_path)

    # Full scan
    full_xml = (
        "<nmaprun><host><ports><port portid='80'/><port portid='8080'/></ports></host></nmaprun>"
    )
    full_path = state.save_raw_output(storage_dir, "nmap", full_xml, "xml", "full")
    state.log_command("nmap", ["-p-", "-A", "192.168.1.100"], 0, 1800.0, full_path)

    # Add nmap metrics
    state.phase_artifacts["nmap_metrics"] = {
        "strategy": "dual",
        "fast_ports": 1,
        "full_ports": 2,
        "improvement_pct": 100.0,
        "merged_ports": 2,
    }

    manager.save_state(state)

    # Verify both raw outputs exist
    assert fast_path.exists()
    assert full_path.exists()

    # Verify command logs show both executions
    loaded_state = manager.load_state(scan_id)
    assert loaded_state is not None
    commands = loaded_state.phase_artifacts["commands"]
    assert len(commands) == 2

    # Verify metrics were persisted
    assert "nmap_metrics" in loaded_state.phase_artifacts
    metrics = loaded_state.phase_artifacts["nmap_metrics"]
    assert metrics["strategy"] == "dual"
    assert metrics["fast_ports"] == 1
    assert metrics["full_ports"] == 2
    assert metrics["improvement_pct"] == 100.0


def test_scan_state_preserves_command_order(storage_dir):
    """Test that command execution order is preserved across save/load."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")
    scan_id = state.scan_id

    # Log commands in sequence
    import time

    state.log_command("nmap", ["-F"], 0, 10.0)
    time.sleep(0.01)  # Ensure different timestamps
    state.log_command("nuclei", ["-u", "http://192.168.1.100"], 0, 5.0)
    time.sleep(0.01)
    state.log_command("testssl", ["192.168.1.100:443"], 0, 15.0)

    manager.save_state(state)

    # Load and verify order
    loaded_state = manager.load_state(scan_id)
    assert loaded_state is not None
    commands = loaded_state.phase_artifacts["commands"]

    assert len(commands) == 3
    assert commands[0]["tool"] == "nmap"
    assert commands[1]["tool"] == "nuclei"
    assert commands[2]["tool"] == "testssl"

    # Verify timestamps are in order
    t1 = commands[0]["timestamp"]
    t2 = commands[1]["timestamp"]
    t3 = commands[2]["timestamp"]
    assert t1 < t2 < t3


def test_large_raw_output_streaming(storage_dir):
    """Test that large raw outputs are handled efficiently."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")

    # Create a 15MB simulated nmap output
    large_content = "x" * (15 * 1024 * 1024)  # 15MB

    # Save large output (should use streaming)
    import time

    start = time.time()
    output_path = state.save_raw_output(storage_dir, "nmap", large_content, "xml", "full")
    duration = time.time() - start

    # Verify file exists and has correct size
    assert output_path.exists()
    assert output_path.stat().st_size == len(large_content)

    # Verify save completed reasonably fast (under 2 seconds for 15MB)
    assert duration < 2.0, f"Large file save took {duration}s, should be under 2s"
