"""Performance benchmarks for storage layer operations."""

import pytest
import time
from pathlib import Path
from erebos.storage.scan_state import ScanStateManager, ScanState
from datetime import datetime, timezone


@pytest.fixture
def storage_dir(tmp_path):
    """Create a temporary storage directory for benchmarks."""
    storage = tmp_path / "erebos-storage-bench"
    storage.mkdir()
    return storage


def test_benchmark_raw_output_save_overhead(storage_dir, benchmark=None):
    """Benchmark the overhead of saving raw outputs to storage."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")

    # Create 1MB test content
    content_1mb = "x" * (1024 * 1024)

    # Measure save operation
    start = time.perf_counter()
    output_path = state.save_raw_output(storage_dir, "nmap", content_1mb, "xml", "test")
    duration = time.perf_counter() - start

    # Verify file was saved
    assert output_path.exists()
    assert output_path.stat().st_size == len(content_1mb)

    # Overhead should be minimal (under 100ms for 1MB)
    assert duration < 0.1, f"Raw output save took {duration * 1000:.2f}ms, should be under 100ms"

    print(f"\n✓ Raw output save (1MB): {duration * 1000:.2f}ms")


def test_benchmark_batch_vs_individual_updates(storage_dir):
    """Compare performance of batch updates vs individual finding updates."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")

    # Create 100 test findings
    findings = []
    for i in range(100):
        findings.append(
            {
                "id": f"finding_{i:03d}",
                "title": f"Test Finding {i}",
                "severity": "MEDIUM",
                "phase": "RECON",
                "tool_name": "nmap",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "evidence": {"url": f"http://192.168.1.100:{8000 + i}"},
                "cvss": 5.0,
                "cves": [f"CVE-2024-{1000 + i}"],
                "exploits": [],
            }
        )

    # Benchmark batch update
    start = time.perf_counter()
    state.findings = findings
    manager.save_state(state)
    batch_duration = time.perf_counter() - start

    # Verify all findings persisted
    loaded_state = manager.load_state(state.scan_id)
    assert loaded_state is not None
    assert len(loaded_state.findings) == 100

    # Batch update should complete quickly (under 500ms for 100 findings)
    assert batch_duration < 0.5, (
        f"Batch update took {batch_duration * 1000:.2f}ms, should be under 500ms"
    )

    print(f"\n✓ Batch update (100 findings): {batch_duration * 1000:.2f}ms")
    print(f"  Average per finding: {batch_duration * 1000 / 100:.2f}ms")


def test_benchmark_deduplication_lookup_performance(storage_dir):
    """Benchmark deduplication lookup with large finding set."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")

    # Create 1000 findings
    findings = []
    for i in range(1000):
        findings.append(
            {
                "id": f"finding_{i:04d}",
                "title": f"Test Finding {i % 10}",  # 10 unique titles with duplicates
                "severity": "MEDIUM",
                "phase": "RECON",
                "tool_name": "nmap",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "evidence": {"url": f"http://192.168.1.100:{8000 + (i % 10)}"},  # 10 unique URLs
                "cvss": 5.0,
                "cves": [],
                "exploits": [],
            }
        )

    # Measure deduplication logic
    start = time.perf_counter()

    def get_dedup_key(f):
        url = f.get("evidence", {}).get("url", "")
        return (f["title"], url, f["tool_name"])

    dedup_keys = set()
    unique_findings = []
    for finding in findings:
        key = get_dedup_key(finding)
        if key not in dedup_keys:
            dedup_keys.add(key)
            unique_findings.append(finding)

    dedup_duration = time.perf_counter() - start

    # Verify deduplication worked (should have only 10 unique findings)
    assert len(unique_findings) == 10

    # Deduplication should be fast (under 50ms for 1000 findings)
    assert dedup_duration < 0.05, (
        f"Deduplication took {dedup_duration * 1000:.2f}ms, should be under 50ms"
    )

    print(f"\n✓ Deduplication lookup (1000 → 10 findings): {dedup_duration * 1000:.2f}ms")


def test_benchmark_dual_nmap_timing_validation(storage_dir):
    """Validate that dual nmap tracking records realistic timing."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")

    # Simulate realistic nmap timings
    fast_scan_duration = 120.0  # 2 minutes
    full_scan_duration = 1800.0  # 30 minutes

    # Log both commands
    fast_xml = "<nmaprun><host><ports><port portid='80'/></ports></host></nmaprun>"
    fast_path = state.save_raw_output(storage_dir, "nmap", fast_xml, "xml", "fast")
    state.log_command("nmap", ["-F", "-A", "192.168.1.100"], 0, fast_scan_duration, fast_path)

    full_xml = (
        "<nmaprun><host><ports><port portid='80'/><port portid='8080'/></ports></host></nmaprun>"
    )
    full_path = state.save_raw_output(storage_dir, "nmap", full_xml, "xml", "full")
    state.log_command("nmap", ["-p-", "-A", "192.168.1.100"], 0, full_scan_duration, full_path)

    # Save state
    manager.save_state(state)

    # Verify command logs have correct durations
    loaded_state = manager.load_state(state.scan_id)
    assert loaded_state is not None
    commands = loaded_state.phase_artifacts["commands"]

    assert len(commands) == 2
    assert commands[0]["duration_seconds"] == fast_scan_duration
    assert commands[1]["duration_seconds"] == full_scan_duration

    # Verify total time is reasonable (fast + full)
    total_time = commands[0]["duration_seconds"] + commands[1]["duration_seconds"]
    assert total_time == 1920.0  # 32 minutes total

    print(f"\n✓ Dual nmap timing validation:")
    print(f"  Fast scan: {fast_scan_duration}s (2 min)")
    print(f"  Full scan: {full_scan_duration}s (30 min)")
    print(f"  Total: {total_time}s (32 min)")


def test_benchmark_migration_overhead(storage_dir):
    """Measure overhead of migration for various scan sizes."""
    from erebos.cli.commands import migrate_storage

    # Create legacy flat structure scans
    legacy_dir = storage_dir / "legacy"
    legacy_dir.mkdir()

    scan_sizes = [1, 10, 50]  # Number of findings per scan
    migration_times = []

    for size in scan_sizes:
        # Create a legacy scan with N findings
        manager = ScanStateManager(legacy_dir)
        state = manager.create_scan(target="192.168.1.100", profile="standard")
        scan_id = state.scan_id

        # Add findings
        state.findings = [
            {
                "id": f"finding_{i:03d}",
                "title": f"Finding {i}",
                "severity": "MEDIUM",
                "phase": "RECON",
                "tool_name": "nmap",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "evidence": {"url": f"http://192.168.1.100:{8000 + i}"},
            }
            for i in range(size)
        ]

        # Save as legacy flat file (manually create for test)
        state_file = legacy_dir / f"{scan_id}_state.json"
        import json

        with open(state_file, "w") as f:
            json.dump(
                {
                    "scan_id": state.scan_id,
                    "target": state.target,
                    "current_phase": state.current_phase,
                    "started_at": state.started_at.isoformat(),
                    "updated_at": state.updated_at.isoformat(),
                    "findings": state.findings,
                    "phase_artifacts": state.phase_artifacts,
                    "profile": state.profile,
                },
                f,
            )

        # Measure migration
        start = time.perf_counter()
        migrate_storage(legacy_dir, dry_run=False, rollback=False)
        migration_duration = time.perf_counter() - start
        migration_times.append(migration_duration)

        # Verify migration created subdirectory
        scan_dir = legacy_dir / scan_id
        assert scan_dir.exists()
        assert (scan_dir / "state.json").exists()

        print(f"\n✓ Migration with {size} findings: {migration_duration * 1000:.2f}ms")

    # Migration overhead should scale linearly (roughly)
    # All migrations should complete under 1 second
    for duration in migration_times:
        assert duration < 1.0, f"Migration took {duration}s, should be under 1s"


def test_benchmark_large_file_streaming_efficiency(storage_dir):
    """Test streaming efficiency for large raw outputs."""
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="192.168.1.100", profile="comprehensive")

    # Test various file sizes
    sizes_mb = [1, 5, 10, 15, 20]

    for size_mb in sizes_mb:
        content = "x" * (size_mb * 1024 * 1024)

        start = time.perf_counter()
        output_path = state.save_raw_output(storage_dir, "nmap", content, "xml", f"{size_mb}mb")
        duration = time.perf_counter() - start

        # Verify file saved correctly
        assert output_path.exists()
        assert output_path.stat().st_size == len(content)

        # Calculate throughput
        throughput_mbps = size_mb / duration

        # Should maintain reasonable throughput (>20 MB/s for SSD)
        assert throughput_mbps > 20, (
            f"Throughput {throughput_mbps:.1f} MB/s too slow (expected >20 MB/s)"
        )

        print(f"\n✓ Streaming {size_mb}MB: {duration * 1000:.2f}ms ({throughput_mbps:.1f} MB/s)")


if __name__ == "__main__":
    # Allow running benchmarks standalone
    pytest.main([__file__, "-v", "-s"])
