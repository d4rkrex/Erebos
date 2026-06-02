"""Integration tests for scan flow."""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from erebos.core.finding import Finding, Phase, Severity
from erebos.core.orchestrator import Orchestrator
from erebos.core.scan_profile import get_profile
from erebos.executors.base import Transport, ToolResult
from erebos.parsers.base import Parser
from erebos.storage import FindingStore, ScanStateManager


class MockTransport:
    """Mock transport for testing."""

    def __init__(self, should_fail=False):
        self.should_fail = should_fail
        self.executed_tools = []

    def execute(self, tool: str, args, env=None, timeout=300) -> ToolResult:
        self.executed_tools.append(tool)
        if self.should_fail:
            return ToolResult(
                tool=tool,
                exit_code=1,
                stdout="",
                stderr="Error",
                duration_seconds=1.0,
            )
        # Return empty JSON array for nuclei
        return ToolResult(
            tool=tool,
            exit_code=0,
            stdout="[]",
            stderr="",
            duration_seconds=1.0,
        )

    def stream(self, tool: str, args, env=None):
        yield f"Starting {tool}"

    def available(self) -> bool:
        return True


class MockParser:
    """Mock parser for testing."""

    def __init__(self):
        self.parsed = False

    def parse(self, output: str):
        self.parsed = True
        return []

    def can_parse(self, output: str) -> bool:
        return True


class TestScanFlow:
    """Integration tests for full scan flow."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_dir = Path(self.temp_dir)

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_orchestrator_initialization(self):
        """Test orchestrator can be initialized."""
        profile = get_profile("standard")
        transport = MockTransport()
        parser = MockParser()

        orchestrator = Orchestrator(
            target="example.com",
            profile=profile,
            transport=transport,
            parsers={"nuclei": parser},
            storage_dir=self.storage_dir,
        )

        assert orchestrator.target == "example.com"
        assert orchestrator.profile == profile

    def test_orchestrator_run_recon_phase(self):
        """Test running recon phase."""
        profile = get_profile("minimal")
        transport = MockTransport()
        parser = MockParser()

        orchestrator = Orchestrator(
            target="example.com",
            profile=profile,
            transport=transport,
            parsers={"katana": parser, "nuclei": parser},
            storage_dir=self.storage_dir,
        )

        # Run only recon phase
        result = orchestrator.run_phase(Phase.RECON)

        assert result is True
        assert orchestrator.state_machine.current_phase == Phase.RECON

    def test_orchestrator_state_persistence(self):
        """Test scan state is persisted."""
        profile = get_profile("standard")
        transport = MockTransport()
        parser = MockParser()

        orchestrator = Orchestrator(
            target="example.com",
            profile=profile,
            transport=transport,
            parsers={"katana": parser, "nuclei": parser},
            storage_dir=self.storage_dir,
            scan_id="test-123",
        )

        # Run recon phase
        orchestrator.run_phase(Phase.RECON)

        # Check state was saved
        state_manager = ScanStateManager(self.storage_dir)
        state = state_manager.load_state("test-123")

        assert state is not None
        assert state.target == "example.com"
        assert state.current_phase == "recon"

    def test_orchestrator_abort(self):
        """Test scan can be aborted."""
        profile = get_profile("standard")
        transport = MockTransport()
        parser = MockParser()

        orchestrator = Orchestrator(
            target="example.com",
            profile=profile,
            transport=transport,
            parsers={"katana": parser, "nuclei": parser},
            storage_dir=self.storage_dir,
            scan_id="test-abort",
        )

        # Run recon
        orchestrator.run_phase(Phase.RECON)

        # Abort
        orchestrator.abort()

        assert orchestrator.state_machine.is_aborted()

    def test_orchestrator_status(self):
        """Test getting scan status."""
        profile = get_profile("standard")
        transport = MockTransport()
        parser = MockParser()

        orchestrator = Orchestrator(
            target="example.com",
            profile=profile,
            transport=transport,
            parsers={"katana": parser, "nuclei": parser},
            storage_dir=self.storage_dir,
            scan_id="test-status",
        )

        # Run a phase
        orchestrator.run_phase(Phase.RECON)

        # Get status
        status = orchestrator.get_status()

        assert status["scan_id"] == "test-status"
        assert status["target"] == "example.com"
        assert status["phase"] == "recon"
        assert status["findings_count"] == 0


class TestStorageIntegration:
    """Integration tests for storage layer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_dir = Path(self.temp_dir)

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_finding_store_crud(self):
        """Test finding store operations."""
        store = FindingStore(self.storage_dir)

        # Create a finding
        finding = Finding(
            tool="nuclei",
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="Test",
            phase_found=Phase.RECON,
        )

        # Add finding
        store.add_finding("scan-1", finding)

        # Retrieve findings
        findings = store.get_findings("scan-1")

        assert len(findings) == 1
        assert findings[0].title == "SQL Injection"

    def test_state_manager_crud(self):
        """Test state manager operations."""
        manager = ScanStateManager(self.storage_dir)

        # Create scan
        state = manager.create_scan("example.com", "standard")

        assert state.target == "example.com"
        assert state.profile == "standard"
        assert state.scan_id is not None

        # Load state
        loaded = manager.load_state(state.scan_id)

        assert loaded is not None
        assert loaded.target == "example.com"

        # List scans
        scans = manager.list_scans()
        assert state.scan_id in scans
