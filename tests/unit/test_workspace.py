"""Tests for WorkspaceManager."""

import json
import tempfile
from pathlib import Path

import pytest

from erebos.storage.workspace import AuditEntry, WorkspaceManager, WorkspaceSession


@pytest.fixture
def workspace_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def manager(workspace_dir):
    return WorkspaceManager(workspace_dir)


class TestWorkspaceManager:
    def test_create_auto_named(self, manager):
        session = manager.create(None, "example.com")
        assert "example_com" in session.name
        assert session.target == "example.com"
        assert session.status == "active"
        assert session.scan_id is not None

    def test_create_named_adds_suffix(self, manager):
        session = manager.create("my-audit", "example.com")
        assert session.name.startswith("my-audit_")
        # Suffix is 6 hex chars
        suffix = session.name.split("my-audit_")[1]
        assert len(suffix) == 6

    def test_create_unique_names(self, manager):
        """Each create generates a unique name due to random suffix (SPOOF-001)."""
        session1 = manager.create("test", "example.com")
        session2 = manager.create("test", "example.com")
        assert session1.name != session2.name

    def test_load(self, manager):
        created = manager.create("load-test", "target.io")
        loaded = manager.load(created.name)
        assert loaded.target == "target.io"
        assert loaded.name == created.name

    def test_load_not_found(self, manager):
        with pytest.raises(FileNotFoundError):
            manager.load("nonexistent")

    def test_find_by_prefix(self, manager):
        session = manager.create("prefix-test", "example.com")
        found = manager.find_by_prefix("prefix-test")
        assert found == session.name

    def test_find_by_prefix_not_found(self, manager):
        result = manager.find_by_prefix("nonexistent")
        assert result is None

    def test_mark_phase_complete(self, manager):
        session = manager.create("phase-test", "target.com")
        manager.mark_phase_complete(session.name, "recon")
        loaded = manager.load(session.name)
        assert "recon" in loaded.completed_phases

    def test_mark_tool_complete(self, manager):
        session = manager.create("tool-test", "target.com")
        manager.mark_tool_complete(session.name, "vuln-scan", "nuclei")
        loaded = manager.load(session.name)
        assert "nuclei" in loaded.completed_tools["vuln-scan"]

    def test_can_resume_active(self, manager):
        session = manager.create("resume-test", "target.com")
        can_resume, invalidated = manager.can_resume(session.name)
        assert can_resume is True
        assert invalidated == []

    def test_can_resume_complete_workspace(self, manager):
        session = manager.create("done-test", "target.com")
        manager.set_status(session.name, "complete")
        can_resume, _ = manager.can_resume(session.name)
        assert can_resume is False

    def test_can_resume_invalidates_missing_deliverables(self, manager):
        session = manager.create("invalid-test", "target.com")
        # Manually add a completed phase without the findings file
        loaded = manager.load(session.name)
        loaded.completed_phases.append("recon")
        # Save directly
        session_path = manager.base_dir / session.name / "session.json"
        session_path.write_text(json.dumps(loaded.model_dump(mode="json")))

        can_resume, invalidated = manager.can_resume(session.name)
        assert can_resume is True
        assert "recon" in invalidated

    def test_list_all(self, manager):
        manager.create("ws-1", "a.com")
        manager.create("ws-2", "b.com")
        sessions = manager.list_all()
        assert len(sessions) == 2

    def test_set_status(self, manager):
        session = manager.create("status-test", "target.com")
        manager.set_status(session.name, "paused")
        loaded = manager.load(session.name)
        assert loaded.status == "paused"

    def test_audit_log_created(self, manager):
        session = manager.create("audit-test", "target.com")
        audit_path = manager.base_dir / session.name / "audit.log"
        assert audit_path.exists()
        content = audit_path.read_text()
        assert "workspace_create" in content

    def test_log_event(self, manager):
        session = manager.create("event-test", "target.com")
        manager.log_event(
            session.name,
            AuditEntry(
                event_type="tool_start",
                phase="vuln-scan",
                tool="nuclei",
                message="Starting nuclei scan",
            ),
        )
        audit_path = manager.base_dir / session.name / "audit.log"
        content = audit_path.read_text()
        assert "tool_start" in content
        assert "nuclei" in content
