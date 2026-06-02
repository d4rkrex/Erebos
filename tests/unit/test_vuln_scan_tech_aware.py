"""Tests for VT-Spec TA-002: Tech-aware template selection in VulnScanRole."""

from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from erebos.agents.base import AgentMessage, AgentRole, FindingsBus
from erebos.agents.roles.vuln_scan import VulnScanRole
from erebos.scanning.tech_detection import TECH_TEMPLATE_MAP
from erebos.agents.tool_executor import ToolResult


class FakeToolExecutor:
    """Fake executor that records invocations."""

    def __init__(self):
        self.calls: List[Dict[str, Any]] = []

    async def run(self, tool: str, args: List[str], timeout: int = 60) -> ToolResult:
        self.calls.append({"tool": tool, "args": args, "timeout": timeout})
        return ToolResult(tool=tool, exit_code=0, stdout="", stderr="", duration_seconds=0.1)


def _make_bus_with_findings(findings: List[Dict[str, Any]], tmp_path: Path) -> FindingsBus:
    """Create a FindingsBus pre-populated with findings."""
    bus_path = tmp_path / "findings-bus.jsonl"
    with open(bus_path, "w") as f:
        for finding in findings:
            msg = AgentMessage(
                id=f"test-{finding.get('title', 'x')[:10]}",
                role=AgentRole.RECON,
                message_type="finding",
                payload=finding,
            )
            f.write(msg.model_dump_json() + "\n")
    return FindingsBus(bus_path)


class TestDetectTechnologies:
    """Test _detect_technologies reads bus and identifies tech stack."""

    def test_detects_nodejs_from_wappalyzer_title(self, tmp_path):
        bus = _make_bus_with_findings(
            [{"title": "Wappalyzer Technology Detection", "description": "Node.js", "target": "x"}],
            tmp_path,
        )
        role = VulnScanRole(
            executor=FakeToolExecutor(),
            bus=bus,
            agent_id="test",
            target="example.com",
        )
        techs = role._detect_technologies()
        assert "nodejs" in techs
        assert "express" in techs

    def test_detects_mongodb_from_evidence(self, tmp_path):
        bus = _make_bus_with_findings(
            [
                {
                    "title": "Mongoose Server Detection",
                    "description": "mongoose detected",
                    "target": "x",
                    "evidence": {"output": "MongoDB connection established"},
                }
            ],
            tmp_path,
        )
        role = VulnScanRole(
            executor=FakeToolExecutor(),
            bus=bus,
            agent_id="test",
            target="example.com",
        )
        techs = role._detect_technologies()
        assert "mongodb" in techs
        assert "mongoose" in techs

    def test_detects_wordpress_from_url(self, tmp_path):
        bus = _make_bus_with_findings(
            [
                {
                    "title": "Discovered URL",
                    "description": "",
                    "target": "https://site.com/wp-admin",
                    "evidence": {"url": "https://site.com/wp-admin"},
                }
            ],
            tmp_path,
        )
        role = VulnScanRole(
            executor=FakeToolExecutor(),
            bus=bus,
            agent_id="test",
            target="site.com",
        )
        techs = role._detect_technologies()
        assert "wordpress" in techs
        assert "php" in techs

    def test_returns_empty_for_no_tech_signals(self, tmp_path):
        bus = _make_bus_with_findings(
            [{"title": "Open port 443", "description": "HTTPS", "target": "x"}],
            tmp_path,
        )
        role = VulnScanRole(
            executor=FakeToolExecutor(),
            bus=bus,
            agent_id="test",
            target="example.com",
        )
        techs = role._detect_technologies()
        assert techs == set()

    def test_detects_python_flask(self, tmp_path):
        bus = _make_bus_with_findings(
            [
                {
                    "title": "Tech Detection",
                    "description": "Flask framework detected via header",
                    "target": "x",
                }
            ],
            tmp_path,
        )
        role = VulnScanRole(
            executor=FakeToolExecutor(),
            bus=bus,
            agent_id="test",
            target="example.com",
        )
        techs = role._detect_technologies()
        assert "flask" in techs
        assert "python" in techs


class TestTechTemplateExpansion:
    """Test that detected techs expand nuclei template directories."""

    @pytest.mark.asyncio
    async def test_nodejs_adds_injection_templates(self, tmp_path):
        # Create minimal template dirs
        templates_dir = tmp_path / "nuclei-templates"
        for d in [
            "http/technologies",
            "http/exposures",
            "http/misconfiguration",
            "dast/vulnerabilities/sqli",
            "dast/vulnerabilities/injection",
            "dast/vulnerabilities/ssti",
            "dast/vulnerabilities/ssrf",
        ]:
            (templates_dir / d).mkdir(parents=True)

        bus = _make_bus_with_findings(
            [{"title": "Wappalyzer: Node.js", "description": "nodejs", "target": "x"}],
            tmp_path,
        )
        executor = FakeToolExecutor()
        role = VulnScanRole(
            executor=executor,
            bus=bus,
            agent_id="test",
            target="example.com",
        )

        with patch.object(role, "_find_nuclei_templates", return_value=templates_dir):
            await role._run_nuclei("example.com", {"nodejs", "express"})

        # Should have run nuclei for base dirs + tech dirs + tags
        tools_called = [c["tool"] for c in executor.calls]
        assert all(t == "nuclei" for t in tools_called)

        # Check that injection-related dirs were included
        all_args = [" ".join(c["args"]) for c in executor.calls]
        has_sqli = any("dast/vulnerabilities/sqli" in a for a in all_args)
        has_injection = any("dast/vulnerabilities/injection" in a for a in all_args)
        has_tags = any("-tags" in a and "nosql" in a for a in all_args)

        assert has_sqli, "Should run sqli templates for Node.js target"
        assert has_injection, "Should run injection templates for Node.js target"
        assert has_tags, "Should run tag-based nosql scan for Node.js target"

    @pytest.mark.asyncio
    async def test_no_techs_runs_base_dirs_only(self, tmp_path):
        templates_dir = tmp_path / "nuclei-templates"
        for d in ["http/technologies", "http/exposures", "http/misconfiguration"]:
            (templates_dir / d).mkdir(parents=True)

        bus = FindingsBus(tmp_path / "empty-bus.jsonl")
        executor = FakeToolExecutor()
        role = VulnScanRole(
            executor=executor,
            bus=bus,
            agent_id="test",
            target="example.com",
        )

        with patch.object(role, "_find_nuclei_templates", return_value=templates_dir):
            await role._run_nuclei("example.com", set())

        # Should only run 3 base dirs, no tags scan
        assert len(executor.calls) == 3
        all_args = [" ".join(c["args"]) for c in executor.calls]
        assert not any("-tags" in a for a in all_args)


class TestTechTemplateMapCompleteness:
    """Validate TECH_TEMPLATE_MAP structure."""

    def test_all_entries_have_dirs_and_tags(self):
        for tech, mapping in TECH_TEMPLATE_MAP.items():
            assert "dirs" in mapping, f"{tech} missing 'dirs'"
            assert "tags" in mapping, f"{tech} missing 'tags'"
            assert isinstance(mapping["dirs"], list)
            assert isinstance(mapping["tags"], list)
            assert len(mapping["dirs"]) > 0, f"{tech} has empty dirs"
            assert len(mapping["tags"]) > 0, f"{tech} has empty tags"
