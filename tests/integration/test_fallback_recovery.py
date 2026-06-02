"""Integration tests for fallback recovery persistence and graceful degradation."""

from __future__ import annotations

from pathlib import Path

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.core.phase_agent import ReconAgent
from erebos.executors.base import ToolResult
from erebos.storage.scan_state import ScanState, ScanStateManager


class SequenceTransport:
    """Simple deterministic transport for recovery integration tests."""

    def __init__(self, results):
        self.results = {tool: list(values) for tool, values in results.items()}

    def execute(self, tool, args, env=None, timeout=None):
        tool_results = self.results.get(tool, [])
        if tool_results:
            return tool_results.pop(0)
        return ToolResult(tool=tool, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    def stream(self, tool, args, env=None):
        yield tool

    def available(self):
        return True


class StaticParser:
    """Parser stub returning fixed findings."""

    def __init__(self, findings=None):
        self.findings = findings or []

    def parse(self, output):
        return list(self.findings)


def make_result(tool: str, exit_code: int, stdout: str = "", stderr: str = "") -> ToolResult:
    return ToolResult(
        tool=tool,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.1,
    )


def test_fallback_events_persist_to_scan_state(tmp_path):
    storage_dir = tmp_path / "storage"
    manager = ScanStateManager(storage_dir)
    state = manager.create_scan(target="example.com", profile="standard")
    transport = SequenceTransport(
        {
            "masscan": [make_result("masscan", 126, stderr="Permission denied")],
            "rustscan": [make_result("rustscan", 0, stdout="[]")],
        }
    )
    agent = ReconAgent(
        transport=transport,
        parsers={"masscan": StaticParser()},
        scan_id=state.scan_id,
        scan_state=state,
        storage_dir=storage_dir,
    )

    agent._run_masscan(
        "example.com",
        {
            "enable_intelligent_error_handler": True,
            "timeout": 5,
        },
    )
    manager.save_state(state)

    restored = manager.load_state(state.scan_id)
    assert restored is not None
    events = restored.get_fallback_events()
    assert len(events) >= 1
    assert events[0]["tool"] == "masscan"
    assert events[0]["recovery_strategy"] == "fallback"


def test_recon_continues_after_degraded_masscan_failure(tmp_path):
    storage_dir = tmp_path / "storage"
    state = ScanState(scan_id="scan-continue", target="example.com", profile="standard")
    katana_finding = Finding(
        tool="katana",
        severity=Severity.INFO,
        title="Discovered URL",
        description="Recovered URL from crawl",
        evidence=FindingEvidence(url="https://example.com/admin"),
        phase_found=Phase.RECON,
    )
    transport = SequenceTransport(
        {
            "katana": [make_result("katana", 0, stdout="https://example.com/admin")],
            "masscan": [make_result("masscan", 126, stderr="Permission denied")],
            "rustscan": [make_result("rustscan", 1, stderr="still denied")],
            "nmap": [make_result("nmap", 1, stderr="still denied")],
        }
    )
    agent = ReconAgent(
        transport=transport,
        parsers={"katana": StaticParser([katana_finding]), "masscan": StaticParser([])},
        scan_id=state.scan_id,
        scan_state=state,
        storage_dir=storage_dir,
    )

    findings = agent.execute(
        "example.com",
        {
            "enable_inference": False,
            "enable_intelligent_error_handler": True,
            "run_masscan": True,
            "run_amass": False,
            "run_subfinder": False,
            "run_ffuf": False,
            "run_gobuster": False,
            "run_dirb": False,
            "run_nikto": False,
            "timeout": 5,
        },
    )

    assert any(f.title == "Discovered URL" for f in findings)
    assert len(state.get_fallback_events()) >= 1
