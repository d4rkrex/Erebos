"""Focused regression tests for vuln-scan tool execution."""

from typing import Dict, List, Tuple

from erebos.core.phase_agent import VulnScanAgent
from erebos.core.finding import Phase, ScanMode, Severity
from erebos.core.target_profile import RiskLevel, TargetType
from erebos.executors.base import ToolResult
from erebos.parsers.nikto import NiktoParser
from erebos.parsers.nuclei import NucleiParser
from erebos.parsers.sqlmap import SqlmapParser
from erebos.storage.scan_state import ScanState


class SequenceTransport:
    """Transport that returns pre-seeded results per tool."""

    def __init__(self, sequences: Dict[str, List[ToolResult]]):
        self.sequences = {tool: list(results) for tool, results in sequences.items()}
        self.calls: List[Tuple[str, List[str]]] = []

    def execute(self, tool: str, args, env=None, timeout=None) -> ToolResult:
        self.calls.append((tool, list(args)))
        results = self.sequences.get(tool, [])
        if results:
            return results.pop(0)
        return ToolResult(tool=tool, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    def stream(self, tool: str, args, env=None):
        yield tool

    def available(self) -> bool:
        return True


def make_result(tool: str, exit_code: int, stdout: str = "", stderr: str = "") -> ToolResult:
    return ToolResult(
        tool=tool,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.1,
    )


class MockService:
    def __init__(self, service: str):
        self.service = service


class MockProfile:
    def __init__(self, risk_level=RiskLevel.LOW, services=None):
        self.risk_level = risk_level
        self.services = services or [MockService("http"), MockService("https")]
        self.target_type = TargetType.WEB_APPLICATION
        self.technologies = []
        self.attack_surface_score = 2.0
        self.confidence = 0.7


def test_run_nuclei_uses_jsonl_flag_and_parses_jsonl_output():
    transport = SequenceTransport(
        {
            "nuclei": [
                make_result(
                    "nuclei",
                    0,
                    stdout='{"template-id":"xss","info":{"name":"XSS","severity":"high"},"matched-at":"https://example.com"}\n',
                )
            ]
        }
    )
    agent = VulnScanAgent(transport=transport, parsers={"nuclei": NucleiParser()})

    findings = agent._run_nuclei(["https://example.com"], {})

    assert len(findings) == 1
    assert "-j" in transport.calls[0][1]
    assert "-json" not in transport.calls[0][1]


def test_run_nikto_uses_host_and_format_arguments():
    transport = SequenceTransport(
        {
            "nikto": [
                make_result(
                    "nikto",
                    0,
                    stdout="+ Target: https://example.com\n+ Server: nginx\n+ Retrieved x-powered-by header: PHP/8.2\n",
                )
            ]
        }
    )
    agent = VulnScanAgent(transport=transport, parsers={"nikto": NiktoParser()})

    agent._run_nikto("https://example.com", {})

    assert transport.calls[0][1][:4] == ["-host", "https://example.com", "-Format", "txt"]


def test_run_nikto_adds_internal_maxtime_for_simple_low_risk_targets():
    transport = SequenceTransport({"nikto": [make_result("nikto", 0, stdout="")]})
    agent = VulnScanAgent(transport=transport, parsers={"nikto": NiktoParser()})

    agent._run_nikto(
        "example.com",
        {
            "target_profile": MockProfile(),
            "timeout": 300,
        },
    )

    assert transport.calls[0][1][:6] == [
        "-host",
        "example.com",
        "-Format",
        "txt",
        "-maxtime",
        "4m30s",
    ]


def test_nikto_help_output_is_marked_as_failure():
    agent = VulnScanAgent(transport=SequenceTransport({}), parsers={})
    result = make_result(
        "nikto",
        0,
        stdout="   Options:\n       -Format+           Save file (-o) format:\n       -host+             Target host/URL\n",
    )

    normalized = agent._normalize_nikto_result(result)

    assert normalized.exit_code == 2
    assert "usage/help output" in normalized.stderr


def test_nikto_maxtime_output_is_marked_degraded():
    agent = VulnScanAgent(transport=SequenceTransport({}), parsers={})
    result = make_result(
        "nikto",
        0,
        stdout="+ ERROR: Host maximum execution time of 4m30 seconds reached\n",
    )

    normalized = agent._normalize_nikto_result(result)

    assert getattr(normalized, "degraded", False) is True
    assert getattr(normalized, "fallback_source", None) == "maxtime"


def test_tool_status_records_skipped_coverage_for_reporting():
    state = ScanState(scan_id="scan-1", target="example.com")
    agent = VulnScanAgent(transport=SequenceTransport({}), parsers={}, scan_state=state)
    result = make_result(
        "nikto", 75, stderr="Coverage skipped after recovery exhaustion: timed out"
    )
    setattr(result, "degraded", True)
    setattr(result, "fallback_source", "skip")
    setattr(result, "attempted_tools", ["nikto", "nikto"])
    setattr(
        result,
        "recovery_context",
        {
            "attempts": [
                {
                    "tool": "nikto",
                    "error_type": "timeout",
                }
            ]
        },
    )

    agent._record_tool_status("nikto", result)

    assert state.phase_artifacts["tool_status"][0]["tool"] == "nikto"
    assert state.phase_artifacts["tool_status"][0]["status"] == "skipped"
    assert state.phase_artifacts["tool_status"][0]["error_types"] == ["timeout"]


def test_sqlmap_tool_status_is_recorded_for_successful_coverage():
    state = ScanState(scan_id="scan-sqlmap", target="example.com")
    transport = SequenceTransport(
        {
            "sqlmap": [
                make_result(
                    "sqlmap",
                    0,
                    stdout='[{"type":"boolean-based blind","parameter":"id","title":"SQL Injection"}]',
                )
            ]
        }
    )
    agent = VulnScanAgent(
        transport=transport,
        parsers={"sqlmap": SqlmapParser()},
        scan_state=state,
    )

    agent._run_sqlmap(["https://example.com/item?id=1"], {})

    sqlmap_status = next(
        item for item in state.phase_artifacts["tool_status"] if item["tool"] == "sqlmap"
    )
    assert sqlmap_status["status"] == "success"
    assert sqlmap_status["attempted_tools"] == ["sqlmap"]


def test_run_sqlmap_avoids_unsupported_json_output_flag():
    state = ScanState(scan_id="scan-sqlmap-cmd", target="example.com")
    transport = SequenceTransport({"sqlmap": [make_result("sqlmap", 0, stdout="")]})
    agent = VulnScanAgent(
        transport=transport,
        parsers={"sqlmap": SqlmapParser()},
        scan_state=state,
    )

    agent._run_sqlmap(["https://example.com/item?id=1"], {})

    assert "--json-output" not in transport.calls[0][1]
    assert state.phase_artifacts["commands"][0]["tool"] == "sqlmap"
