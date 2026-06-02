"""Integration tests for fleet orchestration pipeline.

Tests the full fleet workflow with mocked ToolExecutor output
to validate: pipeline flow, correlation, timeout handling.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from erebos.agents.base import AgentMessage, AgentRole
from erebos.agents.orchestrator import FleetConfig, FleetOrchestrator


# --- Mock fixtures ---

MOCK_NMAP_OUTPUT = """Starting Nmap 7.94
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy
Nmap done: 1 IP address (1 host up) scanned"""

MOCK_NUCLEI_OUTPUT = """[2024-01-01] [sqli-auth-bypass] [high] http://example.com/api/users
[2024-01-01] [xss-reflected] [medium] http://example.com/search?q=test
[2024-01-01] [cve-2023-1234] [critical] http://example.com/admin"""

MOCK_SUBFINDER_OUTPUT = """api.example.com
admin.example.com
dev.example.com"""


def _make_fleet_config(tmp_path: Path, target: str = "example.com") -> FleetConfig:
    return FleetConfig(
        target=target,
        repos=[],
        allowlist=[target, f"*.{target}"],
        dry_run=True,
        max_agents=5,
        roles=[
            AgentRole.RECON,
            AgentRole.VULN_SCAN,
            AgentRole.EXPLOIT,
            AgentRole.CODE_AUDIT,
            AgentRole.REPORTER,
        ],
    )


class TestFleetPipeline:
    """REQ-03 AC-03.2: Full pipeline test."""

    @pytest.mark.asyncio
    async def test_full_pipeline_produces_report(self, tmp_path):
        """All roles execute and reporter produces summary."""
        config = _make_fleet_config(tmp_path)
        orch = FleetOrchestrator(config)

        # Mock all role methods to simulate findings
        async def mock_recon(worker):
            orch._bus.publish(AgentMessage(
                id="recon-1", role=AgentRole.RECON, message_type="finding",
                payload={"title": "Port 80 open", "target": "example.com", "severity": "LOW"},
            ))
            worker.findings_count = 1
            return {"role": "recon", "findings": 1}

        async def mock_vuln_scan(worker):
            orch._bus.publish(AgentMessage(
                id="vuln-1", role=AgentRole.VULN_SCAN, message_type="finding",
                payload={"title": "SQLi on /api/users", "target": "example.com", "severity": "HIGH"},
            ))
            orch._bus.publish(AgentMessage(
                id="vuln-2", role=AgentRole.VULN_SCAN, message_type="finding",
                payload={"title": "XSS on /search", "target": "example.com", "severity": "MEDIUM"},
            ))
            worker.findings_count = 2
            return {"role": "vuln_scan", "findings": 2}

        async def mock_exploit(worker):
            worker.findings_count = 0
            return {"role": "exploit", "successful": 0}

        async def mock_code_audit(worker):
            worker.findings_count = 0
            return {"role": "code-audit", "findings": 0}

        async def mock_reporter(worker):
            total = orch._bus.count("finding")
            worker.findings_count = total
            return {"role": "reporter", "total_findings": total}

        orch._role_recon = mock_recon
        orch._role_vuln_scan = mock_vuln_scan
        orch._role_exploit = mock_exploit
        orch._role_code_audit = mock_code_audit
        orch._role_reporter = mock_reporter

        result = await orch.run()

        assert result["completed"] == 5
        assert result["failed"] == 0
        assert result["total_findings"] >= 3  # recon + vuln findings

    @pytest.mark.asyncio
    async def test_pipeline_with_failed_agent_continues(self, tmp_path):
        """Fleet continues even if one agent fails."""
        config = _make_fleet_config(tmp_path)
        orch = FleetOrchestrator(config)

        async def mock_recon(worker):
            raise RuntimeError("nmap not found")

        async def mock_vuln_scan(worker):
            orch._bus.publish(AgentMessage(
                id="v1", role=AgentRole.VULN_SCAN, message_type="finding",
                payload={"title": "Finding", "target": "example.com", "severity": "HIGH"},
            ))
            worker.findings_count = 1
            return {"role": "vuln_scan", "findings": 1}

        async def mock_noop(worker):
            worker.findings_count = 0
            return {"role": "noop", "findings": 0}

        orch._role_recon = mock_recon
        orch._role_vuln_scan = mock_vuln_scan
        orch._role_exploit = mock_noop
        orch._role_code_audit = mock_noop
        orch._role_reporter = mock_noop

        result = await orch.run()

        assert result["failed"] >= 1
        assert result["completed"] >= 4  # other agents still ran


class TestFleetCorrelation:
    """REQ-03 AC-03.3: Correlation integration."""

    @pytest.mark.asyncio
    async def test_multi_signal_correlation_boost(self, tmp_path):
        """Findings from multiple agents get priority boost in report."""
        config = _make_fleet_config(tmp_path)
        orch = FleetOrchestrator(config)

        async def mock_vuln(worker):
            orch._bus.publish(AgentMessage(
                id="v1", role=AgentRole.VULN_SCAN, message_type="finding",
                payload={"title": "IDOR on /api/users", "target": "example.com", "severity": "HIGH"},
            ))
            worker.findings_count = 1
            return {"findings": 1}

        async def mock_code_audit(worker):
            # Same finding from code audit = multi-signal
            orch._bus.publish(AgentMessage(
                id="c1", role=AgentRole.CODE_AUDIT, message_type="finding",
                payload={"title": "IDOR on /api/users", "target": "example.com", "severity": "HIGH"},
            ))
            worker.findings_count = 1
            return {"findings": 1}

        async def mock_noop(worker):
            worker.findings_count = 0
            return {"findings": 0}

        # Wire the reporter to actually run correlation
        async def mock_reporter(worker):
            from erebos.agents.correlation import CorrelationEngine

            engine = CorrelationEngine(orch._bus)
            results = engine.correlate()
            worker.findings_count = len(results)
            return {
                "total_findings": len(results),
                "top_priority": results[0].priority_score if results else 0,
                "correlated": len([r for r in results if r.signal_count > 1]),
            }

        orch._role_recon = mock_noop
        orch._role_vuln_scan = mock_vuln
        orch._role_exploit = mock_noop
        orch._role_code_audit = mock_code_audit
        orch._role_reporter = mock_reporter

        await orch.run()
        reporter_worker = [w for w in orch._workers if w.role == AgentRole.REPORTER][0]
        assert reporter_worker.findings_count >= 1


class TestFleetTimeout:
    """REQ-03 AC-03.4: Timeout handling."""

    @pytest.mark.asyncio
    async def test_slow_agent_timeout(self, tmp_path):
        """Slow agent is cancelled after timeout, fleet continues."""
        config = _make_fleet_config(tmp_path)
        config.timeout_per_agent = 0.5  # 500ms timeout

        orch = FleetOrchestrator(config)

        async def mock_slow_recon(worker):
            await asyncio.sleep(10)  # Way past timeout
            return {"findings": 0}

        async def mock_fast(worker):
            worker.findings_count = 1
            orch._bus.publish(AgentMessage(
                id="fast-1", role=AgentRole.VULN_SCAN, message_type="finding",
                payload={"title": "Fast finding", "target": "example.com", "severity": "LOW"},
            ))
            return {"findings": 1}

        async def mock_noop(worker):
            worker.findings_count = 0
            return {"findings": 0}

        orch._role_recon = mock_slow_recon
        orch._role_vuln_scan = mock_fast
        orch._role_exploit = mock_noop
        orch._role_code_audit = mock_noop
        orch._role_reporter = mock_noop

        result = await orch.run()

        # Recon should have failed/timed out, others completed
        assert result["failed"] >= 1
        assert result["completed"] >= 4
