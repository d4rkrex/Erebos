"""Tests for fleet orchestration: correlation, priority scoring, wiring."""

from __future__ import annotations



from erebos.agents.base import AgentMessage, AgentRole, FindingsBus
from erebos.agents.correlation import (
    CorrelatedFinding,
    CorrelationEngine,
    PriorityScorer,
)


class TestPriorityScorer:
    """Tests for finding priority scoring (REQ-03)."""

    def test_severity_weights(self):
        scorer = PriorityScorer()
        critical = CorrelatedFinding(title="t", severity="CRITICAL", signal_count=1)
        high = CorrelatedFinding(title="t", severity="HIGH", signal_count=1)
        medium = CorrelatedFinding(title="t", severity="MEDIUM", signal_count=1)
        low = CorrelatedFinding(title="t", severity="LOW", signal_count=1)

        assert scorer.score(critical) == 40
        assert scorer.score(high) == 30
        assert scorer.score(medium) == 20
        assert scorer.score(low) == 10

    def test_correlation_boost(self):
        """+20 per extra signal, capped at +40."""
        scorer = PriorityScorer()
        f2 = CorrelatedFinding(title="t", severity="HIGH", signal_count=2)
        f3 = CorrelatedFinding(title="t", severity="HIGH", signal_count=3)
        f5 = CorrelatedFinding(title="t", severity="HIGH", signal_count=5)

        assert scorer.score(f2) == 50  # 30 + 20
        assert scorer.score(f3) == 70  # 30 + 40
        assert scorer.score(f5) == 70  # 30 + 40 (capped)

    def test_exploitability_bonus(self):
        """Template available +15, auth gap +10."""
        scorer = PriorityScorer()
        f = CorrelatedFinding(title="t", severity="MEDIUM", signal_count=1)

        assert scorer.score(f, template_available=True) == 35  # 20 + 15
        assert scorer.score(f, auth_gap_confirmed=True) == 30  # 20 + 10
        assert scorer.score(f, template_available=True, auth_gap_confirmed=True) == 45

    def test_score_capped_at_100(self):
        """Score never exceeds 100."""
        scorer = PriorityScorer()
        f = CorrelatedFinding(title="t", severity="CRITICAL", signal_count=5)
        score = scorer.score(f, template_available=True, auth_gap_confirmed=True)
        assert score == 100  # 40 + 40 + 15 + 10 = 105 → capped at 100


class TestCorrelationEngine:
    """Tests for inter-agent correlation (REQ-02)."""

    def test_single_signal_no_boost(self, tmp_path):
        """Findings from single role get no correlation boost."""
        bus = FindingsBus(tmp_path / "bus.jsonl")
        bus.publish(AgentMessage(
            id="f1", role=AgentRole.VULN_SCAN, message_type="finding",
            payload={"title": "SQLi", "target": "example.com", "severity": "HIGH"},
        ))

        engine = CorrelationEngine(bus)
        results = engine.correlate()

        assert len(results) == 1
        assert results[0].signal_count == 1
        assert results[0].correlation_boost == 0

    def test_multi_signal_boost(self, tmp_path):
        """Findings from multiple roles get correlation boost."""
        bus = FindingsBus(tmp_path / "bus.jsonl")
        # Same target+title from two different roles
        bus.publish(AgentMessage(
            id="f1", role=AgentRole.VULN_SCAN, message_type="finding",
            payload={"title": "SQLi on /api/users", "target": "example.com", "severity": "HIGH"},
        ))
        bus.publish(AgentMessage(
            id="f2", role=AgentRole.CODE_AUDIT, message_type="finding",
            payload={"title": "SQLi on /api/users", "target": "example.com", "severity": "HIGH"},
        ))

        engine = CorrelationEngine(bus)
        results = engine.correlate()

        assert len(results) == 1
        assert results[0].signal_count == 2
        assert results[0].correlation_boost == 20

    def test_source_diversity_same_role_no_boost(self, tmp_path):
        """T-01: Same role reporting twice doesn't count as extra signal."""
        bus = FindingsBus(tmp_path / "bus.jsonl")
        bus.publish(AgentMessage(
            id="f1", role=AgentRole.VULN_SCAN, message_type="finding",
            payload={"title": "SQLi", "target": "example.com", "severity": "HIGH"},
        ))
        bus.publish(AgentMessage(
            id="f2", role=AgentRole.VULN_SCAN, message_type="finding",
            payload={"title": "SQLi", "target": "example.com", "severity": "HIGH"},
        ))

        engine = CorrelationEngine(bus)
        results = engine.correlate()

        assert len(results) == 1
        # Same role = 1 signal, no boost
        assert results[0].signal_count == 1
        assert results[0].correlation_boost == 0

    def test_auth_gap_increases_priority(self, tmp_path):
        """Code-audit auth gap signal boosts priority."""
        bus = FindingsBus(tmp_path / "bus.jsonl")
        bus.publish(AgentMessage(
            id="f1", role=AgentRole.VULN_SCAN, message_type="finding",
            payload={"title": "IDOR", "target": "example.com", "severity": "HIGH"},
        ))
        bus.publish(AgentMessage(
            id="f2", role=AgentRole.CODE_AUDIT, message_type="finding",
            payload={"title": "IDOR", "target": "example.com", "severity": "HIGH"},
        ))

        engine = CorrelationEngine(bus)
        results = engine.correlate()

        # code-audit presence = auth_gap_confirmed bonus
        assert results[0].priority_score > 30  # higher than just HIGH severity

    def test_caps_at_max_findings(self, tmp_path):
        """D-01: Correlation caps at 500 findings."""
        bus = FindingsBus(tmp_path / "bus.jsonl")
        # Write 600 findings
        for i in range(600):
            bus.publish(AgentMessage(
                id=f"f{i}", role=AgentRole.VULN_SCAN, message_type="finding",
                payload={"title": f"Finding {i}", "target": f"host{i}.com", "severity": "LOW"},
            ))

        engine = CorrelationEngine(bus)
        results = engine.correlate()

        # Should process at most 500
        assert len(results) <= 500

    def test_results_sorted_by_priority(self, tmp_path):
        """Results returned highest priority first."""
        bus = FindingsBus(tmp_path / "bus.jsonl")
        bus.publish(AgentMessage(
            id="low", role=AgentRole.VULN_SCAN, message_type="finding",
            payload={"title": "Low issue", "target": "a.com", "severity": "LOW"},
        ))
        bus.publish(AgentMessage(
            id="critical", role=AgentRole.VULN_SCAN, message_type="finding",
            payload={"title": "Critical issue", "target": "b.com", "severity": "CRITICAL"},
        ))

        engine = CorrelationEngine(bus)
        results = engine.correlate()

        assert results[0].severity == "CRITICAL"
        assert results[0].priority_score > results[-1].priority_score
