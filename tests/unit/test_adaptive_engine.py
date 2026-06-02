"""Unit tests for adaptive exploit engine (Phase 1 + Phase 2)."""

from unittest.mock import patch

import pytest

from erebos.agents.fact_graph import Fact, FactEdge, FactGraph, FactType, EdgeType
from erebos.core.finding import Finding, Phase, Severity
from erebos.exploits.base import (
    ExploitEvidence,
    ExploitPlan,
    ExploitResult,
    ExploitStatus,
    ExploitStep,
    SuccessCriteria,
)
from erebos.exploits.detectors.auth_bypass_validator import AuthBypassValidator
from erebos.exploits.detectors.reflection_detector import ReflectionDetector
from erebos.exploits.strategy import ExploitStrategy


class TestFactGraph:
    """Tests for FactGraph data model and queries."""

    def test_add_fact(self):
        g = FactGraph()

        fact = g.add_fact(Fact(fact_type=FactType.ENDPOINT, data={"url": "http://test.com"}))

        assert fact.id.startswith("fact-")
        assert g.get_fact(fact.id) is fact

    def test_add_edge(self):
        g = FactGraph()
        endpoint = g.add_fact(Fact(fact_type=FactType.ENDPOINT, data={"url": "http://a.com"}))
        vuln = g.add_fact(Fact(fact_type=FactType.VULNERABILITY, data={"cwe": "CWE-89"}))

        edge = g.add_edge(vuln.id, endpoint.id, EdgeType.DISCOVERED_AT)

        assert isinstance(edge, FactEdge)
        assert edge.edge_type == EdgeType.DISCOVERED_AT

    def test_add_edge_invalid_ids(self):
        g = FactGraph()

        edge = g.add_edge("missing", "also-missing", EdgeType.DISCOVERED_AT)

        assert edge is None

    def test_get_facts_by_type(self):
        g = FactGraph()
        g.add_fact(Fact(fact_type=FactType.ENDPOINT, data={"url": "http://a.com"}))
        g.add_fact(Fact(fact_type=FactType.VULNERABILITY, data={"cwe": "CWE-79"}))
        g.add_fact(Fact(fact_type=FactType.ENDPOINT, data={"url": "http://b.com"}))

        assert len(g.get_facts(FactType.ENDPOINT)) == 2
        assert len(g.get_facts(FactType.VULNERABILITY)) == 1

    def test_get_facts_min_confidence(self):
        g = FactGraph()
        g.add_fact(Fact(fact_type=FactType.VULNERABILITY, data={}, confidence=0.9))
        g.add_fact(Fact(fact_type=FactType.VULNERABILITY, data={}, confidence=0.3))

        high_conf = g.get_facts(FactType.VULNERABILITY, min_confidence=0.5)

        assert len(high_conf) == 1
        assert high_conf[0].confidence == pytest.approx(0.9)

    def test_get_linked(self):
        g = FactGraph()
        endpoint = g.add_fact(Fact(fact_type=FactType.ENDPOINT, data={"url": "http://a.com"}))
        vuln = g.add_fact(Fact(fact_type=FactType.VULNERABILITY, data={"cwe": "CWE-89"}))
        g.add_edge(vuln.id, endpoint.id, EdgeType.DISCOVERED_AT)

        linked = g.get_linked(vuln.id)

        assert len(linked) == 1
        assert linked[0].id == endpoint.id

    def test_get_unexploited_vulns(self):
        g = FactGraph()
        exploited = g.add_fact(Fact(fact_type=FactType.VULNERABILITY, data={"cwe": "CWE-89"}))
        untouched = g.add_fact(Fact(fact_type=FactType.VULNERABILITY, data={"cwe": "CWE-79"}))
        g.mark_exploited(exploited.id)

        unexploited = g.get_unexploited_vulns()

        assert len(unexploited) == 1
        assert unexploited[0].id == untouched.id

    def test_count_by_type(self):
        g = FactGraph()
        g.add_fact(Fact(fact_type=FactType.ENDPOINT, data={}))
        g.add_fact(Fact(fact_type=FactType.ENDPOINT, data={}))
        g.add_fact(Fact(fact_type=FactType.VULNERABILITY, data={}))

        counts = g.count_by_type()

        assert counts["endpoint"] == 2
        assert counts["vulnerability"] == 1

    def test_credential_sanitization(self):
        g = FactGraph()

        cred = g.add_fact(
            Fact(
                fact_type=FactType.CREDENTIAL,
                data={"username": "admin", "password": "supersecret123"},
            )
        )

        assert "supersecret123" not in cred.data["password"]
        assert "REDACTED" in cred.data["password"]
        assert cred.data["username"] == "admin"

    def test_long_value_truncation(self):
        g = FactGraph()
        long_value = "x" * 1000

        fact = g.add_fact(Fact(fact_type=FactType.ENDPOINT, data={"response": long_value}))

        assert len(fact.data["response"]) <= g.MAX_DATA_VALUE_LENGTH + 20
        assert fact.data["response"].endswith("...[truncated]")

    def test_html_stripping(self):
        g = FactGraph()

        fact = g.add_fact(
            Fact(
                fact_type=FactType.ENDPOINT,
                data={"body": "<script>alert('xss')</script>Hello"},
            )
        )

        assert "<script>" not in fact.data["body"]
        assert "Hello" in fact.data["body"]

    def test_summary_for_llm(self):
        g = FactGraph()
        g.add_fact(
            Fact(
                fact_type=FactType.ENDPOINT,
                data={"url": "http://a.com"},
                source_agent="recon",
            )
        )

        summary = g.summary_for_llm()

        assert "FactGraph" in summary
        assert "endpoint" in summary
        assert "recon" in summary

    def test_persistence(self, tmp_path):
        path = tmp_path / "facts.jsonl"
        g1 = FactGraph(persist_path=path)
        g1.add_fact(Fact(fact_type=FactType.ENDPOINT, data={"url": "http://a.com"}))

        g2 = FactGraph(persist_path=path)

        assert len(g2.get_facts()) == 1

    def test_clear(self):
        g = FactGraph()
        g.add_fact(Fact(fact_type=FactType.ENDPOINT, data={}))

        g.clear()

        assert len(g.get_facts()) == 0


class TestFindingsBusFactGraphIntegration:
    """Tests for FindingsBus → FactGraph adapter."""

    def test_bus_without_graph_works_normally(self, tmp_path):
        from erebos.agents.base import AgentMessage, AgentRole, FindingsBus

        bus = FindingsBus(tmp_path / "bus.jsonl")
        msg = AgentMessage(
            id="test-1",
            role=AgentRole.VULN_SCAN,
            message_type="finding",
            payload={"cwe": "CWE-89", "url": "http://test.com"},
        )

        bus.publish(msg, sender_role=AgentRole.VULN_SCAN)

        assert bus.graph is None
        assert bus.count() == 1

    def test_bus_with_graph_publishes_facts(self, tmp_path):
        from erebos.agents.base import AgentMessage, AgentRole, FindingsBus

        graph = FactGraph()
        bus = FindingsBus(tmp_path / "bus.jsonl", fact_graph=graph)
        msg = AgentMessage(
            id="test-1",
            role=AgentRole.VULN_SCAN,
            message_type="finding",
            payload={"cwe": "CWE-89", "url": "http://test.com"},
        )

        bus.publish(msg, sender_role=AgentRole.VULN_SCAN)

        assert len(graph.get_facts()) >= 1


class TestExploitDeduplication:
    """Tests for finding deduplication in ExploitRole."""

    @staticmethod
    def _make_role():
        from erebos.agents.roles.exploit import ExploitRole

        role = ExploitRole.__new__(ExploitRole)
        role._allowlist = []
        role._seen_findings = set()
        return role

    @staticmethod
    def _make_finding(*, finding_id: str, target: str, cwe: str, severity: Severity) -> Finding:
        return Finding(
            id=finding_id,
            tool="nuclei",
            severity=severity,
            title=f"Finding {finding_id}",
            description="test finding",
            target=target,
            cwe=cwe,
            phase_found=Phase.VULN_SCAN,
        )

    def test_dedup_same_endpoint_cwe(self):
        role = self._make_role()
        findings = [
            self._make_finding(
                finding_id="f1",
                target="https://test.com/api",
                cwe="CWE-89",
                severity=Severity.HIGH,
            ),
            self._make_finding(
                finding_id="f2",
                target="https://test.com/api/",
                cwe="CWE-89",
                severity=Severity.MEDIUM,
            ),
        ]

        result = role._deduplicate_findings(findings)

        assert len(result) == 1
        assert result[0].id == "f1"
        assert result[0].severity == Severity.HIGH

    def test_dedup_different_cwes_kept(self):
        role = self._make_role()
        findings = [
            self._make_finding(
                finding_id="f1",
                target="https://test.com/api",
                cwe="CWE-89",
                severity=Severity.HIGH,
            ),
            self._make_finding(
                finding_id="f2",
                target="https://test.com/api",
                cwe="CWE-79",
                severity=Severity.MEDIUM,
            ),
        ]

        result = role._deduplicate_findings(findings)

        assert len(result) == 2
        assert {finding.cwe for finding in result} == {"CWE-89", "CWE-79"}


class TestReflectionDetector:
    """Tests for reflected XSS payload detection."""

    def test_detects_payload_reflection_in_html(self):
        detector = ReflectionDetector()
        payload = "<svg/onload=alert(1)>"

        result = detector.detect(
            response_body=f"<html><body>{payload}</body></html>",
            payloads=[payload, "<script>alert(2)</script>"],
            content_type="text/html; charset=utf-8",
        )

        assert result.detected is True
        assert result.matched_payloads == [payload]
        assert result.confidence == pytest.approx(0.85)

    def test_ignores_payload_reflection_in_non_html_content(self):
        detector = ReflectionDetector()
        payload = "<svg/onload=alert(1)>"

        result = detector.detect(
            response_body=f'{{"echo": "{payload}"}}',
            payloads=[payload],
            content_type="application/json",
        )

        assert result.detected is False
        assert result.matched_payloads == []
        assert result.confidence == pytest.approx(0.0)


class TestAuthBypassValidator:
    """Tests for stricter auth bypass validation."""

    def test_accepts_concrete_auth_signals(self):
        validator = AuthBypassValidator()
        evidence = [
            ExploitEvidence(
                request_sent="POST /login",
                response_received='{"token": "abc123", "user": {"id": 1}}',
                status_code=200,
                response_time_ms=25.0,
            )
        ]

        success, matches = validator.validate(evidence)

        assert success is True
        assert "auth_bypass:json_token_key" in matches
        assert "auth_bypass:json_user_key" in matches

    def test_rejects_error_page_that_mentions_token(self):
        validator = AuthBypassValidator()
        evidence = [
            ExploitEvidence(
                request_sent="GET /admin",
                response_received="Unauthorized error: invalid token provided",
                status_code=401,
                response_time_ms=12.0,
            )
        ]

        success, matches = validator.validate(evidence)

        assert success is False
        assert matches == []


class TestExploitIterationContext:
    def test_iteration_context_includes_auth_and_prior_successes(self, tmp_path):
        from erebos.agents.base import AgentMessage, AgentRole, FindingsBus
        from erebos.agents.roles.exploit import ExploitRole
        from erebos.exploits.sanitizer import PromptSanitizer

        bus = FindingsBus(tmp_path / "bus.jsonl")
        bus.publish(
            AgentMessage(
                id="auth-1",
                role=AgentRole.WEB_DISCOVERY,
                message_type="auth_token",
                payload={
                    "domain": "example.com",
                    "auth_token": "header.payload.signature",
                    "auth_email": "user@example.com",
                    "auth_user_id": "42",
                },
            )
        )

        role = ExploitRole.__new__(ExploitRole)
        role._bus = bus
        role._sanitizer = PromptSanitizer()
        role._requests_used = 3
        role._global_request_budget = 10
        role._results = [
            ExploitResult(
                finding_id="sqli-1",
                plan=ExploitPlan(
                    source="llm",
                    strategy=ExploitStrategy.WEB_AGGRESSIVE,
                    steps=[
                        ExploitStep(
                            description="login test", method="POST", path="/rest/user/login"
                        )
                    ],
                    success_criteria=SuccessCriteria(),
                ),
                success=True,
                status=ExploitStatus.SUCCESS,
            )
        ]
        prior_finding = Finding(
            id="sqli-1",
            tool="zap",
            severity=Severity.HIGH,
            title="SQL injection",
            description="login SQLi",
            target="https://example.com/rest/user/login",
            cwe="CWE-89",
            phase_found=Phase.VULN_SCAN,
        )
        current_finding = Finding(
            id="idor-1",
            tool="zap",
            severity=Severity.HIGH,
            title="IDOR",
            description="basket idor",
            target="https://example.com/api/BasketItems/1",
            cwe="CWE-639",
            phase_found=Phase.VULN_SCAN,
        )
        role._findings_by_id = {
            prior_finding.id: prior_finding,
            current_finding.id: current_finding,
        }

        context = role._build_iteration_context(current_finding, [], 2, None)

        assert context["auth_context"]["auth_token_available"] is True
        assert context["auth_context"]["authorization_header_template"] == "Bearer {auth_token}"
        assert context["other_successful_exploits"]["summary"] == (
            "Previously confirmed: SQLi on /rest/user/login"
        )


class TestIDORGeneration:
    """Tests for IDOR variant generation in ExploitRole."""

    @staticmethod
    def _make_role():
        from erebos.agents.roles.exploit import ExploitRole

        role = ExploitRole.__new__(ExploitRole)
        role._allowlist = []
        role._seen_findings = set()
        return role

    @staticmethod
    def _make_finding(target: str) -> Finding:
        return Finding(
            id="idor-1",
            tool="nuclei",
            severity=Severity.HIGH,
            title="IDOR",
            description="possible idor",
            target=target,
            cwe="CWE-639",
            phase_found=Phase.VULN_SCAN,
        )

    def test_generates_numeric_path_variants(self):
        role = self._make_role()
        finding = self._make_finding("https://example.com/api/users/007?expand=true")

        variants = role._generate_idor_variants(finding)

        assert variants == {
            "endpoint_other_id": "https://example.com/api/users/006?expand=true",
            "endpoint_incremented": "https://example.com/api/users/008?expand=true",
        }

    def test_generates_uuid_path_variants(self):
        role = self._make_role()
        finding = self._make_finding(
            "https://example.com/api/users/123e4567-e89b-42d3-a456-426614174000"
        )

        with patch(
            "erebos.agents.roles.exploit.uuid4",
            side_effect=[
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002",
            ],
        ):
            variants = role._generate_idor_variants(finding)

        assert variants == {
            "endpoint_other_id": (
                "https://example.com/api/users/00000000-0000-4000-8000-000000000001"
            ),
            "endpoint_incremented": (
                "https://example.com/api/users/00000000-0000-4000-8000-000000000002"
            ),
        }


# ============================================================
# Phase 3: Reason Loop + Intent Dispatcher Tests
# ============================================================


class TestReasonLoop:
    """Tests for the adaptive Reason Loop."""

    def test_heuristic_generates_intents_for_unexploited_vulns(self):
        import asyncio
        from erebos.agents.fact_graph import FactGraph, Fact, FactType
        from erebos.agents.reason import ReasonLoop

        g = FactGraph()
        g.add_fact(
            Fact(
                fact_type=FactType.VULNERABILITY,
                data={"url": "http://test.com/search", "cwe": "CWE-89"},
                confidence=0.9,
                source_agent="vuln-scan",
            )
        )
        loop = ReasonLoop(fact_graph=g, total_budget=100)
        intents = asyncio.run(loop.reason())
        assert len(intents) >= 1
        assert intents[0].action.value == "exploit"

    def test_max_iterations_stops_loop(self):
        from erebos.agents.fact_graph import FactGraph, Fact, FactType
        from erebos.agents.reason import ReasonLoop

        g = FactGraph()
        g.add_fact(Fact(fact_type=FactType.VULNERABILITY, data={"cwe": "CWE-89"}, confidence=0.9))
        loop = ReasonLoop(fact_graph=g, total_budget=1000)
        loop._iteration = loop.MAX_ITERATIONS
        assert loop.should_continue is False

    def test_budget_exhaustion_stops_loop(self):
        from erebos.agents.fact_graph import FactGraph
        from erebos.agents.reason import ReasonLoop

        g = FactGraph()
        loop = ReasonLoop(fact_graph=g, total_budget=50)
        loop._budget_used = 50
        assert loop.should_continue is False
        assert loop.budget_remaining == 0

    def test_failure_rate_circuit_breaker(self):
        from erebos.agents.fact_graph import FactGraph
        from erebos.agents.reason import ReasonLoop

        g = FactGraph()
        loop = ReasonLoop(fact_graph=g, total_budget=500)
        loop._iteration = 3
        # Simulate 9/10 failures
        for i in range(9):
            loop.record_intent_result(f"i-{i}", success=False, requests_used=5)
        loop.record_intent_result("i-9", success=True, requests_used=5)
        assert loop._failure_rate >= 0.8
        assert loop.should_continue is False

    def test_conclude_returns_summary(self):
        from erebos.agents.fact_graph import FactGraph
        from erebos.agents.reason import ReasonLoop

        g = FactGraph()
        loop = ReasonLoop(fact_graph=g, total_budget=100)
        loop._iteration = 5
        loop.record_intent_result("i-1", success=True, requests_used=20)
        loop.record_intent_result("i-2", success=False, requests_used=10)
        result = loop.conclude()
        assert result["iterations"] == 5
        assert result["budget_used"] == 30
        assert result["budget_remaining"] == 70
        assert result["successful_intents"] == 1

    def test_caching_when_facts_unchanged(self):
        import asyncio
        from erebos.agents.fact_graph import FactGraph, Fact, FactType
        from erebos.agents.reason import ReasonLoop

        g = FactGraph()
        g.add_fact(Fact(fact_type=FactType.VULNERABILITY, data={"cwe": "CWE-79"}, confidence=0.8))
        loop = ReasonLoop(fact_graph=g, total_budget=200)

        intents1 = asyncio.run(loop.reason())
        intents2 = asyncio.run(loop.reason())
        # Second call should return cached (same objects)
        assert intents1 == intents2


class TestIntentDispatcher:
    """Tests for Intent scope validation."""

    def test_allows_in_scope_targets(self):
        from erebos.agents.fact_graph import FactGraph
        from erebos.agents.reason import IntentDispatcher, Intent, IntentAction

        g = FactGraph()
        d = IntentDispatcher(allowlist=["test.com"], fact_graph=g)
        intents = [Intent(action=IntentAction.EXPLOIT, target="http://test.com/api")]
        valid = d.validate_and_dispatch(intents)
        assert len(valid) == 1
        assert d.rejected_count == 0

    def test_blocks_out_of_scope_targets(self):
        from erebos.agents.fact_graph import FactGraph
        from erebos.agents.reason import IntentDispatcher, Intent, IntentAction

        g = FactGraph()
        d = IntentDispatcher(allowlist=["test.com"], fact_graph=g)
        intents = [Intent(action=IntentAction.EXPLOIT, target="http://evil.com/steal")]
        valid = d.validate_and_dispatch(intents)
        assert len(valid) == 0
        assert d.rejected_count == 1

    def test_allows_subdomain_of_allowed(self):
        from erebos.agents.fact_graph import FactGraph
        from erebos.agents.reason import IntentDispatcher, Intent, IntentAction

        g = FactGraph()
        d = IntentDispatcher(allowlist=["test.com"], fact_graph=g)
        intents = [Intent(action=IntentAction.DISCOVER, target="http://sub.test.com/api")]
        valid = d.validate_and_dispatch(intents)
        assert len(valid) == 1

    def test_allows_empty_target(self):
        from erebos.agents.fact_graph import FactGraph
        from erebos.agents.reason import IntentDispatcher, Intent, IntentAction

        g = FactGraph()
        d = IntentDispatcher(allowlist=["test.com"], fact_graph=g)
        intents = [Intent(action=IntentAction.REPORT, target="")]
        valid = d.validate_and_dispatch(intents)
        assert len(valid) == 1

    def test_rejection_summary(self):
        from erebos.agents.fact_graph import FactGraph
        from erebos.agents.reason import IntentDispatcher, Intent, IntentAction

        g = FactGraph()
        d = IntentDispatcher(allowlist=["safe.com"], fact_graph=g)
        intents = [
            Intent(action=IntentAction.EXPLOIT, target="http://evil.com/x"),
            Intent(action=IntentAction.EXPLOIT, target="http://bad.org/y"),
        ]
        d.validate_and_dispatch(intents)
        summary = d.get_rejection_summary()
        assert len(summary) == 2
        assert all(r["reason"] == "scope_violation" for r in summary)
