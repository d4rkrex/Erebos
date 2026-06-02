"""Unit tests for Erebos control plane foundation.

Tests cover:
- Domain models (REQ-001)
- Event sourcing with hash chain (REQ-002)
- Policy engine (REQ-003)
- Approval gates (REQ-004)
- Kill switch (REQ-005)
- Scope enforcement (REQ-006)
- RoE parsing (REQ-007)
- State machine (REQ-008)
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from erebos.core.models import (
    ActionStatus,
    ActionType,
    Engagement,
    EngagementPhase,
    EngagementStatus,
    ImpactLevel,
    PlannedAction,
    RulesOfEngagement,
    Session,
    Target,
    TargetType,
)
from erebos.core.events import Event, EventLog, EventType
from erebos.control.policy import Policy, PolicyEngine
from erebos.control.approval import ApprovalGate, ApprovalRequest, ApprovalStatus
from erebos.control.killswitch import KillSwitch
from erebos.control.scope import ScopeValidator
from erebos.control.roe import derive_policy, generate_template, parse_roe
from erebos.brain.state_machine import (
    EngagementStateMachine,
    TransitionError,
    VALID_TRANSITIONS,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def hmac_secret():
    return "test-secret-key-not-for-production"


@pytest.fixture
def event_log(tmp_dir, hmac_secret):
    return EventLog(tmp_dir / "events.jsonl", hmac_secret)


@pytest.fixture
def sample_engagement():
    return Engagement(
        name="test-engagement",
        targets=[Target(address="192.168.1.100", target_type=TargetType.HOST)],
        roe=RulesOfEngagement(
            targets=["192.168.1.0/24"],
            excluded=["192.168.1.1"],
            operator="tester",
        ),
    )


@pytest.fixture
def sample_action(sample_engagement):
    return PlannedAction(
        engagement_id=sample_engagement.id,
        target_id=sample_engagement.targets[0].id,
        action_type=ActionType.SCAN,
        command="nmap -sV 192.168.1.100",
        description="Service version scan",
        impact_level=ImpactLevel.LOW,
        phase=EngagementPhase.RECON,
    )


# ─── REQ-001: Domain Models ─────────────────────────────────────────────────


class TestDomainModels:
    def test_engagement_creation(self):
        eng = Engagement(name="test")
        assert eng.id  # ULID generated
        assert eng.status == EngagementStatus.CREATED
        assert eng.phase == EngagementPhase.PLANNING
        assert eng.created_at is not None

    def test_engagement_serialization(self, sample_engagement):
        data = sample_engagement.model_dump(mode="json")
        assert data["name"] == "test-engagement"
        assert data["status"] == "created"
        assert data["phase"] == "planning"
        assert len(data["targets"]) == 1

        # Roundtrip
        restored = Engagement(**data)
        assert restored.id == sample_engagement.id
        assert restored.name == sample_engagement.name

    def test_target_model(self):
        target = Target(address="10.0.0.1", target_type=TargetType.HOST)
        assert target.id
        assert target.address == "10.0.0.1"

    def test_planned_action_model(self, sample_action):
        assert sample_action.status == ActionStatus.PROPOSED
        assert sample_action.action_type == ActionType.SCAN

    def test_roe_defaults(self):
        roe = RulesOfEngagement()
        assert roe.data_handling == "no_exfil"
        assert roe.max_depth == 3
        assert "scan" in roe.allowed_action_classes


# ─── REQ-002: Event Sourcing ────────────────────────────────────────────────


class TestEventSourcing:
    def test_event_log_creation(self, event_log):
        assert event_log.log_path.parent.exists()

    def test_hmac_secret_empty_rejected(self, tmp_dir):
        """VT-Spec T-02: Reject empty HMAC secrets."""
        with pytest.raises(ValueError, match="must not be empty"):
            EventLog(tmp_dir / "test.jsonl", "")

        with pytest.raises(ValueError, match="must not be empty"):
            EventLog(tmp_dir / "test.jsonl", "   ")

    def test_append_event(self, event_log, sample_engagement):
        event = Event(
            engagement_id=sample_engagement.id,
            event_type=EventType.ENGAGEMENT_CREATED,
            data={"name": sample_engagement.name},
        )
        result = event_log.append(event)
        assert result.hash != ""
        assert result.previous_hash == ""

    def test_hash_chain(self, event_log, sample_engagement):
        """VT-Spec T-01: Hash chain integrity."""
        e1 = event_log.append(
            Event(
                engagement_id=sample_engagement.id,
                event_type=EventType.ENGAGEMENT_CREATED,
                data={"step": 1},
            )
        )
        e2 = event_log.append(
            Event(
                engagement_id=sample_engagement.id,
                event_type=EventType.PHASE_CHANGED,
                data={"step": 2},
            )
        )
        assert e2.previous_hash == e1.hash
        assert e1.hash != e2.hash

    def test_integrity_verification(self, event_log, sample_engagement):
        """VT-Spec T-01: Verify hash chain."""
        for i in range(5):
            event_log.append(
                Event(
                    engagement_id=sample_engagement.id,
                    event_type=EventType.OBSERVATION_ADDED,
                    data={"index": i},
                )
            )
        assert event_log.verify_integrity() is True

    def test_integrity_tamper_detection(self, event_log, sample_engagement):
        """VT-Spec T-01: Detect tampering."""
        event_log.append(
            Event(
                engagement_id=sample_engagement.id,
                event_type=EventType.ENGAGEMENT_CREATED,
                data={"x": 1},
            )
        )
        event_log.append(
            Event(
                engagement_id=sample_engagement.id,
                event_type=EventType.PHASE_CHANGED,
                data={"x": 2},
            )
        )

        # Tamper with the log
        lines = event_log.log_path.read_text().splitlines()
        if lines:
            data = json.loads(lines[0])
            data["data"]["x"] = "tampered"
            lines[0] = json.dumps(data, default=str)
            event_log.log_path.write_text("\n".join(lines) + "\n")

        assert event_log.verify_integrity() is False

    def test_query_by_type(self, event_log, sample_engagement):
        event_log.append(
            Event(
                engagement_id=sample_engagement.id,
                event_type=EventType.ENGAGEMENT_CREATED,
            )
        )
        event_log.append(
            Event(
                engagement_id=sample_engagement.id,
                event_type=EventType.PHASE_CHANGED,
            )
        )
        results = event_log.query(event_type=EventType.PHASE_CHANGED)
        assert len(results) == 1

    def test_read_all(self, event_log, sample_engagement):
        for _ in range(3):
            event_log.append(
                Event(
                    engagement_id=sample_engagement.id,
                    event_type=EventType.OBSERVATION_ADDED,
                )
            )
        events = event_log.read_all()
        assert len(events) == 3


# ─── REQ-003: Policy Engine ─────────────────────────────────────────────────


class TestPolicyEngine:
    def test_deny_by_default(self, sample_action):
        """Policy denies action classes not explicitly allowed."""
        policy = Policy(allowed_action_classes=["enumerate"])
        engine = PolicyEngine(policy)

        decision = engine.evaluate(sample_action)  # action_type is SCAN
        assert decision.allowed is False
        assert "not in allowed classes" in decision.reason

    def test_allow_permitted_action(self, sample_action):
        policy = Policy(allowed_action_classes=["scan", "enumerate"])
        engine = PolicyEngine(policy)

        decision = engine.evaluate(sample_action)
        assert decision.allowed is True

    def test_approval_required_for_high_impact(self, sample_engagement):
        policy = Policy(allowed_action_classes=["exploit"])
        engine = PolicyEngine(policy)

        action = PlannedAction(
            engagement_id=sample_engagement.id,
            target_id="target-1",
            action_type=ActionType.EXPLOIT,
            command="exploit_payload",
            description="Exploit attempt",
            impact_level=ImpactLevel.HIGH,
            phase=EngagementPhase.EXPLOITATION,
        )
        decision = engine.evaluate(action)
        assert decision.allowed is True
        assert decision.requires_approval is True

    def test_target_in_scope_cidr(self):
        """VT-Spec S-02: CIDR matching."""
        policy = Policy(scope_targets=["10.0.0.0/24"])
        engine = PolicyEngine(policy)

        assert engine.is_target_in_scope("10.0.0.50") is True
        assert engine.is_target_in_scope("10.0.1.50") is False

    def test_target_excluded(self):
        policy = Policy(
            scope_targets=["192.168.1.0/24"],
            scope_excluded=["192.168.1.1"],
        )
        engine = PolicyEngine(policy)

        assert engine.is_target_in_scope("192.168.1.100") is True
        assert engine.is_target_in_scope("192.168.1.1") is False

    def test_yaml_anchors_rejected(self, tmp_dir):
        """VT-Spec S-01: Reject anchors/aliases."""
        policy_file = tmp_dir / "policy.yaml"
        policy_file.write_text(
            "scope_targets: &targets\n  - '10.0.0.1'\nscope_excluded: *targets\n"
        )
        with pytest.raises(ValueError, match="anchors/aliases"):
            PolicyEngine.load_from_yaml(policy_file)

    def test_load_valid_yaml(self, tmp_dir):
        policy_file = tmp_dir / "policy.yaml"
        policy_file.write_text(
            yaml.dump(
                {
                    "scope_targets": ["192.168.1.0/24"],
                    "allowed_action_classes": ["scan"],
                    "max_depth": 2,
                }
            )
        )
        engine = PolicyEngine.load_from_yaml(policy_file)
        assert engine.policy.max_depth == 2


# ─── REQ-004: Approval Gates ────────────────────────────────────────────────


class TestApprovalGates:
    def test_request_approval(self, tmp_dir, hmac_secret):
        gate = ApprovalGate(tmp_dir / "approvals", hmac_secret)

        request = ApprovalRequest(
            action_id="action-123",
            engagement_id="eng-456",
            summary="Exploit CVE-2024-1234",
            risk_level="high",
        )
        result = gate.request_approval(request)
        assert result.status == ApprovalStatus.PENDING

    def test_approve_request(self, tmp_dir, hmac_secret):
        gate = ApprovalGate(tmp_dir / "approvals", hmac_secret)

        request = ApprovalRequest(
            action_id="action-1",
            engagement_id="eng-1",
            summary="Test",
        )
        gate.request_approval(request)

        approved = gate.approve(request.id, approved_by="admin")
        assert approved.status == ApprovalStatus.APPROVED
        assert approved.decided_by == "admin"

    def test_reject_request(self, tmp_dir, hmac_secret):
        gate = ApprovalGate(tmp_dir / "approvals", hmac_secret)

        request = ApprovalRequest(
            action_id="action-2",
            engagement_id="eng-1",
            summary="Dangerous action",
        )
        gate.request_approval(request)

        rejected = gate.reject(request.id, reason="Too risky")
        assert rejected.status == ApprovalStatus.REJECTED
        assert rejected.rejection_reason == "Too risky"

    def test_timeout(self, tmp_dir, hmac_secret):
        gate = ApprovalGate(tmp_dir / "approvals", hmac_secret)

        request = ApprovalRequest(
            action_id="action-3",
            engagement_id="eng-1",
            summary="Expired action",
            timeout_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        gate.request_approval(request)

        result = gate.check_timeout(request.id)
        assert result.status == ApprovalStatus.TIMEOUT

    def test_verify_approval_signature(self, tmp_dir, hmac_secret):
        """VT-Spec T-03: Verify HMAC at execution time."""
        gate = ApprovalGate(tmp_dir / "approvals", hmac_secret)

        request = ApprovalRequest(
            action_id="action-4",
            engagement_id="eng-1",
            summary="Verified action",
        )
        gate.request_approval(request)
        gate.approve(request.id)

        assert gate.verify_approval(request.id) is True

    def test_verify_unapproved_fails(self, tmp_dir, hmac_secret):
        """VT-Spec E-02: Only approved requests pass verification."""
        gate = ApprovalGate(tmp_dir / "approvals", hmac_secret)

        request = ApprovalRequest(
            action_id="action-5",
            engagement_id="eng-1",
            summary="Pending action",
        )
        gate.request_approval(request)

        # Not approved — verification should fail
        assert gate.verify_approval(request.id) is False

    def test_list_pending(self, tmp_dir, hmac_secret):
        gate = ApprovalGate(tmp_dir / "approvals", hmac_secret)

        for i in range(3):
            gate.request_approval(
                ApprovalRequest(
                    action_id=f"action-{i}",
                    engagement_id="eng-1",
                    summary=f"Action {i}",
                )
            )

        pending = gate.list_pending()
        assert len(pending) == 3

    def test_empty_hmac_rejected(self, tmp_dir):
        """VT-Spec T-02: Reject empty HMAC for approval gate."""
        with pytest.raises(ValueError):
            ApprovalGate(tmp_dir / "approvals", "")


# ─── REQ-005: Kill Switch ────────────────────────────────────────────────────


class TestKillSwitch:
    def test_kill_switch_activation(self, tmp_dir, sample_engagement):
        """VT-Spec D-01: Kill switch activation."""
        ks = KillSwitch(tmp_dir / "killswitch")

        result = ks.activate(sample_engagement, reason="Emergency stop")
        assert result["engagement_id"] == sample_engagement.id
        assert result["reason"] == "Emergency stop"
        assert ks.is_killed(sample_engagement.id) is True

    def test_idempotent(self, tmp_dir, sample_engagement):
        """Kill switch is safe to call multiple times."""
        ks = KillSwitch(tmp_dir / "killswitch")

        ks.activate(sample_engagement)
        ks.activate(sample_engagement)  # Should not raise
        assert ks.is_killed(sample_engagement.id) is True

    def test_partial_report(self, tmp_dir, sample_engagement):
        ks = KillSwitch(tmp_dir / "killswitch")

        report = ks.generate_partial_report(sample_engagement)
        assert report["status"] == "aborted"
        assert report["engagement_id"] == sample_engagement.id

    def test_not_killed_before_activation(self, tmp_dir, sample_engagement):
        ks = KillSwitch(tmp_dir / "killswitch")
        assert ks.is_killed(sample_engagement.id) is False


# ─── REQ-006: Scope Enforcement ──────────────────────────────────────────────


class TestScopeEnforcement:
    def test_ip_in_scope(self):
        sv = ScopeValidator(allowed_targets=["192.168.1.0/24"])
        assert sv.is_target_allowed("192.168.1.50") is True
        assert sv.is_target_allowed("10.0.0.1") is False

    def test_ip_excluded(self):
        sv = ScopeValidator(
            allowed_targets=["192.168.1.0/24"],
            excluded_targets=["192.168.1.1"],
        )
        assert sv.is_target_allowed("192.168.1.1") is False
        assert sv.is_target_allowed("192.168.1.2") is True

    def test_hex_ip_normalization(self):
        """VT-Spec E-01: CRITICAL — Normalize hex IP."""
        ip = ScopeValidator.normalize_ip("0x7f000001")
        assert ip == "127.0.0.1"

    def test_octal_ip_normalization(self):
        """VT-Spec E-01: CRITICAL — Normalize octal IP."""
        ip = ScopeValidator.normalize_ip("0177.0.0.01")
        assert ip == "127.0.0.1"

    def test_decimal_ip_normalization(self):
        """VT-Spec E-01: CRITICAL — Normalize decimal integer IP."""
        ip = ScopeValidator.normalize_ip("2130706433")
        assert ip == "127.0.0.1"

    def test_obfuscated_ip_blocked(self):
        """VT-Spec E-01: Obfuscated out-of-scope IP caught."""
        sv = ScopeValidator(allowed_targets=["192.168.1.0/24"])
        # 0x0a000001 = 10.0.0.1 — NOT in scope
        assert sv.is_target_allowed("0x0a000001") is False

    def test_command_with_octal_out_of_scope(self):
        """VT-Spec E-01: Octal IP in commands is extracted and scope-checked."""
        sv = ScopeValidator(allowed_targets=["192.168.1.0/24"])
        allowed, reason = sv.validate_command("nmap 0177.0.0.1")
        assert allowed is False
        assert "out of scope" in reason.lower() or "not in scope" in reason.lower()

    def test_command_blocklist(self):
        """Command blocklist enforcement."""
        sv = ScopeValidator(allowed_targets=["192.168.1.0/24"])

        allowed, reason = sv.validate_command("rm -rf /")
        assert allowed is False
        assert "blocklist" in reason

        allowed, reason = sv.validate_command("dd if=/dev/zero of=/dev/sda")
        assert allowed is False

    def test_command_with_out_of_scope_target(self):
        sv = ScopeValidator(allowed_targets=["192.168.1.0/24"])

        allowed, reason = sv.validate_command("nmap -sV 10.0.0.1")
        assert allowed is False
        assert "out of scope" in reason

    def test_command_with_in_scope_target(self):
        sv = ScopeValidator(allowed_targets=["192.168.1.0/24"])

        allowed, reason = sv.validate_command("nmap -sV 192.168.1.50")
        assert allowed is True

    def test_depth_tracking(self):
        sv = ScopeValidator(allowed_targets=["10.0.0.0/8"], max_depth=2)
        assert sv.track_depth("10.0.0.1") is True  # depth 1
        assert sv.track_depth("10.0.0.1") is True  # depth 2
        assert sv.track_depth("10.0.0.1") is False  # exceeds limit

    def test_hostname_extraction(self):
        sv = ScopeValidator(allowed_targets=["example.com", "*.example.com"])
        targets = sv.extract_targets_from_command("curl https://sub.example.com/path")
        assert "sub.example.com" in targets

    def test_wildcard_domain(self):
        sv = ScopeValidator(allowed_targets=["*.example.com"])
        assert sv.is_target_allowed("sub.example.com") is True
        assert sv.is_target_allowed("other.net") is False


# ─── REQ-007: RoE Parsing ───────────────────────────────────────────────────


class TestRoEParsing:
    def test_parse_valid_roe(self, tmp_dir):
        roe_file = tmp_dir / "roe.yaml"
        roe_file.write_text(
            yaml.dump(
                {
                    "targets": ["192.168.1.0/24", "example.com"],
                    "excluded": ["192.168.1.1"],
                    "techniques": ["scan", "enumerate"],
                    "operator": "test-operator",
                    "max_depth": 2,
                    "data_handling": "no_exfil",
                }
            )
        )
        roe = parse_roe(roe_file)
        assert "192.168.1.0/24" in roe.targets
        assert roe.operator == "test-operator"
        assert roe.max_depth == 2

    def test_reject_anchors(self, tmp_dir):
        """VT-Spec S-01: Reject YAML anchors."""
        roe_file = tmp_dir / "roe.yaml"
        roe_file.write_text(
            "targets: &tgt\n  - '10.0.0.1'\nexcluded: *tgt\noperator: test\n"
        )
        with pytest.raises(ValueError, match="anchors/aliases"):
            parse_roe(roe_file)

    def test_missing_required_keys(self, tmp_dir):
        roe_file = tmp_dir / "roe.yaml"
        roe_file.write_text(yaml.dump({"excluded": ["10.0.0.1"]}))
        with pytest.raises(ValueError, match="missing required"):
            parse_roe(roe_file)

    def test_invalid_target_format(self, tmp_dir):
        """VT-Spec S-02: Reject invalid target formats."""
        roe_file = tmp_dir / "roe.yaml"
        roe_file.write_text(
            yaml.dump({"targets": ["not a valid!!!target"], "operator": "test"})
        )
        with pytest.raises(ValueError, match="Invalid target"):
            parse_roe(roe_file)

    def test_derive_policy(self):
        roe = RulesOfEngagement(
            targets=["10.0.0.0/24"],
            excluded=["10.0.0.1"],
            techniques=["scan", "enumerate"],
            operator="tester",
            max_depth=4,
        )
        policy = derive_policy(roe)
        assert "scan" in policy.allowed_action_classes
        assert policy.max_depth == 4
        assert "10.0.0.0/24" in policy.scope_targets

    def test_generate_template(self, tmp_dir):
        path = generate_template(tmp_dir / "template.yaml")
        assert path.exists()
        content = path.read_text()
        assert "targets:" in content
        assert "operator:" in content


# ─── REQ-008: State Machine ─────────────────────────────────────────────────


class TestStateMachine:
    def test_initial_state(self, sample_engagement):
        sm = EngagementStateMachine(sample_engagement)
        assert sm.current_phase == EngagementPhase.PLANNING

    def test_valid_transition(self, sample_engagement):
        sm = EngagementStateMachine(sample_engagement)
        sm.transition_to(EngagementPhase.RECON, "Starting recon")
        assert sm.current_phase == EngagementPhase.RECON

    def test_invalid_skip_transition(self, sample_engagement):
        """VT-Spec E-03: No skipping phases."""
        sm = EngagementStateMachine(sample_engagement)
        # Cannot skip from PLANNING to EXPLOITATION
        with pytest.raises(TransitionError, match="Invalid transition"):
            sm.transition_to(EngagementPhase.EXPLOITATION)

    def test_sequential_transitions(self, sample_engagement):
        sm = EngagementStateMachine(sample_engagement)
        sm.transition_to(EngagementPhase.RECON)
        sm.transition_to(EngagementPhase.ENUMERATION)
        sm.transition_to(EngagementPhase.EXPLOITATION)
        sm.transition_to(EngagementPhase.POST_EXPLOIT)
        sm.transition_to(EngagementPhase.REPORTING)
        sm.transition_to(EngagementPhase.COMPLETED)
        assert sm.current_phase == EngagementPhase.COMPLETED

    def test_cannot_leave_terminal_state(self, sample_engagement):
        """VT-Spec E-03: Terminal states are final."""
        sm = EngagementStateMachine(sample_engagement)
        sm.transition_to(EngagementPhase.RECON)
        sm.abort("Emergency")
        assert sm.current_phase == EngagementPhase.ABORTED

        with pytest.raises(TransitionError, match="terminal state"):
            sm.transition_to(EngagementPhase.RECON)

    def test_abort_from_any_phase(self, sample_engagement):
        """VT-Spec D-01: Abort always available."""
        sm = EngagementStateMachine(sample_engagement)
        sm.transition_to(EngagementPhase.RECON)
        sm.transition_to(EngagementPhase.ENUMERATION)
        sm.abort("Kill switch")
        assert sm.current_phase == EngagementPhase.ABORTED
        assert sample_engagement.status == EngagementStatus.ABORTED

    def test_phase_gated_actions(self, sample_engagement):
        """VT-Spec E-03: Phase-gated action restrictions."""
        sm = EngagementStateMachine(sample_engagement)

        # Planning phase — no actions allowed
        assert sm.is_action_allowed_in_phase("exploit") is False
        assert sm.is_action_allowed_in_phase("scan") is False

        # Recon phase — only scan
        sm.transition_to(EngagementPhase.RECON)
        assert sm.is_action_allowed_in_phase("scan") is True
        assert sm.is_action_allowed_in_phase("exploit") is False

        # Exploitation phase — scan, enumerate, exploit
        sm.transition_to(EngagementPhase.ENUMERATION)
        sm.transition_to(EngagementPhase.EXPLOITATION)
        assert sm.is_action_allowed_in_phase("exploit") is True

    def test_transition_history(self, sample_engagement):
        sm = EngagementStateMachine(sample_engagement)
        sm.transition_to(EngagementPhase.RECON, "start recon")
        sm.transition_to(EngagementPhase.ENUMERATION, "move to enum")

        history = sm.transition_history
        assert len(history) == 2
        assert history[0]["to_phase"] == "recon"
        assert history[1]["to_phase"] == "enumeration"

    def test_transition_callback(self, sample_engagement):
        transitions = []

        def on_transition(from_p, to_p):
            transitions.append((from_p, to_p))

        sm = EngagementStateMachine(sample_engagement, on_transition=on_transition)
        sm.transition_to(EngagementPhase.RECON)
        assert len(transitions) == 1
        assert transitions[0] == (EngagementPhase.PLANNING, EngagementPhase.RECON)
