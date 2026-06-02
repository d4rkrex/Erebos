"""Unit tests for phase state machine."""

import pytest
from erebos.core.finding import Phase
from erebos.core.orchestrator import PhaseStateMachine


class TestPhaseStateMachine:
    """Tests for PhaseStateMachine."""

    def test_initial_state(self):
        """Test initial state is IDLE."""
        sm = PhaseStateMachine()
        assert sm.current_phase == Phase.IDLE
        assert sm.phase_history == [Phase.IDLE]

    def test_valid_transition_from_idle_to_recon(self):
        """Test valid transition from IDLE to RECON."""
        sm = PhaseStateMachine()
        result = sm.transition(Phase.RECON)
        assert result is True
        assert sm.current_phase == Phase.RECON
        assert Phase.RECON in sm.phase_history

    def test_invalid_transition_from_idle_to_vuln_scan(self):
        """Test invalid transition from IDLE directly to VULN_SCAN."""
        sm = PhaseStateMachine()
        result = sm.transition(Phase.VULN_SCAN)
        assert result is False
        assert sm.current_phase == Phase.IDLE

    def test_valid_transition_recon_to_vuln_scan(self):
        """Test valid transition from RECON to VULN_SCAN."""
        sm = PhaseStateMachine()
        sm.transition(Phase.RECON)
        result = sm.transition(Phase.VULN_SCAN)
        assert result is True
        assert sm.current_phase == Phase.VULN_SCAN

    def test_valid_transition_vuln_scan_to_reporting(self):
        """Test valid transition from VULN_SCAN to REPORTING."""
        sm = PhaseStateMachine()
        sm.transition(Phase.RECON)
        sm.transition(Phase.VULN_SCAN)
        result = sm.transition(Phase.REPORTING)
        assert result is True
        assert sm.current_phase == Phase.REPORTING

    def test_cannot_skip_recon(self):
        """Test that VULN_SCAN requires RECON first."""
        sm = PhaseStateMachine()
        # Try to go from IDLE to VULN_SCAN - should fail
        result = sm.transition(Phase.VULN_SCAN)
        assert result is False
        assert sm.current_phase == Phase.IDLE

    def test_cannot_go_backwards(self):
        """Test that cannot go backwards in phase order."""
        sm = PhaseStateMachine()
        sm.transition(Phase.RECON)
        sm.transition(Phase.VULN_SCAN)
        # Try to go back to RECON - should fail
        result = sm.transition(Phase.RECON)
        assert result is False

    def test_abort_from_any_state(self):
        """Test can abort from any state."""
        sm = PhaseStateMachine()
        sm.transition(Phase.RECON)
        result = sm.transition(Phase.ABORTED)
        assert result is True
        assert sm.is_aborted()

    def test_complete_from_reporting(self):
        """Test can complete from REPORTING."""
        sm = PhaseStateMachine()
        sm.transition(Phase.RECON)
        sm.transition(Phase.VULN_SCAN)
        sm.transition(Phase.REPORTING)
        result = sm.transition(Phase.COMPLETE)
        assert result is True
        assert sm.is_complete()

    def test_has_required_artifacts(self):
        """Test artifact requirement checking."""
        sm = PhaseStateMachine()

        # RECON has no requirements
        assert sm.has_required_artifacts(Phase.RECON, []) is True

        # VULN_SCAN requires RECON
        assert sm.has_required_artifacts(Phase.VULN_SCAN, [Phase.RECON]) is True
        assert sm.has_required_artifacts(Phase.VULN_SCAN, []) is False

        # REPORTING requires both RECON and VULN_SCAN
        assert sm.has_required_artifacts(Phase.REPORTING, [Phase.RECON, Phase.VULN_SCAN]) is True
        assert sm.has_required_artifacts(Phase.REPORTING, [Phase.RECON]) is False

    def test_get_next_phase(self):
        """Test getting next phase."""
        sm = PhaseStateMachine()

        # First phase should be RECON
        assert sm.get_next_phase() == Phase.RECON

        sm.transition(Phase.RECON)

        # After RECON, can go to DISCOVERY, VULN_SCAN, or REPORTING
        next_phase = sm.get_next_phase()
        assert next_phase in [Phase.DISCOVERY, Phase.VULN_SCAN, Phase.REPORTING]

    def test_can_transition_method(self):
        """Test can_transition method."""
        sm = PhaseStateMachine()

        # IDLE can go to RECON
        assert sm.can_transition(Phase.IDLE, Phase.RECON) is True

        # IDLE cannot go to VULN_SCAN directly
        assert sm.can_transition(Phase.IDLE, Phase.VULN_SCAN) is False

        # After RECON, can go to VULN_SCAN
        sm.transition(Phase.RECON)
        assert sm.can_transition(Phase.RECON, Phase.VULN_SCAN) is True
