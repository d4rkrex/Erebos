"""Tests for the Model Scorecard."""


import pytest

from erebos.core.scorecard import DecisionEvent, ModelScorecard, ScorecardEntry


@pytest.fixture
def scorecard(tmp_path):
    """Create a scorecard with temp storage."""
    return ModelScorecard(storage_path=tmp_path / "scorecard.json")


class TestScorecardEntry:
    """Tests for ScorecardEntry math."""

    def test_accuracy_empty(self):
        entry = ScorecardEntry(model="test", cwe_class="CWE-89")
        assert entry.accuracy == 0.0
        assert entry.total == 0

    def test_accuracy_perfect(self):
        entry = ScorecardEntry(model="test", cwe_class="CWE-89", correct=25, incorrect=0)
        assert entry.accuracy == 1.0
        assert entry.miss_rate == 0.0

    def test_accuracy_mixed(self):
        entry = ScorecardEntry(model="test", cwe_class="CWE-89", correct=18, incorrect=2)
        assert entry.accuracy == 0.9
        assert entry.total == 20

    def test_wilson_upper_bound_no_data(self):
        entry = ScorecardEntry(model="test", cwe_class="CWE-89")
        assert entry.wilson_upper_bound() == 1.0  # No data = max uncertainty

    def test_wilson_upper_bound_perfect(self):
        """Perfect accuracy with many samples → low upper bound."""
        entry = ScorecardEntry(model="test", cwe_class="CWE-89", correct=100, incorrect=0)
        ub = entry.wilson_upper_bound()
        assert ub < 0.05  # Should be trusted

    def test_wilson_upper_bound_poor(self):
        """Poor accuracy → high upper bound."""
        entry = ScorecardEntry(model="test", cwe_class="CWE-89", correct=15, incorrect=5)
        ub = entry.wilson_upper_bound()
        assert ub > 0.10  # Should NOT be trusted

    def test_is_trusted_needs_min_samples(self):
        """Trust requires minimum samples."""
        entry = ScorecardEntry(model="test", cwe_class="CWE-89", correct=5, incorrect=0)
        assert not entry.is_trusted()  # Only 5 samples, needs 20

    def test_is_trusted_with_enough_correct(self):
        """100 correct, 0 incorrect → trusted."""
        entry = ScorecardEntry(model="test", cwe_class="CWE-89", correct=100, incorrect=0)
        assert entry.is_trusted()

    def test_is_trusted_high_miss_rate(self):
        """High miss rate → not trusted."""
        entry = ScorecardEntry(model="test", cwe_class="CWE-89", correct=15, incorrect=10)
        assert not entry.is_trusted()


class TestModelScorecard:
    """Tests for ModelScorecard persistence and queries."""

    def test_record_event(self, scorecard):
        """Recording events updates the entry."""
        event = DecisionEvent(
            model="claude-haiku",
            cwe_class="CWE-89",
            decision="false_positive",
            correct=True,
        )
        entry = scorecard.record(event)
        assert entry.correct == 1
        assert entry.incorrect == 0
        assert entry.model == "claude-haiku"

    def test_record_multiple_events(self, scorecard):
        """Multiple events accumulate."""
        for i in range(10):
            scorecard.record(
                DecisionEvent(
                    model="claude-haiku",
                    cwe_class="CWE-89",
                    decision="true_positive",
                    correct=True,
                )
            )
        scorecard.record(
            DecisionEvent(
                model="claude-haiku",
                cwe_class="CWE-89",
                decision="true_positive",
                correct=False,
            )
        )

        entry = scorecard.get_entry("claude-haiku", "CWE-89")
        assert entry is not None
        assert entry.correct == 10
        assert entry.incorrect == 1

    def test_get_entry_missing(self, scorecard):
        """Missing entry returns None."""
        assert scorecard.get_entry("nonexistent", "CWE-99") is None

    def test_should_short_circuit(self, scorecard):
        """Models accumulate trust over time."""
        # Record 100 correct decisions (Wilson UB needs ~100 for 5% threshold)
        for _ in range(100):
            scorecard.record(
                DecisionEvent(
                    model="fast-model",
                    cwe_class="CWE-79",
                    decision="false_positive",
                    correct=True,
                )
            )

        assert scorecard.should_short_circuit("fast-model", "CWE-79")

    def test_should_not_short_circuit_insufficient_data(self, scorecard):
        """Insufficient data → no short circuit."""
        for _ in range(5):
            scorecard.record(
                DecisionEvent(
                    model="new-model",
                    cwe_class="CWE-89",
                    decision="true_positive",
                    correct=True,
                )
            )

        assert not scorecard.should_short_circuit("new-model", "CWE-89")

    def test_persistence(self, tmp_path):
        """Scorecard data persists across instances."""
        path = tmp_path / "sc.json"

        sc1 = ModelScorecard(storage_path=path)
        sc1.record(DecisionEvent(model="test", cwe_class="CWE-89", decision="tp", correct=True))

        # New instance, same file
        sc2 = ModelScorecard(storage_path=path)
        entry = sc2.get_entry("test", "CWE-89")
        assert entry is not None
        assert entry.correct == 1

    def test_get_all_entries(self, scorecard):
        """get_all_entries returns all recorded pairs."""
        scorecard.record(DecisionEvent(model="m1", cwe_class="CWE-89", decision="tp", correct=True))
        scorecard.record(DecisionEvent(model="m1", cwe_class="CWE-79", decision="tp", correct=True))
        scorecard.record(
            DecisionEvent(model="m2", cwe_class="CWE-89", decision="fp", correct=False)
        )

        entries = scorecard.get_all_entries()
        assert len(entries) == 3

    def test_model_summary(self, scorecard):
        """Model summary aggregates correctly."""
        for _ in range(10):
            scorecard.record(
                DecisionEvent(model="claude", cwe_class="CWE-89", decision="tp", correct=True)
            )
        for _ in range(5):
            scorecard.record(
                DecisionEvent(model="claude", cwe_class="CWE-79", decision="tp", correct=True)
            )
        scorecard.record(
            DecisionEvent(model="claude", cwe_class="CWE-79", decision="fp", correct=False)
        )

        summary = scorecard.get_model_summary("claude")
        assert summary["total_decisions"] == 16
        assert summary["classes"] == 2
        assert summary["accuracy"] == 15 / 16
