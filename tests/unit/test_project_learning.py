"""Tests for project-specific learning module."""

from pathlib import Path

from erebos.core.learning import ProjectLearning


class TestProjectLearning:
    """Test ProjectLearning persistence and pattern matching."""

    def _make_learning(self, tmp_path: Path) -> ProjectLearning:
        return ProjectLearning(project_path=tmp_path)

    def test_learn_from_repeated_fp(self, tmp_path):
        """Repeated FP decisions build confidence."""
        pl = self._make_learning(tmp_path)

        # First time — below threshold
        result = pl.learn_from_validation(
            title="express-open-redirect",
            tool="semgrep",
            cwe="CWE-601",
            file_path="src/routes/auth.js",
            decision="false_positive",
            reason="redirect is validated",
        )
        assert result is None  # Not yet suppressible

        # Repeat several times to build confidence
        for _ in range(5):
            pl.learn_from_validation(
                title="express-open-redirect",
                tool="semgrep",
                cwe="CWE-601",
                file_path="src/routes/auth.js",
                decision="false_positive",
            )

        patterns = pl.get_patterns("suppressed_rule")
        assert len(patterns) >= 1
        assert patterns[0].confidence >= 0.7

    def test_confirmed_finding_reduces_fp_confidence(self, tmp_path):
        """A confirmed finding reduces FP pattern confidence."""
        pl = self._make_learning(tmp_path)

        # Build up FP confidence
        for _ in range(4):
            pl.learn_from_validation(
                title="sql-injection",
                tool="semgrep",
                cwe="CWE-89",
                file_path="src/db.js",
                decision="false_positive",
            )

        # Then confirm it's real
        pl.learn_from_validation(
            title="sql-injection",
            tool="semgrep",
            cwe="CWE-89",
            file_path="src/db.js",
            decision="confirmed",
        )

        patterns = pl.get_patterns()
        sqli = [p for p in patterns if "sql-injection" in p.description]
        assert sqli[0].confidence < 0.7  # Should not be suppressible

    def test_should_suppress_after_threshold(self, tmp_path):
        """should_suppress returns True after enough FP occurrences."""
        pl = self._make_learning(tmp_path)

        # Build pattern above threshold (need >= 3 occurrences + confidence >= 0.7)
        for _ in range(6):
            pl.learn_from_validation(
                title="missing-user",
                tool="semgrep",
                cwe="CWE-250",
                file_path="Dockerfile",
                decision="false_positive",
            )

        suppress, pattern = pl.should_suppress("missing-user", "CWE-250", "Dockerfile")
        assert suppress is True
        assert pattern is not None
        assert pattern.confidence >= 0.7

    def test_should_not_suppress_low_confidence(self, tmp_path):
        """should_suppress returns False for low-confidence patterns."""
        pl = self._make_learning(tmp_path)

        pl.learn_from_validation(
            title="some-rule", tool="semgrep", cwe="CWE-79",
            file_path="app.js", decision="false_positive",
        )

        suppress, _ = pl.should_suppress("some-rule", "CWE-79", "app.js")
        assert suppress is False

    def test_learn_sanitizer(self, tmp_path):
        """Explicit sanitizer registration."""
        pl = self._make_learning(tmp_path)

        pattern = pl.learn_sanitizer("escapeHtml", ["CWE-79", "CWE-80"])
        assert pattern.pattern_type == "sanitizer"
        assert pattern.confidence == 0.8
        assert "CWE-79" in pattern.cwe_covered

    def test_persistence(self, tmp_path):
        """Patterns survive reload."""
        pl = self._make_learning(tmp_path)
        pl.learn_sanitizer("sanitize", ["CWE-89"])

        # Reload
        pl2 = ProjectLearning(project_path=tmp_path)
        patterns = pl2.get_patterns("sanitizer")
        assert len(patterns) == 1
        assert patterns[0].metadata["sanitizer_name"] == "sanitize"

    def test_prune_low_confidence(self, tmp_path):
        """Prune removes low-confidence patterns."""
        pl = self._make_learning(tmp_path)
        pl.learn_from_validation(
            title="weak-rule", tool="t", cwe=None,
            file_path="x.js", decision="uncertain",
        )
        pl.learn_sanitizer("strong", ["CWE-89"])

        removed = pl.prune_low_confidence(min_confidence=0.5)
        assert removed == 1
        assert len(pl.get_patterns()) == 1  # Only sanitizer remains

    def test_export_summary(self, tmp_path):
        """Export summary contains expected fields."""
        pl = self._make_learning(tmp_path)
        pl.learn_sanitizer("esc", ["CWE-79"])

        summary = pl.export_summary()
        assert "total_patterns" in summary
        assert summary["total_patterns"] == 1
        assert "stack" in summary

    def test_update_insight(self, tmp_path):
        """Project insight updates correctly."""
        pl = self._make_learning(tmp_path)
        pl.update_insight(stack="express")

        insight = pl.get_insight()
        assert insight.stack == "express"
        assert insight.scan_count == 1
