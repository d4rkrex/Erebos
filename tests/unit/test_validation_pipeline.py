"""Tests for the validation pipeline (Stages A-D)."""


from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.core.validation import ValidationPipeline
from erebos.core.validation.stages import (
    SourceContext,
    StageA_PatternValidity,
    StageB_Reachability,
    StageC_Exploitability,
    StageD_Practicality,
    StageVerdict,
)


# --- Fixtures ---


def _make_finding(**kwargs) -> Finding:
    """Helper to create a Finding with defaults."""
    defaults = {
        "tool": "nuclei",
        "severity": Severity.HIGH,
        "title": "SQL Injection",
        "description": "SQL injection vulnerability detected",
        "target": "example.com",
        "phase_found": Phase.VULN_SCAN,
    }
    defaults.update(kwargs)
    return Finding(**defaults)


# --- Stage A Tests ---


class TestStageA:
    """Tests for Stage A: Pattern Validity."""

    def setup_method(self):
        self.stage = StageA_PatternValidity()

    def test_nuclei_tech_detect_is_fp(self):
        """Tech-detect nuclei findings should be rejected."""
        f = _make_finding(title="tech-detect:nginx", severity=Severity.INFO)
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.FAIL

    def test_nuclei_info_severity_rejected(self):
        """INFO severity nuclei findings are rejected."""
        f = _make_finding(title="Some Info Finding", severity=Severity.INFO)
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.FAIL

    def test_nuclei_high_with_evidence_passes(self):
        """High severity nuclei with URL evidence passes."""
        f = _make_finding(
            severity=Severity.HIGH,
            evidence=FindingEvidence(url="http://example.com/vuln", payload="' OR 1=1 --"),
        )
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.PASS

    def test_nuclei_robots_txt_is_fp(self):
        """robots.txt detection is noise."""
        f = _make_finding(title="robots.txt found", severity=Severity.LOW)
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.FAIL

    def test_semgrep_passes_normally(self):
        """Semgrep findings without known-FP rules pass."""
        f = _make_finding(tool="semgrep", title="javascript.express.security.sql-injection")
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.PASS

    def test_semgrep_high_fp_rule_uncertain(self):
        """Known high-FP semgrep rules return uncertain."""
        f = _make_finding(
            tool="semgrep",
            title="generic.secrets.gitleaks.something",
            description="generic.secrets.gitleaks detected",
        )
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.UNCERTAIN

    def test_recon_tool_info_rejected(self):
        """Recon tool INFO findings are rejected."""
        f = _make_finding(tool="nmap", severity=Severity.INFO, title="Open port 80")
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.FAIL

    def test_unknown_tool_passes(self):
        """Unknown tools pass through with medium confidence."""
        f = _make_finding(tool="custom-scanner")
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.PASS
        assert result.confidence == 0.5


# --- Stage B Tests ---


class TestStageB:
    """Tests for Stage B: Reachability."""

    def setup_method(self):
        self.stage = StageB_Reachability()

    def test_dast_with_url_is_reachable(self):
        """DAST findings with URL evidence prove reachability."""
        f = _make_finding(
            tool="nuclei",
            evidence=FindingEvidence(url="http://target.com/api/v1/users"),
        )
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.PASS
        assert result.confidence >= 0.8

    def test_sast_with_entry_points_passes(self):
        """SAST findings with entry points pass reachability."""
        f = _make_finding(tool="semgrep")
        ctx = SourceContext(
            file_path="routes/users.js",
            entry_points=["HTTP route", "express route handler"],
            data_flow=["req.params.id → db.query()"],
        )
        result = self.stage.evaluate(f, ctx)
        assert result.verdict == StageVerdict.PASS

    def test_sast_with_sanitizers_reduces_score(self):
        """Sanitizers reduce reachability confidence."""
        f = _make_finding(tool="semgrep")
        ctx = SourceContext(
            file_path="routes/users.js",
            entry_points=["HTTP route"],
            sanitizers=["escape", "parameterized"],
        )
        result = self.stage.evaluate(f, ctx)
        # Should be uncertain or fail due to sanitizers
        assert result.confidence < 0.7

    def test_private_function_reduces_score(self):
        """Private functions are harder to reach."""
        f = _make_finding(tool="semgrep")
        ctx = SourceContext(
            file_path="lib/internal.py",
            function_name="_internal_query",
            entry_points=[],
        )
        result = self.stage.evaluate(f, ctx)
        assert result.confidence < 0.6

    def test_no_context_is_uncertain(self):
        """No source context means uncertain reachability."""
        f = _make_finding(tool="semgrep")
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.UNCERTAIN


# --- Stage C Tests ---


class TestStageC:
    """Tests for Stage C: Exploitability."""

    def setup_method(self):
        self.stage = StageC_Exploitability()

    def test_sqli_with_cve_highly_exploitable(self):
        """SQL injection with CVE = highly exploitable."""
        f = _make_finding(
            cwe="CWE-89",
            cve="CVE-2023-12345",
            evidence=FindingEvidence(payload="' OR 1=1 --"),
        )
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.PASS
        assert result.confidence >= 0.8

    def test_xss_moderate_exploitability(self):
        """XSS is moderately exploitable."""
        f = _make_finding(cwe="CWE-79", title="Reflected XSS")
        result = self.stage.evaluate(f)
        # Should pass or be uncertain, not fail
        assert result.verdict in (StageVerdict.PASS, StageVerdict.UNCERTAIN)

    def test_no_cwe_lower_confidence(self):
        """Findings without CWE have lower exploitability confidence."""
        f = _make_finding(cwe=None, cve=None)
        result = self.stage.evaluate(f)
        assert result.confidence <= 0.7

    def test_unsanitized_flow_boosts_score(self):
        """Unsanitized data flow increases exploitability."""
        f = _make_finding(cwe="CWE-89")
        ctx = SourceContext(
            data_flow=["req.body.email → db.query()"],
            sanitizers=[],
        )
        result = self.stage.evaluate(f, ctx)
        assert result.verdict == StageVerdict.PASS

    def test_sanitized_flow_reduces_score(self):
        """Sanitized data flow reduces exploitability."""
        f = _make_finding(cwe="CWE-79")
        ctx = SourceContext(
            data_flow=["req.body.name → render()"],
            sanitizers=["escape", "encode"],
        )
        result = self.stage.evaluate(f, ctx)
        assert result.confidence < 0.7


# --- Stage D Tests ---


class TestStageD:
    """Tests for Stage D: Practicality."""

    def setup_method(self):
        self.stage = StageD_Practicality()

    def test_test_code_rejected(self):
        """Findings in test code are impractical."""
        f = _make_finding()
        ctx = SourceContext(file_path="tests/unit/test_auth.py")
        result = self.stage.evaluate(f, ctx)
        assert result.verdict == StageVerdict.FAIL

    def test_spec_code_rejected(self):
        """Findings in spec directories are impractical."""
        f = _make_finding()
        ctx = SourceContext(file_path="spec/helpers/auth_spec.rb")
        result = self.stage.evaluate(f, ctx)
        assert result.verdict == StageVerdict.FAIL

    def test_critical_with_cve_and_payload_passes(self):
        """Critical + CVE + payload = practical."""
        f = _make_finding(
            severity=Severity.CRITICAL,
            cve="CVE-2024-9999",
            evidence=FindingEvidence(payload="malicious input", url="http://prod.com/api"),
        )
        result = self.stage.evaluate(f)
        assert result.verdict == StageVerdict.PASS
        assert result.confidence >= 0.8

    def test_production_code_passes(self):
        """Production code with evidence passes."""
        f = _make_finding(
            evidence=FindingEvidence(url="http://target.com/api/login"),
        )
        ctx = SourceContext(file_path="src/controllers/auth.js")
        result = self.stage.evaluate(f, ctx)
        assert result.verdict == StageVerdict.PASS


# --- Full Pipeline Tests ---


class TestValidationPipeline:
    """Integration tests for the full pipeline."""

    def setup_method(self):
        self.pipeline = ValidationPipeline()

    def test_obvious_fp_short_circuits_at_a(self):
        """Obvious false positives should short-circuit at Stage A."""
        f = _make_finding(
            title="tech-detect:wordpress",
            severity=Severity.INFO,
        )
        result = self.pipeline.validate_finding(f)
        assert result.is_false_positive
        assert result.short_circuited_at == "A"

    def test_valid_high_finding_passes_all_stages(self):
        """Valid high-severity finding with evidence passes all stages."""
        f = _make_finding(
            severity=Severity.HIGH,
            cwe="CWE-89",
            cve="CVE-2023-1234",
            evidence=FindingEvidence(
                url="http://target.com/login",
                payload="' OR 1=1 --",
                output="SQL error: syntax near...",
            ),
        )
        result = self.pipeline.validate_finding(f)
        assert result.is_valid
        assert result.exploitation_status == "potential"

    def test_batch_validation_produces_stats(self):
        """Batch validation returns correct statistics."""
        findings = [
            _make_finding(title="tech-detect:nginx", severity=Severity.INFO),
            _make_finding(
                title="SQL Injection",
                severity=Severity.HIGH,
                cwe="CWE-89",
                evidence=FindingEvidence(url="http://x.com/sql", payload="test"),
            ),
            _make_finding(title="robots.txt found", severity=Severity.LOW),
        ]
        results, stats = self.pipeline.validate_findings(findings)

        assert stats.total_findings == 3
        assert stats.failed >= 2  # INFO and robots.txt should fail
        assert stats.false_positive_rate >= 0.5

    def test_skip_stages(self):
        """Pipeline respects skip_stages config."""
        pipeline = ValidationPipeline(skip_stages=["C", "D"])
        f = _make_finding(
            evidence=FindingEvidence(url="http://target.com/api"),
        )
        result = pipeline.validate_finding(f)
        # Should only run stages A and B
        assert len(result.stage_results) <= 2

    def test_sast_finding_with_context(self):
        """SAST finding with source context gets proper validation."""
        f = _make_finding(
            tool="semgrep",
            title="javascript.express.sql-injection",
            cwe="CWE-89",
        )
        ctx = SourceContext(
            file_path="routes/users.js",
            line_number=42,
            code_snippet="db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
            entry_points=["express route handler"],
            data_flow=["req.params.id → db.query()"],
            sanitizers=[],
            language="javascript",
        )
        result = self.pipeline.validate_finding(f, ctx)
        assert result.is_valid or result.needs_manual_review
        # Should not be FP since there's clear unsanitized flow
        assert not result.is_false_positive
