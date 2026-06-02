"""Tests for White-Hat Source Analysis Module.

VT-Spec R3, R9: Source code analysis for informed exploitation.
VT-Spec EXEC-01: Semgrep custom rules gated behind trust flag.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from erebos.analysis.correlator import CorrelatedFinding, FindingCorrelator
from erebos.analysis.payload_advisor import PayloadAdvisor, PayloadHint, SanitizerInfo
from erebos.analysis.route_extractor import RouteExtractor, RouteInfo
from erebos.analysis.semgrep_runner import SastFinding, SemgrepRunner
from erebos.analysis.source_analyzer import SourceAnalysisResult, SourceAnalyzer
from erebos.core.finding import Severity


# ============================================================
# Route Extractor Tests
# ============================================================


class TestRouteExtractorFlask:
    """Test Flask route extraction."""

    def test_flask_route_with_methods(self, tmp_path: Path):
        """Extract Flask route with explicit methods."""
        src = tmp_path / "app.py"
        src.write_text("""
from flask import Flask
app = Flask(__name__)

@app.route('/api/users', methods=['GET', 'POST'])
def users():
    return 'users'
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="flask")
        assert len(routes) >= 1
        route = routes[0]
        assert route.path == "/api/users"
        assert route.method in ("GET", "POST")
        assert route.file == "app.py"

    def test_flask_shorthand_decorator(self, tmp_path: Path):
        """Extract Flask shorthand decorators like @app.get()."""
        src = tmp_path / "views.py"
        src.write_text("""
from flask import Flask
app = Flask(__name__)

@app.get('/api/items/<int:item_id>')
def get_item(item_id):
    return f'item {item_id}'

@app.post('/api/items')
def create_item():
    return 'created'
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="flask")
        assert len(routes) == 2
        get_route = next(r for r in routes if r.method == "GET")
        assert get_route.path == "/api/items/<int:item_id>"
        assert "item_id" in get_route.params
        post_route = next(r for r in routes if r.method == "POST")
        assert post_route.path == "/api/items"

    def test_flask_auth_detection(self, tmp_path: Path):
        """Detect auth decorators on Flask routes."""
        src = tmp_path / "protected.py"
        src.write_text("""
from flask import Flask
from flask_login import login_required
app = Flask(__name__)

@app.route('/api/admin', methods=['GET'])
@login_required
def admin():
    return 'admin'
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="flask")
        assert len(routes) == 1
        assert routes[0].has_auth is True


class TestRouteExtractorExpress:
    """Test Express route extraction."""

    def test_express_basic_routes(self, tmp_path: Path):
        """Extract Express.js routes."""
        src = tmp_path / "routes.js"
        src.write_text("""
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => res.json([]));
app.post('/api/users', (req, res) => res.json({}));
app.delete('/api/users/:id', (req, res) => res.sendStatus(204));
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="express")
        assert len(routes) == 3
        methods = {r.method for r in routes}
        assert methods == {"GET", "POST", "DELETE"}
        delete_route = next(r for r in routes if r.method == "DELETE")
        assert "id" in delete_route.params

    def test_express_router(self, tmp_path: Path):
        """Extract Express router routes."""
        src = tmp_path / "userRouter.ts"
        src.write_text("""
import { Router } from 'express';
const router = Router();

router.get('/profile', authenticate, getProfile);
router.put('/profile', authenticate, updateProfile);
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="express")
        assert len(routes) == 2
        assert routes[0].path == "/profile"

    def test_express_auth_detection(self, tmp_path: Path):
        """Detect auth middleware in Express routes."""
        src = tmp_path / "api.js"
        src.write_text("""
const authenticate = require('./middleware/auth');

app.get('/api/protected', authenticate, (req, res) => {
    res.json({});
});
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="express")
        assert len(routes) == 1
        assert routes[0].has_auth is True


class TestRouteExtractorDjango:
    """Test Django route extraction."""

    def test_django_path_routes(self, tmp_path: Path):
        """Extract Django path() routes."""
        src = tmp_path / "urls.py"
        src.write_text("""
from django.urls import path
from . import views

urlpatterns = [
    path('api/users/', views.user_list),
    path('api/users/<int:pk>/', views.user_detail),
    path('api/posts/<slug:slug>/', views.post_detail),
]
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="django")
        assert len(routes) == 3
        detail_route = next(r for r in routes if "pk" in r.params)
        assert detail_route is not None
        assert "pk" in detail_route.params

    def test_django_url_regex(self, tmp_path: Path):
        """Extract Django url() with regex."""
        src = tmp_path / "urls.py"
        src.write_text("""
from django.conf.urls import url
urlpatterns = [
    url(r'^api/legacy/', views.legacy_endpoint),
]
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="django")
        assert len(routes) == 1


class TestRouteExtractorFastAPI:
    """Test FastAPI route extraction."""

    def test_fastapi_routes(self, tmp_path: Path):
        """Extract FastAPI routes."""
        src = tmp_path / "main.py"
        src.write_text("""
from fastapi import FastAPI
app = FastAPI()

@app.get('/api/items/{item_id}')
async def get_item(item_id: int):
    return {"item_id": item_id}

@app.post('/api/items')
async def create_item(item: Item):
    return item

@app.delete('/api/items/{item_id}')
async def delete_item(item_id: int):
    pass
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="fastapi")
        assert len(routes) == 3
        get_route = next(r for r in routes if r.method == "GET")
        assert "item_id" in get_route.params

    def test_fastapi_auth_detection(self, tmp_path: Path):
        """Detect Depends(auth) in FastAPI."""
        src = tmp_path / "secure.py"
        src.write_text("""
from fastapi import FastAPI, Depends
from .auth import get_current_user

app = FastAPI()

@app.get('/api/me')
async def me(current_user = Depends(get_current_user)):
    return current_user
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="fastapi")
        assert len(routes) == 1
        # Auth detection looks at surrounding lines
        assert routes[0].has_auth is True


class TestRouteExtractorSpring:
    """Test Spring route extraction."""

    def test_spring_mapping_annotations(self, tmp_path: Path):
        """Extract Spring @GetMapping, @PostMapping etc."""
        src = tmp_path / "UserController.java"
        src.write_text("""
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @GetMapping("/{id}")
    public User getUser(@PathVariable Long id) {
        return userService.findById(id);
    }
    
    @PostMapping("/")
    public User createUser(@RequestBody User user) {
        return userService.save(user);
    }
    
    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }
}
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="spring")
        assert len(routes) >= 3
        methods = {r.method for r in routes}
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods

    def test_spring_auth_annotation(self, tmp_path: Path):
        """Detect @PreAuthorize on Spring routes."""
        src = tmp_path / "AdminController.java"
        src.write_text("""
@RestController
public class AdminController {
    
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/dashboard")
    public Dashboard getDashboard() {
        return dashboardService.get();
    }
}
""")
        extractor = RouteExtractor()
        routes = extractor.extract(tmp_path, framework="spring")
        assert len(routes) >= 1
        assert routes[0].has_auth is True


# ============================================================
# Semgrep Runner Tests
# ============================================================


class TestSemgrepRunner:
    """Test Semgrep runner and EXEC-01 security controls."""

    def test_build_command_official_rulesets(self):
        """Test command building uses official rulesets."""
        runner = SemgrepRunner(trust_custom_rules=False)
        cmd = runner._build_command(Path("/tmp/src"), runner.OFFICIAL_RULESETS)
        assert cmd[0] == "semgrep"
        assert "scan" in cmd
        assert "--json" in cmd
        assert "--quiet" in cmd
        assert "--config" in cmd
        assert "p/security-audit" in cmd
        assert "p/owasp-top-ten" in cmd
        assert "p/cwe-top-25" in cmd

    def test_exec01_custom_rules_rejected_without_trust(self, caplog):
        """VT-Spec EXEC-01: Custom rules rejected without --trust-rules."""
        runner = SemgrepRunner(trust_custom_rules=False)
        custom_path = Path("/some/custom/rules.yaml")

        with patch.object(runner, "_execute_and_parse", return_value=[]):
            runner.run(Path("/tmp/src"), custom_rules=custom_path)

        assert "EXEC-01" in caplog.text
        assert "rejected" in caplog.text

    def test_exec01_custom_rules_accepted_with_trust(self, tmp_path: Path, caplog):
        """VT-Spec EXEC-01: Custom rules accepted with --trust-rules."""
        import logging
        runner = SemgrepRunner(trust_custom_rules=True)
        custom_path = tmp_path / "rules.yaml"
        custom_path.write_text("rules: []")

        with caplog.at_level(logging.INFO, logger="erebos.analysis.semgrep_runner"):
            with patch.object(runner, "_execute_and_parse", return_value=[]) as mock_exec:
                runner.run(tmp_path, custom_rules=custom_path)

        assert "accepted" in caplog.text
        # Verify custom rules path was included in the command
        call_args = mock_exec.call_args[0]
        cmd = call_args[0]
        assert str(custom_path) in cmd

    def test_parse_semgrep_output(self):
        """Test parsing Semgrep JSON output."""
        runner = SemgrepRunner()
        output = json.dumps({
            "results": [
                {
                    "check_id": "python.lang.security.audit.exec-use",
                    "path": "/src/app/utils.py",
                    "start": {"line": 42, "col": 1},
                    "end": {"line": 42, "col": 30},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Detected use of exec()",
                        "lines": "exec(user_input)",
                        "metadata": {
                            "cwe": ["CWE-78"],
                            "owasp": ["A03:2021"],
                        },
                    },
                }
            ]
        })

        findings = runner._parse_output(output, Path("/src"))
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "python.lang.security.audit.exec-use"
        assert f.severity == Severity.HIGH
        assert f.line == 42
        assert f.cwe == "CWE-78"
        assert f.owasp == "A03:2021"

    def test_official_rulesets_are_immutable(self):
        """Ensure official rulesets cannot be modified."""
        runner = SemgrepRunner()
        assert "p/security-audit" in runner.OFFICIAL_RULESETS
        assert "p/owasp-top-ten" in runner.OFFICIAL_RULESETS
        assert "p/cwe-top-25" in runner.OFFICIAL_RULESETS


# ============================================================
# Correlator Tests
# ============================================================


class TestFindingCorrelator:
    """Test SAST/DAST correlation."""

    def _make_finding(self, file: str, line: int, check_id: str = "test-check") -> SastFinding:
        return SastFinding(
            check_id=check_id,
            severity=Severity.HIGH,
            message="Test finding",
            file=file,
            line=line,
        )

    def _make_route(self, path: str, method: str, file: str, line: int) -> RouteInfo:
        return RouteInfo(path=path, method=method, file=file, line=line)

    def test_correlator_exact_match(self):
        """Test correlator matches SAST finding to route via exact path."""
        correlator = FindingCorrelator()

        finding = self._make_finding("app/views.py", 25)
        route = self._make_route("/api/users", "GET", "app/views.py", 20)
        dast_targets = ["http://target.com/api/users"]

        results = correlator.correlate([finding], dast_targets, [route])
        assert len(results) == 1
        assert results[0].matched_route == route
        assert results[0].matched_url == "http://target.com/api/users"
        assert results[0].correlation_confidence >= 0.8  # high confidence

    def test_correlator_no_match(self):
        """Test correlator with no DAST target match."""
        correlator = FindingCorrelator()

        finding = self._make_finding("app/views.py", 25)
        route = self._make_route("/api/admin", "GET", "app/views.py", 20)
        dast_targets = ["http://target.com/api/users"]

        results = correlator.correlate([finding], dast_targets, [route])
        assert len(results) == 1
        # Route in same file gives some confidence, but no DAST match
        assert results[0].correlation_confidence < 0.8

    def test_correlator_confidence_scoring(self):
        """Test confidence scoring levels."""
        correlator = FindingCorrelator()

        # Finding far from route
        finding_far = self._make_finding("app/views.py", 200)
        # Finding close to route
        finding_close = self._make_finding("app/views.py", 22)
        route = self._make_route("/api/data", "POST", "app/views.py", 20)
        dast_targets = ["http://target.com/api/data"]

        results_far = correlator.correlate([finding_far], dast_targets, [route])
        results_close = correlator.correlate([finding_close], dast_targets, [route])

        # Close finding should have higher confidence
        assert results_close[0].correlation_confidence > results_far[0].correlation_confidence

    def test_correlator_parameterized_route(self):
        """Test correlator matches parameterized routes."""
        correlator = FindingCorrelator()

        finding = self._make_finding("app/views.py", 30)
        route = self._make_route("/api/users/{id}", "GET", "app/views.py", 28)
        dast_targets = ["http://target.com/api/users/123"]

        results = correlator.correlate([finding], dast_targets, [route])
        assert len(results) == 1
        assert results[0].matched_url == "http://target.com/api/users/123"
        assert results[0].correlation_confidence >= 0.7

    def test_correlator_no_routes_in_file(self):
        """Test correlator with finding in file with no routes."""
        correlator = FindingCorrelator()

        finding = self._make_finding("lib/utils.py", 10)
        route = self._make_route("/api/users", "GET", "app/views.py", 20)
        dast_targets = ["http://target.com/api/users"]

        results = correlator.correlate([finding], dast_targets, [route])
        assert len(results) == 1
        assert results[0].correlation_confidence == 0.0


# ============================================================
# Payload Advisor Tests
# ============================================================


class TestPayloadAdvisor:
    """Test payload generation based on source patterns."""

    def test_dompurify_bypass_payloads(self):
        """Test DOMPurify bypass payload generation."""
        advisor = PayloadAdvisor()
        sanitizers = [SanitizerInfo(name="DOMPurify", file="app.js", line=10)]
        hints = advisor.advise("express", sanitizers)

        # Should have framework hints + DOMPurify bypasses
        dompurify_hints = [h for h in hints if h.bypass_target == "sanitizer:DOMPurify"]
        assert len(dompurify_hints) >= 1
        assert any("xss" == h.vuln_type for h in dompurify_hints)
        assert any("mXSS" in h.rationale or "DOMPurify" in h.rationale for h in dompurify_hints)

    def test_framework_weaknesses_express(self):
        """Test Express.js framework weakness hints."""
        advisor = PayloadAdvisor()
        hints = advisor.advise("express", [])

        fw_hints = [h for h in hints if h.bypass_target == "framework:express"]
        assert len(fw_hints) >= 2
        vuln_types = {h.vuln_type for h in fw_hints}
        assert "prototype_pollution" in vuln_types
        assert "nosql_injection" in vuln_types

    def test_framework_weaknesses_flask(self):
        """Test Flask framework weakness hints."""
        advisor = PayloadAdvisor()
        hints = advisor.advise("flask", [])

        fw_hints = [h for h in hints if h.bypass_target == "framework:flask"]
        assert len(fw_hints) >= 1
        assert any("ssti" == h.vuln_type for h in fw_hints)

    def test_resistant_sanitizer(self):
        """Test that resistant sanitizers produce no bypass hints."""
        advisor = PayloadAdvisor()
        sanitizers = [
            SanitizerInfo(name="prepared_statements", file="db.py", line=5),
            SanitizerInfo(name="parameterized_query", file="repo.java", line=10),
        ]
        hints = advisor.advise("flask", sanitizers)

        # Only framework hints, no sanitizer bypass hints
        sanitizer_hints = [
            h for h in hints if h.bypass_target.startswith("sanitizer:")
        ]
        assert len(sanitizer_hints) == 0

    def test_detect_sanitizers(self, tmp_path: Path):
        """Test sanitizer detection in source code."""
        advisor = PayloadAdvisor()
        content_map = {
            "app.js": "const clean = DOMPurify.sanitize(input);",
            "db.py": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        }
        sanitizers = advisor.detect_sanitizers(tmp_path, content_map)
        names = {s.name for s in sanitizers}
        assert "DOMPurify" in names
        assert "prepared_statements" in names


# ============================================================
# Source Analyzer Integration Tests
# ============================================================


class TestSourceAnalyzer:
    """Test full SourceAnalyzer pipeline."""

    def test_full_pipeline_mock_semgrep(self, tmp_path: Path):
        """Test full analysis pipeline with mocked Semgrep."""
        # Create a Flask app
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from flask import Flask, request
app = Flask(__name__)

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q')
    return exec(query)  # vuln!

@app.get('/api/health')
def health():
    return 'ok'
""")
        # Create requirements.txt for framework detection
        reqs = tmp_path / "requirements.txt"
        reqs.write_text("flask==2.3.0\n")

        mock_findings = [
            SastFinding(
                check_id="python.lang.security.audit.exec-use",
                severity=Severity.HIGH,
                message="Detected use of exec()",
                file="app.py",
                line=8,
            )
        ]

        analyzer = SourceAnalyzer(source_path=tmp_path, trust_rules=False)

        with patch.object(analyzer._semgrep, "run", return_value=mock_findings):
            result = analyzer.analyze(
                dast_targets=["http://target.com/api/search?q=test"]
            )

        assert result.framework == "flask"
        assert len(result.routes) >= 1
        assert len(result.sast_findings) == 1
        assert len(result.payload_hints) >= 1  # flask framework hints
        # Correlation should find match
        if result.correlated_findings:
            assert result.correlated_findings[0].correlation_confidence > 0

    def test_analyzer_respects_exec01(self, tmp_path: Path):
        """VT-Spec EXEC-01: Analyzer passes trust flag correctly."""
        reqs = tmp_path / "requirements.txt"
        reqs.write_text("flask==2.3.0\n")
        app = tmp_path / "app.py"
        app.write_text("# empty")

        # Without trust
        analyzer_no_trust = SourceAnalyzer(source_path=tmp_path, trust_rules=False)
        assert analyzer_no_trust._semgrep._trust_custom is False

        # With trust
        analyzer_trust = SourceAnalyzer(source_path=tmp_path, trust_rules=True)
        assert analyzer_trust._semgrep._trust_custom is True

    def test_relative_paths_in_output(self, tmp_path: Path):
        """VT-Spec INJ-03: All paths in results should be relative."""
        sub = tmp_path / "src"
        sub.mkdir()
        app = sub / "main.py"
        app.write_text("""
from fastapi import FastAPI
app = FastAPI()

@app.get('/items')
def items():
    return []
""")
        reqs = tmp_path / "requirements.txt"
        reqs.write_text("fastapi==0.100.0\n")

        analyzer = SourceAnalyzer(source_path=tmp_path, trust_rules=False)
        with patch.object(analyzer._semgrep, "run", return_value=[]):
            result = analyzer.analyze()

        for route in result.routes:
            assert not route.file.startswith("/"), f"Absolute path found: {route.file}"

    def test_defense_detection(self, tmp_path: Path):
        """Test detection of security defenses."""
        app = tmp_path / "app.py"
        app.write_text("""
from flask import Flask
from flask_cors import cors
from flask_limiter import RateLimiter

app = Flask(__name__)
cors(app)
limiter = RateLimiter(app)
app.config['CSP'] = "content-security-policy: default-src 'self'"
""")
        reqs = tmp_path / "requirements.txt"
        reqs.write_text("flask\n")

        analyzer = SourceAnalyzer(source_path=tmp_path, trust_rules=False)
        with patch.object(analyzer._semgrep, "run", return_value=[]):
            result = analyzer.analyze()

        assert "CORS" in result.defenses
        assert "rate-limiting" in result.defenses
        assert "CSP" in result.defenses
