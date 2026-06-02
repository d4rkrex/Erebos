"""Unit tests for the DAST fuzzing template engine.

Tests cover:
- YAML template parsing
- Sandbox validation (INJ-02)
- Payload budget caps (DOS-01)
- Response matchers (word, regex, status, dsl)
- Budget enforcement in executor
- Execute template happy path
- Stop-at-first-match behavior
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from erebos.exploits.dast import (
    DastExecutor,
    DastFuzzRule,
    DastMatcher,
    DastTemplate,
    FuzzLocation,
    FuzzType,
    MatcherType,
    ResponseMatcher,
    SimpleResponse,
    TemplateSandbox,
    TemplateParser,
    TemplateParseError,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sandbox():
    return TemplateSandbox()


@pytest.fixture
def parser():
    return TemplateParser()


@pytest.fixture
def matcher():
    return ResponseMatcher()


@pytest.fixture
def valid_template():
    return DastTemplate(
        id="sqli-error-based",
        name="Error based SQL Injection",
        author="test",
        severity="critical",
        tags=["sqli", "dast"],
        payloads={"injection": ["'", '"', ";"]},
        fuzzing=[
            DastFuzzRule(
                part=FuzzLocation.QUERY,
                type=FuzzType.POSTFIX,
                mode="single",
                fuzz=["{{injection}}"],
            )
        ],
        matchers=[
            DastMatcher(
                type=MatcherType.WORD,
                part="body",
                words=["SQL syntax", "mysql_fetch"],
                condition="or",
            )
        ],
        matchers_condition="or",
    )


@pytest.fixture
def mock_http_client():
    """Mock HTTP client that returns configurable responses."""
    client = AsyncMock()
    response = SimpleResponse(status_code=200, text="Normal response", headers={})
    client.get.return_value = response
    client.post.return_value = response
    return client


# ============================================================================
# Template Parsing Tests
# ============================================================================


class TestTemplateParser:
    """Test YAML template parsing."""

    def test_parse_valid_yaml_string(self, parser):
        """Test parsing a valid nuclei-style YAML template."""
        yaml_content = """
id: sqli-error-based
info:
  name: Error based SQL Injection
  author: geeknik
  severity: critical
  tags: sqli,error,dast

http:
  - payloads:
      injection:
        - "'"
        - '"'
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{injection}}"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "SQL syntax"
"""
        template = parser.parse_string(yaml_content)
        assert template.id == "sqli-error-based"
        assert template.name == "Error based SQL Injection"
        assert template.severity == "critical"
        assert "sqli" in template.tags
        assert len(template.payloads["injection"]) == 2
        assert len(template.fuzzing) == 1
        assert template.fuzzing[0].part == FuzzLocation.QUERY
        assert len(template.matchers) == 1
        assert template.matchers[0].type == MatcherType.WORD

    def test_parse_missing_id_raises(self, parser):
        """Test that missing ID field raises error."""
        yaml_content = """
info:
  name: No ID template
"""
        with pytest.raises(TemplateParseError, match="missing 'id'"):
            parser.parse_string(yaml_content)

    def test_parse_invalid_yaml_raises(self, parser):
        """Test that malformed YAML raises error."""
        with pytest.raises(TemplateParseError, match="Invalid YAML"):
            parser.parse_string("{{not valid yaml: [[[")

    def test_parse_file_not_found(self, parser):
        """Test that non-existent file raises error."""
        with pytest.raises(TemplateParseError, match="not found"):
            parser.parse_file(Path("/nonexistent/template.yaml"))


# ============================================================================
# Sandbox Validation Tests (INJ-02)
# ============================================================================


class TestTemplateSandbox:
    """Test template sandbox security validation — INJ-02."""

    def test_rejects_file_scheme(self, sandbox):
        """VT-Spec INJ-02: Reject file:// scheme in payloads."""
        template = DastTemplate(
            id="test-file-scheme",
            name="Test",
            payloads={"evil": ["file:///etc/passwd"]},
        )
        result = sandbox.validate(template)
        assert not result.valid
        assert any("forbidden scheme" in e for e in result.errors)

    def test_rejects_gopher_scheme(self, sandbox):
        """VT-Spec INJ-02: Reject gopher:// scheme."""
        template = DastTemplate(
            id="test-gopher",
            name="Test",
            payloads={"evil": ["gopher://evil.com"]},
        )
        result = sandbox.validate(template)
        assert not result.valid

    def test_rejects_data_scheme(self, sandbox):
        """VT-Spec INJ-02: Reject data: scheme."""
        template = DastTemplate(
            id="test-data-scheme",
            name="Test",
            payloads={"evil": ["data:text/html,<script>alert(1)</script>"]},
        )
        result = sandbox.validate(template)
        assert not result.valid

    def test_rejects_shell_chars_in_variables(self, sandbox):
        """VT-Spec INJ-02: Reject shell metacharacters in variables."""
        template = DastTemplate(
            id="test-shell-chars",
            name="Test",
            variables={"cmd": "$(whoami)"},
        )
        result = sandbox.validate(template)
        assert not result.valid
        assert any("shell metacharacters" in e for e in result.errors)

    def test_rejects_backtick_in_variables(self, sandbox):
        """VT-Spec INJ-02: Reject backtick command substitution."""
        template = DastTemplate(
            id="test-backtick",
            name="Test",
            variables={"cmd": "`id`"},
        )
        result = sandbox.validate(template)
        assert not result.valid

    def test_rejects_pipe_in_variables(self, sandbox):
        """VT-Spec INJ-02: Reject pipe operator in variables."""
        template = DastTemplate(
            id="test-pipe",
            name="Test",
            variables={"cmd": "cat /etc/passwd | grep root"},
        )
        result = sandbox.validate(template)
        assert not result.valid

    def test_rejects_path_traversal(self, sandbox):
        """VT-Spec INJ-02: Reject path traversal in payloads."""
        template = DastTemplate(
            id="test-traversal",
            name="Test",
            payloads={"lfi": ["../../../etc/passwd"]},
        )
        result = sandbox.validate(template)
        assert not result.valid
        assert any("path traversal" in e for e in result.errors)

    def test_rejects_unsafe_template_id(self, sandbox):
        """VT-Spec INJ-02: Reject template IDs with unsafe characters.

        Pydantic validator catches this at construction time. We also verify
        the sandbox catches it if model_construct bypasses validation.
        """
        # Pydantic validator rejects at model level
        with pytest.raises(Exception):
            DastTemplate(id="test; rm -rf /", name="Test")

        # Sandbox also catches it if bypassed via model_construct
        template = DastTemplate.model_construct(
            id="test; rm -rf /",
            name="Test",
            payloads={},
            variables={},
            fuzzing=[],
            matchers=[],
            tags=[],
            matchers_condition="and",
            stop_at_first_match=True,
            max_payloads=50,
            author="",
            severity="high",
            description="",
        )
        result = sandbox.validate(template)
        assert not result.valid
        assert any("unsafe characters" in e for e in result.errors)

    def test_caps_payload_count_at_50(self, sandbox):
        """VT-Spec DOS-01: Warn when payloads exceed 50."""
        template = DastTemplate(
            id="test-payload-cap",
            name="Test",
            payloads={"big": [f"payload-{i}" for i in range(60)]},
        )
        result = sandbox.validate(template)
        # Should be valid but with warnings
        assert result.valid
        assert any("DOS-01" in w for w in result.warnings)

    def test_truncate_payloads(self, sandbox):
        """VT-Spec DOS-01: Truncate payloads to 50."""
        template = DastTemplate(
            id="test-truncate",
            name="Test",
            payloads={"big": [f"p{i}" for i in range(60)]},
        )
        truncated = sandbox.truncate_payloads(template)
        assert len(truncated.payloads["big"]) == 50

    def test_accepts_valid_template(self, sandbox, valid_template):
        """Valid templates pass sandbox validation."""
        result = sandbox.validate(valid_template)
        assert result.valid
        assert len(result.errors) == 0

    def test_allows_http_scheme_in_payloads(self, sandbox):
        """VT-Spec INJ-02: http/https schemes are allowed."""
        template = DastTemplate(
            id="test-http-ok",
            name="Test",
            payloads={"urls": ["http://evil.com/callback", "https://attacker.com"]},
        )
        result = sandbox.validate(template)
        assert result.valid

    def test_sanitize_payload_removes_backticks(self, sandbox):
        """VT-Spec INJ-02: Sanitize removes command substitution."""
        result = sandbox.sanitize_payload("`whoami`")
        assert "`" not in result

    def test_sanitize_payload_removes_dollar_paren(self, sandbox):
        """VT-Spec INJ-02: Sanitize removes $() substitution."""
        result = sandbox.sanitize_payload("$(cat /etc/passwd)")
        assert "$(" not in result

    def test_sanitize_payload_truncates_length(self, sandbox):
        """VT-Spec DOS-01: Sanitize truncates long payloads."""
        long_payload = "A" * 1000
        result = sandbox.sanitize_payload(long_payload)
        assert len(result) == 500

    def test_rejects_file_scheme_in_variables(self, sandbox):
        """VT-Spec INJ-02: Reject file:// in variable values."""
        template = DastTemplate(
            id="test-var-file",
            name="Test",
            variables={"target": "file:///etc/shadow"},
        )
        result = sandbox.validate(template)
        assert not result.valid


# ============================================================================
# Matcher Tests
# ============================================================================


class TestResponseMatcher:
    """Test response matchers."""

    def test_word_match_in_body(self, matcher):
        """Test word matcher finds substring in body."""
        response = SimpleResponse(status_code=500, text="Error: SQL syntax near 'test'")
        matchers = [DastMatcher(type=MatcherType.WORD, part="body", words=["SQL syntax"])]
        result = matcher.match(response, matchers)
        assert result.matched

    def test_word_no_match(self, matcher):
        """Test word matcher returns false when not found."""
        response = SimpleResponse(status_code=200, text="All good")
        matchers = [DastMatcher(type=MatcherType.WORD, part="body", words=["SQL syntax"])]
        result = matcher.match(response, matchers)
        assert not result.matched

    def test_word_match_condition_or(self, matcher):
        """Test word matcher with OR condition (any word matches)."""
        response = SimpleResponse(status_code=500, text="Warning: mysql_fetch error")
        matchers = [
            DastMatcher(
                type=MatcherType.WORD,
                part="body",
                words=["SQL syntax", "mysql_fetch", "ORA-"],
                condition="or",
            )
        ]
        result = matcher.match(response, matchers)
        assert result.matched

    def test_word_match_condition_and(self, matcher):
        """Test word matcher with AND condition (all words must match)."""
        response = SimpleResponse(status_code=500, text="SQL syntax error")
        matchers = [
            DastMatcher(
                type=MatcherType.WORD,
                part="body",
                words=["SQL syntax", "mysql_fetch"],
                condition="and",
            )
        ]
        result = matcher.match(response, matchers)
        assert not result.matched  # Only one word matches

    def test_regex_match(self, matcher):
        """Test regex matcher finds pattern in body."""
        response = SimpleResponse(
            status_code=500,
            text="Error: SQL syntax near 'x' at line 1 MySQL",
        )
        matchers = [
            DastMatcher(
                type=MatcherType.REGEX,
                part="body",
                regex=[r"SQL syntax.{0,500}?MySQL"],
            )
        ]
        result = matcher.match(response, matchers)
        assert result.matched

    def test_regex_no_match(self, matcher):
        """Test regex matcher returns false when pattern not found."""
        response = SimpleResponse(status_code=200, text="Normal page")
        matchers = [
            DastMatcher(
                type=MatcherType.REGEX,
                part="body",
                regex=[r"SQL syntax.{0,500}?MySQL"],
            )
        ]
        result = matcher.match(response, matchers)
        assert not result.matched

    def test_status_code_match(self, matcher):
        """Test status code matcher."""
        response = SimpleResponse(status_code=500, text="")
        matchers = [DastMatcher(type=MatcherType.STATUS, status=[500, 503])]
        result = matcher.match(response, matchers)
        assert result.matched

    def test_status_code_no_match(self, matcher):
        """Test status code matcher returns false for non-matching code."""
        response = SimpleResponse(status_code=200, text="")
        matchers = [DastMatcher(type=MatcherType.STATUS, status=[500, 503])]
        result = matcher.match(response, matchers)
        assert not result.matched

    def test_dsl_status_code_check(self, matcher):
        """Test DSL expression: status_code == 200."""
        response = SimpleResponse(status_code=200, text="OK")
        matchers = [DastMatcher(type=MatcherType.DSL, dsl=["status_code == 200"])]
        result = matcher.match(response, matchers)
        assert result.matched

    def test_dsl_contains(self, matcher):
        """Test DSL expression: contains(body, 'text')."""
        response = SimpleResponse(status_code=200, text="Found error message")
        matchers = [DastMatcher(type=MatcherType.DSL, dsl=["contains(body, 'error')"])]
        result = matcher.match(response, matchers)
        assert result.matched

    def test_dsl_compound_and(self, matcher):
        """Test DSL compound expression with &&."""
        response = SimpleResponse(status_code=200, text="Error in SQL query")
        matchers = [
            DastMatcher(
                type=MatcherType.DSL,
                dsl=["status_code == 200 && contains(body, 'Error')"],
            )
        ]
        result = matcher.match(response, matchers)
        assert result.matched

    def test_negative_matcher(self, matcher):
        """Test negative matcher inverts result."""
        response = SimpleResponse(status_code=200, text="Normal page")
        matchers = [
            DastMatcher(
                type=MatcherType.WORD,
                part="body",
                words=["Adminer"],
                negative=True,  # Should match when word is NOT found
            )
        ]
        result = matcher.match(response, matchers)
        assert result.matched

    def test_multiple_matchers_and_condition(self, matcher):
        """Test multiple matchers with AND condition."""
        response = SimpleResponse(status_code=500, text="SQL syntax error in MySQL query")
        matchers = [
            DastMatcher(
                type=MatcherType.WORD,
                part="body",
                words=["Adminer"],
                negative=True,
            ),
            DastMatcher(
                type=MatcherType.REGEX,
                part="body",
                regex=[r"SQL syntax.{0,100}?MySQL"],
            ),
        ]
        result = matcher.match(response, matchers, condition="and")
        assert result.matched


# ============================================================================
# Budget Enforcement Tests (DOS-01)
# ============================================================================


class TestBudgetEnforcement:
    """Test DOS-01 budget enforcement."""

    def test_stops_at_budget_limit(self, valid_template, mock_http_client):
        """VT-Spec DOS-01: Executor stops when budget exhausted."""

        async def run():
            executor = DastExecutor(
                http_client=mock_http_client,
                budget=2,  # Very small budget
                allowlist=["example.com"],
            )
            results = await executor.execute_template(
                valid_template, ["http://example.com/test?id=1"]
            )
            # Should stop after budget (2 requests max)
            assert executor.requests_made <= 2
            return results

        asyncio.run(run())

    def test_budget_remaining_decrements(self, valid_template, mock_http_client):
        """VT-Spec DOS-01: Budget remaining decreases with requests."""

        async def run():
            executor = DastExecutor(
                http_client=mock_http_client,
                budget=100,
                allowlist=["example.com"],
            )
            assert executor.budget_remaining == 100
            await executor.execute_template(valid_template, ["http://example.com/test?id=1"])
            assert executor.budget_remaining < 100
            assert executor.requests_made > 0

        asyncio.run(run())

    def test_max_budget_capped_at_5000(self, mock_http_client):
        """VT-Spec DOS-01: Budget cannot exceed MAX_TOTAL_DAST_REQUESTS."""
        executor = DastExecutor(
            http_client=mock_http_client,
            budget=10000,  # Over the cap
        )
        assert executor.budget_remaining <= 5000

    def test_max_payloads_model_validation(self):
        """VT-Spec DOS-01: DastTemplate.max_payloads capped at 50."""
        template = DastTemplate(
            id="test-cap",
            name="Test",
            max_payloads=100,  # Over cap
        )
        assert template.max_payloads == 50


# ============================================================================
# Executor Tests
# ============================================================================


class TestDastExecutor:
    """Test DAST template execution."""

    def test_execute_template_happy_path(self, mock_http_client):
        """Test successful template execution with matching response."""

        async def run():
            # Configure mock to return SQL error
            mock_http_client.get.return_value = SimpleResponse(
                status_code=500,
                text="Error: SQL syntax near '\\'' at line 1 MySQL",
                headers={"Content-Type": "text/html"},
            )

            executor = DastExecutor(
                http_client=mock_http_client,
                budget=100,
                allowlist=["example.com"],
            )

            template = DastTemplate(
                id="sqli-test",
                name="SQL Injection Test",
                severity="critical",
                payloads={"injection": ["'"]},
                fuzzing=[
                    DastFuzzRule(
                        part=FuzzLocation.QUERY,
                        type=FuzzType.POSTFIX,
                        mode="single",
                        fuzz=["{{injection}}"],
                    )
                ],
                matchers=[
                    DastMatcher(
                        type=MatcherType.REGEX,
                        part="body",
                        regex=[r"SQL syntax.{0,500}?MySQL"],
                    )
                ],
                matchers_condition="or",
            )

            results = await executor.execute_template(template, ["http://example.com/page?id=1"])
            assert len(results) > 0
            assert any(r.matched for r in results)
            matched = [r for r in results if r.matched][0]
            assert matched.template_id == "sqli-test"
            assert "'" in matched.payload_used

        asyncio.run(run())

    def test_stop_at_first_match(self, mock_http_client):
        """Test that stop_at_first_match stops after first positive result."""

        async def run():
            mock_http_client.get.return_value = SimpleResponse(
                status_code=500,
                text="SQL syntax error MySQL",
            )

            executor = DastExecutor(
                http_client=mock_http_client,
                budget=100,
                allowlist=["example.com"],
            )

            template = DastTemplate(
                id="sqli-stop-test",
                name="Stop Test",
                payloads={"injection": ["'", '"', ";", "--", "/*"]},
                fuzzing=[
                    DastFuzzRule(
                        part=FuzzLocation.QUERY,
                        type=FuzzType.POSTFIX,
                        fuzz=["{{injection}}"],
                    )
                ],
                matchers=[
                    DastMatcher(
                        type=MatcherType.WORD,
                        part="body",
                        words=["SQL syntax"],
                    )
                ],
                stop_at_first_match=True,
            )

            results = await executor.execute_template(template, ["http://example.com/page?id=1"])
            matched_results = [r for r in results if r.matched]
            # Should stop after first match, not test all 5 payloads
            assert len(matched_results) == 1
            assert executor.requests_made < 5

        asyncio.run(run())

    def test_rejects_out_of_scope_target(self, valid_template, mock_http_client):
        """Test that targets outside allowlist are skipped."""

        async def run():
            executor = DastExecutor(
                http_client=mock_http_client,
                budget=100,
                allowlist=["allowed.com"],
            )

            results = await executor.execute_template(valid_template, ["http://evil.com/page?id=1"])
            assert len(results) == 0
            assert executor.requests_made == 0

        asyncio.run(run())

    def test_passes_default_auth_headers(self, valid_template, mock_http_client):
        async def run():
            executor = DastExecutor(
                http_client=mock_http_client,
                budget=100,
                allowlist=["example.com"],
                default_headers={"Authorization": "Bearer token-123"},
            )

            await executor.execute_template(valid_template, ["http://example.com/page?id=1"])

            assert mock_http_client.get.await_args is not None
            assert mock_http_client.get.await_args.kwargs["headers"] == {
                "Authorization": "Bearer token-123"
            }

        asyncio.run(run())

    def test_sandbox_rejects_malicious_template(self, mock_http_client):
        """VT-Spec INJ-02: Malicious template rejected before execution."""

        async def run():
            executor = DastExecutor(
                http_client=mock_http_client,
                budget=100,
            )

            # Use model_construct to bypass Pydantic validation for testing
            evil_template = DastTemplate.model_construct(
                id="evil; rm -rf /",
                name="Evil",
                payloads={"x": ["file:///etc/passwd"]},
                variables={},
                fuzzing=[],
                matchers=[],
                tags=[],
                matchers_condition="and",
                stop_at_first_match=True,
                max_payloads=50,
                author="",
                severity="high",
                description="",
            )

            results = await executor.execute_template(evil_template, ["http://example.com/"])
            # Should be empty — template rejected by sandbox
            assert len(results) == 0
            assert executor.requests_made == 0

        asyncio.run(run())


# ============================================================================
# Model Tests
# ============================================================================


class TestModels:
    """Test Pydantic model validations."""

    def test_template_id_validation_rejects_special_chars(self):
        """VT-Spec INJ-02: Model rejects unsafe template IDs."""
        with pytest.raises(Exception):  # Pydantic ValidationError
            DastTemplate(id="test; whoami", name="Test")

    def test_template_id_accepts_valid(self):
        """Valid template IDs are accepted."""
        template = DastTemplate(id="sqli-error-based.v2", name="Test")
        assert template.id == "sqli-error-based.v2"

    def test_max_payloads_cap(self):
        """VT-Spec DOS-01: max_payloads > 50 gets capped."""
        template = DastTemplate(id="test", name="Test", max_payloads=200)
        assert template.max_payloads == 50

    def test_max_payloads_minimum(self):
        """VT-Spec DOS-01: max_payloads < 1 gets set to 1."""
        template = DastTemplate(id="test", name="Test", max_payloads=0)
        assert template.max_payloads == 1
