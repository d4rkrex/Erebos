"""Tests for VT-Spec AUTH-03: Scan planner and advisory context."""


from erebos.scanning.planner import (
    PlannerMode,
    ScanContext,
    ScanPlanner,
    StepType,
    build_scan_context_from_findings,
)


class TestScanPlanner:
    """Test scan plan generation from context."""

    def test_plan_with_auth_required(self):
        """When login detected + no auth → plan includes register+login first."""
        ctx = ScanContext(
            target="dvna.labs.example.com",
            base_url="https://dvna.labs.example.com",
            technologies=["Node.js", "Express"],
            has_login=True,
            has_register=True,
            login_fields=["username", "password"],
            register_fields=["name", "username", "email", "password", "cpassword"],
            auth_acquired=False,
            protected_endpoints=["/app/usersearch", "/app/admin"],
        )

        planner = ScanPlanner()
        plan = planner.generate_plan(ctx, mode=PlannerMode.ADVISORY)

        step_types = [s.step_type for s in plan.steps]
        assert StepType.REGISTER in step_types
        assert StepType.LOGIN in step_types
        assert StepType.SCAN_AUTH in step_types
        # Register should come before login
        reg_idx = step_types.index(StepType.REGISTER)
        login_idx = step_types.index(StepType.LOGIN)
        assert reg_idx < login_idx

    def test_plan_without_auth(self):
        """When no login detected → plan is just scan."""
        ctx = ScanContext(
            target="static.example.com",
            technologies=["nginx"],
            has_login=False,
            has_register=False,
            auth_acquired=False,
        )

        planner = ScanPlanner()
        plan = planner.generate_plan(ctx)

        step_types = [s.step_type for s in plan.steps]
        assert StepType.REGISTER not in step_types
        assert StepType.LOGIN not in step_types
        assert StepType.SCAN_UNAUTH in step_types

    def test_plan_with_auth_already_acquired(self):
        """When auth already acquired → skip register/login, include auth scan."""
        ctx = ScanContext(
            target="app.example.com",
            technologies=["PHP", "Laravel"],
            has_login=True,
            has_register=True,
            auth_acquired=True,
            auth_type="cookie",
        )

        planner = ScanPlanner()
        plan = planner.generate_plan(ctx)

        step_types = [s.step_type for s in plan.steps]
        assert StepType.REGISTER not in step_types
        assert StepType.LOGIN not in step_types
        assert StepType.SCAN_AUTH in step_types

    def test_plan_mcp_response_format(self):
        """Advisory plan produces valid MCP response structure."""
        ctx = ScanContext(
            target="test.com",
            has_login=True,
            has_register=True,
            login_fields=["email", "password"],
            register_fields=["email", "password", "name"],
            technologies=["Node.js"],
            protected_endpoints=["/api/private"],
        )

        planner = ScanPlanner()
        plan = planner.generate_plan(ctx, mode=PlannerMode.ADVISORY)
        mcp_resp = plan.to_mcp_response()

        assert "scan_plan" in mcp_resp
        assert "advisory" in mcp_resp
        assert "suggested_next_calls" in mcp_resp
        assert isinstance(mcp_resp["advisory"], str)
        assert "Authentication State" in mcp_resp["advisory"]
        assert "Recommendation" in mcp_resp["advisory"]


class TestScanContextAdvisory:
    """Test the advisory text generation for host agents."""

    def test_advisory_mentions_nosqli_for_nodejs(self):
        ctx = ScanContext(
            target="dvna.example.com",
            technologies=["Node.js", "Express"],
            has_login=True,
            auth_acquired=False,
        )
        advisory = ctx.to_advisory_prompt()
        assert "NoSQL injection" in advisory

    def test_advisory_mentions_auth_recommendation(self):
        ctx = ScanContext(
            target="app.example.com",
            has_login=True,
            has_register=True,
            login_fields=["username", "password"],
            register_fields=["username", "email", "password"],
            auth_acquired=False,
            protected_endpoints=["/app/dashboard"],
        )
        advisory = ctx.to_advisory_prompt()
        assert "Register" in advisory
        assert "Login" in advisory
        assert "Re-scan" in advisory or "Re-scan" in advisory.replace("-", "")

    def test_advisory_shows_authenticated_when_auth_acquired(self):
        ctx = ScanContext(
            target="app.example.com",
            auth_acquired=True,
            auth_type="cookie",
        )
        advisory = ctx.to_advisory_prompt()
        assert "✅" in advisory
        assert "cookie" in advisory


class _MockEvidence:
    def __init__(self, url="", output=""):
        self.url = url
        self.output = output


class _MockFinding:
    def __init__(self, title="", description="", severity="info", url="", target="", evidence=None):
        self.title = title
        self.description = description
        self.severity = severity
        self.url = url
        self.target = target
        self.evidence = evidence or _MockEvidence(url=url)


class TestBuildScanContextFromFindings:
    """Test context builder from findings list."""

    def test_detects_technologies_from_findings(self):
        findings = [
            _MockFinding(
                title="Wappalyzer Technology - Node.js",
                url="https://test.com",
            ),
        ]
        ctx = build_scan_context_from_findings(
            target="test.com",
            findings=findings,
        )
        assert "nodejs" in ctx.technologies or "nodejs" in ctx.technologies_detected

    def test_extracts_endpoints_from_findings(self):
        findings = [
            _MockFinding(
                title="Open endpoint",
                url="https://test.com/api/users",
            ),
        ]
        ctx = build_scan_context_from_findings(target="test.com", findings=findings)
        assert "https://test.com/api/users" in ctx.endpoints
