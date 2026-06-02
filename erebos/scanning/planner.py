"""Scan Strategy Planner — LLM-driven or advisory scan planning.

VT-Spec AUTH-03 / TA-002: Produces adaptive scan plans based on
discovered context (endpoints, forms, auth state, technologies).

Two execution modes:
- AUTONOMOUS: Uses LLMCascade internally to generate and execute plans
- ADVISORY: Returns structured plan for host agent (Claude Code, Copilot CLI)
  to reason about and execute via MCP tool calls

The key insight: when running inside a coding agent, the HOST agent
IS the LLM — we just need to give it the right context. We don't need
to call another LLM; we surface structured observations and let the
host agent decide.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PlannerMode(str, Enum):
    """How the planner should operate."""

    AUTONOMOUS = "autonomous"  # Generates + executes plan internally
    ADVISORY = "advisory"  # Returns plan for host agent to execute


class StepType(str, Enum):
    """Types of plan steps."""

    REGISTER = "register"
    LOGIN = "login"
    SCAN_UNAUTH = "scan_unauthenticated"
    SCAN_AUTH = "scan_authenticated"
    CRAWL = "crawl"
    FUZZ = "fuzz"
    EXPLOIT = "exploit"
    REPORT = "report"


@dataclass
class PlanStep:
    """A single step in the scan plan."""

    step_type: StepType
    description: str
    tool: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    depends_on: Optional[int] = None  # Index of step this depends on
    priority: int = 0  # Lower = execute first

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_type.value,
            "description": self.description,
            "tool": self.tool,
            "parameters": self.parameters,
            "reasoning": self.reasoning,
            "depends_on": self.depends_on,
            "priority": self.priority,
        }


@dataclass
class ScanContext:
    """Enriched context gathered from recon/introspection.

    This is the "world model" that the planner (or host agent) uses to decide
    what to do next. When running via MCP, this entire context is returned
    to the coding agent so it can reason about the scan strategy.
    """

    target: str
    base_url: str = ""
    # Discovery
    technologies: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    # Auth awareness
    has_login: bool = False
    has_register: bool = False
    login_fields: List[str] = field(default_factory=list)
    register_fields: List[str] = field(default_factory=list)
    auth_acquired: bool = False
    auth_type: Optional[str] = None  # "cookie", "bearer", None
    # Protected areas (returned 401/403 without session)
    protected_endpoints: List[str] = field(default_factory=list)
    # Findings so far
    findings_count: int = 0
    critical_findings: int = 0
    technologies_detected: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "base_url": self.base_url,
            "technologies": self.technologies,
            "open_ports": self.open_ports,
            "endpoints": self.endpoints,
            "auth": {
                "has_login": self.has_login,
                "has_register": self.has_register,
                "login_fields": self.login_fields,
                "register_fields": self.register_fields,
                "auth_acquired": self.auth_acquired,
                "auth_type": self.auth_type,
            },
            "protected_endpoints": self.protected_endpoints,
            "findings_summary": {
                "total": self.findings_count,
                "critical": self.critical_findings,
            },
            "technologies_detected": self.technologies_detected,
        }

    def to_advisory_prompt(self) -> str:
        """Format context as a natural language advisory for host agents.

        When Erebos runs as an MCP tool inside Claude Code or Copilot CLI,
        this text is returned alongside findings so the host agent can
        reason about next steps without needing an internal LLM call.
        """
        lines = [
            f"## Scan Context for {self.target}",
            "",
            "### Discovered Technologies",
            ", ".join(self.technologies) if self.technologies else "None detected yet",
            "",
            "### Authentication State",
        ]

        if self.auth_acquired:
            lines.append(f"✅ Authenticated ({self.auth_type})")
        else:
            if self.has_login:
                lines.append(f"⚠️ Login form detected (fields: {self.login_fields})")
            if self.has_register:
                lines.append(f"⚠️ Registration available (fields: {self.register_fields})")
            if self.protected_endpoints:
                lines.append(f"🔒 Protected endpoints found: {self.protected_endpoints[:5]}")
            if self.has_login and not self.auth_acquired:
                lines.append("")
                lines.append(
                    "**Recommendation:** Register → Login → Re-scan authenticated "
                    "to access protected functionality."
                )

        if self.technologies:
            lines.extend(["", "### Suggested Scan Strategy"])
            tech_lower = [t.lower() for t in self.technologies]
            if any(t in tech_lower for t in ("node.js", "express", "mongodb")):
                lines.append("- Run NoSQL injection tests (`-tags nosql,mongodb`)")
            if any(t in tech_lower for t in ("php", "wordpress", "laravel")):
                lines.append("- Run PHP/WordPress specific scans (`-tags wordpress,php`)")
            if any(t in tech_lower for t in ("java", "spring", "tomcat")):
                lines.append("- Run Java deserialization + JNDI tests")
            if any(t in tech_lower for t in ("python", "django", "flask")):
                lines.append("- Run SSTI + Python-specific injection tests")

        return "\n".join(lines)


@dataclass
class ScanPlan:
    """Complete scan plan produced by the planner.

    In AUTONOMOUS mode: executed internally by the fleet orchestrator.
    In ADVISORY mode: returned via MCP response for host agent to execute.
    """

    mode: PlannerMode
    context: ScanContext
    steps: List[PlanStep] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "context": self.context.to_dict(),
            "steps": [s.to_dict() for s in self.steps],
            "reasoning": self.reasoning,
        }

    def to_mcp_response(self) -> Dict[str, Any]:
        """Format as MCP tool response content.

        Returns structured data + natural language advisory that a
        coding agent (Claude Code, Copilot CLI) can use to decide
        next actions via MCP tool calls.
        """
        return {
            "scan_plan": self.to_dict(),
            "advisory": self.context.to_advisory_prompt(),
            "suggested_next_calls": [
                {
                    "tool": step.tool or "erebos_scan",
                    "parameters": step.parameters,
                    "reason": step.reasoning,
                }
                for step in self.steps
                if step.step_type not in (StepType.REPORT,)  # Don't suggest report as next call
            ],
        }


class ScanPlanner:
    """Produces scan plans from enriched context.

    Architecture decision: This class does NOT call an LLM itself.
    Instead it produces structured plans that either:
    - Get executed by the fleet orchestrator (autonomous mode)
    - Get returned to the host coding agent (advisory mode)

    The host agent (Claude Code, Copilot CLI) IS already an LLM —
    we don't need to call another one. We just need to give it
    the right structured context to reason about.
    """

    def generate_plan(
        self,
        context: ScanContext,
        mode: PlannerMode = PlannerMode.AUTONOMOUS,
    ) -> ScanPlan:
        """Generate a scan plan from the current context.

        Uses heuristic rules to produce a baseline plan. In ADVISORY mode,
        the host agent can override/extend this plan with its own reasoning.
        """
        steps: List[PlanStep] = []
        reasoning_parts: List[str] = []

        # ── Rule 1: If auth required but not acquired → register + login first
        if (
            context.has_login
            and not context.auth_acquired
            and (context.protected_endpoints or context.has_register)
        ):
            if context.has_register:
                steps.append(
                    PlanStep(
                        step_type=StepType.REGISTER,
                        description=f"Register test user at {context.target}",
                        tool="erebos_auth",
                        parameters={
                            "target": context.target,
                            "action": "register",
                            "form_fields": context.register_fields,
                        },
                        reasoning="Registration available and protected endpoints detected. "
                        "Need authenticated session to scan behind login.",
                        priority=0,
                    )
                )
                steps.append(
                    PlanStep(
                        step_type=StepType.LOGIN,
                        description=f"Login to obtain session for {context.target}",
                        tool="erebos_auth",
                        parameters={
                            "target": context.target,
                            "action": "login",
                            "form_fields": context.login_fields,
                        },
                        reasoning="Login after registration to obtain session cookie/token.",
                        depends_on=0,
                        priority=1,
                    )
                )
                reasoning_parts.append("Auth-first strategy: register → login → authenticated scan")

        # ── Rule 2: Unauthenticated scan (always runs)
        steps.append(
            PlanStep(
                step_type=StepType.SCAN_UNAUTH,
                description="Unauthenticated vulnerability scan",
                tool="erebos_scan",
                parameters={
                    "target": context.target,
                    "phase": "vuln-scan",
                },
                reasoning="Baseline scan without auth to find public-facing issues.",
                priority=2,
            )
        )

        # ── Rule 3: Authenticated scan (if auth available or will be acquired)
        if context.auth_acquired or context.has_register:
            tech_tags = self._tech_to_tags(context.technologies)
            params: Dict[str, Any] = {
                "target": context.target,
                "phase": "vuln-scan",
                "authenticated": True,
            }
            if tech_tags:
                params["nuclei_tags"] = tech_tags

            steps.append(
                PlanStep(
                    step_type=StepType.SCAN_AUTH,
                    description="Authenticated vulnerability scan with tech-specific templates",
                    tool="erebos_scan",
                    parameters=params,
                    reasoning=f"Scan behind auth with technology-aware templates: {tech_tags}",
                    depends_on=1 if context.has_register and not context.auth_acquired else None,
                    priority=3,
                )
            )
            reasoning_parts.append(
                f"Tech-aware auth scan targeting: {', '.join(context.technologies)}"
            )

        # ── Rule 4: Exploit phase for critical findings
        if context.critical_findings > 0:
            steps.append(
                PlanStep(
                    step_type=StepType.EXPLOIT,
                    description="Validate critical findings with exploit engine",
                    tool="erebos_exploit",
                    parameters={"target": context.target, "severity": "critical"},
                    reasoning="Critical findings detected — validate exploitability.",
                    priority=4,
                )
            )

        plan = ScanPlan(
            mode=mode,
            context=context,
            steps=steps,
            reasoning=" → ".join(reasoning_parts) if reasoning_parts else "Standard scan plan",
        )

        logger.info(
            "Generated %s plan with %d steps for %s: %s",
            mode.value,
            len(steps),
            context.target,
            plan.reasoning,
        )
        return plan

    def _tech_to_tags(self, technologies: List[str]) -> List[str]:
        """Map detected technologies to nuclei tags."""
        from erebos.scanning.tech_detection import get_tags_for_technologies

        tech_set = {t.lower().replace(" ", "").replace(".", "") for t in technologies}
        # Normalize common names
        normalized = set()
        for t in tech_set:
            if "node" in t or "express" in t:
                normalized.add("nodejs")
            elif "php" in t or "laravel" in t:
                normalized.add("php")
            elif "python" in t or "django" in t or "flask" in t:
                normalized.add("python")
            elif "java" in t or "spring" in t:
                normalized.add("java")
            elif "wordpress" in t or "wp" in t:
                normalized.add("wordpress")
            elif "mongo" in t:
                normalized.add("mongodb")
            elif "react" in t or "angular" in t or "vue" in t:
                normalized.add("javascript")
            else:
                normalized.add(t)

        return get_tags_for_technologies(normalized)


def build_scan_context_from_findings(
    target: str,
    findings: List[Any],
    base_url: str = "",
    auth_acquired: bool = False,
    auth_type: Optional[str] = None,
    login_fields: Optional[List[str]] = None,
    register_fields: Optional[List[str]] = None,
) -> ScanContext:
    """Build a ScanContext from scan findings — used by MCP response builder.

    This is called after a scan completes to produce the enriched context
    that gets returned to the host coding agent.
    """
    from erebos.scanning.tech_detection import detect_technologies_from_findings

    technologies = list(detect_technologies_from_findings(findings))

    # Extract endpoints from findings
    endpoints = []
    for f in findings:
        if hasattr(f, "url") and f.url:
            endpoints.append(str(f.url))
        elif hasattr(f, "evidence") and isinstance(f.evidence, dict):
            url = f.evidence.get("url") or f.evidence.get("matched_at", "")
            if url:
                endpoints.append(str(url))

    # Detect protected endpoints (findings mentioning 401/403)
    protected = []
    for f in findings:
        title = getattr(f, "title", "") or ""
        if "401" in title or "403" in title or "unauthorized" in title.lower():
            url = getattr(f, "url", "") or ""
            if url:
                protected.append(url)

    # Count severities
    critical = sum(
        1 for f in findings if getattr(f, "severity", "").lower() in ("critical", "high")
    )

    return ScanContext(
        target=target,
        base_url=base_url or f"https://{target}",
        technologies=technologies,
        endpoints=list(set(endpoints))[:50],  # Cap at 50
        has_login=any("/login" in ep or "/signin" in ep for ep in endpoints),
        has_register=any("/register" in ep or "/signup" in ep for ep in endpoints),
        login_fields=login_fields or [],
        register_fields=register_fields or [],
        auth_acquired=auth_acquired,
        auth_type=auth_type,
        protected_endpoints=protected,
        findings_count=len(findings),
        critical_findings=critical,
        technologies_detected=technologies,
    )
