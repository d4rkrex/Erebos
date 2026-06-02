"""Fleet orchestrator — spawns and coordinates parallel agents.

VT-Spec DS-001: Rate limiting and maximum concurrency controls.
VT-Spec EP-001: Access controls for fleet operations.
VT-Spec RE-001: All actions logged with timestamps + integrity hash.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from typing import Any, Dict, List, Optional, cast

from erebos.agents.base import (
    MAX_FLEET_AGENTS,
    AgentMessage,
    AgentRole,
    AgentStatus,
    FindingsBus,
)

logger = logging.getLogger(__name__)


class FleetConfig:
    """Configuration for fleet mode execution."""

    # VT-Spec R5 Scenario 5.4: Profile-based pipeline definitions
    PROFILE_PIPELINES: Dict[str, List[AgentRole]] = {
        "aggressive": [
            AgentRole.RECON,
            AgentRole.VULN_SCAN,
            AgentRole.WEB_DISCOVERY,
            AgentRole.EXPLOIT,
            AgentRole.REPORTER,
        ],
        "standard": [
            AgentRole.RECON,
            AgentRole.VULN_SCAN,
            AgentRole.REPORTER,
        ],
        "stealth": [
            AgentRole.RECON,
            AgentRole.REPORTER,
        ],
    }

    def __init__(
        self,
        target: str,
        repos: Optional[List[Path]] = None,
        roles: Optional[List[AgentRole]] = None,
        max_agents: int = 5,
        findings_bus_path: Optional[Path] = None,
        allowlist: Optional[List[str]] = None,
        dry_run: bool = False,
        rate_limit_per_minute: int = 30,
        timeout_per_agent: float = 600.0,
        profile: str = "aggressive",
        source_path: Optional[Path] = None,
        trust_rules: bool = False,
        report_format: str = "md",
        redact_paths: bool = False,
        base_path: str = "/",
        osint_mode: str = "none",
        auth_context: Optional[Any] = None,
    ):
        # VT-Spec DS-001: Enforce hard cap on agents
        self.target = target
        self.repos = repos or []
        self.profile = profile
        # VT-Spec R5 Scenario 5.4: Auto-include web_discovery+exploit in aggressive profile
        if roles is not None:
            self.roles = roles
        else:
            self.roles = list(
                self.PROFILE_PIPELINES.get(profile, self.PROFILE_PIPELINES["aggressive"])
            )
        # Auto-include CODE_AUDIT when repos are provided and role not already in list
        _repos = repos or []
        if _repos and AgentRole.CODE_AUDIT not in self.roles:
            # Insert CODE_AUDIT before EXPLOIT so SAST findings flow into exploit targeting
            exploit_idx = (
                self.roles.index(AgentRole.EXPLOIT)
                if AgentRole.EXPLOIT in self.roles
                else len(self.roles)
            )
            self.roles.insert(exploit_idx, AgentRole.CODE_AUDIT)
        self.max_agents = min(max_agents, MAX_FLEET_AGENTS)
        self.findings_bus_path = findings_bus_path or Path("./erebos-storage/findings-bus.jsonl")
        self.allowlist = allowlist or []
        # Auto-include target in allowlist — the target is always in scope
        self._ensure_target_in_allowlist(target)
        self.dry_run = dry_run
        # VT-Spec DS-001: Temporal rate limit for fleet operations
        self.rate_limit_per_minute = min(rate_limit_per_minute, 60)
        self.timeout_per_agent = timeout_per_agent
        # VT-Spec R3: Source analysis path (opt-in)
        self.source_path = source_path
        # VT-Spec EXEC-01: Trust custom Semgrep rules only if explicit
        self.trust_rules = trust_rules
        # VT-Spec R6: Report output format
        self.report_format = report_format
        # VT-Spec INJ-03: Redact paths in reports
        self.redact_paths = redact_paths
        # White-hat scope: restrict scanning to this URL path prefix
        self.base_path = base_path.rstrip("/") + "/" if base_path != "/" else "/"
        # OSINT mode: "none" (active only), "full" (passive + active), "only" (passive only)
        self.osint_mode = osint_mode
        if osint_mode == "only":
            # Override roles to only run recon + reporter
            self.roles = [AgentRole.RECON, AgentRole.REPORTER]
        # VT-Spec AUTH-01: Shared authentication context for authenticated scanning
        self.auth_context = auth_context
        # When True, skip internal LLM cascade — the host coding agent IS the LLM
        self.mcp_mode = False

    def _ensure_target_in_allowlist(self, target: str) -> None:
        """Auto-add target domain to allowlist — the scan target is always in scope."""
        from urllib.parse import urlparse

        host = target.lower().strip()
        if "://" in host:
            host = urlparse(host).hostname or host
        elif ":" in host:
            host = host.rsplit(":", 1)[0]

        if host and host not in self.allowlist:
            self.allowlist.append(host)


class AgentWorker:
    """Represents a running agent in the fleet."""

    def __init__(self, role: AgentRole, fleet_id: str):
        self.id = f"{role.value}-{uuid.uuid4().hex[:8]}"
        self.role = role
        self.fleet_id = fleet_id
        self.status = AgentStatus.IDLE
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.findings_count = 0
        self.errors: List[str] = []


class FleetOrchestrator:
    """Orchestrates parallel agents for pentest execution.

    VT-Spec DS-001: Hard cap at MAX_FLEET_AGENTS concurrent agents.
    VT-Spec EP-001: Validates authorization before fleet operations.
    VT-Spec RE-001: Logs all fleet actions.
    """

    # VT-Spec R5: Pipeline phase ordering — defines dependencies.
    # Each role waits for all roles earlier in the list to complete.
    # VT-Spec DS-001: Per-role timeout overrides (seconds).
    # Vuln-scan runs multiple nuclei passes (up to 8 dirs × 90s each) so needs more time.
    ROLE_TIMEOUT_OVERRIDES: Dict[str, float] = {
        "vuln-scan": 1200.0,  # 20 min — allows 8+ nuclei passes + auth crawl + form fuzzer
        "recon": 600.0,
        "code-audit": 600.0,
        "exploit": 600.0,
    }

    PIPELINE_ORDER: List[AgentRole] = [
        AgentRole.WEB_DISCOVERY,
        AgentRole.VULN_SCAN,
        AgentRole.CODE_AUDIT,
        AgentRole.EXPLOIT,
        AgentRole.REPORTER,
    ]

    def __init__(self, config: FleetConfig):
        self._config = config
        self._bus = FindingsBus(config.findings_bus_path)
        self._reason_loop: Optional[Any] = None
        if self._bus.graph:
            from erebos.agents.reason import ReasonLoop

            self._reason_loop = ReasonLoop(
                fact_graph=self._bus.graph,
                total_budget=1000,
                audit_log_path=Path("./erebos-storage/reason-audit.jsonl"),
            )
        self._workers: List[AgentWorker] = []
        self._fleet_id = f"fleet-{uuid.uuid4().hex[:12]}"
        self._started_at: Optional[datetime] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        # VT-Spec DS-001: Temporal rate limiting (token bucket)
        self._rate_tokens = config.rate_limit_per_minute
        self._rate_max = config.rate_limit_per_minute
        self._rate_last_refill = datetime.now(timezone.utc)
        # VT-Spec RE-001: Log integrity chain
        self._log_chain_hash = hashlib.sha256(b"genesis").hexdigest()
        # VT-Spec D-01: Shared rate limiter for discovery + exploit phases
        self._shared_rate_limiter: Optional[Any] = None

    @property
    def fleet_id(self) -> str:
        return self._fleet_id

    @property
    def bus(self) -> FindingsBus:
        return self._bus

    async def run(self) -> Dict[str, Any]:
        """Execute the fleet — sequentially by pipeline phase.

        VT-Spec R5 Scenario 5.1: web-discovery runs BEFORE vuln-scan so endpoints
        VT-Spec R5 Scenario 5.3: Pipeline sequencing ensures data flows correctly.
        VT-Spec DS-001: Uses semaphore + rate limiter to limit concurrent agents.

        Roles are executed in pipeline order. Roles at the same pipeline stage
        can run concurrently; roles in different stages run sequentially.
        """
        self._started_at = datetime.now(timezone.utc)
        self._log_action("FLEET_START", f"Roles: {[r.value for r in self._config.roles]}")

        # VT-Spec DS-001: Semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(self._config.max_agents)

        # VT-Spec D-01: Create shared rate limiter for discovery + exploit
        self._shared_rate_limiter = self._build_shared_rate_limiter()

        # VT-Spec R5: Group roles by pipeline stage and execute sequentially
        all_results: List[Any] = []
        for stage_roles in self._group_roles_by_stage():
            stage_tasks = []
            for role in stage_roles:
                worker = AgentWorker(role, self._fleet_id)
                self._workers.append(worker)
                stage_tasks.append(self._run_worker(worker))

            # Execute this stage (parallel within stage, sequential between stages)
            stage_results = await asyncio.gather(*stage_tasks, return_exceptions=True)
            all_results.extend(stage_results)

        # Collect results
        summary = self._build_summary(all_results)
        self._log_action("FLEET_COMPLETE", f"Duration: {summary['duration_ms']:.0f}ms")

        return summary

    def _group_roles_by_stage(self) -> List[List[AgentRole]]:
        """Group configured roles by pipeline stage for sequential execution.

        VT-Spec R5 Scenario 5.1: Ensures web-discovery runs before vuln-scan.
        Roles at the same pipeline position run concurrently.
        """
        # Build ordered stages from the configured roles
        stages: List[List[AgentRole]] = []
        role_set = set(self._config.roles)

        for pipeline_role in self.PIPELINE_ORDER:
            if pipeline_role in role_set:
                stages.append([pipeline_role])

        # Include any roles not in PIPELINE_ORDER at the end
        known = set(self.PIPELINE_ORDER)
        extra = [r for r in self._config.roles if r not in known]
        if extra:
            stages.append(extra)

        return stages

    def _build_shared_rate_limiter(self) -> Optional[Any]:
        """VT-Spec D-01: Build shared rate limiter for discovery + exploit phases."""
        try:
            from erebos.security.rate_limit import SharedRateLimiter

            return SharedRateLimiter(
                max_per_second=20.0,
                max_total_requests=10000,
            )
        except (ImportError, TypeError):
            logger.warning("SharedRateLimiter not available; discovery will use defaults")
            return None

    def run_sync(self) -> Dict[str, Any]:
        """Synchronous wrapper for run()."""
        return asyncio.run(self.run())

    def _count_worker_findings_on_bus(self, worker: AgentWorker) -> int:
        """Count findings already published to bus by this worker's role."""
        count = 0
        for msg in self._bus.subscribe(roles=[worker.role], message_types=["finding"]):
            count += 1
        return count

    async def _run_worker(self, worker: AgentWorker) -> Dict[str, Any]:
        """Run a single agent worker with concurrency + rate control + timeout."""
        assert self._semaphore is not None

        # VT-Spec DS-001: Acquire rate limit token before starting
        await self._acquire_rate_token()

        async with self._semaphore:
            worker.status = AgentStatus.RUNNING
            worker.started_at = datetime.now(timezone.utc)
            self._log_action("AGENT_START", f"{worker.id} ({worker.role.value})")

            try:
                role_timeout = self.ROLE_TIMEOUT_OVERRIDES.get(
                    worker.role.value, self._config.timeout_per_agent
                )
                result = await asyncio.wait_for(
                    self._execute_role(worker),
                    timeout=role_timeout,
                )
                worker.status = AgentStatus.COMPLETED
                worker.completed_at = datetime.now(timezone.utc)
                self._log_action(
                    "AGENT_COMPLETE", f"{worker.id}: {result.get('findings', 0)} findings"
                )
                reason_cycle = await self._run_reason_cycle()
                if reason_cycle is not None:
                    result["reason_cycle"] = reason_cycle
                return result
            except asyncio.TimeoutError:
                # Count findings already published before timeout
                worker.findings_count = max(
                    worker.findings_count, self._count_worker_findings_on_bus(worker)
                )
                worker.completed_at = datetime.now(timezone.utc)
                role_timeout = self.ROLE_TIMEOUT_OVERRIDES.get(
                    worker.role.value, self._config.timeout_per_agent
                )
                if worker.findings_count > 0:
                    worker.status = AgentStatus.COMPLETED
                    worker.errors.append(
                        f"Timeout after {role_timeout}s (budget exhausted)"
                    )
                    self._log_action(
                        "AGENT_COMPLETE",
                        f"{worker.id}: timeout but {worker.findings_count} findings produced",
                    )
                else:
                    worker.status = AgentStatus.FAILED
                    worker.errors.append(f"Timeout after {role_timeout}s")
                    self._log_action(
                        "AGENT_TIMEOUT",
                        f"{worker.id}: exceeded {role_timeout}s",
                    )
                return {
                    "error": "timeout",
                    "role": worker.role.value,
                    "findings": worker.findings_count,
                }
            except Exception as e:
                # Count findings already published before error
                worker.findings_count = max(
                    worker.findings_count, self._count_worker_findings_on_bus(worker)
                )
                worker.completed_at = datetime.now(timezone.utc)
                if worker.findings_count > 0:
                    worker.status = AgentStatus.COMPLETED
                    worker.errors.append(f"Partial: {e}")
                    self._log_action(
                        "AGENT_COMPLETE",
                        f"{worker.id}: error but {worker.findings_count} findings produced",
                    )
                else:
                    worker.status = AgentStatus.FAILED
                    worker.errors.append(str(e))
                    self._log_action("AGENT_FAILED", f"{worker.id}: {e}")
                return {
                    "error": str(e),
                    "role": worker.role.value,
                    "findings": worker.findings_count,
                }

    async def _execute_role(self, worker: AgentWorker) -> Dict[str, Any]:
        """Execute the specific role logic for a worker.

        Wires FleetOrchestrator to real role implementations from Phase 2.
        """
        # Publish status to bus
        self._bus.publish(
            AgentMessage(
                id=f"{worker.id}-start",
                role=worker.role,
                message_type="status",
                payload={"status": "running", "target": self._config.target},
            )
        )

        # Role-specific execution — wired to real implementations
        if worker.role == AgentRole.RECON:
            return await self._role_recon(worker)
        elif worker.role == AgentRole.VULN_SCAN:
            return await self._role_vuln_scan(worker)
        elif worker.role == AgentRole.WEB_DISCOVERY:
            return await self._role_web_discovery(worker)
        elif worker.role == AgentRole.EXPLOIT:
            return await self._role_exploit(worker)
        elif worker.role == AgentRole.CODE_AUDIT:
            return await self._role_code_audit(worker)
        elif worker.role == AgentRole.REPORTER:
            return await self._role_reporter(worker)
        else:
            return {"role": worker.role.value, "findings": 0}

    async def _role_recon(self, worker: AgentWorker) -> Dict[str, Any]:
        """Recon agent — runs nmap, subfinder via ToolExecutor."""
        from erebos.agents.roles.recon import ReconRole
        from erebos.agents.tool_executor import ToolConfig

        executor = self._build_tool_executor()

        # Auto-discover tool paths (prefer Go binaries for PD tools)
        recon_tools = [
            ("nmap", ["-Pn", "-sV", "-sC"]),
            ("subfinder", ["-silent"]),
            ("httpx", ["-sc", "-td", "-silent"]),
            ("assetfinder", ["--subs-only"]),
            ("gau", []),
            ("waybackurls", []),
            ("dnsx", ["-silent"]),
            ("katana", ["-silent"]),
            ("naabu", ["-silent"]),
        ]
        for tool_name, default_args in recon_tools:
            tool_path = self._find_tool_binary(tool_name)
            if tool_path:
                try:
                    executor.register_tool(
                        ToolConfig(
                            name=tool_name,
                            path=tool_path,
                            default_args=default_args,
                        )
                    )
                except (FileNotFoundError, ValueError) as e:
                    self._log_action("TOOL_SKIP", f"{tool_name}: {e}")
            else:
                self._log_action("TOOL_SKIP", f"{tool_name}: not found in PATH")

        role = ReconRole(
            executor=executor,
            bus=self._bus,
            agent_id=worker.id,
            target=self._config.target,
            osint_mode=self._config.osint_mode,
            auth_context=self._config.auth_context,
        )
        result = await role.execute()
        worker.findings_count = result.get("findings", 0)

        # VT-Spec EP-01: Validate discovered subdomains against allowlist
        discovered = result.get("discovered_subdomains", [])
        if discovered:
            from erebos.security.scope import AllowlistValidator

            validator = AllowlistValidator(self._config.allowlist)
            allowed = [h for h in discovered if validator.is_allowed(h)]
            blocked = [h for h in discovered if not validator.is_allowed(h)]
            if blocked:
                self._log_action(
                    "EP-01_SUBDOMAIN_BLOCKED",
                    f"Blocked {len(blocked)} subdomains not in allowlist: {blocked[:5]}",
                )
            # Publish allowed subdomains for other agents to consume
            if allowed:
                self._bus.publish(
                    AgentMessage(
                        id=f"{worker.id}-discovered-hosts",
                        role=AgentRole.RECON,
                        message_type="discovered_hosts",
                        payload={"hosts": allowed, "source": "osint"},
                    )
                )

        return result

    async def _role_vuln_scan(self, worker: AgentWorker) -> Dict[str, Any]:
        """Vuln scan agent — runs nuclei via ToolExecutor."""
        from erebos.agents.roles.vuln_scan import VulnScanRole
        from erebos.agents.tool_executor import ToolConfig

        executor = self._build_tool_executor()

        vuln_tools = [
            ("nuclei", ["-nc"]),  # No -silent: it suppresses JSONL output in nuclei v3
            ("nikto", []),
        ]
        for tool_name, default_args in vuln_tools:
            tool_path = self._find_tool_binary(tool_name)
            if tool_path:
                try:
                    executor.register_tool(
                        ToolConfig(
                            name=tool_name,
                            path=tool_path,
                            default_args=default_args,
                        )
                    )
                except (FileNotFoundError, ValueError) as e:
                    self._log_action("TOOL_SKIP", f"{tool_name}: {e}")
            else:
                self._log_action("TOOL_SKIP", f"{tool_name}: not found in PATH")

        # VT-Spec AUTH-01: Auto-acquire auth context if not provided
        auth_ctx = self._config.auth_context
        if not auth_ctx or not auth_ctx.has_auth:
            auth_ctx = await self._auto_acquire_auth(worker.id)

        role = VulnScanRole(
            executor=executor,
            bus=self._bus,
            agent_id=worker.id,
            target=self._config.target,
            allowlist=self._config.allowlist,
            auth_context=auth_ctx,
            repos=self._config.repos or [],
        )
        result = await role.execute()

        # VT-Spec R4: Infrastructure scanning for non-HTTP services
        infra_findings = await self._run_infra_scan(worker)
        if infra_findings:
            result["infra_findings"] = infra_findings
            result.setdefault("findings", 0)
            result["findings"] = result.get("findings", 0) + infra_findings

        worker.findings_count = result.get("findings", 0)

        # VT-Spec AUTH-02: Harvest credentials from vuln-scan findings
        if auth_ctx and role._findings:
            from erebos.auth.harvester import CredentialHarvester

            harvester = CredentialHarvester(auth_ctx)
            harvested = harvester.process_findings(role._findings)
            if harvested:
                self._log_action(
                    "AUTH_HARVEST",
                    f"Harvested {len(harvested)} credential(s) from vuln-scan findings",
                )

        return result

    async def _role_web_discovery(self, worker: AgentWorker) -> Dict[str, Any]:
        """Web discovery agent — attack surface enumeration and auth token acquisition.

        VT-Spec R5 Scenario 5.1: Runs after recon, before vuln-scan.
        VT-Spec T-01: All requests through ScopedHttpClient.
        VT-Spec D-01: Uses shared rate limiter.
        """
        from erebos.agents.roles.web_discovery import WebDiscoveryRole

        role = WebDiscoveryRole(
            bus=self._bus,
            agent_id=worker.id,
            target=self._normalize_target_url(self._config.target),
            allowlist=self._config.allowlist,
            rate_limiter=self._shared_rate_limiter,
            audit_log=Path("./erebos-storage/discovery-audit.jsonl"),
            enable_auth=True,
        )
        result = await role.execute()
        worker.findings_count = result.get("endpoints_discovered", 0)
        return result

    async def _role_exploit(self, worker: AgentWorker) -> Dict[str, Any]:
        """Exploit agent — templates + LLM cascade via ExploitRunner.

        VT-Spec R5 Scenario 5.2: Consumes AttackSurface from web-discovery.
        VT-Spec R5 Scenario 5.3: Reads auth tokens from shared context bus.
        """
        from erebos.agents.roles.exploit import ExploitRole
        from erebos.config.settings import get_settings
        from erebos.exploits.auth_manager import AuthManager
        from erebos.exploits.runner import ExploitRunner
        from erebos.exploits.template_engine import TemplateEngine

        settings = get_settings()
        runner = ExploitRunner(
            allowlist=self._config.allowlist,
            timeout=float(settings.exploitation.timeout),
            dry_run=self._config.dry_run or settings.exploitation.dry_run,
            audit_log=Path("./erebos-storage/exploit-audit.jsonl"),
            max_requests_per_second=10.0,
        )

        # VT-Spec R5 Scenario 5.3: Inject auth tokens from web-discovery phase
        auth_variables = self._gather_auth_tokens_from_bus()

        base_url = self._normalize_target_url(self._config.target)
        auth_manager = AuthManager(
            allowlist=self._config.allowlist,
            audit_log=Path("./erebos-storage/exploit-auth-audit.jsonl"),
        )
        try:
            endpoints = await auth_manager.detect_auth_endpoints(base_url)
            credentials = None
            if endpoints.register_path:
                credentials = await auth_manager.register_user(base_url, endpoints.register_path)
            if endpoints.login and credentials:
                auth_token = await auth_manager.login(base_url, endpoints.login, credentials)
                if auth_token:
                    auth_variables.update(auth_manager.get_variables(base_url))
                    self._publish_auth_token_to_bus(base_url, auth_manager, auth_token.token)
        except Exception as exc:
            logger.warning("Exploit auth bootstrap failed for %s: %s", base_url, exc)

        if auth_variables:
            runner.set_variables(auth_variables)
            self._log_action(
                "AUTH_INJECTED",
                f"Injected {len(auth_variables)} auth variables into runner",
            )

        template_engine = TemplateEngine()
        llm_cascade = self._build_llm_cascade()

        # VT-Spec R5 Scenario 5.2: Read AttackSurface and generate synthetic findings
        attack_surface = self._gather_attack_surface_from_bus()
        if attack_surface:
            self._publish_synthetic_findings_from_surface(attack_surface, worker.id)
            self._log_action(
                "ATTACK_SURFACE_LOADED",
                f"Loaded {len(attack_surface.get('endpoints', []))} endpoints from discovery",
            )

        self._publish_proactive_template_findings(template_engine, worker.id)

        role = ExploitRole(
            runner=runner,
            template_engine=template_engine,
            bus=self._bus,
            agent_id=worker.id,
            allowlist=self._config.allowlist,
            llm_cascade=llm_cascade,
            global_request_budget=5000,
        )
        result = await role.execute()

        # VT-Spec R2/R10: DAST template execution after standard exploit phase
        dast_findings = await self._run_dast_phase(worker, result)
        if dast_findings:
            result["dast_findings"] = dast_findings
            result["successful"] = result.get("successful", 0) + dast_findings

        worker.findings_count = result.get("successful", 0)
        return result

    async def _auto_acquire_auth(self, worker_id: str) -> Optional[Any]:
        """Auto-detect login forms, register+login, and return an AuthContext.

        VT-Spec AUTH-01: Auto-acquire credentials for authenticated scanning.
        VT-Spec AUTH-03: Form introspection adapts to any app's auth convention.
        VT-Spec I-02: Credentials are ephemeral (per-scan, never persisted).

        Decision chain (what the LLM *should* infer but we make explicit):
        0. Check bus for auth already acquired by web-discovery (fast path)
        1. Fetch /register page → parse HTML form → classify fields
        2. Generate random credentials adapted to discovered field names
        3. Submit registration with form-urlencoded (not JSON!)
        4. Fetch /login page → parse its form too
        5. Login with correct field names → extract session cookie or token
        6. Build AuthContext → publish to bus for all agents

        Returns AuthContext with session cookies/tokens, or None if acquisition fails.
        """
        import secrets

        import httpx

        from erebos.auth import AuthContext, AuthCredential, AuthType
        from erebos.auth.form_introspector import (
            build_login_payload,
            build_registration_payload,
            find_login_form,
            find_register_form,
        )

        base_url = self._normalize_target_url(self._config.target)

        # ── Phase 0: Reuse auth already acquired by web-discovery ──────────
        # web-discovery publishes auth_token messages with auth_cookies when it
        # successfully authenticates. Reuse those cookies instead of registering
        # a second test account.
        for msg in self._bus.subscribe(message_types=["auth_token"]):
            payload = msg.payload
            cookies = payload.get("auth_cookies")
            token_type = payload.get("auth_token_type", "")
            if cookies and isinstance(cookies, dict) and token_type.lower() in ("cookie", "session"):
                self._log_action(
                    "AUTH_AUTO_BUS",
                    f"Reusing auth from web-discovery: {list(cookies.keys())}",
                )
                auth_ctx = AuthContext(allowlist=self._config.allowlist)
                auth_ctx.add_static(
                    AuthCredential(auth_type=AuthType.COOKIE, cookies=cookies)
                )
                return auth_ctx

        self._log_action("AUTH_AUTO_START", f"Attempting adaptive auto-auth for {base_url}")

        # VT-Spec I-02: Ephemeral credentials per-scan
        test_username = f"erebos_{secrets.token_hex(4)}"
        test_email = f"{test_username}@pentest.local"
        test_password = secrets.token_urlsafe(16)

        try:
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=False, verify=False
            ) as client:
                # ── Phase 1: Introspect registration form ──────────────────
                register_form = None
                register_paths = ["/register", "/signup", "/sign-up", "/api/register"]
                for path in register_paths:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        if resp.status_code == 200:
                            register_form = find_register_form(resp.text)
                            if register_form:
                                self._log_action(
                                    "AUTH_FORM_INTROSPECTED",
                                    f"Register form at {path}: "
                                    f"fields={register_form.field_names}",
                                )
                                break
                    except httpx.HTTPError:
                        continue

                if not register_form:
                    self._log_action("AUTH_AUTO_SKIP", "No registration form detected")
                    return None

                # ── Phase 2: Submit registration with adapted payload ──────
                reg_payload = build_registration_payload(
                    form=register_form,
                    username=test_username,
                    password=test_password,
                    email=test_email,
                )
                reg_action = register_form.action or "/register"
                reg_url = f"{base_url}{reg_action}"
                self._log_action(
                    "AUTH_AUTO_REGISTER",
                    f"Registering at {reg_url} with adapted fields: " f"{list(reg_payload.keys())}",
                )

                reg_resp = await client.post(reg_url, data=reg_payload)

                # ── Phase 2b: Check if registration already gave us a session ──
                # Many apps (Express, Django, Passport.js) auto-login after
                # registration. Check for session cookies BEFORE the reg_ok
                # heuristic, because some apps (e.g., DVNA/Passport) return
                # 302→/login after successful registration (meaning: "please log
                # in with your new credentials"), which the heuristic would
                # incorrectly classify as failure.
                cookie_keywords = ("sess", "sid", "token", "auth", "jwt", "connect")
                reg_session_cookie = None

                # First check the POST response cookies
                for cookie_name, cookie_value in reg_resp.cookies.items():
                    if any(kw in cookie_name.lower() for kw in cookie_keywords):
                        reg_session_cookie = (cookie_name, cookie_value)
                        break

                # Fallback: check client jar (Express sets connect.sid on first GET,
                # then passport associates it with the user after successful register)
                if not reg_session_cookie:
                    for cookie_name, cookie_value in client.cookies.items():
                        if any(kw in cookie_name.lower() for kw in cookie_keywords):
                            reg_session_cookie = (cookie_name, cookie_value)
                            break

                if reg_session_cookie:
                    # Already authenticated from registration — skip login
                    self._log_action(
                        "AUTH_AUTO_SESSION_FROM_REGISTER",
                        f"Got session from registration: {reg_session_cookie[0]}",
                    )
                    auth_ctx = AuthContext(allowlist=self._config.allowlist)
                    auth_ctx.add_static(
                        AuthCredential(
                            auth_type=AuthType.COOKIE,
                            cookies={reg_session_cookie[0]: reg_session_cookie[1]},
                        )
                    )
                    self._log_action(
                        "AUTH_AUTO_SUCCESS",
                        f"Auth acquired from registration (no login needed): "
                        f"cookie={reg_session_cookie[0]}",
                    )
                    return auth_ctx

                # Fallback success heuristic: 200/201, or 302 to non-login/register page
                reg_ok = reg_resp.status_code in (200, 201) or (
                    reg_resp.status_code == 302
                    and "/login" not in reg_resp.headers.get("location", "")
                    and "/register" not in reg_resp.headers.get("location", "")
                )
                if not reg_ok:
                    self._log_action(
                        "AUTH_AUTO_FAIL",
                        f"Registration failed: status={reg_resp.status_code} "
                        f"location={reg_resp.headers.get('location', 'N/A')}",
                    )
                    return None

                self._log_action(
                    "AUTH_AUTO_REGISTERED",
                    f"User '{test_username}' registered successfully",
                )

                # ── Phase 3: Introspect login form ─────────────────────────
                login_form = None
                login_paths = ["/login", "/signin", "/sign-in", "/auth/login"]
                for path in login_paths:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        if resp.status_code == 200:
                            login_form = find_login_form(resp.text)
                            if login_form:
                                self._log_action(
                                    "AUTH_FORM_INTROSPECTED",
                                    f"Login form at {path}: " f"fields={login_form.field_names}",
                                )
                                break
                    except httpx.HTTPError:
                        continue

                if not login_form:
                    self._log_action("AUTH_AUTO_FAIL", "No login form found after registration")
                    return None

                # ── Phase 4: Login with adapted payload ────────────────────
                login_payload = build_login_payload(
                    form=login_form,
                    username=test_username,
                    password=test_password,
                )
                login_action = login_form.action or "/login"
                login_url = f"{base_url}{login_action}"
                login_resp = await client.post(login_url, data=login_payload)

                # ── Phase 5: Extract session (cookie or JSON token) ────────
                session_cookie = None
                auth_token_value = None

                # Check response cookies
                cookie_keywords = ("sess", "sid", "token", "auth", "jwt", "connect")
                for cookie_name, cookie_value in login_resp.cookies.items():
                    if any(kw in cookie_name.lower() for kw in cookie_keywords):
                        session_cookie = (cookie_name, cookie_value)
                        break

                # Check Set-Cookie header (for redirect responses)
                if not session_cookie:
                    import re

                    set_cookie = login_resp.headers.get("set-cookie", "")
                    for kw in ("connect.sid", "session_id", "JSESSIONID", "session"):
                        if kw in set_cookie:
                            match = re.search(rf"{re.escape(kw)}=([^;]+)", set_cookie)
                            if match:
                                session_cookie = (kw, match.group(1))
                                break

                # Check JSON body for token (API-style auth)
                if login_resp.status_code == 200 and not session_cookie:
                    try:
                        data = login_resp.json()
                        if isinstance(data, dict):
                            for key in ("token", "access_token", "jwt", "id_token"):
                                if data.get(key):
                                    auth_token_value = str(data[key])
                                    break
                    except Exception:
                        pass

                # Determine success
                login_ok = False
                if session_cookie or auth_token_value:
                    login_ok = True
                elif login_resp.status_code == 302:
                    location = login_resp.headers.get("location", "")
                    login_ok = "/login" not in location and "/signin" not in location

                if not login_ok:
                    self._log_action(
                        "AUTH_AUTO_FAIL",
                        f"Login failed: status={login_resp.status_code}, "
                        f"cookie={'yes' if session_cookie else 'no'}",
                    )
                    return None

                # ── Phase 6: Build AuthContext ─────────────────────────────
                auth_ctx = AuthContext(allowlist=self._config.allowlist)

                if auth_token_value:
                    auth_ctx.add_static(
                        AuthCredential(
                            auth_type=AuthType.BEARER,
                            token=auth_token_value,
                            source="auto-acquired",
                            target_scope=self._config.target,
                        )
                    )
                    self._log_action(
                        "AUTH_AUTO_SUCCESS",
                        f"Acquired Bearer token for {self._config.target}",
                    )
                elif session_cookie:
                    cookie_name, cookie_value = session_cookie
                    auth_ctx.add_static(
                        AuthCredential(
                            auth_type=AuthType.COOKIE,
                            cookies={cookie_name: cookie_value},
                            source="auto-acquired",
                            target_scope=self._config.target,
                        )
                    )
                    self._log_action(
                        "AUTH_AUTO_SUCCESS",
                        f"Acquired session cookie '{cookie_name}' " f"for {self._config.target}",
                    )

                # Publish to bus for other agents (exploit, web-discovery)
                token_for_bus = auth_token_value or (
                    f"{session_cookie[0]}={session_cookie[1]}" if session_cookie else ""
                )
                if token_for_bus:
                    from erebos.agents.base import AgentMessage, AgentRole

                    self._bus.publish(
                        AgentMessage(
                            id=f"{self._fleet_id}-auto-auth",
                            role=AgentRole.ORCHESTRATOR,
                            message_type="auth_token",
                            payload={
                                "domain": self._config.target,
                                "auth_token": token_for_bus,
                                "auth_email": test_email,
                                "auth_user_id": "",
                                "target": base_url,
                                "auth_type": "bearer" if auth_token_value else "cookie",
                            },
                        )
                    )

                return auth_ctx

        except Exception as exc:
            self._log_action("AUTH_AUTO_ERROR", f"Auth acquisition failed: {exc}")
            logger.warning("Auto-auth acquisition failed for %s: %s", base_url, exc)
            return None

    def _gather_auth_tokens_from_bus(self) -> Dict[str, str]:
        """Read auth tokens published by earlier phases.

        VT-Spec R5 Scenario 5.3: Pass auth tokens via shared context bus.
        Tokens are keyed by domain; we inject all into runner variables.
        VT-Spec I-01: Tokens are ephemeral (only in-memory via bus).
        """
        variables: Dict[str, str] = {}
        for msg in self._bus.subscribe(message_types=["auth_token"]):
            payload = msg.payload
            if payload.get("auth_token"):
                variables["auth_token"] = payload["auth_token"]
            if payload.get("auth_email"):
                variables["auth_email"] = payload["auth_email"]
            if payload.get("auth_user_id"):
                variables["auth_user_id"] = payload["auth_user_id"]
        return variables

    def _publish_auth_token_to_bus(self, target: str, auth_manager: Any, token: str) -> None:
        """Publish an auth token acquired during exploit bootstrap."""
        domain = urlparse(target).hostname or target
        state = getattr(auth_manager, "_auth_states", {}).get(domain)
        email = state.credentials.email if state and state.credentials else ""
        user_id = state.user_id if state else ""
        self._bus.publish(
            AgentMessage(
                id=f"{self._fleet_id}-auth-{domain}",
                role=AgentRole.ORCHESTRATOR,
                message_type="auth_token",
                payload={
                    "domain": domain,
                    "auth_token": token,
                    "auth_email": email,
                    "auth_user_id": user_id or "",
                    "target": target,
                },
            )
        )

    def _gather_dast_auth_headers(self) -> Dict[str, str]:
        """Build default DAST headers from any published auth token."""
        for msg in self._bus.subscribe(message_types=["auth_token"]):
            token = msg.payload.get("auth_token")
            if token:
                return {"Authorization": f"Bearer {token}"}
        return {}

    def _normalize_target_url(self, target: str) -> str:
        """Return a fully-qualified target URL, defaulting to HTTPS when missing.

        Applies base_path restriction for white-hat scoped engagements.
        """
        if target.startswith(("http://", "https://")):
            url = target.rstrip("/")
        else:
            url = f"https://{target.rstrip('/')}"
        # Append base_path for white-hat scope restriction
        if self._config.base_path and self._config.base_path != "/":
            url = url + self._config.base_path.rstrip("/")
        return url

    def _gather_attack_surface_from_bus(self) -> Optional[Dict[str, Any]]:
        """Read AttackSurface published by web-discovery role.

        VT-Spec R5 Scenario 5.2: Exploit agent receives discovery results.
        """
        for msg in self._bus.subscribe(
            roles=[AgentRole.WEB_DISCOVERY],
            message_types=["attack_surface"],
        ):
            return msg.payload
        return None

    def _publish_synthetic_findings_from_surface(
        self, surface: Dict[str, Any], agent_id: str
    ) -> None:
        """Create synthetic vuln-scan findings from discovered endpoints.

        VT-Spec R5 Scenario 5.2: For discovered endpoints WITHOUT findings,
        create synthetic findings based on endpoint characteristics so the
        exploit role can attempt template matching.
        """
        existing_targets: set = set()
        for msg in self._bus.subscribe(
            roles=[AgentRole.VULN_SCAN],
            message_types=["finding"],
        ):
            for target in (
                msg.payload.get("target", ""),
                msg.payload.get("injectable_url", ""),
                msg.payload.get("raw_target", ""),
            ):
                if target:
                    existing_targets.add(str(target).lower())

        endpoints = surface.get("endpoints", [])
        tech_stack = surface.get("tech_stack", [])
        count = 0

        for ep in endpoints:
            url = ep.get("url", "")
            params = ep.get("params", [])
            injectable_url = self._build_injectable_url(url, params)
            if (
                not url
                or url.lower() in existing_targets
                or injectable_url.lower() in existing_targets
            ):
                continue

            # Infer potential CWEs from endpoint characteristics
            cwe = self._infer_cwe_from_endpoint(ep, tech_stack)
            if not cwe:
                continue

            # VT-Spec R5: Publish as vuln-scan finding so exploit role picks it up
            self._bus.publish(
                AgentMessage(
                    id=f"{agent_id}-synthetic-{count}",
                    role=AgentRole.VULN_SCAN,
                    message_type="finding",
                    payload={
                        "id": f"synthetic-{count}",
                        "title": f"Discovered endpoint: {ep.get('method', 'GET')} {url}",
                        "target": injectable_url,
                        "raw_target": url,
                        "severity": "MEDIUM",
                        "tool": "web-discovery",
                        "cwe": cwe,
                        "phase_found": "discovery",
                        "params": params,
                        "injectable_url": injectable_url,
                        "description": (
                            f"Endpoint discovered via {ep.get('source', 'discovery')}. "
                            f"Tech hints: {', '.join(tech_stack)}. "
                            f"Discovered params: {', '.join(params) if params else 'none'}."
                        ),
                    },
                )
            )
            count += 1

    def _publish_proactive_template_findings(self, template_engine: Any, agent_id: str) -> None:
        """Create synthetic findings for template-defined endpoints found in attack surface.

        Only generates proactive tests for paths that were actually discovered
        during recon/discovery phases — never for hardcoded template paths that
        don't exist on the target.
        """
        base_url = self._config.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip("/")

        # Gather actually-discovered endpoints from bus (recon + web_discovery)
        discovered_paths: set[str] = set()
        for msg in self._bus.subscribe(message_types=["attack_surface"]):
            for endpoint in msg.payload.get("endpoints", []):
                path = endpoint.get("path", "") or endpoint.get("url", "")
                if path:
                    # Normalize: extract path portion
                    if path.startswith("http"):
                        from urllib.parse import urlparse

                        path = urlparse(path).path
                    discovered_paths.add(path.lower().rstrip("/"))

        # Also gather endpoint URLs from recon findings
        for msg in self._bus.subscribe(
            roles=[AgentRole.RECON, AgentRole.WEB_DISCOVERY], message_types=["finding"]
        ):
            for field in ("target", "url", "raw_target"):
                val = msg.payload.get(field, "")
                if val and val.startswith("http"):
                    from urllib.parse import urlparse

                    discovered_paths.add(urlparse(val).path.lower().rstrip("/"))

        if not discovered_paths:
            logger.debug("No discovered paths — skipping proactive template tests")
            return

        existing_targets: set[tuple[str, str]] = set()
        for msg in self._bus.subscribe(roles=[AgentRole.VULN_SCAN], message_types=["finding"]):
            cwe = str(msg.payload.get("cwe", "")).upper()
            for target in (
                msg.payload.get("target", ""),
                msg.payload.get("injectable_url", ""),
                msg.payload.get("raw_target", ""),
            ):
                if target:
                    existing_targets.add((str(target).lower(), cwe))

        count = 0
        for target_path in template_engine.get_all_target_paths():
            path = target_path["path"]
            # Only test paths that were actually discovered on this target
            path_normalized = path.lower().rstrip("/")
            if path_normalized not in discovered_paths:
                continue

            url = path if path.startswith("http") else f"{base_url}{path}"
            cwe = target_path["cwe"].upper()
            target_key = (url.lower(), cwe)
            if target_key in existing_targets:
                continue

            self._bus.publish(
                AgentMessage(
                    id=f"{agent_id}-proactive-{count}",
                    role=AgentRole.VULN_SCAN,
                    message_type="finding",
                    payload={
                        "id": f"proactive-{count}",
                        "title": f"Proactive test: {target_path['description']}",
                        "target": url,
                        "raw_target": url,
                        "severity": "MEDIUM",
                        "tool": "template-engine",
                        "cwe": cwe,
                        "phase_found": "discovery",
                        "description": (
                            f"Template-driven test for {target_path['template_id']} "
                            f"on {target_path['method']} {path}"
                        ),
                        "source": "template-proactive",
                    },
                )
            )
            existing_targets.add(target_key)
            count += 1

        if count:
            self._log_action(
                "PROACTIVE_FINDINGS",
                f"Created {count} proactive findings from templates (filtered by discovered paths)",
            )

    def _build_injectable_url(self, url: str, params: List[str]) -> str:
        if not url or not params:
            return url

        parsed = urlparse(url)
        if f"{params[0]}=" in parsed.query:
            return url

        query = f"{parsed.query}&{params[0]}=" if parsed.query else f"{params[0]}="
        return urlunparse(parsed._replace(query=query))

    def _infer_cwe_from_endpoint(
        self, endpoint: Dict[str, Any], tech_stack: List[str]
    ) -> Optional[str]:
        """Infer potential CWE from endpoint characteristics for template matching.

        VT-Spec R5 Scenario 5.2: Select templates based on endpoint characteristics.
        """
        del tech_stack

        url = endpoint.get("url", "").lower()
        method = endpoint.get("method", "GET").upper()
        params = [str(param).lower() for param in endpoint.get("params", [])]
        auth_required = endpoint.get("auth_required", False)

        search_params = {"q", "query", "search", "id", "name", "filter", "sort"}
        redirect_params = {"redirect", "next", "return"}

        # Auth bypass candidates (401/403 endpoints)
        if auth_required:
            return "CWE-862"

        # File-related endpoints → path traversal
        if any(kw in url for kw in ["/file", "/download", "/upload", "/export", "/import"]):
            if method == "POST" and "upload" in url:
                return "CWE-434"
            return "CWE-22"

        if any(param in search_params for param in params):
            return "CWE-89"

        if any(kw in url for kw in ["search", "find"]):
            return "CWE-89"

        if "url" in params:
            return "CWE-918"

        if any(param in redirect_params for param in params):
            return "CWE-601"

        # Login/auth endpoints → auth bypass
        if any(kw in url for kw in ["/login", "/auth", "/signin"]):
            return "CWE-287"

        # API endpoints with POST → business logic / CORS
        if method == "POST" and any(kw in url for kw in ["/api/", "/rest/"]):
            return "CWE-1236"

        # Any API endpoint without params → CORS check
        if any(kw in url for kw in ["/api/", "/rest/"]):
            return "CWE-942"

        return None

    async def _role_code_audit(self, worker: AgentWorker) -> Dict[str, Any]:
        """Code audit agent — analyzes repos for vuln patterns."""
        from erebos.exploits.repo_analyzer import RepoAnalyzer

        if not self._config.repos:
            self._bus.publish(
                AgentMessage(
                    id=f"{worker.id}-code-audit",
                    role=AgentRole.CODE_AUDIT,
                    message_type="status",
                    payload={"phase": "code-audit", "status": "no_repos"},
                )
            )
            return {"role": "code-audit", "findings": 0, "status": "no_repos"}

        analyzer = RepoAnalyzer(repo_paths=self._config.repos)
        # Broad search for auth gaps and common vuln patterns
        context_list = analyzer.analyze_for_finding(
            keywords=["auth", "password", "token", "sql", "exec", "eval"]
        )
        total_findings = 0
        for ctx in context_list:
            severity = "HIGH" if ctx.auth_required is False else "MEDIUM"
            cwe = "CWE-306" if ctx.auth_required is False else "CWE-200"
            self._bus.publish(
                AgentMessage(
                    id=f"{worker.id}-code-{total_findings}",
                    role=AgentRole.CODE_AUDIT,
                    message_type="finding",
                    payload={
                        "title": f"Code pattern: {ctx.route or ctx.file_path}",
                        "target": ctx.route or str(ctx.file_path),
                        "severity": severity,
                        "cwe": cwe,
                        "file_path": str(ctx.file_path),
                        "auth_required": ctx.auth_required,
                    },
                )
            )
            total_findings += 1

        worker.findings_count = total_findings
        return {"role": "code-audit", "findings": total_findings}

    async def _role_reporter(self, worker: AgentWorker) -> Dict[str, Any]:
        """Reporter agent — correlates and aggregates final report."""
        from erebos.agents.correlation import CorrelationEngine
        from erebos.agents.roles.reporter import ReporterRole

        # VT-Spec R5: Sequential pipeline ensures all prior stages complete before reporter
        # No sleep needed — reporter stage runs after all prior stages finish.

        # Run correlation engine before reporting
        correlation = CorrelationEngine(self._bus)
        correlated = correlation.correlate()
        correlation.publish_results(correlated)

        # Compute fleet metadata for report header
        other_workers = [w for w in self._workers if w.role != AgentRole.REPORTER]
        fleet_start = min((w.started_at for w in other_workers if w.started_at), default=None)
        fleet_end = max((w.completed_at for w in other_workers if w.completed_at), default=None)
        duration_ms = 0.0
        if fleet_start and fleet_end:
            duration_ms = (fleet_end - fleet_start).total_seconds() * 1000

        fleet_metadata = {
            "duration_ms": duration_ms,
            "agents_completed": sum(1 for w in other_workers if w.status == AgentStatus.COMPLETED),
            "agents_failed": sum(1 for w in other_workers if w.status == AgentStatus.FAILED),
        }

        # Generate report with correlation data
        # VT-Spec R6: Pass report format from config
        # VT-Spec INJ-03: Pass redact_paths flag
        role = ReporterRole(
            bus=self._bus,
            agent_id=worker.id,
            target=self._config.target,
            fleet_id=self._fleet_id,
            report_format=self._config.report_format,
            redact_paths=self._config.redact_paths,
            fleet_metadata=fleet_metadata,
        )
        result = await role.execute(correlated=correlated)
        result["correlated_findings"] = len(correlated)
        result["top_priority"] = correlated[0].priority_score if correlated else 0
        worker.findings_count = result.get("total_findings", 0)
        return result

    async def _run_reason_cycle(self) -> Optional[Dict[str, Any]]:
        """Run one cycle of the Reason Loop (if FactGraph is available).

        Called after each agent completes. Returns intents for next actions.
        """
        if not hasattr(self, "_reason_loop") or self._reason_loop is None:
            return None

        if not self._reason_loop.should_continue:
            return cast(Dict[str, Any], self._reason_loop.conclude())

        intents = await self._reason_loop.reason()
        if not intents:
            return None

        from erebos.agents.reason import IntentDispatcher

        dispatcher = IntentDispatcher(
            allowlist=self._config.allowlist,
            fact_graph=self._bus.graph,
        )
        valid_intents = dispatcher.validate_and_dispatch(intents)

        if dispatcher.rejected_count > 0:
            self._log_action(
                "INTENTS_REJECTED",
                f"Rejected {dispatcher.rejected_count} out-of-scope intents",
            )

        return {
            "valid_intents": len(valid_intents),
            "rejected_intents": dispatcher.rejected_count,
            "intents": [
                {"action": intent.action.value, "target": intent.target} for intent in valid_intents
            ],
        }

    async def _run_dast_phase(self, worker: AgentWorker, exploit_result: Dict[str, Any]) -> int:
        """VT-Spec R2/R10: Run DAST templates after standard exploit phase.

        VT-Spec DOS-01: DAST shares budget with main exploit phase.
        VT-Spec INJ-02: Templates validated through sandbox before execution.
        """
        try:
            from erebos.exploits.dast.executor import DastExecutor, MAX_TOTAL_DAST_REQUESTS

            # Search for templates in priority order: repo-bundled, project CWD, Docker, user-installed
            repo_root = Path(__file__).resolve().parent.parent.parent
            candidate_paths = [
                repo_root / "templates" / "nuclei" / "dast" / "vulnerabilities",
                Path("./templates/nuclei/dast/vulnerabilities"),
                Path("/app/templates/nuclei/dast/vulnerabilities"),
                Path.home() / ".erebos/templates/dast/vulnerabilities",
            ]
            templates_dir = next((p for p in candidate_paths if p.exists()), None)
            if templates_dir is None:
                self._log_action("DAST_SKIP", "No DAST templates directory found")
                return 0

            # VT-Spec DOS-01: Remaining budget after exploit phase
            budget_used = exploit_result.get("budget_used", 0)
            remaining_budget = max(0, MAX_TOTAL_DAST_REQUESTS - budget_used)
            if remaining_budget == 0:
                self._log_action("DAST_SKIP", "DOS-01: Budget exhausted by exploit phase")
                return 0

            # Gather discovered endpoints from bus
            targets = self._gather_dast_targets()
            if not targets:
                self._log_action("DAST_SKIP", "No discovered endpoints for DAST")
                return 0

            # Create scoped HTTP client for DAST requests
            from erebos.security.scoped_client import ScopedHttpClient

            auth_headers = self._gather_dast_auth_headers()
            async with ScopedHttpClient(
                allowlist=self._config.allowlist,
                timeout=10.0,
                default_headers=auth_headers,
            ) as http_client:
                executor = DastExecutor(
                    http_client=http_client,
                    budget=remaining_budget,
                    allowlist=self._config.allowlist,
                    default_headers=auth_headers,
                    dast_mode=True,
                )
                findings = await executor.execute_all(templates_dir, targets)

            # Publish DAST findings to bus
            for idx, finding in enumerate(findings):
                self._bus.publish(
                    AgentMessage(
                        id=f"{worker.id}-dast-{idx}",
                        role=AgentRole.EXPLOIT,
                        message_type="finding",
                        payload=finding.model_dump(mode="json"),
                    )
                )

            self._log_action("DAST_COMPLETE", f"DAST found {len(findings)} vulnerabilities")
            return len(findings)

        except (ImportError, FileNotFoundError, OSError) as e:
            self._log_action("DAST_ERROR", f"DAST execution failed: {e}")
            return 0

    def _gather_dast_targets(self) -> List[str]:
        """Gather discovered endpoint URLs for DAST scanning."""
        targets: List[str] = []
        seen: set = set()

        # Get from web discovery attack surface
        for msg in self._bus.subscribe(
            roles=[AgentRole.WEB_DISCOVERY],
            message_types=["attack_surface"],
        ):
            for ep in msg.payload.get("endpoints", []):
                url = ep.get("url", "")
                if url and url not in seen:
                    seen.add(url)
                    targets.append(url)

        # Also add the primary target
        if self._config.target not in seen:
            target_url = self._config.target
            if not target_url.startswith("http"):
                target_url = f"https://{target_url}"
            targets.append(target_url)

        return targets[:200]  # DOS-01: Cap targets

    async def _run_infra_scan(self, worker: AgentWorker) -> int:
        """VT-Spec R4: Run infrastructure scanning for non-HTTP services.

        Checks recon results for non-HTTP ports and runs network templates.
        VT-Spec DOS-01: Budget-aware execution.
        """
        try:
            from erebos.scanners.infra_scanner import InfraScanner

            # Gather non-HTTP services from recon findings
            services = self._gather_non_http_services()
            if not services:
                return 0

            scanner = InfraScanner()
            findings = await scanner.scan(services, execute_probes=True)

            # Publish infra findings to bus
            for idx, finding in enumerate(findings):
                self._bus.publish(
                    AgentMessage(
                        id=f"{worker.id}-infra-{idx}",
                        role=AgentRole.VULN_SCAN,
                        message_type="finding",
                        payload=finding.model_dump(mode="json"),
                    )
                )

            self._log_action("INFRA_SCAN_COMPLETE", f"Found {len(findings)} infra vulnerabilities")
            return len(findings)

        except (ImportError, FileNotFoundError, OSError) as e:
            self._log_action("INFRA_SCAN_ERROR", f"Infra scan failed: {e}")
            return 0

    def _gather_non_http_services(self) -> List[Any]:
        """Gather non-HTTP services detected during recon phase."""
        from erebos.scanners.service_matcher import ServiceInfo

        services: List[ServiceInfo] = []
        http_ports = {80, 443, 8080, 8443, 8000, 8888}

        for msg in self._bus.subscribe(
            roles=[AgentRole.RECON],
            message_types=["finding"],
        ):
            payload = msg.payload
            port = payload.get("port")
            if port and int(port) not in http_ports:
                service = payload.get("service", "unknown")
                version = payload.get("version", "")
                host = payload.get("target", self._config.target)
                try:
                    services.append(
                        ServiceInfo(
                            host=host,
                            port=int(port),
                            protocol="tcp",
                            service=service,
                            version=version,
                        )
                    )
                except (ValueError, TypeError):
                    continue

        return services

    def _build_llm_cascade(self):
        """Create an LLM cascade for exploit planning when provider credentials exist.

        In MCP mode or when running inside a host coding agent, skip internal cascade —
        the host agent IS the LLM.
        """
        import os

        if self._config.mcp_mode or self._is_hosted_by_coding_agent():
            return None

        from erebos.config.settings import get_settings
        from erebos.exploits.llm_cascade import (
            ClaudeProvider,
            CopilotProvider,
            DeepSeekProvider,
            LLMCascade,
            OpenRouterProvider,
        )
        from erebos.exploits.sanitizer import PromptSanitizer

        settings = get_settings()
        env_map = {
            "copilot": "GITHUB_COPILOT_API_KEY",
            "claude": "ANTHROPIC_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
        }
        provider_factories = {
            "copilot": CopilotProvider,
            "claude": ClaudeProvider,
            "openrouter": OpenRouterProvider,
            "deepseek": DeepSeekProvider,
        }

        providers = []
        for provider_config in settings.exploitation.llm_cascade:
            api_key = os.environ.get(env_map[provider_config.provider], "")
            if not api_key:
                # Auto-resolve Copilot from gh CLI session
                if provider_config.provider == "copilot":
                    try:
                        provider = CopilotProvider.from_gh_session(
                            model=provider_config.model,
                            rate_limit=provider_config.rate_limit,
                        )
                        providers.append(provider)
                    except Exception:
                        pass  # gh not available or not logged in
                continue
            provider_cls = provider_factories[provider_config.provider]
            providers.append(
                provider_cls(
                    api_key=api_key,
                    model=provider_config.model,
                    rate_limit=provider_config.rate_limit,
                )
            )

        if not providers:
            return None

        return LLMCascade(
            providers=providers,
            sanitizer=PromptSanitizer(settings.exploitation.redact_patterns),
        )

    @staticmethod
    def _is_hosted_by_coding_agent() -> bool:
        """Detect if running inside a host coding agent (Copilot CLI, Claude Code, etc.)."""
        import os

        # Known coding agent environment markers
        agent_markers = [
            "COPILOT_CLI",           # GitHub Copilot CLI
            "COPILOT_AGENT_SESSION_ID",  # Copilot agent session
            "CLAUDE_CODE",           # Claude Code
            "CURSOR_SESSION_ID",     # Cursor IDE agent
            "AIDER_SESSION",         # Aider
            "CLINE_SESSION",         # Cline
        ]
        return any(os.environ.get(var) for var in agent_markers)

    def _build_tool_executor(self):  # -> ToolExecutor
        """Create a ToolExecutor with fleet allowlist."""
        from erebos.agents.tool_executor import ToolExecutor

        return ToolExecutor(allowlist=self._config.allowlist)

    def _find_tool_binary(self, tool_name: str) -> Optional[str]:
        """Find tool binary, preferring Go binaries over Python packages.

        ProjectDiscovery tools (httpx, nuclei, subfinder, etc.) are Go binaries
        commonly installed in ~/go/bin or /opt/homebrew/bin. Python packages like
        the 'httpx' library also install CLI scripts that shadow the Go binaries.
        This method checks known Go paths first.
        """
        import shutil

        # Priority paths for Go-based security tools
        go_tools = {
            "httpx",
            "subfinder",
            "nuclei",
            "naabu",
            "katana",
            "dnsx",
            "assetfinder",
            "gau",
            "waybackurls",
            "gobuster",
            "ffuf",
        }
        priority_paths = [
            Path.home() / "go" / "bin" / tool_name,
            Path("/opt/homebrew/bin") / tool_name,
            Path("/usr/local/bin") / tool_name,
        ]

        if tool_name in go_tools:
            for p in priority_paths:
                if p.exists() and p.is_file():
                    return str(p)

        # Fallback to PATH
        return shutil.which(tool_name)

    def _build_summary(self, results: List[Any]) -> Dict[str, Any]:
        """Build fleet execution summary."""
        duration_ms = 0.0
        if self._started_at:
            duration_ms = (datetime.now(timezone.utc) - self._started_at).total_seconds() * 1000

        return {
            "fleet_id": self._fleet_id,
            "target": self._config.target,
            "duration_ms": duration_ms,
            "agents": len(self._workers),
            "completed": sum(1 for w in self._workers if w.status == AgentStatus.COMPLETED),
            "failed": sum(1 for w in self._workers if w.status == AgentStatus.FAILED),
            "total_findings": self._bus.count("finding"),
            "workers": [
                {
                    "id": w.id,
                    "role": w.role.value,
                    "status": w.status.value,
                    "findings": w.findings_count,
                }
                for w in self._workers
            ],
        }

    def _log_action(self, action: str, detail: str) -> None:
        """VT-Spec RE-001: Log all fleet actions with integrity hash chain."""
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = f"{timestamp} | {action} | {self._fleet_id} | {detail}"
        # Chain hash for tamper detection (AC-005)
        self._log_chain_hash = hashlib.sha256(
            f"{self._log_chain_hash}:{entry}".encode()
        ).hexdigest()
        logger.info(f"[FLEET] {entry} | hash={self._log_chain_hash[:12]}")

    async def _acquire_rate_token(self) -> None:
        """VT-Spec DS-001: Token bucket rate limiter for fleet operations."""
        while True:
            now = datetime.now(timezone.utc)
            elapsed = (now - self._rate_last_refill).total_seconds()
            # Refill tokens based on elapsed time
            refill = int(elapsed * (self._rate_max / 60.0))
            if refill > 0:
                self._rate_tokens = min(self._rate_max, self._rate_tokens + refill)
                self._rate_last_refill = now

            if self._rate_tokens > 0:
                self._rate_tokens -= 1
                return

            # Wait for a token to become available
            await asyncio.sleep(1.0)

    @property
    def log_integrity_hash(self) -> str:
        """Return current log chain hash for verification."""
        return self._log_chain_hash
