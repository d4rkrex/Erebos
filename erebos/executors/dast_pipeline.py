"""DAST Pipeline — orchestrates fast scan → nuclei → LLM-adaptive exploitation.

Modes:
  fast   — DastInjectionExecutor only (pattern matching, auth bypass, traversal)
  nuclei — DastExecutor with nuclei templates (237 templates)
  deep   — ExploitRole + LLMCascade (iterative, LLM-driven adaptation)
  full   — fast → API security (with chained auth) → nuclei → deep

Attack chaining:
  - Auth bypass findings from fast scan → extract token → pass to API security
  - All findings from fast/nuclei → feed into ExploitRole for adaptive exploitation
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from erebos.core.finding import Finding
from erebos.executors.api_security import ApiSecurityExecutor
from erebos.executors.dast_injection import DastInjectionExecutor, DastMode, InjectionType

logger = logging.getLogger(__name__)

# DoS-01: Cap recon URLs to prevent resource exhaustion
_MAX_RECON_URLS = 50


class DastPipeline:
    """Orchestrates multi-stage DAST scanning with attack chaining.

    The pipeline feeds findings from each stage into the next:
    1. Fast scan: pattern matching, auth bypass, path traversal
    2. API security: IDOR, mass assignment, GraphQL (uses token from stage 1)
    3. Nuclei templates: 237 DAST-specific templates via DastExecutor
    4. Deep exploitation: LLM-adaptive via ExploitRole (if configured)
    """

    # VT-Spec DoS-01: API-like path patterns for endpoint filtering
    _API_PATH_PATTERNS = re.compile(r"/(api|rest|v[0-9]+|graphql)/", re.IGNORECASE)

    def __init__(
        self,
        mode: str = DastMode.FULL,
        timeout: float = 10.0,
        max_concurrent: int = 5,
        login_endpoints: Optional[List[str]] = None,
        api_endpoints: Optional[List[str]] = None,
        traversal_paths: Optional[List[str]] = None,
        recon_urls: Optional[List[str]] = None,
    ):
        self.mode = mode
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.login_endpoints = login_endpoints
        self.api_endpoints = api_endpoints
        self.traversal_paths = traversal_paths
        self._extracted_tokens: List[str] = []
        # VT-Spec DoS-01: Cap recon_urls to prevent resource exhaustion
        self.recon_urls: List[str] = (recon_urls or [])[:_MAX_RECON_URLS]

    async def run(
        self,
        target: str,
        parameters: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute the DAST pipeline against target.

        Returns dict with findings per stage + summary.
        """
        results: Dict[str, Any] = {
            "target": target,
            "mode": self.mode,
            "stages": {},
            "findings": [],
            "tokens_extracted": 0,
            "total_findings": 0,
        }

        # Stage 1: Fast scan (always runs unless mode=nuclei or mode=deep)
        if self.mode in (DastMode.FAST, DastMode.FULL):
            fast_findings = await self._stage_fast(target, parameters)
            results["stages"]["fast"] = {
                "findings": len(fast_findings),
                "details": [f.title for f in fast_findings],
            }
            results["findings"].extend(fast_findings)

            # Extract tokens from auth bypass findings for chaining
            self._extract_tokens(fast_findings)
            results["tokens_extracted"] = len(self._extracted_tokens)

        # Stage 2: API Security (uses extracted tokens for deeper access)
        if self.mode in (DastMode.FAST, DastMode.FULL):
            api_findings = await self._stage_api_security(target)
            results["stages"]["api_security"] = {
                "findings": len(api_findings),
                "details": [f.title for f in api_findings],
            }
            results["findings"].extend(api_findings)

        # Stage 3: Nuclei templates
        if self.mode in (DastMode.NUCLEI, DastMode.FULL):
            nuclei_findings = await self._stage_nuclei(target)
            results["stages"]["nuclei"] = {
                "findings": len(nuclei_findings),
                "details": [f.title for f in nuclei_findings],
            }
            results["findings"].extend(nuclei_findings)

        # Stage 4: Deep exploitation (LLM-driven)
        if self.mode in (DastMode.DEEP, DastMode.FULL):
            deep_findings = await self._stage_deep(target, results["findings"])
            results["stages"]["deep"] = {
                "findings": len(deep_findings),
                "details": [f.title for f in deep_findings],
            }
            results["findings"].extend(deep_findings)

        results["total_findings"] = len(results["findings"])

        # Dedup findings across stages (same vuln type + same endpoint = 1 finding)
        results["findings"] = self._dedup_findings(results["findings"])
        results["total_findings"] = len(results["findings"])

        return results

    def _dedup_findings(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings using title+target hash.

        Keeps the first occurrence (usually from the earliest/fastest stage).
        """
        seen: set = set()
        unique: List[Finding] = []
        for f in findings:
            # Normalize key: lowercase title + target URL path
            key = f"{f.title.lower().strip()}|{(f.target or '').lower().strip()}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
            else:
                logger.debug("[DAST:dedup] Duplicate removed: %s", f.title)
        if len(findings) != len(unique):
            logger.info(
                "[DAST:dedup] Removed %d duplicates (%d → %d)",
                len(findings) - len(unique),
                len(findings),
                len(unique),
            )
        return unique

    async def _stage_fast(
        self, target: str, parameters: Optional[List[str]]
    ) -> List[Finding]:
        """Stage 1: Fast pattern-matching scan with auth bypass and traversal."""
        logger.info("[DAST:fast] Starting injection scan against %s", target)

        # VT-Spec: Extract query parameters from recon URLs as injection targets
        recon_params = self._extract_params_from_urls(self.recon_urls)
        if recon_params:
            logger.info("[DAST:fast] Extracted %d params from recon URLs", len(recon_params))
            # Merge with explicitly provided parameters (explicit params take priority)
            if parameters:
                merged = list(set(parameters + recon_params))
            else:
                merged = recon_params
            parameters = merged

        executor = DastInjectionExecutor(
            timeout=self.timeout,
            max_concurrent=self.max_concurrent,
            injection_types=[
                InjectionType.SQLI,
                InjectionType.XSS,
                InjectionType.TRAVERSAL,
                InjectionType.CMDI,
                InjectionType.AUTH_BYPASS,
            ],
        )

        findings = await executor.run(
            target=target,
            parameters=parameters,
            login_endpoints=self.login_endpoints,
            traversal_paths=self.traversal_paths,
        )

        logger.info("[DAST:fast] Found %d findings", len(findings))
        return findings

    async def _stage_api_security(self, target: str) -> List[Finding]:
        """Stage 2: API security tests with chained auth from stage 1."""
        logger.info("[DAST:api] Starting API security scan (tokens: %d)", len(self._extracted_tokens))

        token = self._extracted_tokens[0] if self._extracted_tokens else None

        executor = ApiSecurityExecutor(
            timeout=self.timeout,
            max_concurrent=self.max_concurrent,
            auth_token=token,
        )

        # Use provided endpoints, recon-discovered API paths, or smart defaults
        api_base = target.rstrip("/")
        endpoints = self.api_endpoints
        if not endpoints and self.recon_urls:
            # VT-Spec: Filter recon URLs for API-like paths
            api_urls = [
                urlparse(u).path
                for u in self.recon_urls
                if self._API_PATH_PATTERNS.search(u)
            ]
            if api_urls:
                # Deduplicate paths
                endpoints = list(dict.fromkeys(api_urls))
                logger.info(
                    "[DAST:api] Using %d API endpoints from recon", len(endpoints)
                )
        if not endpoints:
            endpoints = [
                "/Products/1",
                "/Products/2",
                "/Users/1",
                "/Users/2",
                "/Feedbacks",
                "/BasketItems/1",
            ]

        findings = await executor.run(
            target=f"{api_base}/api",
            endpoints=endpoints,
            tests=["idor", "mass_assignment", "rate_limit", "graphql"],
            auth_token=token,
        )

        logger.info("[DAST:api] Found %d findings", len(findings))
        return findings

    async def _stage_nuclei(self, target: str) -> List[Finding]:
        """Stage 3: Nuclei DAST templates (249 templates) via DastExecutor + httpx."""
        from pathlib import Path

        logger.info("[DAST:nuclei] Starting nuclei template scan against %s", target)

        # VT-Spec: Resolve templates reliably regardless of CWD
        repo_root = Path(__file__).resolve().parent.parent.parent
        templates_dir = repo_root / "templates" / "nuclei" / "dast" / "vulnerabilities"
        if not templates_dir.exists():
            # Fallback: relative to CWD (legacy behavior)
            templates_dir = Path("templates/nuclei/dast/vulnerabilities")
            if not templates_dir.exists():
                logger.warning("[DAST:nuclei] Templates directory not found, skipping")
                return []

        try:
            import httpx
            from urllib.parse import urlparse as _urlparse

            from erebos.exploits.dast.executor import DastExecutor

            # Extract hostname for allowlist (DastExecutor checks hostname, not full URL)
            parsed_target = _urlparse(target)
            allowlist_host = parsed_target.hostname or target

            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "Erebos-DAST/1.0"},
            ) as client:
                executor = DastExecutor(
                    http_client=client,
                    budget=500,  # Conservative budget per scan
                    allowlist=[allowlist_host],
                    dast_mode=True,  # Relax sandbox for legitimate DAST fuzzing
                )
                # VT-Spec: Use recon URLs as additional nuclei targets (scope-checked)
                nuclei_targets = [target]
                if self.recon_urls:
                    for url in self.recon_urls:
                        parsed_url = _urlparse(url)
                        if parsed_url.hostname == allowlist_host and url not in nuclei_targets:
                            nuclei_targets.append(url)
                    logger.info(
                        "[DAST:nuclei] Scanning %d targets (1 base + %d from recon)",
                        len(nuclei_targets),
                        len(nuclei_targets) - 1,
                    )
                findings = await executor.execute_all(templates_dir, nuclei_targets)

            logger.info(
                "[DAST:nuclei] Found %d findings (%d requests made)",
                len(findings),
                executor.requests_made,
            )
            return findings

        except ImportError as e:
            logger.warning("[DAST:nuclei] Missing dependency: %s", e)
            return []
        except Exception as e:
            logger.error("[DAST:nuclei] Execution failed: %s", e, exc_info=True)
            return []

    async def _stage_deep(self, target: str, prior_findings: List[Finding]) -> List[Finding]:
        """Stage 4: LLM-adaptive exploitation via ExploitRole.

        Takes all prior findings and feeds them to the ReasonLoop for
        intelligent exploitation with attack chaining.
        Requires LLMCascade configuration (API keys).
        """
        logger.info(
            "[DAST:deep] LLM exploitation — %d prior findings to exploit",
            len(prior_findings),
        )

        if not prior_findings:
            logger.info("[DAST:deep] No prior findings to exploit, skipping")
            return []

        try:
            from erebos.agents.base import FindingsBus
            from erebos.agents.roles.exploit import ExploitRole
            from erebos.config.settings import get_settings
            from erebos.exploits.llm_cascade import LLMCascade
            from erebos.exploits.runner import ExploitRunner
            from erebos.exploits.template_engine import TemplateEngine

            # Lazy import playbook registry to avoid circular imports
            try:
                from erebos.exploits.playbooks.registry import get_default_registry

                playbook_registry = get_default_registry()
            except ImportError:
                playbook_registry = None

            settings = get_settings()

            # Check if LLM provider is configured
            providers = []
            if hasattr(settings, "ai") and hasattr(settings.ai, "providers"):
                providers = settings.ai.providers or []
            if not providers:
                # Check env for common API keys
                import os

                has_key = any(
                    os.environ.get(k)
                    for k in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY"]
                )
                if not has_key:
                    logger.info(
                        "[DAST:deep] No LLM provider configured (set OPENAI_API_KEY, "
                        "ANTHROPIC_API_KEY, or OPENROUTER_API_KEY). Skipping."
                    )
                    return []

            # Initialize components
            bus = FindingsBus()
            cascade = LLMCascade(playbook_registry=playbook_registry)
            runner = ExploitRunner(
                allowlist=[target],
                global_budget=200,
            )
            template_engine = TemplateEngine()

            exploit_role = ExploitRole(
                runner=runner,
                template_engine=template_engine,
                bus=bus,
                agent_id="dast-deep",
                allowlist=[target],
                max_exploits=10,
                llm_cascade=cascade,
                global_request_budget=200,
            )

            # Feed prior findings into exploit role
            new_findings: List[Finding] = []
            for finding in prior_findings[:5]:  # Limit to top 5 to avoid budget exhaustion
                try:
                    result = await exploit_role.exploit_finding(finding)
                    if result and result.status.value == "confirmed":
                        new_findings.append(finding)  # Mark as confirmed
                except Exception as e:
                    logger.debug("[DAST:deep] Exploit attempt failed for %s: %s", finding.title, e)

            logger.info("[DAST:deep] Confirmed %d findings via LLM exploitation", len(new_findings))
            return new_findings

        except ImportError as e:
            logger.warning("[DAST:deep] Missing dependency for LLM exploitation: %s", e)
            return []
        except Exception as e:
            logger.error("[DAST:deep] LLM exploitation failed: %s", e, exc_info=True)
            return []

    def _extract_params_from_urls(self, urls: List[str]) -> List[str]:
        """Extract unique query parameter names from URLs for injection testing.

        VT-Spec: Parses recon-discovered URLs and returns parameter names
        that can be used as injection targets in the fast scan stage.
        """
        params: set = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                params.update(query_params.keys())
            except Exception:
                logger.debug("[DAST:params] Failed to parse URL: %s", url)
                continue
        result = sorted(params)
        if result:
            logger.debug("[DAST:params] Extracted parameters: %s", result)
        return result

    def _extract_tokens(self, findings: List[Finding]) -> None:
        """Extract auth tokens from auth bypass findings for chaining."""
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

        for finding in findings:
            if not finding.evidence or not finding.evidence.output:
                continue
            matches = jwt_pattern.findall(finding.evidence.output)
            for token in matches:
                if token not in self._extracted_tokens:
                    self._extracted_tokens.append(token)
                    logger.info("[DAST:chain] Extracted JWT from %s", finding.title)
