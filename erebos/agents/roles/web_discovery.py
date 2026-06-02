"""Web discovery agent role — attack surface enumeration and auth token acquisition.

VT-Spec R5 Scenario 5.1: Runs AFTER vuln-scan, BEFORE exploit.
VT-Spec R5 Scenario 5.4: Auth tokens passed to exploit agent via shared context bus.

Security mitigations:
- VT-Spec T-01: All requests go through ScopedHttpClient (allowlist enforced)
- VT-Spec D-01: SharedRateLimiter with circuit breaker
- VT-Spec I-01: Auth tokens stored in bus payload, not persisted to disk
- VT-Spec S-01: Redirect validation via ScopedHttpClient
- VT-Spec R-01: Chain-hashed audit logging inherited from WebDiscovery/AuthManager
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from erebos.agents.base import AgentMessage, AgentRole, FindingsBus
from erebos.exploits.auth_manager import AuthManager
from erebos.exploits.discovery import AttackSurface, WebDiscovery
from erebos.security.rate_limit import SharedRateLimiter
from erebos.security.scoped_client import ScopedHttpClient

logger = logging.getLogger(__name__)


class WebDiscoveryRole:
    """Web discovery agent — discovers attack surface and acquires auth tokens.

    VT-Spec R5 Scenario 5.1: Orchestrates WebDiscovery + AuthManager,
    publishes AttackSurface and auth tokens to the findings bus for
    consumption by the exploit role.
    """

    def __init__(
        self,
        bus: FindingsBus,
        agent_id: str,
        target: str,
        allowlist: Optional[List[str]] = None,
        rate_limiter: Optional[SharedRateLimiter] = None,
        audit_log: Optional[Path] = None,
        max_pages_to_crawl: int = 50,
        enable_auth: bool = True,
    ):
        """Initialize web discovery role.

        Args:
            bus: FindingsBus for inter-agent communication.
            agent_id: Unique agent identifier.
            target: Base URL of target (e.g., "http://target.local").
            allowlist: Allowed hostnames for scope enforcement.
            rate_limiter: SharedRateLimiter for D-01 compliance.
            audit_log: Path for chain-hashed audit logs (R-01).
            max_pages_to_crawl: Max pages for HTML crawling.
            enable_auth: Whether to run AuthManager for token acquisition.
        """
        self._bus = bus
        self._agent_id = agent_id
        # Normalize target to include scheme (ScopedHttpClient requires it)
        _t = target.rstrip("/")
        if not _t.startswith(("http://", "https://")):
            _t = f"https://{_t}"
        self._target = _t
        self._allowlist = [host.lower().strip() for host in (allowlist or [])]
        self._rate_limiter = rate_limiter
        self._audit_log = audit_log
        self._max_pages_to_crawl = max_pages_to_crawl
        self._enable_auth = enable_auth

    async def execute(self) -> Dict[str, Any]:
        """Run web discovery pipeline and publish results to bus.

        VT-Spec R5 Scenario 5.1: Instantiates WebDiscovery, runs discover(),
        stores AttackSurface in shared bus context.
        VT-Spec R5 Scenario 5.4: Runs AuthManager to get tokens.

        Returns:
            Dict with role execution summary.
        """
        results: Dict[str, Any] = {
            "role": "web-discovery",
            "endpoints_discovered": 0,
            "tech_stack": [],
            "auth_acquired": False,
            "auth_targets": [],
        }

        # VT-Spec T-01: All HTTP goes through ScopedHttpClient with allowlist
        # VT-Spec D-01: SharedRateLimiter passed to client for rate control
        async with ScopedHttpClient(
            allowlist=self._allowlist,
            rate_limiter=self._rate_limiter,
        ) as client:
            # --- Phase 1: Web Discovery ---
            discovery = WebDiscovery(
                target=self._target,
                client=client,
                rate_limiter=self._rate_limiter,
                audit_log=self._audit_log,
                max_pages_to_crawl=self._max_pages_to_crawl,
            )

            attack_surface = await discovery.discover()
            results["endpoints_discovered"] = len(attack_surface.endpoints)
            results["tech_stack"] = attack_surface.tech_stack

            # Publish AttackSurface to bus for exploit role consumption
            # VT-Spec R5 Scenario 5.2: Exploit agent reads this from bus
            self._publish_attack_surface(attack_surface)

        # --- Phase 2: Auth Token Acquisition ---
        # VT-Spec R5 Scenario 5.4: Auth tokens passed via shared context
        if self._enable_auth:
            auth_result = await self._acquire_auth_tokens()
            results["auth_acquired"] = auth_result.get("acquired", False)
            results["auth_targets"] = auth_result.get("targets", [])

        self._publish_summary(results)
        return results

    async def _acquire_auth_tokens(self) -> Dict[str, Any]:
        """Run AuthManager to acquire tokens for the target.

        VT-Spec R5 Scenario 5.4: Tokens stored in bus keyed by domain.
        VT-Spec I-02: Credentials generated per-scan, not persisted.
        VT-Spec S-01: Redirect validation handled by AuthManager internally.
        """
        result: Dict[str, Any] = {"acquired": False, "targets": []}

        auth_manager = AuthManager(
            allowlist=self._allowlist,
            audit_log=self._audit_log,
        )

        try:
            token = await auth_manager.get_token(self._target)
            if token:
                domain = self._extract_domain(self._target)
                result["acquired"] = True
                result["targets"].append(domain)

                # VT-Spec R5 Scenario 5.3: Publish auth token to bus
                # keyed by domain for exploit role consumption.
                # VT-Spec I-01: Token in memory only, bus is ephemeral.
                self._publish_auth_token(domain, token, auth_manager)
                logger.info(
                    "VT-Spec R5: Auth token acquired for %s", domain
                )
        except Exception as e:
            logger.warning(
                "Web discovery auth acquisition failed for %s: %s",
                self._target,
                e,
            )

        return result

    def _publish_attack_surface(self, surface: AttackSurface) -> None:
        """Publish the full AttackSurface to the bus for exploit role.

        VT-Spec R5 Scenario 5.2: Exploit agent receives discovery results.
        """
        self._bus.publish(
            AgentMessage(
                id=f"{self._agent_id}-attack-surface",
                role=AgentRole.WEB_DISCOVERY,
                message_type="attack_surface",
                payload=surface.model_dump(mode="json"),
            )
        )
        logger.info(
            "VT-Spec R5: Published AttackSurface with %d endpoints",
            len(surface.endpoints),
        )

    def _publish_auth_token(
        self, domain: str, token: str, auth_manager: AuthManager
    ) -> None:
        """Publish auth token to bus keyed by domain.

        VT-Spec R5 Scenario 5.3: Per-target token isolation.
        VT-Spec I-01: Tokens are ephemeral (bus cleared per scan).
        """
        # Get credentials email for variable injection
        state = auth_manager._auth_states.get(domain)
        email = state.credentials.email if state and state.credentials else ""
        user_id = state.user_id if state else ""
        token_type = state.token_type if state else "Bearer"
        session_cookies = state.session_cookies if state else {}

        self._bus.publish(
            AgentMessage(
                id=f"{self._agent_id}-auth-{domain}",
                role=AgentRole.WEB_DISCOVERY,
                message_type="auth_token",
                payload={
                    "domain": domain,
                    "auth_token": token,
                    "auth_email": email,
                    "auth_user_id": user_id or "",
                    "auth_token_type": token_type,
                    "auth_cookies": session_cookies,
                    "target": self._target,
                },
            )
        )

    def _publish_summary(self, results: Dict[str, Any]) -> None:
        """Publish execution summary to bus."""
        self._bus.publish(
            AgentMessage(
                id=f"{self._agent_id}-summary",
                role=AgentRole.WEB_DISCOVERY,
                message_type="result",
                payload=results,
            )
        )

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for per-target keying."""
        parsed = urlparse(url)
        return (parsed.hostname or "").lower().strip()
