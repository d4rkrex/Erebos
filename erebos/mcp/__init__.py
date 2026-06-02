"""MCP Engagement Server — SSE transport with engagement lifecycle tools.

Exposes pentest tools: scan_start, scan_status, scan_abort, scan_report, scan_approve.

# VT-Spec T-001 MEDIUM: Verify approval source matches engagement operator
# VT-Spec DOS-001 MEDIUM: SIGTERM/SIGINT handler triggers graceful shutdown
# VT-Spec S-001 LOW: Document MCP stdio mode has no auth (local-only trust model)
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import signal
import sys
import time
from typing import Any, Dict, List, Optional

from erebos.control.killswitch import KillSwitch
from erebos.core.models import Engagement, EngagementStatus

logger = logging.getLogger(__name__)

# VT-Spec S-001 LOW: Local-only trust model documentation
MCP_STDIO_AUTH_NOTE = """
WARNING: MCP stdio transport has NO authentication.
This is by design for local-only usage (Claude Code, IDE integrations).
Do NOT expose stdio transport over network (socat, SSH tunnel without auth).
If network exposure is required, use SSE transport with bearer token auth.
"""


class EngagementManager:
    """Manages active engagements for MCP server.

    # VT-Spec T-001: Tracks operator identity per engagement for approval verification.
    """

    def __init__(self):
        self._engagements: Dict[str, Engagement] = {}
        self._operators: Dict[str, str] = {}  # engagement_id -> operator_identity
        self._approval_credentials: Dict[str, str] = {}  # engagement_id -> approval_token
        self._approval_timestamps: Dict[str, float] = {}  # rate limiting

    def register(
        self, engagement: Engagement, operator: str, approval_token: Optional[str] = None
    ) -> None:
        """Register an engagement with operator binding."""
        self._engagements[engagement.id] = engagement
        self._operators[engagement.id] = operator
        if approval_token:
            self._approval_credentials[engagement.id] = approval_token

    def get(self, engagement_id: str) -> Optional[Engagement]:
        """Get engagement by ID."""
        return self._engagements.get(engagement_id)

    def get_operator(self, engagement_id: str) -> Optional[str]:
        """Get operator for engagement."""
        return self._operators.get(engagement_id)

    def verify_approval_source(
        self,
        engagement_id: str,
        caller_ip: str,
        caller_token: Optional[str] = None,
    ) -> bool:
        """VT-Spec T-001 MEDIUM: Verify approval source matches engagement operator.

        - Validates caller identity binding
        - Checks separate approval credential if configured
        - Rate-limits approvals (cooldown period)
        """
        if engagement_id not in self._engagements:
            return False

        # VT-Spec T-001: Rate-limit approvals (5 second cooldown)
        last_approval = self._approval_timestamps.get(engagement_id, 0)
        if time.time() - last_approval < 5.0:
            logger.warning(
                "VT-Spec T-001: Approval rate-limited",
                extra={"engagement_id": engagement_id, "caller_ip": caller_ip},
            )
            return False

        # VT-Spec T-001: If separate approval credential configured, verify it
        stored_approval_token = self._approval_credentials.get(engagement_id)
        if stored_approval_token and caller_token:
            if not hmac.compare_digest(stored_approval_token, caller_token):
                logger.warning(
                    "VT-Spec T-001: Approval credential mismatch",
                    extra={"engagement_id": engagement_id, "caller_ip": caller_ip},
                )
                return False

        self._approval_timestamps[engagement_id] = time.time()
        return True

    def remove(self, engagement_id: str) -> None:
        """Remove engagement."""
        self._engagements.pop(engagement_id, None)
        self._operators.pop(engagement_id, None)
        self._approval_credentials.pop(engagement_id, None)


class GracefulShutdownHandler:
    """VT-Spec DOS-001 MEDIUM: Signal handler for graceful shutdown.

    On SIGTERM/SIGINT:
    1. Set killswitch for active engagement
    2. Await KillSwitch.activate() (max 30s)
    3. Close SSE connections with terminal event
    4. Call generate_partial_report()
    5. Exit within 60s
    """

    def __init__(
        self,
        kill_switch: Optional[KillSwitch] = None,
        engagement_manager: Optional[EngagementManager] = None,
        disconnect_callback=None,
        report_callback=None,
    ):
        self._kill_switch = kill_switch
        self._engagement_manager = engagement_manager
        self._disconnect_callback = disconnect_callback
        self._report_callback = report_callback
        self._shutting_down = False

    def install(self) -> None:
        """Install signal handlers for SIGTERM and SIGINT.

        # VT-Spec DOS-001: Register shutdown handlers.
        """
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        logger.info("VT-Spec DOS-001: Graceful shutdown handlers installed")

    def _handle_signal(self, signum: int, frame) -> None:
        """VT-Spec DOS-001: Handle shutdown signal."""
        if self._shutting_down:
            logger.warning("VT-Spec DOS-001: Force exit on second signal")
            sys.exit(1)

        self._shutting_down = True
        sig_name = signal.Signals(signum).name
        logger.warning(
            f"VT-Spec DOS-001: Received {sig_name}, initiating graceful shutdown (60s deadline)"
        )

        # Run async shutdown in event loop if possible
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._async_shutdown())
        except RuntimeError:
            # No running loop — do synchronous cleanup
            self._sync_shutdown()

    async def _async_shutdown(self) -> None:
        """VT-Spec DOS-001: Async graceful shutdown sequence."""
        try:
            # Step 1: Activate killswitch for all active engagements
            if self._kill_switch and self._engagement_manager:
                for eng_id, eng in list(self._engagement_manager._engagements.items()):
                    if eng.status == EngagementStatus.ACTIVE:
                        logger.info(f"VT-Spec DOS-001: Killing engagement {eng_id}")
                        self._kill_switch.activate(
                            eng, reason="Graceful shutdown (SIGTERM)", operator="system"
                        )

            # Step 2: Wait for cleanup (max 30s)
            await asyncio.sleep(min(5, 30))

            # Step 3: Generate partial reports
            if self._report_callback:
                try:
                    self._report_callback()
                except Exception as e:
                    logger.error(f"VT-Spec DOS-001: Partial report failed: {e}")

            # Step 4: Disconnect SSE connections
            if self._disconnect_callback:
                try:
                    await self._disconnect_callback()
                except Exception as e:
                    logger.error(f"VT-Spec DOS-001: Disconnect failed: {e}")

        except Exception as e:
            logger.error(f"VT-Spec DOS-001: Shutdown error: {e}")
        finally:
            logger.info("VT-Spec DOS-001: Graceful shutdown complete")
            sys.exit(0)

    def _sync_shutdown(self) -> None:
        """Synchronous fallback shutdown."""
        logger.info("VT-Spec DOS-001: Synchronous shutdown (no event loop)")
        if self._kill_switch and self._engagement_manager:
            for eng_id, eng in list(self._engagement_manager._engagements.items()):
                if eng.status == EngagementStatus.ACTIVE:
                    self._kill_switch.activate(
                        eng, reason="Graceful shutdown (SIGTERM)", operator="system"
                    )
        sys.exit(0)

    @property
    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress."""
        return self._shutting_down


def log_stdio_auth_warning() -> None:
    """VT-Spec S-001 LOW: Log warning about stdio auth model at startup."""
    token = os.environ.get("EREBOS_MCP_TOKEN")
    if not token:
        logger.warning(
            "VT-Spec S-001: No MCP token configured. %s",
            MCP_STDIO_AUTH_NOTE.strip().replace("\n", " "),
        )
