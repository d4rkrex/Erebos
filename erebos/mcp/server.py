"""MCP SSE Server for engagement lifecycle tools.

Starlette app with SSE transport providing:
- scan_start, scan_status, scan_abort, scan_report, scan_approve tools
- Bearer token auth (constant-time comparison)
- Rate limiting (per-IP, per-token)
- IP allowlist
- Per-IP connection limits
- CORS deny-all
- Health endpoint: GET /health

# VT-Spec T-001 MEDIUM: scan_approve verifies approval source
# VT-Spec DOS-001 MEDIUM: Signal handler triggers graceful shutdown
# VT-Spec S-001 LOW: --require-auth flag for stdio mode
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from erebos.agents.mcp_sse import MCPSSEServer, create_sse_server_from_config
from erebos.config.profiles import ENGAGEMENT_PROFILES, get_profile
from erebos.mcp import (
    EngagementManager,
    GracefulShutdownHandler,
    log_stdio_auth_warning,
)

logger = logging.getLogger(__name__)


class EngagementMCPServer:
    """MCP server with engagement lifecycle tools.

    Tools exposed:
    - scan_start: Start new engagement
    - scan_status: Query engagement status
    - scan_abort: Abort engagement via killswitch
    - scan_report: Generate report for engagement
    - scan_approve: Approve pending action (with source verification)
    """

    def __init__(self, config: Any):
        self._config = config
        self._engagement_manager = EngagementManager()
        self._sse_server: Optional[MCPSSEServer] = None

    def create_server(self) -> MCPSSEServer:
        """Create and configure the SSE server.

        # VT-Spec S-001: Log auth warning at startup if no token.
        """
        log_stdio_auth_warning()
        self._sse_server = create_sse_server_from_config(self._config)
        return self._sse_server

    def handle_scan_start(
        self,
        target: str,
        profile: str = "full-pentest",
        roe_path: Optional[str] = None,
        operator: str = "mcp",
        approval_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Handle scan_start tool call.

        Returns engagement_id and status.
        """
        from erebos.core.models import Engagement, Target

        # Validate profile
        try:
            eng_profile = get_profile(profile)
        except ValueError as e:
            return {"error": str(e), "code": "INVALID_PROFILE"}

        # Create engagement
        engagement = Engagement(
            name=f"mcp-{target}-{profile}",
            targets=[Target(address=target)],
        )

        # VT-Spec T-001: Register with operator binding
        self._engagement_manager.register(
            engagement, operator=operator, approval_token=approval_token
        )

        logger.info(
            "Engagement created via MCP",
            extra={
                "engagement_id": engagement.id,
                "target": target,
                "profile": profile,
                "operator": operator,
            },
        )

        return {
            "engagement_id": engagement.id,
            "status": "created",
            "target": target,
            "profile": profile,
        }

    def handle_scan_status(self, engagement_id: str) -> Dict[str, Any]:
        """Handle scan_status tool call."""
        engagement = self._engagement_manager.get(engagement_id)
        if not engagement:
            return {"error": "ENGAGEMENT_NOT_FOUND", "code": "ENGAGEMENT_NOT_FOUND"}

        return {
            "engagement_id": engagement.id,
            "status": engagement.status.value,
            "phase": engagement.phase.value,
            "targets": [t.address for t in engagement.targets],
        }

    def handle_scan_abort(self, engagement_id: str) -> Dict[str, Any]:
        """Handle scan_abort tool call."""
        engagement = self._engagement_manager.get(engagement_id)
        if not engagement:
            return {"error": "ENGAGEMENT_NOT_FOUND", "code": "ENGAGEMENT_NOT_FOUND"}

        # Trigger abort
        engagement.status = EngagementStatus.ABORTED
        engagement.abort_reason = "Aborted via MCP"

        logger.info(f"Engagement aborted via MCP: {engagement_id}")

        return {
            "engagement_id": engagement_id,
            "status": "aborted",
            "message": "Engagement aborted. Cleanup initiated.",
        }

    def handle_scan_approve(
        self,
        engagement_id: str,
        action_id: str,
        caller_ip: str = "127.0.0.1",
        caller_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Handle scan_approve tool call.

        # VT-Spec T-001 MEDIUM: Verify approval source matches engagement operator.
        """
        engagement = self._engagement_manager.get(engagement_id)
        if not engagement:
            return {"error": "ENGAGEMENT_NOT_FOUND", "code": "ENGAGEMENT_NOT_FOUND"}

        # VT-Spec T-001: Verify approval source
        if not self._engagement_manager.verify_approval_source(
            engagement_id, caller_ip, caller_token
        ):
            logger.warning(
                "VT-Spec T-001: Approval source verification failed",
                extra={
                    "engagement_id": engagement_id,
                    "action_id": action_id,
                    "caller_ip": caller_ip,
                },
            )
            return {
                "error": "Approval source verification failed",
                "code": "APPROVAL_DENIED",
            }

        logger.info(
            "Action approved via MCP",
            extra={
                "engagement_id": engagement_id,
                "action_id": action_id,
                "caller_ip": caller_ip,
                "source": "mcp",
            },
        )

        return {
            "engagement_id": engagement_id,
            "action_id": action_id,
            "status": "approved",
            "source": "mcp",
        }

    def handle_scan_report(self, engagement_id: str, format: str = "markdown") -> Dict[str, Any]:
        """Handle scan_report tool call."""
        engagement = self._engagement_manager.get(engagement_id)
        if not engagement:
            return {"error": "ENGAGEMENT_NOT_FOUND", "code": "ENGAGEMENT_NOT_FOUND"}

        return {
            "engagement_id": engagement_id,
            "format": format,
            "status": "report_generated",
        }


# Import for type reference only
from erebos.core.models import EngagementStatus  # noqa: E402
