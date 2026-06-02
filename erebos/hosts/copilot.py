"""Copilot CLI host integration."""

from typing import Optional
from erebos.cli.commands import ErebosCLI


class CopilotAdapter:
    """Adapter for Copilot CLI integration.

    This adapter ensures Erebos commands work identically in Copilot CLI
    as they do in OpenCode.
    """

    def __init__(self):
        self.cli = ErebosCLI()

    def get_commands(self) -> dict:
        """Get the command registry for Copilot CLI."""
        return {
            "scan": self.scan,
            "status": self.status,
            "report": self.report,
            "config": self.config,
            "allowlist": self.allowlist,
            "abort": self.abort,
            "tools": self.tools,
        }

    def scan(
        self,
        target: str,
        phase: Optional[str] = None,
        profile: str = "standard",
        dry_run: bool = False,
    ) -> dict:
        """Execute a pentest scan.

        Args:
            target: Target URL or domain
            phase: Specific phase to run (recon, discovery, vuln-scan, all)
            profile: Scan profile (minimal, standard, comprehensive, web-only, vuln-focused)
            dry_run: Simulate without executing

        Returns:
            dict with scan results
        """
        return self.cli.scan(target, phase, profile, dry_run)

    def status(self, scan_id: Optional[str] = None) -> dict:
        """Get scan status.

        Args:
            scan_id: Optional specific scan ID

        Returns:
            dict with status information
        """
        return self.cli.status(scan_id)

    def report(
        self,
        scan_id: Optional[str] = None,
        format: str = "markdown",
    ) -> dict:
        """Generate a report.

        Args:
            scan_id: Scan ID to generate report for
            format: Report format (markdown, json)

        Returns:
            dict with report content
        """
        return self.cli.report(scan_id, format)

    def config(self, action: str, key: Optional[str] = None, value: Optional[str] = None) -> dict:
        """Manage configuration.

        Args:
            action: Action (get, set, list)
            key: Configuration key
            value: Configuration value (for set)

        Returns:
            dict with configuration
        """
        return self.cli.config(action, key, value)

    def allowlist(self, action: str, target: Optional[str] = None) -> dict:
        """Manage target allowlist.

        Args:
            action: Action (add, remove, list)
            target: Target to add/remove

        Returns:
            dict with allowlist
        """
        return self.cli.allowlist(action, target)

    def abort(self, scan_id: Optional[str] = None) -> dict:
        """Abort a running scan.

        Args:
            scan_id: Optional scan ID to abort

        Returns:
            dict with abort result
        """
        return self.cli.abort(scan_id)

    def tools(self) -> dict:
        """Check available tools.

        Returns:
            dict with tool availability
        """
        return self.cli.tools()


# Plugin registration helper
def register_copilot_plugin() -> CopilotAdapter:
    """Register Erebos as a Copilot CLI plugin.

    This function should be called by Copilot CLI during initialization.

    Returns:
        CopilotAdapter instance
    """
    return CopilotAdapter()


# Export for Copilot CLI plugin system
__all__ = [
    "CopilotAdapter",
    "register_copilot_plugin",
]
