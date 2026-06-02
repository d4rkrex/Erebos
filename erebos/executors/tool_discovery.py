"""Tool discovery and availability checking."""

import shutil
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ToolInfo:
    """Information about a discovered tool."""

    name: str
    path: Optional[str]
    available: bool
    version: Optional[str] = None
    error: Optional[str] = None


class ToolDiscovery:
    """Discover and verify availability of security tools."""

    # Required tools for MVP
    REQUIRED_TOOLS = ["katana", "nuclei", "nikto"]

    # Optional tools
    OPTIONAL_TOOLS = ["nmap", "subfinder", "amass", "sqlmap", "xsser", "masscan", "searchsploit"]

    def __init__(self):
        self._tool_cache: Dict[str, ToolInfo] = {}

    def check_tool(self, tool_name: str) -> ToolInfo:
        """Check if a specific tool is available."""
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name]

        # Find the tool in PATH
        tool_path = shutil.which(tool_name)

        if tool_path:
            # Try to get version
            version = self._get_version(tool_name, tool_path)
            info = ToolInfo(
                name=tool_name,
                path=tool_path,
                available=True,
                version=version,
            )
        else:
            info = ToolInfo(
                name=tool_name,
                path=None,
                available=False,
                error=f"Tool '{tool_name}' not found in PATH",
            )

        self._tool_cache[tool_name] = info
        return info

    def check_tools(self, tool_names: List[str]) -> Dict[str, ToolInfo]:
        """Check availability of multiple tools."""
        results = {}
        for tool in tool_names:
            results[tool] = self.check_tool(tool)
        return results

    def check_required_tools(self) -> Dict[str, ToolInfo]:
        """Check all required tools."""
        return self.check_tools(self.REQUIRED_TOOLS)

    def check_optional_tools(self) -> Dict[str, ToolInfo]:
        """Check all optional tools."""
        return self.check_tools(self.OPTIONAL_TOOLS)

    def get_available_tools(self) -> List[str]:
        """Get list of available tool names."""
        available = []
        for tool in self.REQUIRED_TOOLS + self.OPTIONAL_TOOLS:
            info = self.check_tool(tool)
            if info.available:
                available.append(tool)
        return available

    def is_mvp_ready(self) -> bool:
        """Check if all MVP required tools are available."""
        for tool in self.REQUIRED_TOOLS:
            info = self.check_tool(tool)
            if not info.available:
                return False
        return True

    def get_missing_tools(self) -> List[str]:
        """Get list of missing required tools."""
        missing = []
        for tool in self.REQUIRED_TOOLS:
            info = self.check_tool(tool)
            if not info.available:
                missing.append(tool)
        return missing

    def get_tool_info_summary(self) -> str:
        """Get a summary of tool availability."""
        lines = ["Tool Availability:"]

        lines.append("\nRequired Tools:")
        for tool in self.REQUIRED_TOOLS:
            info = self.check_tool(tool)
            status = "✓" if info.available else "✗"
            version = f" ({info.version})" if info.version else ""
            lines.append(f"  {status} {tool}{version}")

        lines.append("\nOptional Tools:")
        for tool in self.OPTIONAL_TOOLS:
            info = self.check_tool(tool)
            status = "✓" if info.available else "✗"
            version = f" ({info.version})" if info.version else ""
            lines.append(f"  {status} {tool}{version}")

        return "\n".join(lines)

    def _get_version(self, tool_name: str, tool_path: str) -> Optional[str]:
        """Try to get the version of a tool."""
        import subprocess

        version_flags = {
            "katana": ["-version"],
            "nuclei": ["-version"],
            "nikto": ["-h"],
            "nmap": ["--version"],
            "subfinder": ["-version"],
            "amass": ["-version"],
            "sqlmap": ["--version"],
            "xsser": ["--version"],
            "masscan": ["--version"],
            "searchsploit": ["--version"],
        }

        flags = version_flags.get(tool_name, ["--version"])

        try:
            result = subprocess.run(
                [tool_path] + flags,
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Try to extract version from output
            output = result.stdout + result.stderr
            return self._extract_version(output)
        except Exception:
            return None

    def _extract_version(self, output: str) -> Optional[str]:
        """Extract version string from tool output."""
        import re

        # Common version patterns
        patterns = [
            r"v?(\d+\.\d+(?:\.\d+)?)",
            r"version\s+v?(\d+\.\d+(?:\.\d+)?)",
            r"(\d+\.\d+(?:\.\d+)\s+\w+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)

        return None


# Singleton instance
_discovery: Optional[ToolDiscovery] = None


def get_tool_discovery() -> ToolDiscovery:
    """Get the global ToolDiscovery instance."""
    global _discovery
    if _discovery is None:
        _discovery = ToolDiscovery()
    return _discovery


def check_tool(tool_name: str) -> ToolInfo:
    """Check if a tool is available (convenience function)."""
    return get_tool_discovery().check_tool(tool_name)


def is_mvp_ready() -> bool:
    """Check if MVP required tools are available."""
    return get_tool_discovery().is_mvp_ready()


def get_missing_tools() -> List[str]:
    """Get list of missing required tools."""
    return get_tool_discovery().get_missing_tools()
