"""Host integration module."""

from erebos.hosts.opencode import HOST_NAME, get_host_commands
from erebos.hosts.copilot import CopilotAdapter, register_copilot_plugin

__all__ = [
    "HOST_NAME",
    "get_host_commands",
    "CopilotAdapter",
    "register_copilot_plugin",
]
