"""Erebos TUI - Terminal User Interface for scan monitoring.

The TUI requires the 'textual' package.
Import models directly for testing without textual:
    from erebos.tui.models import ScanDisplay, TUIState, FindingDisplay
"""

from erebos.tui.models import ScanDisplay, TUIState, FindingDisplay

# Lazy import of app to avoid requiring textual at module load time
# Use: from erebos.tui.app import ErebosTUI, run_tui
__all__ = ["ErebosTUI", "run_tui", "ScanDisplay", "TUIState", "FindingDisplay"]

__autocomplete__ = ["ErebosTUI", "run_tui"]


def __getattr__(name: str):
    """Lazy load the ErebosTUI class from app module."""
    if name == "ErebosTUI":
        from erebos.tui.app import ErebosTUI

        return ErebosTUI
    if name == "run_tui":
        from erebos.tui.app import run_tui

        return run_tui
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
