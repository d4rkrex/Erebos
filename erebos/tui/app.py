"""Erebos TUI main application."""

import asyncio
from pathlib import Path
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.driver import Driver
from textual.mode import ModalScreen, Mode
from textual.screen import Screen
from textual.widgets import Header, Footer, Static

from erebos.tui.screens import DashboardScreen, ScanDetailScreen, TargetsScreen
from erebos.tui.models import TUIState


class ErebosTUI(App):
    """Main TUI application for Erebos scan monitoring."""

    TITLE = "Erebos TUI"
    SUBTITLE = "Pentest Orchestration Monitor"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("ctrl+c", "quit", "Quit", show=True),
        Binding("1", "switch_mode('dashboard')", "Dashboard"),
        Binding("2", "switch_mode('scan_detail')", "Scan Detail"),
        Binding("3", "switch_mode('targets')", "Targets"),
        Binding("r", "refresh", "Refresh"),
        Binding("?", "toggle_help", "Help"),
    ]

    CSS = """
    Screen {
        background: $surface;
    }

    Header {
        background: $primary;
        color: $text;
    }

    Footer {
        background: $primary;
        color: $text;
    }

    #help-overlay {
        align: center middle;
        background: $surface;
        border: thick $accent;
        padding: 2;
    }

    #help-overlay > Static {
        margin: 1 2;
    }
    """

    def __init__(
        self,
        storage_dir: str = "./erebos-storage",
        refresh_interval: int = 2,
        auto_refresh: bool = True,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.storage_dir = storage_dir
        self.refresh_interval = refresh_interval
        self.auto_refresh = auto_refresh
        self.state = TUIState(refresh_interval=refresh_interval, auto_refresh=auto_refresh)
        self._refresh_task: Optional[asyncio.Task] = None
        self._selected_scan_id: str = ""

    def on_mount(self) -> None:
        """Set up the application on mount."""
        # Install all screens as modes
        dashboard = DashboardScreen(storage_dir=self.storage_dir)
        scan_detail = ScanDetailScreen(storage_dir=self.storage_dir)
        targets = TargetsScreen(storage_dir=self.storage_dir)

        self.install_screen(dashboard, name="dashboard")
        self.install_screen(scan_detail, name="scan_detail")
        self.install_screen(targets, name="targets")

        self.push_screen("dashboard")

        # Start auto-refresh if enabled
        if self.auto_refresh:
            self._start_auto_refresh()

    def _start_auto_refresh(self) -> None:
        """Start the auto-refresh timer."""
        if self._refresh_task and not self._refresh_task.done():
            return

        async def auto_refresh_loop():
            while True:
                await asyncio.sleep(self.refresh_interval)
                current = self.screen
                if hasattr(current, "refresh_data"):
                    current.refresh_data()

        self._refresh_task = asyncio.create_task(auto_refresh_loop())

    def _stop_auto_refresh(self) -> None:
        """Stop the auto-refresh timer."""
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()

    def action_refresh(self) -> None:
        """Manually trigger a refresh of the current screen."""
        current = self.screen
        if hasattr(current, "refresh_data"):
            current.refresh_data()
        elif hasattr(current, "refresh_findings"):
            current.refresh_findings()
        elif hasattr(current, "refresh_targets"):
            current.refresh_targets()

    def action_switch_mode(self, mode: str) -> None:
        """Switch to a different mode (screen)."""
        if mode == "dashboard":
            self.push_screen("dashboard")
        elif mode == "scan_detail":
            self.push_screen("scan_detail")
        elif mode == "targets":
            self.push_screen("targets")
        elif mode == "help":
            self.push_screen(HelpOverlay())

    def action_toggle_help(self) -> None:
        """Toggle the help overlay."""
        # Simple toggle - push/pop help overlay
        if self.screen and isinstance(self.screen, HelpOverlay):
            self.pop_screen()
        else:
            self.push_screen(HelpOverlay())

    def on_unmount(self) -> None:
        """Clean up on unmount."""
        self._stop_auto_refresh()


class HelpOverlay(ModalScreen):
    """Modal overlay showing keyboard shortcuts."""

    CSS = """
    HelpOverlay {
        align: center middle;
    }

    #help-box {
        width: 60;
        height: auto;
        background: $surface;
        border: thick $accent;
        padding: 2 4;
    }
    """

    BINDINGS = [
        Binding("q", "app.pop_screen", "Close"),
        Binding("escape", "app.pop_screen", "Close"),
        Binding("?", "app.pop_screen", "Close"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the help overlay."""
        yield Static(
            """
[bold cyan]Erebos TUI — Keyboard Shortcuts[/bold cyan]

[bold]Navigation[/bold]
  1         Switch to Dashboard
  2         Switch to Scan Detail
  3         Switch to Targets
  t         Switch to Targets

[bold]Actions[/bold]
  r         Refresh current screen
  q         Quit
  ?         Toggle this help

[bold]Table Navigation[/bold]
  j / ↓     Move down
  k / ↑     Move up
  Enter     Select
  /         Search/filter

[bold]Finding Filters[/bold]
  Tab       Cycle through filter options
  Click     Change filter

[bold]Status Icons[/bold]
  ⏸ idle    ⏳ pending    🔄 running
  ✅ complete   ❌ failed    ⏭ skipped
""",
            markup=True,
            id="help-content",
        )

    def on_mount(self) -> None:
        """Center the help box on mount."""
        pass


def run_tui(
    storage_dir: str = "./erebos-storage",
    refresh_interval: int = 2,
    auto_refresh: bool = True,
) -> None:
    """Launch the Erebos TUI application.

    Args:
        storage_dir: Path to the erebos storage directory.
        refresh_interval: Auto-refresh interval in seconds.
        auto_refresh: Whether to enable auto-refresh.
    """
    app = ErebosTUI(
        storage_dir=storage_dir,
        refresh_interval=refresh_interval,
        auto_refresh=auto_refresh,
    )
    app.run()


if __name__ == "__main__":
    run_tui()
