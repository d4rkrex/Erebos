"""Dashboard CLI commands.

VT-Spec ID-01: Default bind to 127.0.0.1 with warning on non-localhost.
"""

from __future__ import annotations

import click


@click.command()
@click.option("--web", is_flag=True, help="Launch web dashboard instead of TUI")
@click.option(
    "--host",
    default="127.0.0.1",
    help="Web dashboard bind address (default: 127.0.0.1)",
    show_default=True,
)
@click.option(
    "--port",
    default=8484,
    type=int,
    help="Web dashboard port (default: 8484)",
    show_default=True,
)
@click.option("--no-browser", is_flag=True, help="Don't auto-open browser (web mode)")
@click.option("--scan-id", default=None, help="Specific scan ID to display")
def dashboard(web: bool, host: str, port: int, no_browser: bool, scan_id: str | None) -> None:
    """Launch the Erebos dashboard (TUI or Web).

    By default launches the terminal UI. Use --web for browser dashboard.
    """
    if web:
        from erebos.dashboard.web.server import run_web

        run_web(host=host, port=port, open_browser=not no_browser)
    else:
        from erebos.dashboard.tui.app import run_tui

        run_tui(scan_id=scan_id)
