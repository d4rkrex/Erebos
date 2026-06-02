"""TUI Dashboard application using Textual.

VT-Spec DS-001: Read-only dashboard — no mutations to scan state.
"""

from __future__ import annotations

from datetime import datetime

from textual.app import App, ComposeResult
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header, Log, Static

from erebos.dashboard.data_layer import DashboardDataLayer
from erebos.dashboard.models import AgentStateView, DashboardSnapshot


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "INFO": "bold blue",
}

AGENT_STATE_ICONS = {
    AgentStateView.IDLE: "⏸️",
    AgentStateView.RUNNING: "🔄",
    AgentStateView.COMPLETED: "✅",
    AgentStateView.FAILED: "❌",
}


class SeverityPanel(Static):
    """Shows severity distribution counts."""

    def render(self) -> str:
        return self.renderable if hasattr(self, "renderable") and self.renderable else "Loading..."

    def update_counts(self, snapshot: DashboardSnapshot) -> None:
        c = snapshot.severity_counts
        lines = [
            "┌─── Findings ───────────────┐",
            f"│ 🔴 Critical: {c.critical:<4}          │",
            f"│ 🟠 High:     {c.high:<4}          │",
            f"│ 🟡 Medium:   {c.medium:<4}          │",
            f"│ 🟢 Low:      {c.low:<4}          │",
            f"│ ⚪ Info:     {c.info:<4}          │",
            f"│ ── Total:    {c.total:<4}          │",
            "└────────────────────────────┘",
        ]
        self.update("\n".join(lines))


class ProgressPanel(Static):
    """Shows phase progress."""

    PHASE_ICONS = {
        "idle": "⏹",
        "recon": "🔍",
        "discovery": "🌐",
        "vuln-scan": "🛡️",
        "validation": "✓",
        "reporting": "📝",
        "complete": "🏁",
        "aborted": "⛔",
    }

    def update_progress(self, snapshot: DashboardSnapshot) -> None:
        p = snapshot.progress
        bar_width = 20
        filled = int(p.percentage / 100 * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)
        icon = self.PHASE_ICONS.get(p.current_phase, "?")

        status = "🟢 ACTIVE" if snapshot.is_active else "⏹ IDLE"
        target = snapshot.target or "—"

        lines = [
            "┌─── Progress ───────────────┐",
            f"│ Target: {target:<19}│",
            f"│ Status: {status:<19}│",
            f"│ Phase:  {icon} {p.current_phase:<15}│",
            f"│ [{bar}] {p.percentage:>3.0f}% │",
            "└────────────────────────────┘",
        ]
        self.update("\n".join(lines))


class AgentsPanel(Static):
    """Shows agent statuses."""

    def update_agents(self, snapshot: DashboardSnapshot) -> None:
        if not snapshot.agents:
            self.update("┌─── Agents ─────────┐\n│ No agents active   │\n└────────────────────┘")
            return

        lines = ["┌─── Agents ──────────────────────────┐"]
        for agent in snapshot.agents:
            icon = AGENT_STATE_ICONS.get(agent.state, "?")
            role = agent.role[:12].ljust(12)
            findings = f"({agent.findings_count} findings)" if agent.findings_count else ""
            lines.append(f"│ {icon} {role} {agent.state.value:<10} {findings:<16}│")
        lines.append("└──────────────────────────────────────┘")
        self.update("\n".join(lines))


class ExploitPanel(Static):
    """Shows exploitation status breakdown."""

    def update_exploitation(self, snapshot: DashboardSnapshot) -> None:
        e = snapshot.exploitation_counts
        lines = [
            "┌─── Exploitation ───────────┐",
            f"│ ⏳ Pending:       {e.pending:<4}      │",
            f"│ 💥 Exploited:     {e.exploited:<4}      │",
            f"│ ⚠️  Potential:     {e.potential:<4}      │",
            f"│ ❌ False Positive: {e.false_positive:<4}     │",
            f"│ ⏭️  Skipped:       {e.skipped:<4}      │",
            "└────────────────────────────┘",
        ]
        self.update("\n".join(lines))


class DashboardApp(App):
    """Erebos TUI Dashboard."""

    CSS = """
    Screen {
        layout: grid;
        grid-size: 2 3;
        grid-columns: 1fr 2fr;
        grid-rows: auto 1fr auto;
    }
    #left-top {
        row-span: 1;
        column-span: 1;
    }
    #left-mid {
        row-span: 1;
        column-span: 1;
    }
    #left-bot {
        row-span: 1;
        column-span: 1;
    }
    #right-top {
        row-span: 1;
        column-span: 1;
    }
    #findings-table {
        row-span: 1;
        column-span: 1;
    }
    #log-panel {
        row-span: 1;
        column-span: 1;
        height: 100%;
    }
    Static {
        padding: 0 1;
    }
    """

    TITLE = "Erebos Dashboard"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
    ]

    def __init__(self, scan_id: str | None = None, refresh_ms: int = 500):
        super().__init__()
        self._data_layer = DashboardDataLayer()
        self._scan_id = scan_id
        self._refresh_ms = refresh_ms
        self._bus_offset = 0
        self._refresh_timer: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield ProgressPanel(id="left-top")
        yield AgentsPanel(id="right-top")
        yield SeverityPanel(id="left-mid")
        yield DataTable(id="findings-table")
        yield ExploitPanel(id="left-bot")
        yield Log(id="log-panel", highlight=True)
        yield Footer()

    def on_mount(self) -> None:
        # Setup findings table columns
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Severity", "Title", "Target", "CVE", "Tool")

        # Initial data load
        self._do_refresh()

        # Start periodic refresh
        self._refresh_timer = self.set_interval(self._refresh_ms / 1000.0, self._do_refresh)

    def action_refresh(self) -> None:
        self._do_refresh()

    def _do_refresh(self) -> None:
        """Fetch latest data and update all panels."""
        try:
            snapshot = self._data_layer.get_snapshot(self._scan_id)
        except Exception:
            return

        # Update panels
        self.query_one("#left-top", ProgressPanel).update_progress(snapshot)
        self.query_one("#right-top", AgentsPanel).update_agents(snapshot)
        self.query_one("#left-mid", SeverityPanel).update_counts(snapshot)
        self.query_one("#left-bot", ExploitPanel).update_exploitation(snapshot)

        # Update findings table
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        for f in snapshot.top_findings:
            table.add_row(f.severity, f.title[:50], f.target or "—", f.cve or "—", f.tool)

        # Update log with new bus events
        self._update_log()

    def _update_log(self) -> None:
        """Tail FindingsBus for new events."""
        try:
            events, new_offset = self._data_layer.tail_bus_from(self._bus_offset, self._scan_id)
            self._bus_offset = new_offset

            log_widget = self.query_one("#log-panel", Log)
            for event in events:
                ts = (
                    event.timestamp.strftime("%H:%M:%S")
                    if isinstance(event.timestamp, datetime)
                    else str(event.timestamp)[:8]
                )
                log_widget.write_line(f"[{ts}] {event.summary}")
        except Exception:
            pass


def run_tui(scan_id: str | None = None) -> None:
    """Launch the TUI dashboard."""
    app = DashboardApp(scan_id=scan_id)
    app.run()
