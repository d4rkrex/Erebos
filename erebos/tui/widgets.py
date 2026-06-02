"""TUI reusable widgets (Textual widgets)."""

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import (
    DataTable,
    Header,
    Footer,
    Static,
    Button,
    Log,
    Input,
    RadioButton,
    RadioSet,
    TabbedContent,
    Tab,
)


# ─── Severity Helpers ──────────────────────────────────────────────────────────


def severity_color(severity: str) -> str:
    """Return Textual color for a severity level."""
    colors = {
        "CRITICAL": "red",
        "HIGH": "orange",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "white",
    }
    return colors.get(severity.upper(), "white")


def severity_emoji(severity: str) -> str:
    """Return emoji for severity level."""
    emojis = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "⚪",
    }
    return emojis.get(severity.upper(), "⚪")


# ─── Scan Table Widget ────────────────────────────────────────────────────────


class ScanTable(DataTable):
    """Data table displaying active scans."""

    BINDINGS = [
        Binding("enter", "select_cursor", "Select", show=False),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._scan_data: list = []

    def on_mount(self) -> None:
        """Set up columns on mount."""
        self.add_columns(
            ("Status", "status"),
            ("Scan ID", "scan_id"),
            ("Target", "target"),
            ("Phase", "phase"),
            ("Profile", "profile"),
            ("Findings", "findings"),
        )
        self.cursor_type = "row"

    def update_scans(self, scans: list) -> None:
        """Update table with scan data."""
        self.clear()
        self._scan_data = scans
        for scan in scans:
            scan_id = scan.get("scan_id", "-")
            target = scan.get("target", "-")
            phase = scan.get("current_phase", "idle")
            profile = scan.get("profile", "-")
            findings = scan.get("findings_count", 0)
            status = self._phase_emoji(phase)

            self.add_row(
                status,
                scan_id,
                target,
                phase,
                profile,
                str(findings),
            )

    def _phase_emoji(self, phase: str) -> str:
        emojis = {
            "idle": "⏸",
            "recon": "🔍",
            "discovery": "🕵️",
            "vuln-scan": "⚠️",
            "validation": "✅",
            "reporting": "📋",
            "complete": "✅",
            "aborted": "🛑",
        }
        return emojis.get(phase, "❓")

    def get_selected_scan_id(self) -> str | None:
        """Get the scan_id of the currently selected row."""
        row_index = self.cursor_row
        if 0 <= row_index < len(self._scan_data):
            return self._scan_data[row_index].get("scan_id")
        return None


# ─── Finding Table Widget ─────────────────────────────────────────────────────


class FindingTable(DataTable):
    """Data table displaying findings with severity color."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("/", "focus_search", "Search", show=False),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._finding_data: list = []

    def on_mount(self) -> None:
        """Set up columns on mount."""
        self.add_columns(
            ("Sev", "severity"),
            ("Tool", "tool"),
            ("Title", "title"),
            ("Phase", "phase"),
            ("URL", "url"),
        )
        self.cursor_type = "row"

    def update_findings(self, findings: list) -> None:
        """Update table with finding data."""
        self.clear()
        self._finding_data = findings
        for f in findings:
            sev = f.get("severity", "INFO")
            tool = f.get("tool", "-")
            title = f.get("title", "-")
            phase = f.get("phase_found", "-")
            url = ""
            if isinstance(f.get("evidence"), dict):
                url = f.get("evidence", {}).get("url", "")
            elif isinstance(f.get("evidence"), str):
                url = f.get("evidence", "")

            # Style severity column with color
            row_key = self.add_row(
                f"{severity_emoji(sev)} {sev[:3]}",
                tool,
                title,
                phase,
                str(url)[:30],
            )
            # Apply row color based on severity
            color = severity_color(sev)
            # Note: Textual's DataTable doesn't support row-level color natively
            # without custom CSS, so we rely on the severity emoji prefix


# ─── Filter Bar Widget ────────────────────────────────────────────────────────


class FilterBar(Container):
    """Horizontal filter bar for severity and phase."""

    class SeverityChanged(Message):
        """Message sent when severity filter changes."""

        def __init__(self, value: str) -> None:
            self.value = value
            super().__init__()

    class PhaseChanged(Message):
        """Message sent when phase filter changes."""

        def __init__(self, value: str) -> None:
            self.value = value
            super().__init__()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.selected_severity = "all"
        self.selected_phase = "all"

    def compose(self) -> ComposeResult:
        """Compose the filter bar."""
        with Horizontal(id="filter-bar"):
            yield Static("🔍 Sev:", id="sev-label")
            with RadioSet(id="severity-filter"):
                yield RadioButton("All", value="all", id="sev-all")
                yield RadioButton("🔴 CRIT", value="CRITICAL", id="sev-crit")
                yield RadioButton("🟠 HIGH", value="HIGH", id="sev-high")
                yield RadioButton("🟡 MED", value="MEDIUM", id="sev-med")
                yield RadioButton("🔵 LOW", value="LOW", id="sev-low")
                yield RadioButton("⚪ INFO", value="INFO", id="sev-info")
            yield Static("  |  Phase:", id="phase-label")
            with RadioSet(id="phase-filter"):
                yield RadioButton("All", value="all", id="phase-all")
                yield RadioButton("Recon", value="recon", id="phase-recon")
                yield RadioButton("Disc", value="discovery", id="phase-disc")
                yield RadioButton("Vuln", value="vuln-scan", id="phase-vuln")
                yield RadioButton("Report", value="reporting", id="phase-report")

    @on(RadioSet.Changing, "#severity-filter")
    def on_severity_change(self, event: RadioSet.Changing) -> None:
        """Handle severity filter change."""
        if event.pressed.value:
            self.selected_severity = event.pressed.value
            self.post_message(self.SeverityChanged(event.pressed.value))

    @on(RadioSet.Changing, "#phase-filter")
    def on_phase_change(self, event: RadioSet.Changing) -> None:
        """Handle phase filter change."""
        if event.pressed.value:
            self.selected_phase = event.pressed.value
            self.post_message(self.PhaseChanged(event.pressed.value))


# ─── Tool Status Widget ───────────────────────────────────────────────────────


class ToolStatusLog(Log):
    """Log widget showing tool execution status."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auto_scroll = True

    def log_status(self, tool: str, status: str, message: str = "") -> None:
        """Log a tool status message."""
        icons = {
            "pending": "⏳",
            "running": "🔄",
            "complete": "✅",
            "failed": "❌",
            "skipped": "⏭",
        }
        icon = icons.get(status, "❓")
        line = f"[cyan]{icon} [{tool}][/cyan] {status.upper()}"
        if message:
            line += f" — {message}"
        self.write_line(line)


# ─── Scan Info Panel ───────────────────────────────────────────────────────────


class ScanInfoPanel(Container):
    """Panel showing details of a selected scan."""

    scan_id = reactive("")
    target = reactive("")
    phase = reactive("")
    profile = reactive("")
    findings_count = reactive(0)
    started_at = reactive("")

    def compose(self) -> ComposeResult:
        """Compose the scan info panel."""
        yield Static("📋 Scan Details", id="scan-info-title")
        yield Static(id="scan-info-body")

    def update(self, scan: dict) -> None:
        """Update the scan info display."""
        self.scan_id = scan.get("scan_id", "-")
        self.target = scan.get("target", "-")
        self.phase = scan.get("current_phase", "idle")
        self.profile = scan.get("profile", "-")
        self.findings_count = scan.get("findings_count", 0)
        self.started_at = scan.get("started_at", "-")

        body = self.query_one("#scan-info-body", Static)
        body.update(
            f"[cyan]Scan ID:[/cyan] {self.scan_id}\n"
            f"[cyan]Target:[/cyan] {self.target}\n"
            f"[cyan]Phase:[/cyan] {self.phase}\n"
            f"[cyan]Profile:[/cyan] {self.profile}\n"
            f"[cyan]Findings:[/cyan] {self.findings_count}\n"
            f"[cyan]Started:[/cyan] {self.started_at}"
        )
