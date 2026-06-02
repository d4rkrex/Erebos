"""TUI screens for Erebos."""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.message import Message
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Static, Button, Header, Footer, TabbedContent, Tab, DataTable

from erebos.tui.widgets import ScanTable, FindingTable, FilterBar, ToolStatusLog, ScanInfoPanel
from textual.widgets import DataTable


# ─── Dashboard Screen ─────────────────────────────────────────────────────────


class DashboardScreen(Screen):
    """Main dashboard showing all active scans and summary stats."""

    CSS = """
    DashboardScreen {
        layout: grid;
        grid-size: 2 1;
        grid-columns: 1fr 2fr;
    }

    #scan-list-panel {
        width: 40%;
        height: 100%;
        border: solid $primary;
    }

    #detail-panel {
        width: 60%;
        height: 100%;
        border: solid $accent;
    }

    ScanTable {
        height: 1fr;
    }

    #finding-filter-bar {
        height: auto;
        padding: 1;
        background: $surface;
        border-bottom: solid $primary;
    }

    FindingTable {
        height: 1fr;
    }

    ScanInfoPanel {
        height: auto;
        padding: 1;
        background: $surface;
    }

    #tool-log {
        height: 30%;
        border-top: solid $accent;
    }
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("t", "app.switch_mode('targets')", "Targets"),
        ("1", "app.switch_mode('dashboard')", "Dashboard"),
        ("2", "app.switch_mode('scan_detail')", "Scan Detail"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, storage_dir: str = "./erebos-storage", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.storage_dir = storage_dir
        self._scan_data: list = []
        self._selected_scan_id: str | None = None

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout."""
        yield Header()
        with Horizontal():
            with VerticalScroll(id="scan-list-panel"):
                yield Static("📊 Active Scans", id="scan-title")
                yield ScanTable(id="scan-table")
                yield Button("🔄 Refresh", id="btn-refresh", variant="primary")
            with VerticalScroll(id="detail-panel"):
                yield ScanInfoPanel(id="scan-info")
                yield FilterBar(id="finding-filter-bar")
                yield FindingTable(id="finding-table")
                yield ToolStatusLog(id="tool-log")
        yield Footer()

    def on_mount(self) -> None:
        """Load data on mount."""
        self.title = "Erebos TUI — Dashboard"
        self.refresh_data()

    def refresh_data(self) -> None:
        """Refresh scan and finding data from storage."""
        from pathlib import Path
        from erebos.storage import ScanStateManager, FindingStore

        state_manager = ScanStateManager(Path(self.storage_dir))
        finding_store = FindingStore(Path(self.storage_dir))

        scan_ids = state_manager.list_scans()
        self._scan_data = []

        for scan_id in scan_ids:
            state = state_manager.load_state(scan_id)
            if state:
                findings = finding_store.get_findings(scan_id)
                scan_dict = {
                    "scan_id": state.scan_id,
                    "target": state.target,
                    "current_phase": state.current_phase,
                    "profile": state.profile,
                    "started_at": state.started_at.isoformat()
                    if hasattr(state.started_at, "isoformat")
                    else str(state.started_at),
                    "findings_count": len(findings),
                }
                self._scan_data.append(scan_dict)

        # Update scan table
        scan_table = self.query_one("#scan-table", ScanTable)
        scan_table.update_scans(self._scan_data)

        # Update finding table with selected scan
        self.update_findings_for_selected()

    def update_findings_for_selected(self) -> None:
        """Update findings table for the selected scan."""
        from pathlib import Path
        from erebos.storage import FindingStore, ScanStateManager

        scan_id = self._selected_scan_id or (
            self._scan_data[0].get("scan_id") if self._scan_data else None
        )

        if not scan_id:
            return

        finding_store = FindingStore(Path(self.storage_dir))
        state_manager = ScanStateManager(Path(self.storage_dir))

        findings = finding_store.get_findings(scan_id)
        finding_dicts = []
        for f in findings:
            d = f.model_dump()
            finding_dicts.append(d)

        finding_table = self.query_one("#finding-table", FindingTable)
        finding_table.update_findings(finding_dicts)

        # Update scan info panel
        scan_info = self.query_one("#scan-info", ScanInfoPanel)
        state = state_manager.load_state(scan_id)
        if state:
            scan_dict = {
                "scan_id": state.scan_id,
                "target": state.target,
                "current_phase": state.current_phase,
                "profile": state.profile,
                "started_at": state.started_at.isoformat()
                if hasattr(state.started_at, "isoformat")
                else str(state.started_at),
                "findings_count": len(findings),
            }
            scan_info.update(scan_dict)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-refresh":
            self.refresh_data()

    def on_data_table_row_selected(self, event: ScanTable.RowSelected) -> None:
        """Handle scan selection."""
        # Row selection is handled via cursor change
        pass

    def action_refresh(self) -> None:
        """Manual refresh action."""
        self.refresh_data()


# ─── Scan Detail Screen ────────────────────────────────────────────────────────


class ScanDetailScreen(Screen):
    """Detailed view for a single scan with all findings."""

    CSS = """
    ScanDetailScreen {
        layout: vertical;
    }

    #detail-header {
        height: auto;
        padding: 1;
        background: $surface;
        border-bottom: solid $primary;
    }

    #detail-body {
        height: 1fr;
    }

    FindingTable {
        height: 100%;
    }
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("1", "app.switch_mode('dashboard')", "Dashboard"),
        ("t", "app.switch_mode('targets')", "Targets"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, scan_id: str = "", storage_dir: str = "./erebos-storage", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scan_id = scan_id
        self.storage_dir = storage_dir
        self.severity_filter = "all"
        self.phase_filter = "all"

    def compose(self) -> ComposeResult:
        """Compose the scan detail layout."""
        yield Header()
        yield FilterBar(id="detail-filter-bar")
        with VerticalScroll(id="detail-body"):
            yield FindingTable(id="detail-finding-table")
        yield Footer()

    def on_mount(self) -> None:
        """Load findings on mount."""
        self.title = f"Erebos TUI — Scan {self.scan_id}"
        self.refresh_findings()

    def refresh_findings(self) -> None:
        """Refresh findings from storage."""
        from pathlib import Path
        from erebos.storage import FindingStore

        finding_store = FindingStore(Path(self.storage_dir))
        findings = finding_store.get_findings(self.scan_id)

        finding_dicts = []
        for f in findings:
            d = f.model_dump()
            # Apply filters
            if self.severity_filter != "all" and d.get("severity") != self.severity_filter:
                continue
            if self.phase_filter != "all" and d.get("phase_found") != self.phase_filter:
                continue
            finding_dicts.append(d)

        table = self.query_one("#detail-finding-table", FindingTable)
        table.update_findings(finding_dicts)

    def action_refresh(self) -> None:
        """Refresh action."""
        self.refresh_findings()

    def watch_selected_severity(self, value: str) -> None:
        """React to severity filter change."""
        self.severity_filter = value
        self.refresh_findings()

    def watch_selected_phase(self, value: str) -> None:
        """React to phase filter change."""
        self.phase_filter = value
        self.refresh_findings()


# ─── Targets Screen ────────────────────────────────────────────────────────────


class TargetsScreen(Screen):
    """Targets overview screen showing all targets and their status."""

    CSS = """
    TargetsScreen {
        layout: vertical;
    }

    #targets-header {
        height: auto;
        padding: 1;
        background: $surface;
    }

    DataTable {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("1", "app.switch_mode('dashboard')", "Dashboard"),
        ("2", "app.switch_mode('scan_detail')", "Scan Detail"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, storage_dir: str = "./erebos-storage", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.storage_dir = storage_dir

    def compose(self) -> ComposeResult:
        """Compose the targets layout."""
        yield Header()
        with VerticalScroll(id="targets-header"):
            yield Static("🎯 Targets Overview", id="targets-title")
        yield DataTable(id="targets-table")
        yield Footer()

    def on_mount(self) -> None:
        """Load targets on mount."""
        self.title = "Erebos TUI — Targets"
        table = self.query_one("#targets-table", DataTable)
        table.add_columns(
            ("Target", "target"),
            ("Phase", "phase"),
            ("Profile", "profile"),
            ("Findings", "findings"),
            ("Tools", "tools"),
        )
        self.refresh_targets()

    def refresh_targets(self) -> None:
        """Refresh targets from storage."""
        from pathlib import Path
        from erebos.storage import ScanStateManager, FindingStore

        state_manager = ScanStateManager(Path(self.storage_dir))
        finding_store = FindingStore(Path(self.storage_dir))

        scan_ids = state_manager.list_scans()
        table = self.query_one("#targets-table", DataTable)
        table.clear()

        for scan_id in scan_ids:
            state = state_manager.load_state(scan_id)
            if state:
                findings = finding_store.get_findings(scan_id)
                tools_run = ", ".join(
                    set(f["tool"] for f in findings if isinstance(f, dict) and f.get("tool"))
                )
                table.add_row(
                    state.target,
                    state.current_phase,
                    state.profile,
                    str(len(findings)),
                    tools_run[:40],
                )

    def action_refresh(self) -> None:
        """Refresh action."""
        self.refresh_targets()
