"""Shared read-only data layer for dashboard interfaces.

Reads from FindingStore, ScanStateManager, and FindingsBus without
interfering with active scan operations.

VT-Spec DS-001: Dashboard is read-only — no writes to scan state.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional

from erebos.core.finding import Finding, Phase, Severity
from erebos.dashboard.models import (
    AgentStateView,
    AgentStatusView,
    BusEvent,
    DashboardSnapshot,
    ExploitationCounts,
    FindingSummaryView,
    ProgressView,
    SeverityCounts,
)
from erebos.storage.scan_state import FindingStore, ScanStateManager

logger = logging.getLogger(__name__)

# Phase ordering for progress calculation
PHASE_ORDER = [
    Phase.IDLE,
    Phase.RECON,
    Phase.DISCOVERY,
    Phase.VULN_SCAN,
    Phase.VALIDATION,
    Phase.REPORTING,
    Phase.COMPLETE,
]


class DashboardDataLayer:
    """Read-only data access for dashboard interfaces.

    VT-Spec DS-001: All operations are read-only.
    No mutations to FindingStore, ScanStateManager, or FindingsBus.
    """

    def __init__(self, storage_dir: Optional[Path] = None):
        self._storage_dir = storage_dir or Path("./erebos-storage")
        self._state_mgr = ScanStateManager(self._storage_dir)
        self._finding_store = FindingStore(self._storage_dir)

    def get_snapshot(self, scan_id: Optional[str] = None) -> DashboardSnapshot:
        """Get a complete dashboard snapshot.

        If scan_id is not provided, uses the most recent scan.
        """
        if scan_id is None:
            scan_id = self._get_latest_scan_id()

        if scan_id is None:
            return DashboardSnapshot()

        state = self._state_mgr.load_state(scan_id)
        if state is None:
            return DashboardSnapshot(scan_id=scan_id)

        findings = self._finding_store.get_findings(scan_id)
        severity_counts = self._count_severities(findings)
        exploitation_counts = self._count_exploitation(findings)
        top_findings = self._get_top_findings(findings, limit=5)
        agents = self._get_agent_statuses(scan_id)
        progress = self._build_progress(state)

        is_active = state.current_phase not in ("complete", "aborted", "idle")

        return DashboardSnapshot(
            scan_id=scan_id,
            target=state.target,
            is_active=is_active,
            progress=progress,
            severity_counts=severity_counts,
            exploitation_counts=exploitation_counts,
            agents=agents,
            top_findings=top_findings,
            total_findings=len(findings),
            last_updated=datetime.now(timezone.utc),
        )

    def get_findings(self, scan_id: Optional[str] = None) -> List[Finding]:
        """Get all findings for a scan."""
        if scan_id is None:
            scan_id = self._get_latest_scan_id()
        if scan_id is None:
            return []
        return self._finding_store.get_findings(scan_id)

    def tail_bus(self, scan_id: Optional[str] = None) -> Iterator[BusEvent]:
        """Yield bus events from the FindingsBus JSONL file.

        Reads the entire file and yields parsed events.
        For live tailing, call repeatedly with offset tracking.
        """
        bus_path = self._get_bus_path(scan_id)
        if bus_path is None or not bus_path.exists():
            return

        with open(bus_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    yield BusEvent(
                        timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        role=data.get("role", "unknown"),
                        message_type=data.get("message_type", "unknown"),
                        summary=self._summarize_message(data),
                    )
                except (json.JSONDecodeError, KeyError):
                    continue

    def tail_bus_from(
        self, offset: int = 0, scan_id: Optional[str] = None
    ) -> tuple[List[BusEvent], int]:
        """Read bus events from a byte offset. Returns (events, new_offset)."""
        bus_path = self._get_bus_path(scan_id)
        if bus_path is None or not bus_path.exists():
            return [], 0

        events: List[BusEvent] = []
        with open(bus_path, "rb") as f:
            f.seek(offset)
            raw = f.read()
            new_offset = offset + len(raw)

        for line in raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                events.append(
                    BusEvent(
                        timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        role=data.get("role", "unknown"),
                        message_type=data.get("message_type", "unknown"),
                        summary=self._summarize_message(data),
                    )
                )
            except (json.JSONDecodeError, KeyError):
                continue

        return events, new_offset

    def list_scans(self) -> List[str]:
        """List all available scan IDs."""
        return self._state_mgr.list_scans()

    # ── Private helpers ─────────────────────────────────────────────────

    def _get_latest_scan_id(self) -> Optional[str]:
        """Get the most recent scan ID by modification time."""
        scans = self._state_mgr.list_scans()
        if not scans:
            return None

        # Sort by state file mtime (most recent first)
        def _mtime(sid: str) -> float:
            state_file = self._storage_dir / sid / "state.json"
            if state_file.exists():
                return state_file.stat().st_mtime
            legacy = self._storage_dir / f"{sid}_state.json"
            if legacy.exists():
                return legacy.stat().st_mtime
            return 0.0

        scans.sort(key=_mtime, reverse=True)
        return scans[0]

    def _count_severities(self, findings: List[Finding]) -> SeverityCounts:
        """Count findings by severity."""
        counts = SeverityCounts()
        for f in findings:
            sev = f.severity.upper() if isinstance(f.severity, str) else f.severity
            if sev in ("CRITICAL", Severity.CRITICAL):
                counts.critical += 1
            elif sev in ("HIGH", Severity.HIGH):
                counts.high += 1
            elif sev in ("MEDIUM", Severity.MEDIUM):
                counts.medium += 1
            elif sev in ("LOW", Severity.LOW):
                counts.low += 1
            else:
                counts.info += 1
        return counts

    def _count_exploitation(self, findings: List[Finding]) -> ExploitationCounts:
        """Count findings by exploitation status."""
        counts = ExploitationCounts()
        for f in findings:
            status = getattr(f, "exploitation_status", None) or "pending"
            if status == "exploited":
                counts.exploited += 1
            elif status == "potential":
                counts.potential += 1
            elif status == "false_positive":
                counts.false_positive += 1
            elif status == "skipped":
                counts.skipped += 1
            else:
                counts.pending += 1
        return counts

    def _get_top_findings(
        self, findings: List[Finding], limit: int = 5
    ) -> List[FindingSummaryView]:
        """Get top N findings by severity."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(
                f.severity.upper() if isinstance(f.severity, str) else f.severity, 4
            ),
        )

        return [
            FindingSummaryView(
                id=f.id,
                title=f.title,
                severity=f.severity if isinstance(f.severity, str) else f.severity.value,
                target=f.target,
                cve=f.cve,
                tool=f.tool,
            )
            for f in sorted_findings[:limit]
        ]

    def _get_agent_statuses(self, scan_id: str) -> List[AgentStatusView]:
        """Read agent statuses from bus messages."""
        bus_path = self._get_bus_path(scan_id)
        if bus_path is None or not bus_path.exists():
            return []

        agent_states: dict[str, AgentStatusView] = {}
        with open(bus_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    role = data.get("role", "unknown")
                    msg_type = data.get("message_type", "")
                    ts_raw = data.get("timestamp")
                    ts = datetime.fromisoformat(ts_raw) if ts_raw else datetime.now(timezone.utc)

                    if role not in agent_states:
                        agent_states[role] = AgentStatusView(role=role)

                    agent = agent_states[role]
                    agent.last_activity = ts

                    if msg_type == "status":
                        payload = data.get("payload", {})
                        status_str = payload.get("status", "running")
                        if status_str == "completed":
                            agent.state = AgentStateView.COMPLETED
                        elif status_str == "failed":
                            agent.state = AgentStateView.FAILED
                        else:
                            agent.state = AgentStateView.RUNNING
                    elif msg_type == "finding":
                        agent.findings_count += 1
                        agent.state = AgentStateView.RUNNING

                except (json.JSONDecodeError, KeyError):
                    continue

        return list(agent_states.values())

    def _build_progress(self, state) -> ProgressView:
        """Build progress view from scan state."""
        current = state.current_phase
        completed_phases = []
        percentage = 0.0

        for i, phase in enumerate(PHASE_ORDER):
            phase_val = phase.value if hasattr(phase, "value") else phase
            if phase_val == current:
                percentage = (i / (len(PHASE_ORDER) - 1)) * 100
                break
            completed_phases.append(phase_val)

        if current in ("complete", "aborted"):
            percentage = 100.0

        return ProgressView(
            current_phase=current,
            phases_completed=completed_phases,
            total_phases=len(PHASE_ORDER),
            percentage=percentage,
            started_at=state.started_at if hasattr(state, "started_at") else None,
        )

    def _get_bus_path(self, scan_id: Optional[str] = None) -> Optional[Path]:
        """Find the FindingsBus JSONL path for a scan."""
        if scan_id is None:
            scan_id = self._get_latest_scan_id()
        if scan_id is None:
            return None

        # Check scan subdirectory for bus.jsonl
        bus_path = self._storage_dir / scan_id / "bus.jsonl"
        if bus_path.exists():
            return bus_path

        # Check workspace-level bus
        workspace_bus = self._storage_dir / "bus.jsonl"
        if workspace_bus.exists():
            return workspace_bus

        return None

    def _summarize_message(self, data: dict) -> str:
        """Create a human-readable summary from a bus message."""
        msg_type = data.get("message_type", "")
        payload = data.get("payload", {})
        role = data.get("role", "agent")

        if msg_type == "finding":
            title = payload.get("title", payload.get("finding", {}).get("title", "unknown"))
            severity = payload.get("severity", payload.get("finding", {}).get("severity", "?"))
            return f"[{role}] Finding: {title} ({severity})"
        elif msg_type == "status":
            status = payload.get("status", "update")
            return f"[{role}] Status: {status}"
        elif msg_type == "request":
            return f"[{role}] Request: {payload.get('action', 'unknown')}"
        else:
            return f"[{role}] {msg_type}"
