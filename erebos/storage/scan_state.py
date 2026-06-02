"""Storage layer for scan state and findings."""

import json
import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

from erebos.core.finding import Finding
from erebos.core.target_profile import TargetProfile

logger = logging.getLogger(__name__)


class ScanState:
    """Scan state for persistence (pause/resume)."""

    def __init__(
        self,
        scan_id: str,
        target: str,
        profile: str = "standard",
        current_phase: str = "idle",
    ):
        self.scan_id = scan_id
        self.target = target
        self.profile = profile
        self.current_phase = current_phase
        self.started_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        self.findings: List[Dict] = []
        self.target_profile: Optional[TargetProfile] = None
        # Initialize phase_artifacts with commands list for command logging
        self.phase_artifacts: Dict = {"commands": [], "fallback_events": []}

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        data = {
            "scan_id": self.scan_id,
            "target": self.target,
            "profile": self.profile,
            "current_phase": self.current_phase,
            "started_at": self.started_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "findings": self.findings,
            "phase_artifacts": self.phase_artifacts,
        }
        if self.target_profile is not None:
            data["target_profile"] = self.target_profile.to_dict()
            data["phase_artifacts"] = dict(self.phase_artifacts)
            data["phase_artifacts"]["target_profile"] = self.target_profile.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "ScanState":
        """Create from dictionary."""
        state = cls(
            scan_id=data["scan_id"],
            target=data["target"],
            profile=data.get("profile", "standard"),
            current_phase=data.get("current_phase", "idle"),
        )
        state.findings = data.get("findings", [])
        target_profile_data = data.get("target_profile") or data.get("phase_artifacts", {}).get(
            "target_profile"
        )
        if target_profile_data:
            state.target_profile = TargetProfile.from_dict(target_profile_data)
        # Ensure commands key exists in phase_artifacts
        state.phase_artifacts = data.get("phase_artifacts", {"commands": []})
        if "commands" not in state.phase_artifacts:
            state.phase_artifacts["commands"] = []
        if "fallback_events" not in state.phase_artifacts:
            state.phase_artifacts["fallback_events"] = []
        if state.target_profile is not None:
            state.phase_artifacts["target_profile"] = state.target_profile.to_dict()
        if "started_at" in data:
            state.started_at = datetime.fromisoformat(data["started_at"])
        if "updated_at" in data:
            state.updated_at = datetime.fromisoformat(data["updated_at"])
        return state

    def log_command(
        self,
        tool: str,
        args: List[str],
        exit_code: int,
        duration: float,
        output_file: Optional[Path] = None,
    ) -> None:
        """Log a command execution to phase_artifacts.

        Args:
            tool: Tool name (e.g., "nmap", "nuclei")
            args: Command arguments
            exit_code: Process exit code
            duration: Execution duration in seconds
            output_file: Optional path to raw output file
        """
        command_log = {
            "tool": tool,
            "args": args,
            "command": f"{tool} {' '.join(args)}",
            "exit_code": exit_code,
            "duration_seconds": duration,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if output_file:
            command_log["output_file"] = str(output_file)

        if "commands" not in self.phase_artifacts:
            self.phase_artifacts["commands"] = []
        self.phase_artifacts["commands"].append(command_log)
        logger.debug(f"Logged command: {tool} (exit_code={exit_code}, duration={duration:.2f}s)")

    def log_fallback_event(self, event: Dict) -> None:
        """Persist a fallback event in scan artifacts."""
        if "fallback_events" not in self.phase_artifacts:
            self.phase_artifacts["fallback_events"] = []
        self.phase_artifacts["fallback_events"].append(event)

    def get_fallback_events(self) -> List[Dict]:
        """Return persisted fallback events."""
        events = self.phase_artifacts.get("fallback_events", [])
        return list(events) if isinstance(events, list) else []

    def save_raw_output(
        self,
        storage_dir: Path,
        tool: str,
        content: str,
        format: str,
        variant: str = "",
    ) -> Path:
        """Save raw tool output to {scan_id}/raw/ subdirectory.

        Args:
            storage_dir: Root storage directory (e.g., "erebos-storage")
            tool: Tool name (nmap, nuclei, etc.)
            content: Raw output content
            format: File extension (xml, json, txt)
            variant: Optional variant (fast, full) for tools run multiple times

        Returns:
            Path to saved file
        """
        raw_dir = Path(storage_dir) / self.scan_id / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        variant_str = f"_{variant}" if variant else ""
        filename = f"{tool}{variant_str}_{timestamp}.{format}"

        output_path = raw_dir / filename

        try:
            # Stream large outputs to avoid memory issues (>10MB)
            if len(content) > 10 * 1024 * 1024:
                logger.debug(
                    f"Streaming large output ({len(content) / 1024 / 1024:.1f}MB) to {output_path}"
                )
                with open(output_path, "w") as f:
                    # Write in chunks
                    chunk_size = 1024 * 1024  # 1MB chunks
                    for i in range(0, len(content), chunk_size):
                        f.write(content[i : i + chunk_size])
            else:
                output_path.write_text(content)

            logger.debug(f"Saved raw output to {output_path}")
            return output_path
        except IOError as e:
            logger.error(f"Failed to save raw output to {output_path}: {e}")
            # Return a dummy path to not block parsing
            return raw_dir / f"{tool}_failed.txt"


class FindingStore:
    """Finding CRUD operations."""

    def __init__(self, storage_dir: Path):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def add_finding(self, scan_id: str, finding: Finding) -> bool:
        """Add a finding to the store with deduplication.

        Args:
            scan_id: Scan identifier
            finding: Finding to add

        Returns:
            True if finding was added, False if duplicate was rejected
        """
        findings = self.get_findings(scan_id)

        # Deduplication key: (title, url, tool_name)
        dedup_key = self._get_dedup_key(finding)
        existing_keys = {self._get_dedup_key(f) for f in findings}

        if dedup_key in existing_keys:
            logger.debug(f"Skipping duplicate finding: {dedup_key}")
            return False

        findings.append(finding)
        findings_file = self.storage_dir / scan_id / "findings.json"
        findings_file.parent.mkdir(parents=True, exist_ok=True)
        self._save_findings(findings_file, findings)
        return True

    def _get_dedup_key(self, finding: Finding) -> tuple:
        """Get deduplication key for a finding.

        Returns tuple of (title, url, tool_name).
        """
        # Handle evidence.url - it might be None or missing
        url = ""
        if hasattr(finding, "evidence") and finding.evidence:
            if hasattr(finding.evidence, "url"):
                url = finding.evidence.url or ""
            elif isinstance(finding.evidence, dict):
                url = finding.evidence.get("url", "")

        return (finding.title, url, finding.tool)

    def get_findings(self, scan_id: str) -> List[Finding]:
        """Get all findings for a scan (handles both storage formats)."""
        # Try new subdirectory structure first
        findings_file = self.storage_dir / scan_id / "findings.json"
        if not findings_file.exists():
            # Fallback to legacy flat structure
            findings_file = self.storage_dir / f"{scan_id}_findings.json"

        if not findings_file.exists():
            return []

        with open(findings_file) as f:
            data = json.load(f)

        findings = []
        for f in data:
            try:
                # Handle evidence that might be a dict or string
                if isinstance(f.get("evidence"), dict):
                    f["evidence"] = f["evidence"]
                elif f.get("evidence"):
                    f["evidence"] = {"output": str(f["evidence"])}
                else:
                    f["evidence"] = {}
                findings.append(Finding(**f))
            except Exception as e:
                logger.error(f"Failed to load finding: {e}")
                continue
        return findings

    def update_findings_batch(self, scan_id: str, findings: List[Finding]) -> None:
        """Atomically update all findings (used after enrichment).

        Args:
            scan_id: Scan identifier
            findings: Complete list of findings with enrichment data

        Raises:
            IOError: If write fails
        """
        findings_file = self.storage_dir / scan_id / "findings.json"
        findings_file.parent.mkdir(parents=True, exist_ok=True)

        # Validate findings before write
        for finding in findings:
            # Validate CVSS score
            if finding.cvss is not None and not self._validate_cvss(finding.cvss):
                logger.error(
                    f"Invalid CVSS score {finding.cvss} for finding '{finding.title}' - "
                    f"must be between 0.0 and 10.0"
                )
                finding.cvss = None

            # Validate CVE IDs
            if finding.cves:
                validated_cves = []
                for cve_id in finding.cves:
                    if self._validate_cve_id(cve_id):
                        validated_cves.append(cve_id)
                    else:
                        logger.warning(f"Invalid CVE ID format: {cve_id}")
                finding.cves = validated_cves

            # Warn about partial enrichment
            if finding.cvss is None and finding.cves:
                logger.warning(
                    f"Partial enrichment for finding '{finding.title}': "
                    f"has {len(finding.cves)} CVEs but no CVSS score"
                )

        # Atomic write using temp file + rename
        temp_file = findings_file.with_suffix(".tmp")
        try:
            self._save_findings(temp_file, findings)
            temp_file.replace(findings_file)
            logger.info(f"Updated {len(findings)} findings for scan {scan_id}")
        except IOError as e:
            logger.error(f"Failed to update findings batch: {e}")
            if temp_file.exists():
                temp_file.unlink()
            raise

    def _validate_cvss(self, score: float) -> bool:
        """Validate CVSS score is between 0.0 and 10.0.

        Args:
            score: CVSS score to validate

        Returns:
            True if valid, False otherwise
        """
        return 0.0 <= score <= 10.0

    def _validate_cve_id(self, cve_id: str) -> bool:
        """Validate CVE ID format (CVE-YYYY-NNNNN).

        Args:
            cve_id: CVE identifier to validate

        Returns:
            True if valid format, False otherwise
        """
        # CVE format: CVE-YYYY-NNNNN (year 1999+, 4+ digit ID)
        pattern = r"^CVE-\d{4}-\d{4,}$"
        return bool(re.match(pattern, cve_id))

    def _save_findings(self, path: Path, findings: List[Finding]) -> None:
        """Save findings to file."""
        data = [f.model_dump() for f in findings]
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)


class ScanStateManager:
    """Manages scan state persistence."""

    def __init__(self, storage_dir: Path):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def create_scan(self, target: str, profile: str = "standard") -> ScanState:
        """Create a new scan state with subdirectory structure."""
        scan_id = str(uuid4())[:8]

        # Create scan subdirectory structure
        scan_dir = self.storage_dir / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)

        # Create raw/ subdirectory for tool outputs
        raw_dir = scan_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        state = ScanState(scan_id=scan_id, target=target, profile=profile)
        self.save_state(state)
        logger.info(f"Created scan {scan_id} with subdirectory structure at {scan_dir}")
        return state

    def save_state(self, state: ScanState) -> None:
        """Save scan state to subdirectory."""
        state.updated_at = datetime.now(timezone.utc)

        # NEW: Write to {scan_id}/state.json instead of {scan_id}_state.json
        state_file = self.storage_dir / state.scan_id / "state.json"
        state_file.parent.mkdir(parents=True, exist_ok=True)

        with open(state_file, "w") as f:
            json.dump(state.to_dict(), f, indent=2, default=str)

    def load_state(self, scan_id: str) -> Optional[ScanState]:
        """Load scan state with backward compatibility fallback.

        Tries new subdirectory structure first ({scan_id}/state.json),
        then falls back to legacy flat structure ({scan_id}_state.json).
        """
        # Try new subdirectory structure first
        state_file = self.storage_dir / scan_id / "state.json"
        if state_file.exists():
            with open(state_file) as f:
                data = json.load(f)
            return ScanState.from_dict(data)

        # Fallback to old flat structure (backward compatibility)
        legacy_file = self.storage_dir / f"{scan_id}_state.json"
        if legacy_file.exists():
            logger.warning(
                f"Loading scan {scan_id} from legacy flat structure: {legacy_file}. "
                "Run 'erebos migrate-storage' to upgrade to subdirectory structure. "
                "Legacy format support will be removed in v1.3.0."
            )
            with open(legacy_file) as f:
                data = json.load(f)
            return ScanState.from_dict(data)

        return None

    def list_scans(self) -> List[str]:
        """List all scan IDs from both new and legacy storage formats."""
        scan_ids = []

        # List scans from new subdirectory structure
        for item in self.storage_dir.iterdir():
            if item.is_dir() and (item / "state.json").exists():
                scan_ids.append(item.name)

        # List scans from legacy flat structure
        for state_file in self.storage_dir.glob("*_state.json"):
            scan_id = state_file.stem.replace("_state", "")
            if scan_id not in scan_ids:  # Avoid duplicates if already migrated
                scan_ids.append(scan_id)

        return scan_ids

    def delete_scan(self, scan_id: str) -> None:
        """Delete scan state and findings (handles both storage formats)."""
        # Try deleting new subdirectory structure
        scan_dir = self.storage_dir / scan_id
        if scan_dir.exists() and scan_dir.is_dir():
            shutil.rmtree(scan_dir)
            logger.info(f"Deleted scan directory: {scan_dir}")
            return

        # Fall back to deleting legacy flat files
        state_file = self.storage_dir / f"{scan_id}_state.json"
        findings_file = self.storage_dir / f"{scan_id}_findings.json"
        if state_file.exists():
            state_file.unlink()
            logger.debug(f"Deleted legacy state file: {state_file}")
        if findings_file.exists():
            findings_file.unlink()
            logger.debug(f"Deleted legacy findings file: {findings_file}")
