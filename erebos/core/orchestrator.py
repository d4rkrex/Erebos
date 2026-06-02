"""Phase state machine orchestrator."""

import logging
import signal
import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional

from erebos.core.finding import Finding, Phase, ScanMode
from erebos.core.phase_agent import (
    DiscoveryAgent,
    ReportingAgent,
    ValidationAgent,
    VulnScanAgent,
    get_agent_for_phase,
)
from erebos.core.scan_profile import ScanProfile
from erebos.executors.base import Transport
from erebos.parsers.base import Parser
from erebos.storage import FindingStore, ScanState, ScanStateManager
from erebos.config import get_settings

logger = logging.getLogger(__name__)


class AbortException(Exception):
    """Exception raised when scan is aborted."""

    pass


class PauseException(Exception):
    """Exception raised when scan is paused."""

    pass


class KillSwitch:
    """Global kill switch for aborting scans."""

    def __init__(self):
        self._aborted = False
        self._paused = False
        self._scan_ids = set()
        self._lock = threading.Lock()

    def register_scan(self, scan_id: str) -> None:
        """Register a scan ID for this kill switch."""
        with self._lock:
            self._scan_ids.add(scan_id)

    def unregister_scan(self, scan_id: str) -> None:
        """Unregister a scan ID."""
        with self._lock:
            self._scan_ids.discard(scan_id)

    def abort_all(self) -> None:
        """Abort all registered scans."""
        with self._lock:
            self._aborted = True

    def abort(self, scan_id: Optional[str] = None) -> None:
        """Abort a specific scan."""
        sid = scan_id or ""
        with self._lock:
            if sid in self._scan_ids or not scan_id:
                self._aborted = True

    def pause(self, scan_id: Optional[str] = None) -> None:
        """Pause a specific scan."""
        sid = scan_id or ""
        with self._lock:
            if sid in self._scan_ids or not scan_id:
                self._paused = True

    def resume(self, scan_id: Optional[str] = None) -> None:
        """Resume a specific scan."""
        sid = scan_id or ""
        with self._lock:
            if sid in self._scan_ids or not scan_id:
                self._paused = False

    def is_aborted(self, scan_id: Optional[str] = None) -> bool:
        """Check if any scan should be aborted."""
        return self._aborted

    def is_paused(self, scan_id: Optional[str] = None) -> bool:
        """Check if scan should be paused."""
        return self._paused and (scan_id is None or scan_id in self._scan_ids)

    def reset(self) -> None:
        """Reset the kill switch."""
        with self._lock:
            self._aborted = False
            self._paused = False

    def reset_scan(self, scan_id: str) -> None:
        """Reset state for a specific scan."""
        with self._lock:
            self._scan_ids.discard(scan_id)


# Global kill switch instance
_global_kill_switch = KillSwitch()


def get_kill_switch() -> KillSwitch:
    """Get the global kill switch instance."""
    return _global_kill_switch


def reset_kill_switch() -> None:
    """Reset the global kill switch (useful for testing)."""
    _global_kill_switch.reset()


class PhaseStateMachine:
    """Finite state machine for pentest phase orchestration."""

    # Valid phase transitions
    TRANSITIONS = {
        Phase.IDLE: [Phase.RECON],
        Phase.RECON: [
            Phase.DISCOVERY,
            Phase.VULN_SCAN,
            Phase.REPORTING,
            Phase.COMPLETE,
            Phase.ABORTED,
        ],
        Phase.DISCOVERY: [Phase.VULN_SCAN, Phase.REPORTING, Phase.COMPLETE, Phase.ABORTED],
        Phase.VULN_SCAN: [Phase.VALIDATION, Phase.REPORTING, Phase.COMPLETE, Phase.ABORTED],
        Phase.VALIDATION: [Phase.REPORTING, Phase.COMPLETE, Phase.ABORTED],
        Phase.REPORTING: [Phase.COMPLETE, Phase.ABORTED],
        Phase.COMPLETE: [],
        Phase.ABORTED: [],
    }

    # Required artifacts for each phase
    REQUIRED_ARTIFACTS = {
        Phase.RECON: [],
        Phase.DISCOVERY: [Phase.RECON],
        Phase.VULN_SCAN: [Phase.RECON],
        Phase.VALIDATION: [Phase.VULN_SCAN],
        Phase.REPORTING: [Phase.RECON, Phase.VULN_SCAN],
    }

    def __init__(self):
        self.current_phase = Phase.IDLE
        self.phase_history: List[Phase] = [Phase.IDLE]

    def can_transition(self, from_phase: Phase, to_phase: Phase) -> bool:
        """Check if transition is valid."""
        if from_phase not in self.TRANSITIONS:
            return False
        return to_phase in self.TRANSITIONS[from_phase]

    def transition(self, to_phase: Phase) -> bool:
        """Attempt to transition to a new phase."""
        if not self.can_transition(self.current_phase, to_phase):
            return False
        self.current_phase = to_phase
        self.phase_history.append(to_phase)
        return True

    def has_required_artifacts(self, phase: Phase, completed_phases: List[Phase]) -> bool:
        """Check if required artifacts exist for a phase."""
        required = self.REQUIRED_ARTIFACTS.get(phase, [])
        return all(req in completed_phases for req in required)

    def get_next_phase(self) -> Optional[Phase]:
        """Get the next logical phase."""
        for next_phase in self.TRANSITIONS[self.current_phase]:
            if next_phase not in [Phase.COMPLETE, Phase.ABORTED]:
                return next_phase
        return None

    def is_complete(self) -> bool:
        """Check if scan is complete."""
        return self.current_phase == Phase.COMPLETE

    def is_aborted(self) -> bool:
        """Check if scan was aborted."""
        return self.current_phase == Phase.ABORTED


class Orchestrator:
    """Main orchestrator for pentest execution with pause/resume support."""

    def __init__(
        self,
        target: str,
        profile: ScanProfile,
        transport: Transport,
        parsers: Dict[str, Parser],
        storage_dir: Path = Path("./erebos-storage"),
        on_phase_change: Optional[Callable[[Phase], None]] = None,
        on_progress: Optional[Callable[[str, float], None]] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
        scan_id: Optional[str] = None,
    ):
        self.target = target
        self.profile = profile
        self.transport = transport
        self.parsers = parsers
        self.storage_dir = storage_dir
        self.on_phase_change = on_phase_change
        self.on_progress = on_progress
        self.on_finding = on_finding
        self.scan_id = scan_id

        # State management
        self.state_machine = PhaseStateMachine()

        # Storage
        self.state_manager = ScanStateManager(storage_dir)
        self.finding_store = FindingStore(storage_dir)

        # Current scan state (load or create)
        self.current_scan_state: Optional[ScanState] = None
        if scan_id:
            self.current_scan_state = self.state_manager.load_state(scan_id)
            if not self.current_scan_state:
                # Create new scan state if not found
                self.current_scan_state = ScanState(
                    scan_id=scan_id,
                    target=target,
                    profile=profile.name,
                )
                self.state_manager.save_state(self.current_scan_state)

        # Execution state
        self.all_findings: List[Finding] = []
        self.context: Dict = {}

        # Register with kill switch
        if self.scan_id:
            get_kill_switch().register_scan(self.scan_id)

    @classmethod
    def create_for_scan(
        cls,
        target: str,
        profile: ScanProfile,
        scan_id: str,
        storage_dir: Path = Path("./erebos-storage"),
        on_progress: Optional[Callable[[str, float], None]] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
    ) -> "Orchestrator":
        """Factory method to create an orchestrator for a scan."""
        from erebos.executors.cli_adapter import CLIAdapter
        from erebos.config.settings import get_settings
        from erebos.parsers import (
            NucleiParser,
            NiktoParser,
            KatanaParser,
            NmapParser,
            FfufParser,
            GobusterParser,
            SqlmapParser,
            DirbParser,
            AmassParser,
            SubfinderParser,
            MasscanParser,
            HttpxParser,
            DnsxParser,
            AssetfinderParser,
            NaabuParser,
            GauParser,
            WaybackurlsParser,
            AlterxParser,
            ArjunParser,
            DirsearchParser,
            DalfoxParser,
            WpscanParser,
            KxssParser,
            BxssParser,
        )

        settings = get_settings()
        transport = CLIAdapter(extra_path=settings.execution.extra_path)
        parsers = {
            "nuclei": NucleiParser(),
            "nikto": NiktoParser(),
            "katana": KatanaParser(),
            "nmap": NmapParser(),
            "ffuf": FfufParser(),
            "gobuster": GobusterParser(),
            "sqlmap": SqlmapParser(),
            "dirb": DirbParser(),
            "amass": AmassParser(),
            "subfinder": SubfinderParser(),
            "masscan": MasscanParser(),
            "httpx": HttpxParser(),
            "dnsx": DnsxParser(),
            "assetfinder": AssetfinderParser(),
            "naabu": NaabuParser(),
            "gau": GauParser(),
            "waybackurls": WaybackurlsParser(),
            "alterx": AlterxParser(),
            "arjun": ArjunParser(),
            "dirsearch": DirsearchParser(),
            "dalfox": DalfoxParser(),
            "wpscan": WpscanParser(),
            "kxss": KxssParser(),
            "bxss": BxssParser(),
        }

        return cls(
            target=target,
            profile=profile,
            transport=transport,
            parsers=parsers,
            storage_dir=storage_dir,
            on_progress=on_progress,
            on_finding=on_finding,
            scan_id=scan_id,
        )

    def _check_abort(self) -> None:
        """Check if scan should be aborted."""
        if get_kill_switch().is_aborted(self.scan_id):
            logger.info(f"Scan {self.scan_id} aborted by kill switch")
            raise AbortException(f"Scan {self.scan_id} aborted")

    def _check_pause(self) -> None:
        """Check if scan should be paused."""
        if get_kill_switch().is_paused(self.scan_id):
            logger.info(f"Scan {self.scan_id} paused")
            # Save current state before pausing
            self._save_state()
            raise PauseException(f"Scan {self.scan_id} paused")

    def _save_state(self) -> None:
        """Save current scan state."""
        if self.scan_id and self.current_scan_state:
            # Update existing state instead of creating new one (preserves command logs)
            self.current_scan_state.current_phase = self.state_machine.current_phase.value
            self.current_scan_state.findings = [f.model_dump() for f in self.all_findings]
            # Preserve existing phase_artifacts (including command logs)
            if "commands" not in self.current_scan_state.phase_artifacts:
                self.current_scan_state.phase_artifacts["commands"] = []
            self.state_manager.save_state(self.current_scan_state)

    def _load_state(self, scan_id: str) -> bool:
        """Load scan state for resume."""
        state = self.state_manager.load_state(scan_id)
        if not state:
            return False

        # Set current scan state
        self.current_scan_state = state

        # Restore state
        self.scan_id = scan_id
        self.target = state.target

        # Restore phase
        phase_map = {
            "idle": Phase.IDLE,
            "recon": Phase.RECON,
            "discovery": Phase.DISCOVERY,
            "vuln-scan": Phase.VULN_SCAN,
            "validation": Phase.VALIDATION,
            "reporting": Phase.REPORTING,
            "complete": Phase.COMPLETE,
            "aborted": Phase.ABORTED,
        }
        current = phase_map.get(state.current_phase, Phase.IDLE)

        # Rebuild state machine history
        self.state_machine = PhaseStateMachine()
        if current != Phase.IDLE:
            self.state_machine.transition(current)

        # Load findings
        self.all_findings = [Finding(**f) for f in state.findings]

        # Register with kill switch
        get_kill_switch().register_scan(scan_id)

        return True

    def run_phase(self, phase: Phase) -> bool:
        """Execute a specific phase."""
        if not self.state_machine.can_transition(self.state_machine.current_phase, phase):
            logger.warning(f"Cannot transition from {self.state_machine.current_phase} to {phase}")
            return False

        # Check for abort before starting phase
        self._check_abort()

        # Get the appropriate agent
        try:
            agent = get_agent_for_phase(
                phase,
                self.transport,
                self.parsers,
                self.on_progress,
                self.on_finding,
                self.finding_store,
                self.scan_id,
                self.current_scan_state,
                self.storage_dir,
            )
        except ValueError as e:
            logger.error(f"Failed to get agent for phase {phase}: {e}")
            return False

        # Build context for phase
        context = self._build_phase_context(phase)

        # Execute phase
        try:
            self._check_abort()
            findings = agent.execute(self.target, context)
            self.all_findings.extend(findings)

            # Save findings
            if self.scan_id:
                for finding in findings:
                    self.finding_store.add_finding(self.scan_id, finding)

            # Transition state
            self.state_machine.transition(phase)
            self._save_state()

            if self.on_phase_change:
                self.on_phase_change(phase)

            return True

        except AbortException:
            self.state_machine.transition(Phase.ABORTED)
            self._save_state()
            return False
        except PauseException:
            # State already saved in _check_pause
            return False
        except Exception as e:
            logger.error(f"Error executing phase {phase}: {e}")
            return False

    def _build_phase_context(self, phase: Phase) -> Dict:
        """Build context dictionary for phase execution."""
        context = {}
        settings = get_settings()

        # Add findings from previous phases
        context["findings"] = self.all_findings
        context["target"] = self.target

        # Extract URLs from recon findings
        recon_urls = []
        for f in self.all_findings:
            if f.phase_found == Phase.RECON and f.evidence and f.evidence.url:
                recon_urls.append(f.evidence.url)
        context["recon_findings"] = recon_urls
        context["urls"] = recon_urls if recon_urls else [self.target]

        # Add profile-specific options
        if self.profile.name == "minimal":
            context["nuclei_severities"] = ["critical", "high"]
        elif self.profile.name == "standard":
            context["nuclei_severities"] = ["critical", "high", "medium"]
        elif self.profile.name == "comprehensive":
            context["nuclei_severities"] = ["critical", "high", "medium", "low"]

        # Add nmap strategy from profile
        context["nmap_strategy"] = getattr(self.profile, "nmap_strategy", "fast")
        logger.info(f"Using nmap strategy: {context['nmap_strategy']}")

        if self.profile.name == "minimal":
            context["scan_mode"] = ScanMode.STEALTH.value
        elif self.profile.name == "comprehensive":
            context["scan_mode"] = ScanMode.AGGRESSIVE.value
        else:
            context["scan_mode"] = ScanMode.NORMAL.value

        # Set tool execution flags based on profile
        tools_config = getattr(self.profile, "tools", None)
        if tools_config:
            context["run_katana"] = (
                "katana" in tools_config.recon if hasattr(tools_config, "recon") else False
            )
            context["run_nmap"] = (
                "nmap" in tools_config.recon if hasattr(tools_config, "recon") else False
            )
            context["run_nikto"] = (
                "nikto" in tools_config.recon if hasattr(tools_config, "recon") else False
            )
            context["run_amass"] = (
                "amass" in tools_config.recon if hasattr(tools_config, "recon") else False
            )
            context["run_subfinder"] = (
                "subfinder" in tools_config.recon if hasattr(tools_config, "recon") else False
            )
            context["run_ffuf"] = (
                "ffuf" in tools_config.discovery if hasattr(tools_config, "discovery") else False
            )
            context["run_gobuster"] = (
                "gobuster" in tools_config.discovery
                if hasattr(tools_config, "discovery")
                else False
            )
            context["run_dirb"] = (
                "dirb" in tools_config.discovery if hasattr(tools_config, "discovery") else False
            )
            context["run_masscan"] = (
                "masscan" in tools_config.discovery if hasattr(tools_config, "discovery") else False
            )
            context["run_nuclei"] = (
                any("nuclei" in t for t in tools_config.vuln_scan)
                if hasattr(tools_config, "vuln_scan")
                else False
            )
        else:
            # Default values when no tools_config
            context["run_katana"] = False
            context["run_nmap"] = False
            context["run_nikto"] = False
            context["run_amass"] = False
            context["run_subfinder"] = False
            context["run_ffuf"] = False
            context["run_gobuster"] = False
            context["run_dirb"] = False
            context["run_masscan"] = False
            context["run_nuclei"] = False

        # Pass inference engine setting from profile
        context["enable_inference"] = getattr(self.profile, "inference_engine", True)
        context["enable_target_profile"] = settings.ai.enable_target_profile
        context["enable_intelligent_decisions"] = settings.ai.enable_intelligent_decisions
        context["decision_default_threshold"] = settings.ai.decision_default_threshold
        context["decision_stealth_threshold"] = settings.ai.decision_stealth_threshold
        context["decision_aggressive_threshold"] = settings.ai.decision_aggressive_threshold
        context["decision_max_latency_ms"] = settings.ai.decision_max_latency_ms
        context[
            "enable_intelligent_error_handler"
        ] = settings.execution.enable_intelligent_error_handler
        context[
            "error_handler_fallback_chains_path"
        ] = settings.execution.error_handler_fallback_chains_path
        if self.current_scan_state and self.current_scan_state.target_profile is not None:
            context["target_profile"] = self.current_scan_state.target_profile
        if self.current_scan_state:
            profile_inference = self.current_scan_state.phase_artifacts.get("profile_inference", {})
            if profile_inference.get("nuclei_tags"):
                context["nuclei_tags"] = profile_inference["nuclei_tags"]
            if profile_inference.get("high_risk"):
                context["profile_high_risk"] = profile_inference["high_risk"]

        # VT-Spec TA-002: Detect technologies from recon findings and inject tags
        if phase == Phase.VULN_SCAN and self.all_findings:
            from erebos.scanning.tech_detection import (
                detect_technologies_from_findings,
                get_tags_for_technologies,
            )

            detected_techs = detect_technologies_from_findings(self.all_findings)
            if detected_techs:
                logger.info(f"TA-002: Detected technologies from recon: {detected_techs}")
                tech_tags = get_tags_for_technologies(detected_techs)
                existing_tags = set(context.get("nuclei_tags") or [])
                existing_tags.update(tech_tags)
                context["nuclei_tags"] = sorted(existing_tags)
                context["detected_technologies"] = sorted(detected_techs)

        phase_tools = {
            Phase.RECON: [
                "katana",
                "nmap",
                "ffuf",
                "gobuster",
                "dirb",
                "amass",
                "subfinder",
                "masscan",
            ],
            Phase.DISCOVERY: ["ffuf", "gobuster", "dirb", "masscan"],
            Phase.VULN_SCAN: ["nuclei", "nikto", "sqlmap", "wpscan"],
            Phase.VALIDATION: ["sqlmap", "nuclei"],
            Phase.REPORTING: [],
        }
        context["available_tools"] = phase_tools.get(phase, [])

        return context

    def run_all(self, phases: Optional[List[Phase]] = None) -> bool:
        """Run all phases in sequence with progress callbacks."""
        if phases is None:
            phases = []
            while not self.state_machine.is_complete():
                next_phase = self.state_machine.get_next_phase()
                if next_phase is None:
                    break
                phases.append(next_phase)

        for phase in phases:
            # Check abort before each phase
            self._check_abort()

            if not self.run_phase(phase):
                if self.state_machine.is_aborted():
                    logger.info(f"Scan aborted during {phase}")
                    return False
                return False

        return True

    def run_all_with_streaming(self) -> bool:
        """Run all phases with real-time output streaming."""

        def progress_callback(message: str, percent: float) -> None:
            if self.on_progress:
                self.on_progress(message, percent)
            # Also log for streaming
            logger.info(f"Progress: {message} ({percent}%)")

        # Set up finding callback for streaming
        def finding_callback(finding: Finding) -> None:
            if self.on_finding:
                self.on_finding(finding)
            logger.info(f"New finding: {finding.title} [{finding.severity}]")

        # Update agent callbacks for streaming
        # Note: In a real implementation, this would stream via WebSocket or similar

        return self.run_all()

    def _execute_phase(self, phase: Phase) -> bool:
        """Execute a specific phase (placeholder)."""
        # This will be implemented with actual tool execution
        return True

    def run_scan(self, phases: Optional[List[Phase]] = None) -> bool:
        """Run the full scan pipeline.

        Args:
            phases: Optional list of phases to run. If None, runs all phases.

        Returns:
            True if scan completed successfully, False otherwise.
        """
        # Determine phases to run based on profile tools
        if phases is None:
            phases = []

            # Add recon if profile has recon tools
            if self.profile.tools.recon:
                phases.append(Phase.RECON)

            # Add discovery if profile has discovery tools
            if self.profile.tools.discovery:
                phases.append(Phase.DISCOVERY)

            # Add vuln-scan if profile has vuln_scan tools
            if self.profile.tools.vuln_scan:
                phases.append(Phase.VULN_SCAN)

            # Add validation
            phases.append(Phase.VALIDATION)

            # Add reporting
            phases.append(Phase.REPORTING)

        # Run all phases
        success = self.run_all(phases)

        # Mark complete or aborted
        if success:
            self.state_machine.transition(Phase.COMPLETE)
            self._save_state()

        return success

    def get_findings(self) -> List[Finding]:
        """Get all findings from the scan."""
        return self.all_findings

    def abort(self) -> None:
        """Abort the current scan."""
        get_kill_switch().abort(self.scan_id)
        self.state_machine.transition(Phase.ABORTED)
        self._save_state()
        if self.scan_id:
            get_kill_switch().unregister_scan(self.scan_id)

    def pause(self) -> None:
        """Pause the current scan."""
        get_kill_switch().pause(self.scan_id)
        self._save_state()

    def resume(self) -> bool:
        """Resume a paused scan."""
        get_kill_switch().resume(self.scan_id)
        # Continue from current phase
        return self.run_all()

    def get_status(self) -> Dict:
        """Get current scan status."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "phase": self.state_machine.current_phase.value,
            "history": [p.value for p in self.state_machine.phase_history],
            "findings_count": len(self.all_findings),
            "is_aborted": self.state_machine.is_aborted(),
            "is_complete": self.state_machine.is_complete(),
        }
