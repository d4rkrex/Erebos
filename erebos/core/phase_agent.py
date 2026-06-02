"""Phase agents for executing specific phases."""

import sys
import tempfile
from abc import ABC, abstractmethod
from typing import Callable, Dict, Generator, List, Optional
import logging
from pathlib import Path

from erebos.core.error_handler import (
    FallbackChainManager,
    IntelligentErrorHandler,
    ScanStateFallbackStore,
)
from erebos.core.finding import ExploitRef, Finding, FindingEvidence, Phase, Severity
from erebos.core.inference_engine import InferenceEngine
from erebos.executors.base import ToolResult, Transport
from erebos.parsers.base import Parser
from erebos.storage.scan_state import FindingStore, ScanState


logger = logging.getLogger(__name__)


class PhaseAgent(ABC):
    """Abstract base class for phase-specific agents."""

    def __init__(
        self,
        transport: Transport,
        parsers: Dict[str, Parser],
        on_progress: Optional[Callable[[str, float], None]] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
        finding_store: Optional[FindingStore] = None,
        scan_id: Optional[str] = None,
        scan_state: Optional[ScanState] = None,
        storage_dir: Optional[Path] = None,
    ):
        self.transport = transport
        self.parsers = parsers
        self.on_progress = on_progress
        self.on_finding = on_finding
        self.finding_store = finding_store
        self.scan_id = scan_id
        self.scan_state = scan_state
        self.storage_dir = storage_dir or Path("./erebos-storage")
        self.findings: List[Finding] = []
        self.error_handler: Optional[IntelligentErrorHandler] = None

    @property
    @abstractmethod
    def phase(self) -> Phase:
        """The phase this agent handles."""
        pass

    @property
    @abstractmethod
    def tools(self) -> List[str]:
        """List of tools used by this phase."""
        pass

    @abstractmethod
    def execute(self, target: str, context: dict) -> List[Finding]:
        """Execute the phase and return findings."""
        pass

    def _report_progress(self, message: str, percent: float) -> None:
        """Report progress to callback."""
        if self.on_progress:
            self.on_progress(message, percent)

    def _add_finding(self, finding: Finding) -> None:
        """Add a finding and notify callback."""
        self.findings.append(finding)
        if self.on_finding:
            self.on_finding(finding)

    def _stream_tool_output(
        self, tool: str, args: List[str], env: Optional[dict] = None
    ) -> Generator[str, None, None]:
        """Stream tool output in real-time."""
        yield from self.transport.stream(tool, args, env)

    def _execute_tool(
        self,
        tool: str,
        args: List[str],
        context: dict,
        category: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        """Execute a tool, optionally routing through intelligent recovery."""
        enabled = context.get("enable_intelligent_error_handler") or context.get(
            "enable_error_recovery", False
        )
        resolved_timeout = timeout if timeout is not None else context.get("timeout", 300)

        if enabled and category:
            if self.error_handler is None:
                manager = FallbackChainManager.load(
                    context.get("error_handler_fallback_chains_path")
                )
                self.error_handler = IntelligentErrorHandler(
                    transport=self.transport,
                    config=manager.config,
                    fallback_state_store=(
                        ScanStateFallbackStore(self.scan_state)
                        if self.scan_state is not None
                        else None
                    ),
                )
            return self.error_handler.execute_with_fallback(
                tool=tool,
                args=args,
                category=category,
                env=context.get("env"),
                timeout=resolved_timeout,
                scan_id=self.scan_id or "unknown",
            )

        return self.transport.execute(
            tool,
            args,
            env=context.get("env"),
            timeout=resolved_timeout,
        )

    def _apply_result_metadata(self, findings: List[Finding], result) -> List[Finding]:
        """Propagate degraded execution metadata into findings."""
        degraded = bool(getattr(result, "degraded", False))
        fallback_source = getattr(result, "fallback_source", None)

        if not degraded and not fallback_source:
            return findings

        for finding in findings:
            finding.degraded = degraded
            finding.fallback_source = fallback_source

        return findings

    @staticmethod
    def _is_nikto_help_output(output: str) -> bool:
        """Detect nikto help/usage output returned instead of real scan data."""
        normalized = output.lower()
        return (
            "options:" in normalized
            and "-format+" in normalized
            and ("-host+" in normalized or "-url+" in normalized)
            and "+ target:" not in normalized
        )

    @staticmethod
    def _is_nikto_maxtime_output(output: str) -> bool:
        """Detect nikto completing with its internal maxtime guard."""
        return "host maximum execution time" in output.lower()

    @classmethod
    def _normalize_nikto_result(cls, result):
        """Treat nikto help text as a no-op failure even if it exits zero."""
        if cls._is_nikto_help_output(result.stdout):
            result.exit_code = result.exit_code or 2
            if not result.stderr:
                result.stderr = "Nikto returned usage/help output instead of scan results"
        maxtime_text = f"{result.stdout or ''}\n{result.stderr or ''}"
        if cls._is_nikto_maxtime_output(maxtime_text):
            setattr(result, "degraded", True)
            if not getattr(result, "fallback_source", None):
                setattr(result, "fallback_source", "maxtime")
        return result

    def _record_tool_status(self, tool: str, result) -> None:
        """Persist per-tool execution status for coverage reporting."""
        if self.scan_state is None:
            return

        attempted_tools = list(getattr(result, "attempted_tools", []) or [])
        recovery_context = getattr(result, "recovery_context", {}) or {}
        attempts = (
            recovery_context.get("attempts", []) if isinstance(recovery_context, dict) else []
        )
        error_types = sorted(
            {
                str(event.get("error_type", "unknown"))
                for event in attempts
                if isinstance(event, dict) and event.get("tool") in ({tool} | set(attempted_tools))
            }
        )

        status = "success"
        fallback_source = getattr(result, "fallback_source", None)
        degraded = bool(getattr(result, "degraded", False))

        if fallback_source == "skip" or "skip" in attempted_tools or result.exit_code == 75:
            status = "skipped"
        elif degraded and result.exit_code == 0:
            status = "degraded"
        elif result.exit_code != 0:
            status = "failed"

        entry = {
            "phase": self.phase.value,
            "tool": tool,
            "status": status,
            "exit_code": result.exit_code,
            "degraded": degraded,
            "fallback_source": fallback_source,
            "attempted_tools": attempted_tools,
            "error_types": error_types,
            "message": (result.stderr or result.stdout or "")[:500],
        }

        tool_status = self.scan_state.phase_artifacts.setdefault("tool_status", [])
        filtered = [
            item
            for item in tool_status
            if not (item.get("phase") == self.phase.value and item.get("tool") == tool)
        ]
        filtered.append(entry)
        self.scan_state.phase_artifacts["tool_status"] = filtered

    @staticmethod
    def _nikto_execution_settings(context: dict) -> tuple[list[str], int]:
        """Apply conservative nikto limits for simple low-risk web targets."""
        args: list[str] = []
        timeout = int(context.get("timeout", 300))

        target_profile = context.get("target_profile")
        if target_profile is None:
            return args, timeout

        risk_value = getattr(target_profile, "risk_level", "")
        risk_level = str(getattr(risk_value, "value", risk_value)).lower()
        services = list(getattr(target_profile, "services", []) or [])
        service_names = {
            str(getattr(service, "service", "")).lower()
            for service in services
            if service is not None
        }
        simple_web_target = (
            bool(services) and len(services) <= 2 and service_names.issubset({"http", "https"})
        )

        if risk_level == "low" and simple_web_target and timeout >= 300:
            args.extend(["-maxtime", "4m30s"])
            timeout = max(timeout, 330)

        return args, timeout

    def _record_decision_result(self, result, phase: Phase) -> None:
        """Persist decision-engine output for auditability."""
        if self.scan_state is None or result is None:
            return
        audit = self.scan_state.phase_artifacts.setdefault("decision_engine", [])
        audit.append({"phase": phase.value, **result.to_dict()})

    def _get_recommended_tools(self, target: str, context: dict, tools: List[str]):
        """Get decision-engine recommendations for the current phase."""
        if not context.get("enable_intelligent_decisions", False):
            return None
        inference = InferenceEngine()
        phase_context = inference.phase_context_from_runtime(self.phase, target, tools, context)
        result = inference.recommend_tools_for_phase(phase_context)
        if result is not None:
            self._record_decision_result(result, self.phase)
        return result


class ReconAgent(PhaseAgent):
    """Agent for the reconnaissance phase using discovery, enumeration, and crawling tools."""

    @property
    def phase(self) -> Phase:
        return Phase.RECON

    @property
    def tools(self) -> List[str]:
        return [
            "nmap", "katana", "subfinder", "amass", "masscan", "ffuf", "gobuster", "dirb",
            # New recon/discovery tools
            "httpx", "dnsx", "assetfinder", "naabu", "gau", "waybackurls", "alterx",
            "arjun", "dirsearch",
        ]

    def execute(self, target: str, context: dict) -> List[Finding]:
        """Execute reconnaissance phase with inference-driven approach."""
        self.findings = []
        self._report_progress(f"Starting {self.phase.value} phase", 0.0)

        enable_inference = context.get("enable_inference", True)

        if enable_inference:
            # SMART FLOW: nmap FIRST, then inference decides what tools to run
            self._report_progress("Running nmap for discovery", 5.0)

            # Run nmap FIRST to discover the attack surface
            if context.get("run_nmap", True):
                try:
                    nmap_findings = self._run_nmap(target, context)
                except Exception as e:
                    logger.warning(f"nmap execution failed: {e}")
                    nmap_findings = []
                self.findings.extend(nmap_findings)
                self._report_progress(f"nmap found {len(nmap_findings)} services", 20.0)

            # If nmap found nothing, pivot to cloud/CDN recon strategy:
            # subdomain discovery + httpx probing (targets behind WAF/CDN won't respond to port scans)
            if not nmap_findings:
                self._report_progress("No ports found — pivoting to subdomain discovery", 25.0)
                logger.info(
                    "nmap found 0 services. Activating cloud recon: "
                    "subfinder → assetfinder → httpx → gau"
                )

                # Phase 1: Subdomain discovery
                subfinder_findings = self._run_subfinder(target, context)
                self.findings.extend(subfinder_findings)

                assetfinder_findings = self._run_assetfinder(target, context)
                self.findings.extend(assetfinder_findings)

                # Collect discovered subdomains for httpx probing
                discovered_subs = set()
                for f in self.findings:
                    if f.evidence and f.evidence.url:
                        discovered_subs.add(f.evidence.url)
                    elif f.evidence and f.evidence.raw:
                        for line in f.evidence.raw.splitlines():
                            line = line.strip()
                            if line and "." in line:
                                discovered_subs.add(line)

                # Phase 2: HTTP probing on discovered subdomains
                if discovered_subs:
                    self._report_progress(
                        f"Probing {len(discovered_subs)} subdomains with httpx", 40.0
                    )
                    context["httpx_targets"] = list(discovered_subs)
                    httpx_findings = self._run_httpx(target, context)
                    self.findings.extend(httpx_findings)

                # Phase 3: Passive URL collection
                self._report_progress("Collecting passive URLs (gau)", 55.0)
                gau_findings = self._run_gau(target, context)
                self.findings.extend(gau_findings)

                waybackurls_findings = self._run_waybackurls(target, context)
                self.findings.extend(waybackurls_findings)

                # Phase 4: DNS resolution on discovered subdomains
                if discovered_subs:
                    self._report_progress("Resolving DNS for subdomains", 65.0)
                    context["dnsx_targets"] = list(discovered_subs)
                    dnsx_findings = self._run_dnsx(target, context)
                    self.findings.extend(dnsx_findings)

                self._report_progress("Cloud recon complete", 70.0)

            else:
                # Standard flow: nmap found services, run inference for enrichment
                self._report_progress("Running inference engine", 30.0)
                logger.debug(
                    f"Before inference - nmap_xml_path = "
                    f"{context.get('nmap_xml_path', 'NOT SET')}"
                )
                self._run_inference(target, context, self.findings)

            # Persist enriched findings using batch update
            if self.finding_store and self.scan_id and self.findings:
                # Validate CVSS scores before saving
                for finding in self.findings:
                    if finding.cvss is not None:
                        if finding.cvss < 0.0 or finding.cvss > 10.0:
                            logger.error(
                                f"Invalid CVSS score {finding.cvss} for finding '{finding.title}' - "
                                f"must be between 0.0 and 10.0. Setting to None."
                            )
                            finding.cvss = None

                # Calculate enrichment coverage metrics
                total_findings = len(self.findings)
                cvss_count = sum(1 for f in self.findings if f.cvss is not None)
                cve_count = sum(1 for f in self.findings if f.cves)
                exploit_count = sum(1 for f in self.findings if f.exploits)

                cvss_coverage = (cvss_count / total_findings * 100) if total_findings > 0 else 0.0
                cve_coverage = (cve_count / total_findings * 100) if total_findings > 0 else 0.0
                exploit_coverage = (
                    (exploit_count / total_findings * 100) if total_findings > 0 else 0.0
                )

                logger.info(
                    f"Enrichment coverage - CVSS: {cvss_coverage:.1f}%, "
                    f"CVEs: {cve_coverage:.1f}%, Exploits: {exploit_coverage:.1f}%"
                )

                # Save enriched findings in batch
                self.finding_store.update_findings_batch(self.scan_id, self.findings)
                logger.info(f"Persisted {total_findings} enriched findings to storage")

            # Run additional recon tools if explicitly configured
            if context.get("run_amass", False):
                amass_findings = self._run_amass(target, context)
                self.findings.extend(amass_findings)

            if context.get("run_subfinder", False) and nmap_findings:
                # Only run if not already triggered by cloud pivot above
                subfinder_findings = self._run_subfinder(target, context)
                self.findings.extend(subfinder_findings)

        else:
            # LEGACY FLOW: Sequential execution (for backward compatibility)
            logger.debug("Inference disabled — using legacy sequential flow")

            if context.get("run_amass", False):
                amass_findings = self._run_amass(target, context)
                self.findings.extend(amass_findings)

            if context.get("run_subfinder", False):
                subfinder_findings = self._run_subfinder(target, context)
                self.findings.extend(subfinder_findings)

            if context.get("run_nmap", True):
                nmap_findings = self._run_nmap(target, context)
                self.findings.extend(nmap_findings)

            if context.get("run_katana", True):
                katana_findings = self._run_katana(target, context)
                self.findings.extend(katana_findings)

            if context.get("run_nikto", False):
                nikto_result = self._run_nikto(target, context)
                if nikto_result:
                    self.findings.extend(nikto_result)

            if context.get("run_masscan", False):
                masscan_findings = self._run_masscan(target, context)
                self.findings.extend(masscan_findings)

            if context.get("run_ffuf", False):
                ffuf_findings = self._run_ffuf(target, context)
                self.findings.extend(ffuf_findings)

            if context.get("run_gobuster", False):
                gobuster_findings = self._run_gobuster(target, context)
                self.findings.extend(gobuster_findings)

            if context.get("run_dirb", False):
                dirb_findings = self._run_dirb(target, context)
                self.findings.extend(dirb_findings)

            if context.get("run_httpx", False):
                httpx_findings = self._run_httpx(target, context)
                self.findings.extend(httpx_findings)

            if context.get("run_dnsx", False):
                dnsx_findings = self._run_dnsx(target, context)
                self.findings.extend(dnsx_findings)

            if context.get("run_assetfinder", False):
                assetfinder_findings = self._run_assetfinder(target, context)
                self.findings.extend(assetfinder_findings)

            if context.get("run_naabu", False):
                naabu_findings = self._run_naabu(target, context)
                self.findings.extend(naabu_findings)

            if context.get("run_gau", False):
                gau_findings = self._run_gau(target, context)
                self.findings.extend(gau_findings)

            if context.get("run_waybackurls", False):
                waybackurls_findings = self._run_waybackurls(target, context)
                self.findings.extend(waybackurls_findings)

            if context.get("run_alterx", False):
                alterx_findings = self._run_alterx(target, context)
                self.findings.extend(alterx_findings)

            if context.get("run_arjun", False):
                arjun_findings = self._run_arjun(target, context)
                self.findings.extend(arjun_findings)

            if context.get("run_dirsearch", False):
                dirsearch_findings = self._run_dirsearch(target, context)
                self.findings.extend(dirsearch_findings)

        self._report_progress(f"{self.phase.value} phase complete", 100.0)
        return self.findings

    def _run_katana(self, target: str, context: dict) -> List[Finding]:
        """Run katana for URL crawling."""
        self._report_progress("Running katana", 10.0)

        # Build katana arguments
        katana_args = [
            "-u",
            target,
            "-silent",
        ]

        # Add any additional options from context
        if "katana_options" in context:
            katana_args.extend(context["katana_options"])

        # Execute katana
        result = self._execute_tool(
            "katana", katana_args, context, timeout=context.get("timeout", 300)
        )

        # Log command execution
        if self.scan_state:
            self.scan_state.log_command(
                tool="katana",
                args=katana_args,
                exit_code=result.exit_code,
                duration=result.duration_seconds,
            )

        # Save raw output
        if self.scan_state and result.stdout:
            raw_output_path = self.scan_state.save_raw_output(
                storage_dir=self.storage_dir,
                tool="katana",
                content=result.stdout,
                format="txt",
            )
            logger.debug(f"Saved katana raw output to {raw_output_path}")

        if result.exit_code != 0:
            logger.warning(f"katana failed: {result.stderr}")
            self._report_progress("katana completed with errors", 30.0)
        else:
            self._report_progress("katana completed successfully", 30.0)

        # Parse results
        parser = self.parsers.get("katana")
        if parser and result.stdout:
            try:
                parsed_findings = self._apply_result_metadata(parser.parse(result.stdout), result)
                for finding in parsed_findings:
                    self._add_finding(finding)
                self._report_progress(f"Found {len(parsed_findings)} URLs", 40.0)
            except Exception as e:
                logger.error(f"Failed to parse katana output: {e}")

        return self.findings

    def _run_nmap_single(self, target: str, context: dict) -> List[Finding]:
        """Run nmap fast scan (top 100 ports) - legacy/single strategy."""
        self._report_progress("Running nmap", 40.0)
        print("[DEBUG _run_nmap] STARTING", flush=True)
        import sys

        sys.stdout.flush()

        # Strip protocol from target for nmap (nmap doesn't accept http://)
        import re

        nmap_target = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        logger.info(f"nmap target: {nmap_target}")

        # Save XML output to a temp file for ExploitDbService correlation
        nmap_xml_path: Optional[str] = None
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            nmap_xml_path = tmp.name

        # Build nmap arguments — -A enables OS, version, script, traceroute;
        # Using -F (fast scan) for quicker results; use -p- for comprehensive scan
        nmap_args = [
            nmap_target,
            "-A",  # Aggressive: OS detection + version + scripts
            "-F",  # Fast scan (top 100 ports)
            "-T4",  # Faster timing
            "-oX",
            nmap_xml_path,
        ]

        # Add additional options from context
        if "nmap_options" in context:
            nmap_args.extend(context["nmap_options"])

        # Execute nmap
        logger.info(f"Executing nmap: {' '.join(nmap_args)}")
        result = self._execute_tool(
            "nmap",
            nmap_args,
            context,
            category="network_scanning",
            timeout=context.get("timeout", 600),
        )

        # Log command execution to scan state
        if self.scan_state:
            self.scan_state.log_command(
                tool="nmap",
                args=nmap_args,
                exit_code=result.exit_code,
                duration=result.duration_seconds,
                output_file=Path(nmap_xml_path) if nmap_xml_path else None,
            )

        logger.info(f"nmap exit code: {result.exit_code}")
        logger.info(f"nmap stdout length: {len(result.stdout) if result.stdout else 0}")
        logger.info(f"nmap stderr: {result.stderr[:500] if result.stderr else 'None'}")

        # Store XML path in context for ExploitDbService
        if nmap_xml_path:
            context["nmap_xml_path"] = nmap_xml_path
            logger.info(f"nmap XML saved to: {nmap_xml_path}")

        # Parse results - read from XML file since nmap writes XML there
        parser = self.parsers.get("nmap")
        print(f"[DEBUG] nmap_xml_path = {nmap_xml_path}", flush=True)
        print(
            f"[DEBUG] file exists = {Path(nmap_xml_path).exists() if nmap_xml_path else 'None'}",
            flush=True,
        )

        if parser and nmap_xml_path:
            if Path(nmap_xml_path).exists():
                try:
                    xml_content = Path(nmap_xml_path).read_text()
                    print(f"[DEBUG] XML content length = {len(xml_content)}", flush=True)

                    # Save raw XML output to storage
                    if self.scan_state and xml_content:
                        raw_output_path = self.scan_state.save_raw_output(
                            storage_dir=self.storage_dir,
                            tool="nmap",
                            content=xml_content,
                            format="xml",
                            variant="single",
                        )
                        logger.info(f"Saved nmap raw output to {raw_output_path}")

                    nmap_parser = parser
                    parsed_findings = self._apply_result_metadata(
                        nmap_parser.parse_to_findings(xml_content), result
                    )  # type: ignore[attr-defined]
                    self._report_progress(f"nmap found {len(parsed_findings)} ports/services", 70.0)
                    print(f"[DEBUG] nmap parsed {len(parsed_findings)} findings", flush=True)
                    return parsed_findings
                except Exception as e:
                    print(f"[DEBUG] Parse error: {e}", flush=True)
                    logger.error(f"Failed to parse nmap output: {e}")
            else:
                print(f"[DEBUG] XML file does not exist", flush=True)

        return []

    def _run_nmap(self, target: str, context: dict) -> List[Finding]:
        """Run nmap scan using configured strategy (fast or dual).

        Routes to _run_nmap_single() for fast-only strategy, or _run_nmap_dual()
        for comprehensive dual-scan strategy.
        """
        strategy = context.get("nmap_strategy", "fast")
        logger.info(f"Using nmap strategy: {strategy}")

        if strategy == "dual":
            return self._run_nmap_dual(target, context)
        else:
            return self._run_nmap_single(target, context)

    def _run_nmap_dual(self, target: str, context: dict) -> List[Finding]:
        """Run dual nmap strategy: fast scan (-F) followed by full scan (-p-).

        This provides early feedback with top 100 ports (~2 min), then comprehensive
        coverage with all 65535 ports (~30 min). Results are merged with preference
        for full scan data on overlapping ports.

        Args:
            target: Scan target
            context: Execution context

        Returns:
            Merged findings from both scans (fast + full)
        """
        import re
        from pathlib import Path

        # Strip protocol from target for nmap
        nmap_target = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        logger.info(f"Dual nmap strategy - target: {nmap_target}")

        # ===== PHASE 1: Fast scan (top 100 ports, ~2 minutes) =====
        self._report_progress("Running nmap fast scan (top 100 ports)", 5.0)

        # Create temp file for fast scan XML
        fast_xml_path: Optional[str] = None
        with tempfile.NamedTemporaryFile(suffix="_fast.xml", delete=False) as tmp:
            fast_xml_path = tmp.name

        # Build fast scan arguments
        fast_args = [
            nmap_target,
            "-A",  # Aggressive: OS detection + version + scripts
            "-F",  # Fast scan (top ~100 ports)
            "-T4",  # Faster timing
            "-oX",
            fast_xml_path,
        ]

        if "nmap_options" in context:
            fast_args.extend(context["nmap_options"])

        # Execute fast scan
        logger.info(f"Executing fast nmap: {' '.join(fast_args)}")
        fast_result = self._execute_tool(
            "nmap",
            fast_args,
            context,
            category="network_scanning",
            timeout=context.get("timeout", 300),
        )

        # Log fast scan command
        if self.scan_state:
            self.scan_state.log_command(
                tool="nmap",
                args=fast_args,
                exit_code=fast_result.exit_code,
                duration=fast_result.duration_seconds,
                output_file=Path(fast_xml_path) if fast_xml_path else None,
            )

        logger.info(f"Fast nmap exit code: {fast_result.exit_code}")

        # Parse fast scan results
        fast_findings: List[Finding] = []
        parser = self.parsers.get("nmap")

        if parser and fast_xml_path and Path(fast_xml_path).exists():
            try:
                xml_content = Path(fast_xml_path).read_text()

                # Save raw XML output for fast scan
                if self.scan_state and xml_content:
                    raw_output_path = self.scan_state.save_raw_output(
                        storage_dir=self.storage_dir,
                        tool="nmap",
                        content=xml_content,
                        format="xml",
                        variant="fast",
                    )
                    logger.info(f"Saved fast nmap raw output to {raw_output_path}")

                fast_findings = self._apply_result_metadata(
                    parser.parse_to_findings(xml_content), fast_result
                )  # type: ignore[attr-defined]
                logger.info(f"Fast scan found {len(fast_findings)} ports/services")

                # Store fast XML in context for inference engine
                context["nmap_xml_path"] = fast_xml_path
                context["nmap_xml_path_fast"] = fast_xml_path

                # Report early findings
                self._report_progress(f"Fast scan complete, found {len(fast_findings)} ports", 50.0)
            except Exception as e:
                logger.error(f"Failed to parse fast nmap output: {e}")
        else:
            logger.warning("Fast nmap scan produced no XML output")

        # Return early findings for immediate user feedback
        # The orchestrator can display these while full scan continues

        # ===== PHASE 2: Full scan (all 65535 ports, ~30 minutes) =====
        self._report_progress("Running nmap full scan (all 65535 ports)", 55.0)

        # Create temp file for full scan XML
        full_xml_path: Optional[str] = None
        with tempfile.NamedTemporaryFile(suffix="_full.xml", delete=False) as tmp:
            full_xml_path = tmp.name

        # Build full scan arguments
        full_args = [
            nmap_target,
            "-A",  # Aggressive: OS detection + version + scripts
            "-p-",  # All 65535 ports
            "-T4",  # Faster timing
            "-oX",
            full_xml_path,
        ]

        if "nmap_options" in context:
            full_args.extend(context["nmap_options"])

        # Execute full scan (this will take ~30 minutes)
        logger.info(f"Executing full nmap: {' '.join(full_args)}")
        logger.info("Full scan will take approximately 30 minutes...")

        full_result = self._execute_tool(
            "nmap",
            full_args,
            context,
            category="network_scanning",
            timeout=context.get("timeout", 2400),
        )

        # Log full scan command
        if self.scan_state:
            self.scan_state.log_command(
                tool="nmap",
                args=full_args,
                exit_code=full_result.exit_code,
                duration=full_result.duration_seconds,
                output_file=Path(full_xml_path) if full_xml_path else None,
            )

        logger.info(f"Full nmap exit code: {full_result.exit_code}")

        # Parse full scan results
        full_findings: List[Finding] = []

        if parser and full_xml_path and Path(full_xml_path).exists():
            try:
                xml_content = Path(full_xml_path).read_text()

                # Save raw XML output for full scan
                if self.scan_state and xml_content:
                    raw_output_path = self.scan_state.save_raw_output(
                        storage_dir=self.storage_dir,
                        tool="nmap",
                        content=xml_content,
                        format="xml",
                        variant="full",
                    )
                    logger.info(f"Saved full nmap raw output to {raw_output_path}")

                full_findings = self._apply_result_metadata(
                    parser.parse_to_findings(xml_content), full_result
                )  # type: ignore[attr-defined]
                logger.info(f"Full scan found {len(full_findings)} ports/services")

                # Update context with full XML path (inference will use this)
                context["nmap_xml_path"] = full_xml_path
                context["nmap_xml_path_full"] = full_xml_path

                self._report_progress(f"Full scan complete, found {len(full_findings)} ports", 95.0)
            except Exception as e:
                logger.error(f"Failed to parse full nmap output: {e}")
        else:
            logger.warning("Full nmap scan produced no XML output")

        # ===== PHASE 3: Merge results =====
        self._report_progress("Merging fast and full scan results", 97.0)
        merged_findings = self._merge_nmap_results(fast_findings, full_findings)

        # Calculate port discovery metrics
        fast_port_count = len([f for f in fast_findings if self._get_port_key(f)])
        full_port_count = len([f for f in full_findings if self._get_port_key(f)])

        if fast_port_count > 0:
            improvement_pct = ((full_port_count - fast_port_count) / fast_port_count) * 100
            if improvement_pct > 0:
                logger.info(
                    f"Port discovery improvement: +{improvement_pct:.1f}% "
                    f"(fast: {fast_port_count}, full: {full_port_count})"
                )
            else:
                logger.info(
                    f"Full scan found no additional ports (fast: {fast_port_count}, full: {full_port_count})"
                )
        else:
            logger.info(f"Fast scan found no ports, full scan found {full_port_count} ports")

        # Store metrics in context for reporting (will be saved to phase_artifacts)
        context["nmap_metrics"] = {
            "strategy": "dual",
            "fast_ports": fast_port_count,
            "full_ports": full_port_count,
            "improvement_pct": ((full_port_count - fast_port_count) / fast_port_count * 100)
            if fast_port_count > 0
            else 0.0,
            "merged_ports": len([f for f in merged_findings if self._get_port_key(f)]),
        }

        logger.info(
            f"Merged results: fast={len(fast_findings)}, full={len(full_findings)}, final={len(merged_findings)}"
        )

        return merged_findings

    def _get_port_key(self, finding: Finding) -> Optional[tuple]:
        """Extract (host, port, protocol) tuple from finding URL.

        Used for merging nmap results by matching port/service identity.

        Args:
            finding: Finding with evidence.url containing host:port

        Returns:
            Tuple of (host, port, protocol) or None if URL is invalid
        """
        if not finding.evidence or not finding.evidence.url:
            return None

        url = finding.evidence.url

        # Parse URL to extract host, port, protocol
        # Expected formats: http://host:port, https://host:port, host:port
        import re
        from urllib.parse import urlparse

        # Try parsing as URL first
        if url.startswith(("http://", "https://")):
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port
            protocol = parsed.scheme

            if port:
                return (host, port, protocol)

        # Try parsing as host:port
        match = re.match(r"^([a-zA-Z0-9.-]+):(\d+)(?:/(\w+))?$", url)
        if match:
            host = match.group(1)
            port = int(match.group(2))
            protocol = match.group(3) or "tcp"  # Default to tcp if not specified
            return (host, port, protocol)

        # No port found
        return None

    def _merge_nmap_results(
        self, fast_findings: List[Finding], full_findings: List[Finding]
    ) -> List[Finding]:
        """Merge fast and full nmap scan results, preferring full scan data.

        When the same port appears in both scans, the full scan finding is preferred
        because it has more detailed service detection data. Unique ports from both
        scans are included in the final result.

        Args:
            fast_findings: Findings from fast scan (-F, top 100 ports)
            full_findings: Findings from full scan (-p-, all 65535 ports)

        Returns:
            Merged list of findings with duplicates resolved
        """
        if not fast_findings and not full_findings:
            logger.warning("Both fast and full scans produced no findings")
            return []

        if not fast_findings:
            logger.info(f"No fast findings, returning {len(full_findings)} full scan findings")
            return full_findings

        if not full_findings:
            logger.warning(f"Full scan failed, returning {len(fast_findings)} fast scan findings")
            return fast_findings

        # Build index of full scan findings by port key
        full_index: dict = {}
        non_port_full: List[Finding] = []  # Non-port findings (no URL)

        for finding in full_findings:
            port_key = self._get_port_key(finding)
            if port_key:
                full_index[port_key] = finding
            else:
                non_port_full.append(finding)

        # Merge: add fast findings only if not in full index
        merged: dict = {}
        non_port_fast: List[Finding] = []

        for finding in fast_findings:
            port_key = self._get_port_key(finding)
            if port_key:
                # Check if this port was found in full scan
                if port_key in full_index:
                    # Full scan has this port - prefer full scan data
                    merged[port_key] = full_index[port_key]
                    logger.debug(f"Port {port_key} found in both scans - using full scan data")
                else:
                    # Only in fast scan
                    merged[port_key] = finding
                    logger.debug(f"Port {port_key} only in fast scan")
            else:
                non_port_fast.append(finding)

        # Add ports only found in full scan
        for port_key, finding in full_index.items():
            if port_key not in merged:
                merged[port_key] = finding
                logger.debug(f"Port {port_key} only in full scan")

        # Combine: merged ports + non-port findings from both scans
        result = list(merged.values()) + non_port_fast + non_port_full

        logger.debug(
            f"Merge summary - fast ports: {len(fast_findings)}, "
            f"full ports: {len(full_findings)}, "
            f"merged: {len(merged)}, "
            f"non-port fast: {len(non_port_fast)}, "
            f"non-port full: {len(non_port_full)}, "
            f"final: {len(result)}"
        )

        return result

    def _run_inference(self, target: str, context: dict, findings: List[Finding]) -> List:
        """Run the inference engine for adaptive enrichment.

        Processes nmap scan result through InferenceEngine and executes
        enrichment actions (CVE lookup, HTTP probe, ExploitDB correlation).
        Enriched findings are returned with cvss, cves, exploits, http_banner fields.

        Args:
            target: Scan target.
            context: Execution context.
            findings: Existing findings from nmap scan.

        Returns:
            Enriched findings with CVE/exploit data.
        """
        from erebos.core.inference_engine import InferenceEngine
        from erebos.core.target_profile import TargetProfiler
        from erebos.parsers.nmap import NmapParser, NmapScanResult
        from erebos.enrichment.cve_service import CveService
        from erebos.enrichment.exploit_db import ExploitDbService
        from erebos.enrichment.http_probe import HttpProbeService

        self._report_progress("Running inference engine", 72.0)

        # Get nmap XML from the file saved in _run_nmap
        nmap_xml_path = context.get("nmap_xml_path")
        nmap_result: Optional[NmapScanResult] = None

        if nmap_xml_path and Path(nmap_xml_path).exists():
            xml_content = Path(nmap_xml_path).read_text()
            nmap_result = NmapParser().parse(xml_content)
        else:
            # Fall back: re-parse from findings evidence (limited)
            logger.warning("nmap XML not available for inference, skipping adaptive enrichment")
            return findings

        # Initialize services
        cve_service = CveService(api_key=context.get("nvd_api_key"))
        exploit_service = ExploitDbService()
        http_service = HttpProbeService(
            max_concurrent=context.get("http_probe_concurrent", 20),
            timeout=context.get("http_probe_timeout", 5.0),
        )

        # Run inference engine
        engine = InferenceEngine()
        decisions = engine.infer(nmap_result)

        self._report_progress(f"Inference engine emitted {len(decisions)} decisions", 74.0)

        # Track open ports for batch HTTP probing
        http_probe_targets: List[tuple] = []
        cve_lookup_tasks: List[tuple] = []  # (cpe, host)

        # Build host→finding map
        finding_map: Dict[str, Finding] = {}
        for f in findings:
            if f.evidence.url:
                finding_map[f.evidence.url] = f

        # Process decisions in priority order
        for decision in decisions:
            params = decision.params

            if decision.action == "http_probe":
                host = str(params.get("host", ""))
                port = str(params.get("port", ""))
                if host and port:
                    http_probe_targets.append((host, int(port)))

            elif decision.action == "cve_lookup":
                cpe = str(params.get("cpe", ""))
                if cpe:
                    cve_lookup_tasks.append((cpe, params.get("host", "")))

        # Execute HTTP probes in parallel batch
        probe_results = {}
        if http_probe_targets:
            self._report_progress(
                f"Probing {len(http_probe_targets)} ports for HTTP services", 76.0
            )
            probe_results = http_service.probe_batch(http_probe_targets)

            # Update findings with HTTP banners
            for (host, port), probe_result in probe_results.items():
                url_key = f"{host}:{port}"
                if url_key in finding_map and probe_result.is_http:
                    finding = finding_map[url_key]
                    if finding.evidence:
                        finding.evidence.http_banner = probe_result.server_banner

        # Execute CVE lookups
        for cpe, host in cve_lookup_tasks:
            self._report_progress(f"Looking up CVEs for CPE: {cpe}", 78.0)
            cve_records = cve_service.lookup_cpe(cpe)
            if cve_records:
                # Update corresponding finding(s)
                for finding in findings:
                    extra_output = finding.evidence.output or ""
                    if cpe in extra_output or (host and host in (finding.evidence.url or "")):
                        # Set CVSS to max found
                        max_cvss = max((r.cvss_v3_score or 0.0) for r in cve_records)
                        if max_cvss > 0:
                            finding.cvss = max_cvss
                        # Set multiple CVEs
                        for rec in cve_records:
                            if rec.cve_id and rec.cve_id not in finding.cves:
                                finding.cves.append(rec.cve_id)
                        # Legacy single CVE (backward compat)
                        if not finding.cve:
                            finding.cve = cve_records[0].cve_id

                # Process CVEs for ExploitDB
                cve_decisions = engine.process_cve_results(cve_records)
                for cve_decision in cve_decisions:
                    cve_ids: List[str] = cve_decision.params.get("cve_ids", [])  # type: ignore[assignment]
                    for cve_id in cve_ids:
                        exploits = exploit_service.get_exploits_for_cve(cve_id)
                        for exploit in exploits:
                            # Attach to highest-CVSS finding
                            if findings:
                                # Find the finding for this host
                                for finding in findings:
                                    if host and host in (finding.evidence.url or ""):
                                        if isinstance(exploit, ExploitRef):
                                            finding.exploits.append(exploit)
                                        break

        if context.get("enable_target_profile", True):
            profiler = TargetProfiler(enable_profile=True)
            profile = profiler.create_profile(
                target=target,
                nmap_result=nmap_result,
                http_results=probe_results,
                scan_id=self.scan_id,
                completed_phases=[self.phase.value],
            )
            if profile and self.scan_state:
                self.scan_state.target_profile = profile
                self.scan_state.phase_artifacts["target_profile"] = profile.to_dict()
                logger.info(
                    "Target profile created: %s score=%.1f risk=%s",
                    profile.target_type.value,
                    profile.attack_surface_score,
                    profile.risk_level.value,
                )

                profile_decisions = engine.infer_for_profile(
                    target=target,
                    nmap_result=nmap_result,
                    http_results=probe_results,
                    profile=profile,
                )
                profile_inference = self.scan_state.phase_artifacts.setdefault(
                    "profile_inference",
                    {"decisions": [], "nuclei_tags": [], "high_risk": False},
                )
                profile_inference["evaluated"] = True
                profile_inference["profile_target_type"] = profile.target_type.value
                existing_tags = set(profile_inference.get("nuclei_tags", []))
                high_risk = bool(profile_inference.get("high_risk", False))

                for decision in profile_decisions:
                    profile_inference.setdefault("decisions", []).append(
                        {
                            "trigger": decision.trigger,
                            "action": decision.action,
                            "params": dict(decision.params),
                            "priority": decision.priority,
                        }
                    )

                    if decision.action == "nuclei_tag_scan":
                        tags = decision.params.get("tags")
                        if isinstance(tags, (list, tuple, set)):
                            for tag in list(tags):
                                existing_tags.add(str(tag))
                        elif tags:
                            existing_tags.add(str(tags))
                    elif decision.action == "flag_high_risk":
                        if not high_risk:
                            description = (
                                f"Target profile indicates elevated exposure for {target}. "
                                f"Attack surface score {profile.attack_surface_score:.2f} "
                                f"({profile.risk_level.value})."
                            )
                            decision_services = decision.params.get("services")
                            if (
                                isinstance(decision_services, (list, tuple, set))
                                and decision_services
                            ):
                                services = ", ".join(
                                    [str(service) for service in list(decision_services)]
                                )
                                description += f" Exposed services: {services}."
                            self._add_finding(
                                Finding(
                                    tool="target-profile",
                                    severity=Severity.CRITICAL
                                    if profile.attack_surface_score >= 8.0
                                    else Severity.HIGH,
                                    title="Profile-Aware Risk Escalation",
                                    description=description,
                                    evidence=FindingEvidence(
                                        url=profile.host,
                                        output=str(decision.params),
                                    ),
                                    phase_found=Phase.RECON,
                                )
                            )
                        high_risk = True

                profile_inference["decision_count"] = len(profile_inference.get("decisions", []))
                profile_inference["nuclei_tags"] = sorted(existing_tags)
                profile_inference["high_risk"] = high_risk

                if context.get("enable_intelligent_decisions", False):
                    decision_context = InferenceEngine.phase_context_from_runtime(
                        Phase.VULN_SCAN,
                        target,
                        ["nuclei", "nikto", "sqlmap", "wpscan"],
                        {**context, "target_profile": profile, "urls": [target]},
                    )
                    recommendation = InferenceEngine().recommend_tools_for_phase(decision_context)
                    if recommendation is not None:
                        self._record_decision_result(recommendation, Phase.VULN_SCAN)

        self._report_progress("Inference enrichment complete", 85.0)
        return findings

    def _run_ffuf(self, target: str, context: dict) -> List[Finding]:
        """Run ffuf for directory fuzzing."""
        self._report_progress("Running ffuf", 50.0)

        # Build ffuf arguments
        ffuf_args = [
            "-u",
            f"{target}/FUZZ",
            "-json",
        ]

        # Add wordlist
        if "ffuf_wordlist" in context:
            ffuf_args.extend(["-w", context["ffuf_wordlist"]])
        else:
            ffuf_args.extend(["-w", "/usr/share/wordlists/dirb/common.txt"])

        # Add additional options
        if "ffuf_options" in context:
            ffuf_args.extend(context["ffuf_options"])

        # Execute ffuf
        result = self._execute_tool(
            "ffuf",
            ffuf_args,
            context,
            category="web_enumeration",
            timeout=context.get("timeout", 300),
        )

        # Parse results
        parser = self.parsers.get("ffuf")
        if parser and result.stdout:
            try:
                parsed_findings = self._apply_result_metadata(parser.parse(result.stdout), result)
                self._report_progress(f"ffuf found {len(parsed_findings)} endpoints", 80.0)
                return parsed_findings
            except Exception as e:
                logger.error(f"Failed to parse ffuf output: {e}")

        return []

    def _run_gobuster(self, target: str, context: dict) -> List[Finding]:
        """Run gobuster for directory scanning."""
        self._report_progress("Running gobuster", 55.0)

        # Build gobuster arguments
        gobuster_args = [
            "dir",
            "-u",
            target,
            "-q",  # Quiet mode
        ]

        # Add wordlist
        if "gobuster_wordlist" in context:
            gobuster_args.extend(["-w", context["gobuster_wordlist"]])
        else:
            gobuster_args.extend(["-w", "/usr/share/wordlists/dirb/common.txt"])

        # Add additional options
        if "gobuster_options" in context:
            gobuster_args.extend(context["gobuster_options"])

        # Execute gobuster
        result = self._execute_tool(
            "gobuster",
            gobuster_args,
            context,
            category="web_enumeration",
            timeout=context.get("timeout", 300),
        )

        # Parse results
        parser = self.parsers.get("gobuster")
        if parser and result.stdout:
            try:
                parsed_findings = self._apply_result_metadata(parser.parse(result.stdout), result)
                self._report_progress(f"gobuster found {len(parsed_findings)} directories", 85.0)
                return parsed_findings
            except Exception as e:
                logger.error(f"Failed to parse gobuster output: {e}")

        return []

    def _run_dirb(self, target: str, context: dict) -> List[Finding]:
        """Run dirb for directory scanning."""
        self._report_progress("Running dirb", 60.0)

        # Build dirb arguments
        dirb_args = [
            target,
        ]

        # Add wordlist
        if "dirb_wordlist" in context:
            dirb_args.append(context["dirb_wordlist"])

        # Add additional options
        if "dirb_options" in context:
            dirb_args.extend(context["dirb_options"])

        # Execute dirb
        result = self._execute_tool(
            "dirb",
            dirb_args,
            context,
            category="web_enumeration",
            timeout=context.get("timeout", 300),
        )

        # Parse results
        parser = self.parsers.get("dirb")
        if parser and result.stdout:
            try:
                parsed_findings = self._apply_result_metadata(parser.parse(result.stdout), result)
                self._report_progress(f"dirb found {len(parsed_findings)} directories", 90.0)
                return parsed_findings
            except Exception as e:
                logger.error(f"Failed to parse dirb output: {e}")

        return []

    def _run_nikto(self, target: str, context: dict) -> List[Finding]:
        """Run nikto for basic reconnaissance."""
        nikto_args = [
            "-host",
            target,
            "-Format",
            "txt",
        ]

        result = self._execute_tool(
            "nikto",
            nikto_args,
            context,
            category="web_scanning",
            timeout=context.get("timeout", 300),
        )
        result = self._normalize_nikto_result(result)

        # Log command execution
        if self.scan_state:
            self.scan_state.log_command(
                tool="nikto",
                args=nikto_args,
                exit_code=result.exit_code,
                duration=result.duration_seconds,
            )

        # Save raw output
        if self.scan_state and result.stdout:
            raw_output_path = self.scan_state.save_raw_output(
                storage_dir=self.storage_dir,
                tool="nikto",
                content=result.stdout,
                format="txt",
            )
            logger.debug(f"Saved nikto raw output to {raw_output_path}")

        if result.exit_code == 0 or result.stdout:
            parser = self.parsers.get("nikto")
            if parser:
                try:
                    findings = self._apply_result_metadata(parser.parse(result.stdout), result)
                    self._report_progress(f"nikto found {len(findings)} issues", 80.0)
                    return findings
                except Exception as e:
                    logger.error(f"Failed to parse nikto output: {e}")

        return []

    def _run_amass(self, target: str, context: dict) -> List[Finding]:
        """Run amass for subdomain enumeration."""
        self._report_progress("Running amass", 10.0)

        # Build amass arguments
        amass_args = [
            "enum",
            "-passive",
            "-d",
            target,
            "-json",
            "-",
        ]

        # Add additional options from context
        if "amass_options" in context:
            amass_args.extend(context["amass_options"])

        # Execute amass
        result = self._execute_tool(
            "amass", amass_args, context, timeout=context.get("timeout", 300)
        )

        if result.exit_code != 0:
            logger.warning(f"amass failed: {result.stderr}")
            self._report_progress("amass completed with errors", 30.0)
        else:
            self._report_progress("amass completed successfully", 30.0)

        # Parse results
        parser = self.parsers.get("amass")
        if parser and result.stdout:
            try:
                parsed_findings = self._apply_result_metadata(parser.parse(result.stdout), result)
                for finding in parsed_findings:
                    self._add_finding(finding)
                self._report_progress(f"Found {len(parsed_findings)} subdomains", 40.0)
            except Exception as e:
                logger.error(f"Failed to parse amass output: {e}")

        return self.findings

    def _run_subfinder(self, target: str, context: dict) -> List[Finding]:
        """Run subfinder for passive subdomain enumeration."""
        self._report_progress("Running subfinder", 15.0)

        # Build subfinder arguments
        subfinder_args = [
            "-d",
            target,
            "-silent",
        ]

        # Add additional options from context
        if "subfinder_options" in context:
            subfinder_args.extend(context["subfinder_options"])

        # Execute subfinder
        result = self._execute_tool(
            "subfinder", subfinder_args, context, timeout=context.get("timeout", 300)
        )

        if result.exit_code != 0:
            logger.warning(f"subfinder failed: {result.stderr}")
            self._report_progress("subfinder completed with errors", 35.0)
        else:
            self._report_progress("subfinder completed successfully", 35.0)

        # Parse results
        parser = self.parsers.get("subfinder")
        parsed_findings: List[Finding] = []
        if parser and result.stdout:
            try:
                parsed_findings = self._apply_result_metadata(
                    parser.parse(result.stdout), result
                )
                for finding in parsed_findings:
                    self._add_finding(finding)
                self._report_progress(f"Found {len(parsed_findings)} subdomains", 45.0)
            except Exception as e:
                logger.error(f"Failed to parse subfinder output: {e}")

        return parsed_findings

    def _run_masscan(self, target: str, context: dict) -> List[Finding]:
        """Run masscan for fast port scanning.

        Note: Masscan requires root privileges. If not running as root,
        results may be empty or the tool may fail silently.
        """
        self._report_progress("Running masscan", 40.0)

        # Build masscan arguments
        masscan_args = [
            target,
            "-p1-10000",
            "--rate=1000",
            "-oJ",
            "-",
        ]

        # Add additional options from context
        if "masscan_options" in context:
            masscan_args.extend(context["masscan_options"])

        # Add port range if specified
        if "masscan_ports" in context:
            masscan_args = [target, "-p", context["masscan_ports"], "--rate=1000", "-oJ", "-"]

        # Execute masscan
        result = self._execute_tool(
            "masscan",
            masscan_args,
            context,
            category="network_scanning",
            timeout=context.get("timeout", 600),
        )

        if result.exit_code != 0:
            logger.warning(f"masscan failed: {result.stderr}")
            self._report_progress("masscan completed with errors", 70.0)
        else:
            self._report_progress("masscan completed successfully", 70.0)

        # Parse results
        parser = self.parsers.get("masscan")
        if parser and result.stdout:
            try:
                parsed_findings = self._apply_result_metadata(parser.parse(result.stdout), result)
                self._report_progress(f"masscan found {len(parsed_findings)} open ports", 80.0)
                return parsed_findings
            except Exception as e:
                logger.error(f"Failed to parse masscan output: {e}")

        return []

    def _run_httpx(self, target: str, context: dict) -> List[Finding]:
        """Run httpx for HTTP probing and live host detection.

        Supports two modes:
        - Single target: probes just the target domain
        - Batch mode: if context["httpx_targets"] is set, pipes all to httpx via stdin
        """
        self._report_progress("Running httpx", 55.0)

        httpx_targets = context.get("httpx_targets")
        if httpx_targets and len(httpx_targets) > 1:
            # Batch mode: write targets to temp file and use -l
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(httpx_targets))
                targets_file = tf.name
            httpx_args = ["-l", targets_file, "-json", "-silent", "-td", "-sc"]
        else:
            httpx_args = ["-u", target, "-json", "-silent", "-td", "-sc"]

        if context.get("httpx_options"):
            httpx_args.extend(context["httpx_options"])

        result = self._execute_tool(
            "httpx", httpx_args, context, category="recon",
            timeout=context.get("timeout", 300),
        )
        self._record_tool_status("httpx", result)

        if result.exit_code != 0:
            logger.warning(f"httpx failed: {result.stderr}")
            return []

        parser = self.parsers.get("httpx")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse httpx output: {e}")
        return []

    def _run_dnsx(self, target: str, context: dict) -> List[Finding]:
        """Run dnsx for DNS resolution and validation.

        Supports batch mode via context["dnsx_targets"] for resolving discovered subdomains.
        """
        self._report_progress("Running dnsx", 58.0)

        dnsx_targets = context.get("dnsx_targets")
        if dnsx_targets and len(dnsx_targets) > 1:
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(dnsx_targets))
                targets_file = tf.name
            dnsx_args = ["-l", targets_file, "-resp", "-silent"]
        else:
            dnsx_args = ["-d", target, "-resp", "-silent"]

        if context.get("dnsx_options"):
            dnsx_args.extend(context["dnsx_options"])

        result = self._execute_tool(
            "dnsx", dnsx_args, context, category="recon",
            timeout=context.get("timeout", 120),
        )
        self._record_tool_status("dnsx", result)

        if result.exit_code != 0:
            logger.warning(f"dnsx failed: {result.stderr}")
            return []

        parser = self.parsers.get("dnsx")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse dnsx output: {e}")
        return []

    def _run_assetfinder(self, target: str, context: dict) -> List[Finding]:
        """Run assetfinder for passive subdomain/asset discovery."""
        self._report_progress("Running assetfinder", 60.0)
        assetfinder_args = ["--subs-only", target]
        if context.get("assetfinder_options"):
            assetfinder_args = context["assetfinder_options"] + [target]

        result = self._execute_tool(
            "assetfinder", assetfinder_args, context, category="recon",
            timeout=context.get("timeout", 120),
        )
        self._record_tool_status("assetfinder", result)

        if result.exit_code != 0:
            logger.warning(f"assetfinder failed: {result.stderr}")
            return []

        parser = self.parsers.get("assetfinder")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse assetfinder output: {e}")
        return []

    def _run_naabu(self, target: str, context: dict) -> List[Finding]:
        """Run naabu for fast port scanning."""
        self._report_progress("Running naabu", 62.0)
        naabu_args = ["-host", target, "-json", "-silent"]
        if context.get("naabu_options"):
            naabu_args.extend(context["naabu_options"])

        result = self._execute_tool(
            "naabu", naabu_args, context, category="recon",
            timeout=context.get("timeout", 300),
        )
        self._record_tool_status("naabu", result)

        if result.exit_code != 0:
            logger.warning(f"naabu failed: {result.stderr}")
            return []

        parser = self.parsers.get("naabu")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse naabu output: {e}")
        return []

    def _run_gau(self, target: str, context: dict) -> List[Finding]:
        """Run gau for passive URL collection from multiple sources."""
        self._report_progress("Running gau", 65.0)
        gau_args = [target]
        if context.get("gau_options"):
            gau_args.extend(context["gau_options"])

        result = self._execute_tool(
            "gau", gau_args, context, category="recon",
            timeout=context.get("timeout", 180),
        )
        self._record_tool_status("gau", result)

        if result.exit_code != 0:
            logger.warning(f"gau failed: {result.stderr}")
            return []

        parser = self.parsers.get("gau")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse gau output: {e}")
        return []

    def _run_waybackurls(self, target: str, context: dict) -> List[Finding]:
        """Run waybackurls for historical URL mining from Wayback Machine."""
        self._report_progress("Running waybackurls", 68.0)
        waybackurls_args = [target]
        if context.get("waybackurls_options"):
            waybackurls_args.extend(context["waybackurls_options"])

        result = self._execute_tool(
            "waybackurls", waybackurls_args, context, category="recon",
            timeout=context.get("timeout", 180),
        )
        self._record_tool_status("waybackurls", result)

        if result.exit_code != 0:
            logger.warning(f"waybackurls failed: {result.stderr}")
            return []

        parser = self.parsers.get("waybackurls")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse waybackurls output: {e}")
        return []

    def _run_alterx(self, target: str, context: dict) -> List[Finding]:
        """Run alterx for subdomain permutation generation."""
        self._report_progress("Running alterx", 70.0)
        alterx_args = ["-d", target, "-silent"]
        if context.get("alterx_options"):
            alterx_args.extend(context["alterx_options"])

        result = self._execute_tool(
            "alterx", alterx_args, context, category="recon",
            timeout=context.get("timeout", 60),
        )
        self._record_tool_status("alterx", result)

        if result.exit_code != 0:
            logger.warning(f"alterx failed: {result.stderr}")
            return []

        parser = self.parsers.get("alterx")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse alterx output: {e}")
        return []

    def _run_arjun(self, target: str, context: dict) -> List[Finding]:
        """Run arjun for hidden HTTP parameter discovery."""
        self._report_progress("Running arjun", 72.0)
        arjun_args = ["-u", target, "-oJ", "/dev/stdout"]
        if context.get("arjun_options"):
            arjun_args.extend(context["arjun_options"])

        result = self._execute_tool(
            "arjun", arjun_args, context, category="recon",
            timeout=context.get("timeout", 300),
        )
        self._record_tool_status("arjun", result)

        if result.exit_code != 0:
            logger.warning(f"arjun failed: {result.stderr}")
            return []

        parser = self.parsers.get("arjun")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse arjun output: {e}")
        return []

    def _run_dirsearch(self, target: str, context: dict) -> List[Finding]:
        """Run dirsearch for directory/file brute-force."""
        self._report_progress("Running dirsearch", 75.0)
        dirsearch_args = ["-u", target, "--format", "plain", "-q"]
        if context.get("dirsearch_options"):
            dirsearch_args.extend(context["dirsearch_options"])

        result = self._execute_tool(
            "dirsearch", dirsearch_args, context, category="recon",
            timeout=context.get("timeout", 300),
        )
        self._record_tool_status("dirsearch", result)

        if result.exit_code != 0:
            logger.warning(f"dirsearch failed: {result.stderr}")
            return []

        parser = self.parsers.get("dirsearch")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse dirsearch output: {e}")
        return []


class DiscoveryAgent(PhaseAgent):
    """Agent for the discovery phase."""

    @property
    def phase(self) -> Phase:
        return Phase.DISCOVERY

    @property
    def tools(self) -> List[str]:
        return []  # Discovery uses results from recon

    def execute(self, target: str, context: dict) -> List[Finding]:
        """Execute discovery phase."""
        self.findings = []
        self._report_progress(f"Starting {self.phase.value} phase", 0.0)

        # Discovery uses URLs from recon context
        recon_urls = context.get("recon_findings", [])

        self._report_progress(f"Processing {len(recon_urls)} URLs from recon", 50.0)

        # For now, discovery is a pass-through
        # In future, could add additional tools here

        self._report_progress(f"{self.phase.value} phase complete", 100.0)
        return self.findings


class VulnScanAgent(PhaseAgent):
    """Agent for the vulnerability scanning phase."""

    @property
    def phase(self) -> Phase:
        return Phase.VULN_SCAN

    @property
    def tools(self) -> List[str]:
        return ["nuclei", "nikto", "sqlmap", "dalfox", "wpscan", "kxss", "bxss"]

    def execute(self, target: str, context: dict) -> List[Finding]:
        """Execute vulnerability scanning phase."""
        self.findings = []
        self._report_progress(f"Starting {self.phase.value} phase", 0.0)

        # Get URLs from recon if available
        urls = context.get("urls", [target])

        decision_result = self._get_recommended_tools(target, context, self.tools)
        selected_tools = (
            [item.tool_name for item in decision_result.selected_tools] if decision_result else []
        )
        selected_params = (
            {item.tool_name: list(item.parameters) for item in decision_result.selected_tools}
            if decision_result
            else {}
        )
        if decision_result is not None:
            context["decision_engine_recommendations"] = decision_result.to_dict()
            context["decision_tool_parameters"] = selected_params

        run_nuclei = (not selected_tools and context.get("run_nuclei", True)) or (
            "nuclei" in selected_tools or "nuclei-wordpress" in selected_tools
        )
        run_nikto = (not selected_tools and True) or ("nikto" in selected_tools)
        run_sqlmap = (not selected_tools and context.get("run_sqlmap", False)) or (
            "sqlmap" in selected_tools
        )

        if run_nuclei:
            nuclei_findings = self._run_nuclei(urls, context)
            self.findings.extend(nuclei_findings)

        if run_nikto:
            nikto_findings = self._run_nikto(target, context)
            self.findings.extend(nikto_findings)

        if run_sqlmap:
            sqlmap_findings = self._run_sqlmap(urls, context)
            self.findings.extend(sqlmap_findings)

        # New vuln scanning tools
        if context.get("run_dalfox", False) or "dalfox" in selected_tools:
            dalfox_findings = self._run_dalfox(urls, context)
            self.findings.extend(dalfox_findings)

        if context.get("run_wpscan", False) or "wpscan" in selected_tools:
            wpscan_findings = self._run_wpscan(target, context)
            self.findings.extend(wpscan_findings)

        if context.get("run_kxss", False) or "kxss" in selected_tools:
            kxss_findings = self._run_kxss(urls, context)
            self.findings.extend(kxss_findings)

        if context.get("run_bxss", False) or "bxss" in selected_tools:
            bxss_findings = self._run_bxss(urls, context)
            self.findings.extend(bxss_findings)

        self._report_progress(f"{self.phase.value} complete - {len(self.findings)} findings", 100.0)
        return self.findings

    def _run_nuclei(self, urls: List[str], context: dict) -> List[Finding]:
        """Run nuclei vulnerability scanner."""
        self._report_progress("Running nuclei", 20.0)

        # Build nuclei arguments
        nuclei_args = [
            "-u",
            ",".join(urls) if len(urls) > 1 else urls[0],
            "-j",
            "-silent",
        ]

        # Add severity filter if specified
        severities = context.get("nuclei_severities", ["critical", "high", "medium"])
        nuclei_args.extend(["-severity", ",".join(severities)])

        # Add templates if specified
        if "nuclei_templates" in context:
            nuclei_args.extend(["-t", context["nuclei_templates"]])
        if "nuclei_tags" in context and context["nuclei_tags"]:
            tags = context["nuclei_tags"]
            if isinstance(tags, list):
                nuclei_args.extend(["-tags", ",".join(tags)])
            else:
                nuclei_args.extend(["-tags", str(tags)])
        if "decision_tool_parameters" in context:
            for tool_key in ("nuclei", "nuclei-wordpress"):
                if tool_key in context["decision_tool_parameters"]:
                    nuclei_args.extend(context["decision_tool_parameters"][tool_key])
                    break

        result = self._execute_tool(
            "nuclei",
            nuclei_args,
            context,
            category="web_scanning",
            timeout=context.get("timeout", 600),
        )

        # Log command execution
        if self.scan_state:
            self.scan_state.log_command(
                tool="nuclei",
                args=nuclei_args,
                exit_code=result.exit_code,
                duration=result.duration_seconds,
            )

        # Save raw output
        if self.scan_state and result.stdout:
            raw_output_path = self.scan_state.save_raw_output(
                storage_dir=self.storage_dir,
                tool="nuclei",
                content=result.stdout,
                format="json",
            )
            logger.debug(f"Saved nuclei raw output to {raw_output_path}")

        if result.exit_code != 0 and not result.stdout:
            logger.warning(f"nuclei failed: {result.stderr}")

        self._record_tool_status("nuclei", result)

        # Parse results
        parser = self.parsers.get("nuclei")
        if parser and result.stdout:
            try:
                findings = self._apply_result_metadata(parser.parse(result.stdout), result)
                self._report_progress(f"nuclei found {len(findings)} vulnerabilities", 60.0)
                return findings
            except Exception as e:
                logger.error(f"Failed to parse nuclei output: {e}")
                # Fallback to raw output
                if "raw" in self.parsers:
                    try:
                        findings = self._apply_result_metadata(
                            self.parsers["raw"].parse(result.stdout), result
                        )
                        return findings
                    except Exception:
                        pass

        return []

    def _run_nikto(self, target: str, context: dict) -> List[Finding]:
        """Run nikto web server scanner."""
        self._report_progress("Running nikto", 70.0)

        nikto_args = [
            "-host",
            target,
            "-Format",
            "txt",
        ]
        nikto_runtime_args, nikto_timeout = self._nikto_execution_settings(context)
        if nikto_runtime_args:
            nikto_args.extend(nikto_runtime_args)
        if "decision_tool_parameters" in context and "nikto" in context["decision_tool_parameters"]:
            nikto_args.extend(context["decision_tool_parameters"]["nikto"])

        result = self._execute_tool(
            "nikto",
            nikto_args,
            context,
            category="web_scanning",
            timeout=nikto_timeout,
        )
        result = self._normalize_nikto_result(result)

        # Log command execution
        if self.scan_state:
            self.scan_state.log_command(
                tool="nikto",
                args=nikto_args,
                exit_code=result.exit_code,
                duration=result.duration_seconds,
            )

        # Save raw output
        if self.scan_state and result.stdout:
            raw_output_path = self.scan_state.save_raw_output(
                storage_dir=self.storage_dir,
                tool="nikto",
                content=result.stdout,
                format="txt",
            )
            logger.debug(f"Saved nikto raw output to {raw_output_path}")

        self._record_tool_status("nikto", result)

        if getattr(result, "fallback_source", None) == "skip":
            self._report_progress("nikto skipped after recovery exhaustion", 90.0)

        parser = self.parsers.get("nikto")
        if parser and result.stdout:
            try:
                findings = self._apply_result_metadata(parser.parse(result.stdout), result)
                self._report_progress(f"nikto found {len(findings)} issues", 90.0)
                return findings
            except Exception as e:
                logger.error(f"Failed to parse nikto output: {e}")

        return []

    def _run_sqlmap(self, urls: List[str], context: dict) -> List[Finding]:
        """Run sqlmap for SQL injection testing."""
        self._report_progress("Running sqlmap", 80.0)

        findings = []
        sqlmap_results = []

        # Test each URL with sqlmap
        for url in urls:
            # Build sqlmap arguments
            sqlmap_args = [
                "-u",
                url,
                "--batch",  # Run in batch mode
            ]

            # Add additional options
            if "sqlmap_options" in context:
                sqlmap_args.extend(context["sqlmap_options"])

            # Add risk level
            if "sqlmap_risk" in context:
                sqlmap_args.extend(["--risk", str(context["sqlmap_risk"])])

            # Add level
            if "sqlmap_level" in context:
                sqlmap_args.extend(["--level", str(context["sqlmap_level"])])
            if (
                "decision_tool_parameters" in context
                and "sqlmap" in context["decision_tool_parameters"]
            ):
                sqlmap_args.extend(context["decision_tool_parameters"]["sqlmap"])

            result = self._execute_tool(
                "sqlmap", sqlmap_args, context, timeout=context.get("timeout", 900)
            )
            sqlmap_results.append(result)

            if self.scan_state:
                self.scan_state.log_command(
                    tool="sqlmap",
                    args=sqlmap_args,
                    exit_code=result.exit_code,
                    duration=result.duration_seconds,
                )

            if self.scan_state and result.stdout:
                raw_output_path = self.scan_state.save_raw_output(
                    storage_dir=self.storage_dir,
                    tool="sqlmap",
                    content=result.stdout,
                    format="txt",
                )
                logger.debug(f"Saved sqlmap raw output to {raw_output_path}")

            # Parse results
            parser = self.parsers.get("sqlmap")
            if parser and result.stdout:
                try:
                    parsed_findings = self._apply_result_metadata(
                        parser.parse(result.stdout), result
                    )
                    findings.extend(parsed_findings)
                    self._report_progress(
                        f"sqlmap found {len(parsed_findings)} SQL injection issues", 95.0
                    )
                except Exception as e:
                    logger.error(f"Failed to parse sqlmap output: {e}")

        if sqlmap_results:
            attempts = []
            degraded = False
            fallback_source = None
            worst_exit = 0
            last_message = ""
            for result in sqlmap_results:
                degraded = degraded or bool(getattr(result, "degraded", False))
                fallback_source = fallback_source or getattr(result, "fallback_source", None)
                attempts.extend(list(getattr(result, "attempted_tools", []) or []))
                recovery_context = getattr(result, "recovery_context", {}) or {}
                if result.exit_code != 0 and worst_exit == 0:
                    worst_exit = result.exit_code
                if result.stderr or result.stdout:
                    last_message = result.stderr or result.stdout

            aggregate_result = ToolResult(
                tool="sqlmap",
                exit_code=worst_exit,
                stdout="",
                stderr=last_message[:500],
                duration_seconds=sum(result.duration_seconds for result in sqlmap_results),
            )
            setattr(aggregate_result, "degraded", degraded)
            setattr(aggregate_result, "fallback_source", fallback_source)
            setattr(aggregate_result, "attempted_tools", attempts or ["sqlmap"])
            setattr(
                aggregate_result,
                "recovery_context",
                {
                    "attempts": [
                        attempt
                        for result in sqlmap_results
                        for attempt in (getattr(result, "recovery_context", {}) or {}).get(
                            "attempts", []
                        )
                        if isinstance(attempt, dict)
                    ]
                },
            )
            self._record_tool_status("sqlmap", aggregate_result)

        return findings

    def _run_dalfox(self, urls: List[str], context: dict) -> List[Finding]:
        """Run dalfox XSS scanner against discovered URLs."""
        self._report_progress("Running dalfox", 60.0)
        findings: List[Finding] = []

        for url in urls[:20]:  # Cap to avoid excessive scanning
            dalfox_args = ["url", url, "--format", "json", "--silence"]
            if context.get("dalfox_options"):
                dalfox_args.extend(context["dalfox_options"])

            result = self._execute_tool(
                "dalfox", dalfox_args, context, category="vuln-scan",
                timeout=context.get("timeout", 300),
            )
            self._record_tool_status("dalfox", result)

            if result.exit_code != 0:
                continue

            parser = self.parsers.get("dalfox")
            if parser and result.stdout:
                try:
                    parsed = self._apply_result_metadata(parser.parse(result.stdout), result)
                    findings.extend(parsed)
                except Exception as e:
                    logger.error(f"Failed to parse dalfox output: {e}")

        return findings

    def _run_wpscan(self, target: str, context: dict) -> List[Finding]:
        """Run wpscan WordPress vulnerability scanner."""
        self._report_progress("Running wpscan", 70.0)
        wpscan_args = ["--url", target, "--format", "json", "--no-banner"]
        if context.get("wpscan_api_token"):
            wpscan_args.extend(["--api-token", context["wpscan_api_token"]])
        if context.get("wpscan_options"):
            wpscan_args.extend(context["wpscan_options"])

        result = self._execute_tool(
            "wpscan", wpscan_args, context, category="vuln-scan",
            timeout=context.get("timeout", 300),
        )
        self._record_tool_status("wpscan", result)

        if result.exit_code not in (0, 5):  # wpscan exits 5 when vulns found
            logger.warning(f"wpscan failed: {result.stderr}")
            return []

        parser = self.parsers.get("wpscan")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse wpscan output: {e}")
        return []

    def _run_kxss(self, urls: List[str], context: dict) -> List[Finding]:
        """Run kxss reflected parameter detection."""
        self._report_progress("Running kxss", 80.0)
        kxss_args: List[str] = []
        if context.get("kxss_options"):
            kxss_args.extend(context["kxss_options"])

        result = self._execute_tool(
            "kxss", kxss_args, context, category="vuln-scan",
            timeout=context.get("timeout", 120),
        )
        self._record_tool_status("kxss", result)

        if result.exit_code != 0:
            logger.warning(f"kxss failed: {result.stderr}")
            return []

        parser = self.parsers.get("kxss")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse kxss output: {e}")
        return []

    def _run_bxss(self, urls: List[str], context: dict) -> List[Finding]:
        """Run bxss blind XSS testing."""
        self._report_progress("Running bxss", 85.0)
        callback_url = context.get("bxss_callback", "")
        if not callback_url:
            logger.info("bxss skipped: no callback URL configured (set bxss_callback in context)")
            return []

        bxss_args = ["-u", urls[0] if urls else "", "-b", callback_url]
        if context.get("bxss_options"):
            bxss_args.extend(context["bxss_options"])

        result = self._execute_tool(
            "bxss", bxss_args, context, category="vuln-scan",
            timeout=context.get("timeout", 120),
        )
        self._record_tool_status("bxss", result)

        if result.exit_code != 0:
            logger.warning(f"bxss failed: {result.stderr}")
            return []

        parser = self.parsers.get("bxss")
        if parser and result.stdout:
            try:
                return self._apply_result_metadata(parser.parse(result.stdout), result)
            except Exception as e:
                logger.error(f"Failed to parse bxss output: {e}")
        return []


class ValidationAgent(PhaseAgent):
    """Agent for the validation phase."""

    @property
    def phase(self) -> Phase:
        return Phase.VALIDATION

    @property
    def tools(self) -> List[str]:
        return []

    def execute(self, target: str, context: dict) -> List[Finding]:
        """Execute validation phase."""
        self.findings = []
        self._report_progress(f"Starting {self.phase.value} phase", 0.0)

        # Get findings from previous phases
        previous_findings = context.get("findings", [])

        self._report_progress(f"Validating {len(previous_findings)} findings", 50.0)

        # Mark findings as manually validated (placeholder)
        # In a real implementation, this could run additional checks

        self._report_progress(f"{self.phase.value} phase complete", 100.0)
        return self.findings


class ReportingAgent(PhaseAgent):
    """Agent for the reporting phase."""

    @property
    def phase(self) -> Phase:
        return Phase.REPORTING

    @property
    def tools(self) -> List[str]:
        return []

    def execute(self, target: str, context: dict) -> List[Finding]:
        """Execute reporting phase - aggregates findings."""
        self.findings = []
        self._report_progress(f"Starting {self.phase.value} phase", 0.0)

        # Get all findings from previous phases
        all_findings = context.get("findings", [])

        self._report_progress(f"Aggregating {len(all_findings)} findings", 50.0)

        # Deduplicate findings
        seen = set()
        unique_findings = []
        for finding in all_findings:
            key = (finding.title, finding.evidence.url)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        self.findings = unique_findings

        self._report_progress(
            f"Reporting phase complete - {len(unique_findings)} unique findings", 100.0
        )
        return self.findings


def get_agent_for_phase(
    phase: Phase,
    transport: Transport,
    parsers: Dict[str, Parser],
    on_progress: Optional[Callable[[str, float], None]] = None,
    on_finding: Optional[Callable[[Finding], None]] = None,
    finding_store: Optional[FindingStore] = None,
    scan_id: Optional[str] = None,
    scan_state: Optional[ScanState] = None,
    storage_dir: Optional[Path] = None,
) -> PhaseAgent:
    """Factory function to get the appropriate agent for a phase."""
    agents = {
        Phase.RECON: ReconAgent,
        Phase.DISCOVERY: DiscoveryAgent,
        Phase.VULN_SCAN: VulnScanAgent,
        Phase.VALIDATION: ValidationAgent,
        Phase.REPORTING: ReportingAgent,
    }

    agent_class = agents.get(phase)
    if not agent_class:
        raise ValueError(f"No agent found for phase: {phase}")

    return agent_class(
        transport, parsers, on_progress, on_finding, finding_store, scan_id, scan_state, storage_dir
    )
