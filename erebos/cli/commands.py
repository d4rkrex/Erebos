"""CLI commands for Erebos."""

import json
import logging
import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from typing import Dict, List, Optional, Tuple

from erebos.config import get_settings
from erebos.core.finding import Finding
from erebos.core.target_profile import TargetProfile, TargetProfiler
from erebos.core.orchestrator import Orchestrator
from erebos.core.scan_profile import PROFILES, get_profile
from erebos.enrichment.http_probe import HttpProbeResult, HttpProbeService
from erebos.executors.tool_discovery import get_tool_discovery
from erebos.parsers.nmap import NmapScanResult, PortInfo
from erebos.reporting import MarkdownReportBuilder
from erebos.security import AllowlistValidator
from erebos.storage import FindingStore, ScanStateManager

logger = logging.getLogger(__name__)
console = Console()


def _parse_targets(target_string: str) -> List[str]:
    """Parse comma-separated target string into list of targets."""
    return [t.strip() for t in target_string.split(",") if t.strip()]


def _parse_target_file(file_path: str) -> List[str]:
    """Parse target file - one target per line, comments start with #."""
    targets = []
    path = Path(file_path)
    if not path.exists():
        raise ValueError(f"Target file not found: {file_path}")

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)

    if not targets:
        raise ValueError(f"No valid targets found in {file_path}")

    return targets


def _parse_profile_target(target: str) -> Tuple[str, List[Tuple[str, int]], Optional[str]]:
    """Normalize target input for lightweight TargetProfile probing."""
    if not target:
        raise ValueError("Target cannot be empty")

    if "://" in target:
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ValueError(f"Invalid target format: {target}")
        default_port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
        port = parsed.port or default_port
        probe_ports = [(parsed.hostname, port)] if port else []
        return parsed.hostname, probe_ports, parsed.scheme or None

    if ":" in target and target.count(":") == 1:
        host, port_str = target.rsplit(":", 1)
        if port_str.isdigit():
            return host, [(host, int(port_str))], None

    return target, [(target, 443), (target, 80)], None


def _build_manual_target_profile(target: str, timeout: float = 5.0) -> TargetProfile:
    """Build a lightweight TargetProfile without running the full scan pipeline."""
    host, probe_targets, scheme = _parse_profile_target(target)
    http_service = HttpProbeService(timeout=timeout)
    profiler = TargetProfiler(enable_profile=True)

    http_results: Dict[Tuple[str, int], HttpProbeResult] = {}
    ports: List[PortInfo] = []
    for probe_host, probe_port in probe_targets:
        result = http_service.probe(probe_host, probe_port)
        if result.is_http:
            http_results[(probe_host, probe_port)] = result
            service_name = "https" if result.is_https else "http"
            ports.append(
                PortInfo(
                    port=str(probe_port),
                    protocol="tcp",
                    state="open",
                    service=service_name,
                    product=result.server_banner or service_name,
                    host=probe_host,
                )
            )

    if not http_results and probe_targets:
        fallback_host, fallback_port = probe_targets[0]
        ports.append(
            PortInfo(
                port=str(fallback_port),
                protocol="tcp",
                state="filtered",
                service=scheme or "unknown",
                host=fallback_host,
            )
        )

    profile = profiler.create_profile(
        target,
        NmapScanResult(ports=ports),
        http_results=http_results,
        completed_phases=["manual-profile"],
    )
    if profile is None:
        raise RuntimeError("TargetProfile is disabled")
    return profile


def _render_target_profile_summary(profile: TargetProfile, scan_id: Optional[str] = None) -> str:
    """Render a concise terminal-friendly TargetProfile summary."""
    technologies = ", ".join(tech.name for tech in profile.technologies[:8]) or "None"
    services = (
        ", ".join(
            f"{service.port}/{service.protocol} {service.service}"
            for service in profile.services[:8]
        )
        or "None"
    )
    lines = [
        f"Target: {profile.target}",
        f"Host: {profile.host}",
        f"Type: {profile.target_type.value} ({profile.target_type_confidence:.2f})",
        f"Risk: {profile.risk_level.value} | Score: {profile.attack_surface_score:.2f}",
        f"Confidence: {profile.confidence:.2f}",
        f"Technologies: {technologies}",
        f"Services: {services}",
    ]
    if scan_id:
        lines.append(f"Scan ID: {scan_id}")
    return "\n".join(lines)


# Shell completion for Click
# These functions provide completion for different shells
def _get_phase_completion():
    """Return phase choices for completion."""
    return ["recon", "discovery", "vuln-scan", "validation", "all"]


def _get_profile_completion():
    """Return profile choices for completion."""
    return list(PROFILES.keys())


def _get_format_completion():
    """Return format choices for completion."""
    return ["markdown", "json"]


def _get_action_completion():
    """Return action choices for completion."""
    return ["get", "set", "list"]


def _get_allowlist_action_completion():
    """Return allowlist action choices for completion."""
    return ["add", "remove", "list"]


# Register shell completions using Click's built-in support
# The shell parameter receives one of: bash, zsh, fish, powershell
def _install_shell_completion(shell: str):
    """Install shell completion for the CLI."""
    if shell == "bash":
        # Bash completion is handled automatically by Click
        pass
    elif shell == "zsh":
        # Zsh completion
        pass
    elif shell == "fish":
        # Fish completion
        pass
    # PowerShell completion would require additional setup


class ErebosCLI:
    """Programmatic Erebos CLI interface for host integrations."""

    def scan(
        self,
        target: str,
        phase: Optional[str] = None,
        profile: str = "standard",
        dry_run: bool = False,
    ) -> dict:
        """Execute a scan (programmatic interface)."""
        targets = _parse_targets(target)
        if len(targets) > 1:
            return self.scan_multiple(targets, phase, profile, dry_run)

        target = targets[0]
        settings = get_settings()
        allowlist = AllowlistValidator(settings.security.allowlist)

        if not allowlist.is_allowed(target):
            return {
                "success": False,
                "error": f"Target '{target}' not in allowlist",
            }

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "message": f"Would scan {target} with profile '{profile}'",
            }

        storage_dir = Path("./erebos-storage")
        state_manager = ScanStateManager(storage_dir)
        finding_store = FindingStore(storage_dir)

        scan_state = state_manager.create_scan(target, profile)

        profile_obj = get_profile(profile)
        orchestrator = Orchestrator.create_for_scan(
            target=target,
            profile=profile_obj,
            scan_id=scan_state.scan_id,
            storage_dir=storage_dir,
        )

        success = orchestrator.run_scan()
        findings = orchestrator.get_findings()

        return {
            "success": success,
            "scan_id": scan_state.scan_id,
            "target": target,
            "profile": profile,
            "phase": phase or "all",
            "findings_count": len(findings),
        }

    def scan_multiple(
        self,
        targets: List[str],
        phase: Optional[str] = None,
        profile: str = "standard",
        dry_run: bool = False,
        parallel: bool = False,
    ) -> dict:
        """Execute scans on multiple targets."""
        settings = get_settings()
        allowlist = AllowlistValidator(settings.security.allowlist)

        valid_targets = []
        invalid_targets = []

        for target in targets:
            if allowlist.is_allowed(target):
                valid_targets.append(target)
            else:
                invalid_targets.append(target)

        if invalid_targets:
            return {
                "success": False,
                "error": f"Targets not in allowlist: {invalid_targets}",
                "invalid_targets": invalid_targets,
            }

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "message": f"Would scan {len(valid_targets)} targets with profile '{profile}'",
                "targets": valid_targets,
            }

        storage_dir = Path("./erebos-storage")
        state_manager = ScanStateManager(storage_dir)

        scan_ids = []
        results = {}
        for target in valid_targets:
            scan_state = state_manager.create_scan(target, profile)
            scan_ids.append(scan_state.scan_id)

            profile_obj = get_profile(profile)
            orchestrator = Orchestrator.create_for_scan(
                target=target,
                profile=profile_obj,
                scan_id=scan_state.scan_id,
                storage_dir=storage_dir,
            )
            success = orchestrator.run_scan()
            findings = orchestrator.get_findings()
            results[scan_state.scan_id] = {
                "success": success,
                "findings_count": len(findings),
            }

        return {
            "success": True,
            "scan_ids": scan_ids,
            "targets": valid_targets,
            "profile": profile,
            "phase": phase or "all",
            "results": results,
        }

    def status(self, scan_id: Optional[str] = None) -> dict:
        """Get scan status."""
        storage_dir = Path("./erebos-storage")
        state_manager = ScanStateManager(storage_dir)

        if scan_id:
            state = state_manager.load_state(scan_id)
            if state:
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "target": state.target,
                    "phase": state.current_phase,
                    "profile": state.profile,
                }
            return {"success": False, "error": f"Scan {scan_id} not found"}

        scans = state_manager.list_scans()
        return {"success": True, "scans": scans}

    def target_profile(self, target: str, save: bool = True) -> dict:
        """Build a lightweight TargetProfile outside the full scan flow."""
        settings = get_settings()
        if not settings.ai.enable_target_profile:
            return {"success": False, "error": "TargetProfile feature is disabled in config"}

        allowlist = AllowlistValidator(settings.security.allowlist)
        if not allowlist.is_allowed(target):
            return {"success": False, "error": f"Target '{target}' not in allowlist"}

        profile = _build_manual_target_profile(target)
        result = {
            "success": True,
            "target": target,
            "profile": profile.to_dict(),
            "summary": _render_target_profile_summary(profile),
        }

        if save:
            storage_dir = Path("./erebos-storage")
            state_manager = ScanStateManager(storage_dir)
            scan_state = state_manager.create_scan(target, "manual-profile")
            scan_state.target_profile = profile
            scan_state.phase_artifacts["target_profile"] = profile.to_dict()
            scan_state.phase_artifacts["profile_source"] = "manual-profile"
            state_manager.save_state(scan_state)
            result["scan_id"] = scan_state.scan_id
            result["summary"] = _render_target_profile_summary(profile, scan_state.scan_id)

        return result

    def report(self, scan_id: str, format: str = "markdown") -> dict:
        """Generate report."""
        storage_dir = Path("./erebos-storage")
        finding_store = FindingStore(storage_dir)

        findings = finding_store.get_findings(scan_id)
        if not findings:
            return {"success": False, "error": "No findings"}

        if format == "markdown":
            state_manager = ScanStateManager(storage_dir)
            state = state_manager.load_state(scan_id)
            target = state.target if state else "unknown"

            builder = MarkdownReportBuilder(
                target,
                scan_id,
                state.target_profile if state else None,
                state.phase_artifacts if state else None,
            )
            path = builder.build(findings)
            return {"success": True, "format": "markdown", "path": str(path)}

        return {
            "success": True,
            "format": "json",
            "findings": [f.model_dump(mode="json") for f in findings],
        }

    def config(self, action: str, key: Optional[str] = None, value: Optional[str] = None) -> dict:
        """Manage configuration."""
        settings = get_settings()

        if action == "get" and key:
            if hasattr(settings, key):
                return {"success": True, "key": key, "value": getattr(settings, key)}
            return {"success": False, "error": f"Unknown key: {key}"}

        if action == "set" and key and value:
            return {
                "success": False,
                "error": "Config persistence not yet implemented",
            }

        if action == "list":
            return {"success": True, "config": settings.model_dump(mode="json")}

        return {"success": False, "error": "Invalid config action"}

    def allowlist(self, action: str, target: Optional[str] = None) -> dict:
        """Manage allowlist."""
        settings = get_settings()
        allowlist = AllowlistValidator(settings.security.allowlist)

        if action == "list":
            return {"success": True, "allowlist": settings.security.allowlist}

        if action == "add" and target:
            allowlist.add(target)
            return {"success": True, "action": "add", "target": target}

        if action == "remove" and target:
            allowlist.remove(target)
            return {"success": True, "action": "remove", "target": target}

        return {"success": False, "error": "Invalid allowlist action"}

    def abort(self, scan_id: Optional[str] = None) -> dict:
        """Abort a scan."""
        if not scan_id:
            return {"success": False, "error": "scan_id required"}

        storage_dir = Path("./erebos-storage")
        state_manager = ScanStateManager(storage_dir)

        state = state_manager.load_state(scan_id)
        if state:
            state.current_phase = "aborted"
            state_manager.save_state(state)
            return {"success": True, "scan_id": scan_id}

        return {"success": False, "error": f"Scan {scan_id} not found"}

    def tools(self) -> dict:
        """Check available tools."""
        discovery = get_tool_discovery()
        return {
            "success": True,
            "mvp_ready": discovery.is_mvp_ready(),
            "missing_tools": discovery.get_missing_tools(),
            "available_tools": discovery.get_available_tools(),
            "summary": discovery.get_tool_info_summary(),
        }


def _run_scan(
    scan_state,
    profile,
    storage_dir: Path,
    console: Console,
    dast_mode: str = "full",
    base_path: str = "/",
) -> bool:
    """Execute the scan pipeline for a single target."""
    import asyncio

    profile_obj = get_profile(profile)
    finding_store = FindingStore(storage_dir)

    def on_progress(message: str, percent: float):
        progress_str = f"{message}"
        if percent > 0:
            console.print(f"  [blue][[/blue]{percent:5.1f}%] [green]{progress_str}[/green]")

    def on_finding(finding: Finding):
        finding_store.add_finding(scan_state.scan_id, finding)
        console.print(f"  [dim]>[/dim] [bold]{finding.severity}[/bold] {finding.title}")

    orchestrator = Orchestrator.create_for_scan(
        target=scan_state.target,
        profile=profile_obj,
        scan_id=scan_state.scan_id,
        storage_dir=storage_dir,
        on_progress=on_progress,
        on_finding=on_finding,
    )

    success = orchestrator.run_scan()

    # Run DAST pipeline after tool-based phases
    if dast_mode != "none":
        console.print()
        console.print(f"[cyan]🔥 DAST Pipeline[/cyan] (mode={dast_mode})")
        try:
            from erebos.executors.dast_pipeline import DastPipeline

            # VT-Spec: Extract recon URLs from orchestrator findings to feed DAST pipeline
            recon_urls: List[str] = []
            target_url = scan_state.target
            if not target_url.startswith("http"):
                target_url = f"https://{target_url}"
            # Apply base_path for white-hat scope restriction
            if base_path and base_path != "/":
                target_url = target_url.rstrip("/") + base_path.rstrip("/")

            # Scope check: only include URLs matching the target's hostname
            from urllib.parse import urlparse as _cli_urlparse

            target_host = _cli_urlparse(target_url).hostname

            for f in orchestrator.all_findings:
                # Extract from evidence.url
                if f.evidence and f.evidence.url:
                    parsed = _cli_urlparse(f.evidence.url)
                    if parsed.hostname == target_host:
                        recon_urls.append(f.evidence.url)
                # Extract from target field containing http URLs
                if f.target and f.target.startswith("http"):
                    parsed = _cli_urlparse(f.target)
                    if parsed.hostname == target_host:
                        recon_urls.append(f.target)

            # Deduplicate while preserving order
            recon_urls = list(dict.fromkeys(recon_urls))

            if recon_urls:
                console.print(f"  [dim]Feeding {len(recon_urls)} recon URLs into DAST[/dim]")

            pipeline = DastPipeline(mode=dast_mode, recon_urls=recon_urls)

            dast_results = asyncio.run(pipeline.run(target=target_url))

            dast_findings = dast_results.get("findings", [])
            if dast_findings:
                console.print(
                    f"  [green]DAST found {len(dast_findings)} findings "
                    f"(tokens chained: {dast_results.get('tokens_extracted', 0)})[/green]"
                )
                for finding in dast_findings:
                    on_finding(finding)
                orchestrator.all_findings.extend(dast_findings)
            else:
                console.print("  [dim]DAST: 0 additional findings[/dim]")
        except Exception as e:
            console.print(f"  [yellow]DAST pipeline error: {e}[/yellow]")
            logger.warning("DAST pipeline failed: %s", e, exc_info=True)

    return success


@click.group()
def cli():
    """Erebos - CLI-based pentest orchestration agent."""
    pass


# Register dashboard command
from erebos.dashboard.cli import dashboard  # noqa: E402

cli.add_command(dashboard)


@cli.command()
@click.argument("target")
@click.option("--phase", default="all", help="Phase to run: recon, vuln-scan, exploit, all")
@click.option(
    "--profile",
    default="standard",
    help="Scan profile: minimal, standard, comprehensive, web-only, vuln-focused",
)
@click.option("--dry-run", is_flag=True, help="Simulate without executing tools")
@click.option("--parallel", is_flag=True, help="Run scans in parallel (for multiple targets)")
@click.option("-w", "--workspace", default=None, help="Named workspace for pause/resume")
@click.option(
    "--repo",
    multiple=True,
    type=click.Path(exists=True),
    help="Source repo path for code-aware exploitation (can be repeated)",
)
@click.option("--fleet", is_flag=True, help="Enable fleet mode (parallel agents)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress live display, print JSON summary only")
@click.option(
    "--source", type=click.Path(exists=True), help="Source code path for white-hat SAST analysis"
)
@click.option(
    "--ingest",
    type=click.Path(exists=True),
    help="Ingest external findings file (SARIF, Fortify FPR, Burp XML, Semgrep JSON, CSV)",
)
@click.option(
    "--ingest-format",
    "ingest_format",
    type=click.Choice(["auto", "sarif", "fortify", "burp", "semgrep", "csv", "native"]),
    default="auto",
    help="Format of ingested findings",
)
@click.option(
    "--report-format",
    "report_format",
    type=click.Choice(["md", "html", "json"]),
    default="md",
    help="Report output format",
)
@click.option("--trust-rules", is_flag=True, help="Trust custom Semgrep rules (EXEC-01 override)")
@click.option("--redact-paths", is_flag=True, help="Redact file paths in reports (INJ-03)")
@click.option(
    "--dast-mode",
    "dast_mode",
    type=click.Choice(["fast", "nuclei", "deep", "full"]),
    default="full",
    help="DAST execution depth: fast (pattern only), nuclei (templates), deep (LLM), full (all)",
)
@click.option(
    "--base-path",
    "base_path",
    default="/",
    help="Restrict scanning to this URL path prefix (white-hat scope, e.g. /api/v2/)",
)
@click.option(
    "--osint",
    "osint",
    is_flag=True,
    help="Include passive OSINT recon (subfinder, gau, waybackurls) before active scanning",
)
@click.option(
    "--osint-only",
    "osint_only",
    is_flag=True,
    help="Run only passive OSINT — no active scanning, no packets sent to target",
)
@click.option(
    "--auth-header",
    "auth_header",
    default=None,
    help="Inject auth header into all tools (e.g. 'Authorization: Bearer ey...')",
)
@click.option(
    "--auth-cookie",
    "auth_cookie",
    default=None,
    help="Inject session cookie into all tools (e.g. 'session_id=abc123')",
)
@click.option(
    "--auth-profile",
    "auth_profile",
    type=click.Path(exists=True),
    default=None,
    help="Path to auth profile YAML (supports bearer, basic, cookie, form-login)",
)
def scan(
    target: str,
    phase: str,
    profile: str,
    dry_run: bool,
    parallel: bool,
    workspace: str,
    repo: tuple,
    fleet: bool,
    quiet: bool,
    source: Optional[str],
    ingest: Optional[str],
    ingest_format: str,
    report_format: str,
    trust_rules: bool,
    redact_paths: bool,
    dast_mode: str,
    base_path: str,
    osint: bool,
    osint_only: bool,
    auth_header: Optional[str],
    auth_cookie: Optional[str],
    auth_profile: Optional[str],
):
    """Run a pentest scan on target.

    Supports comma-separated targets:
        erebos scan example.com,test.com

    For batch scanning from file, use 'scan-batch' command.
    """
    settings = get_settings()
    allowlist = AllowlistValidator(settings.security.allowlist)

    targets = _parse_targets(target)

    valid_targets = []
    invalid_targets = []
    for t in targets:
        if allowlist.is_allowed(t):
            valid_targets.append(t)
        else:
            invalid_targets.append(t)

    if invalid_targets:
        console.print(f"[red]Error:[/red] Targets not in allowlist: {invalid_targets}")
        console.print("Add them with: erebos allowlist add <target>")
        return

    if not valid_targets:
        console.print("[red]Error:[/red] No valid targets provided")
        return

    # VT-Spec R3: Source analysis integration (opt-in via --source)
    source_analysis_result = None
    if source:
        from erebos.analysis.source_analyzer import SourceAnalyzer

        console.print(f"[cyan]🔍 Source analysis:[/cyan] Analyzing {source}")
        # VT-Spec EXEC-01: Only trust custom rules if --trust-rules provided
        analyzer = SourceAnalyzer(
            source_path=Path(source),
            allowlist=settings.security.allowlist,
            trust_rules=trust_rules,
        )
        source_analysis_result = analyzer.analyze()
        console.print(
            f"  Routes: {len(source_analysis_result.routes)}, SAST findings: {len(source_analysis_result.sast_findings)}"
        )

    # VT-Spec R1: Findings ingestion integration (opt-in via --ingest)
    ingested_findings = None
    if ingest:
        from erebos.ingestion.ingester import FindingsIngester

        console.print(f"[cyan]📥 Ingesting findings:[/cyan] {ingest}")
        # VT-Spec SCOPE-01: AllowlistValidator on all ingested finding URLs
        ingester = FindingsIngester(allowlist=settings.security.allowlist)
        fmt_hint = ingest_format if ingest_format != "auto" else None
        ingest_result = ingester.ingest(Path(ingest), format_hint=fmt_hint)
        ingested_findings = ingest_result.findings
        console.print(
            f"  Format: {ingest_result.format_detected}, "
            f"Accepted: {ingest_result.accepted}, Rejected: {ingest_result.rejected}"
        )

    # Fleet mode — spawn parallel agents
    if fleet:
        from erebos.agents.orchestrator import FleetConfig as _FleetConfig, FleetOrchestrator

        # Resolve osint mode
        osint_mode = "only" if osint_only else ("full" if osint else "none")

        # VT-Spec AUTH-01: Build auth context from CLI flags / profile
        _auth_ctx = None
        if auth_header or auth_cookie or auth_profile:
            from erebos.auth import AuthContext, AuthCredential, AuthType, load_auth_profile

            _auth_ctx = AuthContext(allowlist=settings.security.allowlist)
            if auth_profile:
                try:
                    creds = load_auth_profile(Path(auth_profile))
                    for cred in creds:
                        _auth_ctx.add_static(cred)
                    console.print(
                        f"[cyan]🔐 Auth:[/cyan] Loaded {len(creds)} credential(s) from profile"
                    )
                except (PermissionError, ValueError) as e:
                    console.print(f"[red]Auth error:[/red] {e}")
                    return
            if auth_header:
                parts = auth_header.split(":", 1)
                if len(parts) == 2:
                    _auth_ctx.add_static(
                        AuthCredential(
                            auth_type=AuthType.CUSTOM_HEADER,
                            header_name=parts[0].strip(),
                            header_value=parts[1].strip(),
                        )
                    )
                else:
                    console.print("[red]Error:[/red] --auth-header format: 'Header-Name: value'")
                    return
            if auth_cookie:
                cookies = {}
                for pair in auth_cookie.split(";"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        cookies[k.strip()] = v.strip()
                _auth_ctx.add_static(
                    AuthCredential(
                        auth_type=AuthType.COOKIE,
                        cookies=cookies,
                    )
                )
            if _auth_ctx.has_auth:
                console.print("[cyan]🔐 Authenticated scanning:[/cyan] enabled")

        fleet_cfg = _FleetConfig(
            target=valid_targets[0],
            repos=[Path(r) for r in repo] if repo else [],
            allowlist=settings.security.allowlist,
            dry_run=dry_run,
            max_agents=settings.fleet.max_agents,
            findings_bus_path=Path(
                f"./erebos-storage/{valid_targets[0].replace('.', '-')}-"
                f"{int(__import__('time').time())}/findings-bus.jsonl"
            ),
            source_path=Path(source) if source else None,
            trust_rules=trust_rules,
            report_format=report_format,
            redact_paths=redact_paths,
            base_path=base_path,
            osint_mode=osint_mode,
            auth_context=_auth_ctx,
        )
        console.print(
            f"[bold cyan]🐝 Fleet mode:[/bold cyan] Spawning agents for {valid_targets[0]}"
        )
        if repo:
            console.print(f"  Repos: {list(repo)}")

        orch = FleetOrchestrator(fleet_cfg)

        # VT-Spec R1: Inject ingested findings into bus before scan starts
        if ingested_findings:
            from erebos.agents.base import AgentMessage, AgentRole

            for idx, finding in enumerate(ingested_findings):
                orch.bus.publish(
                    AgentMessage(
                        id=f"ingested-{idx}",
                        role=AgentRole.VULN_SCAN,
                        message_type="finding",
                        payload=finding.model_dump(mode="json"),
                    )
                )
            console.print(f"  Injected {len(ingested_findings)} findings into fleet bus")

        # VT-Spec R3/R9: Inject source analysis findings into bus
        if source_analysis_result and source_analysis_result.sast_findings:
            from erebos.agents.base import AgentMessage, AgentRole
            from erebos.core.finding import Finding, Phase

            for idx, sast in enumerate(source_analysis_result.sast_findings):
                finding = Finding(
                    id=f"sast-{idx}",
                    title=f"SAST: {sast.message}",
                    description=f"[{sast.check_id}] {sast.message} in {sast.file}:{sast.line}",
                    severity=sast.severity.value
                    if hasattr(sast.severity, "value")
                    else sast.severity,
                    phase_found=Phase.VULN_SCAN,
                    target=valid_targets[0] + ("/" + sast.file if sast.file else ""),
                    cwe=sast.cwe,
                    tool="semgrep",
                )
                orch.bus.publish(
                    AgentMessage(
                        id=f"sast-{idx}",
                        role=AgentRole.VULN_SCAN,
                        message_type="finding",
                        payload=finding.model_dump(mode="json"),
                    )
                )
            console.print(
                f"  Injected {len(source_analysis_result.sast_findings)} SAST findings into fleet bus"
            )

        if quiet:
            # AC-01.4: --quiet prints only JSON summary
            result = orch.run_sync()
            click.echo(json.dumps(result, default=str))
            return

        # AC-01.1/AC-01.2: Rich Live table showing agent progress
        from rich.live import Live

        _MAX_DISPLAY_FINDINGS = 20  # DOS-01: limit live display rows

        def _build_fleet_table(orch_ref: FleetOrchestrator) -> Table:
            """Build Rich table of agent status."""
            table = Table(title="🐝 Fleet Status", show_lines=False)
            table.add_column("Role", style="cyan", width=12)
            table.add_column("Status", width=10)
            table.add_column("Findings", justify="right", width=9)
            table.add_column("Duration", justify="right", width=10)
            for w in orch_ref._workers:
                status_style = {
                    "pending": "dim",
                    "running": "yellow",
                    "completed": "green",
                    "failed": "red",
                }.get(w.status.value, "white")
                dur = ""
                if w.started_at:
                    from datetime import datetime, timezone

                    end = w.completed_at or datetime.now(timezone.utc)
                    elapsed = (end - w.started_at).total_seconds()
                    dur = f"{elapsed:.1f}s"
                table.add_row(
                    w.role.value,
                    f"[{status_style}]{w.status.value}[/{status_style}]",
                    str(w.findings_count),
                    dur,
                )
            return table

        import asyncio

        async def _run_fleet_with_live():
            task = asyncio.create_task(orch.run())
            with Live(_build_fleet_table(orch), console=console, refresh_per_second=2) as live:
                while not task.done():
                    await asyncio.sleep(0.5)
                    live.update(_build_fleet_table(orch))
                live.update(_build_fleet_table(orch))
            return await task

        result = asyncio.run(_run_fleet_with_live())

        # AC-01.3: Final summary by severity
        console.print()
        console.print(
            f"[green]✓ Fleet complete:[/green] {result['completed']}/{result['agents']} agents in {result['duration_ms']:.0f}ms"
        )
        findings_count = result.get("total_findings", 0)
        if findings_count > 0:
            console.print(f"  Total findings: {findings_count}")
            # ID-01: Truncate titles to 80 chars, show max 20
            bus_findings = (
                [m for m in orch._bus._messages if m.get("message_type") == "finding"]
                if hasattr(orch._bus, "_messages")
                else []
            )
            shown = bus_findings[:_MAX_DISPLAY_FINDINGS]
            for f in shown:
                title = f.get("payload", {}).get("title", "")[:80]  # ID-01
                sev = f.get("payload", {}).get("severity", "?")
                console.print(f"    [{sev}] {title}")
            if len(bus_findings) > _MAX_DISPLAY_FINDINGS:
                console.print(f"    ... and {len(bus_findings) - _MAX_DISPLAY_FINDINGS} more")
        return

    if dry_run:
        console.print(
            f"[yellow]DRY RUN:[/yellow] Would scan {len(valid_targets)} target(s) with profile '{profile}'"
        )
        for t in valid_targets:
            console.print(f"  - {t}")
        return

    storage_dir = Path("./erebos-storage")
    state_manager = ScanStateManager(storage_dir)

    if len(valid_targets) == 1:
        console.print(
            f"[blue]Starting scan on {valid_targets[0]} with profile '{profile}'...[/blue]"
        )
        console.print()

        scan_state = state_manager.create_scan(valid_targets[0], profile)
        console.print(f"[green]Scan ID: {scan_state.scan_id}[/green]")
        console.print()

        try:
            success = _run_scan(
                scan_state, profile, storage_dir, console, dast_mode=dast_mode, base_path=base_path
            )
            if success:
                console.print()
                console.print(f"[green]Scan {scan_state.scan_id} completed successfully[/green]")
            else:
                console.print()
                console.print(f"[yellow]Scan {scan_state.scan_id} completed with issues[/yellow]")
        except Exception as e:
            console.print(f"[red]Scan failed: {e}[/red]")
            import traceback

            traceback.print_exc()
        return
    else:
        if parallel:
            console.print(f"[blue]Running {len(valid_targets)} scans in parallel...[/blue]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning targets...", total=len(valid_targets))

                def run_single_scan(t):
                    sm = ScanStateManager(storage_dir)
                    state = sm.create_scan(t, profile)
                    try:
                        success = _run_scan(
                            state,
                            profile,
                            storage_dir,
                            console,
                            dast_mode=dast_mode,
                            base_path=base_path,
                        )
                        return state, success, None
                    except Exception as e:
                        return state, False, str(e)

                with ThreadPoolExecutor(max_workers=min(len(valid_targets), 5)) as executor:
                    futures = {executor.submit(run_single_scan, t): t for t in valid_targets}
                    completed = 0
                    for future in as_completed(futures):
                        target = futures[future]
                        try:
                            scan_state, success, error = future.result()
                            if success:
                                console.print(
                                    f"  [green]✓[/green] {target} -> {scan_state.scan_id}"
                                )
                            else:
                                console.print(
                                    f"  [yellow]⚠[/yellow] {target} -> {scan_state.scan_id} (issues)"
                                )
                        except Exception as e:
                            console.print(f"  [red]✗[/red] {target} -> {e}")
                        completed += 1
                        progress.update(task, completed=completed)
        else:
            for t in valid_targets:
                console.print(f"[blue]Starting scan on {t}...[/blue]")
                scan_state = state_manager.create_scan(t, profile)
                console.print(f"[green]Scan ID: {scan_state.scan_id}[/green]")
                try:
                    success = _run_scan(
                        scan_state,
                        profile,
                        storage_dir,
                        console,
                        dast_mode=dast_mode,
                        base_path=base_path,
                    )
                    if success:
                        console.print(f"[green]Scan {scan_state.scan_id} completed[/green]")
                    else:
                        console.print(
                            f"[yellow]Scan {scan_state.scan_id} completed with issues[/yellow]"
                        )
                except Exception as e:
                    console.print(f"[red]Scan failed: {e}[/red]")
                console.print()


@cli.command("ingest")
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["auto", "sarif", "fortify", "burp", "semgrep", "csv", "native"]),
    default="auto",
    help="Format of findings file",
)
@click.option("--target", help="Target to scope findings against (uses allowlist)")
def ingest(file: str, fmt: str, target: Optional[str]):
    """Ingest external findings into Erebos for validation.

    VT-Spec R1: Accept findings from external scanners and normalize.
    VT-Spec SCOPE-01: All ingested finding URLs validated against allowlist.
    VT-Spec INJ-01: Sanitize all ingested fields at parse time.
    """
    settings = get_settings()
    allowlist = list(settings.security.allowlist)

    # If a target is provided, add it to the allowlist for scoping
    if target:
        allowlist.append(target)

    from erebos.ingestion.ingester import FindingsIngester

    # VT-Spec SCOPE-01: AllowlistValidator on all ingested finding URLs
    ingester = FindingsIngester(allowlist=allowlist)
    fmt_hint = fmt if fmt != "auto" else None
    result = ingester.ingest(Path(file), format_hint=fmt_hint)

    console.print("[green]✓ Ingestion complete[/green]")
    console.print(f"  Format detected: {result.format_detected}")
    console.print(f"  Total parsed: {result.total_parsed}")
    console.print(f"  Accepted (in-scope): {result.accepted}")
    console.print(f"  Rejected (out-of-scope): {result.rejected}")

    if result.findings:
        console.print("\n[cyan]Findings:[/cyan]")
        for f in result.findings[:20]:  # DOS-01: Cap display
            console.print(f"  [{f.severity}] {f.title[:80]}")
        if len(result.findings) > 20:
            console.print(f"  ... and {len(result.findings) - 20} more")


@cli.command("scan-batch")
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--profile",
    default="standard",
    help="Scan profile: minimal, standard, comprehensive, web-only, vuln-focused",
)
@click.option(
    "--concurrency",
    default=3,
    type=int,
    help="Number of parallel scans (default: 3)",
)
@click.option("--dry-run", is_flag=True, help="Simulate without executing tools")
def scan_batch(file_path: str, profile: str, concurrency: int, dry_run: bool):
    """Run pentest scans on targets from a file.

    File format: one target per line, lines starting with # are comments.

    Example:
        # targets.txt
        example.com
        test.com
        https://api.example.com

    Usage:
        erebos scan-batch targets.txt
        erebos scan-batch targets.txt --concurrency 5
    """
    try:
        targets = _parse_target_file(file_path)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        return

    settings = get_settings()
    allowlist = AllowlistValidator(settings.security.allowlist)

    valid_targets = []
    invalid_targets = []
    for t in targets:
        if allowlist.is_allowed(t):
            valid_targets.append(t)
        else:
            invalid_targets.append(t)

    if invalid_targets:
        console.print(
            f"[yellow]Warning:[/yellow] {len(invalid_targets)} target(s) not in allowlist: {invalid_targets}"
        )

    if not valid_targets:
        console.print("[red]Error:[/red] No valid targets to scan")
        return

    console.print(f"[blue]Found {len(valid_targets)} valid target(s) to scan[/blue]")

    if dry_run:
        console.print(
            f"[yellow]DRY RUN:[/yellow] Would scan {len(valid_targets)} target(s) with profile '{profile}'"
        )
        for t in valid_targets:
            console.print(f"  - {t}")
        return

    storage_dir = Path("./erebos-storage")
    state_manager = ScanStateManager(storage_dir)

    console.print(f"[blue]Starting scans with concurrency={concurrency}...[/blue]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"Scanning {len(valid_targets)} targets...", total=len(valid_targets)
        )

        def run_single_scan(t):
            sm = ScanStateManager(storage_dir)
            state = sm.create_scan(t, profile)
            try:
                success = _run_scan(
                    state, profile, storage_dir, console, dast_mode="full", base_path="/"
                )
                return state, success, None
            except Exception as e:
                return state, False, str(e)

        with ThreadPoolExecutor(max_workers=min(concurrency, len(valid_targets))) as executor:
            futures = {executor.submit(run_single_scan, t): t for t in valid_targets}
            completed = 0
            for future in as_completed(futures):
                target = futures[future]
                try:
                    scan_state, success, error = future.result()
                    if success:
                        console.print(f"  [green]✓[/green] {target} -> {scan_state.scan_id}")
                    else:
                        console.print(
                            f"  [yellow]⚠[/yellow] {target} -> {scan_state.scan_id} (issues)"
                        )
                except Exception as e:
                    console.print(f"  [red]✗[/red] {target} -> {e}")
                completed += 1
                progress.update(task, completed=completed)

    console.print(f"[green]Completed {len(valid_targets)} scan(s)[/green]")


@cli.command()
@click.option("--scan-id", help="Scan ID to check")
@click.option("--tools", is_flag=True, help="Show tool execution telemetry")
def status(scan_id: str, tools: bool):
    """Show scan status and tool telemetry."""
    storage_dir = Path("./erebos-storage")

    if scan_id:
        state_manager = ScanStateManager(storage_dir)
        state = state_manager.load_state(scan_id)
        if not state:
            console.print(f"[red]Scan {scan_id} not found[/red]")
            return

        # Header
        console.print(f"\n[bold]Scan {scan_id}[/bold]")
        console.print(f"  Target:  {state.target}")
        console.print(f"  Phase:   {state.current_phase}")
        console.print(f"  Profile: {state.profile}")
        console.print(f"  Started: {state.started_at}")

        # Finding summary
        findings = state.findings or []
        if findings:
            by_sev: dict = {}
            for f in findings:
                sev = (
                    f.get("severity", "UNKNOWN")
                    if isinstance(f, dict)
                    else getattr(f, "severity", "UNKNOWN")
                )
                by_sev[sev] = by_sev.get(sev, 0) + 1
            console.print(f"\n  [bold]Findings ({len(findings)} total):[/bold]")
            sev_colors = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "dim",
            }
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if sev in by_sev:
                    color = sev_colors.get(sev, "white")
                    console.print(f"    [{color}]{sev:10}[/{color}] {by_sev[sev]}")

        # Tool telemetry
        artifacts = state.phase_artifacts or {}
        tool_status = artifacts.get("tool_status", [])
        if tool_status or tools:
            console.print(f"\n  [bold]Tool Telemetry ({len(tool_status)} tools):[/bold]")
            if not tool_status:
                console.print("    [dim]No tool telemetry recorded[/dim]")
            else:
                for t in tool_status:
                    tool_name = t.get("tool", "?")
                    st = t.get("status", "?")
                    exit_code = t.get("exit_code", "?")
                    msg = t.get("message", "")[:80]

                    if st == "success":
                        icon = "[green]✓[/green]"
                    elif st == "failed":
                        icon = "[red]✗[/red]"
                    elif st == "degraded":
                        icon = "[yellow]~[/yellow]"
                    elif st == "skipped":
                        icon = "[dim]○[/dim]"
                    else:
                        icon = "?"

                    console.print(f"    {icon} {tool_name:15} {st:10} (exit {exit_code})")
                    if tools and msg:
                        console.print(f"      [dim]{msg}[/dim]")
        console.print()
    else:
        state_manager = ScanStateManager(storage_dir)
        scans = state_manager.list_scans()
        if scans:
            console.print("\n[bold]Scans:[/bold]")
            for scan in scans:
                console.print(f"  - {scan}")
            console.print()
        else:
            console.print("No active scans")


@cli.command("target-profile")
@click.argument("target")
@click.option("--format", "output_format", default="text", type=click.Choice(["text", "json"]))
@click.option(
    "--no-save", is_flag=True, help="Do not persist the generated profile to scan storage"
)
def target_profile_cmd(target: str, output_format: str, no_save: bool):
    """Build a lightweight TargetProfile for a single target."""
    result = ErebosCLI().target_profile(target, save=not no_save)
    if not result["success"]:
        console.print(f"[red]Error:[/red] {result['error']}")
        return

    if output_format == "json":
        console.print(json.dumps(result, indent=2, default=str))
        return

    console.print("[blue]Target Profile[/blue]")
    console.print(result["summary"])


@cli.command()
@click.option("--scan-id", required=True, help="Scan ID")
@click.option("--format", default="markdown", type=click.Choice(["markdown", "json"]))
def report(scan_id: str, format: str):
    """Generate report for a scan."""
    storage_dir = Path("./erebos-storage")
    finding_store = FindingStore(storage_dir)

    findings = finding_store.get_findings(scan_id)

    if not findings:
        console.print(f"[yellow]No findings for scan {scan_id}[/yellow]")
        return

    if format == "markdown":
        state_manager = ScanStateManager(storage_dir)
        state = state_manager.load_state(scan_id)
        target = state.target if state else "unknown"

        builder = MarkdownReportBuilder(
            target,
            scan_id,
            state.target_profile if state else None,
            state.phase_artifacts if state else None,
        )
        path = builder.build(findings)
        console.print(f"[green]Report saved to:[/green] {path}")
    else:
        console.print(json.dumps([f.model_dump() for f in findings], indent=2, default=str))


@cli.group()
def allowlist():
    """Manage target allowlist."""
    pass


@allowlist.command("add")
@click.argument("target")
def allowlist_add(target: str):
    """Add target to allowlist."""
    settings = get_settings()
    validator = AllowlistValidator(settings.security.allowlist)
    validator.add(target)
    console.print(f"[green]Added {target} to allowlist[/green]")


@allowlist.command("remove")
@click.argument("target")
def allowlist_remove(target: str):
    """Remove target from allowlist."""
    settings = get_settings()
    validator = AllowlistValidator(settings.security.allowlist)
    validator.remove(target)
    console.print(f"[green]Removed {target} from allowlist[/green]")


@allowlist.command("list")
def allowlist_list():
    """List all allowlist entries."""
    settings = get_settings()
    allowlist = settings.security.allowlist

    table = Table(title="Allowlist")
    table.add_column("Target")
    for entry in allowlist:
        table.add_row(entry)

    console.print(table)


@cli.group()
def config():
    """Manage configuration."""
    pass


@config.command("get")
@click.argument("key")
def config_get(key: str):
    """Get configuration value."""
    settings = get_settings()
    # Simple key lookup
    if hasattr(settings, key):
        value = getattr(settings, key)
        console.print(f"{key}: {value}")
    else:
        console.print(f"[red]Unknown key: {key}[/red]")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str):
    """Set configuration value."""
    console.print("[yellow]Config persistence not yet implemented[/yellow]")


@cli.command("tui")
@click.option(
    "--storage-dir",
    default="./erebos-storage",
    type=click.Path(),
    help="Path to erebos storage directory",
)
@click.option(
    "--refresh-interval",
    default=2,
    type=int,
    help="Auto-refresh interval in seconds (default: 2)",
)
@click.option(
    "--no-auto-refresh",
    is_flag=True,
    help="Disable auto-refresh",
)
def tui(storage_dir: str, refresh_interval: int, no_auto_refresh: bool):
    """Launch the TUI for scan monitoring.

    The TUI provides an interactive terminal interface to:
    - View all active scans
    - See findings by severity and phase
    - Monitor tool execution status
    - Filter and search findings

    Keyboard shortcuts:
      1/2/3    Switch screens
      r        Refresh data
      j/k      Navigate lists
      q        Quit

    Examples:
        erebos tui
        erebos tui --storage-dir /path/to/storage
        erebos tui --refresh-interval 5
        erebos tui --no-auto-refresh
    """
    try:
        from erebos.tui.app import run_tui
    except ImportError:
        console.print("[red]Error:[/red] TUI requires the 'textual' package.")
        console.print("Install it with: pip install textual")
        console.print("Or add it to your pyproject.toml dependencies.")
        return

    try:
        run_tui(
            storage_dir=storage_dir,
            refresh_interval=refresh_interval,
            auto_refresh=not no_auto_refresh,
        )
    except Exception as e:
        console.print(f"[red]TUI Error:[/red] {e}")
        console.print("Make sure you are running in a terminal that supports")
        console.print("cursor movement and ANSI colors.")


@cli.command()
@click.option("--scan-id", required=True, help="Scan ID to abort")
def abort(scan_id: str):
    """Abort a running scan."""
    storage_dir = Path("./erebos-storage")
    state_manager = ScanStateManager(storage_dir)

    state = state_manager.load_state(scan_id)
    if state:
        state.current_phase = "aborted"
        state_manager.save_state(state)
        console.print(f"[green]Aborted scan {scan_id}[/green]")
    else:
        console.print(f"[red]Scan {scan_id} not found[/red]")


@cli.command()
def tools():
    """Check available security tools."""
    discovery = get_tool_discovery()

    console.print(discovery.get_tool_info_summary())

    if discovery.is_mvp_ready():
        console.print("\n[green]MVP ready - all required tools available[/green]")
    else:
        console.print("\n[red]MVP not ready - missing required tools[/red]")


@cli.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell: str):
    """Generate shell completion scripts.

    Examples:
        # Bash - add to ~/.bashrc
        erebos completion bash >> ~/.bashrc

        # Zsh - add to ~/.zshrc
        erebos completion zsh >> ~/.zshrc

        # Fish - automatically loaded
        erebos completion fish > ~/.config/fish/completions/erebos.fish
    """
    if shell == "bash":
        script = _get_bash_completion()
    elif shell == "zsh":
        script = _get_zsh_completion()
    else:  # fish
        script = _get_fish_completion()

    console.print(script)


def _get_bash_completion() -> str:
    """Generate bash completion script."""
    return """# Erebos CLI bash completion
_erebos_complete() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="scan status report target-profile allowlist config abort tools completion"

    case "${prev}" in
        scan)
            COMPREPLY=($(compgen -f -- ${cur}))
            return 0
            ;;
        --phase)
            COMPREPLY=($(compgen -W "recon discovery vuln-scan validation all" -- ${cur}))
            return 0
            ;;
        --profile)
            COMPREPLY=($(compgen -W "minimal standard comprehensive web-only vuln-focused" -- ${cur}))
            return 0
            ;;
        --format)
            COMPREPLY=($(compgen -W "markdown json" -- ${cur}))
            return 0
            ;;
        --scan-id)
            return 0
            ;;
        allowlist)
            COMPREPLY=($(compgen -W "add remove list" -- ${cur}))
            return 0
            ;;
        config)
            COMPREPLY=($(compgen -W "get set list" -- ${cur}))
            return 0
            ;;
        *)
            COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
            return 0
            ;;
    esac
}
complete -f -F _erebos_complete erebos
"""


def _get_zsh_completion() -> str:
    """Generate zsh completion script."""
    return """# Erebos CLI zsh completion
autoload -U compinit
compdef _erebos erebos

_erebos() {
    local -a opts
    opts=(
        "scan:Run a pentest scan"
        "status:Show scan status"
        "report:Generate report"
        "target-profile:Build a lightweight target profile"
        "allowlist:Manage target allowlist"
        "config:Manage configuration"
        "abort:Abort a running scan"
        "tools:Check available security tools"
        "completion:Generate shell completion scripts"
    )

    _describe 'command' opts
}
"""


def _get_fish_completion() -> str:
    """Generate fish completion script."""
    return """# Erebos CLI fish completion
complete -c erebos -f -a "scan status report target-profile allowlist config abort tools completion"

complete -c erebos -n "not __fish_seen_subcommand_from scan" -s phase -l phase -d "Phase to run" -a "recon discovery vuln-scan validation all"
complete -c erebos -n "not __fish_seen_subcommand_from scan" -s profile -l profile -d "Scan profile" -a "minimal standard comprehensive web-only vuln-focused"
complete -c erebos -n "not __fish_seen_subcommand_from scan" -s dry-run -l dry-run -d "Simulate without executing"
complete -c erebos -n "__fish_seen_subcommand_from report" -s format -l format -d "Report format" -a "markdown json"
complete -c erebos -n "__fish_seen_subcommand_from scan status report abort" -s scan-id -l scan-id -d "Scan ID"
complete -c erebos -n "__fish_seen_subcommand_from allowlist" -a "add remove list"
complete -c erebos -n "__fish_seen_subcommand_from config" -a "get set list"
complete -c erebos -n "__fish_seen_subcommand_from completion" -a "bash zsh fish"
"""


@cli.command("migrate-storage")
@click.option(
    "--dry-run", is_flag=True, help="Show what would be migrated without actually moving files"
)
@click.option("--rollback", is_flag=True, help="Rollback subdirectory structure to flat structure")
@click.option(
    "--storage-dir",
    type=click.Path(exists=True),
    default=None,
    help="Storage directory to migrate (defaults to ./erebos-storage)",
)
def migrate_storage_cmd(dry_run: bool, rollback: bool, storage_dir: str | None):
    """Migrate storage from flat structure to subdirectories.

    Converts old format:
        erebos-storage/
        ├── abc123_state.json
        └── abc123_findings.json

    To new format:
        erebos-storage/
        └── abc123/
            ├── state.json
            ├── findings.json
            └── raw/

    Use --dry-run to preview changes without modifying files.
    Use --rollback to revert subdirectories back to flat structure.

    Examples:
        erebos migrate-storage --dry-run
        erebos migrate-storage
        erebos migrate-storage --rollback
    """
    storage_path = Path(storage_dir if storage_dir else "./erebos-storage")
    migrate_storage(str(storage_path), dry_run, rollback)


def migrate_storage(storage_dir: str, dry_run: bool = False, rollback: bool = False):
    """Core migration logic that can be called from CLI or tests."""
    storage_path = Path(storage_dir)
    if not storage_path.exists():
        console.print(f"[red]Error:[/red] No storage directory found at {storage_path}")
        return

    if rollback:
        _rollback_migration(storage_path, dry_run)
    else:
        _migrate_to_subdirectories(storage_path, dry_run)


def _migrate_to_subdirectories(storage_dir: Path, dry_run: bool):
    """Migrate flat files to subdirectories."""
    state_files = list(storage_dir.glob("*_state.json"))

    if not state_files:
        console.print("[yellow]No legacy flat files found to migrate[/yellow]")
        return

    console.print(f"[blue]Found {len(state_files)} scan(s) to migrate[/blue]")

    migrated_count = 0
    skipped_count = 0
    error_count = 0

    for state_file in state_files:
        scan_id = state_file.stem.replace("_state", "")
        findings_file = storage_dir / f"{scan_id}_findings.json"

        # Target subdirectory
        scan_dir = storage_dir / scan_id

        # Skip if already migrated
        if scan_dir.exists() and (scan_dir / "state.json").exists():
            console.print(f"[dim]⊘ Skipping {scan_id} (already migrated)[/dim]")
            skipped_count += 1
            continue

        if dry_run:
            console.print(f"[cyan]Would migrate {scan_id}:[/cyan]")
            console.print(f"  [dim]→[/dim] Create: {scan_dir}/")
            console.print(f"  [dim]→[/dim] Move: {state_file.name} → {scan_dir}/state.json")
            if findings_file.exists():
                console.print(
                    f"  [dim]→[/dim] Move: {findings_file.name} → {scan_dir}/findings.json"
                )
            migrated_count += 1
        else:
            try:
                # Create subdirectory
                scan_dir.mkdir(parents=True, exist_ok=True)
                (scan_dir / "raw").mkdir(exist_ok=True)

                # Move files
                shutil.move(str(state_file), str(scan_dir / "state.json"))
                if findings_file.exists():
                    shutil.move(str(findings_file), str(scan_dir / "findings.json"))

                console.print(f"[green]✓[/green] Migrated scan {scan_id}")
                migrated_count += 1
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to migrate {scan_id}: {e}")
                error_count += 1
                continue

    # Print summary
    console.print()
    if dry_run:
        console.print("[cyan]Dry run complete:[/cyan]")
        console.print(f"  Would migrate: {migrated_count} scan(s)")
        console.print(f"  Would skip: {skipped_count} scan(s)")
        console.print()
        console.print("Run without --dry-run to apply changes.")
    else:
        console.print("[green]Migration complete:[/green]")
        console.print(f"  Migrated: {migrated_count} scan(s)")
        console.print(f"  Skipped: {skipped_count} scan(s)")
        if error_count > 0:
            console.print(f"  [yellow]Errors: {error_count} scan(s)[/yellow]")
            import sys

            sys.exit(1)


def _rollback_migration(storage_dir: Path, dry_run: bool):
    """Rollback subdirectories to flat structure."""
    scan_dirs = [d for d in storage_dir.iterdir() if d.is_dir()]

    if not scan_dirs:
        console.print("[yellow]No scan directories found to rollback[/yellow]")
        return

    console.print(f"[blue]Found {len(scan_dirs)} scan director(ies) to check[/blue]")

    rolled_back_count = 0
    skipped_count = 0
    error_count = 0

    for scan_dir in scan_dirs:
        scan_id = scan_dir.name
        state_file = scan_dir / "state.json"
        findings_file = scan_dir / "findings.json"

        if not state_file.exists():
            console.print(f"[dim]⊘ Skipping {scan_id} (no state.json found)[/dim]")
            skipped_count += 1
            continue

        # Check if flat files already exist
        flat_state = storage_dir / f"{scan_id}_state.json"
        if flat_state.exists():
            console.print(f"[dim]⊘ Skipping {scan_id} (flat structure already exists)[/dim]")
            skipped_count += 1
            continue

        if dry_run:
            console.print(f"[cyan]Would rollback {scan_id}:[/cyan]")
            console.print(
                f"  [dim]→[/dim] Move: {state_file.relative_to(storage_dir)} → {scan_id}_state.json"
            )
            if findings_file.exists():
                console.print(
                    f"  [dim]→[/dim] Move: {findings_file.relative_to(storage_dir)} → {scan_id}_findings.json"
                )
            console.print(f"  [dim]→[/dim] Remove: {scan_dir}/")
            rolled_back_count += 1
        else:
            try:
                # Move files back
                shutil.move(str(state_file), str(storage_dir / f"{scan_id}_state.json"))
                if findings_file.exists():
                    shutil.move(str(findings_file), str(storage_dir / f"{scan_id}_findings.json"))

                # Remove subdirectory (including raw/)
                shutil.rmtree(scan_dir)

                console.print(f"[green]✓[/green] Rolled back scan {scan_id}")
                rolled_back_count += 1
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to rollback {scan_id}: {e}")
                error_count += 1
                continue

    # Print summary
    console.print()
    if dry_run:
        console.print("[cyan]Dry run complete:[/cyan]")
        console.print(f"  Would rollback: {rolled_back_count} scan(s)")
        console.print(f"  Would skip: {skipped_count} scan(s)")
        console.print()
        console.print("Run without --dry-run to apply changes.")
    else:
        console.print("[green]Rollback complete:[/green]")
        console.print(f"  Rolled back: {rolled_back_count} scan(s)")
        console.print(f"  Skipped: {skipped_count} scan(s)")
        if error_count > 0:
            console.print(f"  [yellow]Errors: {error_count} scan(s)[/yellow]")
            import sys

            sys.exit(1)


if __name__ == "__main__":
    cli()


# --- Workspace commands (shannon-pipeline-upgrade) ---


@cli.command("workspaces")
def list_workspaces():
    """List all scan workspaces with status summary."""
    from erebos.storage.workspace import WorkspaceManager

    settings = get_settings()
    manager = WorkspaceManager(Path(settings.workspace.base_dir))
    sessions = manager.list_all()

    if not sessions:
        console.print("[dim]No workspaces found.[/dim]")
        return

    table = Table(title="Workspaces")
    table.add_column("Name", style="cyan")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Phases Done")
    table.add_column("Last Activity")

    for session in sessions:
        status_style = {
            "active": "yellow",
            "paused": "blue",
            "complete": "green",
            "aborted": "red",
        }.get(session.status, "white")

        table.add_row(
            session.name,
            session.target,
            f"[{status_style}]{session.status}[/{status_style}]",
            str(len(session.completed_phases)),
            session.updated_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


@cli.command("resume")
@click.option("-w", "--workspace", required=True, help="Workspace name (or prefix)")
@click.option("--profile", default="standard", help="Scan profile to use")
def resume_workspace(workspace: str, profile: str):
    """Resume a paused workspace scan."""
    from erebos.storage.workspace import WorkspaceManager

    settings = get_settings()
    manager = WorkspaceManager(Path(settings.workspace.base_dir))

    # Find workspace by prefix (user may omit random suffix)
    resolved = manager.find_by_prefix(workspace)
    if resolved is None:
        console.print(f"[red]Error:[/red] Workspace not found: {workspace}")
        return

    can_resume, invalidated = manager.can_resume(resolved)
    if not can_resume:
        console.print(
            f"[red]Error:[/red] Workspace '{resolved}' cannot be resumed (status: complete or aborted)"
        )
        return

    session = manager.load(resolved)

    if invalidated:
        console.print(
            f"[yellow]Warning:[/yellow] Re-running phases with missing deliverables: {invalidated}"
        )

    console.print(f"[blue]Resuming workspace '{resolved}'[/blue]")
    console.print(f"  Target: {session.target}")
    console.print(f"  Completed phases: {session.completed_phases}")
    console.print("  Resuming from next incomplete phase...")

    # Run scan with workspace context (skipping completed phases)
    storage_dir = Path("./erebos-storage")
    state_manager = ScanStateManager(storage_dir)
    scan_state = state_manager.create_scan(session.target, profile)

    try:
        success = _run_scan(scan_state, profile, storage_dir, console, dast_mode="full")
        if success:
            manager.set_status(resolved, "complete")
            console.print(f"[green]Workspace '{resolved}' completed[/green]")
        else:
            console.print(f"[yellow]Workspace '{resolved}' completed with issues[/yellow]")
    except Exception as e:
        manager.set_status(resolved, "paused")
        console.print(f"[red]Scan paused: {e}[/red]")


def _create_scan_handler(settings):
    """Create async scan handler that wraps the Fleet Orchestrator.

    Uses fire-and-forget pattern: returns scan_id immediately,
    runs fleet in background thread, tracks state for status/findings polling.
    """
    import threading
    import time
    from dataclasses import dataclass, field
    from typing import Dict

    # Storage base: use settings or env, fallback to ./erebos-storage
    _storage_base = Path(os.environ.get("EREBOS_STORAGE_DIR", "./erebos-storage"))
    if hasattr(settings, "storage") and hasattr(settings.storage, "base_dir"):
        _storage_base = Path(settings.storage.base_dir)

    @dataclass
    class ScanState:
        scan_id: str
        target: str
        profile: str
        status: str = "running"  # running | completed | error
        started_at: float = field(default_factory=time.time)
        finished_at: float = 0.0
        findings_count: int = 0
        findings_summary: Dict[str, int] = field(default_factory=dict)
        error: str = ""
        tool_status: list = field(default_factory=list)
        auth_header: str = ""
        auth_cookie: str = ""

    # Shared state across requests (thread-safe via GIL for simple reads/writes)
    active_scans: Dict[str, ScanState] = {}

    def _run_scan_background(scan_state: ScanState):
        """Run scan in background thread using Fleet Orchestrator (parallel agents)."""

        from erebos.agents.orchestrator import FleetConfig, FleetOrchestrator

        try:
            # Build auth context from MCP params
            auth_ctx = None
            if scan_state.auth_header or scan_state.auth_cookie:
                from erebos.auth import AuthContext, AuthCredential, AuthType

                auth_ctx = AuthContext(allowlist=settings.security.allowlist)
                if scan_state.auth_header:
                    parts = scan_state.auth_header.split(":", 1)
                    if len(parts) == 2:
                        auth_ctx.add_static(
                            AuthCredential(
                                auth_type=AuthType.CUSTOM_HEADER,
                                header_name=parts[0].strip(),
                                header_value=parts[1].strip(),
                            )
                        )
                if scan_state.auth_cookie:
                    cookies = {}
                    for pair in scan_state.auth_cookie.split(";"):
                        pair = pair.strip()
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            cookies[k.strip()] = v.strip()
                    if cookies:
                        auth_ctx.add_static(
                            AuthCredential(
                                auth_type=AuthType.COOKIE,
                                cookies=cookies,
                            )
                        )

            # Fleet mode: use profile pipeline (aggressive includes web-discovery + exploit)
            profile_roles = FleetConfig.PROFILE_PIPELINES.get(
                scan_state.profile,
                FleetConfig.PROFILE_PIPELINES["aggressive"],
            )
            config = FleetConfig(
                target=scan_state.target,
                roles=profile_roles,
                allowlist=settings.security.allowlist,
                max_agents=len(profile_roles),
                findings_bus_path=_storage_base / scan_state.scan_id / "findings-bus.jsonl",
                timeout_per_agent=1800.0,  # 30 min per agent
                auth_context=auth_ctx,
            )
            config.mcp_mode = True  # Host coding agent IS the LLM — skip internal cascade
            fleet = FleetOrchestrator(config)
            summary = fleet.run_sync()

            scan_state.findings_count = summary.get("total_findings", 0)
            scan_state.findings_summary = {}
            # Read finding severities from bus file
            for msg in fleet.bus.subscribe(message_types=["finding"]):
                sev = msg.payload.get("severity", "INFO")
                scan_state.findings_summary[sev] = scan_state.findings_summary.get(sev, 0) + 1

            scan_state.tool_status = [
                {"agent": w.get("id", ""), "role": w.get("role", ""), "status": w.get("status", "")}
                for w in summary.get("workers", [])
            ]
            scan_state.status = "completed"

            # VT-Spec AUTH-03: Build scan context advisory for host agents
            # This enables coding agents (Claude Code, Copilot CLI) to reason
            # about next steps without needing an internal LLM call
            try:
                from erebos.scanning.planner import (
                    ScanPlanner,
                    build_scan_context_from_findings,
                    PlannerMode,
                )

                findings_for_context = [
                    m.payload for m in fleet.bus.subscribe(message_types=["finding"])
                ]
                scan_context = build_scan_context_from_findings(
                    target=scan_state.target,
                    findings=findings_for_context,
                    base_url=f"https://{scan_state.target}",
                    auth_acquired=auth_ctx is not None and auth_ctx.has_auth,
                    auth_type="cookie"
                    if (auth_ctx and auth_ctx.get_cookies())
                    else ("bearer" if (auth_ctx and auth_ctx.get_headers()) else None),
                )
                planner = ScanPlanner()
                plan = planner.generate_plan(scan_context, mode=PlannerMode.ADVISORY)
                scan_state.scan_context = plan.context.to_dict()
                scan_state.advisory = plan.context.to_advisory_prompt()
            except Exception as ctx_err:
                logger.debug("Failed to build scan context advisory: %s", ctx_err)
                scan_state.scan_context = None
                scan_state.advisory = None

            # Persist state to storage
            import json

            storage_dir = _storage_base / scan_state.scan_id
            storage_dir.mkdir(parents=True, exist_ok=True)
            state_file = storage_dir / "state.json"
            findings_list = [m.payload for m in fleet.bus.subscribe(message_types=["finding"])]
            state_file.write_text(
                json.dumps(
                    {
                        "scan_id": scan_state.scan_id,
                        "target": scan_state.target,
                        "profile": scan_state.profile,
                        "current_phase": "complete",
                        "started_at": scan_state.started_at,
                        "fleet_id": summary.get("fleet_id", ""),
                        "duration_ms": summary.get("duration_ms", 0),
                        "findings": findings_list,
                        "phase_artifacts": {
                            "workers": summary.get("workers", []),
                            "tool_status": scan_state.tool_status,
                        },
                    },
                    indent=2,
                )
            )

        except Exception as e:
            scan_state.status = "error"
            scan_state.error = str(e)
        finally:
            scan_state.finished_at = time.time()

    async def _handle_scan(arguments: dict) -> dict:
        target = arguments.get("target", "")
        dry_run = arguments.get("dry_run", False)
        profile_name = arguments.get("profile", "standard")

        if not target:
            return {"error": "target is required"}

        # Validate target is in allowlist
        from erebos.security.scope import AllowlistValidator

        validator = AllowlistValidator(settings.security.allowlist)
        if not validator.is_allowed(target):
            return {"error": f"Target '{target}' not in security allowlist"}

        if dry_run:
            return {
                "status": "dry_run",
                "target": target,
                "profile": profile_name,
                "message": f"Would scan {target} with profile {profile_name}",
                "allowlist_check": "passed",
            }

        # Generate scan_id from target
        scan_id = target.replace(".", "-").replace("*", "w")[:16]

        # Check if already running
        if scan_id in active_scans and active_scans[scan_id].status == "running":
            s = active_scans[scan_id]
            elapsed = time.time() - s.started_at
            return {
                "status": "already_running",
                "scan_id": scan_id,
                "target": target,
                "elapsed_seconds": int(elapsed),
                "message": f"Scan already in progress ({int(elapsed)}s elapsed). Use 'status' tool to check.",
            }

        # Create state and launch background thread
        auth_header = arguments.get("auth_header", "")
        auth_cookie = arguments.get("auth_cookie", "")
        scan_state = ScanState(
            scan_id=scan_id,
            target=target,
            profile=profile_name,
            auth_header=auth_header,
            auth_cookie=auth_cookie,
        )
        active_scans[scan_id] = scan_state

        thread = threading.Thread(target=_run_scan_background, args=(scan_state,), daemon=True)
        thread.start()

        # VT-Spec AUTH-03: Build early advisory for host agents at launch time
        # Quick introspection so coding agents get context immediately
        launch_advisory = None
        try:
            from erebos.scanning.planner import PlannerMode, ScanContext, ScanPlanner

            # Build minimal context from what we know at launch
            has_auth = bool(auth_header or auth_cookie)
            ctx = ScanContext(
                target=target,
                base_url=target if target.startswith("http") else f"https://{target}",
                auth_acquired=has_auth,
                auth_type="cookie" if auth_cookie else ("header" if auth_header else None),
            )
            planner = ScanPlanner()
            plan = planner.generate_plan(ctx, mode=PlannerMode.ADVISORY)
            launch_advisory = plan.context.to_advisory_prompt()
        except Exception:
            pass

        result = {
            "status": "launched",
            "scan_id": scan_id,
            "target": target,
            "profile": profile_name,
            "message": f"Scan launched in background. Use 'status' tool with scan_id='{scan_id}' to check progress.",
        }
        if launch_advisory:
            result["advisory"] = launch_advisory
            result["hint"] = (
                "Use 'auth' tool with action='introspect' to discover login forms, "
                "then 'auth' with action='auto' to register+login before re-scanning "
                "with auth_cookie parameter for deeper coverage."
            )
        return result

    async def _handle_status(arguments: dict) -> dict:
        scan_id = arguments.get("scan_id", "")

        if scan_id and scan_id in active_scans:
            s = active_scans[scan_id]
            elapsed = (s.finished_at or time.time()) - s.started_at
            result = {
                "scan_id": s.scan_id,
                "target": s.target,
                "status": s.status,
                "elapsed_seconds": int(elapsed),
                "profile": s.profile,
            }
            if s.status == "completed":
                result["findings_count"] = s.findings_count
                result["findings_summary"] = s.findings_summary
                result["tool_status"] = s.tool_status
                # VT-Spec AUTH-03: Include scan context advisory for host agents
                result["scan_context"] = getattr(s, "scan_context", None)
                result["advisory"] = getattr(s, "advisory", None)
            elif s.status == "error":
                result["error"] = s.error
            return result

        # List all scans
        scans = []
        for sid, s in active_scans.items():
            elapsed = (s.finished_at or time.time()) - s.started_at
            scans.append(
                {
                    "scan_id": sid,
                    "target": s.target,
                    "status": s.status,
                    "elapsed_seconds": int(elapsed),
                    "findings_count": s.findings_count,
                }
            )
        return {"scans": scans, "total": len(scans)}

    # Return both handlers as a tuple — the caller will wire them
    _handle_scan._status_handler = _handle_status
    return _handle_scan


def _create_exploit_handler(settings):
    """Create the exploit tool handler for MCP."""

    async def _handle_exploit(arguments: dict) -> dict:
        target = arguments.get("target", "")
        finding_id = arguments.get("finding_id", "")
        cwe = arguments.get("cwe", "")

        if not finding_id or not target:
            return {"error": "finding_id and target are required"}

        # Validate target allowlist (extract hostname from URL)
        from urllib.parse import urlparse

        from erebos.security.scope import AllowlistValidator

        validator = AllowlistValidator(settings.security.allowlist)
        hostname = target
        if "://" in target or target.startswith("//"):
            parsed = urlparse(target)
            hostname = parsed.hostname or target

        if not validator.is_allowed(hostname):
            return {"error": f"Target '{hostname}' not in security allowlist"}

        # Build a synthetic finding for the exploit engine
        from erebos.core.finding import Finding, Phase, Severity

        finding = Finding(
            id=finding_id,
            title=f"Manual exploit: {cwe or 'unknown'} on {target}",
            severity=Severity.HIGH,
            source="mcp-exploit",
            tool="mcp-manual",
            phase_found=Phase.VULN_SCAN,
            target=target,
            cwe=cwe or None,
            description=f"Manual exploit request via MCP for {target}",
        )

        # Match template
        from erebos.exploits.template_engine import TemplateEngine

        engine = TemplateEngine()
        plan = engine.match(finding)

        if not plan:
            return {
                "status": "no_template",
                "finding_id": finding_id,
                "target": target,
                "cwe": cwe,
                "message": f"No exploit template matches CWE {cwe}. "
                "LLM cascade would generate a plan in aggressive mode.",
            }

        # Execute the plan
        from erebos.exploits.runner import ExploitRunner

        runner = ExploitRunner(
            allowlist=settings.security.allowlist,
            max_requests_per_second=10.0,
        )

        try:
            result = await runner.execute(
                plan=plan,
                target=target,
                finding_id=finding_id,
                cwe=cwe,
            )
            return {
                "status": "completed",
                "finding_id": finding_id,
                "target": target,
                "strategy": plan.strategy.value,
                "template_id": plan.template_id,
                "success": result.success,
                "exploit_status": result.status.value if result.status else "unknown",
                "evidence_count": len(result.evidence) if result.evidence else 0,
                "error": result.error,
            }
        except Exception as e:
            return {
                "status": "error",
                "finding_id": finding_id,
                "target": target,
                "error": str(e),
            }

    return _handle_exploit


@cli.command("mcp-serve")
@click.option("--port", default=None, type=int, help="TCP port (default: stdio)")
@click.option("--tools", default=None, help="Comma-separated tool names to expose (default: all)")
def mcp_serve(port: int, tools: str):
    """Start Erebos as an MCP server for code agent integration.

    By default uses stdio transport (for .mcp.json registration).
    Use --port for TCP transport.
    """
    import asyncio

    settings = get_settings()

    # AC-01 abuse case: validate allowlist before starting
    if not settings.security.allowlist:
        console.print("[red]Error:[/red] Cannot start MCP server without configured allowlist.")
        console.print("Add targets first: erebos allowlist add <target>")
        raise SystemExit(1)

    from erebos.agents.mcp_stdio import MCPStdioServer

    tool_filter = None
    if tools:
        tool_filter = [t.strip() for t in tools.split(",") if t.strip()]

    console.print("[bold cyan]🔌 Erebos MCP Server[/bold cyan]")
    console.print(f"  Allowlist: {len(settings.security.allowlist)} targets")
    if tool_filter:
        console.print(f"  Tools: {tool_filter}")
    else:
        console.print("  Tools: all")

    if port:
        # SSE/TCP transport mode
        from erebos.agents.mcp_sse import MCPSSEServer

        token = ""
        if hasattr(settings, "mcp") and hasattr(settings.mcp, "token"):
            token = settings.mcp.token or ""
        # Read token from env var or file
        import os

        env_token = os.environ.get("EREBOS_MCP_TOKEN", "")
        if env_token:
            token = env_token
        token_file = os.environ.get("EREBOS_MCP_TOKEN_FILE")
        if token_file and os.path.isfile(token_file):
            token = open(token_file).read().strip()

        ip_allowlist = []
        if hasattr(settings, "mcp") and hasattr(settings.mcp, "ip_allowlist"):
            ip_allowlist = settings.mcp.ip_allowlist

        console.print(f"  Transport: SSE on 0.0.0.0:{port}")
        console.print(f"\n[dim]Listening on :{port}... (Ctrl+C to stop)[/dim]")

        server = MCPSSEServer(
            token=token,
            host="0.0.0.0",
            port=port,
            ip_allowlist=ip_allowlist,
            security_allowlist=settings.security.allowlist,
            insecure=True,  # Docker port-binding to 127.0.0.1 provides network isolation
            on_scan=_create_scan_handler(settings),
            on_exploit=_create_exploit_handler(settings),
        )
        try:
            server.run()
        except KeyboardInterrupt:
            pass
    else:
        # Stdio transport mode
        console.print("  Transport: stdio")
        console.print("  Register in .mcp.json:")
        console.print('    {"erebos": {"command": "erebos", "args": ["mcp-serve"]}}')
        console.print("\n[dim]Listening on stdio... (Ctrl+C to stop)[/dim]")

        server = MCPStdioServer()
        try:
            asyncio.run(server.serve())
        except KeyboardInterrupt:
            pass


@cli.command("mcp-stdio")
def mcp_stdio_cmd():
    """Start MCP server in stdio mode (clean JSON-RPC, no UI output).

    Proxies scan/status/findings to the local SSE server (persistent state).
    Designed for remote invocation via SSH:
        ssh ar-appsec-01 docker exec -i erebos python -m erebos mcp-stdio
    """
    import asyncio
    import os
    import sys

    # Suppress all non-JSON output on stdout
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

    settings = get_settings()

    if not settings.security.allowlist:
        sys.stderr.write("Error: no allowlist configured\n")
        raise SystemExit(1)

    # Read token from env/file
    token = ""
    if hasattr(settings, "mcp") and hasattr(settings.mcp, "token"):
        token = settings.mcp.token or ""
    env_token = os.environ.get("EREBOS_MCP_TOKEN", "")
    if env_token:
        token = env_token
    token_file = os.environ.get("EREBOS_MCP_TOKEN_FILE")
    if token_file and os.path.isfile(token_file):
        token = open(token_file).read().strip()

    # Determine SSE server URL for proxying stateful operations
    sse_port = os.environ.get("EREBOS_SSE_PORT", "8443")
    sse_url = f"http://127.0.0.1:{sse_port}/mcp"

    from erebos.agents.mcp_stdio_proxy import MCPStdioProxy

    server = MCPStdioProxy(
        auth_token=token,
        sse_url=sse_url,
        security_allowlist=settings.security.allowlist,
    )
    try:
        asyncio.run(server.serve())
    except (KeyboardInterrupt, EOFError):
        pass


# ─── Control Plane Commands (REQ-009) ───────────────────────────────────────


@cli.command("engage")
@click.argument("target")
@click.option("--roe", type=click.Path(exists=True), help="Rules of Engagement YAML file")
@click.option("--policy", type=click.Path(exists=True), help="Policy YAML file")
@click.option("--dry-run", is_flag=True, help="Show derived policy without starting engagement")
@click.option("--name", default=None, help="Engagement name")
def engage_cmd(target: str, roe: str, policy: str, dry_run: bool, name: str):
    """Create and start an autonomous engagement against TARGET.

    TARGET can be an IP, CIDR, or hostname.
    Requires either --roe or --policy to define scope and rules.

    VT-Spec E-03: Mandatory --dry-run showing fully resolved policy.
    """
    from erebos.control.roe import parse_roe, derive_policy
    from erebos.control.policy import PolicyEngine
    from erebos.core.models import Engagement, Target

    if not roe and not policy:
        console.print("[red]Error: Either --roe or --policy must be specified[/red]")
        raise SystemExit(1)

    # Parse RoE and derive policy
    if roe:
        roe_path = Path(roe)
        try:
            roe_data = parse_roe(roe_path)
        except (ValueError, FileNotFoundError) as e:
            console.print(f"[red]RoE parse error: {e}[/red]")
            raise SystemExit(1)
        eng_policy = derive_policy(roe_data)
        engine = PolicyEngine(eng_policy)
    else:
        policy_path = Path(policy)
        try:
            engine = PolicyEngine.load_from_yaml(policy_path)
        except (ValueError, FileNotFoundError) as e:
            console.print(f"[red]Policy load error: {e}[/red]")
            raise SystemExit(1)
        eng_policy = engine.policy

    # VT-Spec E-03: --dry-run shows resolved policy
    if dry_run:
        console.print("\n[bold cyan]═══ Resolved Policy (Dry Run) ═══[/bold cyan]\n")
        table = Table(title="Policy Summary")
        table.add_column("Setting", style="bold")
        table.add_column("Value")
        table.add_row("Scope Targets", ", ".join(eng_policy.scope_targets))
        table.add_row("Excluded", ", ".join(eng_policy.scope_excluded))
        table.add_row("Max Depth", str(eng_policy.max_depth))
        table.add_row("Allowed Actions", ", ".join(eng_policy.allowed_action_classes))
        table.add_row("Time Budget (min)", str(eng_policy.time_budget_minutes))
        console.print(table)
        console.print("\n[dim]No engagement created (--dry-run mode)[/dim]")
        return

    # Create engagement
    eng_name = name or f"engage-{target}"
    engagement = Engagement(
        name=eng_name,
        targets=[Target(address=target)],
    )

    # Validate target is in scope
    if not engine.is_target_in_scope(target):
        console.print(f"[red]Error: Target '{target}' is not within policy scope[/red]")
        raise SystemExit(1)

    console.print(f"[green]✓ Engagement created: {engagement.id}[/green]")
    console.print(f"  Name: {eng_name}")
    console.print(f"  Target: {target}")
    console.print(f"  Phase: {engagement.phase.value}")
    console.print(f"  Allowed actions: {eng_policy.allowed_action_classes}")


@cli.command("approve")
@click.argument("request_id")
@click.option("--operator", default="operator", help="Operator identity")
def approve_cmd(request_id: str, operator: str):
    """Approve a pending action request."""
    from erebos.control.approval import ApprovalGate

    queue_dir = Path("./erebos-storage/approvals")
    hmac_secret = os.environ.get("EREBOS_HMAC_SECRET", "")
    if not hmac_secret:
        console.print("[red]Error: EREBOS_HMAC_SECRET environment variable required[/red]")
        raise SystemExit(1)

    gate = ApprovalGate(queue_dir, hmac_secret)
    try:
        result = gate.approve(request_id, approved_by=operator)
        console.print(f"[green]✓ Approved: {request_id}[/green]")
        console.print(f"  Action: {result.action_id}")
        console.print(f"  By: {operator}")
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise SystemExit(1)


@cli.command("reject")
@click.argument("request_id")
@click.option("--reason", required=True, help="Reason for rejection")
@click.option("--operator", default="operator", help="Operator identity")
def reject_cmd(request_id: str, reason: str, operator: str):
    """Reject a pending action request."""
    from erebos.control.approval import ApprovalGate

    queue_dir = Path("./erebos-storage/approvals")
    hmac_secret = os.environ.get("EREBOS_HMAC_SECRET", "")
    if not hmac_secret:
        console.print("[red]Error: EREBOS_HMAC_SECRET environment variable required[/red]")
        raise SystemExit(1)

    gate = ApprovalGate(queue_dir, hmac_secret)
    try:
        result = gate.reject(request_id, reason=reason, rejected_by=operator)
        console.print(f"[yellow]✗ Rejected: {request_id}[/yellow]")
        console.print(f"  Reason: {reason}")
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise SystemExit(1)


@cli.command("abort")
@click.argument("engagement_id")
@click.option("--reason", default="Manual abort via CLI", help="Abort reason")
def abort_engagement_cmd(engagement_id: str, reason: str):
    """Activate kill switch for an engagement (REQ-005).

    Immediately terminates all processes associated with the engagement.
    """
    from erebos.control.killswitch import KillSwitch
    from erebos.core.models import Engagement

    state_dir = Path("./erebos-storage/killswitch")
    ks = KillSwitch(state_dir)

    # Create minimal engagement for abort
    engagement = Engagement(id=engagement_id, name=f"abort-{engagement_id}")

    result = ks.activate(engagement, reason=reason)

    if result["verified"] or not result["errors"]:
        console.print(f"[red]⚡ Kill switch activated: {engagement_id}[/red]")
        console.print(f"  Reason: {reason}")
        if result["processes_killed"]:
            console.print(f"  Processes killed: {result['processes_killed']}")
        if result["tmux_sessions_destroyed"]:
            console.print(f"  Tmux sessions: {result['tmux_sessions_destroyed']}")
    else:
        console.print("[red]⚠ Kill switch activated with errors:[/red]")
        for err in result["errors"]:
            console.print(f"    - {err}")


# ─── Brain / Decision Loop Commands (Phase 1) ──────────────────────────────


@cli.group()
def brain():
    """Autonomous decision loop (OODA brain) commands."""
    pass


@brain.command("start")
@click.argument("engagement_id")
@click.option("--autonomous", is_flag=True, default=False, help="Full autonomous mode")
@click.option(
    "--max-iterations",
    type=int,
    default=None,
    help="Override max iterations budget",
)
@click.option(
    "--time-budget",
    type=int,
    default=None,
    help="Override time budget in seconds",
)
@click.option(
    "--max-actions",
    type=int,
    default=None,
    help="Override max actions per iteration",
)
def brain_start(
    engagement_id: str,
    autonomous: bool,
    max_iterations: Optional[int],
    time_budget: Optional[int],
    max_actions: Optional[int],
):
    """Start the autonomous OODA brain loop for an engagement.

    # VT-Spec E-02: CLI budget overrides capped at policy maximums
    """
    from erebos.brain.executor_bridge import ExecutorBridge
    from erebos.brain.hypothesis import HypothesisEngine
    from erebos.brain.llm import LLMReasoner
    from erebos.brain.loop_controller import LoopBudget, LoopController
    from erebos.brain.observer import Observer
    from erebos.brain.planner import Planner
    from erebos.brain.state_machine import EngagementStateMachine
    from erebos.control.approval import ApprovalGate
    from erebos.control.killswitch import KillSwitch
    from erebos.control.policy import Policy, PolicyEngine
    from erebos.control.scope import ScopeValidator
    from erebos.core.events import EventLog
    from erebos.core.models import (
        Engagement,
        EngagementPhase,
        EngagementStatus,
    )

    # Resolve HMAC secret
    hmac_secret = os.environ.get("EREBOS_HMAC_SECRET", "")
    if not hmac_secret:
        console.print("[red]Error: EREBOS_HMAC_SECRET environment variable required[/red]")
        raise SystemExit(1)

    # Load or create engagement (stub — in production, load from storage)
    storage_dir = Path("./erebos-storage")
    event_log = EventLog(storage_dir / "events" / f"{engagement_id}.jsonl", hmac_secret)

    # For now, create a minimal engagement context
    engagement = Engagement(
        id=engagement_id,
        name=f"brain-{engagement_id}",
        status=EngagementStatus.ACTIVE,
        phase=EngagementPhase.RECON,
    )

    # Validate engagement is active
    if engagement.status in (EngagementStatus.COMPLETED, EngagementStatus.ABORTED):
        console.print(
            f"[red]Error: Engagement {engagement_id} is {engagement.status.value} — cannot start brain[/red]"
        )
        raise SystemExit(1)

    # Build policy from RoE
    policy = Policy(
        allowed_action_classes=engagement.roe.allowed_action_classes,
        max_actions_per_phase=100,
        time_budget_minutes=60,
    )
    policy_engine = PolicyEngine(policy)

    # VT-Spec E-02: Cap CLI overrides at policy maximums
    budget = LoopBudget()
    if max_iterations is not None:
        # VT-Spec E-02: Cannot exceed policy max
        capped = min(max_iterations, policy.max_actions_per_phase)
        if max_iterations != capped:
            console.print(
                f"[yellow]⚠ VT-Spec E-02: max-iterations capped from {max_iterations} to {capped} (policy limit)[/yellow]"
            )
        budget.max_iterations = capped
    if time_budget is not None:
        # VT-Spec E-02: Cannot exceed policy time budget
        policy_seconds = policy.time_budget_minutes * 60
        capped = min(time_budget, policy_seconds)
        if time_budget != capped:
            console.print(
                f"[yellow]⚠ VT-Spec E-02: time-budget capped from {time_budget}s to {capped}s (policy limit)[/yellow]"
            )
        budget.wall_clock_budget = float(capped)
    if max_actions is not None:
        # VT-Spec E-02: Cap at reasonable limit
        capped = min(max_actions, 50)
        budget.max_actions_per_iteration = capped

    # Build components
    scope_validator = ScopeValidator(
        allowed_targets=engagement.roe.targets,
        excluded_targets=engagement.roe.excluded,
    )
    kill_switch = KillSwitch(storage_dir / "killswitch")
    approval_gate = ApprovalGate(storage_dir / "approvals", hmac_secret)

    observer = Observer(event_log=event_log)
    llm_reasoner = LLMReasoner(provider="stub")
    hypothesis_engine = HypothesisEngine(event_log=event_log, llm_reasoner=llm_reasoner)
    state_machine = EngagementStateMachine(engagement)
    planner = Planner(policy_engine, scope_validator, state_machine, event_log)
    executor_bridge = ExecutorBridge(
        scope_validator, policy_engine, approval_gate, kill_switch, event_log
    )

    loop_controller = LoopController(
        observer=observer,
        hypothesis_engine=hypothesis_engine,
        planner=planner,
        executor_bridge=executor_bridge,
        state_machine=state_machine,
        kill_switch=kill_switch,
        event_log=event_log,
        budget=budget,
    )

    console.print(f"[bold green]🧠 Starting brain loop for engagement {engagement_id}[/bold green]")
    console.print(f"  Mode: {'autonomous' if autonomous else 'supervised'}")
    console.print(
        f"  Budget: {budget.max_iterations} iterations, {budget.wall_clock_budget:.0f}s wall clock"
    )

    result = loop_controller.run(engagement)

    console.print("\n[bold]Brain loop completed:[/bold]")
    console.print(f"  Iterations: {result.iterations_completed}")
    console.print(f"  Observations: {result.total_observations}")
    console.print(f"  Actions: {result.total_actions}")
    console.print(f"  Final phase: {result.final_phase.value}")
    console.print(f"  Reason: {result.reason}")
    console.print(f"  Duration: {result.duration_seconds:.1f}s")
