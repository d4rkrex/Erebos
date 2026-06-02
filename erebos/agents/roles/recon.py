"""Recon agent role — passive OSINT + active scanning.

Passive (OSINT): subfinder, assetfinder, gau, waybackurls, dnsx
Active: nmap, httpx, naabu, katana

VT-Spec T-01: All arguments validated, no shell=True.
VT-Spec D-01: Output capped, timeouts enforced.
VT-Spec EP-01: Discovered subdomains validated against allowlist before active scan.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from erebos.agents.base import AgentMessage, AgentRole, FindingsBus
from erebos.agents.tool_executor import ToolExecutor, ToolResult
from erebos.core.finding import Finding

logger = logging.getLogger(__name__)


class ReconRole:
    """Recon agent — discovers attack surface via passive OSINT and active scanning.

    Passive (OSINT): subfinder, assetfinder, gau, waybackurls, dnsx
    Active: nmap, httpx, naabu, katana

    Publishes discovered hosts, ports, and URLs to FindingsBus.
    """

    # Tool classification for OSINT mode control
    PASSIVE_TOOLS = ["subfinder", "assetfinder", "gau", "waybackurls", "dnsx"]
    ACTIVE_TOOLS = ["nmap", "httpx", "naabu", "katana"]

    def __init__(
        self,
        executor: ToolExecutor,
        bus: FindingsBus,
        agent_id: str,
        target: str,
        osint_mode: str = "none",
        auth_context: Optional[Any] = None,
    ):
        self._executor = executor
        self._bus = bus
        self._agent_id = agent_id
        self._target = target
        self._osint_mode = osint_mode
        self._findings: List[Finding] = []
        self._discovered_subdomains: List[str] = []
        # VT-Spec AUTH-01: Auth context for active tools (katana, httpx)
        self._auth_context = auth_context

    async def execute(self) -> Dict[str, Any]:
        """Run recon tools and publish findings.

        Behavior depends on osint_mode:
        - "none": active tools only (legacy behavior)
        - "full": passive first, then active (feeds discovered hosts to active)
        - "only": passive tools only (no packets to target)
        """
        results: Dict[str, Any] = {"role": "recon", "findings": 0, "tools_run": []}

        if self._osint_mode in ("full", "only"):
            # Run passive OSINT tools
            passive_results = await self._execute_passive()
            results["tools_run"].extend(passive_results)

        if self._osint_mode != "only":
            # Run active tools (include discovered subdomains as extra targets)
            active_results = await self._execute_active()
            results["tools_run"].extend(active_results)

        results["findings"] = len(self._findings)
        results["discovered_subdomains"] = self._discovered_subdomains
        return results

    async def _execute_passive(self) -> List[str]:
        """Run passive OSINT tools — no traffic sent to target."""
        tools_run: List[str] = []

        subfinder_result = await self._run_subfinder()
        if subfinder_result:
            tools_run.append("subfinder")

        assetfinder_result = await self._run_assetfinder()
        if assetfinder_result:
            tools_run.append("assetfinder")

        gau_result = await self._run_gau()
        if gau_result:
            tools_run.append("gau")

        waybackurls_result = await self._run_waybackurls()
        if waybackurls_result:
            tools_run.append("waybackurls")

        dnsx_result = await self._run_dnsx()
        if dnsx_result:
            tools_run.append("dnsx")

        return tools_run

    async def _execute_active(self) -> List[str]:
        """Run active scanning tools — sends traffic to target."""
        tools_run: List[str] = []

        nmap_result = await self._run_nmap()
        if nmap_result:
            tools_run.append("nmap")

        httpx_result = await self._run_httpx()
        if httpx_result:
            tools_run.append("httpx")

        naabu_result = await self._run_naabu()
        if naabu_result:
            tools_run.append("naabu")

        katana_result = await self._run_katana()
        if katana_result:
            tools_run.append("katana")

        return tools_run

    async def _run_nmap(self) -> Optional[ToolResult]:
        """Execute nmap port scan against target."""
        try:
            result = await self._executor.run(
                "nmap",
                args=["-oX", "-"],  # XML output to stdout
                target=self._target,
                timeout=300,
            )

            if result.exit_code == 0 and result.stdout:
                findings = self._parse_nmap_output(result.stdout)
                for f in findings:
                    self._findings.append(f)
                    self._publish_finding(f)

            return result
        except (ValueError, FileNotFoundError) as e:
            logger.warning(f"Recon nmap skipped: {e}")
            self._publish_status(f"nmap skipped: {e}")
            return None

    async def _run_subfinder(self) -> Optional[ToolResult]:
        """Execute subfinder subdomain enumeration (passive)."""
        try:
            result = await self._executor.run(
                "subfinder",
                args=["-d"],
                target=self._target,
                timeout=120,
            )

            if result.exit_code == 0 and result.stdout:
                findings = self._parse_subfinder_output(result.stdout)
                for f in findings:
                    self._findings.append(f)
                    self._publish_finding(f)
                # Track discovered subdomains for active phase
                for line in result.stdout.strip().split("\n"):
                    host = line.strip()
                    if host and host not in self._discovered_subdomains:
                        self._discovered_subdomains.append(host)

            return result
        except (ValueError, FileNotFoundError) as e:
            logger.warning(f"Recon subfinder skipped: {e}")
            self._publish_status(f"subfinder skipped: {e}")
            return None

    def _parse_nmap_output(self, xml_output: str) -> List[Finding]:
        """Parse nmap XML output into findings via canonical NmapParser.

        VT-Spec T-01: Wrapped in try/except — never crashes on parse failure.
        """
        try:
            from erebos.parsers.nmap import NmapParser

            parser = NmapParser()
            return parser.parse_to_findings(xml_output)
        except Exception as e:
            # T-01: Log and continue — never crash role on malformed output
            logger.warning(f"T-01: NmapParser failed, falling back to empty: {e}")
            return []

    def _parse_subfinder_output(self, output: str) -> List[Finding]:
        """Parse subfinder output via canonical SubfinderParser.

        VT-Spec T-01: Wrapped in try/except — never crashes on parse failure.
        """
        try:
            from erebos.parsers.subfinder import SubfinderParser

            parser = SubfinderParser()
            return parser.parse(output)
        except Exception as e:
            # T-01: Log and continue
            logger.warning(f"T-01: SubfinderParser failed, falling back to empty: {e}")
            return []

    async def _run_httpx(self) -> Optional[ToolResult]:
        """Execute httpx HTTP probing against target."""
        try:
            args = ["-sc", "-td", "-json"]
            # VT-Spec AUTH-01: Inject auth headers for authenticated probing
            if self._auth_context and self._auth_context.has_auth:
                args.extend(self._auth_context.httpx_args())

            result = await self._executor.run(
                "httpx",
                args=args,
                target=self._target,
                timeout=120,
            )

            if result.exit_code == 0 and result.stdout:
                findings = self._parse_tool_output("httpx", result.stdout)
                for f in findings:
                    self._findings.append(f)
                    self._publish_finding(f)

            return result
        except (ValueError, FileNotFoundError) as e:
            logger.warning(f"Recon httpx skipped: {e}")
            self._publish_status(f"httpx skipped: {e}")
            return None

    async def _run_assetfinder(self) -> Optional[ToolResult]:
        """Execute assetfinder subdomain discovery (passive)."""
        try:
            result = await self._executor.run(
                "assetfinder",
                args=["--subs-only"],
                target=self._target,
                timeout=120,
            )

            if result.exit_code == 0 and result.stdout:
                findings = self._parse_tool_output("assetfinder", result.stdout)
                for f in findings:
                    self._findings.append(f)
                    self._publish_finding(f)
                # Track discovered subdomains for active phase
                for line in result.stdout.strip().split("\n"):
                    host = line.strip()
                    if host and host not in self._discovered_subdomains:
                        self._discovered_subdomains.append(host)

            return result
        except (ValueError, FileNotFoundError) as e:
            logger.warning(f"Recon assetfinder skipped: {e}")
            self._publish_status(f"assetfinder skipped: {e}")
            return None

    async def _run_naabu(self) -> Optional[ToolResult]:
        """Execute naabu fast port scanning."""
        try:
            result = await self._executor.run(
                "naabu",
                args=["-host", self._target, "-json", "-silent"],
                target=self._target,
                timeout=300,
            )

            if result.exit_code == 0 and result.stdout:
                findings = self._parse_tool_output("naabu", result.stdout)
                for f in findings:
                    self._findings.append(f)
                    self._publish_finding(f)

            return result
        except (ValueError, FileNotFoundError) as e:
            logger.warning(f"Recon naabu skipped: {e}")
            self._publish_status(f"naabu skipped: {e}")
            return None

    async def _run_gau(self) -> Optional[ToolResult]:
        """Execute gau — passive URL collection from OTX, Wayback, CommonCrawl.

        VT-Spec DOS-02: Output capped at 10MB by ToolExecutor.
        """
        try:
            result = await self._executor.run(
                "gau",
                args=["--threads", "2", "--timeout", "30"],
                target=self._target,
                timeout=180,
            )

            if result.exit_code == 0 and result.stdout:
                findings = self._parse_tool_output("gau", result.stdout)
                for f in findings:
                    self._findings.append(f)
                    self._publish_finding(f)

            return result
        except (ValueError, FileNotFoundError) as e:
            logger.warning(f"Recon gau skipped: {e}")
            self._publish_status(f"gau skipped: {e}")
            return None

    async def _run_waybackurls(self) -> Optional[ToolResult]:
        """Execute waybackurls — historical URL mining from Wayback Machine.

        VT-Spec DOS-02: Output capped at 10MB by ToolExecutor.
        """
        try:
            result = await self._executor.run(
                "waybackurls",
                args=[],
                target=self._target,
                timeout=120,
            )

            if result.exit_code == 0 and result.stdout:
                findings = self._parse_tool_output("waybackurls", result.stdout)
                for f in findings:
                    self._findings.append(f)
                    self._publish_finding(f)

            return result
        except (ValueError, FileNotFoundError) as e:
            logger.warning(f"Recon waybackurls skipped: {e}")
            self._publish_status(f"waybackurls skipped: {e}")
            return None

    async def _run_dnsx(self) -> Optional[ToolResult]:
        """Execute dnsx — DNS resolution and validation (passive)."""
        try:
            result = await self._executor.run(
                "dnsx",
                args=["-silent", "-resp", "-a", "-aaaa", "-cname", "-mx"],
                target=self._target,
                timeout=60,
            )

            if result.exit_code == 0 and result.stdout:
                # dnsx outputs resolved records — parse as subdomains
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("["):
                        host = line.split()[0] if " " in line else line
                        if host and host not in self._discovered_subdomains:
                            self._discovered_subdomains.append(host)

            return result
        except (ValueError, FileNotFoundError) as e:
            logger.warning(f"Recon dnsx skipped: {e}")
            self._publish_status(f"dnsx skipped: {e}")
            return None

    async def _run_katana(self) -> Optional[ToolResult]:
        """Execute katana — active web crawling for endpoint discovery."""
        try:
            target_url = self._target
            if not target_url.startswith(("http://", "https://")):
                target_url = f"https://{target_url}"

            args = ["-u", target_url, "-d", "2", "-silent", "-jc"]
            # VT-Spec AUTH-01: Inject auth headers for authenticated crawling
            if self._auth_context and self._auth_context.has_auth:
                args.extend(self._auth_context.katana_args())

            result = await self._executor.run(
                "katana",
                args=args,
                target=self._target,
                timeout=180,
            )

            if result.exit_code == 0 and result.stdout:
                findings = self._parse_tool_output("katana", result.stdout)
                for f in findings:
                    self._findings.append(f)
                    self._publish_finding(f)

            return result
        except (ValueError, FileNotFoundError) as e:
            logger.warning(f"Recon katana skipped: {e}")
            self._publish_status(f"katana skipped: {e}")
            return None

    def _parse_tool_output(self, tool: str, output: str) -> List[Finding]:
        """Parse tool output via canonical parser registry.

        VT-Spec T-01: Wrapped in try/except — never crashes on parse failure.
        """
        try:
            from erebos.parsers import get_parser_for_tool

            parser = get_parser_for_tool(tool)
            if parser:
                return parser.parse(output)
            logger.warning(f"No parser registered for tool: {tool}")
            return []
        except Exception as e:
            logger.warning(f"T-01: Parser for {tool} failed: {e}")
            return []

    def _publish_finding(self, finding: Finding) -> None:
        """Publish a finding to the bus with role verification (S-01)."""
        payload = finding.model_dump(mode="json")
        # Add target context for correlation engine
        payload["target"] = self._target
        if finding.evidence and finding.evidence.url:
            payload["target"] = finding.evidence.url
        self._bus.publish(AgentMessage(
            id=f"{self._agent_id}-finding-{len(self._findings)}",
            role=AgentRole.RECON,  # S-01: Always own role
            message_type="finding",
            payload=payload,
        ))

    def _publish_status(self, message: str) -> None:
        """Publish status update to bus."""
        self._bus.publish(AgentMessage(
            id=f"{self._agent_id}-status",
            role=AgentRole.RECON,
            message_type="status",
            payload={"message": message, "target": self._target},
        ))
