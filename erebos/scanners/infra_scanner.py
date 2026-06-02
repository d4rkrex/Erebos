"""Infrastructure vulnerability scanner using network templates.

Orchestrates template loading, service matching, network probing,
and CVE enrichment to identify vulnerabilities in detected services.

VT-Spec INJ-02: Strict template parsing with schema validation.
VT-Spec DOS-01: Budget-aware execution with caps on probes and payloads.
"""

import asyncio
import logging
import re
import socket
from pathlib import Path
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.scanners.cve_enricher import CVEEnricher, CVEInfo
from erebos.scanners.network_template import NetworkMatcher, NetworkTemplate, NetworkTemplateParser
from erebos.scanners.service_matcher import ServiceInfo, ServiceMatcher

logger = logging.getLogger(__name__)


class ProbeResult(BaseModel):
    """Result of executing a network probe against a service."""

    matched: bool
    template_id: str
    response_data: str = ""
    matcher_details: str = ""


class NetworkProbeExecutor:
    """Execute network probes (TCP/UDP connections with payloads).

    VT-Spec DOS-01: Respects scan budget and timeout limits.
    """

    # VT-Spec DOS-01: Maximum total probes per scan
    MAX_PROBES_PER_SCAN = 1000
    DEFAULT_TIMEOUT = 10.0

    def __init__(self) -> None:
        self._probes_executed = 0

    @property
    def probes_executed(self) -> int:
        return self._probes_executed

    def reset_budget(self) -> None:
        """Reset probe execution counter."""
        self._probes_executed = 0

    async def execute(
        self,
        template: NetworkTemplate,
        target: ServiceInfo,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> ProbeResult:
        """Send probe data and check response against matchers.

        VT-Spec DOS-01: Halts when budget exhausted.
        """
        # VT-Spec DOS-01: Budget check
        if self._probes_executed >= self.MAX_PROBES_PER_SCAN:
            logger.warning("DOS-01: Probe budget exhausted (%d probes)", self.MAX_PROBES_PER_SCAN)
            return ProbeResult(
                matched=False,
                template_id=template.id,
                matcher_details="budget_exhausted",
            )

        self._probes_executed += 1

        try:
            response = await asyncio.wait_for(
                self._send_probe(template, target),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return ProbeResult(matched=False, template_id=template.id, matcher_details="timeout")
        except (OSError, ConnectionRefusedError, ConnectionResetError) as e:
            return ProbeResult(
                matched=False, template_id=template.id, matcher_details=f"connection_error: {e}"
            )

        # Check response against matchers
        matched, details = self._check_matchers(template, response)

        return ProbeResult(
            matched=matched,
            template_id=template.id,
            response_data=response[:512],  # Truncate for safety
            matcher_details=details,
        )

    async def _send_probe(self, template: NetworkTemplate, target: ServiceInfo) -> str:
        """Open socket, send payload, read response."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._send_probe_sync, template, target)

    def _send_probe_sync(self, template: NetworkTemplate, target: ServiceInfo) -> str:
        """Synchronous socket probe execution."""
        sock_type = socket.SOCK_STREAM if template.protocol == "tcp" else socket.SOCK_DGRAM
        sock = socket.socket(socket.AF_INET, sock_type)
        sock.settimeout(10.0)

        try:
            if template.protocol == "tcp":
                sock.connect((target.host, target.port))

            # Send each input
            for inp in template.inputs:
                data = self._prepare_data(inp.data, inp.type)
                if template.protocol == "tcp":
                    sock.sendall(data)
                else:
                    sock.sendto(data, (target.host, target.port))

            # Read response
            read_size = template.read_size or 1024
            try:
                response = sock.recv(read_size)
                return response.decode("utf-8", errors="replace")
            except socket.timeout:
                return ""
        finally:
            sock.close()

    def _prepare_data(self, data: str, data_type: str) -> bytes:
        """Convert input data to bytes based on type."""
        if data_type == "hex":
            try:
                return bytes.fromhex(data)
            except ValueError:
                return data.encode("utf-8")
        else:
            # Handle escape sequences in text
            return data.encode("utf-8").decode("unicode_escape").encode("utf-8")

    def _check_matchers(self, template: NetworkTemplate, response: str) -> Tuple[bool, str]:
        """Check response against template matchers.

        Returns (matched, details_string).
        """
        if not template.matchers:
            # No matchers = match if we got any response
            return bool(response), "response_received" if response else "no_response"

        results: List[Tuple[bool, str]] = []

        for matcher in template.matchers:
            matched, detail = self._eval_matcher(matcher, response)
            results.append((matched, detail))

        if not results:
            return False, "no_matchers"

        # Apply matchers-condition
        if template.matchers_condition == "and":
            all_matched = all(r[0] for r in results)
            details = "; ".join(r[1] for r in results if r[0])
            return all_matched, details or "all_matchers_required"
        else:  # "or"
            for matched, detail in results:
                if matched:
                    return True, detail
            return False, "no_matcher_hit"

    def _eval_matcher(self, matcher: NetworkMatcher, response: str) -> Tuple[bool, str]:
        """Evaluate a single matcher against the response."""
        result = False
        detail = ""

        if matcher.type == "word":
            response_to_check = response
            if matcher.encoding == "hex":
                response_to_check = response.encode("utf-8", errors="replace").hex()

            if matcher.condition == "and":
                result = all(w in response_to_check for w in matcher.words)
            else:
                result = any(w in response_to_check for w in matcher.words)

            if result:
                matched_words = [w for w in matcher.words if w in response_to_check]
                detail = f"word_match: {matched_words[0][:30] if matched_words else ''}"

        elif matcher.type == "regex":
            for pattern in matcher.regex:
                try:
                    if re.search(pattern, response):
                        result = True
                        detail = f"regex_match: {pattern[:30]}"
                        break
                except re.error:
                    continue

        elif matcher.type == "dsl":
            # Basic DSL evaluation for common functions
            for expr in matcher.dsl:
                if self._eval_dsl(expr, response):
                    result = True
                    detail = f"dsl_match: {expr[:30]}"
                    break

        # Handle negative matchers
        if matcher.negative:
            result = not result

        return result, detail

    def _eval_dsl(self, expr: str, response: str) -> bool:
        """Evaluate basic DSL expressions (contains, length checks).

        VT-Spec INJ-02: Only safe DSL functions are evaluated.
        """
        # contains(raw, 'string')
        contains_match = re.match(r"contains\((?:raw|response|body),\s*'([^']+)'\)", expr)
        if contains_match:
            return contains_match.group(1) in response

        # len(raw) > N
        len_match = re.match(r"len\((?:raw|response|body)\)\s*([><=!]+)\s*(\d+)", expr)
        if len_match:
            op = len_match.group(1)
            val = int(len_match.group(2))
            if op == ">":
                return len(response) > val
            elif op == "<":
                return len(response) < val
            elif op == ">=":
                return len(response) >= val
            elif op == "==":
                return len(response) == val

        return False


class InfraScanner:
    """Infrastructure vulnerability scanner using network templates.

    Orchestrates the full scanning pipeline:
    1. Load applicable network templates
    2. Match templates to detected services (by port, product, version)
    3. Execute matching templates
    4. Enrich with CVE data
    5. Return findings
    """

    def __init__(
        self,
        templates_dir: Optional[Path] = None,
        max_concurrent_probes: int = 10,
    ) -> None:
        self._templates_dir = templates_dir or Path("templates/nuclei/network")
        self._parser = NetworkTemplateParser()
        self._matcher = ServiceMatcher()
        self._enricher = CVEEnricher()
        self._executor = NetworkProbeExecutor()
        self._max_concurrent = max_concurrent_probes
        self._templates: Optional[List[NetworkTemplate]] = None

    @property
    def templates_loaded(self) -> int:
        """Number of templates currently loaded."""
        return len(self._templates) if self._templates else 0

    def load_templates(self, force: bool = False) -> List[NetworkTemplate]:
        """Load templates from directory (cached unless force=True)."""
        if self._templates is None or force:
            self._templates = self._parser.load_directory(self._templates_dir)
            logger.info("Loaded %d network templates from %s", len(self._templates), self._templates_dir)
        return self._templates

    async def scan(
        self,
        services: List[ServiceInfo],
        execute_probes: bool = True,
    ) -> List[Finding]:
        """Scan detected services for vulnerabilities.

        Args:
            services: List of detected network services
            execute_probes: If True, send actual network probes. If False, only match + enrich.

        Returns:
            List of Finding objects for confirmed/potential vulnerabilities.
        """
        findings: List[Finding] = []

        # 1. Load templates
        templates = self.load_templates()

        # 2. Match templates to services
        matches = self._matcher.match(templates, services)
        logger.info("Matched %d template-service pairs", len(matches))

        # 3. Execute probes (if enabled)
        if execute_probes:
            self._executor.reset_budget()
            probe_findings = await self._execute_probes(matches)
            findings.extend(probe_findings)
        else:
            # Without probing, report potential matches
            for template, service in matches:
                finding = self._create_finding_from_match(template, service, confirmed=False)
                findings.append(finding)

        # 4. Enrich with CVE data
        cve_findings = self._enrich_with_cves(services)
        findings.extend(cve_findings)

        logger.info("InfraScanner produced %d findings", len(findings))
        return findings

    async def _execute_probes(
        self, matches: List[Tuple[NetworkTemplate, ServiceInfo]]
    ) -> List[Finding]:
        """Execute network probes with concurrency limit."""
        findings: List[Finding] = []
        semaphore = asyncio.Semaphore(self._max_concurrent)

        async def probe_with_limit(template: NetworkTemplate, service: ServiceInfo) -> Optional[Finding]:
            async with semaphore:
                result = await self._executor.execute(template, service)
                if result.matched:
                    return self._create_finding_from_match(
                        template, service, confirmed=True, probe_result=result
                    )
                return None

        tasks = [probe_with_limit(t, s) for t, s in matches]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                findings.append(result)
            elif isinstance(result, Exception):
                logger.debug("Probe failed with exception: %s", result)

        return findings

    def _create_finding_from_match(
        self,
        template: NetworkTemplate,
        service: ServiceInfo,
        confirmed: bool = False,
        probe_result: Optional[ProbeResult] = None,
    ) -> Finding:
        """Create a Finding from a template match."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        severity = severity_map.get(template.severity, Severity.MEDIUM)

        title = f"{'[Confirmed]' if confirmed else '[Potential]'} {template.name}"
        title = title[:100]

        description = template.description or template.name
        if template.cve_id:
            description = f"{template.cve_id}: {description}"
        description += f"\nTarget: {service.host}:{service.port}/{service.protocol}"
        if service.product:
            description += f"\nProduct: {service.product} {service.version}"

        evidence_output = ""
        if probe_result:
            evidence_output = f"Matcher: {probe_result.matcher_details}"
            if probe_result.response_data:
                # Sanitize response data for safe storage
                safe_response = probe_result.response_data[:256].replace("\x00", "")
                evidence_output += f"\nResponse: {safe_response}"

        return Finding(
            tool="infra-scanner",
            severity=severity,
            title=title,
            description=description[:500],  # Cap description length
            target=f"{service.host}:{service.port}",
            cve=template.cve_id,
            evidence=FindingEvidence(
                url=f"{service.host}:{service.port}",
                output=evidence_output[:1000],
            ),
            phase_found=Phase.VULN_SCAN,
        )

    def _enrich_with_cves(self, services: List[ServiceInfo]) -> List[Finding]:
        """Create findings from CVE enrichment."""
        findings: List[Finding] = []
        cves = self._enricher.enrich(services)

        # Map CVEs back to services
        for service in services:
            if not service.product:
                continue
            service_cves = self._enricher.enrich_single(service)
            for cve in service_cves:
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }
                finding = Finding(
                    tool="cve-enricher",
                    severity=severity_map.get(cve.severity, Severity.MEDIUM),
                    title=f"[CVE] {cve.cve_id} - {cve.description[:60]}",
                    description=(
                        f"{cve.cve_id} (CVSS {cve.cvss_score}): {cve.description}\n"
                        f"Affected: {cve.affected_product} {cve.affected_versions}\n"
                        f"Exploit available: {cve.exploit_available}"
                    ),
                    target=f"{service.host}:{service.port}",
                    cve=cve.cve_id,
                    cvss=cve.cvss_score,
                    evidence=FindingEvidence(
                        url=f"{service.host}:{service.port}",
                        output=f"Product: {service.product} {service.version}",
                    ),
                    phase_found=Phase.VULN_SCAN,
                )
                findings.append(finding)

        return findings
