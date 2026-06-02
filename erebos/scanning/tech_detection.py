"""Shared technology detection and template mapping for vuln-scan phases.

VT-Spec TA-002: Tech-aware template selection from recon findings.
Used by both Fleet Mode (agents/roles/vuln_scan.py) and Classic Mode
(core/phase_agent.py) to adapt scanning strategy based on detected tech stack.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

from erebos.core.finding import Finding

logger = logging.getLogger(__name__)


# Technology-to-template mapping.
# Maps detected technologies (lowercase keywords) to additional nuclei template
# directories and tag-based scans that should be included.
TECH_TEMPLATE_MAP: Dict[str, Dict[str, Any]] = {
    "nodejs": {
        "dirs": [
            "dast/vulnerabilities/nosqli",
            "dast/vulnerabilities/sqli",
            "dast/vulnerabilities/injection",
            "dast/vulnerabilities/ssti",
            "dast/vulnerabilities/ssrf",
        ],
        "tags": ["nosql", "mongodb", "ssrf", "ssti"],
    },
    "express": {
        "dirs": [
            "dast/vulnerabilities/nosqli",
            "dast/vulnerabilities/sqli",
            "dast/vulnerabilities/injection",
            "dast/vulnerabilities/ssti",
        ],
        "tags": ["nosql", "mongodb", "injection"],
    },
    "mongodb": {
        "dirs": [
            "dast/vulnerabilities/nosqli",
            "dast/vulnerabilities/sqli",
            "dast/vulnerabilities/injection",
        ],
        "tags": ["nosql", "mongodb"],
    },
    "mongoose": {
        "dirs": [
            "dast/vulnerabilities/nosqli",
            "dast/vulnerabilities/sqli",
            "dast/vulnerabilities/injection",
        ],
        "tags": ["nosql", "mongodb"],
    },
    "php": {
        "dirs": [
            "dast/vulnerabilities/sqli",
            "dast/vulnerabilities/lfi",
            "dast/vulnerabilities/rfi",
            "dast/vulnerabilities/xss",
        ],
        "tags": ["sqli", "lfi", "rfi", "php"],
    },
    "wordpress": {
        "dirs": [
            "http/vulnerabilities/wordpress",
            "dast/vulnerabilities/sqli",
            "dast/vulnerabilities/xss",
        ],
        "tags": ["wordpress", "wp"],
    },
    "java": {
        "dirs": [
            "dast/vulnerabilities/sqli",
            "dast/vulnerabilities/ssti",
            "dast/vulnerabilities/xxe",
        ],
        "tags": ["sqli", "java", "spring"],
    },
    "spring": {
        "dirs": [
            "http/vulnerabilities/springboot",
            "dast/vulnerabilities/sqli",
            "dast/vulnerabilities/ssti",
        ],
        "tags": ["spring", "springboot"],
    },
    "python": {
        "dirs": [
            "dast/vulnerabilities/ssti",
            "dast/vulnerabilities/sqli",
            "dast/vulnerabilities/cmdi",
        ],
        "tags": ["ssti", "python", "jinja"],
    },
    "django": {
        "dirs": [
            "dast/vulnerabilities/ssti",
            "dast/vulnerabilities/sqli",
        ],
        "tags": ["django", "ssti"],
    },
    "flask": {
        "dirs": [
            "dast/vulnerabilities/ssti",
            "dast/vulnerabilities/sqli",
        ],
        "tags": ["flask", "jinja", "ssti"],
    },
}


def detect_technologies_from_findings(findings: List[Finding]) -> Set[str]:
    """Detect technologies from a list of Finding objects.

    VT-Spec TA-002: Inspects finding titles, descriptions, and evidence to identify
    technologies like Node.js, Express, MongoDB, PHP, WordPress, etc.

    Args:
        findings: List of Finding objects from recon or vuln-scan phases.

    Returns:
        Set of normalized lowercase technology keywords matching TECH_TEMPLATE_MAP keys.
    """
    detected: Set[str] = set()

    for finding in findings:
        title = (finding.title or "").lower()
        description = (finding.description or "").lower()
        evidence = finding.evidence
        output = (evidence.output or "").lower() if evidence else ""
        url = (evidence.url or "").lower() if evidence else ""
        target_str = (finding.target or "").lower()

        text = f"{title} {description} {output} {url} {target_str}"
        _match_technologies(text, detected)

    return detected


def detect_technologies_from_payloads(payloads: List[Dict[str, Any]]) -> Set[str]:
    """Detect technologies from raw message payloads (dict format).

    Used by Fleet Mode where findings are read from the bus as dicts
    rather than parsed Finding objects.

    Args:
        payloads: List of payload dictionaries from AgentMessage.

    Returns:
        Set of normalized lowercase technology keywords matching TECH_TEMPLATE_MAP keys.
    """
    detected: Set[str] = set()

    for payload in payloads:
        title = (payload.get("title") or "").lower()
        description = (payload.get("description") or "").lower()
        evidence = payload.get("evidence") or {}
        output = (evidence.get("output") or "").lower()
        url = (evidence.get("url") or "").lower()
        target_str = (payload.get("target") or "").lower()

        text = f"{title} {description} {output} {url} {target_str}"
        _match_technologies(text, detected)

    return detected


def get_tags_for_technologies(technologies: Set[str]) -> List[str]:
    """Get nuclei tags for a set of detected technologies.

    Args:
        technologies: Set of detected technology keywords.

    Returns:
        Sorted deduplicated list of nuclei tags to use.
    """
    tags: Set[str] = set()
    for tech in technologies:
        mapping = TECH_TEMPLATE_MAP.get(tech)
        if mapping:
            tags.update(mapping["tags"])
    return sorted(tags)


def get_template_dirs_for_technologies(technologies: Set[str]) -> List[str]:
    """Get additional nuclei template directories for detected technologies.

    Args:
        technologies: Set of detected technology keywords.

    Returns:
        Deduplicated list of template directory paths (relative to templates root).
    """
    dirs: List[str] = []
    seen: set = set()
    for tech in technologies:
        mapping = TECH_TEMPLATE_MAP.get(tech)
        if mapping:
            for d in mapping["dirs"]:
                if d not in seen:
                    seen.add(d)
                    dirs.append(d)
    return dirs


def _match_technologies(text: str, detected: Set[str]) -> None:
    """Match technology keywords in combined text and add to detected set."""
    if any(kw in text for kw in ("node.js", "nodejs", "node js", "express")):
        detected.add("nodejs")
        detected.add("express")
    if any(kw in text for kw in ("mongodb", "mongoose", "mongo")):
        detected.add("mongodb")
        detected.add("mongoose")
    if any(kw in text for kw in ("php", "laravel", "symfony", "codeigniter")):
        detected.add("php")
    if "wordpress" in text or "wp-" in text:
        detected.add("wordpress")
        detected.add("php")
    if any(kw in text for kw in ("java", "tomcat", "spring", "struts")):
        detected.add("java")
    if "spring" in text or "springboot" in text:
        detected.add("spring")
        detected.add("java")
    if any(kw in text for kw in ("python", "django", "flask", "jinja")):
        detected.add("python")
    if "django" in text:
        detected.add("django")
    if "flask" in text or "jinja" in text:
        detected.add("flask")
