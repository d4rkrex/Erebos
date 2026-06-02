"""Erebos native JSON format parser.

VT-Spec R8: Erebos native JSON format support.
VT-Spec INJ-01: All fields sanitized at parse time.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from erebos.core.finding import Finding
from erebos.ingestion.base import (
    MAX_DESCRIPTION_LENGTH,
    MAX_EVIDENCE_LENGTH,
    MAX_TITLE_LENGTH,
    FindingsParser,
    sanitize_text,
)

logger = logging.getLogger(__name__)


class NativeParser(FindingsParser):
    """Parser for Erebos native JSON format.

    Expects a JSON object with a 'findings' array containing Finding-compatible objects.
    """

    @property
    def format_name(self) -> str:
        return "native"

    def detect(self, content: bytes) -> bool:
        """Detect native format by checking for 'findings' key with expected fields."""
        try:
            text = content[:4096].decode("utf-8", errors="ignore")
            return '"findings"' in text and '"phase_found"' in text
        except Exception:
            return False

    def parse(self, content: bytes) -> List[Finding]:
        """Parse Erebos native JSON into Finding objects.

        VT-Spec INJ-01: All text fields sanitized even for native format.
        """
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning("Failed to parse native JSON: %s", e)
            return []

        findings: List[Finding] = []
        items = data.get("findings", [])

        if not isinstance(items, list):
            logger.warning("Native JSON 'findings' field is not an array")
            return []

        for item in items:
            if not isinstance(item, dict):
                continue
            finding = self._parse_item(item)
            if finding:
                findings.append(finding)

        return findings

    def _parse_item(self, item: Dict[str, Any]) -> Finding | None:
        """Parse a single native finding item."""
        try:
            # VT-Spec INJ-01: Sanitize text fields even from native format
            if "title" in item:
                item["title"] = sanitize_text(item["title"], MAX_TITLE_LENGTH)
            if "description" in item:
                item["description"] = sanitize_text(item["description"], MAX_DESCRIPTION_LENGTH)
            if "target" in item and item["target"]:
                item["target"] = sanitize_text(item["target"], MAX_EVIDENCE_LENGTH)

            # Sanitize evidence fields
            if "evidence" in item and isinstance(item["evidence"], dict):
                ev = item["evidence"]
                if ev.get("url"):
                    ev["url"] = sanitize_text(ev["url"], MAX_EVIDENCE_LENGTH)
                if ev.get("output"):
                    ev["output"] = sanitize_text(ev["output"], MAX_EVIDENCE_LENGTH)
                if ev.get("payload"):
                    ev["payload"] = sanitize_text(ev["payload"], MAX_EVIDENCE_LENGTH)

            return Finding(**item)
        except Exception as e:
            logger.warning("Failed to parse native finding: %s", e)
            return None
