"""Correlate SAST findings with DAST targets.

VT-Spec R3: SAST+DAST correlation for higher confidence exploitation.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from erebos.analysis.route_extractor import RouteInfo
from erebos.analysis.semgrep_runner import SastFinding

logger = logging.getLogger(__name__)


class CorrelatedFinding(BaseModel):
    """A SAST finding correlated with a DAST-accessible endpoint."""

    sast_finding: SastFinding
    matched_route: Optional[RouteInfo] = None
    matched_url: Optional[str] = None
    correlation_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    # 1.0 = exact route match, 0.5 = fuzzy path match, 0.0 = no match


class FindingCorrelator:
    """Correlate SAST findings with DAST targets.

    A correlation match means:
    - SAST found a vuln in code that handles a specific route
    - That route maps to a DAST-discoverable URL
    - Confidence boost: SAST+DAST match = CONFIRMED
    """

    def correlate(
        self,
        sast_findings: List[SastFinding],
        dast_targets: List[str],
        routes: List[RouteInfo],
    ) -> List[CorrelatedFinding]:
        """Match SAST findings to DAST-accessible endpoints.

        Returns findings with correlation_confidence field.
        """
        # Build route lookup: file -> routes
        file_routes: dict[str, List[RouteInfo]] = {}
        for route in routes:
            file_routes.setdefault(route.file, []).append(route)

        # Parse DAST target paths for matching
        dast_paths = self._extract_dast_paths(dast_targets)

        correlated: List[CorrelatedFinding] = []
        for finding in sast_findings:
            cf = self._correlate_single(finding, file_routes, dast_paths, dast_targets)
            correlated.append(cf)

        # Sort by confidence descending
        correlated.sort(key=lambda c: c.correlation_confidence, reverse=True)
        return correlated

    def _correlate_single(
        self,
        finding: SastFinding,
        file_routes: dict[str, List[RouteInfo]],
        dast_paths: List[str],
        dast_targets: List[str],
    ) -> CorrelatedFinding:
        """Correlate a single SAST finding."""
        # Step 1: Find routes in the same file as the finding
        routes_in_file = file_routes.get(finding.file, [])

        if not routes_in_file:
            return CorrelatedFinding(
                sast_finding=finding,
                correlation_confidence=0.0,
            )

        # Step 2: Find closest route by line proximity
        best_route = self._find_closest_route(finding, routes_in_file)
        if not best_route:
            return CorrelatedFinding(
                sast_finding=finding,
                correlation_confidence=0.1,  # Same file but no nearby route
            )

        # Step 3: Match route to DAST target
        matched_url, match_confidence = self._match_route_to_dast(
            best_route, dast_paths, dast_targets
        )

        # Confidence scoring:
        # - Route in same file: 0.3
        # - Route close to finding line: +0.2
        # - Route matches DAST target exactly: +0.5
        # - Route matches DAST target fuzzy: +0.3
        confidence = 0.3  # base: route in same file

        line_distance = abs(finding.line - best_route.line)
        if line_distance <= 20:
            confidence += 0.2
        elif line_distance <= 50:
            confidence += 0.1

        confidence += match_confidence
        confidence = min(confidence, 1.0)

        return CorrelatedFinding(
            sast_finding=finding,
            matched_route=best_route,
            matched_url=matched_url,
            correlation_confidence=confidence,
        )

    def _find_closest_route(
        self, finding: SastFinding, routes: List[RouteInfo]
    ) -> Optional[RouteInfo]:
        """Find route closest to the finding's line number."""
        if not routes:
            return None

        # Find route whose line is closest but before the finding
        # (route handler is usually defined before the vulnerable code)
        best: Optional[RouteInfo] = None
        best_distance = float("inf")

        for route in routes:
            distance = abs(finding.line - route.line)
            if distance < best_distance:
                best_distance = distance
                best = route

        return best

    def _match_route_to_dast(
        self, route: RouteInfo, dast_paths: List[str], dast_targets: List[str]
    ) -> tuple[Optional[str], float]:
        """Match a route path to DAST targets.

        Returns (matched_url, confidence_boost).
        """
        route_pattern = self._route_to_regex(route.path)

        for i, dast_path in enumerate(dast_paths):
            # Exact match
            if dast_path == route.path or dast_path.rstrip("/") == route.path.rstrip("/"):
                return dast_targets[i], 0.5

            # Regex match (parameterized routes)
            if route_pattern and re.match(route_pattern, dast_path):
                return dast_targets[i], 0.5

        # Fuzzy: check if route path prefix matches any DAST path
        route_prefix = route.path.split("{")[0].split("<")[0].split(":")[0].rstrip("/")
        if route_prefix and len(route_prefix) > 1:
            for i, dast_path in enumerate(dast_paths):
                if dast_path.startswith(route_prefix):
                    return dast_targets[i], 0.3

        return None, 0.0

    def _route_to_regex(self, path: str) -> Optional[str]:
        """Convert route path to regex pattern for matching."""
        if not path:
            return None

        # Replace common param patterns with regex groups
        pattern = path
        # Flask/FastAPI: <type:name> or {name}
        pattern = re.sub(r"<\w+:\w+>", r"[^/]+", pattern)
        pattern = re.sub(r"<\w+>", r"[^/]+", pattern)
        pattern = re.sub(r"\{(\w+)\}", r"[^/]+", pattern)
        # Express: :name
        pattern = re.sub(r":(\w+)", r"[^/]+", pattern)

        if pattern == path:
            return None  # No params, skip regex

        return f"^{re.escape(pattern).replace(re.escape('[^/]+'), '[^/]+')}$"

    def _extract_dast_paths(self, dast_targets: List[str]) -> List[str]:
        """Extract URL paths from DAST target URLs."""
        paths: List[str] = []
        for target in dast_targets:
            try:
                parsed = urlparse(target)
                paths.append(parsed.path or "/")
            except Exception:
                paths.append(target)
        return paths
