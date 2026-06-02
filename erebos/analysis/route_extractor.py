"""Route extraction from source code for multiple web frameworks.

VT-Spec R3: Extract HTTP routes to map attack surface.
VT-Spec INJ-03: Use relative paths only.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# File extensions to scan per framework
_EXTENSION_MAP: Dict[str, List[str]] = {
    "flask": [".py"],
    "fastapi": [".py"],
    "django": [".py"],
    "express": [".js", ".ts", ".mjs"],
    "spring": [".java", ".kt"],
}


class RouteInfo(BaseModel):
    """Extracted route information."""

    path: str  # e.g., "/api/users/{id}"
    method: str  # GET, POST, etc.
    file: str  # relative source file (INJ-03: no absolute paths)
    line: int
    params: List[str] = Field(default_factory=list)
    has_auth: bool = False  # if route has auth decorator/annotation


class RouteExtractor:
    """Extract HTTP routes from source code.

    Supports Flask, Express, Django, Spring, FastAPI frameworks.
    VT-Spec INJ-03: All file paths are relative to source_path.
    """

    FRAMEWORK_PATTERNS: Dict[str, List[str]] = {
        "flask": [
            r'@\w+\.route\(["\']([^"\']+)["\'](?:.*?methods\s*=\s*\[([^\]]+)\])?',
            r'@\w+\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
        ],
        "express": [
            r'(?:app|router)\.(get|post|put|delete|patch|all)\(\s*["\']([^"\']+)["\']',
            r'router\.route\(\s*["\']([^"\']+)["\']',
        ],
        "django": [
            r'path\(\s*["\']([^"\']+)["\']',
            r'url\(\s*r?["\']([^"\']+)["\']',
        ],
        "spring": [
            r'@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*["\']?([^"\')\s,]+)',
            r'@RequestMapping\(.*?value\s*=\s*["\']([^"\']+)',
        ],
        "fastapi": [
            r'@\w+\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']',
        ],
    }

    # Auth decorator/annotation patterns
    _AUTH_PATTERNS: Dict[str, List[str]] = {
        "flask": [r"@login_required", r"@auth\.required", r"@jwt_required"],
        "fastapi": [r"Depends\(.*auth", r"Depends\(.*current_user"],
        "express": [r"authenticate", r"requireAuth", r"isAuthenticated", r"passport\."],
        "django": [r"@login_required", r"@permission_required", r"IsAuthenticated"],
        "spring": [r"@PreAuthorize", r"@Secured", r"@RolesAllowed"],
    }

    def detect_framework(self, source_path: Path) -> Optional[str]:
        """Detect framework from project files."""
        # Check for Python frameworks
        requirements_files = list(source_path.glob("**/requirements*.txt")) + list(
            source_path.glob("**/pyproject.toml")
        )
        for rf in requirements_files[:5]:
            try:
                content = rf.read_text(errors="ignore")
                if "fastapi" in content.lower():
                    return "fastapi"
                if "flask" in content.lower():
                    return "flask"
                if "django" in content.lower():
                    return "django"
            except OSError:
                continue

        # Check for Node.js
        package_files = list(source_path.glob("**/package.json"))
        for pf in package_files[:5]:
            try:
                content = pf.read_text(errors="ignore")
                if "express" in content.lower():
                    return "express"
            except OSError:
                continue

        # Check for Spring (pom.xml, build.gradle)
        build_files = list(source_path.glob("**/pom.xml")) + list(
            source_path.glob("**/build.gradle*")
        )
        for bf in build_files[:5]:
            try:
                content = bf.read_text(errors="ignore")
                if "spring" in content.lower():
                    return "spring"
            except OSError:
                continue

        return None

    def extract(self, source_path: Path, framework: Optional[str] = None) -> List[RouteInfo]:
        """Scan source files and extract all routes.

        VT-Spec INJ-03: Only relative paths stored in RouteInfo.file.
        """
        if framework is None:
            framework = self.detect_framework(source_path)
        if framework is None:
            # Try all frameworks
            routes: List[RouteInfo] = []
            for fw in self.FRAMEWORK_PATTERNS:
                routes.extend(self._extract_for_framework(source_path, fw))
            return routes

        return self._extract_for_framework(source_path, framework)

    def _extract_for_framework(self, source_path: Path, framework: str) -> List[RouteInfo]:
        """Extract routes for a specific framework."""
        patterns = self.FRAMEWORK_PATTERNS.get(framework, [])
        if not patterns:
            return []

        extensions = _EXTENSION_MAP.get(framework, [".py", ".js", ".ts", ".java"])
        routes: List[RouteInfo] = []

        for ext in extensions:
            for source_file in source_path.rglob(f"*{ext}"):
                # Skip node_modules, venv, .git
                rel_path = source_file.relative_to(source_path)
                parts = rel_path.parts
                if any(
                    p in parts
                    for p in ("node_modules", "venv", ".venv", ".git", "__pycache__", "dist")
                ):
                    continue

                try:
                    content = source_file.read_text(errors="ignore")
                except OSError:
                    continue

                file_routes = self._extract_from_file(
                    content, str(rel_path), framework, patterns
                )
                routes.extend(file_routes)

        return routes

    def _extract_from_file(
        self, content: str, rel_path: str, framework: str, patterns: List[str]
    ) -> List[RouteInfo]:
        """Extract routes from a single file."""
        routes: List[RouteInfo] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            for pattern_idx, pattern in enumerate(patterns):
                match = re.search(pattern, line)
                if not match:
                    continue

                route_info = self._parse_match(match, framework, rel_path, line_num, pattern_idx)
                if route_info:
                    # Check if route has auth
                    route_info.has_auth = self._has_auth_context(
                        lines, line_num, framework
                    )
                    routes.append(route_info)

        return routes

    def _parse_match(
        self, match: re.Match, framework: str, rel_path: str, line_num: int,
        pattern_idx: int = 0,
    ) -> Optional[RouteInfo]:
        """Parse regex match into RouteInfo based on framework."""
        groups = match.groups()

        if framework in ("flask",):
            if pattern_idx == 0:
                # Pattern 0: @app.route('/path', methods=[...])
                path = groups[0]
                methods_raw = groups[1] if len(groups) > 1 and groups[1] else None
                if methods_raw:
                    methods = [m.strip().strip("'\"").upper() for m in methods_raw.split(",")]
                else:
                    methods = ["GET"]
                params = self._extract_params(path)
                return RouteInfo(
                    path=path, method=methods[0], file=rel_path,
                    line=line_num, params=params
                )
            else:
                # Pattern 1: @app.get('/path') — groups: (method, path)
                method = groups[0].upper()
                path = groups[1]
                params = self._extract_params(path)
                return RouteInfo(
                    path=path, method=method, file=rel_path,
                    line=line_num, params=params
                )

        elif framework == "express":
            if len(groups) >= 2:
                # app.get('/path', ...) or router.route('/path')
                if len(groups) == 2:
                    method = groups[0].upper()
                    path = groups[1]
                else:
                    method = groups[0].upper()
                    path = groups[1]
                params = self._extract_params(path)
                return RouteInfo(
                    path=path, method=method, file=rel_path,
                    line=line_num, params=params
                )
            elif len(groups) == 1:
                path = groups[0]
                params = self._extract_params(path)
                return RouteInfo(
                    path=path, method="ALL", file=rel_path,
                    line=line_num, params=params
                )

        elif framework == "django":
            path = groups[0]
            # Django uses <type:name> for params
            params = re.findall(r"<(?:\w+:)?(\w+)>", path)
            return RouteInfo(
                path="/" + path.lstrip("/"), method="ALL", file=rel_path,
                line=line_num, params=params
            )

        elif framework == "spring":
            if len(groups) >= 2:
                method_prefix = groups[0]
                path = groups[1]
                method_map = {
                    "Get": "GET", "Post": "POST", "Put": "PUT",
                    "Delete": "DELETE", "Patch": "PATCH", "Request": "ALL",
                }
                method = method_map.get(method_prefix, "ALL")
                params = self._extract_params(path)
                return RouteInfo(
                    path=path, method=method, file=rel_path,
                    line=line_num, params=params
                )
            elif len(groups) == 1:
                path = groups[0]
                params = self._extract_params(path)
                return RouteInfo(
                    path=path, method="ALL", file=rel_path,
                    line=line_num, params=params
                )

        elif framework == "fastapi":
            if len(groups) >= 2:
                method = groups[0].upper()
                path = groups[1]
                params = self._extract_params(path)
                return RouteInfo(
                    path=path, method=method, file=rel_path,
                    line=line_num, params=params
                )

        return None

    def _extract_params(self, path: str) -> List[str]:
        """Extract path parameters from route path."""
        # Flask/FastAPI: <param> or {param}
        params = re.findall(r"<(?:\w+:)?(\w+)>", path)
        params.extend(re.findall(r"\{(\w+)\}", path))
        # Express: :param
        params.extend(re.findall(r":(\w+)", path))
        return params

    def _has_auth_context(self, lines: List[str], line_num: int, framework: str) -> bool:
        """Check if route has authentication decorator/middleware nearby."""
        auth_patterns = self._AUTH_PATTERNS.get(framework, [])
        if not auth_patterns:
            return False

        # Look at preceding 5 lines for decorators/annotations
        start = max(0, line_num - 6)
        end = min(len(lines), line_num + 2)
        context = "\n".join(lines[start:end])

        for pattern in auth_patterns:
            if re.search(pattern, context):
                return True
        return False
