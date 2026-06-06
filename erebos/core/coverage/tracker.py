"""Coverage tracking for SAST and DAST scans."""

from __future__ import annotations

import fcntl
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

logger = logging.getLogger(__name__)

_SUPPORTED_EXTENSIONS = {
    ".go",
    ".java",
    ".js",
    ".php",
    ".py",
    ".rb",
    ".ts",
    ".yaml",
    ".yml",
}

_EXCLUDED_DIRS = {".git", "__pycache__", "build", "dist", "node_modules", "vendor"}


@dataclass
class CoverageReport:
    """Coverage statistics for a scan target."""

    target: str
    total_files: int
    scanned_files: int
    coverage_percent: float
    uncovered_files: List[str]
    endpoints_hit: int
    last_scan_at: str


class CoverageTracker:
    """Tracks scan coverage — what files/endpoints were analyzed."""

    def __init__(self, storage_path: Optional[Path] = None):
        if storage_path is None:
            storage_path = Path("./erebos-storage/coverage.json")
        self._path = Path(storage_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def record_sast_coverage(self, scanned_files: List[str], target_path: str) -> None:
        """Record which files were scanned by SAST."""
        target_key = self._normalize_target(target_path)
        data = self._load()
        entry = data.setdefault(target_key, self._new_entry(target_key, target_path))

        existing_files = set(entry.get("scanned_files", []))
        existing_files.update(self._normalize_scanned_files(scanned_files, target_path))
        entry["target_path"] = self._normalize_target(target_path)
        entry["scanned_files"] = sorted(existing_files)
        entry["last_scan_at"] = self._now()

        self._save(data)

    def record_dast_coverage(self, endpoints_hit: List[str], target: str) -> None:
        """Record which endpoints were hit by DAST tools."""
        target_key = self._normalize_target(target)
        data = self._load()
        entry = data.setdefault(target_key, self._new_entry(target_key, None))

        existing_endpoints = set(entry.get("endpoints_hit", []))
        existing_endpoints.update(endpoint for endpoint in endpoints_hit if endpoint)
        entry["endpoints_hit"] = sorted(existing_endpoints)
        entry["last_scan_at"] = self._now()

        self._save(data)

    def get_coverage_report(self, target: str) -> CoverageReport:
        """Get coverage statistics for a target."""
        target_key = self._normalize_target(target)
        data = self._load()
        entry = data.get(target_key, self._new_entry(target_key, None))

        target_path = entry.get("target_path")
        scanned = set(entry.get("scanned_files", []))
        endpoints = set(entry.get("endpoints_hit", []))

        total_files = 0
        scanned_count = len(scanned)
        uncovered_files: List[str] = []

        if target_path and Path(target_path).exists():
            all_files = self._collect_source_files(Path(target_path))
            total_files = len(all_files)
            scanned_count = sum(1 for file_path in all_files if file_path in scanned)
            uncovered_files = [file_path for file_path in all_files if file_path not in scanned]
        elif Path(target).exists():
            all_files = self._collect_source_files(Path(target))
            total_files = len(all_files)
            scanned_count = sum(1 for file_path in all_files if file_path in scanned)
            uncovered_files = [file_path for file_path in all_files if file_path not in scanned]
        else:
            scanned_count = len(scanned)

        coverage_percent = (scanned_count / total_files * 100.0) if total_files else 0.0

        return CoverageReport(
            target=target_key,
            total_files=total_files,
            scanned_files=scanned_count,
            coverage_percent=round(coverage_percent, 2),
            uncovered_files=uncovered_files,
            endpoints_hit=len(endpoints),
            last_scan_at=entry.get("last_scan_at", ""),
        )

    def get_uncovered_files(self, target_path: str) -> List[str]:
        """Find source files that haven't been scanned yet."""
        target_key = self._normalize_target(target_path)
        data = self._load()
        entry = data.get(target_key, self._new_entry(target_key, target_path))
        scanned = set(entry.get("scanned_files", []))
        all_files = self._collect_source_files(Path(target_path))
        return [file_path for file_path in all_files if file_path not in scanned]

    def _collect_source_files(self, target_path: Path) -> List[str]:
        if not target_path.exists() or not target_path.is_dir():
            return []

        files = []
        for path in target_path.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in _SUPPORTED_EXTENSIONS:
                continue
            if any(part in _EXCLUDED_DIRS for part in path.parts):
                continue
            files.append(path.relative_to(target_path).as_posix())
        return sorted(files)

    def _normalize_scanned_files(self, scanned_files: List[str], target_path: str) -> List[str]:
        base_path = Path(target_path).resolve(strict=False)
        normalized = []

        for file_path in scanned_files:
            if not file_path:
                continue
            candidate = Path(file_path)
            resolved = (candidate if candidate.is_absolute() else base_path / candidate).resolve(
                strict=False
            )
            try:
                normalized.append(resolved.relative_to(base_path).as_posix())
            except ValueError:
                normalized.append(candidate.as_posix())

        return sorted(set(normalized))

    def _normalize_target(self, target: str) -> str:
        path = Path(target)
        if path.exists():
            return str(path.resolve())
        return target

    def _new_entry(self, target: str, target_path: Optional[str]) -> dict[str, Any]:
        normalized_target_path = None
        if target_path is not None:
            normalized_target_path = self._normalize_target(target_path)

        return {
            "target": target,
            "target_path": normalized_target_path,
            "scanned_files": [],
            "endpoints_hit": [],
            "last_scan_at": "",
        }

    def _load(self) -> dict[str, Any]:
        if not self._path.exists():
            return {}
        try:
            with self._path.open("r", encoding="utf-8") as file_handle:
                return json.load(file_handle)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load coverage data: %s", exc)
            return {}

    def _save(self, data: dict[str, Any]) -> None:
        try:
            with self._path.open("w", encoding="utf-8") as file_handle:
                fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(data, file_handle, indent=2)
                finally:
                    fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            logger.error("Failed to save coverage data: %s", exc)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()
