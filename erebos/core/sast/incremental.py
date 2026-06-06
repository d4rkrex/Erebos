"""Incremental SAST scanning based on git diffs."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import List

from erebos.core.sast.scanner import SastResult, SastScanner

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


class IncrementalScanner:
    """Scans only files changed since last scan or since a git ref."""

    def __init__(self, scanner: SastScanner):
        self._scanner = scanner

    def get_changed_files(self, repo_path: str, since_ref: str = "HEAD~1") -> List[str]:
        """Get files changed since a git ref."""
        return self._git_changed_files(
            repo_path,
            ["diff", "--name-only", "--diff-filter=ACMR", since_ref],
        )

    def scan_changed(self, repo_path: str, since_ref: str = "HEAD~1") -> SastResult:
        """Scan only changed files."""
        changed_files = self.get_changed_files(repo_path, since_ref=since_ref)
        return self._scan_files(repo_path, changed_files)

    def scan_staged(self, repo_path: str) -> SastResult:
        """Scan only staged files (pre-commit hook use case)."""
        staged_files = self._git_changed_files(
            repo_path,
            ["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        )
        return self._scan_files(repo_path, staged_files)

    def _scan_files(self, repo_path: str, files: List[str]) -> SastResult:
        repo_root = str(Path(repo_path).resolve())
        supported_files = self._filter_supported_files(files)
        if not supported_files:
            return SastResult(
                findings=[],
                files_scanned=0,
                rules_run=0,
                scan_time_ms=0,
                errors=[],
                target_path=repo_root,
            )

        cmd = self._scanner._build_command(supported_files[0])
        cmd.extend(supported_files[1:])
        logger.info("Running incremental SAST scan on %s files", len(supported_files))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._scanner._timeout,
                cwd=repo_root,
            )
        except subprocess.TimeoutExpired:
            return SastResult(
                findings=[],
                files_scanned=0,
                rules_run=0,
                scan_time_ms=self._scanner._timeout * 1000,
                errors=[f"Scan timed out after {self._scanner._timeout}s"],
                target_path=repo_root,
            )
        except FileNotFoundError:
            return SastResult(
                findings=[],
                files_scanned=0,
                rules_run=0,
                scan_time_ms=0,
                errors=["semgrep not found. Install with: pip install semgrep"],
                target_path=repo_root,
            )

        return self._scanner._parse_output(result.stdout, result.stderr, repo_root)

    def _git_changed_files(self, repo_path: str, diff_args: List[str]) -> List[str]:
        repo_root = Path(repo_path).resolve()
        try:
            result = subprocess.run(
                ["git", *diff_args],
                capture_output=True,
                text=True,
                cwd=repo_root,
                check=False,
            )
        except FileNotFoundError:
            logger.warning("git not found while collecting changed files")
            return []

        if result.returncode != 0:
            logger.warning("Failed to collect changed files: %s", result.stderr.strip())
            return []

        changed_files = []
        for file_name in result.stdout.splitlines():
            if not file_name:
                continue
            file_path = (repo_root / file_name).resolve(strict=False)
            if file_path.exists() and file_path.is_file():
                changed_files.append(str(file_path))

        return sorted(set(changed_files))

    def _filter_supported_files(self, files: List[str]) -> List[str]:
        return [
            file_path
            for file_path in files
            if Path(file_path).suffix.lower() in _SUPPORTED_EXTENSIONS
        ]
