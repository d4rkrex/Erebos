# Changelog

All notable changes to Erebos will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Storage Infrastructure
- **Subdirectory-based storage structure**: Each scan now has its own directory (`{scan_id}/`) containing `state.json` and `raw/` subdirectory
- **Raw output persistence**: All tool outputs automatically saved to `{scan_id}/raw/` with timestamps and variants (e.g., `nmap_fast_20240320T120000.xml`)
- **Command logging**: Full command execution history tracked in `phase_artifacts["commands"]` with timestamps, exit codes, and durations
- **Finding deduplication**: Automatic deduplication by `(title, url, tool_name)` tuple to prevent duplicate findings
- **Backward compatibility**: Can read legacy flat-file format (`{scan_id}_state.json`) with automatic fallback
- **Migration CLI command**: `erebos migrate` with `--dry-run` and `--rollback` flags for safe migration
- **Streaming I/O**: Large raw outputs (>10MB) written in chunks to avoid memory issues

#### Enrichment Integration
- **Batch finding updates**: Atomic batch persistence with `update_findings_batch()` for efficient enrichment integration
- **CVSS validation**: Enrichment layer validates CVSS scores (0.0-10.0 range), logs errors for invalid values
- **CVE validation**: CVE IDs validated against regex pattern `CVE-YYYY-NNNNN+`
- **Coverage metrics**: Calculate and log enrichment coverage (CVSS %, CVE %, Exploit %) after inference
- **Enrichment persistence**: Enriched findings automatically saved after ReconAgent inference

#### Dual Nmap Strategy
- **Fast scan first**: `nmap -F -A -T4` scans top ~100 ports in ~2 minutes for early feedback
- **Full scan after**: `nmap -p- -A -T4` scans all 65535 ports in ~30 minutes for complete coverage
- **Intelligent merge**: Combines fast and full scan results, preferring full scan data for overlapping ports
- **Profile override**: `comprehensive` profile uses `nmap_strategy="dual"` by default
- **Port discovery metrics**: Tracks fast_ports, full_ports, improvement_pct, and merged_ports
- **Progress reporting**: User feedback at key milestones (5%, 50%, 55%, 95%, 97%)

#### Testing
- **57 new tests** covering storage, enrichment, dual nmap, migration, backward compatibility, E2E, performance benchmarks, and error handling
- **Integration tests**: 18 tests for migration and backward compatibility scenarios
- **E2E tests**: 7 comprehensive end-to-end scan lifecycle tests
- **Performance benchmarks**: 6 benchmark tests for storage operations and dual nmap timing
- **Error handling tests**: 9 tests for edge cases (disk full, corrupted JSON, malformed paths, etc.)

### Changed
- **ScanState.findings**: Now stored directly in state.json (no separate findings.json file)
- **Storage directory structure**: Moved from flat files to subdirectory-per-scan layout
- **ToolResult model**: Added `command_string` field for command logging
- **ScanProfile**: Added `nmap_strategy` field (Literal["fast", "dual"])
- **Orchestrator**: Passes `nmap_strategy` from profile to phase context
- **ReconAgent**: Implements dual nmap execution and result merging in `_run_nmap()` and `_run_nmap_dual()`

### Deprecated
- **Legacy flat-file storage**: `{scan_id}_state.json` format is deprecated in favor of subdirectory structure
  - Still supported for reading (backward compatibility)
  - New scans use subdirectory format
  - Migration recommended via `erebos migrate`
  - **Deprecation timeline**: Legacy format will be removed in v2.0.0 (estimated Q3 2026)

### Fixed
- Raw output files no longer lost between tool executions
- Finding deduplication prevents redundant entries across multiple tool runs
- Command execution history now preserved for audit trails
- Large tool outputs (>10MB) no longer cause memory issues due to streaming I/O

## [0.1.0] - 2024-03-19

### Added
- Initial release of Erebos
- Phase-based orchestration (RECON, DISCOVERY, VULN_SCAN, VALIDATION, REPORTING)
- Tool adapters for katana, nuclei, nikto, nmap
- CLI and MCP transport support
- Allowlist enforcement for target validation
- Rate limiting and request throttling
- Markdown report generation
- Pause/resume scan functionality
- Scan profiles (minimal, standard, comprehensive, web-only, vuln-focused)

[Unreleased]: https://github.com/yourusername/erebos-lite/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/erebos-lite/releases/tag/v0.1.0
