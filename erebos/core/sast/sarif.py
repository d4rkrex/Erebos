"""SARIF 2.1.0 output generation for Erebos SAST findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from erebos.core.sast.scanner import SastFinding, SastResult
from erebos.core.validation import ValidationResult

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SEVERITY_LEVELS = {
    "ERROR": "error",
    "WARNING": "warning",
    "INFO": "note",
}


class SarifGenerator:
    """Convert Erebos SAST findings into SARIF 2.1.0 documents."""

    def __init__(self) -> None:
        self._document: Optional[Dict[str, Any]] = None

    def generate(
        self,
        sast_result: SastResult,
        validation_results: Optional[List[ValidationResult]] = None,
    ) -> Dict[str, Any]:
        """Generate and store a SARIF document for the provided scan results."""
        validations = validation_results or []
        rules = self._build_rules(sast_result.findings)
        rule_indexes = {rule["id"]: index for index, rule in enumerate(rules)}
        cwe_taxa = self._build_cwe_taxa(sast_result.findings)

        results = [
            self._build_result(
                finding,
                rule_indexes.get(finding.rule_id),
                validations[index] if index < len(validations) else None,
            )
            for index, finding in enumerate(sast_result.findings)
        ]

        run: Dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": "Erebos SAST",
                    "informationUri": "https://github.com/d4rkrex/Erebos",
                    "rules": rules,
                },
                "taxonomies": [
                    {
                        "name": "CWE",
                        "organization": "MITRE",
                        "shortDescription": {"text": "Common Weakness Enumeration"},
                        "informationUri": "https://cwe.mitre.org/",
                        "taxa": cwe_taxa,
                    }
                ]
                if cwe_taxa
                else [],
            },
            "results": results,
            "artifacts": self._build_artifacts(sast_result.findings),
            "invocations": [self._build_invocation(sast_result)],
            "properties": {
                "filesScanned": sast_result.files_scanned,
                "rulesRun": sast_result.rules_run,
                "scanTimeMs": sast_result.scan_time_ms,
                "targetPath": sast_result.target_path,
            },
        }

        self._document = {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [run],
        }
        return self._document

    def to_file(self, path: str | Path) -> None:
        """Write the last generated SARIF document to a file."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.to_json(), encoding="utf-8")

    def to_json(self) -> str:
        """Serialize the last generated SARIF document to JSON."""
        if self._document is None:
            msg = "No SARIF document generated yet"
            raise ValueError(msg)
        return json.dumps(self._document, indent=2)

    def _build_rules(self, findings: List[SastFinding]) -> List[Dict[str, Any]]:
        rules: List[Dict[str, Any]] = []
        seen_rule_ids = set()

        for finding in findings:
            if finding.rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(finding.rule_id)

            rule: Dict[str, Any] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.message},
                "fullDescription": {"text": finding.message},
                "defaultConfiguration": {
                    "level": _SEVERITY_LEVELS.get(finding.severity, "warning")
                },
                "help": {"text": finding.message},
                "properties": self._build_rule_properties(finding),
            }

            relationship = self._build_cwe_relationship(finding.cwe)
            if relationship:
                rule["relationships"] = [relationship]

            rules.append(rule)

        return rules

    def _build_rule_properties(self, finding: SastFinding) -> Dict[str, Any]:
        properties: Dict[str, Any] = {
            "tags": [],
        }

        if finding.cwe:
            properties["tags"].append(self._normalize_cwe(finding.cwe)[0])
        if finding.owasp:
            if isinstance(finding.owasp, list):
                properties["tags"].extend(str(item) for item in finding.owasp)
            else:
                properties["tags"].append(str(finding.owasp))

        metadata = finding.metadata or {}
        if metadata:
            properties["metadata"] = metadata

        return properties

    def _build_result(
        self,
        finding: SastFinding,
        rule_index: Optional[int],
        validation_result: Optional[ValidationResult],
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _SEVERITY_LEVELS.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [self._build_location(finding)],
            "partialFingerprints": {
                "primaryLocationLineHash": (
                    f"{finding.file_path}:{finding.line_start}:{finding.line_end}:{finding.rule_id}"
                )
            },
        }
        if rule_index is not None:
            result["ruleIndex"] = rule_index

        if validation_result is not None:
            result["properties"] = {
                "erebosValidation": {
                    "verdict": validation_result.final_verdict.value,
                    "confidence": validation_result.confidence,
                    "exploitationStatus": validation_result.exploitation_status,
                    "shortCircuitedAt": validation_result.short_circuited_at,
                }
            }

        return result

    def _build_location(self, finding: SastFinding) -> Dict[str, Any]:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file_path},
                "region": {
                    "startLine": finding.line_start,
                    "endLine": finding.line_end or finding.line_start,
                    "startColumn": finding.col_start or 1,
                    "endColumn": finding.col_end or finding.col_start or 1,
                    "snippet": {"text": finding.code_snippet},
                },
            }
        }

    def _build_artifacts(self, findings: List[SastFinding]) -> List[Dict[str, Any]]:
        artifacts = []
        seen_paths = set()

        for finding in findings:
            if finding.file_path in seen_paths:
                continue
            seen_paths.add(finding.file_path)
            artifacts.append({"location": {"uri": finding.file_path}})

        return artifacts

    def _build_invocation(self, sast_result: SastResult) -> Dict[str, Any]:
        invocation: Dict[str, Any] = {
            "executionSuccessful": not bool(sast_result.errors),
            "properties": {
                "filesScanned": sast_result.files_scanned,
                "rulesRun": sast_result.rules_run,
                "scanTimeMs": sast_result.scan_time_ms,
            },
        }

        if sast_result.errors:
            invocation["toolExecutionNotifications"] = [
                {"level": "error", "message": {"text": error}} for error in sast_result.errors
            ]

        return invocation

    def _build_cwe_taxa(self, findings: List[SastFinding]) -> List[Dict[str, Any]]:
        taxa: List[Dict[str, Any]] = []
        seen_cwes = set()

        for finding in findings:
            if not finding.cwe:
                continue
            cwe_id, cwe_text = self._normalize_cwe(finding.cwe)
            if cwe_id in seen_cwes:
                continue
            seen_cwes.add(cwe_id)
            taxa.append(
                {
                    "id": cwe_id,
                    "name": cwe_id,
                    "shortDescription": {"text": cwe_text},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html",
                }
            )

        return taxa

    def _build_cwe_relationship(self, cwe: Optional[str]) -> Optional[Dict[str, Any]]:
        if not cwe:
            return None
        cwe_id, _ = self._normalize_cwe(cwe)
        return {
            "target": {
                "id": cwe_id,
                "toolComponent": {"name": "CWE"},
            },
            "kinds": ["relevant"],
        }

    def _normalize_cwe(self, raw_cwe: str) -> tuple[str, str]:
        cwe_text = raw_cwe.strip()
        if ":" in cwe_text:
            cwe_id, description = cwe_text.split(":", 1)
            return cwe_id.strip(), description.strip()
        return cwe_text, cwe_text
