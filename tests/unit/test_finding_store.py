"""Unit tests for finding store enrichment features."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from erebos.core.finding import Finding, FindingEvidence, Severity, Phase
from erebos.storage.scan_state import FindingStore


class TestFindingStoreEnrichment:
    """Tests for FindingStore enrichment and validation."""

    def test_batch_update(self, tmp_path):
        """Test batch update updates all findings atomically."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        store = FindingStore(storage_dir)
        scan_id = "batch-test"

        # Create 10 findings
        findings = []
        for i in range(10):
            finding = Finding(
                title=f"Finding {i}",
                description=f"Description {i}",
                severity=Severity.MEDIUM,
                tool="nmap",
                phase_found=Phase.RECON,
                cvss=5.0 + i * 0.5,
                cves=[f"CVE-2024-{1000 + i}"],
                evidence=FindingEvidence(url=f"https://example.com/port{i}"),
            )
            findings.append(finding)

        # Act
        store.update_findings_batch(scan_id, findings)

        # Assert
        findings_file = storage_dir / scan_id / "findings.json"
        assert findings_file.exists()

        # Verify atomic write - check temp file was cleaned up
        temp_file = findings_file.with_suffix(".tmp")
        assert not temp_file.exists()

        # Verify all 10 findings saved
        saved_findings = store.get_findings(scan_id)
        assert len(saved_findings) == 10

        # Verify enrichment data preserved
        for i, finding in enumerate(saved_findings):
            assert finding.cvss == 5.0 + i * 0.5
            assert f"CVE-2024-{1000 + i}" in finding.cves

    def test_cvss_validation(self, tmp_path):
        """Test CVSS validation with invalid scores."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        store = FindingStore(storage_dir)
        scan_id = "cvss-validation"

        findings = [
            # Valid scores
            Finding(
                title="Valid Low",
                description="Valid CVSS 3.5",
                severity=Severity.LOW,
                tool="nuclei",
                phase_found=Phase.VULN_SCAN,
                cvss=3.5,
                evidence=FindingEvidence(url="https://example.com/1"),
            ),
            Finding(
                title="Valid High",
                description="Valid CVSS 9.8",
                severity=Severity.CRITICAL,
                tool="nuclei",
                phase_found=Phase.VULN_SCAN,
                cvss=9.8,
                evidence=FindingEvidence(url="https://example.com/2"),
            ),
            # Invalid scores - use model_construct to bypass Pydantic validation
            Finding.model_construct(
                id="test-invalid-high",
                title="Invalid High",
                description="Invalid CVSS 12.5",
                severity=Severity.CRITICAL,
                tool="nuclei",
                phase_found=Phase.VULN_SCAN,
                cvss=12.5,  # Invalid - too high
                evidence=FindingEvidence(url="https://example.com/3"),
                timestamp=datetime.now(timezone.utc),
            ),
            Finding.model_construct(
                id="test-invalid-negative",
                title="Invalid Negative",
                description="Invalid CVSS -1.0",
                severity=Severity.INFO,
                tool="nuclei",
                phase_found=Phase.VULN_SCAN,
                cvss=-1.0,  # Invalid - negative
                evidence=FindingEvidence(url="https://example.com/4"),
                timestamp=datetime.now(timezone.utc),
            ),
        ]

        # Act - expect logging for invalid scores
        with patch("logging.Logger.error") as mock_error:
            store.update_findings_batch(scan_id, findings)

            # Assert validation errors were logged
            assert mock_error.call_count == 2  # Two invalid scores

        # Assert - invalid scores set to None
        saved_findings = store.get_findings(scan_id)
        assert len(saved_findings) == 4

        # Valid scores preserved
        assert saved_findings[0].cvss == 3.5
        assert saved_findings[1].cvss == 9.8

        # Invalid scores set to None
        assert saved_findings[2].cvss is None
        assert saved_findings[3].cvss is None

    def test_partial_enrichment(self, tmp_path):
        """Test partial enrichment warning (CVEs but no CVSS)."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        store = FindingStore(storage_dir)
        scan_id = "partial-enrichment"

        findings = [
            # Fully enriched
            Finding(
                title="Full Enrichment",
                description="Has CVSS and CVEs",
                severity=Severity.HIGH,
                tool="nmap",
                phase_found=Phase.RECON,
                cvss=7.5,
                cves=["CVE-2024-1234", "CVE-2024-5678"],
                evidence=FindingEvidence(url="https://example.com/1"),
            ),
            # Partially enriched (CVEs but no CVSS)
            Finding(
                title="Partial Enrichment 1",
                description="Has CVEs but no CVSS",
                severity=Severity.MEDIUM,
                tool="nmap",
                phase_found=Phase.RECON,
                cvss=None,
                cves=["CVE-2024-9999"],
                evidence=FindingEvidence(url="https://example.com/2"),
            ),
            Finding(
                title="Partial Enrichment 2",
                description="Has CVEs but no CVSS",
                severity=Severity.LOW,
                tool="nmap",
                phase_found=Phase.RECON,
                cvss=None,
                cves=["CVE-2024-8888", "CVE-2024-7777"],
                evidence=FindingEvidence(url="https://example.com/3"),
            ),
            # No enrichment
            Finding(
                title="No Enrichment",
                description="No CVSS or CVEs",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="https://example.com/4"),
            ),
        ]

        # Act - expect warnings for partial enrichment
        with patch("logging.Logger.warning") as mock_warning:
            store.update_findings_batch(scan_id, findings)

            # Assert warnings for partial enrichment (2 findings have CVEs but no CVSS)
            assert mock_warning.call_count == 2

            # Check warning messages mention partial enrichment
            for call in mock_warning.call_args_list:
                message = call[0][0]
                assert "partial enrichment" in message.lower()

        # Assert all findings saved
        saved_findings = store.get_findings(scan_id)
        assert len(saved_findings) == 4

    def test_batch_update_failure_rollback(self, tmp_path):
        """Test batch update rollback on IOError."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        store = FindingStore(storage_dir)
        scan_id = "rollback-test"

        # Create initial findings
        initial_findings = [
            Finding(
                title="Initial Finding",
                description="Original data",
                severity=Severity.LOW,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="https://example.com/1"),
            )
        ]
        store.update_findings_batch(scan_id, initial_findings)

        # Verify initial state
        saved = store.get_findings(scan_id)
        assert len(saved) == 1
        assert saved[0].title == "Initial Finding"

        # Create new findings to update
        new_findings = [
            Finding(
                title="Updated Finding",
                description="New data",
                severity=Severity.HIGH,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="https://example.com/2"),
            )
        ]

        # Act - mock IOError during save
        with patch.object(store, "_save_findings", side_effect=IOError("Disk full")):
            with pytest.raises(IOError):
                store.update_findings_batch(scan_id, new_findings)

        # Assert - verify temp file was cleaned up
        findings_file = storage_dir / scan_id / "findings.json"
        temp_file = findings_file.with_suffix(".tmp")
        assert not temp_file.exists(), "Temp file should be cleaned up on error"

        # Assert - original data preserved (rollback successful)
        preserved = store.get_findings(scan_id)
        assert len(preserved) == 1
        assert preserved[0].title == "Initial Finding"

    def test_cve_format_validation(self, tmp_path):
        """Test CVE ID format validation."""
        # Arrange
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        store = FindingStore(storage_dir)
        scan_id = "cve-validation"

        findings = [
            Finding(
                title="Valid and Invalid CVEs",
                description="Mix of valid and invalid CVE IDs",
                severity=Severity.CRITICAL,
                tool="nuclei",
                phase_found=Phase.VULN_SCAN,
                cvss=9.8,
                cves=[
                    "CVE-2024-1234",  # Valid
                    "CVE-2023-99999",  # Valid (5 digits)
                    "CVE-2022-12345678",  # Valid (8 digits)
                    "CVE-202-1234",  # Invalid (year too short)
                    "CVE-2024-123",  # Invalid (ID too short)
                    "INVALID-FORMAT",  # Invalid
                    "CVE-2024",  # Invalid
                ],
                evidence=FindingEvidence(url="https://example.com/1"),
            ),
        ]

        # Act - expect warnings for invalid CVE formats
        with patch("logging.Logger.warning") as mock_warning:
            store.update_findings_batch(scan_id, findings)

            # Assert warnings for invalid CVE IDs
            assert mock_warning.call_count == 4  # 4 invalid CVE formats

        # Assert - only valid CVEs preserved
        saved_findings = store.get_findings(scan_id)
        assert len(saved_findings) == 1

        valid_cves = saved_findings[0].cves
        assert len(valid_cves) == 3
        assert "CVE-2024-1234" in valid_cves
        assert "CVE-2023-99999" in valid_cves
        assert "CVE-2022-12345678" in valid_cves

        # Invalid CVEs filtered out
        assert "CVE-202-1234" not in valid_cves
        assert "CVE-2024-123" not in valid_cves
        assert "INVALID-FORMAT" not in valid_cves
        assert "CVE-2024" not in valid_cves
