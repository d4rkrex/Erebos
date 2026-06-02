"""Unit tests for baseline capture models and exploit response detectors."""

from __future__ import annotations

from erebos.exploits.base import BaselineResult
from erebos.exploits.detectors.count_detector import ResponseCountDetector
from erebos.exploits.detectors.size_detector import ResponseSizeAnomalyDetector
from erebos.exploits.detectors.structural_detector import StructuralDiffDetector


class TestResponseSizeAnomalyDetector:
    def test_size_detector_flags_when_2x_larger(self):
        detector = ResponseSizeAnomalyDetector()
        baseline = BaselineResult(response_size=100)

        assert detector.check(baseline, "x" * 250) is True

    def test_size_detector_no_flag_within_threshold(self):
        detector = ResponseSizeAnomalyDetector()
        baseline = BaselineResult(response_size=100)

        assert detector.check(baseline, "x" * 150) is False

    def test_size_detector_custom_multiplier(self):
        detector = ResponseSizeAnomalyDetector(multiplier=3.0)
        baseline = BaselineResult(response_size=100)

        assert detector.check(baseline, "x" * 250) is False
        assert detector.check(baseline, "x" * 350) is True

    def test_size_detector_zero_baseline(self):
        detector = ResponseSizeAnomalyDetector()
        baseline = BaselineResult(response_size=0)

        assert detector.check(baseline, "x" * 250) is False

    def test_size_detector_describe_match(self):
        detector = ResponseSizeAnomalyDetector()
        baseline = BaselineResult(response_size=100)

        description = detector.describe_match(baseline, "x" * 250)

        assert "response_size_anomaly" in description
        assert "payload=250B" in description
        assert "baseline=100B" in description
        assert "ratio=2.5x" in description


class TestResponseCountDetector:
    def test_count_detector_flags_absolute_threshold(self):
        detector = ResponseCountDetector()
        baseline = BaselineResult(array_item_count=3)
        response_body = "[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]"

        assert detector.check(baseline, response_body) is True

    def test_count_detector_flags_multiplier_threshold(self):
        detector = ResponseCountDetector()
        baseline = BaselineResult(array_item_count=3)
        response_body = "[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]"

        assert detector.check(baseline, response_body) is True

    def test_count_detector_no_flag_below_both(self):
        detector = ResponseCountDetector()
        baseline = BaselineResult(array_item_count=5)
        response_body = "[1, 2, 3, 4, 5, 6, 7, 8]"

        assert detector.check(baseline, response_body) is False

    def test_count_detector_handles_nested_data_field(self):
        detector = ResponseCountDetector()
        baseline = BaselineResult(array_item_count=1)
        response_body = '{"data": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]}'

        assert detector.check(baseline, response_body) is True

    def test_count_detector_returns_false_on_non_json(self):
        detector = ResponseCountDetector()
        baseline = BaselineResult(array_item_count=3)

        assert detector.check(baseline, "<html><body>Error</body></html>") is False

    def test_count_detector_none_baseline(self):
        detector = ResponseCountDetector()
        baseline = BaselineResult(array_item_count=None)
        response_body = "[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]"

        assert detector.check(baseline, response_body) is False


class TestStructuralDiffDetector:
    def test_structural_detector_flags_new_keys(self):
        detector = StructuralDiffDetector()
        baseline = BaselineResult(json_keys=["status", "data"])
        response_body = '{"status": "ok", "data": [], "admin": true, "password": "secret"}'

        assert detector.check(baseline, response_body) is True

    def test_structural_detector_no_flag_same_keys(self):
        detector = StructuralDiffDetector()
        baseline = BaselineResult(json_keys=["status", "data"])
        response_body = '{"status": "ok", "data": []}'

        assert detector.check(baseline, response_body) is False

    def test_structural_detector_subset_of_baseline(self):
        detector = StructuralDiffDetector()
        baseline = BaselineResult(json_keys=["status", "data", "admin"])
        response_body = '{"status": "ok", "data": []}'

        assert detector.check(baseline, response_body) is False

    def test_structural_detector_array_first_item_keys(self):
        keys = StructuralDiffDetector._extract_keys(
            '[{"status": "ok", "data": []}, {"status": "later", "admin": true}]'
        )

        assert keys == {"status", "data"}

    def test_structural_detector_empty_baseline_keys(self):
        detector = StructuralDiffDetector()
        baseline = BaselineResult(json_keys=[])
        response_body = '{"status": "ok", "admin": true}'

        assert detector.check(baseline, response_body) is False

    def test_structural_detector_non_json_response(self):
        detector = StructuralDiffDetector()
        baseline = BaselineResult(json_keys=["status", "data"])

        assert detector.check(baseline, "<html><body>Not JSON</body></html>") is False


class TestBaselineResult:
    def test_baseline_result_defaults(self):
        baseline = BaselineResult()

        assert baseline.response_size == 0
        assert baseline.status_code == 0
        assert baseline.json_keys == []
        assert baseline.array_item_count is None
        assert baseline.raw_body == ""

    def test_baseline_result_from_response(self):
        baseline = BaselineResult(
            response_size=128,
            status_code=200,
            json_keys=["status", "data"],
            array_item_count=3,
            raw_body='{"status": "ok", "data": [1, 2, 3]}',
        )

        assert baseline.response_size == 128
        assert baseline.status_code == 200
        assert baseline.json_keys == ["status", "data"]
        assert baseline.array_item_count == 3
        assert '"status": "ok"' in baseline.raw_body
