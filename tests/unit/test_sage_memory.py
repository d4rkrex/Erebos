"""Unit tests for SAGE memory."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from erebos.core.sage import SageMemory, SageQuery


class TestSageMemory:
    """Tests for SageMemory."""

    def test_record_and_query_round_trip(self, tmp_path: Path):
        sage = SageMemory(tmp_path / "sage.db")

        for _ in range(4):
            sage.record_decision(
                finding_title="SQL Injection on /login",
                tool="nuclei",
                cwe="CWE-89",
                decision="confirmed",
                project_stack="django",
                target="app.example.com",
            )

        pattern = sage.query_pattern("SQL Injection on /login", "nuclei", "CWE-89")

        assert pattern is not None
        assert pattern.pattern_type == "true_positive"
        assert pattern.tool == "nuclei"
        assert pattern.cwe == "CWE-89"
        assert pattern.occurrences == 4
        assert pattern.confidence > 0.6
        assert "django" in pattern.project_types
        assert "app.example.com" in pattern.metadata["targets"]
        assert sage.get_stack_insights("django")

    def test_confidence_growth_with_repeated_decisions(self, tmp_path: Path):
        sage = SageMemory(tmp_path / "sage.db")

        title = "JWT secret disclosure"
        for _ in range(4):
            sage.record_decision(title, "semgrep", "CWE-798", "confirmed", "express", "api-1")
        initial = sage.query_pattern(title, "semgrep", "CWE-798")
        assert initial is not None

        sage.record_decision(title, "semgrep", "CWE-798", "confirmed", "express", "api-2")
        grown = sage.query_pattern(title, "semgrep", "CWE-798")

        assert grown is not None
        assert grown.confidence >= initial.confidence
        assert grown.occurrences == 5

        sage.record_decision(title, "semgrep", "CWE-798", "false_positive", "express", "api-3")
        contradicted = sage.query_pattern(title, "semgrep", "CWE-798")

        assert contradicted is not None
        assert contradicted.confidence < grown.confidence

    def test_fp_pattern_detection_threshold(self, tmp_path: Path):
        sage = SageMemory(tmp_path / "sage.db")
        title = "Missing X-Frame-Options on 10.10.10.10"

        for _ in range(4):
            sage.record_decision(title, "nuclei", "CWE-1021", "false_positive", "express", "a")

        assert sage.get_fp_patterns() == []
        candidate = sage.query_pattern(title, "nuclei", "CWE-1021")
        assert candidate is not None
        assert candidate.pattern_type == "tool_quirk"

        sage.record_decision(title, "nuclei", "CWE-1021", "false_positive", "express", "b")
        fps = sage.get_fp_patterns(tool="nuclei", cwe="CWE-1021")

        assert len(fps) == 1
        assert fps[0].pattern_type == "false_positive"
        assert fps[0].occurrences == 5

    def test_tool_reliability_calculation(self, tmp_path: Path):
        sage = SageMemory(tmp_path / "sage.db")

        for index in range(3):
            sage.record_decision(
                f"Semgrep FP #{index}",
                "semgrep",
                "CWE-79",
                "false_positive",
                "express",
                f"fp-{index}",
            )
        for index in range(2):
            sage.record_decision(
                f"Semgrep TP #{index}",
                "semgrep",
                "CWE-79",
                "confirmed",
                "express",
                f"tp-{index}",
            )

        stats = sage.get_tool_reliability("semgrep", "CWE-79")

        assert stats["total_seen"] == 5.0
        assert stats["fp_rate"] == 0.6
        assert 0.0 < stats["confidence"] <= 1.0

    def test_prune_stale(self, tmp_path: Path):
        db_path = tmp_path / "sage.db"
        sage = SageMemory(db_path)
        sage.record_decision("Stale title", "nuclei", None, "confirmed", "django", "target-1")
        sage.record_decision("Stale title", "nuclei", None, "confirmed", "django", "target-1")
        sage.record_decision("Stale title", "nuclei", None, "confirmed", "django", "target-1")
        sage.record_decision("Stale title", "nuclei", None, "confirmed", "django", "target-1")

        with sqlite3.connect(db_path) as conn:
            old_time = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
            conn.execute("UPDATE patterns SET last_seen = ?", (old_time,))
            conn.commit()

        removed = sage.prune_stale(max_age_days=180)

        assert removed == 1
        assert sage.query_pattern("Stale title", "nuclei", None) is None

    def test_title_normalization_strips_dynamic_parts(self, tmp_path: Path):
        sage = SageMemory(tmp_path / "sage.db")

        left = (
            "Error 550e8400-e29b-41d4-a716-446655440000 from 192.168.1.10 digest deadbeefdeadbeef"
        )
        right = "Error 123e4567-e89b-12d3-a456-426614174000 from 10.0.0.7 digest cafebabecafebabe"

        assert sage._normalize_title(left) == sage._normalize_title(right)

    def test_export_summary(self, tmp_path: Path):
        sage = SageMemory(tmp_path / "sage.db")
        for _ in range(5):
            sage.record_decision(
                "Header disclosure",
                "nuclei",
                "CWE-200",
                "false_positive",
                "express",
                "app-1",
            )
        for _ in range(4):
            sage.record_decision(
                "SQL injection",
                "semgrep",
                "CWE-89",
                "confirmed",
                "django",
                "app-2",
            )

        summary = sage.export_summary()

        assert summary["total_patterns"] == 2
        assert summary["total_decisions"] == 9
        assert summary["known_false_positives"] == 1
        assert summary["patterns_by_type"]["false_positive"] == 1
        assert summary["tool_breakdown"]["nuclei"] == 1
        assert summary["tool_breakdown"]["semgrep"] == 1

    def test_concurrent_access(self, tmp_path: Path):
        sage = SageMemory(tmp_path / "sage.db")
        errors: list[Exception] = []

        def worker(worker_id: int) -> None:
            try:
                for attempt in range(10):
                    sage.record_decision(
                        "Concurrent reflected xss on 127.0.0.1",
                        "dalfox",
                        "CWE-79",
                        "false_positive",
                        "react",
                        f"target-{worker_id}-{attempt}",
                    )
            except Exception as exc:  # pragma: no cover - diagnostic path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors
        stats = sage.get_tool_reliability("dalfox", "CWE-79")
        assert stats["total_seen"] == 50.0
        fps = sage.get_fp_patterns(tool="dalfox", cwe="CWE-79")
        assert len(fps) == 1
        assert fps[0].occurrences == 50

    def test_sage_query_integration(self, tmp_path: Path):
        sage = SageMemory(tmp_path / "sage.db")
        query = SageQuery(sage)

        for _ in range(5):
            sage.record_decision(
                "Verbose server banner at 203.0.113.7",
                "httpx",
                "CWE-200",
                "false_positive",
                "spring",
                "prod-1",
            )

        is_known_fp, confidence = query.is_known_fp(
            "Verbose server banner at 198.51.100.8",
            "httpx",
            "CWE-200",
        )

        assert is_known_fp is True
        assert confidence > 0.6
        assert query.get_tool_fp_rate("httpx") == 1.0
