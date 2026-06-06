"""SQLite-backed SAGE memory for cross-scan learning."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_DYNAMIC_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
_DYNAMIC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DYNAMIC_HEX_RE = re.compile(r"\b[a-f0-9]{12,}\b", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")
_VALID_DECISIONS = {"confirmed", "false_positive", "uncertain"}
_PATTERN_TYPES = {"false_positive", "true_positive", "tool_quirk", "stack_pattern"}


@dataclass
class SagePattern:
    """A learned pattern from scan history."""

    pattern_hash: str
    pattern_type: str
    tool: str
    cwe: Optional[str]
    description: str
    confidence: float
    occurrences: int
    first_seen: str
    last_seen: str
    project_types: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "SagePattern":
        """Build a SagePattern from a SQLite row."""
        return cls(
            pattern_hash=row["pattern_hash"],
            pattern_type=row["pattern_type"],
            tool=row["tool"],
            cwe=row["cwe"],
            description=row["description"] or "",
            confidence=float(row["confidence"]),
            occurrences=int(row["occurrences"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            project_types=json.loads(row["project_types"] or "[]"),
            metadata=json.loads(row["metadata"] or "{}"),
        )


class SageMemory:
    """Cross-scan knowledge accumulation system.

    Stores patterns learned from scan history to improve future scans.
    Persisted in SQLite at ~/.erebos/sage.db
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = Path(db_path or Path.home() / ".erebos" / "sage.db").expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._pool_lock = threading.Lock()
        self._write_lock = threading.RLock()
        self._connections: Dict[int, sqlite3.Connection] = {}
        self._initialize_db()

    @staticmethod
    def _normalize_title(title: str) -> str:
        """Normalize finding titles to reduce dynamic noise."""
        normalized = title.strip().lower()
        normalized = _DYNAMIC_UUID_RE.sub("<uuid>", normalized)
        normalized = _DYNAMIC_IP_RE.sub("<ip>", normalized)
        normalized = _DYNAMIC_HEX_RE.sub("<hash>", normalized)
        normalized = _WHITESPACE_RE.sub(" ", normalized)
        return normalized.strip()

    def _pattern_hash(self, finding_title: str, tool: str, cwe: Optional[str]) -> Tuple[str, str]:
        normalized = self._normalize_title(finding_title)
        digest = hashlib.sha256(f"{tool}|{cwe or ''}|{normalized}".encode("utf-8")).hexdigest()
        return digest, normalized

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _get_connection(self) -> sqlite3.Connection:
        thread_id = threading.get_ident()
        with self._pool_lock:
            connection = self._connections.get(thread_id)
            if connection is None:
                connection = sqlite3.connect(
                    self._db_path,
                    check_same_thread=False,
                    timeout=30.0,
                )
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = NORMAL")
                self._connections[thread_id] = connection
            return connection

    def _initialize_db(self) -> None:
        conn = self._get_connection()
        with conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS patterns (
                    id INTEGER PRIMARY KEY,
                    pattern_hash TEXT UNIQUE NOT NULL,
                    pattern_type TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    cwe TEXT,
                    title_normalized TEXT NOT NULL,
                    description TEXT,
                    confidence REAL DEFAULT 0.5,
                    occurrences INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    project_types TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY,
                    pattern_hash TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    project_stack TEXT,
                    target TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (pattern_hash) REFERENCES patterns(pattern_hash)
                );

                CREATE INDEX IF NOT EXISTS idx_patterns_tool_cwe ON patterns(tool, cwe);
                CREATE INDEX IF NOT EXISTS idx_patterns_type ON patterns(pattern_type);
                CREATE INDEX IF NOT EXISTS idx_decisions_hash ON decisions(pattern_hash);
                """
            )

    def record_decision(
        self,
        finding_title: str,
        tool: str,
        cwe: Optional[str],
        decision: str,
        project_stack: str,
        target: str,
    ) -> None:
        """Record a validation decision for future learning."""
        if decision not in _VALID_DECISIONS:
            raise ValueError(f"Unsupported decision: {decision}")

        pattern_hash, title_normalized = self._pattern_hash(finding_title, tool, cwe)
        now = self._now()

        with self._write_lock:
            conn = self._get_connection()
            with conn:
                row = conn.execute(
                    "SELECT * FROM patterns WHERE pattern_hash = ?",
                    (pattern_hash,),
                ).fetchone()

                if row is None:
                    conn.execute(
                        """
                        INSERT INTO patterns (
                            pattern_hash, pattern_type, tool, cwe, title_normalized,
                            description, confidence, occurrences, first_seen, last_seen,
                            project_types, metadata
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            pattern_hash,
                            "tool_quirk" if decision == "false_positive" else "true_positive",
                            tool,
                            cwe,
                            title_normalized,
                            f"Learned pattern for '{title_normalized}' from {tool}",
                            0.5,
                            1,
                            now,
                            now,
                            json.dumps([project_stack] if project_stack else []),
                            json.dumps(
                                {"targets": [target] if target else [], "last_decision": decision}
                            ),
                        ),
                    )
                else:
                    project_types = self._merge_unique_json_list(
                        row["project_types"], project_stack
                    )
                    metadata = self._merge_metadata(row["metadata"], decision, target)
                    conn.execute(
                        """
                        UPDATE patterns
                        SET last_seen = ?,
                            project_types = ?,
                            metadata = ?
                        WHERE pattern_hash = ?
                        """,
                        (
                            now,
                            json.dumps(project_types),
                            json.dumps(metadata),
                            pattern_hash,
                        ),
                    )

                conn.execute(
                    """
                    INSERT INTO decisions (pattern_hash, decision, project_stack, target, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (pattern_hash, decision, project_stack, target, now),
                )
                self._refresh_pattern_state(conn, pattern_hash)

    def _merge_unique_json_list(self, raw_json: str, value: str) -> List[str]:
        items = json.loads(raw_json or "[]")
        if value and value not in items:
            items.append(value)
        return items

    def _merge_metadata(self, raw_json: str, decision: str, target: str) -> Dict[str, Any]:
        metadata = json.loads(raw_json or "{}")
        targets = list(metadata.get("targets", []))
        if target and target not in targets:
            targets.append(target)
        metadata["targets"] = targets
        metadata["last_decision"] = decision
        return metadata

    def _refresh_pattern_state(self, conn: sqlite3.Connection, pattern_hash: str) -> None:
        stats = conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN decision = 'false_positive' THEN 1 ELSE 0 END) AS fp_count,
                SUM(CASE WHEN decision = 'confirmed' THEN 1 ELSE 0 END) AS confirmed_count,
                SUM(CASE WHEN decision = 'uncertain' THEN 1 ELSE 0 END) AS uncertain_count
            FROM decisions
            WHERE pattern_hash = ?
            """,
            (pattern_hash,),
        ).fetchone()

        total = int(stats["total"] or 0)
        fp_count = int(stats["fp_count"] or 0)
        confirmed_count = int(stats["confirmed_count"] or 0)
        uncertain_count = int(stats["uncertain_count"] or 0)
        dominant = max(fp_count, confirmed_count, uncertain_count)
        consistency = dominant / total if total else 0.0
        evidence_factor = min(1.0, 0.5 + (total / 10.0))
        contradiction_penalty = max(total - dominant - uncertain_count, 0) * 0.03
        confidence = max(0.0, min(1.0, (consistency * evidence_factor) - contradiction_penalty))

        pattern_type = self._derive_pattern_type(fp_count, confirmed_count, uncertain_count)
        conn.execute(
            """
            UPDATE patterns
            SET pattern_type = ?, confidence = ?, occurrences = ?
            WHERE pattern_hash = ?
            """,
            (pattern_type, confidence, total, pattern_hash),
        )

    def _derive_pattern_type(
        self,
        fp_count: int,
        confirmed_count: int,
        uncertain_count: int,
    ) -> str:
        if fp_count >= 5 and fp_count > confirmed_count:
            return "false_positive"
        if confirmed_count >= 3 and confirmed_count >= fp_count:
            return "true_positive"
        if fp_count > confirmed_count:
            return "tool_quirk"
        if uncertain_count > max(fp_count, confirmed_count):
            return "stack_pattern"
        return "true_positive"

    def query_pattern(
        self, finding_title: str, tool: str, cwe: Optional[str]
    ) -> Optional[SagePattern]:
        """Check if we have a known pattern for this finding type."""
        pattern_hash, _ = self._pattern_hash(finding_title, tool, cwe)
        row = (
            self._get_connection()
            .execute(
                "SELECT * FROM patterns WHERE pattern_hash = ?",
                (pattern_hash,),
            )
            .fetchone()
        )
        if row is None:
            return None
        pattern = SagePattern.from_row(row)
        if pattern.occurrences > 3 and pattern.confidence > 0.6:
            return pattern
        return None

    def get_fp_patterns(
        self, tool: Optional[str] = None, cwe: Optional[str] = None
    ) -> List[SagePattern]:
        """Get known false positive patterns, optionally filtered."""
        clauses = ["pattern_type = ?"]
        params: List[Optional[str]] = ["false_positive"]
        if tool is not None:
            clauses.append("tool = ?")
            params.append(tool)
        if cwe is not None:
            clauses.append("cwe = ?")
            params.append(cwe)
        rows = (
            self._get_connection()
            .execute(
                f"SELECT * FROM patterns WHERE {' AND '.join(clauses)} ORDER BY confidence DESC, occurrences DESC",
                tuple(params),
            )
            .fetchall()
        )
        return [SagePattern.from_row(row) for row in rows]

    def get_tool_reliability(self, tool: str, cwe: Optional[str] = None) -> Dict[str, float]:
        """Get reliability stats for a tool."""
        clauses = ["p.tool = ?"]
        params: List[Optional[str]] = [tool]
        if cwe is not None:
            clauses.append("p.cwe = ?")
            params.append(cwe)
        stats = (
            self._get_connection()
            .execute(
                f"""
            SELECT
                COUNT(d.id) AS total_seen,
                SUM(CASE WHEN d.decision = 'false_positive' THEN 1 ELSE 0 END) AS fp_count,
                SUM(CASE WHEN d.decision = 'confirmed' THEN 1 ELSE 0 END) AS confirmed_count,
                SUM(CASE WHEN d.decision = 'uncertain' THEN 1 ELSE 0 END) AS uncertain_count
            FROM decisions d
            JOIN patterns p ON p.pattern_hash = d.pattern_hash
            WHERE {' AND '.join(clauses)}
            """,
                tuple(params),
            )
            .fetchone()
        )

        total_seen = float(stats["total_seen"] or 0)
        if total_seen == 0:
            return {"fp_rate": 0.0, "confidence": 0.0, "total_seen": 0.0}

        fp_count = float(stats["fp_count"] or 0)
        confirmed_count = float(stats["confirmed_count"] or 0)
        uncertain_count = float(stats["uncertain_count"] or 0)
        fp_rate = fp_count / total_seen
        confidence = max(
            0.0, min(1.0, ((fp_count + confirmed_count) / total_seen) * min(1.0, total_seen / 10.0))
        )
        if uncertain_count:
            confidence *= max(0.0, 1.0 - (uncertain_count / total_seen) * 0.5)
        return {
            "fp_rate": fp_rate,
            "confidence": confidence,
            "total_seen": total_seen,
        }

    def get_stack_insights(self, stack: str) -> List[SagePattern]:
        """Get patterns common to a specific tech stack."""
        rows = (
            self._get_connection()
            .execute("SELECT * FROM patterns ORDER BY confidence DESC, occurrences DESC")
            .fetchall()
        )
        return [
            SagePattern.from_row(row)
            for row in rows
            if stack in json.loads(row["project_types"] or "[]")
        ]

    def prune_stale(self, max_age_days: int = 180) -> int:
        """Remove patterns not seen in N days. Returns count removed."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        conn = self._get_connection()
        with self._write_lock:
            stale_hashes = [
                row["pattern_hash"]
                for row in conn.execute("SELECT pattern_hash, last_seen FROM patterns").fetchall()
                if datetime.fromisoformat(row["last_seen"]) < cutoff
            ]
            if not stale_hashes:
                return 0
            placeholders = ", ".join("?" for _ in stale_hashes)
            with conn:
                conn.execute(
                    f"DELETE FROM decisions WHERE pattern_hash IN ({placeholders})",
                    tuple(stale_hashes),
                )
                conn.execute(
                    f"DELETE FROM patterns WHERE pattern_hash IN ({placeholders})",
                    tuple(stale_hashes),
                )
        return len(stale_hashes)

    def export_summary(self) -> Dict[str, Any]:
        """Export summary stats for CLI display."""
        conn = self._get_connection()
        total_patterns = int(conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0])
        total_decisions = int(conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0])

        patterns_by_type = {
            row["pattern_type"]: row["count"]
            for row in conn.execute(
                "SELECT pattern_type, COUNT(*) AS count FROM patterns GROUP BY pattern_type"
            ).fetchall()
        }
        tool_breakdown = {
            row["tool"]: row["count"]
            for row in conn.execute(
                "SELECT tool, COUNT(*) AS count FROM patterns GROUP BY tool"
            ).fetchall()
        }
        return {
            "total_patterns": total_patterns,
            "total_decisions": total_decisions,
            "known_false_positives": len(self.get_fp_patterns()),
            "patterns_by_type": patterns_by_type,
            "tool_breakdown": tool_breakdown,
        }


class SageQuery:
    """Query helper for validation pipeline integration."""

    def __init__(self, sage: SageMemory):
        self._sage = sage

    def is_known_fp(self, title: str, tool: str, cwe: Optional[str]) -> Tuple[bool, float]:
        """Returns (is_known_fp, confidence). Used by Stage A."""
        pattern = self._sage.query_pattern(title, tool, cwe)
        if pattern is None or pattern.pattern_type != "false_positive":
            return False, 0.0
        return True, pattern.confidence

    def get_tool_fp_rate(self, tool: str) -> float:
        """Get historical FP rate for tool. Used to weight findings."""
        return float(self._sage.get_tool_reliability(tool)["fp_rate"])
