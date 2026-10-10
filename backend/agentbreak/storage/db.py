"""SQLite persistence layer for AgentBreak runs, cases, and events."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from agentbreak.contracts import (
    CaseResult,
    CaseResultPublic,
    CaseSpec,
    EventDraft,
    ReplayCase,
    ReplayFingerprints,
    RunProgress,
    RunRequest,
    RunStatus,
    RunSummary,
    TraceEvent,
)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Database:
    """Thread-safe SQLite storage for runs, cases, and trace events."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            db_path,
            check_same_thread=False,
            autocommit=True,
        )
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    progress_json TEXT NOT NULL,
                    metrics_json TEXT NOT NULL,
                    error TEXT,
                    source_run_id TEXT
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    run_id TEXT NOT NULL,
                    trial_id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    candidate_id TEXT,
                    payload_sha256 TEXT,
                    fixture_sha256 TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    defense TEXT NOT NULL,
                    execution_mode TEXT NOT NULL,
                    spec_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    fingerprints_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    trial_id TEXT,
                    seq INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    parent_event_ids_json TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    schema_version INTEGER NOT NULL DEFAULT 1,
                    UNIQUE (run_id, seq),
                    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_run_seq ON events(run_id, seq);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_run_id ON cases(run_id);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at DESC);"
            )

    def mark_unfinished_interrupted(self) -> int:
        """Mark active/queued runs as interrupted after restart."""
        with self._lock:
            cur = self._conn.cursor()
            now = _now_utc().isoformat().replace("+00:00", "Z")
            cur.execute(
                """
                UPDATE runs
                SET status = 'interrupted', completed_at = ?
                WHERE status IN ('queued', 'running');
                """,
                (now,),
            )
            return cur.rowcount

    def create_run(
        self,
        request: RunRequest,
        *,
        run_id: UUID | None = None,
        source_run_id: UUID | None = None,
    ) -> RunSummary:
        assigned_id = run_id or uuid4()
        now = _now_utc()
        progress = RunProgress(
            scheduled=0,
            completed=0,
            failed=0,
            phase="queued",
        )
        summary = RunSummary(
            id=assigned_id,
            status=RunStatus.QUEUED,
            request=request,
            created_at=now,
            completed_at=None,
            progress=progress,
            metrics={},
            error=None,
            source_run_id=source_run_id,
        )
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT INTO runs (
                    id, status, request_json, created_at, completed_at,
                    progress_json, metrics_json, error, source_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(summary.id),
                    summary.status.value,
                    summary.request.model_dump_json(),
                    summary.created_at.isoformat().replace("+00:00", "Z"),
                    None,
                    summary.progress.model_dump_json(),
                    json.dumps(summary.metrics),
                    summary.error,
                    str(summary.source_run_id) if summary.source_run_id else None,
                ),
            )
        return summary

    def get_run_summary(self, run_id: UUID) -> RunSummary | None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM runs WHERE id = ?;", (str(run_id),))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_summary(row)

    def get_run_detail(
        self, run_id: UUID
    ) -> tuple[RunSummary, list[CaseResultPublic]] | None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM runs WHERE id = ?;", (str(run_id),))
            run_row = cur.fetchone()
            if not run_row:
                return None
            summary = self._row_to_summary(run_row)

            cur.execute(
                "SELECT result_json FROM cases WHERE run_id = ? ORDER BY created_at ASC;",
                (str(run_id),),
            )
            case_rows = cur.fetchall()
            cases = [
                CaseResult.model_validate_json(r["result_json"]).to_public()
                for r in case_rows
            ]
            return summary, cases

    def list_runs(self, limit: int = 20) -> list[RunSummary]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?;", (limit,)
            )
            rows = cur.fetchall()
            return [self._row_to_summary(r) for r in rows]

    def update_run(
        self,
        run_id: UUID,
        *,
        status: RunStatus | None = None,
        progress: RunProgress | None = None,
        metrics: dict | None = None,
        error: str | None = None,
        completed_at: datetime | None = None,
    ) -> None:
        with self._lock:
            cur = self._conn.cursor()
            updates = []
            params = []
            if status is not None:
                updates.append("status = ?")
                params.append(status.value)
            if progress is not None:
                updates.append("progress_json = ?")
                params.append(progress.model_dump_json())
            if metrics is not None:
                updates.append("metrics_json = ?")
                params.append(json.dumps(metrics))
            if error is not None:
                updates.append("error = ?")
                params.append(error)
            if completed_at is not None:
                updates.append("completed_at = ?")
                params.append(completed_at.isoformat().replace("+00:00", "Z"))
            if not updates:
                return
            params.append(str(run_id))
            cur.execute(
                f"UPDATE runs SET {', '.join(updates)} WHERE id = ?;", params
            )

    def save_case(
        self,
        spec: CaseSpec,
        result: CaseResult,
        fingerprints: ReplayFingerprints,
    ) -> None:
        now = _now_utc().isoformat().replace("+00:00", "Z")
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO cases (
                    run_id, trial_id, scenario_id, task_id, candidate_id,
                    payload_sha256, fixture_sha256, policy_version, defense,
                    execution_mode, spec_json, result_json, fingerprints_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(spec.run_id),
                    str(spec.trial_id),
                    spec.scenario.id,
                    spec.scenario.task_id,
                    str(spec.candidate.id) if spec.candidate else None,
                    spec.candidate.payload_sha256 if spec.candidate else None,
                    result.fixture_sha256,
                    spec.policy_version,
                    spec.defense.value,
                    spec.execution_mode.value,
                    spec.model_dump_json(),
                    result.model_dump_json(),
                    fingerprints.model_dump_json(),
                    now,
                ),
            )

    def get_replay_cases(self, run_id: UUID) -> list[ReplayCase]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT spec_json, result_json, fingerprints_json FROM cases WHERE run_id = ? ORDER BY created_at ASC;",
                (str(run_id),),
            )
            rows = cur.fetchall()
            return [
                ReplayCase(
                    spec=CaseSpec.model_validate_json(r["spec_json"]),
                    result=CaseResult.model_validate_json(r["result_json"]),
                    fingerprints=ReplayFingerprints.model_validate_json(
                        r["fingerprints_json"]
                    ),
                )
                for r in rows
            ]

    def get_max_event_seq(self, run_id: UUID) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT MAX(seq) as max_seq FROM events WHERE run_id = ?;",
                (str(run_id),),
            )
            row = cur.fetchone()
            if row and row["max_seq"] is not None:
                return int(row["max_seq"])
            return 0

    def get_event(self, run_id: UUID, event_id: UUID) -> TraceEvent | None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM events WHERE run_id = ? AND id = ?;",
                (str(run_id), str(event_id)),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_event(row)

    def save_event(self, event: TraceEvent) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT INTO events (
                    id, run_id, trial_id, seq, timestamp, type,
                    parent_event_ids_json, data_json, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(event.id),
                    str(event.run_id),
                    str(event.trial_id) if event.trial_id else None,
                    event.seq,
                    event.timestamp.isoformat().replace("+00:00", "Z"),
                    event.type.value,
                    json.dumps([str(p) for p in event.parent_event_ids]),
                    json.dumps(event.data),
                    event.schema_version,
                ),
            )

    def get_events_page(
        self, run_id: UUID, after_seq: int = 0, limit: int = 200
    ) -> tuple[list[TraceEvent], int, bool]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT * FROM events
                WHERE run_id = ? AND seq > ?
                ORDER BY seq ASC
                LIMIT ?;
                """,
                (str(run_id), after_seq, limit + 1),
            )
            rows = cur.fetchall()
            has_more = len(rows) > limit
            page_rows = rows[:limit]
            events = [self._row_to_event(r) for r in page_rows]
            next_after_seq = events[-1].seq if events else after_seq
            return events, next_after_seq, has_more

    def get_all_events(self, run_id: UUID) -> list[TraceEvent]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM events WHERE run_id = ? ORDER BY seq ASC;",
                (str(run_id),),
            )
            rows = cur.fetchall()
            return [self._row_to_event(r) for r in rows]

    def _row_to_summary(self, row: sqlite3.Row) -> RunSummary:
        return RunSummary(
            id=UUID(row["id"]),
            status=RunStatus(row["status"]),
            request=RunRequest.model_validate_json(row["request_json"]),
            created_at=row["created_at"],
            completed_at=row["completed_at"],
            progress=RunProgress.model_validate_json(row["progress_json"]),
            metrics=json.loads(row["metrics_json"]),
            error=row["error"],
            source_run_id=UUID(row["source_run_id"])
            if row["source_run_id"]
            else None,
        )

    def _row_to_event(self, row: sqlite3.Row) -> TraceEvent:
        parent_ids = [
            UUID(p) for p in json.loads(row["parent_event_ids_json"])
        ]
        return TraceEvent(
            schema_version=row["schema_version"],
            id=UUID(row["id"]),
            run_id=UUID(row["run_id"]),
            trial_id=UUID(row["trial_id"]) if row["trial_id"] else None,
            seq=row["seq"],
            timestamp=row["timestamp"],
            type=row["type"],
            parent_event_ids=parent_ids,
            data=json.loads(row["data_json"]),
        )


_GLOBAL_DB: Database | None = None
_DB_LOCK = threading.Lock()


def get_db(db_path: str | None = None) -> Database:
    global _GLOBAL_DB
    with _DB_LOCK:
        if _GLOBAL_DB is None or db_path is not None:
            resolved_path = (
                db_path
                or os.environ.get("AGENTBREAK_DB_PATH")
                or "./data/agentbreak.db"
            )
            _GLOBAL_DB = Database(resolved_path)
        return _GLOBAL_DB


def reset_db_for_test(db_path: str = ":memory:") -> Database:
    global _GLOBAL_DB
    with _DB_LOCK:
        _GLOBAL_DB = Database(db_path)
        return _GLOBAL_DB
