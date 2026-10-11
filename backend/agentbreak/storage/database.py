"""SQLite persistence for runs, cases, and trace events.

Uses WAL mode for concurrent reader/writer. All writes use short serialized
transactions — no open transaction around network awaits. JSON payload columns
store complex Pydantic models.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator
from uuid import UUID, uuid4

from agentbreak.contracts import (
    CaseResult,
    CaseResultPublic,
    CaseSpec,
    ErrorDetail,
    EventDraft,
    EventsResponse,
    ReplayBundle,
    ReplayCase,
    ReplayFingerprints,
    RunProgress,
    RunRequest,
    RunStatus,
    RunSummary,
    TraceEvent,
    canonical_sha256,
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id              TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'queued',
    request_json    TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    completed_at    TEXT,
    progress_json   TEXT NOT NULL DEFAULT '{}',
    metrics_json    TEXT NOT NULL DEFAULT '{}',
    error_json      TEXT,
    source_run_id   TEXT
);

CREATE TABLE IF NOT EXISTS cases (
    trial_id        TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    spec_json       TEXT NOT NULL,
    result_json     TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS idx_cases_run ON cases(run_id);

CREATE TABLE IF NOT EXISTS events (
    id              TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    trial_id        TEXT,
    type            TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    data_json       TEXT NOT NULL DEFAULT '{}',
    parent_ids_json TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY (run_id) REFERENCES runs(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_run_seq ON events(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);

CREATE TABLE IF NOT EXISTS candidates (
    id              TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    candidate_json  TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS idx_candidates_run ON candidates(run_id);
"""


class Database:
    """Thread-safe SQLite store. One instance shared by the whole app."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._local = threading.local()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, timeout=10)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close connection for current thread if open."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def initialize(self) -> None:
        """Create tables and mark stale runs interrupted."""
        conn = self._conn()
        conn.executescript(_SCHEMA)
        conn.execute(
            "UPDATE runs SET status = ?, completed_at = ? WHERE status IN (?, ?)",
            (
                RunStatus.INTERRUPTED.value,
                datetime.now(timezone.utc).isoformat(),
                RunStatus.QUEUED.value,
                RunStatus.RUNNING.value,
            ),
        )
        conn.commit()

    @contextmanager
    def _tx(self) -> Generator[sqlite3.Connection, None, None]:
        conn = self._conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # ------------------------------------------------------------------ runs
    def create_run(self, run_id: UUID, request: RunRequest, source_run_id: UUID | None = None) -> RunSummary:
        now = datetime.now(timezone.utc)
        progress = RunProgress()
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO runs (id, status, request_json, created_at, progress_json, source_run_id) VALUES (?,?,?,?,?,?)",
                (
                    str(run_id),
                    RunStatus.QUEUED.value,
                    request.model_dump_json(),
                    now.isoformat(),
                    progress.model_dump_json(),
                    str(source_run_id) if source_run_id else None,
                ),
            )
        return RunSummary(
            id=run_id,
            status=RunStatus.QUEUED,
            request=request,
            created_at=now,
            progress=progress,
            source_run_id=source_run_id,
        )

    def get_run(self, run_id: UUID) -> RunSummary | None:
        row = self._conn().execute("SELECT * FROM runs WHERE id = ?", (str(run_id),)).fetchone()
        if row is None:
            return None
        return self._row_to_summary(row)

    def list_runs(self, limit: int = 20) -> list[RunSummary]:
        rows = self._conn().execute(
            "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_summary(row) for row in rows]

    def update_run_status(self, run_id: UUID, status: RunStatus, error: ErrorDetail | None = None) -> None:
        completed_at = datetime.now(timezone.utc).isoformat() if status in (
            RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED, RunStatus.INTERRUPTED
        ) else None
        error_json = error.model_dump_json() if error else None
        with self._tx() as conn:
            conn.execute(
                "UPDATE runs SET status = ?, completed_at = COALESCE(?, completed_at), error_json = COALESCE(?, error_json) WHERE id = ?",
                (status.value, completed_at, error_json, str(run_id)),
            )

    def update_run_progress(self, run_id: UUID, progress: RunProgress) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE runs SET progress_json = ? WHERE id = ?",
                (progress.model_dump_json(), str(run_id)),
            )

    def update_run_metrics(self, run_id: UUID, metrics: dict) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE runs SET metrics_json = ? WHERE id = ?",
                (json.dumps(metrics, ensure_ascii=False, allow_nan=False), str(run_id)),
            )

    def count_active_runs(self) -> tuple[int, int]:
        """Return (running_count, queued_count)."""
        row = self._conn().execute(
            "SELECT "
            "SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running, "
            "SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queued "
            "FROM runs"
        ).fetchone()
        return (row["running"] or 0, row["queued"] or 0)

    # ------------------------------------------------------------------ cases
    def save_case_spec(self, run_id: UUID, spec: CaseSpec) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cases (trial_id, run_id, spec_json) VALUES (?,?,?)",
                (str(spec.trial_id), str(run_id), spec.model_dump_json()),
            )

    def save_case_result(self, run_id: UUID, result: CaseResult) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE cases SET result_json = ? WHERE trial_id = ? AND run_id = ?",
                (result.model_dump_json(), str(result.trial_id), str(run_id)),
            )

    def get_cases(self, run_id: UUID) -> list[CaseResultPublic]:
        rows = self._conn().execute(
            "SELECT result_json FROM cases WHERE run_id = ? AND result_json IS NOT NULL",
            (str(run_id),),
        ).fetchall()
        results = []
        for row in rows:
            full = CaseResult.model_validate_json(row["result_json"])
            results.append(full.to_public())
        return results

    def get_full_cases(self, run_id: UUID) -> list[tuple[CaseSpec, CaseResult]]:
        """Return (spec, result) pairs for completed cases — used by retest and export."""
        rows = self._conn().execute(
            "SELECT spec_json, result_json FROM cases WHERE run_id = ? AND result_json IS NOT NULL",
            (str(run_id),),
        ).fetchall()
        pairs = []
        for row in rows:
            spec = CaseSpec.model_validate_json(row["spec_json"])
            result = CaseResult.model_validate_json(row["result_json"])
            pairs.append((spec, result))
        return pairs

    # ------------------------------------------------------------------ events
    def next_seq(self, run_id: UUID) -> int:
        row = self._conn().execute(
            "SELECT COALESCE(MAX(seq), 0) AS max_seq FROM events WHERE run_id = ?",
            (str(run_id),),
        ).fetchone()
        return (row["max_seq"] or 0) + 1

    def save_event(self, event: TraceEvent) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO events (id, run_id, seq, trial_id, type, timestamp, data_json, parent_ids_json) VALUES (?,?,?,?,?,?,?,?)",
                (
                    str(event.id),
                    str(event.run_id),
                    event.seq,
                    str(event.trial_id) if event.trial_id else None,
                    event.type.value,
                    event.timestamp.isoformat(),
                    json.dumps(event.data, ensure_ascii=False, allow_nan=False),
                    json.dumps([str(pid) for pid in event.parent_event_ids]),
                ),
            )

    def get_events(self, run_id: UUID, after_seq: int = 0, limit: int = 200) -> EventsResponse:
        rows = self._conn().execute(
            "SELECT * FROM events WHERE run_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
            (str(run_id), after_seq, limit + 1),
        ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = [self._row_to_event(row) for row in rows]
        next_after = items[-1].seq if items else after_seq
        return EventsResponse(items=items, next_after_seq=next_after, has_more=has_more)

    def get_all_events(self, run_id: UUID) -> list[TraceEvent]:
        rows = self._conn().execute(
            "SELECT * FROM events WHERE run_id = ? ORDER BY seq ASC", (str(run_id),)
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    # ------------------------------------------------------------------ candidates
    def save_candidate(self, run_id: UUID, candidate_json: str, candidate_id: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO candidates (id, run_id, candidate_json) VALUES (?,?,?)",
                (candidate_id, str(run_id), candidate_json),
            )

    # ------------------------------------------------------------------ export
    def build_replay_bundle(self, run_id: UUID) -> ReplayBundle | None:
        run = self.get_run(run_id)
        if run is None:
            return None
        pairs = self.get_full_cases(run_id)
        if not pairs:
            return None
        events = self.get_all_events(run_id)
        replay_cases = []
        for spec, result in pairs:
            fingerprints = ReplayFingerprints(
                fixture_sha256=canonical_sha256(spec.fixture_snapshot),
                model_settings_sha256=canonical_sha256(spec.model_settings),
                policy_sha256=canonical_sha256({"version": spec.policy_version}),
            )
            replay_cases.append(ReplayCase(spec=spec, result=result, fingerprints=fingerprints))
        return ReplayBundle(
            run=run,
            exported_at=datetime.now(timezone.utc),
            cases=replay_cases,
            events=events,
        )

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _row_to_summary(row: sqlite3.Row) -> RunSummary:
        error = None
        if row["error_json"]:
            error = ErrorDetail.model_validate_json(row["error_json"])
        progress_data = json.loads(row["progress_json"]) if row["progress_json"] else {}
        progress = RunProgress.model_validate(progress_data) if progress_data else RunProgress()
        metrics = json.loads(row["metrics_json"]) if row["metrics_json"] else {}
        return RunSummary(
            id=UUID(row["id"]),
            status=RunStatus(row["status"]),
            request=RunRequest.model_validate_json(row["request_json"]),
            created_at=row["created_at"],
            completed_at=row["completed_at"],
            progress=progress,
            metrics=metrics,
            error=error,
            source_run_id=UUID(row["source_run_id"]) if row["source_run_id"] else None,
        )

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> TraceEvent:
        parent_ids = json.loads(row["parent_ids_json"]) if row["parent_ids_json"] else []
        data = json.loads(row["data_json"]) if row["data_json"] else {}
        return TraceEvent(
            id=UUID(row["id"]),
            run_id=UUID(row["run_id"]),
            seq=row["seq"],
            trial_id=UUID(row["trial_id"]) if row["trial_id"] else None,
            type=row["type"],
            timestamp=row["timestamp"],
            data=data,
            parent_event_ids=[UUID(pid) for pid in parent_ids],
        )
