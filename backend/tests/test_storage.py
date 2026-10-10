"""Tests for the SQLite persistence layer (storage.database.Database)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from agentbreak.contracts import (
    Budget,
    ErrorDetail,
    EventDraft,
    EventType,
    RunProgress,
    RunRequest,
    RunStatus,
    TraceEvent,
)
from agentbreak.storage.database import Database


@pytest.fixture
def db():
    """In-memory database for each test."""
    d = Database(":memory:")
    d.initialize()
    return d


class TestRunCrud:
    def test_create_and_get_run(self, db: Database):
        run_id = uuid4()
        req = RunRequest(scenario_ids=["doc_exfil"])
        run = db.create_run(run_id, req)
        assert run.id == run_id
        assert run.status == RunStatus.QUEUED

        fetched = db.get_run(run_id)
        assert fetched is not None
        assert fetched.id == run_id
        assert fetched.status == RunStatus.QUEUED

    def test_get_nonexistent_run(self, db: Database):
        assert db.get_run(uuid4()) is None

    def test_list_runs_newest_first(self, db: Database):
        import time
        ids = []
        for _ in range(3):
            rid = uuid4()
            ids.append(rid)
            db.create_run(rid, RunRequest(scenario_ids=["doc_exfil"]))
            time.sleep(0.01)
        runs = db.list_runs(limit=10)
        assert len(runs) == 3
        # Newest first
        assert runs[0].id == ids[-1]

    def test_list_runs_with_limit(self, db: Database):
        for _ in range(5):
            db.create_run(uuid4(), RunRequest(scenario_ids=["doc_exfil"]))
        runs = db.list_runs(limit=2)
        assert len(runs) == 2

    def test_update_run_status(self, db: Database):
        run_id = uuid4()
        db.create_run(run_id, RunRequest(scenario_ids=["doc_exfil"]))
        db.update_run_status(run_id, RunStatus.RUNNING)
        run = db.get_run(run_id)
        assert run.status == RunStatus.RUNNING

    def test_update_run_status_completed_sets_time(self, db: Database):
        run_id = uuid4()
        db.create_run(run_id, RunRequest(scenario_ids=["doc_exfil"]))
        db.update_run_status(run_id, RunStatus.COMPLETED)
        run = db.get_run(run_id)
        assert run.status == RunStatus.COMPLETED
        assert run.completed_at is not None

    def test_update_run_with_error(self, db: Database):
        run_id = uuid4()
        db.create_run(run_id, RunRequest(scenario_ids=["doc_exfil"]))
        error = ErrorDetail(code="test_error", message="Something broke")
        db.update_run_status(run_id, RunStatus.FAILED, error=error)
        run = db.get_run(run_id)
        assert run.status == RunStatus.FAILED
        assert run.error is not None
        assert run.error.code == "test_error"

    def test_update_run_progress(self, db: Database):
        run_id = uuid4()
        db.create_run(run_id, RunRequest(scenario_ids=["doc_exfil"]))
        progress = RunProgress(scheduled=10, completed=3, failed=1, phase="attack")
        db.update_run_progress(run_id, progress)
        run = db.get_run(run_id)
        assert run.progress.scheduled == 10
        assert run.progress.completed == 3
        assert run.progress.phase == "attack"

    def test_update_run_metrics(self, db: Database):
        run_id = uuid4()
        db.create_run(run_id, RunRequest(scenario_ids=["doc_exfil"]))
        metrics = {"total_cases": 5, "attack_success_rate": 0.4}
        db.update_run_metrics(run_id, metrics)
        run = db.get_run(run_id)
        assert run.metrics["total_cases"] == 5

    def test_count_active_runs(self, db: Database):
        db.create_run(uuid4(), RunRequest(scenario_ids=["doc_exfil"]))
        db.create_run(uuid4(), RunRequest(scenario_ids=["doc_exfil"]))
        running, queued = db.count_active_runs()
        assert queued == 2
        assert running == 0

    def test_source_run_id(self, db: Database):
        source_id = uuid4()
        db.create_run(source_id, RunRequest(scenario_ids=["doc_exfil"]))
        retest_id = uuid4()
        db.create_run(retest_id, RunRequest(scenario_ids=["doc_exfil"]), source_run_id=source_id)
        run = db.get_run(retest_id)
        assert run.source_run_id == source_id


class TestEvents:
    def test_save_and_retrieve_events(self, db: Database):
        run_id = uuid4()
        db.create_run(run_id, RunRequest(scenario_ids=["doc_exfil"]))
        event = TraceEvent(
            id=uuid4(), run_id=run_id, seq=1, trial_id=None,
            type=EventType.RUN_STARTED, timestamp=datetime.now(timezone.utc),
            data={"test": True},
        )
        db.save_event(event)
        resp = db.get_events(run_id)
        assert len(resp.items) == 1
        assert resp.items[0].type == EventType.RUN_STARTED

    def test_event_pagination(self, db: Database):
        run_id = uuid4()
        db.create_run(run_id, RunRequest(scenario_ids=["doc_exfil"]))
        for i in range(5):
            event = TraceEvent(
                id=uuid4(), run_id=run_id, seq=i + 1, trial_id=None,
                type=EventType.RUN_STARTED, timestamp=datetime.now(timezone.utc),
                data={},
            )
            db.save_event(event)

        # Get first 2
        resp = db.get_events(run_id, after_seq=0, limit=2)
        assert len(resp.items) == 2
        assert resp.has_more is True
        assert resp.next_after_seq == 2

        # Get next 2
        resp2 = db.get_events(run_id, after_seq=2, limit=2)
        assert len(resp2.items) == 2
        assert resp2.next_after_seq == 4

        # Get last
        resp3 = db.get_events(run_id, after_seq=4, limit=2)
        assert len(resp3.items) == 1
        assert resp3.has_more is False

    def test_next_seq(self, db: Database):
        run_id = uuid4()
        db.create_run(run_id, RunRequest(scenario_ids=["doc_exfil"]))
        assert db.next_seq(run_id) == 1
        event = TraceEvent(
            id=uuid4(), run_id=run_id, seq=1, trial_id=None,
            type=EventType.RUN_STARTED, timestamp=datetime.now(timezone.utc),
        )
        db.save_event(event)
        assert db.next_seq(run_id) == 2

    def test_get_all_events(self, db: Database):
        run_id = uuid4()
        db.create_run(run_id, RunRequest(scenario_ids=["doc_exfil"]))
        for i in range(3):
            db.save_event(TraceEvent(
                id=uuid4(), run_id=run_id, seq=i + 1, trial_id=None,
                type=EventType.RUN_STARTED, timestamp=datetime.now(timezone.utc),
            ))
        events = db.get_all_events(run_id)
        assert len(events) == 3


class TestStartupInterruption:
    def test_stale_runs_marked_interrupted(self):
        """On init, queued/running runs should be marked interrupted."""
        db = Database(":memory:")
        db.initialize()
        run_id = uuid4()
        db.create_run(run_id, RunRequest(scenario_ids=["doc_exfil"]))
        db.update_run_status(run_id, RunStatus.RUNNING)

        # Re-initialize (simulating restart)
        db.initialize()
        run = db.get_run(run_id)
        assert run.status == RunStatus.INTERRUPTED
