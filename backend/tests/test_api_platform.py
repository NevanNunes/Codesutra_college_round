"""Integration tests for AgentBreak platform API routes, orchestrator, and storage."""

import asyncio
import json
import time
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from agentbreak.api.routes import get_orchestrator, set_orchestrator
from agentbreak.contracts import (
    DefensePreset,
    ExecutionMode,
    ReplayBundle,
    RunDetailResponse,
    RunRequest,
    RunStatus,
)
from agentbreak.main import create_app
from agentbreak.orchestrator import Orchestrator
from agentbreak.storage.db import Database, get_db, reset_db_for_test


@pytest.fixture
def test_app(tmp_path):
    db_file = str(tmp_path / "test.db")
    db = reset_db_for_test(db_file)
    orchestrator = Orchestrator(db)
    set_orchestrator(orchestrator)
    app = create_app()
    return app, db, orchestrator


def test_get_scenarios(test_app):
    app, _, _ = test_app
    with TestClient(app) as client:
        resp = client.get("/api/scenarios")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert len(data["items"]) == 2
    ids = {item["id"] for item in data["items"]}
    assert ids == {"doc_exfil", "email_bola"}


def test_run_lifecycle_suite_fixture_gateway(test_app):
    app, db, orchestrator = test_app
    with TestClient(app) as client:
        post_resp = client.post(
            "/api/runs",
            json={
                "scenario_ids": ["doc_exfil", "email_bola"],
                "operation": "suite",
                "defense": "gateway",
                "execution_mode": "fixture",
                "seed": 0,
            },
        )
        assert post_resp.status_code == 202
        run_id = post_resp.json()["run_id"]
        assert post_resp.json()["status"] == "queued"

        # Poll until complete
        for _ in range(50):
            detail_resp = client.get(f"/api/runs/{run_id}")
            assert detail_resp.status_code == 200
            detail = detail_resp.json()
            if detail["run"]["status"] in ("completed", "failed"):
                break
            time.sleep(0.1)

        assert detail["run"]["status"] == "completed"
        cases = detail["cases"]
        assert len(cases) == 16  # 8 clean + 8 held-out attacks
        clean_cases = [c for c in cases if c["candidate_id"] is None]
        attack_cases = [c for c in cases if c["candidate_id"] is not None]
        assert len(clean_cases) == 8
        assert len(attack_cases) == 8

        # All clean cases succeeded
        for c in clean_cases:
            assert c["benign_success"] is True

        # Under gateway, no attacks have verified violations
        for c in attack_cases:
            assert len(c["violations"]) == 0
            assert c["oracle_outcome"] == "failure"  # defense held

        # Events endpoint
        events_resp = client.get(f"/api/runs/{run_id}/events?limit=50")
        assert events_resp.status_code == 200
        ev_data = events_resp.json()
        assert len(ev_data["items"]) > 0

        # Export JSON
        export_json = client.get(f"/api/runs/{run_id}/export?format=json")
        assert export_json.status_code == 200
        assert export_json.headers["content-type"] == "application/json"
        bundle_dict = export_json.json()
        bundle = ReplayBundle.model_validate(bundle_dict)
        assert bundle.run.id == UUID(run_id)

        # Export Markdown
        export_md = client.get(f"/api/runs/{run_id}/export?format=markdown")
        assert export_md.status_code == 200
        assert "text/markdown" in export_md.headers["content-type"]
        assert "AgentBreak" in export_md.text


def test_retest_flow(test_app):
    app, db, orchestrator = test_app
    with TestClient(app) as client:
        # First run on baseline
        post_resp = client.post(
            "/api/runs",
            json={
                "scenario_ids": ["doc_exfil", "email_bola"],
                "operation": "suite",
                "defense": "baseline",
                "execution_mode": "fixture",
                "seed": 0,
            },
        )
        assert post_resp.status_code == 202
        orig_run_id = post_resp.json()["run_id"]

        for _ in range(50):
            detail = client.get(f"/api/runs/{orig_run_id}").json()
            if detail["run"]["status"] == "completed":
                break
            time.sleep(0.1)

        assert detail["run"]["status"] == "completed"

        # Submit Retest under gateway
        retest_resp = client.post(
            f"/api/runs/{orig_run_id}/retest",
            json={"defense": "gateway", "include_benign": True},
        )
        assert retest_resp.status_code == 202
        new_run_id = retest_resp.json()["run_id"]

        for _ in range(50):
            detail_retest = client.get(f"/api/runs/{new_run_id}").json()
            if detail_retest["run"]["status"] == "completed":
                break
            time.sleep(0.1)

        assert detail_retest["run"]["status"] == "completed"
        assert detail_retest["run"]["source_run_id"] == orig_run_id
        assert detail_retest["run"]["request"]["defense"] == "gateway"


def test_auth_enforcement(monkeypatch, test_app):
    monkeypatch.setenv("DEMO_ACCESS_TOKEN", "secret-test-token")
    app, _, _ = test_app
    with TestClient(app) as client:
        # Health is unauthenticated
        health_resp = client.get("/api/health")
        assert health_resp.status_code == 200

        # Scenarios without auth -> 401
        scenarios_unauth = client.get("/api/scenarios")
        assert scenarios_unauth.status_code == 401

        # Scenarios with wrong auth -> 401
        scenarios_wrong = client.get(
            "/api/scenarios", headers={"Authorization": "Bearer wrong-token"}
        )
        assert scenarios_wrong.status_code == 401

        # Scenarios with correct auth -> 200
        scenarios_auth = client.get(
            "/api/scenarios", headers={"Authorization": "Bearer secret-test-token"}
        )
        assert scenarios_auth.status_code == 200


def test_cancel_flow(test_app):
    app, db, orchestrator = test_app
    with TestClient(app) as client:
        # Create a run directly in DB in queued state
        run_req = RunRequest(
            scenario_ids=["doc_exfil"],
            operation="suite",
            defense="gateway",
            execution_mode="fixture",
            seed=0,
        )
        summary = db.create_run(run_req)
        # Cancel the queued run
        cancel_resp = client.post(f"/api/runs/{summary.id}/cancel")
        assert cancel_resp.status_code == 202
        assert cancel_resp.json()["status"] == "cancelled"

        # Cancelling already cancelled run -> 409
        cancel_again = client.post(f"/api/runs/{summary.id}/cancel")
        assert cancel_again.status_code == 409
        assert cancel_again.json()["error"]["code"] == "invalid_transition"


def test_restart_interruption(tmp_path):
    db_file = str(tmp_path / "test_restart.db")
    db = Database(db_file)
    run_req = RunRequest(
        scenario_ids=["doc_exfil"],
        operation="suite",
        defense="gateway",
        execution_mode="fixture",
        seed=0,
    )
    summary = db.create_run(run_req)
    db.update_run(summary.id, status=RunStatus.RUNNING)

    # Simulate restart
    db2 = Database(db_file)
    count = db2.mark_unfinished_interrupted()
    assert count == 1
    reloaded = db2.get_run_summary(summary.id)
    assert reloaded.status == RunStatus.INTERRUPTED
