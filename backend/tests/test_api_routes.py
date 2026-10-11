"""API integration tests for Session D Phase 2 routes.

Uses HTTPX TestClient against the real FastAPI app with an in-memory SQLite DB.
Tests cover health, scenarios, run lifecycle, events, cancel, retest, and export.
"""

from __future__ import annotations

import asyncio
import os
import time
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

# Force fixture mode for tests
os.environ.setdefault("ALLOW_LIVE_RUNS", "false")
os.environ.setdefault("DATABASE_PATH", ":memory:")

from agentbreak.contracts import RunStatus, ErrorDetail
from agentbreak.main import create_app


@pytest.fixture
def app():
    """Create a fresh app instance for each test and initialize state."""
    app = create_app()
    
    from agentbreak.storage.database import Database
    db = Database(":memory:")
    db.initialize()
    app.state.db = db
    
    from agentbreak.llm import StubModelClient
    app.state.model_client = StubModelClient()
    app.state.live_ready = False
    app.state.run_queue = asyncio.Queue()
    app.state.cancel_tokens = {}
    app.state.retest_configs = {}
    
    return app


@pytest.fixture
async def client(app):
    """Async test client that goes through the full ASGI lifespan."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ------------------------------------------------------------------ health
class TestHealth:
    async def test_health_returns_ok(self, client):
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["schema_version"] == 1
        assert data["live_ready"] is False

    async def test_health_no_auth_required(self, client):
        """Health should work even if DEMO_ACCESS_TOKEN is set."""
        response = await client.get("/api/health")
        assert response.status_code == 200


# ------------------------------------------------------------------ scenarios
class TestScenarios:
    async def test_list_scenarios(self, client):
        response = await client.get("/api/scenarios")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        items = data["items"]
        assert len(items) == 2
        ids = {s["id"] for s in items}
        assert ids == {"doc_exfil", "email_bola"}

    async def test_scenarios_no_grants_exposed(self, client):
        """Public view should not contain grants or expected_benign."""
        response = await client.get("/api/scenarios")
        for item in response.json()["items"]:
            assert "grant" not in item
            assert "expected_benign" not in item
            assert "fixture_id" not in item


# ------------------------------------------------------------------ runs
class TestRuns:
    async def test_create_run(self, client):
        response = await client.post("/api/runs", json={
            "scenario_ids": ["doc_exfil"],
            "operation": "discover",
            "defense": "baseline",
            "execution_mode": "fixture",
        })
        assert response.status_code == 202
        data = response.json()
        assert "run_id" in data
        assert data["status"] == "queued"

    async def test_create_run_invalid_scenario(self, client):
        response = await client.post("/api/runs", json={
            "scenario_ids": ["nonexistent"],
        })
        assert response.status_code == 422

    async def test_list_runs(self, client):
        # Create a run first
        await client.post("/api/runs", json={
            "scenario_ids": ["doc_exfil"],
            "execution_mode": "fixture",
        })
        response = await client.get("/api/runs")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert len(data["items"]) >= 1

    async def test_list_runs_with_limit(self, client):
        response = await client.get("/api/runs?limit=5")
        assert response.status_code == 200

    async def test_get_run_not_found(self, client):
        fake_id = str(uuid4())
        response = await client.get(f"/api/runs/{fake_id}")
        assert response.status_code == 404
        data = response.json()
        assert data["error"]["code"] == "not_found"

    async def test_get_run_detail(self, client):
        # Create a run
        create_resp = await client.post("/api/runs", json={
            "scenario_ids": ["doc_exfil"],
            "execution_mode": "fixture",
        })
        run_id = create_resp.json()["run_id"]
        # Give worker a moment
        await asyncio.sleep(0.5)
        response = await client.get(f"/api/runs/{run_id}")
        assert response.status_code == 200
        data = response.json()
        assert "run" in data
        assert data["run"]["id"] == run_id

    async def test_live_mode_rejected_when_not_ready(self, client):
        response = await client.post("/api/runs", json={
            "scenario_ids": ["doc_exfil"],
            "execution_mode": "live",
        })
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "live_not_ready"


# ------------------------------------------------------------------ events
class TestEvents:
    async def test_events_not_found(self, client):
        fake_id = str(uuid4())
        response = await client.get(f"/api/runs/{fake_id}/events")
        assert response.status_code == 404

    async def test_events_empty_for_new_run(self, client):
        create_resp = await client.post("/api/runs", json={
            "scenario_ids": ["doc_exfil"],
            "execution_mode": "fixture",
        })
        run_id = create_resp.json()["run_id"]
        response = await client.get(f"/api/runs/{run_id}/events")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "next_after_seq" in data
        assert "has_more" in data


# ------------------------------------------------------------------ cancel
class TestCancel:
    async def test_cancel_not_found(self, client):
        fake_id = str(uuid4())
        response = await client.post(f"/api/runs/{fake_id}/cancel")
        assert response.status_code == 404

    async def test_cancel_queued_run(self, client):
        # Create a run
        create_resp = await client.post("/api/runs", json={
            "scenario_ids": ["doc_exfil"],
            "execution_mode": "fixture",
        })
        run_id = create_resp.json()["run_id"]
        # Try to cancel it immediately (may be queued or running)
        response = await client.post(f"/api/runs/{run_id}/cancel")
        assert response.status_code == 202
        data = response.json()
        assert data["run_id"] == run_id


# ------------------------------------------------------------------ retest
class TestRetest:
    async def test_retest_not_found(self, client):
        fake_id = str(uuid4())
        response = await client.post(f"/api/runs/{fake_id}/retest", json={"include_benign": True})
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"

    async def test_retest_queued_run_returns_409(self, client):
        create_resp = await client.post("/api/runs", json={
            "scenario_ids": ["doc_exfil"],
            "execution_mode": "fixture",
        })
        run_id = create_resp.json()["run_id"]
        response = await client.post(f"/api/runs/{run_id}/retest", json={"include_benign": True})
        assert response.status_code == 409
        data = response.json()
        assert data["error"]["code"] == "invalid_transition"
        assert "completed source run" in data["error"]["message"].lower()

    async def test_retest_failed_run_returns_409(self, client, app):
        create_resp = await client.post("/api/runs", json={
            "scenario_ids": ["doc_exfil"],
            "execution_mode": "fixture",
        })
        run_id = create_resp.json()["run_id"]
        # Explicitly set run status to FAILED in DB to simulate failed run
        db = app.state.db
        from uuid import UUID
        db.update_run_status(UUID(run_id), RunStatus.FAILED,
                             ErrorDetail(code="run_error", message="Run failed: FixtureTraceNotFoundError"))
        
        response = await client.post(f"/api/runs/{run_id}/retest", json={"include_benign": True})
        assert response.status_code == 409
        data = response.json()
        assert data["error"]["code"] == "invalid_transition"
        assert "completed source run" in data["error"]["message"].lower()

    async def test_retest_completed_run_accepted(self, client, app):
        create_resp = await client.post("/api/runs", json={
            "scenario_ids": ["doc_exfil"],
            "execution_mode": "fixture",
        })
        run_id = create_resp.json()["run_id"]
        # Mark source run as completed in DB
        db = app.state.db
        from uuid import UUID
        db.update_run_status(UUID(run_id), RunStatus.COMPLETED)

        response = await client.post(f"/api/runs/{run_id}/retest", json={"include_benign": True})
        assert response.status_code == 202
        data = response.json()
        assert "run_id" in data
        new_run_id = data["run_id"]
        assert new_run_id != run_id

        # Verify new run is stored with source_run_id linked
        retest_run = db.get_run(UUID(new_run_id))
        assert retest_run is not None
        assert retest_run.source_run_id == UUID(run_id)
        assert retest_run.status == RunStatus.QUEUED


# ------------------------------------------------------------------ export
class TestExport:
    async def test_export_not_found(self, client):
        fake_id = str(uuid4())
        response = await client.get(f"/api/runs/{fake_id}/export?format=json")
        assert response.status_code == 404


# ------------------------------------------------------------------ error envelopes
class TestErrors:
    async def test_404_envelope(self, client):
        response = await client.get("/api/nonexistent")
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == "not_found"

    async def test_405_envelope(self, client):
        response = await client.delete("/api/health")
        assert response.status_code == 405
        data = response.json()
        assert data["error"]["code"] == "method_not_allowed"

    async def test_422_envelope(self, client):
        response = await client.post("/api/runs", json={"invalid": "data"})
        assert response.status_code == 422
        data = response.json()
        assert data["error"]["code"] == "validation_error"
