"""End-to-end integration tests for AgentBreak suite, retest, and regression CLI."""

import time
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from agentbreak.cli import run_regression
from agentbreak.contracts import ReplayBundle, RunRequest
from agentbreak.main import create_app
from agentbreak.orchestrator import Orchestrator
from agentbreak.storage.db import Database, reset_db_for_test
from agentbreak.api.routes import set_orchestrator


@pytest.fixture
def e2e_env(tmp_path):
    db_file = str(tmp_path / "e2e.db")
    db = reset_db_for_test(db_file)
    orchestrator = Orchestrator(db)
    set_orchestrator(orchestrator)
    app = create_app()
    return app, db, orchestrator


def test_full_e2e_suite_baseline_to_gateway_retest(e2e_env):
    app, db, _ = e2e_env

    with TestClient(app) as client:
        # Step 1: POST fixture suite under baseline
        post_baseline = client.post(
            "/api/runs",
            json={
                "scenario_ids": ["doc_exfil", "email_bola"],
                "operation": "suite",
                "defense": "baseline",
                "execution_mode": "fixture",
                "seed": 0,
            },
        )
        assert post_baseline.status_code == 202
        baseline_id = post_baseline.json()["run_id"]

        # Poll baseline to completion
        for _ in range(50):
            b_detail = client.get(f"/api/runs/{baseline_id}").json()
            if b_detail["run"]["status"] in ("completed", "failed"):
                break
            time.sleep(0.1)

        assert b_detail["run"]["status"] == "completed"
        b_cases = b_detail["cases"]
        assert len(b_cases) == 16
        b_clean = [c for c in b_cases if c["candidate_id"] is None]
        b_attacks = [c for c in b_cases if c["candidate_id"] is not None]
        assert len(b_clean) == 8
        assert len(b_attacks) == 8

        # Clean tasks succeed
        for c in b_clean:
            assert c["benign_success"] is True

        # Under baseline, attacks succeed (verified violations exist)
        assert any(len(c["violations"]) > 0 for c in b_attacks)

        # Step 2: Validate event integrity
        ev_resp = client.get(f"/api/runs/{baseline_id}/events?limit=500")
        assert ev_resp.status_code == 200
        events = ev_resp.json()["items"]
        event_ids = [e["id"] for e in events]
        # No event ID duplication
        assert len(event_ids) == len(set(event_ids))
        # Monotonic sequence
        seqs = [e["seq"] for e in events]
        assert seqs == sorted(seqs)
        # Parent ordering: every parent event precedes child
        id_to_seq = {e["id"]: e["seq"] for e in events}
        for e in events:
            for p in e["parent_event_ids"]:
                assert p in id_to_seq
                assert id_to_seq[p] < e["seq"]

        # No secret leakage in event data
        forbidden_keys = {"api_key", "authorization", "password", "secret"}
        for e in events:
            for k in e["data"].keys():
                assert k.lower() not in forbidden_keys

        # Step 3: Retest under gateway
        retest_post = client.post(
            f"/api/runs/{baseline_id}/retest",
            json={"defense": "gateway", "include_benign": True},
        )
        assert retest_post.status_code == 202
        retest_id = retest_post.json()["run_id"]

        for _ in range(50):
            g_detail = client.get(f"/api/runs/{retest_id}").json()
            if g_detail["run"]["status"] in ("completed", "failed"):
                break
            time.sleep(0.1)

        assert g_detail["run"]["status"] == "completed"
        assert g_detail["run"]["source_run_id"] == baseline_id
        assert g_detail["run"]["request"]["defense"] == "gateway"

        g_cases = g_detail["cases"]
        assert len(g_cases) == 16
        g_clean = [c for c in g_cases if c["candidate_id"] is None]
        g_attacks = [c for c in g_cases if c["candidate_id"] is not None]
        assert len(g_clean) == 8
        assert len(g_attacks) == 8

        # Clean tasks still succeed under gateway
        for c in g_clean:
            assert c["benign_success"] is True

        # Under gateway, NO verified violations (defense held)
        for c in g_attacks:
            assert len(c["violations"]) == 0
            assert c["oracle_outcome"] == "failure"  # attacker lost

        # Blocked tool proposals recorded in attempted_violations across attacks
        assert any(len(c["attempted_violations"]) > 0 for c in g_attacks)

        # Exact candidate replay verification
        b_candidates = {c["candidate_id"]: c["payload_sha256"] for c in b_attacks}
        g_candidates = {c["candidate_id"]: c["payload_sha256"] for c in g_attacks}
        assert b_candidates == g_candidates

        # Step 4: Export evidence
        export_json = client.get(f"/api/runs/{retest_id}/export?format=json")
        assert export_json.status_code == 200
        bundle = ReplayBundle.model_validate(export_json.json())
        assert bundle.run.id == UUID(retest_id)
        assert len(bundle.cases) == 16
        assert len(bundle.events) > 0

        export_md = client.get(f"/api/runs/{retest_id}/export?format=markdown")
        assert export_md.status_code == 200
        assert "AgentBreak" in export_md.text


def test_cli_regression_via_custom_opener(e2e_env):
    """Test the CLI regress logic against the app using a TestClient adapter."""
    app, _, _ = e2e_env

    class TestClientOpener:
        def __init__(self, client):
            self.client = client

        def __call__(self, request, timeout=10.0):
            url = request.full_url
            path = url.replace("http://localhost:8000", "")
            method = request.get_method()
            headers = dict(request.headers)
            body = request.data.decode("utf-8") if request.data else None
            json_body = json.loads(body) if body else None

            resp = self.client.request(
                method, path, headers=headers, json=json_body
            )

            class MockResponse:
                def __init__(self, r):
                    self.r = r

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def read(self):
                    return self.r.content

            return MockResponse(resp)

    import json
    with TestClient(app) as client:
        exit_code = run_regression(
            mode="fixture",
            defense="gateway",
            server_url="http://localhost:8000",
            opener=TestClientOpener(client),
            poll_interval=0.05,
        )
        assert exit_code == 0
