"""Unit tests for agentbreak.cli module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from agentbreak.cli import main, run_regress


def test_cli_help():
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0


def test_cli_no_args():
    exit_code = main([])
    assert exit_code == 2


def test_cli_regress_connection_failure():
    with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")):
        exit_code = main(["regress", "--mode", "fixture", "--defense", "gateway"])
        assert exit_code == 2


def test_cli_regress_live_mode_rejected_when_not_ready():
    # Health returns live_ready=False
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.read.return_value = json.dumps({"status": "ok", "live_ready": False}).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        exit_code = main(["regress", "--mode", "live", "--defense", "gateway"])
        assert exit_code == 2


def test_cli_regress_gateway_success(monkeypatch):
    run_id = str(uuid4())
    trial_benign = str(uuid4())
    trial_attack = str(uuid4())

    responses = {
        "/api/health": (200, {"status": "ok", "live_ready": True}),
        "/api/runs": (202, {"run_id": run_id, "status": "queued"}),
        f"/api/runs/{run_id}": (200, {
            "run": {
                "id": run_id,
                "status": "completed",
                "progress": {"scheduled": 2, "completed": 2, "phase": "done"},
            },
            "cases": [
                {
                    "trial_id": trial_benign,
                    "candidate_id": None,
                    "status": "completed",
                    "oracle_outcome": "failure",
                    "benign_success": True,
                    "violations": [],
                },
                {
                    "trial_id": trial_attack,
                    "candidate_id": str(uuid4()),
                    "status": "completed",
                    "oracle_outcome": "failure",  # attack failed = defense held!
                    "benign_success": None,
                    "violations": [],
                },
            ],
        }),
    }

    def fake_make_request(method, url, headers, body=None, timeout=10.0):
        for path, (code, data) in responses.items():
            if url.endswith(path):
                return code, data
        return 404, {"error": {"code": "not_found", "message": "Not found"}}

    with patch("agentbreak.cli._make_request", side_effect=fake_make_request):
        exit_code = main(["regress", "--mode", "fixture", "--defense", "gateway", "--poll-interval", "0.01"])
        assert exit_code == 0


def test_cli_regress_security_violation_exits_1(monkeypatch):
    run_id = str(uuid4())
    trial_attack = str(uuid4())

    responses = {
        "/api/health": (200, {"status": "ok", "live_ready": True}),
        "/api/runs": (202, {"run_id": run_id, "status": "queued"}),
        f"/api/runs/{run_id}": (200, {
            "run": {
                "id": run_id,
                "status": "completed",
                "progress": {"scheduled": 1, "completed": 1, "phase": "done"},
            },
            "cases": [
                {
                    "trial_id": trial_attack,
                    "candidate_id": str(uuid4()),
                    "status": "completed",
                    "oracle_outcome": "success",  # attacker succeeded = security violation!
                    "benign_success": None,
                    "violations": [{"kind": "unauthorized_read", "impact": "high"}],
                },
            ],
        }),
    }

    def fake_make_request(method, url, headers, body=None, timeout=10.0):
        for path, (code, data) in responses.items():
            if url.endswith(path):
                return code, data
        return 404, {"error": {"code": "not_found", "message": "Not found"}}

    with patch("agentbreak.cli._make_request", side_effect=fake_make_request):
        exit_code = main(["regress", "--mode", "fixture", "--defense", "gateway", "--poll-interval", "0.01"])
        assert exit_code == 1


def test_cli_regress_benign_failure_exits_1(monkeypatch):
    run_id = str(uuid4())
    trial_benign = str(uuid4())

    responses = {
        "/api/health": (200, {"status": "ok", "live_ready": True}),
        "/api/runs": (202, {"run_id": run_id, "status": "queued"}),
        f"/api/runs/{run_id}": (200, {
            "run": {
                "id": run_id,
                "status": "completed",
                "progress": {"scheduled": 1, "completed": 1, "phase": "done"},
            },
            "cases": [
                {
                    "trial_id": trial_benign,
                    "candidate_id": None,
                    "status": "completed",
                    "oracle_outcome": "failure",
                    "benign_success": False,  # Clean task failed!
                    "violations": [],
                },
            ],
        }),
    }

    def fake_make_request(method, url, headers, body=None, timeout=10.0):
        for path, (code, data) in responses.items():
            if url.endswith(path):
                return code, data
        return 404, {"error": {"code": "not_found", "message": "Not found"}}

    with patch("agentbreak.cli._make_request", side_effect=fake_make_request):
        exit_code = main(["regress", "--mode", "fixture", "--defense", "gateway", "--poll-interval", "0.01"])
        assert exit_code == 1


def test_cli_regress_inconclusive_exits_2(monkeypatch):
    run_id = str(uuid4())
    trial_inconclusive = str(uuid4())

    responses = {
        "/api/health": (200, {"status": "ok", "live_ready": True}),
        "/api/runs": (202, {"run_id": run_id, "status": "queued"}),
        f"/api/runs/{run_id}": (200, {
            "run": {
                "id": run_id,
                "status": "completed",
                "progress": {"scheduled": 1, "completed": 1, "phase": "done"},
            },
            "cases": [
                {
                    "trial_id": trial_inconclusive,
                    "candidate_id": str(uuid4()),
                    "status": "timed_out",
                    "oracle_outcome": "inconclusive",
                    "benign_success": None,
                    "violations": [],
                },
            ],
        }),
    }

    def fake_make_request(method, url, headers, body=None, timeout=10.0):
        for path, (code, data) in responses.items():
            if url.endswith(path):
                return code, data
        return 404, {"error": {"code": "not_found", "message": "Not found"}}

    with patch("agentbreak.cli._make_request", side_effect=fake_make_request):
        exit_code = main(["regress", "--mode", "fixture", "--defense", "gateway", "--poll-interval", "0.01"])
        assert exit_code == 2
