"""CLI tests live under Module A's allowed test_metrics* ownership."""
import json
from pathlib import Path
from uuid import uuid4
from urllib.error import URLError

import pytest

from agentbreak.cli import run_regression

EXAMPLES = Path(__file__).resolve().parents[2] / "docs" / "examples"


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def opener_for(responses, calls=None):
    def opener(request, timeout):
        assert 0 < timeout <= 10
        if calls is not None:
            calls.append(request)
        if not responses:
            raise URLError("stub transport unavailable")
        return Response(responses.pop(0))
    return opener


def suite():
    bundle = json.loads((EXAMPLES / "replay-bundle.json").read_text())
    run = bundle["run"]
    run["request"].update(operation="suite", defense="gateway", scenario_ids=["doc_exfil", "email_bola"])
    run["progress"] = {"scheduled": 16, "completed": 16, "failed": 0, "phase": "done"}
    cases = []
    for index in range(16):
        case = json.loads((EXAMPLES / "result.json").read_text())
        case.pop("state_diff")
        case.update(trial_id=str(uuid4()), defense="gateway", task_id=f"clean.task{index}", benign_success=True)
        if index < 8:
            case.update(candidate_id=None, payload_sha256=None)
        else:
            case["candidate_id"] = str(uuid4())
        cases.append(case)
    return {"run": run, "cases": cases}


def invoke(detail, **kwargs):
    return run_regression(mode="fixture", defense="gateway", opener=opener_for([
        {"run_id": detail["run"]["id"], "status": "queued"}, detail,
    ]), sleep=lambda _: None, **kwargs)


def test_cli_polls_terminal_and_prints_real_counts(capsys):
    detail = suite()
    calls = []
    running = json.loads(json.dumps(detail))
    running["run"]["status"] = "running"
    responses = [{"run_id": detail["run"]["id"]}, running, detail]
    assert run_regression(mode="fixture", defense="gateway", opener=opener_for(responses, calls), sleep=lambda _: None, token="demo-placeholder") == 0
    output = capsys.readouterr().out
    assert "scheduled_cases: 16" in output and "evidence export:" in output
    assert "demo-placeholder" not in output
    assert json.loads(calls[0].data)["operation"] == "suite"
    assert calls[0].get_header("Authorization") == "Bearer demo-placeholder"


@pytest.mark.parametrize("status", ["failed", "cancelled", "interrupted"])
def test_terminal_states_are_not_passes(status):
    detail = suite()
    detail["run"]["status"] = status
    assert invoke(detail) == 2


@pytest.mark.parametrize("change", ["empty", "missing", "unknown_benign", "inconclusive", "duplicate", "wrong_mode", "malformed"])
def test_incomplete_or_malformed_suite_cannot_pass(change):
    detail = suite()
    if change == "empty":
        detail["cases"] = []
    elif change == "missing":
        detail["cases"].pop()
    elif change == "unknown_benign":
        detail["cases"][0]["benign_success"] = None
    elif change == "inconclusive":
        detail["cases"][-1].update(status="timed_out", oracle_outcome="inconclusive", benign_success=None)
    elif change == "duplicate":
        detail["cases"][1] = detail["cases"][0]
    elif change == "wrong_mode":
        detail["run"]["request"]["execution_mode"] = "live"
    else:
        detail["cases"] = "not a list"
    assert invoke(detail) == 2


@pytest.mark.parametrize("security", [True, False])
def test_verified_failure_even_before_timeout(security):
    detail = suite()
    if security:
        detail["cases"][-1].update(status="timed_out", oracle_outcome="success", benign_success=False, violations=[{
            "kind": "canary_leak", "impact": "high", "evidence_event_ids": [str(uuid4())], "details": {},
        }])
    else:
        detail["cases"][0]["benign_success"] = False
    assert invoke(detail) == 1


def test_live_readiness_checked_on_server_without_local_keys(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    calls = []
    assert run_regression(mode="live", defense="gateway", opener=opener_for([
        {"status": "ok", "schema_version": 1, "live_ready": False},
    ], calls)) == 2
    assert len(calls) == 1 and calls[0].full_url.endswith("/api/health")
    assert "no fixture fallback" in capsys.readouterr().err


def test_transport_and_deadline_are_not_security_success(capsys):
    assert run_regression(mode="fixture", defense="gateway", opener=opener_for([])) == 2
    detail = suite()
    ticks = iter([0, 0, 2])
    assert invoke(detail, poll_deadline=1, clock=lambda: next(ticks)) == 2
    assert "deadline" in capsys.readouterr().err
