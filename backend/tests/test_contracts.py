"""Schema freeze tests; no provider calls, storage, or target implementation."""

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from agentbreak import contracts as c


EXAMPLES = Path(__file__).resolve().parents[2] / "docs" / "examples"
EXAMPLE_MODELS = {
    "run-request.json": c.RunRequest,
    "scenario.json": c.ScenarioSpec,
    "scenarios-response.json": c.ScenariosResponse,
    "candidate.json": c.AttackCandidate,
    "case.json": c.CaseSpec,
    "result.json": c.CaseResult,
    "event.json": c.TraceEvent,
    "model-reply.json": c.ModelReply,
    "health-response.json": c.HealthResponse,
    "retest-request.json": c.RetestRequest,
    "error-response.json": c.ErrorResponse,
    "replay-bundle.json": c.ReplayBundle,
}


def example(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("name,model", EXAMPLE_MODELS.items())
def test_examples_validate_and_round_trip(name, model):
    value = model.model_validate_json((EXAMPLES / name).read_text(encoding="utf-8"))
    assert model.model_validate_json(value.model_dump_json()) == value
    json.dumps(value.model_dump(mode="json"), allow_nan=False)
    assert model.model_json_schema()["additionalProperties"] is False


def test_every_example_is_validated():
    assert {path.name for path in EXAMPLES.glob("*.json")} == set(EXAMPLE_MODELS)


@pytest.mark.parametrize("field,invalid", [
    ("max_candidates", 13), ("max_candidates", 0), ("max_candidates", True),
    ("max_model_turns", 7), ("max_tool_calls", 9), ("case_timeout_s", 61),
    ("run_timeout_s", 301), ("max_total_tokens", 60001),
    ("max_total_tokens", "500"), ("max_total_tokens", 100.5),
])
def test_budget_hard_limits(field, invalid):
    with pytest.raises(ValidationError):
        c.Budget(**{field: invalid})


def test_timeout_order():
    with pytest.raises(ValidationError):
        c.Budget(case_timeout_s=60, run_timeout_s=30)


@pytest.mark.parametrize("patch", [
    {"scenario_ids": []}, {"scenario_ids": ["other"]},
    {"scenario_ids": ["doc_exfil", "doc_exfil"]},
    {"defense": "prompt"}, {"execution_mode": "replay"},
    {"operation": "run"}, {"seed": -1}, {"seed": True}, {"seed": 2**32},
    {"grant": {}}, {"model_endpoint": "https://example.test"},
])
def test_request_rejects_invalid_or_privileged_fields(patch):
    data = example("run-request.json")
    data.update(patch)
    with pytest.raises(ValidationError):
        c.RunRequest.model_validate(data)


@pytest.mark.parametrize("model,args", [
    (c.SearchDocsArgs, {"query": "status"}),
    (c.GetCustomerArgs, {"customer_id": "cust_a"}),
    (c.SendEmailArgs, {"to": "ops@acme.test", "subject": "Status", "body": "shipped"}),
])
@pytest.mark.parametrize("extra", ["role", "approved", "tenant_id", "execute"])
def test_tools_reject_privilege_injection(model, args, extra):
    with pytest.raises(ValidationError):
        model.model_validate({**args, extra: True})


@pytest.mark.parametrize("recipient", ["ops@acme.test.evil", "OPS@ACME.TEST", "ops@acme.test ", "Name <ops@acme.test>", "ops@example.com"])
def test_recipients_are_exact_normalized_mock_addresses(recipient):
    with pytest.raises(ValidationError):
        c.SendEmailArgs(to=recipient, subject="status", body="status")


@pytest.mark.parametrize("patch", [
    {"payload_sha256": "0" * 64}, {"text": "x" * 4001}, {"text": ""},
    {"generation": 1}, {"parent_id": "00000000-0000-4000-8000-000000000003"},
    {"id": "bad-id"}, {"code": "print('no')"},
])
def test_candidate_hash_limits_and_lineage(patch):
    data = example("candidate.json")
    data.update(patch)
    with pytest.raises(ValidationError):
        c.AttackCandidate.model_validate(data)


def test_exact_payload_hash_does_not_normalize():
    assert c.payload_sha256("text") != c.payload_sha256("text\n")
    assert c.payload_sha256("é") != c.payload_sha256("e\u0301")
    assert c.canonical_sha256({"a": 1, "b": 2}) == c.canonical_sha256({"b": 2, "a": 1})


@pytest.mark.parametrize("field,value", [("scenario_id", "email_bola"), ("source_id", "another"), ("surface", "email")])
def test_case_matches_candidate_slot(field, value):
    data = example("case.json")
    data["candidate"][field] = value
    with pytest.raises(ValidationError, match="mismatch"):
        c.CaseSpec.model_validate(data)


def test_snapshot_integrity_and_independence():
    data = example("case.json")
    left, right = c.CaseSpec.model_validate(data), c.CaseSpec.model_validate(data)
    left.fixture_snapshot.documents[0].body = "mutated"
    assert right.fixture_snapshot.documents[0].body == "Order A100 is shipped."
    data["fixture_snapshot"]["documents"].append(copy.deepcopy(data["fixture_snapshot"]["documents"][0]))
    with pytest.raises(ValidationError, match="unique"):
        c.CaseSpec.model_validate(data)


def test_public_projection_is_explicit_and_does_not_mutate_internal():
    scenario = c.ScenarioSpec.model_validate(example("scenario.json"))
    public = scenario.to_public().model_dump(mode="json")
    assert public == example("scenarios-response.json")["items"][0]
    assert {"grant", "expected_benign", "fixture_id"}.isdisjoint(public)
    result = c.CaseResult.model_validate(example("result.json"))
    assert "state_diff" not in result.to_public().model_dump()
    assert "state_diff" in result.model_dump()
    with pytest.raises(ValidationError):
        c.ScenarioSpecPublic.model_validate(scenario.model_dump())


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), {1: "value"}, {"x": object()}, {"x": (1, 2)}, {"api_key": "placeholder"}, {"nested": {"Authorization": "placeholder"}}, {"environment": {}}])
def test_json_rejects_python_values_and_credential_keys(bad):
    with pytest.raises(ValidationError):
        c.EventDraft(type="run_started", data={"value": bad})


def test_event_ids_and_sequence_are_assigned_by_emitter_only():
    with pytest.raises(ValidationError):
        c.EventDraft(type="run_started", seq=1)
    data = example("event.json")
    del data["seq"]
    with pytest.raises(ValidationError):
        c.TraceEvent.model_validate(data)


@pytest.mark.parametrize("bad_time", ["2026-10-10T12:00:00", "2026-10-10", "12345", 1_700_000_000, datetime(2026, 10, 10)])
def test_naive_or_non_iso_timestamps_rejected(bad_time):
    data = example("event.json")
    data["timestamp"] = bad_time
    with pytest.raises(ValidationError):
        c.TraceEvent.model_validate(data)


def test_timestamps_normalize_to_utc():
    data = example("event.json")
    data["timestamp"] = "2026-10-10T14:00:00+02:00"
    event = c.TraceEvent.model_validate(data)
    assert event.timestamp == datetime(2026, 10, 10, 12, tzinfo=timezone.utc)
    assert event.model_dump(mode="json")["timestamp"].endswith("Z")


def test_event_pagination_and_cursor():
    event = c.TraceEvent.model_validate(example("event.json"))
    assert c.EventsResponse(items=[event], next_after_seq=1, has_more=False)
    assert c.EventsResponse(items=[], next_after_seq=17, has_more=False)
    for items, cursor, more in [([event, event], 1, False), ([event], 2, False), ([], 0, True)]:
        with pytest.raises(ValidationError):
            c.EventsResponse(items=items, next_after_seq=cursor, has_more=more)
    with pytest.raises(ValidationError):
        c.EventsQuery(limit=501)


def test_incomplete_result_is_inconclusive_unless_effect_verified():
    data = example("result.json")
    data["status"] = "timed_out"
    with pytest.raises(ValidationError):
        c.CaseResult.model_validate(data)
    data["oracle_outcome"] = "inconclusive"
    assert c.CaseResult.model_validate(data)
    data["oracle_outcome"] = "success"
    data["violations"] = [{"kind": "canary_leak", "impact": "high", "evidence_event_ids": data["evidence_event_ids"], "details": {"sink": "final_output"}}]
    assert c.CaseResult.model_validate(data).status == c.CaseStatus.TIMED_OUT
    data["benign_success"] = True
    with pytest.raises(ValidationError):
        c.CaseResult.model_validate(data)


def model_messages():
    reply = c.ModelReply.model_validate(example("model-reply.json"))
    return [
        c.ModelMessage(role="system", content=[c.TextBlock(text="Support assistant")]),
        c.ModelMessage(role="user", content=[c.TextBlock(text="Check A")]),
        c.ModelMessage(role="assistant", content=reply.content),
        c.ModelMessage(role="user", content=[c.ToolResultBlock(call_id="call_1", content={"order_status": "shipped"})]),
    ]


def test_normalized_model_reply_and_transport_sequence():
    reply = c.ModelReply.model_validate(example("model-reply.json"))
    assert reply.text == "I will check the permitted customer."
    assert reply.tool_calls[0].call_id == "call_1"
    assert reply.usage.total_tokens == 150
    c.validate_message_sequence(model_messages())
    with pytest.raises(ValueError, match="unresolved"):
        c.validate_message_sequence(model_messages()[:-1])
    messages = model_messages()
    messages[-1].content[0].call_id = "unknown"
    with pytest.raises(ValueError, match="call order"):
        c.validate_message_sequence(messages)
    with pytest.raises(ValidationError):
        c.ModelMessage(role="assistant", content=[c.ToolResultBlock(call_id="call_1", content={})])
    with pytest.raises(ValidationError):
        c.ModelReply.model_validate({**example("model-reply.json"), "thinking": "not accepted"})


def test_parallel_calls_preserve_order_and_all_denials_get_results():
    messages = model_messages()
    messages[2].content.append(c.ToolUseBlock(call=c.ToolCall(call_id="call_2", name="unknown", arguments={})))
    messages[3].content.append(c.ToolResultBlock(call_id="call_2", content={"code": "unknown_tool"}, is_error=True))
    c.validate_message_sequence(messages)
    messages[3].content.reverse()
    with pytest.raises(ValueError):
        c.validate_message_sequence(messages)


def replay_bundle():
    spec = c.CaseSpec.model_validate(example("case.json"))
    result = c.CaseResult.model_validate(example("result.json"))
    event = c.TraceEvent.model_validate(example("event.json"))
    run = c.RunSummary(id=spec.run_id, status="completed", request=c.RunRequest.model_validate(example("run-request.json")), created_at=event.timestamp, completed_at=event.timestamp)
    return c.ReplayBundle(
        run=run, exported_at=event.timestamp,
        cases=[c.ReplayCase(spec=spec, result=result, fingerprints=c.ReplayFingerprints(
            fixture_sha256=c.canonical_sha256(spec.fixture_snapshot),
            model_settings_sha256=c.canonical_sha256(spec.model_settings),
            policy_sha256=c.payload_sha256("baseline-v1"),
        ))], events=[event],
    )


def test_bundle_round_trip_and_fingerprints():
    bundle = replay_bundle()
    assert c.ReplayBundle.model_validate_json(bundle.model_dump_json()) == bundle
    assert bundle.cases[0].spec.fixture_snapshot.customers[0].internal_token.startswith("SYNTHETIC_")
    for field in ("fixture_sha256", "model_settings_sha256"):
        data = bundle.model_dump(mode="json")
        data["cases"][0]["fingerprints"][field] = "0" * 64
        with pytest.raises(ValidationError, match="fingerprint"):
            c.ReplayBundle.model_validate(data)


def test_bundle_rejects_missing_evidence_or_wrong_trial():
    data = replay_bundle().model_dump(mode="json")
    data["events"] = []
    with pytest.raises(ValidationError, match="missing evidence"):
        c.ReplayBundle.model_validate(data)
    data = replay_bundle().model_dump(mode="json")
    data["cases"][0]["result"]["trial_id"] = str(UUID(int=9))
    with pytest.raises(ValidationError, match="identity"):
        c.ReplayBundle.model_validate(data)


def test_benign_predicate_vocabulary_is_closed():
    data = example("scenario.json")
    data["expected_benign"] = [{"kind": "eval", "expression": "True"}]
    with pytest.raises(ValidationError):
        c.ScenarioSpec.model_validate(data)
    with pytest.raises(ValidationError):
        c.EffectCountPredicate(minimum=2, maximum=1)


def test_health_and_retest_strict_bools():
    with pytest.raises(ValidationError):
        c.HealthResponse(live_ready="false")
    with pytest.raises(ValidationError):
        c.RetestRequest(include_benign=1)
    with pytest.raises(ValidationError):
        c.RetestRequest(defense="baseline")
    with pytest.raises(ValidationError):
        c.HealthResponse(live_ready=False, schema_version=True)


def test_bundle_example_reuses_exact_input_and_result_examples():
    bundle = c.ReplayBundle.model_validate(example("replay-bundle.json"))
    assert bundle.cases[0].spec == c.CaseSpec.model_validate(example("case.json"))
    assert bundle.cases[0].result == c.CaseResult.model_validate(example("result.json"))
    assert bundle.events == [c.TraceEvent.model_validate(example("event.json"))]


def test_protocols_accept_async_structural_implementations():
    class StubModel:
        async def complete(self, messages, tools, *, model_id, temperature, max_tokens):
            return c.ModelReply.model_validate(example("model-reply.json"))

    class StubSink:
        async def __call__(self, event_draft):
            return c.TraceEvent.model_validate(example("event.json"))

    assert isinstance(StubModel(), c.ModelClient)
    assert isinstance(StubSink(), c.EventSink)


@pytest.mark.parametrize("field,value", [("execution_mode", "live"), ("defense", "gateway")])
def test_bundle_rejects_mislabeled_mode_or_defense(field, value):
    data = replay_bundle().model_dump(mode="json")
    data["run"]["request"][field] = value
    with pytest.raises(ValidationError, match="match run"):
        c.ReplayBundle.model_validate(data)


def test_result_cannot_cite_run_level_evidence_as_its_own_effect():
    data = replay_bundle().model_dump(mode="json")
    data["events"][0]["trial_id"] = None
    with pytest.raises(ValidationError, match="own trial"):
        c.ReplayBundle.model_validate(data)
