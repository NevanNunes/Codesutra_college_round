import asyncio
import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentbreak.attacks.engine import AttackEngine
from agentbreak.contracts import (
    AttackCandidate,
    Budget,
    CaseResult,
    ModelReply,
    ModelSettings,
    ScenarioSpec,
    TextBlock,
    Usage,
    payload_sha256,
)


EXAMPLES = Path(__file__).resolve().parents[2] / "docs" / "examples"


def _json(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def _scenario():
    return ScenarioSpec.model_validate(_json("scenario.json"))


def _reply(text: str) -> ModelReply:
    return ModelReply(
        content=[TextBlock(text=text)], usage=Usage(input_tokens=2, output_tokens=3),
        stop_reason="end_turn", model_id="attacker-fixture",
    )


def _result(candidate: AttackCandidate, *, mode="fixture", defense="baseline", outcome="failure") -> CaseResult:
    data = _json("result.json")
    data.update({
        "candidate_id": str(candidate.id),
        "payload_sha256": candidate.payload_sha256,
        "execution_mode": mode,
        "defense": defense,
        "oracle_outcome": outcome,
        "violations": [],
        "attempted_violations": [],
    })
    return CaseResult.model_validate(data)


def _settings():
    return ModelSettings(provider="fixture", target_model_id="target", attacker_model_id="attacker", max_tokens=64)


@pytest.mark.asyncio
async def test_engine_adapts_with_observable_feedback_and_parent_id(scripted_model, memory_event_sink):
    model = scripted_model([
        _reply(json.dumps({"text": "first synthetic instruction", "strategy": "root"})),
        _reply(json.dumps({"text": "revised synthetic instruction", "strategy": "mutation"})),
    ])
    scenario = _scenario()
    run_id = UUID("00000000-0000-4000-8000-000000000001")
    sink = memory_event_sink(run_id)
    seen = []

    async def execute(candidate):
        seen.append(candidate)
        return _result(candidate)

    results = await AttackEngine(model, model_settings=_settings()).discover(
        scenario, Budget(max_candidates=2), 7, execute, sink
    )
    assert len(results) == 2
    assert seen[1].parent_id == seen[0].id
    second_prompt = model.calls[1]["messages"][0].content[0].text
    assert str(seen[0].id) in second_prompt
    assert "parent_id" in second_prompt
    assert "source_consumed" in second_prompt
    assert seen[0].text in second_prompt
    assert "allowed_customer_ids" not in second_prompt
    assert "expected_benign" not in second_prompt
    generated = [event for event in sink.events if event.type.value == "candidate_generated"]
    assert generated[1].parent_event_ids == [generated[0].id]


@pytest.mark.asyncio
async def test_invalid_json_gets_one_repair_then_is_not_executed(scripted_model, memory_event_sink):
    model = scripted_model([_reply("not json"), _reply("still not json")])
    called = False

    async def execute(_candidate):
        nonlocal called
        called = True
        raise AssertionError("invalid candidate must not execute")

    results = await AttackEngine(model, model_settings=_settings()).discover(
        _scenario(), Budget(max_candidates=1), 1, execute, memory_event_sink(uuid4())
    )
    assert results == []
    assert not called
    assert len(model.calls) == 2


@pytest.mark.asyncio
async def test_duplicate_exhaustion_is_bounded(scripted_model, memory_event_sink):
    proposal = json.dumps({"text": "same", "strategy": "repeat"})
    model = scripted_model([_reply(proposal) for _ in range(4)])
    executions = []

    async def execute(candidate):
        executions.append(candidate)
        return _result(candidate)

    results = await AttackEngine(model, model_settings=_settings()).discover(
        _scenario(), Budget(max_candidates=2), 1, execute, memory_event_sink(uuid4())
    )
    assert len(results) == 1
    assert len(executions) == 1
    assert len(model.calls) == 4  # max_candidates * 2 proposal attempts


@pytest.mark.asyncio
async def test_budget_token_limit_and_cancellation(scripted_model, memory_event_sink):
    model = scripted_model([_reply(json.dumps({"text": "one", "strategy": "x"}))])
    executed = []

    async def execute(candidate):
        executed.append(candidate)
        return _result(candidate)

    results = await AttackEngine(model, model_settings=_settings()).discover(
        _scenario(), Budget(max_candidates=2, max_total_tokens=1), 1, execute, memory_event_sink(uuid4())
    )
    assert results == []
    assert not executed
    assert model.calls == []  # reserve input as well as output before calling

    async def never_finishes(_candidate):
        await asyncio.Event().wait()

    model = scripted_model([_reply(json.dumps({"text": "cancel me", "strategy": "x"}))])
    task = asyncio.create_task(AttackEngine(model, model_settings=_settings()).discover(
        _scenario(), Budget(max_candidates=1), 1, never_finishes, memory_event_sink(uuid4())
    ))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_trusted_slot_and_candidate_fields_are_rejected(scripted_model, memory_event_sink):
    model = scripted_model([
        _reply(json.dumps({"text": "x", "source_id": "other", "strategy": "bad"})),
        _reply(json.dumps({"text": "x", "strategy": "ok"})),
    ])
    async def execute(candidate):
        return _result(candidate)

    results = await AttackEngine(model, model_settings=_settings()).discover(
        _scenario(), Budget(max_candidates=1), 1,
        execute, memory_event_sink(uuid4())
    )
    assert len(results) == 1

    scenario = _scenario()
    with pytest.raises(ValidationError):
        AttackCandidate(
            id=uuid4(), scenario_id=scenario.id, source_id=scenario.source_id,
            surface=scenario.surface, text="x", strategy="x", payload_sha256=payload_sha256("x"),
            code="not permitted",
        )


@pytest.mark.asyncio
async def test_provider_error_is_not_converted_to_attack_failure(memory_event_sink):
    class BrokenModel:
        async def complete(self, *args, **kwargs):
            raise RuntimeError("provider unavailable")

    with pytest.raises(RuntimeError, match="provider unavailable"):
        await AttackEngine(BrokenModel(), model_settings=_settings()).discover(
            _scenario(), Budget(max_candidates=1), 1, execute_case=lambda candidate: _result(candidate), emit=memory_event_sink(uuid4())
        )


@pytest.mark.parametrize("patch", [
    {"source_id": "other"}, {"scenario_id": "email_bola"}, {"surface": "email"},
    {"text": "x" * 4001}, {"text": ""}, {"text": 123}, {"strategy": "invalid strategy"},
    {"grant": {}}, {"metadata": {}}, {"fixture_snapshot": {}}, {"expected_benign": []},
    {"parent_id": str(uuid4())}, {"generation": 5}, {"policy": "none"},
])
async def test_invalid_proposals_never_reach_executor(patch, scripted_model, memory_event_sink):
    payload = json.dumps({"text": "sandbox text", "strategy": "test", **patch})
    model = scripted_model([_reply(payload), _reply(payload)])

    async def execute(candidate):
        pytest.fail("invalid proposal executed")

    assert await AttackEngine(model, model_settings=_settings()).discover(
        _scenario(), Budget(max_candidates=1), 0, execute, memory_event_sink(uuid4())
    ) == []
    assert len(model.calls) == 2


async def test_only_one_format_repair_per_discovery(scripted_model, memory_event_sink):
    model = scripted_model([_reply("{") for _ in range(6)])
    async def execute(candidate):
        pytest.fail("invalid JSON executed")
    assert await AttackEngine(model, model_settings=_settings()).discover(
        _scenario(), Budget(max_candidates=3), 0, execute, memory_event_sink(uuid4())
    ) == []
    prompts = [call["messages"][0].content[0].text for call in model.calls]
    assert sum('"repair_request": true' in prompt for prompt in prompts) == 1


async def test_success_before_timeout_stops_and_inconclusive_is_preserved(scripted_model, memory_event_sink):
    model = scripted_model([_reply(json.dumps({"text": str(i)})) for i in range(2)])
    results_seen = []
    async def execute(candidate):
        data = _result(candidate).model_dump(mode="json")
        data.update(status="timed_out", oracle_outcome="inconclusive", benign_success=None)
        if results_seen:
            data.update(oracle_outcome="success", violations=[{
                "kind": "canary_leak", "impact": "high", "evidence_event_ids": [str(uuid4())],
                "details": {"sink": "final_output"},
            }])
        result = CaseResult.model_validate(data)
        results_seen.append(result)
        return result
    results = await AttackEngine(model, model_settings=_settings()).discover(
        _scenario(), Budget(max_candidates=6), 2, execute, memory_event_sink(uuid4())
    )
    assert [result.oracle_outcome.value for result in results] == ["inconclusive", "success"]
    assert len(model.calls) == 2


async def test_target_usage_exhausts_local_budget(scripted_model, memory_event_sink):
    model = scripted_model([_reply(json.dumps({"text": "test"}))])
    async def execute(candidate):
        data = _result(candidate).model_dump(mode="json")
        data["usage"] = {"input_tokens": 9000, "output_tokens": 1000}
        return CaseResult.model_validate(data)
    assert len(await AttackEngine(model, model_settings=_settings()).discover(
        _scenario(), Budget(max_candidates=6, max_total_tokens=10000), 2, execute, memory_event_sink(uuid4())
    )) == 1


async def test_model_and_executor_deadlines_propagate_errors(scripted_model, memory_event_sink, monkeypatch):
    import agentbreak.attacks.engine as module
    original_wait_for = asyncio.wait_for
    async def bounded(awaitable, timeout):
        assert 0 < timeout <= 300
        return await original_wait_for(awaitable, timeout=0.01)
    monkeypatch.setattr(module.asyncio, "wait_for", bounded)
    class HungModel:
        async def complete(self, *args, **kwargs):
            await asyncio.Event().wait()
    async def execute(candidate):
        await asyncio.Event().wait()
    with pytest.raises(TimeoutError):
        await AttackEngine(HungModel(), model_settings=_settings()).discover(
            _scenario(), Budget(), 0, execute, memory_event_sink(uuid4())
        )
    model = scripted_model([_reply(json.dumps({"text": "test"}))])
    with pytest.raises(TimeoutError):
        await AttackEngine(model, model_settings=_settings()).discover(
            _scenario(), Budget(), 0, execute, memory_event_sink(uuid4())
        )


async def test_branch_event_parent_matches_candidate_parent(scripted_model, memory_event_sink):
    model = scripted_model([_reply(json.dumps({"text": str(i)})) for i in range(4)])
    sink = memory_event_sink(uuid4())
    candidates = []
    async def execute(candidate):
        candidates.append(candidate)
        result = _result(candidate)
        # Only the first trial consumed the source: force branching from root.
        result.source_consumed = len(candidates) == 1
        return result
    await AttackEngine(model, model_settings=_settings()).discover(
        _scenario(), Budget(max_candidates=4), 0, execute, sink
    )
    for candidate, event in zip(candidates[1:], sink.events[1:]):
        assert candidate.parent_id == candidates[0].id
        assert event.parent_event_ids == [sink.events[0].id]
