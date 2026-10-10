"""Shared helpers for Module B tests (no tests live here; filename keeps B's ownership glob)."""

from __future__ import annotations

from uuid import UUID, uuid4

from agentbreak.contracts import (
    Budget, CaseSpec, DefensePreset, ExecutionMode, ModelReply, ModelSettings, TextBlock, ToolCall,
    ToolUseBlock, Usage,
)
from agentbreak.fixtures import list_attack_seeds, list_scenarios, load_snapshot

RUN_ID = UUID("00000000-0000-4000-8000-0000000000aa")
SETTINGS = ModelSettings(provider="fixture", target_model_id="fixture-target",
                         attacker_model_id="fixture-attacker")
POLICY = {DefensePreset.BASELINE: "baseline-v1", DefensePreset.GATEWAY: "gateway-v1"}


def scenario(scenario_id: str):
    return next(s for s in list_scenarios() if s.id == scenario_id)


def seed(scenario_id: str, split: str = "discovery", index: int = 0):
    return [s for s in list_attack_seeds(split) if s.candidate.scenario_id == scenario_id][index].candidate


def make_spec(scenario_id: str = "doc_exfil", *, candidate=None, defense=DefensePreset.BASELINE,
              mode=ExecutionMode.FIXTURE, budget: Budget | None = None, scenario_obj=None,
              snapshot=None) -> CaseSpec:
    scen = scenario_obj or scenario(scenario_id)
    return CaseSpec(
        run_id=RUN_ID, trial_id=uuid4(), scenario=scen, candidate=candidate, defense=defense,
        execution_mode=mode, fixture_snapshot=snapshot or load_snapshot(scen.fixture_id),
        budget=budget or Budget(), seed=1, model_settings=SETTINGS, policy_version=POLICY[defense])


def call_reply(*calls, text: str = "", usage=(10, 5)) -> ModelReply:
    """calls: (call_id, tool_name, arguments) tuples, emitted in this order."""
    blocks = ([TextBlock(text=text)] if text else []) + [
        ToolUseBlock(call=ToolCall(call_id=cid, name=name, arguments=args)) for cid, name, args in calls]
    return ModelReply(content=blocks, usage=Usage(input_tokens=usage[0], output_tokens=usage[1]),
                      stop_reason="tool_use", model_id="fixture-target")


def final_reply(text: str, *, stop_reason: str = "end_turn") -> ModelReply:
    return ModelReply(content=[TextBlock(text=text)] if text else [], usage=Usage(input_tokens=10, output_tokens=5),
                      stop_reason=stop_reason, model_id="fixture-target")


def events_of(sink, event_type):
    return [e for e in sink.events if e.type == event_type]


def result_blocks(model, call_index: int):
    """ToolResultBlocks in the last user message of the Nth model call."""
    return model.calls[call_index]["messages"][-1].content
