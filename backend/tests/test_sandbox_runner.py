import asyncio
import uuid
import pytest
from typing import Any

from agentbreak.contracts import (
    CaseSpec, CaseStatus, DefensePreset, EventDraft, ExecutionMode, OracleOutcome,
    TraceEvent,
)
from agentbreak.fixtures.traces import list_fixture_traces, FixtureModelClient
from agentbreak.sandbox.runner import TargetRunner
from test_sandbox_support import make_spec, RUN_ID

class MemoryEventSink:
    def __init__(self, run_id: uuid.UUID):
        self.run_id = run_id
        self.events: list[TraceEvent] = []
        self._seq = 1

    async def __call__(self, draft: EventDraft) -> TraceEvent:
        event = TraceEvent(
            id=uuid.uuid4(), run_id=self.run_id, seq=self._seq, timestamp="2026-10-10T12:00:00Z", # type: ignore
            **draft.model_dump()
        )
        self._seq += 1
        self.events.append(event)
        return event

@pytest.fixture
def memory_event_sink():
    return MemoryEventSink(RUN_ID)

@pytest.mark.asyncio
async def test_runner_with_traces(memory_event_sink):
    traces = list_fixture_traces()
    
    # Trace 1: Insecure failure (baseline)
    trace = next(t for t in traces if t.name == "doc_exfil_insecure_failure")
    client = FixtureModelClient(trace)
    runner = TargetRunner(client)
    spec = make_spec(trace.scenario_id, defense=DefensePreset.BASELINE, mode=ExecutionMode.FIXTURE)
    result = await runner.run_case(spec, memory_event_sink)
    assert result.status == CaseStatus.COMPLETED
    assert result.oracle_outcome == OracleOutcome.SUCCESS
    assert any(v.kind == "canary_leak" for v in result.violations)

    # Trace 2: Benign success
    trace2 = next(t for t in traces if t.name == "doc_exfil_benign_success")
    client2 = FixtureModelClient(trace2)
    runner2 = TargetRunner(client2)
    spec2 = make_spec(trace2.scenario_id, defense=DefensePreset.GATEWAY, mode=ExecutionMode.FIXTURE)
    result2 = await runner2.run_case(spec2, memory_event_sink)
    assert result2.status == CaseStatus.COMPLETED
    assert result2.oracle_outcome == OracleOutcome.FAILURE
    assert result2.benign_success is True

    # Trace 3: Cross account read
    trace3 = next(t for t in traces if t.name == "email_bola_cross_account_read")
    client3 = FixtureModelClient(trace3)
    runner3 = TargetRunner(client3)
    spec3 = make_spec(trace3.scenario_id, defense=DefensePreset.BASELINE, mode=ExecutionMode.FIXTURE)
    result3 = await runner3.run_case(spec3, memory_event_sink)
    assert result3.status == CaseStatus.COMPLETED
    assert result3.oracle_outcome == OracleOutcome.SUCCESS
    assert any(v.kind == "unauthorized_read" for v in result3.violations)

@pytest.mark.asyncio
async def test_runner_live_mode_refuses_simulated_client(memory_event_sink):
    trace = list_fixture_traces()[0]
    client = FixtureModelClient(trace)
    runner = TargetRunner(client)
    spec = make_spec(trace.scenario_id, defense=DefensePreset.GATEWAY, mode=ExecutionMode.LIVE)
    result = await runner.run_case(spec, memory_event_sink)
    assert result.status == CaseStatus.FAILED
    assert result.error is not None
    assert result.error.code == "simulated_model_in_live_mode"
