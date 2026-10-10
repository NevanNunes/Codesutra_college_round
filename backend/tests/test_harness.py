import asyncio
import pytest
from uuid import uuid4

from agentbreak.contracts import (
    Budget, DefensePreset, ExecutionMode, RunRequest, CaseStatus, OracleOutcome,
    EventDraft, EventType
)
from agentbreak.evaluation.harness import EvaluationHarness
from agentbreak.storage.database import Database
from agentbreak.llm import StubModelClient
from agentbreak.sandbox.runner import TargetRunner


@pytest.fixture
def db():
    database = Database(":memory:")
    database.initialize()
    return database


@pytest.fixture
def harness(db):
    return EvaluationHarness(db=db, model_client=StubModelClient())


def test_load_suites(harness):
    benign = harness.load_suite("benign")
    assert len(benign) > 0

    discovery = harness.load_suite("discovery")
    assert len(discovery) > 0

    held_out = harness.load_suite("held_out")
    assert len(held_out) > 0

    with pytest.raises(ValueError, match="Unknown or missing suite"):
        harness.load_suite("invalid")


@pytest.mark.asyncio
async def test_run_suite_both_profiles(harness, db):
    req = RunRequest(
        scenario_ids=["doc_exfil"],
        operation="suite",
        defense=DefensePreset.BASELINE,
        execution_mode=ExecutionMode.FIXTURE,
        budget=Budget(max_model_turns=2, max_tool_calls=4, max_total_tokens=1000, case_timeout_s=5),
        seed=123,
    )
    cases = harness.load_suite("benign")[:1]
    
    run_id = uuid4()
    db.create_run(run_id, req)

    results = await harness.run_cases(
        run_id=run_id,
        req=req,
        cases=cases,
        profiles=[DefensePreset.BASELINE, DefensePreset.GATEWAY]
    )

    assert len(results) == 2
    assert results[0].defense == DefensePreset.BASELINE
    assert results[1].defense == DefensePreset.GATEWAY

    # Verify storage linked verdict to case and run
    stored_cases = db.get_cases(run_id)
    assert len(stored_cases) == 2


@pytest.mark.asyncio
async def test_timeout_handled(harness, db, monkeypatch):
    req = RunRequest(
        scenario_ids=["doc_exfil"],
        operation="suite",
        defense=DefensePreset.BASELINE,
        execution_mode=ExecutionMode.FIXTURE,
        budget=Budget(max_model_turns=2, max_tool_calls=4, max_total_tokens=1000, case_timeout_s=5),
    )
    cases = harness.load_suite("benign")[:1]
    run_id = uuid4()
    db.create_run(run_id, req)

    async def _mock_run_case(*args, **kwargs):
        raise asyncio.TimeoutError()

    monkeypatch.setattr(TargetRunner, "run_case", _mock_run_case)
    
    results = await harness.run_cases(
        run_id=run_id,
        req=req,
        cases=cases,
        profiles=[DefensePreset.BASELINE]
    )
    
    assert len(results) == 1
    assert results[0].status == CaseStatus.TIMED_OUT
    assert results[0].oracle_outcome == OracleOutcome.INCONCLUSIVE
    assert results[0].error is not None
    assert results[0].error.code == "case_timeout"


@pytest.mark.asyncio
async def test_execution_failure_handled(harness, db, monkeypatch):
    req = RunRequest(
        scenario_ids=["doc_exfil"],
        operation="suite",
        defense=DefensePreset.BASELINE,
        execution_mode=ExecutionMode.FIXTURE,
        budget=Budget(),
    )
    cases = harness.load_suite("benign")[:1]
    run_id = uuid4()
    db.create_run(run_id, req)

    async def _mock_run_case(*args, **kwargs):
        raise ValueError("Simulated runner crash")

    monkeypatch.setattr(TargetRunner, "run_case", _mock_run_case)
    
    results = await harness.run_cases(
        run_id=run_id,
        req=req,
        cases=cases,
        profiles=[DefensePreset.BASELINE]
    )
    
    assert len(results) == 1
    assert results[0].status == CaseStatus.FAILED
    assert results[0].oracle_outcome == OracleOutcome.INCONCLUSIVE
    assert "ValueError" in results[0].error.message


@pytest.mark.asyncio
async def test_storage_failure_during_run(harness, db, monkeypatch):
    req = RunRequest(
        scenario_ids=["doc_exfil"],
        operation="suite",
        defense=DefensePreset.BASELINE,
        execution_mode=ExecutionMode.FIXTURE,
        budget=Budget(),
    )
    cases = harness.load_suite("benign")[:1]
    run_id = uuid4()
    db.create_run(run_id, req)

    def _mock_save_spec(*args, **kwargs):
        raise RuntimeError("Disk full")

    monkeypatch.setattr(db, "save_case_spec", _mock_save_spec)
    
    with pytest.raises(RuntimeError, match="Disk full"):
        await harness.run_cases(run_id=run_id, req=req, cases=cases, profiles=[DefensePreset.BASELINE])
