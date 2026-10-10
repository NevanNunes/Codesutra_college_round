import pytest
from uuid import uuid4
import asyncio

from agentbreak.contracts import RunRequest, DefensePreset, ExecutionMode, Budget, RunStatus, TraceEvent, EventType, OracleOutcome, Violation, ReplayBundle
from agentbreak.fixtures import list_scenarios, load_snapshot
from tests.test_compare import _mock_result

from agentbreak.evaluation.replay import (
    compare_traces, TraceComparison, get_finding_signature,
    deduplicate_findings, verify_remediation, ReplayRunner
)
from agentbreak.evaluation.scoring import score_finding
from agentbreak.storage.database import Database

@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    db = Database(str(db_path))
    db.initialize()
    return db

def test_compare_traces():
    run_id = uuid4()
    trial_id = uuid4()
    
    orig = [
        TraceEvent(id=uuid4(), run_id=run_id, seq=1, trial_id=trial_id, type=EventType.TOOL_EXECUTED, timestamp="2026-01-01T00:00:00Z", data={"tool_name": "list_directory"}, parent_event_ids=[]),
        TraceEvent(id=uuid4(), run_id=run_id, seq=2, trial_id=trial_id, type=EventType.TOOL_BLOCKED, timestamp="2026-01-01T00:00:01Z", data={"tool_name": "send_email"}, parent_event_ids=[]),
        TraceEvent(id=uuid4(), run_id=run_id, seq=3, trial_id=trial_id, type=EventType.ORACLE_RESULT, timestamp="2026-01-01T00:00:02Z", data={"outcome": "success"}, parent_event_ids=[]),
    ]
    
    # Exact match
    res = compare_traces(orig, orig)
    assert res.exact_match
    assert res.semantic_match
    
    # Semantic match (different order)
    semantic = [
        TraceEvent(id=uuid4(), run_id=run_id, seq=1, trial_id=trial_id, type=EventType.TOOL_BLOCKED, timestamp="2026-01-01T00:00:01Z", data={"tool_name": "send_email"}, parent_event_ids=[]),
        TraceEvent(id=uuid4(), run_id=run_id, seq=2, trial_id=trial_id, type=EventType.TOOL_EXECUTED, timestamp="2026-01-01T00:00:00Z", data={"tool_name": "list_directory"}, parent_event_ids=[]),
        TraceEvent(id=uuid4(), run_id=run_id, seq=3, trial_id=trial_id, type=EventType.ORACLE_RESULT, timestamp="2026-01-01T00:00:02Z", data={"outcome": "success"}, parent_event_ids=[]),
    ]
    res = compare_traces(orig, semantic)
    assert not res.exact_match
    assert res.semantic_match
    
    # Mismatch
    mismatch = [
        TraceEvent(id=uuid4(), run_id=run_id, seq=1, trial_id=trial_id, type=EventType.TOOL_EXECUTED, timestamp="2026-01-01T00:00:00Z", data={"tool_name": "list_directory"}, parent_event_ids=[]),
        TraceEvent(id=uuid4(), run_id=run_id, seq=3, trial_id=trial_id, type=EventType.ORACLE_RESULT, timestamp="2026-01-01T00:00:02Z", data={"outcome": "failure"}, parent_event_ids=[]),
    ]
    res = compare_traces(orig, mismatch)
    assert not res.exact_match
    assert not res.semantic_match


def test_deduplicate_findings():
    trial1 = uuid4()
    trial2 = uuid4()
    
    v1 = Violation(kind="unauthorized_read", impact="high", details={}, evidence_event_ids=[uuid4()])
    v2 = Violation(kind="unauthorized_read", impact="high", details={}, evidence_event_ids=[uuid4()])
    v3 = Violation(kind="payment_abuse", impact="high", details={}, evidence_event_ids=[uuid4()])
    
    s1 = score_finding(uuid4(), v1, True)
    s2 = score_finding(uuid4(), v2, True)
    s3 = score_finding(uuid4(), v3, True)
    
    e1 = TraceEvent(id=uuid4(), run_id=uuid4(), seq=1, trial_id=trial1, type=EventType.TOOL_EXECUTED, timestamp="2026-01-01T00:00:00Z", data={"tool_name": "read_doc"}, parent_event_ids=[])
    e2 = TraceEvent(id=uuid4(), run_id=uuid4(), seq=1, trial_id=trial2, type=EventType.TOOL_EXECUTED, timestamp="2026-01-01T00:00:00Z", data={"tool_name": "read_doc"}, parent_event_ids=[])
    e3 = TraceEvent(id=uuid4(), run_id=uuid4(), seq=1, trial_id=trial1, type=EventType.TOOL_EXECUTED, timestamp="2026-01-01T00:00:00Z", data={"tool_name": "pay"}, parent_event_ids=[])
    
    events_by_trial = {
        trial1: [e1, e3],
        trial2: [e2]
    }
    
    deduped = deduplicate_findings([(trial1, s1), (trial2, s2), (trial1, s3)], events_by_trial)
    assert len(deduped) == 3
    
    # One group should have 1 score (the unauthorized read that used read_doc only)
    read_group = next(g for g in deduped if g.rule_kind == "unauthorized_read" and g.signature.endswith("read_doc"))
    assert len(read_group.traces) == 1
    assert len(read_group.scores) == 1


def test_verify_remediation():
    trial1 = uuid4()
    trial2 = uuid4()
    
    v1 = Violation(kind="unauthorized_read", impact="high", details={}, evidence_event_ids=[uuid4()])
    s1 = score_finding(uuid4(), v1, True)
    e1 = TraceEvent(id=uuid4(), run_id=uuid4(), seq=1, trial_id=trial1, type=EventType.TOOL_EXECUTED, timestamp="2026-01-01T00:00:00Z", data={"tool_name": "read_doc"}, parent_event_ids=[])
    
    orig = deduplicate_findings([(trial1, s1)], {trial1: [e1]})
    
    # Retest Passed (Blocked)
    s_passed = score_finding(uuid4(), v1, False)  # blocked
    e_passed = TraceEvent(id=uuid4(), run_id=uuid4(), seq=1, trial_id=trial2, type=EventType.TOOL_BLOCKED, timestamp="2026-01-01T00:00:00Z", data={"tool_name": "read_doc"}, parent_event_ids=[])
    replay_passed = deduplicate_findings([(trial2, s_passed)], {trial2: [e_passed]})
    
    status_passed = verify_remediation(orig, replay_passed)
    assert len(status_passed) == 1
    assert status_passed[0].status == "retest_passed"
    
    # Retest Failed (Executed)
    s_failed = score_finding(uuid4(), v1, True)
    e_failed = TraceEvent(id=uuid4(), run_id=uuid4(), seq=1, trial_id=trial2, type=EventType.TOOL_EXECUTED, timestamp="2026-01-01T00:00:00Z", data={"tool_name": "read_doc"}, parent_event_ids=[])
    replay_failed = deduplicate_findings([(trial2, s_failed)], {trial2: [e_failed]})
    
    status_failed = verify_remediation(orig, replay_failed)
    assert len(status_failed) == 1
    assert status_failed[0].status == "retest_failed"

@pytest.mark.asyncio
async def test_replay_runner(db):
    b_run_id = uuid4()
    req = RunRequest(scenario_ids=["doc_exfil"], operation="discover", defense=DefensePreset.BASELINE, execution_mode=ExecutionMode.FIXTURE, budget=Budget(), seed=42)
    db.create_run(b_run_id, req)
    
    # Create an initial run and build replay bundle
    from agentbreak.contracts import CaseSpec, ModelSettings, canonical_sha256, AttackCandidate
    from agentbreak.fixtures import list_scenarios, load_snapshot
    scenario = list_scenarios()[0]
    snapshot = load_snapshot(scenario.fixture_id)

    cid = uuid4()
    import hashlib
    candidate = AttackCandidate(id=cid, scenario_id=scenario.id, source_id=scenario.source_id, surface=scenario.surface, strategy="direct", text="attack", payload_sha256=hashlib.sha256(b"attack").hexdigest())
    
    b_res = _mock_result(candidate_id=cid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.FAILURE)
    b_res.run_id = b_run_id
    b_res.scenario_id = scenario.id
    b_res.task_id = scenario.task_id
    b_res.fixture_sha256 = canonical_sha256(snapshot)
    b_res.payload_sha256 = candidate.payload_sha256
    
    spec_b = CaseSpec(run_id=b_run_id, trial_id=b_res.trial_id, scenario=scenario, candidate=candidate, defense=DefensePreset.BASELINE, execution_mode=ExecutionMode.FIXTURE, fixture_snapshot=snapshot, seed=42, model_settings=ModelSettings(provider="test", target_model_id="test", attacker_model_id="test", temperature=0, max_tokens=1), policy_version="v1")
    db.save_case_spec(b_run_id, spec_b)
    db.save_case_result(b_run_id, b_res)
    
    event_id = b_res.evidence_event_ids[0]
    dummy_event = TraceEvent(id=event_id, run_id=b_run_id, seq=1, trial_id=b_res.trial_id, type=EventType.TOOL_EXECUTED, timestamp="2026-01-01T00:00:00Z", data={}, parent_event_ids=[])
    db.save_event(dummy_event)
    
    db.update_run_status(b_run_id, RunStatus.COMPLETED)
    
    bundle = db.build_replay_bundle(b_run_id)
    assert bundle is not None
    
    replay_run_id = uuid4()
    db.create_run(replay_run_id, req)
    
    runner = ReplayRunner(db)
    
    # Since DummyApp and TargetRunner are mostly synchronous stubs in the tests without real models,
    # it will run through target runner but since model_client is None, it will error out or complete with benign success.
    # In the actual test, TargetRunner handles the case.
    
    results = await runner.run_replay(bundle, replay_run_id, DefensePreset.GATEWAY)
    
    assert len(results) == 1
    assert results[0].run_id == replay_run_id
    assert results[0].defense == DefensePreset.GATEWAY
