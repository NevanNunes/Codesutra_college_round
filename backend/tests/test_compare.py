import pytest
from uuid import uuid4

from agentbreak.contracts import CaseResult, OracleOutcome, DefensePreset, ExecutionMode, Violation
from agentbreak.evaluation.compare import compare_runs

from agentbreak.contracts import ToolCounts, Usage, StateDiff

def _mock_result(
    candidate_id=None,
    defense=DefensePreset.BASELINE,
    oracle_outcome=OracleOutcome.SUCCESS,
    violations=None,
    attempted_violations=None,
    benign_success=None,
    scenario_id="doc_exfil",
    task_id="task_1"
) -> CaseResult:
    return CaseResult(
        run_id=uuid4(),
        trial_id=uuid4(),
        scenario_id=scenario_id,
        task_id=task_id,
        candidate_id=candidate_id,
        payload_sha256="123" * 21 + "1" if candidate_id else None,
        fixture_sha256="123" * 21 + "1",
        policy_version="v1",
        defense=defense,
        execution_mode=ExecutionMode.FIXTURE,
        status="completed",
        oracle_outcome=oracle_outcome,
        violations=violations or [],
        attempted_violations=attempted_violations or [],
        benign_success=benign_success,
        final_output="test",
        evidence_event_ids=[uuid4()],
        source_consumed=True,
        tool_counts=ToolCounts(),
        duration_ms=100,
        usage=Usage(),
        state_diff=StateDiff()
    )

def test_equal_baseline_and_defended():
    cid = uuid4()
    b = _mock_result(candidate_id=cid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    d = _mock_result(candidate_id=cid, defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    report = compare_runs([b], [d])
    
    assert report.matched_attack_cases == 1
    assert report.unmatched_attack_cases == 0
    p1 = next(c for c in report.categories if c.policy_category == "P1")
    assert p1.baseline_asr == 1.0
    assert p1.defended_asr == 1.0
    assert p1.asr_absolute_change == 0.0
    assert p1.asr_relative_reduction == 0.0
    assert report.findings.still_reproducible == 1

def test_complete_mitigation():
    cid = uuid4()
    b = _mock_result(candidate_id=cid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    d = _mock_result(candidate_id=cid, defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.FAILURE, attempted_violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    report = compare_runs([b], [d])
    
    p1 = next(c for c in report.categories if c.policy_category == "P1")
    assert p1.baseline_asr == 1.0
    assert p1.defended_asr == 0.0
    assert p1.asr_relative_reduction == 100.0
    assert report.findings.resolved == 1

def test_zero_baseline_asr():
    cid = uuid4()
    b = _mock_result(candidate_id=cid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.FAILURE)
    d = _mock_result(candidate_id=cid, defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.FAILURE)
    report = compare_runs([b], [d])
    
    p1 = next(c for c in report.categories if c.policy_category == "P1")
    assert p1.baseline_asr == 0.0
    assert p1.defended_asr == 0.0
    assert p1.asr_relative_reduction is None
    assert p1.relative_reduction_undefined_reason is not None

def test_new_defended_only_violation():
    cid = uuid4()
    b = _mock_result(candidate_id=cid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.FAILURE)
    d = _mock_result(candidate_id=cid, defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    report = compare_runs([b], [d])
    
    assert report.findings.new_findings == 1
    p1 = next(c for c in report.categories if c.policy_category == "P1")
    assert p1.baseline_asr == 0.0
    assert p1.defended_asr == 1.0

def test_utility_regression():
    tid = "task_1"
    b = _mock_result(task_id=tid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.FAILURE, benign_success=True)
    d = _mock_result(task_id=tid, defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.FAILURE, benign_success=False)
    report = compare_runs([b], [d])
    
    assert report.utility.regression_count == 1
    assert report.utility.regression_rate == 1.0
    assert report.utility.new_failures == 1
    assert report.utility.baseline_success_rate == 1.0
    assert report.utility.defended_success_rate == 0.0

def test_mismatched_versions():
    cid = uuid4()
    b = _mock_result(candidate_id=cid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.FAILURE)
    d = _mock_result(candidate_id=cid, defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.FAILURE)
    d.fixture_sha256 = "456" * 21 + "1"  # change hash
    
    report = compare_runs([b], [d])
    assert any("Mismatched fixture hashes" in w for w in report.warnings)

def test_missing_trials():
    cid = uuid4()
    b = _mock_result(candidate_id=cid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.FAILURE)
    
    report = compare_runs([b], [])
    assert report.unmatched_attack_cases == 1
    assert any("Missing defended attack trials" in w for w in report.warnings)

def test_inconclusive_results():
    cid = uuid4()
    b = _mock_result(candidate_id=cid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.INCONCLUSIVE)
    d = _mock_result(candidate_id=cid, defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    report = compare_runs([b], [d])
    
    assert report.findings.inconclusive == 1
    p1 = next(c for c in report.categories if c.policy_category == "P1")
    assert p1.baseline_inconclusive_rate == 1.0
    assert p1.defended_inconclusive_rate == 0.0

def test_partial_mitigation():
    cid = uuid4()
    b = _mock_result(candidate_id=cid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={}),
        Violation(kind="unauthorized_read", impact="medium", evidence_event_ids=[uuid4()], details={})
    ])
    d = _mock_result(candidate_id=cid, defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    report = compare_runs([b], [d])
    
    assert report.findings.partially_mitigated == 1
    assert report.findings.still_reproducible == 0
