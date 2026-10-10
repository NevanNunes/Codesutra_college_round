import pytest
from uuid import uuid4

from agentbreak.contracts import (
    CaseResult, CaseStatus, OracleOutcome, DefensePreset, ExecutionMode,
    ToolCounts, Usage, ErrorDetail, StateDiff, Violation
)
from agentbreak.evaluation.metrics import calculate_metrics, POLICY_CATEGORIES


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
        status=CaseStatus.COMPLETED,
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


def test_empty_suite():
    metrics = calculate_metrics([])
    assert metrics.attack_success_rate is None
    assert metrics.category_matrix == []


def test_all_inconclusive_suites():
    r1 = _mock_result(candidate_id=uuid4(), oracle_outcome=OracleOutcome.INCONCLUSIVE)
    metrics = calculate_metrics([r1])
    
    assert metrics.attack_success_rate is None
    assert metrics.inconclusive_rate == 1.0
    
    # We should have categories in the matrix. 
    # doc_exfil defaults to P1, P2
    p1 = next(c for c in metrics.category_matrix if c.policy_category == "P1")
    assert p1.inconclusive_count == 1
    assert p1.inconclusive_rate == 1.0
    assert p1.conclusive_trials == 0
    assert p1.attack_success_rate is None


def test_mixed_attack_and_benign_metrics():
    att1 = _mock_result(candidate_id=uuid4(), oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    att2 = _mock_result(candidate_id=uuid4(), oracle_outcome=OracleOutcome.FAILURE, attempted_violations=[
        Violation(kind="unauthorized_send", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    # Benign passing
    ben1 = _mock_result(oracle_outcome=OracleOutcome.FAILURE, benign_success=True)
    # Benign failing (incorrectly blocked)
    ben2 = _mock_result(defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.FAILURE, benign_success=False)

    metrics = calculate_metrics([att1, att2, ben1, ben2])

    assert metrics.attack_success_rate == 0.5 # 1 executed / 2 conclusive
    assert metrics.attempt_rate == 1.0        # 2 attempted / 2 conclusive
    assert metrics.block_rate == 0.5          # 1 blocked / 2 attempted

    assert metrics.utility.success_rate == 0.5
    assert metrics.utility.over_block_rate == 1.0 # 1 failed / 1 defended
    assert metrics.utility.regression_rate == 1.0


def test_category_matrix_distribution():
    r1 = _mock_result(candidate_id=uuid4(), oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    r2 = _mock_result(candidate_id=uuid4(), scenario_id="email_bola", oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="payment_abuse", impact="high", evidence_event_ids=[uuid4()], details={})
    ])

    metrics = calculate_metrics([r1, r2])

    p1 = next(c for c in metrics.category_matrix if c.policy_category == "P1")
    p3 = next(c for c in metrics.category_matrix if c.policy_category == "P3")
    p5 = next(c for c in metrics.category_matrix if c.policy_category == "P5")

    assert p1.coverage_status == "tested"
    assert p1.executed_violation_count == 1
    assert p1.attack_success_rate == 1.0

    assert p3.coverage_status == "tested"
    assert p3.executed_violation_count == 1

    assert p5.coverage_status == "not_tested"
    assert p5.planned_cases == 0


def test_baseline_and_defended_separation():
    base = _mock_result(candidate_id=uuid4(), defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.SUCCESS, violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])
    gate = _mock_result(candidate_id=uuid4(), defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.FAILURE, attempted_violations=[
        Violation(kind="canary_leak", impact="high", evidence_event_ids=[uuid4()], details={})
    ])

    metrics = calculate_metrics([base, gate])
    
    assert metrics.residual_violation_rate == 0.0 # Gateway had 0 executed / 1 conclusive

    mat_base = next(c for c in metrics.category_matrix if c.policy_category == "P1" and c.target_profile == "baseline")
    mat_gate = next(c for c in metrics.category_matrix if c.policy_category == "P1" and c.target_profile == "gateway")

    assert mat_base.attack_success_rate == 1.0
    assert mat_gate.attack_success_rate == 0.0
    assert mat_gate.block_rate == 1.0


def test_zero_denominators():
    r = _mock_result(candidate_id=uuid4(), oracle_outcome=OracleOutcome.FAILURE)
    metrics = calculate_metrics([r])
    
    # 0 attempted / 0 executed + attempted
    assert metrics.block_rate is None
    
    p1 = next(c for c in metrics.category_matrix if c.policy_category == "P1")
    assert p1.block_rate is None
