from typing import Any
from uuid import UUID
from pydantic import BaseModel, Field

from agentbreak.contracts import CaseResult, EventDraft, TraceEvent
from agentbreak.evaluation.metrics import OverallMetrics, MetricRecord
from agentbreak.evaluation.compare import ComparisonReport
from agentbreak.evaluation.scoring import FindingScore

class SecurityOverview(BaseModel):
    run_id: str
    timestamp: str
    target_profile: str
    configuration_identity: str
    planned_cases: int
    executed_cases: int
    conclusive_count: int
    inconclusive_count: int
    confirmed_unique_findings: int | None
    severity_distribution: dict[str, int]
    overall_attack_success_rate: float | None
    overall_asr_denominator: int
    legitimate_task_success_rate: float | None
    baseline_defended_summary: str | None
    coverage_warnings: list[str]
    highest_priority_unresolved: str | None


class AttackEffectiveness(BaseModel):
    attempts: int
    blocked_attempts: int
    confirmed_violations: int
    attack_success_rate: float | None = None
    time_to_first_finding_ms: int | None = None
    unique_findings: int | None = None
    execution_budget_utilized: float | None = None
    model_call_counts: int | None = None
    search_efficiency: float | None = None


class AdaptiveAttackerAnalytics(BaseModel):
    available_budget: dict[str, int] | None = None
    executions: int | None = None
    model_calls: int | None = None
    unique_paths: int | None = None
    duplicate_attempts: int | None = None
    new_findings_per_budget: float | None = None
    time_to_first_finding: int | None = None
    data_unavailable: bool = True


class RemediationRetest(BaseModel):
    finding_id: UUID
    priority: str
    recommendation: str
    remediation_status: str
    last_retest: str | None
    previous_outcome: str
    latest_outcome: str
    remaining_risk: str


class EvidenceCoverage(BaseModel):
    case_identifiers: list[str]
    suite_designation: str
    run_metadata: dict[str, Any]
    configuration_hashes: list[str]
    trace_references: list[str]
    oracle_decisions: list[str]
    missing_evidence: list[str]
    coverage_gaps: list[str]
    reproducibility: str


class DashboardReport(BaseModel):
    security_overview: SecurityOverview
    attack_effectiveness: AttackEffectiveness
    category_matrix: list[MetricRecord]
    attack_chains_and_traces: list[dict]  # Simplified trace representation
    severity_and_impact: list[FindingScore]
    baseline_vs_defended: ComparisonReport | None
    utility_regression: dict[str, Any] | None
    adaptive_analytics: AdaptiveAttackerAnalytics
    remediation_retesting: list[RemediationRetest]
    evidence_coverage: EvidenceCoverage


def generate_dashboard_report(
    run_id: UUID,
    results: list[CaseResult],
    events: list[TraceEvent],
    metrics: OverallMetrics,
    scores: list[FindingScore],
    comparison: ComparisonReport | None = None
) -> DashboardReport:
    """Generates the full comprehensive dashboard report for a single run (or compared runs)."""

    total_attack_cases = len([r for r in results if r.candidate_id])
    total_benign_cases = len([r for r in results if r.candidate_id is None])
    
    # 1. Security Overview
    severity_dist = {"Critical": 0, "High": 0, "Moderate": 0, "Low": 0, "Unknown": 0}
    for s in scores:
        severity_dist[s.severity_band] = severity_dist.get(s.severity_band, 0) + 1
        
    conclusive = sum(1 for r in metrics.category_matrix for c in [r.conclusive_trials]) 
    # Actually, metrics already gives us overall stats, but we can compute from category matrix
    conclusive = sum(m.conclusive_trials for m in metrics.category_matrix)
    inconclusive = sum(m.inconclusive_count for m in metrics.category_matrix)
    executed = sum(m.executed_cases for m in metrics.category_matrix)
    planned = sum(m.planned_cases for m in metrics.category_matrix)
    
    executed_v = sum(m.executed_violation_count for m in metrics.category_matrix)
    
    overview = SecurityOverview(
        run_id=str(run_id),
        timestamp=events[0].timestamp.isoformat() if events else "unknown",
        target_profile=results[0].defense.value if results else "unknown",
        configuration_identity=results[0].fixture_sha256 if results else "unknown",
        planned_cases=planned,
        executed_cases=executed,
        conclusive_count=conclusive,
        inconclusive_count=inconclusive,
        confirmed_unique_findings=len(scores),
        severity_distribution=severity_dist,
        overall_attack_success_rate=metrics.attack_success_rate,
        overall_asr_denominator=conclusive,
        legitimate_task_success_rate=metrics.utility.success_rate,
        baseline_defended_summary="Compared" if comparison else "No baseline provided.",
        coverage_warnings=[f"Category {m.policy_category} is {m.coverage_status}" for m in metrics.category_matrix if m.coverage_status != "tested"],
        highest_priority_unresolved="Immediate" if severity_dist["Critical"] > 0 else None
    )

    # 2. Attack Effectiveness
    attempts = sum(m.attempted_blocked_count for m in metrics.category_matrix) + executed_v
    
    effectiveness = AttackEffectiveness(
        attempts=attempts,
        blocked_attempts=sum(m.attempted_blocked_count for m in metrics.category_matrix),
        confirmed_violations=executed_v,
        attack_success_rate=metrics.attack_success_rate,
        time_to_first_finding_ms=None,
        unique_findings=len(scores),
        execution_budget_utilized=None,
        model_call_counts=None,
        search_efficiency=None
    )

    # 4. Traces
    traces = []
    for r in results:
        traces.append({
            "trial_id": str(r.trial_id),
            "scenario_id": r.scenario_id,
            "status": r.status.value,
            "oracle_outcome": r.oracle_outcome.value,
            "violations": len(r.violations)
        })

    # 8. Adaptive Analytics (mostly None because we don't have this metadata yet)
    adaptive = AdaptiveAttackerAnalytics()

    # 9. Remediation
    remediations = []
    for s in scores:
        remediations.append(RemediationRetest(
            finding_id=s.finding_id,
            priority=s.remediation_priority,
            recommendation="Review finding and apply relevant policy patch.",
            remediation_status="open",
            last_retest=None,
            previous_outcome="executed",
            latest_outcome="executed",
            remaining_risk=s.impact.potential_impact
        ))

    # 10. Evidence
    evidence = EvidenceCoverage(
        case_identifiers=[str(r.trial_id) for r in results],
        suite_designation="mixed",
        run_metadata={"total_cases": len(results)},
        configuration_hashes=[r.fixture_sha256 for r in results],
        trace_references=[str(e.id) for e in events],
        oracle_decisions=[r.oracle_outcome.value for r in results],
        missing_evidence=[],
        coverage_gaps=[],
        reproducibility="high"
    )

    return DashboardReport(
        security_overview=overview,
        attack_effectiveness=effectiveness,
        category_matrix=metrics.category_matrix,
        attack_chains_and_traces=traces,
        severity_and_impact=scores,
        baseline_vs_defended=comparison,
        utility_regression=metrics.utility.model_dump() if metrics.utility else None,
        adaptive_analytics=adaptive,
        remediation_retesting=remediations,
        evidence_coverage=evidence
    )
