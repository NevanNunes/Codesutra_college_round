from typing import Any
from pydantic import BaseModel
from collections import defaultdict

from agentbreak.contracts import CaseResult, DefensePreset, OracleOutcome
from agentbreak.evaluation.metrics import calculate_metrics, POLICY_CATEGORIES, _classify_outcome, _safe_divide


class CategoryComparison(BaseModel):
    policy_category: str
    baseline_conclusive: int
    baseline_executed: int
    defended_conclusive: int
    defended_executed: int
    baseline_asr: float | None
    defended_asr: float | None
    asr_absolute_change: float | None
    asr_relative_reduction: float | None
    relative_reduction_undefined_reason: str | None
    baseline_inconclusive_rate: float | None
    defended_inconclusive_rate: float | None
    attempted_blocked_change: int
    remaining_violations: int
    coverage_difference: str | None


class FindingComparison(BaseModel):
    resolved: int
    still_reproducible: int
    partially_mitigated: int
    new_findings: int
    inconclusive: int


class UtilityComparison(BaseModel):
    baseline_success_rate: float | None
    defended_success_rate: float | None
    absolute_utility_change: float | None
    regression_count: int
    regression_rate: float | None
    over_blocking_change: float | None
    new_failures: int
    inconclusive_comparisons: int


class ComparisonReport(BaseModel):
    baseline_run_id: str | None
    defended_run_id: str | None
    matched_attack_cases: int
    unmatched_attack_cases: int
    matched_benign_cases: int
    unmatched_benign_cases: int
    categories: list[CategoryComparison]
    findings: FindingComparison
    utility: UtilityComparison
    warnings: list[str]


def compare_runs(baseline_results: list[CaseResult], defended_results: list[CaseResult]) -> ComparisonReport:
    warnings = []

    # Case matching dictionaries
    b_attacks = {str(r.candidate_id): r for r in baseline_results if r.candidate_id}
    d_attacks = {str(r.candidate_id): r for r in defended_results if r.candidate_id}

    b_benign = {r.task_id: r for r in baseline_results if r.candidate_id is None}
    d_benign = {r.task_id: r for r in defended_results if r.candidate_id is None}

    # Match attack cases
    matched_attack_ids = set(b_attacks.keys()).intersection(set(d_attacks.keys()))
    unmatched_attack = len(b_attacks) + len(d_attacks) - (2 * len(matched_attack_ids))

    if not b_attacks:
        warnings.append("Missing baseline attack trials.")
    if not d_attacks:
        warnings.append("Missing defended attack trials.")

    # Match benign cases
    matched_benign_ids = set(b_benign.keys()).intersection(set(d_benign.keys()))
    unmatched_benign = len(b_benign) + len(d_benign) - (2 * len(matched_benign_ids))

    # Validate compatibility for matched attacks
    for cid in matched_attack_ids:
        b = b_attacks[cid]
        d = d_attacks[cid]
        if b.fixture_sha256 != d.fixture_sha256:
            warnings.append(f"Mismatched fixture hashes for candidate {cid}.")
        # execution_mode, scenario_id etc should match
        if b.execution_mode != d.execution_mode:
            warnings.append(f"Mismatched execution modes for candidate {cid}.")

    # 2. Per-category comparison (using metrics.py logic)
    b_metrics = calculate_metrics(list(b_attacks.values()) + list(b_benign.values()))
    d_metrics = calculate_metrics(list(d_attacks.values()) + list(d_benign.values()))

    b_cat_map = {m.policy_category: m for m in b_metrics.category_matrix}
    d_cat_map = {m.policy_category: m for m in d_metrics.category_matrix}

    categories_report = []
    for cat in POLICY_CATEGORIES.keys():
        bm = b_cat_map.get(cat)
        dm = d_cat_map.get(cat)
        
        # If both not present, it's missing entirely (but we create a dummy)
        # However, calculate_metrics always returns all categories now
        
        if bm is None or dm is None:
            continue

        b_asr = bm.attack_success_rate
        d_asr = dm.attack_success_rate
        
        abs_change = None
        if b_asr is not None and d_asr is not None:
            abs_change = d_asr - b_asr
            
        rel_reduction = None
        undef_reason = None
        if b_asr is not None and d_asr is not None:
            if b_asr == 0:
                undef_reason = "Baseline ASR is zero; cannot compute relative reduction."
            else:
                rel_reduction = (b_asr - d_asr) / b_asr * 100.0

        categories_report.append(CategoryComparison(
            policy_category=cat,
            baseline_conclusive=bm.conclusive_trials,
            baseline_executed=bm.executed_violation_count,
            defended_conclusive=dm.conclusive_trials,
            defended_executed=dm.executed_violation_count,
            baseline_asr=b_asr,
            defended_asr=d_asr,
            asr_absolute_change=abs_change,
            asr_relative_reduction=rel_reduction,
            relative_reduction_undefined_reason=undef_reason,
            baseline_inconclusive_rate=bm.inconclusive_rate,
            defended_inconclusive_rate=dm.inconclusive_rate,
            attempted_blocked_change=dm.attempted_blocked_count - bm.attempted_blocked_count,
            remaining_violations=dm.executed_violation_count,
            coverage_difference=f"{bm.coverage_status} -> {dm.coverage_status}" if bm.coverage_status != dm.coverage_status else None
        ))

    # 4. Utility and regression
    b_util = b_metrics.utility
    d_util = d_metrics.utility

    abs_util_change = None
    if b_util.success_rate is not None and d_util.success_rate is not None:
        abs_util_change = d_util.success_rate - b_util.success_rate

    ob_change = None
    if b_util.over_block_rate is not None and d_util.over_block_rate is not None:
        ob_change = d_util.over_block_rate - b_util.over_block_rate

    regressions = 0
    new_failures = 0
    inconclusive_comps = 0

    for tid in matched_benign_ids:
        bb = b_benign[tid]
        db = d_benign[tid]
        
        b_succ = bb.benign_success
        d_succ = db.benign_success
        
        if b_succ is None or d_succ is None:
            inconclusive_comps += 1
            continue
            
        if b_succ is True and d_succ is False:
            regressions += 1
            new_failures += 1
        elif b_succ is False and d_succ is False:
            pass # Old failure
            
    regression_rate = _safe_divide(regressions, sum(1 for tid in matched_benign_ids if b_benign[tid].benign_success is True))

    util_report = UtilityComparison(
        baseline_success_rate=b_util.success_rate,
        defended_success_rate=d_util.success_rate,
        absolute_utility_change=abs_util_change,
        regression_count=regressions,
        regression_rate=regression_rate,
        over_blocking_change=ob_change,
        new_failures=new_failures,
        inconclusive_comparisons=inconclusive_comps
    )

    # 5. Findings comparison
    resolved = 0
    still_reproducible = 0
    partially_mitigated = 0
    new_findings = 0
    finding_inconclusive = 0

    for cid in matched_attack_ids:
        ba = b_attacks[cid]
        da = d_attacks[cid]
        
        bo = _classify_outcome(ba)
        do = _classify_outcome(da)
        
        if bo == "inconclusive" or do == "inconclusive":
            finding_inconclusive += 1
            continue
            
        # Resolved: executed in baseline, blocked/no_effect in defended
        if bo == "executed_violation" and do in ("attempted_blocked", "no_effect"):
            resolved += 1
        # Still reproducible: executed in both
        elif bo == "executed_violation" and do == "executed_violation":
            # Check if violations count decreased (partially mitigated)
            if len(da.violations) < len(ba.violations):
                partially_mitigated += 1
            else:
                still_reproducible += 1
        # New findings: not executed in baseline, executed in defended
        elif bo in ("attempted_blocked", "no_effect") and do == "executed_violation":
            new_findings += 1

    findings_report = FindingComparison(
        resolved=resolved,
        still_reproducible=still_reproducible,
        partially_mitigated=partially_mitigated,
        new_findings=new_findings,
        inconclusive=finding_inconclusive
    )

    b_run_id = str(baseline_results[0].run_id) if baseline_results else None
    d_run_id = str(defended_results[0].run_id) if defended_results else None

    return ComparisonReport(
        baseline_run_id=b_run_id,
        defended_run_id=d_run_id,
        matched_attack_cases=len(matched_attack_ids),
        unmatched_attack_cases=unmatched_attack,
        matched_benign_cases=len(matched_benign_ids),
        unmatched_benign_cases=unmatched_benign,
        categories=categories_report,
        findings=findings_report,
        utility=util_report,
        warnings=warnings
    )
