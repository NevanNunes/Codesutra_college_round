import json
import re
from pathlib import Path
from uuid import uuid4

import pytest

from agentbreak.contracts import CaseResult
from agentbreak.evaluation.metrics import calculate_metrics
from agentbreak.evaluation.reports import render_markdown


EXAMPLES = Path(__file__).resolve().parents[2] / "docs" / "examples"


def result(**patch):
    data = json.loads((EXAMPLES / "result.json").read_text(encoding="utf-8"))
    data["trial_id"] = str(uuid4())
    data.update(patch)
    return CaseResult.model_validate(data)


def test_metrics_zero_denominators_and_fixture_live_separation():
    metrics = calculate_metrics([
        result(execution_mode="fixture", defense="gateway", candidate_id=None, payload_sha256=None, benign_success=None, oracle_outcome="inconclusive", status="timed_out"),
        result(execution_mode="live", defense="gateway"),
    ])
    fixture = metrics["by_execution_mode"]["fixture"]["gateway"]
    assert fixture["asr"] is None
    assert fixture["asr_numerator"] == 0
    assert fixture["asr_denominator"] == 0
    assert fixture["execution_incomplete_count"] == 1
    assert metrics["by_execution_mode"]["live"]["gateway"]["reported_case_count"] == 1
    assert fixture["total_scheduled_cases"] is None


def test_metrics_distinguish_blocked_proposal_from_effect_and_pair_only_matches():
    candidate_id = "00000000-0000-4000-8000-000000000003"
    baseline = result(oracle_outcome="success", violations=[{
        "kind": "unauthorized_read", "impact": "high",
        "evidence_event_ids": ["00000000-0000-4000-8000-000000000004"], "details": {"customer_id": "cust_b"},
    },], attempted_violations=[], defense="baseline")
    blocked = result(
        oracle_outcome="failure", defense="gateway", attempted_violations=[{
            "kind": "unauthorized_read", "impact": "high",
            "evidence_event_ids": ["00000000-0000-4000-8000-000000000004"], "details": {"customer_id": "cust_b"},
        }], tool_counts={"proposed": 1, "denied": 1, "forbidden_executed": 0},
    )
    metrics = calculate_metrics([baseline, blocked])
    gateway = metrics["groups"]["fixture/gateway"]
    assert gateway["asr"] == 0
    assert gateway["tool_activity"]["denied"] == 1
    assert gateway["tool_activity"]["forbidden_executed"] == 0
    assert gateway["tool_activity"]["forbidden_denied"] is None
    comparison = metrics["comparison_by_execution_mode"]["fixture"]["paired_prevention"]
    assert comparison["prevented_numerator"] == 1
    assert comparison["prevented_denominator"] == 1


def test_metrics_preserve_success_on_incomplete_case_and_clean_regression():
    baseline_clean = result(candidate_id=None, payload_sha256=None, benign_success=True, defense="baseline")
    gateway_clean = result(candidate_id=None, payload_sha256=None, benign_success=False, defense="gateway")
    incomplete_success = result(status="timed_out", oracle_outcome="success", defense="baseline", violations=[{
        "kind": "canary_leak", "impact": "high",
        "evidence_event_ids": ["00000000-0000-4000-8000-000000000004"], "details": {"sink": "outbox"},
    }])
    metrics = calculate_metrics([baseline_clean, gateway_clean, incomplete_success])
    baseline = metrics["groups"]["fixture/baseline"]
    assert baseline["asr"] == 1
    assert baseline["inconclusive_count"] == 0
    assert metrics["comparison_by_execution_mode"]["fixture"]["matched_clean_regressions"]["regression_numerator"] == 1


def test_report_safe_payload_and_required_evidence_sections():
    dangerous = "payload with ```\n![remote](https://evil.test/x.png)\n<script>alert(1)</script>"
    bundle = {
        "scenario": {"id": "doc_exfil", "title": "Synthetic", "surface": "document", "source_id": "doc_a", "legitimate_task": "task", "attack_goal": "goal"},
        "candidate": {"id": str(uuid4()), "parent_id": None, "generation": 0, "payload_sha256": "a" * 64, "text": dangerous},
        "result": {"status": "completed", "oracle_outcome": "failure", "source_consumed": True, "benign_success": False, "violations": [], "attempted_violations": [], "state_diff": {"outbox_added": []}, "final_output": dangerous, "evidence_event_ids": []},
        "metrics": {},
    }
    report = render_markdown(bundle)
    assert dangerous in report
    assert report.count("![remote](") == 2
    assert "````\npayload with ```" in report
    assert "<script>" in report  # preserved as text in a fenced block
    for section in ("Exact injected text", "Actual mock state/effects", "Evidence event IDs", "Reproducer instructions", "Limitations"):
        assert section in report


def violation():
    return {"kind": "unauthorized_read", "impact": "high", "evidence_event_ids": [str(uuid4())], "details": {}}


def test_unmatched_snapshots_ids_modes_and_tasks_never_pair():
    baseline = result(oracle_outcome="success", violations=[violation()])
    clean = result(candidate_id=None, payload_sha256=None, benign_success=True)
    mismatches = [
        result(defense="gateway", fixture_sha256="0" * 64),
        result(defense="gateway", candidate_id=str(uuid4())),
        result(defense="gateway", execution_mode="live"),
        result(defense="gateway", payload_sha256="0" * 64),
        result(defense="gateway", candidate_id=None, payload_sha256=None, task_id="another.task"),
    ]
    metrics = calculate_metrics([baseline, clean, *mismatches])
    pairs = metrics["comparison_by_execution_mode"]["fixture"]
    assert pairs["paired_prevention"]["untested"] == 1
    assert pairs["paired_prevention"]["prevented_denominator"] == 0
    assert pairs["paired_prevention"]["prevention_rate"] is None
    assert pairs["matched_clean_regressions"]["untested"] == 1


def test_repeated_matches_are_not_invented_one_to_one_pairs():
    baseline = result(oracle_outcome="success", violations=[violation()])
    guarded = [result(defense="gateway") for _ in range(2)]
    pairs = calculate_metrics([baseline, *guarded])["comparison_by_execution_mode"]["fixture"]["paired_prevention"]
    assert pairs["ambiguous_repeated_matches"] == 1
    assert pairs["prevented_denominator"] == 0
    with pytest.raises(ValueError, match="duplicate"):
        calculate_metrics([baseline, baseline])


def test_clean_coverage_separate_from_attacked_task_success():
    clean = result(candidate_id=None, payload_sha256=None, benign_success=True)
    missing = result(candidate_id=None, payload_sha256=None, benign_success=None, status="timed_out", oracle_outcome="inconclusive")
    attacked = result(benign_success=False)
    group = calculate_metrics([clean, missing, attacked])["groups"]["fixture/baseline"]
    assert group["clean_task_success"] == 1
    assert group["clean_evaluation_coverage"] == 0.5
    assert group["attacked_task_success"] == 0
    assert group["tokens"]["total"]["total"] == 360
    assert group["runtime_ms"]["median"] == 25


def test_frozen_bundle_report_contains_actual_fingerprints_and_evidence():
    bundle = json.loads((EXAMPLES / "replay-bundle.json").read_text())
    report = render_markdown(bundle)
    for fingerprint in bundle["cases"][0]["fingerprints"].values():
        assert fingerprint in report
    assert bundle["cases"][0]["spec"]["model_settings"]["attacker_model_id"] in report
    assert bundle["events"][0]["id"] in report
    assert '"scheduled_progress"' in report


def test_untrusted_metadata_cannot_escape_to_live_markdown():
    attack = "`\n\n![image](https://outside.test/a)\n<script>x</script>\n~~~\n``````"
    report = render_markdown({
        "scenario": {"title": attack, "legitimate_task": attack, "attack_goal": attack},
        "candidate": {"text": attack, "id": attack},
    })
    # Inspect Markdown structure: every raw untrusted markup token must be
    # inside a fence longer than any run of backticks in the payload.
    fence = None
    outside = []
    for line in report.splitlines():
        if fence is None and re.fullmatch(r"`{3,}", line):
            fence = line
        elif fence is not None and line == fence:
            fence = None
        elif fence is None:
            outside.append(line)
    assert fence is None
    assert "![image]" not in "\n".join(outside)
    assert "<script>" not in "\n".join(outside)
    assert attack in report
