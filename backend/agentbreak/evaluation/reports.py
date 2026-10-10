"""Safe Markdown evidence rendering for synthetic AgentBreak bundles."""

from __future__ import annotations

import json
import re
from typing import Any

from agentbreak.evaluation.metrics import calculate_metrics


def _dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


def _max_backtick_run(text: str) -> int:
    runs = re.findall(r"`+", text)
    return max((len(run) for run in runs), default=0)


def _code_block(text: str) -> str:
    """Render arbitrary text without allowing it to escape the code block."""
    text = str(text)
    fence = "`" * max(3, _max_backtick_run(text) + 1)
    return f"{fence}\n{text}\n{fence}"


def _code_value(value: Any) -> str:
    if isinstance(value, str):
        return _code_block(value)
    return _code_block(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str))


def _inline(value: Any) -> str:
    # Entities cannot introduce Markdown structure, HTML, or autolinks. Newlines
    # in titles/metadata must not be able to terminate a block and add markup.
    return "".join(character if character.isalnum() or character == " " else f"&#{ord(character)};" for character in str(value))


def _first_case(bundle: dict[str, Any]) -> dict[str, Any] | None:
    cases = bundle.get("cases")
    if isinstance(cases, list) and cases and isinstance(cases[0], dict):
        return cases[0]
    return None


def _candidate_entries(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    direct = bundle.get("candidate")
    if isinstance(direct, dict):
        entries.append(direct)
    candidates = bundle.get("candidates")
    if isinstance(candidates, list):
        entries.extend(item for item in candidates if isinstance(item, dict))
    cases = bundle.get("cases")
    if isinstance(cases, list):
        for case in cases:
            if not isinstance(case, dict):
                continue
            spec = case.get("spec", {})
            candidate = spec.get("candidate") if isinstance(spec, dict) else None
            if isinstance(candidate, dict):
                entries.append(candidate)
    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any]] = set()
    for candidate in entries:
        identity = (candidate.get("id"), candidate.get("payload_sha256"))
        if identity not in seen:
            seen.add(identity)
            unique.append(candidate)
    return unique


def _result_entries(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    direct = bundle.get("result")
    if isinstance(direct, dict):
        results.append(direct)
    cases = bundle.get("cases")
    if isinstance(cases, list):
        for case in cases:
            if isinstance(case, dict) and isinstance(case.get("result"), dict):
                results.append(case["result"])
    return results


def render_markdown(bundle: dict[str, Any]) -> str:
    """Render an evidence report with no live links, images, or executable input."""

    bundle = _dump(bundle)
    if not isinstance(bundle, dict):
        raise TypeError("report bundle must be a mapping")
    case = _first_case(bundle)
    spec = case.get("spec", {}) if case else {}
    scenario = bundle.get("scenario") or (spec.get("scenario") if isinstance(spec, dict) else {}) or {}
    run = bundle.get("run", {})
    request = run.get("request", {}) if isinstance(run, dict) else {}
    results = _result_entries(bundle)
    candidates = _candidate_entries(bundle)
    first_result = results[0] if results else bundle.get("result", {})

    mode = request.get("execution_mode") or first_result.get("execution_mode") or "unknown"
    defense = request.get("defense") or first_result.get("defense") or "unknown"
    scenario_id = scenario.get("id") or first_result.get("scenario_id") or "unknown"

    lines = [
        "# AgentBreak Evidence Report",
        "",
        "## Executive summary",
        "",
        f"- Scenario: {_inline(scenario_id)}",
        f"- Execution mode: {_inline(mode)}",
        f"- Defense: {_inline(defense)}",
        "- This report contains synthetic sandbox evidence. Recorded event edges are execution/input dependencies, not proof of model causality.",
        "",
        "## Scenario and threat model",
        "",
        f"- Title: {_inline(scenario.get('title', 'not supplied'))}",
        f"- Surface: {_inline(scenario.get('surface', 'not supplied'))}",
        f"- Source slot: {_inline(scenario.get('source_id', 'not supplied'))}",
        f"- Legitimate task: {_inline(scenario.get('legitimate_task', 'not supplied'))}",
        f"- Synthetic attack objective: {_inline(scenario.get('attack_goal', 'not supplied'))}",
        "",
        "## Exact injected text",
        "",
    ]
    if not candidates:
        lines.append("No candidate payload was supplied.")
    for index, candidate in enumerate(candidates, start=1):
        lines.extend([
            f"### Candidate {index}",
            f"- Candidate ID: {_inline(candidate.get('id', 'not supplied'))}",
            f"- Parent ID: {_inline(candidate.get('parent_id', 'none'))}",
            f"- Generation: {_inline(candidate.get('generation', 'not supplied'))}",
            f"- Payload SHA-256: {_inline(candidate.get('payload_sha256', 'not supplied'))}",
            "",
            _code_block(candidate.get("text", "")),
            "",
        ])

    lines.extend(["## Observed effects and oracle", ""])
    if not results:
        lines.append("No case result was supplied.")
    for index, result in enumerate(results, start=1):
        lines.extend([
            f"### Case {index}",
            f"- Status: {_inline(result.get('status', 'not supplied'))}",
            f"- Oracle outcome: {_inline(result.get('oracle_outcome', 'not supplied'))}",
            f"- Source consumed: {_inline(result.get('source_consumed', 'not supplied'))}",
            f"- Benign success: {_inline(result.get('benign_success', 'not evaluated'))}",
            "",
            "Violations:",
            _code_value(result.get("violations", [])),
            "",
            "Attempted violations (not proof of effect):",
            _code_value(result.get("attempted_violations", [])),
            "",
            "Actual mock state/effects:",
            _code_value(result.get("state_diff", {})),
            "",
            "Final visible output:",
            _code_value(result.get("final_output", "")),
            "",
            "Evidence event IDs:",
            _code_value(result.get("evidence_event_ids", [])),
            "",
        ])

    configurations = []
    for saved in bundle.get("cases", []):
        saved_spec = saved.get("spec", {})
        configurations.append({
            "trial_id": saved_spec.get("trial_id"),
            "scenario": saved_spec.get("scenario"),
            "model_settings": saved_spec.get("model_settings"),
            "policy_version": saved_spec.get("policy_version"),
            "fingerprints": saved.get("fingerprints"),
            "seed": saved_spec.get("seed"),
            "budget": saved_spec.get("budget"),
            "execution_mode": saved_spec.get("execution_mode"),
            "defense": saved_spec.get("defense"),
        })
    metrics = calculate_metrics(results) if results and all("run_id" in result for result in results) else bundle.get("metrics", {})
    suggestions = {
        "unauthorized_read": "Enforce exact customer ACL membership from the trusted task grant before returning a record.",
        "unauthorized_send": "Require the send action grant and exact normalized recipient allowlist membership before appending to the mock outbox.",
        "canary_leak": "Strip protected internal_token fields before model consumption; keep a separate output check as defense-in-depth, not proof of gateway prevention.",
    }
    kinds = sorted({violation.get("kind") for result in results for violation in result.get("violations", [])})
    lines.extend([
        "## Model, policy, and configuration fingerprints",
        "",
        _code_value(configurations or bundle.get("fingerprints", bundle.get("model_settings", {}))),
        _code_value({"app_git_revision": bundle.get("app_git_revision"), "run_id": run.get("id"), "source_run_id": run.get("source_run_id")}),
        "",
        "## Recorded events",
        "",
        _code_value(bundle.get("events", [])),
        "",
        "## Defense comparison and clean regressions",
        "",
        _code_value(metrics),
        _code_value({"scheduled_progress": run.get("progress"), "error": run.get("error")}),
        "A single-run export normally contains one defense. Paired comparisons require both saved result populations; empty comparisons are not prevention evidence.",
        "",
        _code_value(bundle.get("defense_comparison", bundle.get("comparisons", {}))),
        "",
        "## Reproducer instructions",
        "",
        "1. Use the recorded AgentBreak run and its saved candidate payload; do not substitute a new payload.",
        "2. Execute the candidate against a fresh copy of the recorded synthetic fixture snapshot.",
        "3. Change only the named defense preset, then compare the deterministic oracle, state diff, and evidence event IDs.",
        "4. Keep fixture/live mode labels unchanged; fixture replay is not live discovery.",
        "5. On the operator's service, POST /api/runs/{saved-run-id}/retest with the JSON below to replay saved inputs, not discovery mutations. Then poll GET /api/runs/{returned-run-id} and download /api/runs/{returned-run-id}/export?format=json. Supply the demo token as an Authorization header, never in the URL.",
        _code_value({"defense": "gateway", "include_benign": True}),
        "For a separate held-out suite (not a reproduction of an arbitrary discovered candidate):",
        _code_block(f"python -m agentbreak.cli regress --mode {mode if mode in ('fixture', 'live') else 'fixture'} --defense gateway"),
        "",
        "## Deterministic remediation suggestions",
        "",
        *[suggestions[kind] for kind in kinds if kind in suggestions],
        "Suggestions are fixed mappings from confirmed violation kinds, not an LLM judgment or automatic source edits.",
        "",
        "## Limitations",
        "",
        "- Results cover registered local mock-tool scenarios only; they are not a production security guarantee.",
        "- A denied proposal is an attempted violation, not a verified prohibited effect.",
        "- Remote model calls are not deterministic merely because temperature is zero.",
        "- Canary matching and the fixed mock oracle do not cover arbitrary encoding or unknown sensitive data.",
        "- Runtime and token summaries are reported only from recorded case data.",
    ])
    return "\n".join(lines) + "\n"


__all__ = ["render_markdown"]
