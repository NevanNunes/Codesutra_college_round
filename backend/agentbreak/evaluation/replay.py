from uuid import UUID
from typing import Literal

from pydantic import BaseModel, Field
from agentbreak.contracts import ReplayBundle, ReplayCase, RunRequest, TraceEvent, CaseResult, EventType
from agentbreak.evaluation.scoring import FindingScore


class TraceComparison(BaseModel):
    exact_match: bool
    semantic_match: bool
    orig_tools: list[str]
    replay_tools: list[str]
    orig_oracle: str | None
    replay_oracle: str | None


def compare_traces(orig: list[TraceEvent], replay: list[TraceEvent]) -> TraceComparison:
    """Compare relevant event signatures while handling generated event IDs and timestamps."""
    def extract_signature(events: list[TraceEvent]):
        tools = []
        oracle = None
        for e in events:
            if e.type == EventType.TOOL_EXECUTED:
                tools.append(f"exec:{e.data.get('tool_name')}")
            elif e.type == EventType.TOOL_BLOCKED:
                tools.append(f"block:{e.data.get('tool_name')}")
            elif e.type == EventType.ORACLE_RESULT:
                oracle = e.data.get("outcome")
        return tools, oracle

    orig_tools, orig_oracle = extract_signature(orig)
    replay_tools, replay_oracle = extract_signature(replay)
    
    exact_match = (orig_tools == replay_tools) and (orig_oracle == replay_oracle)
    semantic_match = (set(orig_tools) == set(replay_tools)) and (orig_oracle == replay_oracle)
    
    return TraceComparison(
        exact_match=exact_match,
        semantic_match=semantic_match,
        orig_tools=orig_tools,
        replay_tools=replay_tools,
        orig_oracle=orig_oracle,
        replay_oracle=replay_oracle
    )


class DedupedFinding(BaseModel):
    signature: str
    policy_category: str
    rule_kind: str
    status: Literal["attempted", "executed"]
    traces: list[UUID] = Field(default_factory=list)
    scores: list[FindingScore] = Field(default_factory=list)
    
    
def get_finding_signature(score: FindingScore, trial_id: UUID, events: list[TraceEvent]) -> str:
    """Creates a stable security-relevant feature signature for deduplication."""
    tools = []
    for e in events:
        if e.type in (EventType.TOOL_EXECUTED, EventType.TOOL_BLOCKED):
            tools.append(e.data.get("tool_name", "unknown"))
    tool_str = ",".join(sorted(set(tools)))
    return f"{score.policy_category}:{score.rule_kind}:{score.status}:{tool_str}"


def deduplicate_findings(scores: list[tuple[UUID, FindingScore]], events_by_trial: dict[UUID, list[TraceEvent]]) -> list[DedupedFinding]:
    """Group findings by stable signatures to prevent counting identical attacks repeatedly."""
    groups = {}
    for trial_id, score in scores:
        events = events_by_trial.get(trial_id, [])
        sig = get_finding_signature(score, trial_id, events)
        if sig not in groups:
            groups[sig] = DedupedFinding(
                signature=sig,
                policy_category=score.policy_category,
                rule_kind=score.rule_kind,
                status=score.status,
            )
        groups[sig].traces.append(trial_id)
        groups[sig].scores.append(score)
    return list(groups.values())


class RemediationStatus(BaseModel):
    finding_signature: str
    status: Literal["open", "fix_implemented", "retest_passed", "retest_failed", "inconclusive", "reopened"]
    reproducibility: str


def verify_remediation(orig_findings: list[DedupedFinding], replay_findings: list[DedupedFinding]) -> list[RemediationStatus]:
    """Verify whether a defense resolved the original issue."""
    statuses = []
    replay_sigs = {f.signature for f in replay_findings if f.status == "executed"}
    
    for orig in orig_findings:
        if orig.status != "executed":
            continue
        if orig.signature in replay_sigs:
            status = "retest_failed"
            reproducibility = "1/1 reproduced"
        else:
            # Check if there's any related finding (same rule) that got executed
            related_executed = [f for f in replay_findings if f.rule_kind == orig.rule_kind and f.status == "executed"]
            if related_executed:
                status = "retest_failed"
                reproducibility = "1/1 reproduced (variant)"
            else:
                # Was it blocked?
                related_blocked = [f for f in replay_findings if f.rule_kind == orig.rule_kind and f.status == "attempted"]
                if related_blocked:
                    status = "retest_passed"
                    reproducibility = "0/1 reproduced"
                else:
                    status = "inconclusive"
                    reproducibility = "0/1 reproduced (no attempt)"
                    
        statuses.append(RemediationStatus(
            finding_signature=orig.signature,
            status=status,
            reproducibility=reproducibility
        ))
    return statuses

import asyncio
from agentbreak.evaluation.harness import EvaluationHarness, TargetRunner, _make_timeout_result, _make_error_result, _get_case_client, DummyApp
from agentbreak.main import _DbEventSink
from agentbreak.contracts import DefensePreset, Budget

class ReplayRunner:
    def __init__(self, db, model_client=None):
        self.db = db
        self._app = DummyApp(model_client)
        
    async def run_replay(self, bundle: ReplayBundle, run_id: UUID, target_profile: DefensePreset, budget: Budget | None = None) -> list[CaseResult]:
        """Use the evaluation harness runner to rerun the saved case against a selected sandbox configuration."""
        all_results = []
        emit = _DbEventSink(self.db, run_id)
        
        # We need a dummy req to feed into _get_case_client
        scenario_ids = list({case.spec.scenario.id for case in bundle.cases}) or ["dummy"]
        req = RunRequest(scenario_ids=scenario_ids, operation="discover", defense=target_profile, execution_mode=bundle.run.request.execution_mode, budget=budget or bundle.run.request.budget, seed=bundle.run.request.seed)
        
        for case in bundle.cases:
            # We must use the original spec but possibly different target_profile
            spec = case.spec.model_copy()
            spec.run_id = run_id
            spec.trial_id = case.spec.trial_id
            spec.defense = target_profile
            
            self.db.save_case_spec(run_id, spec)
            if spec.candidate:
                self.db.save_candidate(run_id, spec.candidate.model_dump_json(), str(spec.candidate.id))
                
            case_client = _get_case_client(self._app, req, spec)
            runner = TargetRunner(case_client)
            
            try:
                result = await asyncio.wait_for(
                    runner.run_case(spec, emit),
                    timeout=req.budget.case_timeout_s,
                )
            except (TimeoutError, asyncio.TimeoutError):
                result = _make_timeout_result(spec)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                result = _make_error_result(spec, exc)
                
            self.db.save_case_result(run_id, result)
            all_results.append(result)
            
        return all_results
