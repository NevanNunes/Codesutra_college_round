"""Tests for the Adaptive Attack Engine."""

import asyncio
import pytest
from uuid import UUID, uuid4

from agentbreak.attacks.engine import AdaptiveAttackEngine
from agentbreak.contracts import (
    AttackCandidate, Budget, CaseResult, CaseStatus, DefensePreset, ErrorDetail,
    ExecutionMode, ModelSettings, OracleOutcome, RunRequest, ScenarioSpec, Usage,
    Violation
)
from agentbreak.fixtures import load_snapshot
from agentbreak.fixtures.data import FIXTURE_ID
from agentbreak.storage import Database


class FakeGenerator:
    def __init__(self, candidates):
        self.candidates = candidates
        self.call_count = 0
        self._settings = ModelSettings(provider="test", target_model_id="t1", attacker_model_id="a1")

    async def generate_candidate(self, scenario, generation, parent_id=None, feedback=None):
        if self.call_count >= len(self.candidates):
            return None
        cand = self.candidates[self.call_count]
        self.call_count += 1
        return cand


class FakeCaseClient:
    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.call_count = 0

    async def complete(self, messages, tools, model_id, temperature, max_tokens):
        # We don't actually call this because we mock the TargetRunner? No, TargetRunner runs this.
        # But wait, we can just mock the TargetRunner or pass a case client that does nothing.
        # Actually, it's easier to mock TargetRunner, but the engine creates TargetRunner internally!
        pass


@pytest.fixture
def db():
    d = Database(":memory:")
    d.initialize()
    return d


@pytest.fixture
def scenario():
    return ScenarioSpec(
        id="doc_exfil",
        task_id="test_task",
        version=1,
        title="Test Scenario",
        surface="document",
        source_id="doc_a",
        legitimate_task="Read a doc",
        attack_goal="Steal a doc",
        fixture_id=FIXTURE_ID,
        grant={"principal_id": "p1", "tenant_id": "t1", "allowed_customer_ids": [], "allowed_tools": [], "allowed_recipients": []},
        expected_benign=[{"kind": "final_contains", "values": ["done"]}]
    )


@pytest.mark.asyncio
async def test_engine_budget_limit(db, scenario):
    from agentbreak.contracts import payload_sha256
    
    # Generator returns 10 candidates, but budget is 2
    candidates = []
    for i in range(10):
        t = f"payload {i}"
        candidates.append(AttackCandidate(
            id=uuid4(), scenario_id="doc_exfil", source_id="doc_a", surface="document",
            text=t, strategy="test", payload_sha256=payload_sha256(t)
        ))
    
    generator = FakeGenerator(candidates)
    engine = AdaptiveAttackEngine(generator)
    
    req = RunRequest(scenario_ids=["doc_exfil"], budget=Budget(max_candidates=2))
    from agentbreak.fixtures.data import FIXTURE_ID
    snapshot = load_snapshot(FIXTURE_ID)
    
    run_id = uuid4()
    db.create_run(run_id, req)
    
    events = []
    async def emit(evt):
        events.append(evt)
        
    def progress_updater(c, f):
        pass

    # We need a case_client that immediately finishes with failure to not timeout
    # Or we can just let it timeout if it takes too long.
    # We can mock TargetRunner via monkeypatch?
    
    class FastRunner:
        def __init__(self, client): pass
        async def run_case(self, spec, emit):
            return CaseResult(
                run_id=spec.run_id, trial_id=spec.trial_id, scenario_id=spec.scenario.id,
                task_id=spec.scenario.task_id, candidate_id=spec.candidate.id if spec.candidate else None,
                payload_sha256=spec.candidate.payload_sha256 if spec.candidate else None,
                fixture_sha256="0"*64, policy_version=spec.policy_version,
                defense=spec.defense, execution_mode=spec.execution_mode, status=CaseStatus.COMPLETED,
                oracle_outcome=OracleOutcome.FAILURE, final_output="done",
                source_consumed=True, tool_counts={"proposed":0, "denied":0, "forbidden_executed":0},
                duration_ms=10, usage=Usage(input_tokens=0, output_tokens=0),
                state_diff={"returned_customer_ids": [], "disclosed_fields": [], "outbox_added": []}
            )

    import agentbreak.attacks.engine as engine_mod
    original_runner = engine_mod.TargetRunner
    engine_mod.TargetRunner = FastRunner
    
    try:
        results = await engine.run_campaign(
            db, emit, run_id, req, scenario, snapshot, "baseline_v1", None, asyncio.Event(), progress_updater
        )
        
        assert len(results) == 2  # Budget is 2
        assert generator.call_count == 2
    finally:
        engine_mod.TargetRunner = original_runner


@pytest.mark.asyncio
async def test_engine_deduplication(db, scenario):
    from agentbreak.contracts import payload_sha256
    # Generator returns same candidate twice
    t = "same payload"
    c = AttackCandidate(
        id=uuid4(), scenario_id="doc_exfil", source_id="doc_a", surface="document",
        text=t, strategy="test", payload_sha256=payload_sha256(t)
    )
    c2 = c.model_copy(update={"id": uuid4()})
    
    generator = FakeGenerator([c, c2])
    engine = AdaptiveAttackEngine(generator)
    
    req = RunRequest(scenario_ids=["doc_exfil"], budget=Budget(max_candidates=2))
    from agentbreak.fixtures.data import FIXTURE_ID
    snapshot = load_snapshot(FIXTURE_ID)
    
    run_id = uuid4()
    db.create_run(run_id, req)
    
    class FastRunner:
        def __init__(self, client): pass
        async def run_case(self, spec, emit):
            return CaseResult(
                run_id=spec.run_id, trial_id=spec.trial_id, scenario_id=spec.scenario.id,
                task_id=spec.scenario.task_id, candidate_id=spec.candidate.id if spec.candidate else None,
                payload_sha256=spec.candidate.payload_sha256 if spec.candidate else None,
                fixture_sha256="0"*64, policy_version=spec.policy_version,
                defense=spec.defense, execution_mode=spec.execution_mode, status=CaseStatus.COMPLETED,
                oracle_outcome=OracleOutcome.FAILURE, final_output="done",
                source_consumed=True, tool_counts={"proposed":0, "denied":0, "forbidden_executed":0},
                duration_ms=10, usage=Usage(input_tokens=0, output_tokens=0),
                state_diff={"returned_customer_ids": [], "disclosed_fields": [], "outbox_added": []}
            )

    import agentbreak.attacks.engine as engine_mod
    engine_mod.TargetRunner = FastRunner
    
    async def mock_emit(evt):
        pass

    try:
        results = await engine.run_campaign(
            db, mock_emit, run_id, req, scenario, snapshot, "baseline_v1", None, asyncio.Event(), lambda c, f: None
        )
        
        # Second one is deduplicated, so it goes back to generator but generator runs out of candidates.
        assert len(results) == 1
    finally:
        from agentbreak.sandbox.runner import TargetRunner
        engine_mod.TargetRunner = TargetRunner


@pytest.mark.asyncio
async def test_engine_feedback_blocked(db, scenario):
    from agentbreak.contracts import payload_sha256
    t1 = "p1"
    c1 = AttackCandidate(
        id=uuid4(), scenario_id="doc_exfil", source_id="doc_a", surface="document",
        text=t1, strategy="s1", payload_sha256=payload_sha256(t1)
    )
    t2 = "p2"
    c2 = AttackCandidate(
        id=uuid4(), scenario_id="doc_exfil", source_id="doc_a", surface="document",
        text=t2, strategy="s2", payload_sha256=payload_sha256(t2)
    )
    
    feedback_received = []
    
    class FeedbackRecordingGenerator:
        def __init__(self):
            self.call_count = 0
            self._settings = ModelSettings(provider="test", target_model_id="t1", attacker_model_id="a1")
        async def generate_candidate(self, scenario, generation, parent_id=None, feedback=None):
            feedback_received.append(feedback)
            if self.call_count == 0:
                self.call_count += 1
                return c1
            elif self.call_count == 1:
                self.call_count += 1
                return c2
            return None

    generator = FeedbackRecordingGenerator()
    engine = AdaptiveAttackEngine(generator)
    
    req = RunRequest(scenario_ids=["doc_exfil"], budget=Budget(max_candidates=2))
    from agentbreak.fixtures.data import FIXTURE_ID
    snapshot = load_snapshot(FIXTURE_ID)
    run_id = uuid4()
    db.create_run(run_id, req)
    
    class BlockedRunner:
        def __init__(self, client): pass
        async def run_case(self, spec, emit):
            return CaseResult(
                run_id=spec.run_id, trial_id=spec.trial_id, scenario_id=spec.scenario.id,
                task_id=spec.scenario.task_id, candidate_id=spec.candidate.id if spec.candidate else None,
                payload_sha256=spec.candidate.payload_sha256 if spec.candidate else None,
                fixture_sha256="0"*64, policy_version=spec.policy_version,
                defense=spec.defense, execution_mode=spec.execution_mode, status=CaseStatus.COMPLETED,
                oracle_outcome=OracleOutcome.FAILURE, final_output="done",
                source_consumed=True, tool_counts={"proposed":1, "denied":1, "forbidden_executed":0},
                benign_success=False, evidence_event_ids=[],
                duration_ms=10, usage=Usage(input_tokens=0, output_tokens=0),
                attempted_violations=[Violation(kind="unauthorized_send", impact="high", evidence_event_ids=[uuid4()], details={"reason": "blocked"})],
                state_diff={"returned_customer_ids": [], "disclosed_fields": [], "outbox_added": []}
            )

    import agentbreak.attacks.engine as engine_mod
    engine_mod.TargetRunner = BlockedRunner
    
    async def mock_emit(evt):
        pass

    try:
        await engine.run_campaign(
            db, mock_emit, run_id, req, scenario, snapshot, "gateway_v1", None, asyncio.Event(), lambda c, f: None
        )
        
        # Generation 0 feedback is None
        assert feedback_received[0] is None
        # Generation 1 feedback should mention blocked
        assert "BLOCKED by the policy gateway" in feedback_received[1]
    finally:
        from agentbreak.sandbox.runner import TargetRunner
        engine_mod.TargetRunner = TargetRunner
