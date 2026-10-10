import asyncio
import copy
from typing import Literal, Any
from uuid import UUID, uuid4

from agentbreak.contracts import (
    AttackCandidate, AttackSeed, BenignCase, Budget, CaseResult, CaseSpec,
    DefensePreset, ExecutionMode, ModelSettings, RunRequest
)
from agentbreak.sandbox.runner import TargetRunner
from agentbreak.storage.database import Database
from agentbreak.fixtures import (
    list_benign_cases, list_attack_seeds, list_scenarios, load_snapshot
)
from agentbreak.main import (
    _DbEventSink, _get_case_client, _make_error_result, _make_timeout_result
)


class DummyApp:
    """Mock ASGI app to pass to _get_case_client if needed."""
    class State:
        pass
    def __init__(self, model_client):
        self.state = self.State()
        self.state.model_client = model_client


class EvaluationHarness:
    """Reliable evaluation runner for executing suites against target profiles."""

    def __init__(self, db: Database, model_client: Any = None) -> None:
        self.db = db
        self.model_client = model_client
        self._app = DummyApp(model_client)

    def load_suite(self, suite_name: Literal["benign", "discovery", "held_out"]) -> list[BenignCase | AttackSeed]:
        """Load and validate a complete suite."""
        if suite_name == "benign":
            cases = list_benign_cases()
        elif suite_name == "discovery":
            cases = list_attack_seeds("discovery")
        elif suite_name == "held_out":
            cases = list_attack_seeds("held_out")
        else:
            raise ValueError(f"Unknown or missing suite: {suite_name}")
        
        if not cases:
            raise ValueError(f"Suite {suite_name} is unexpectedly empty.")
        
        return cases

    async def run_cases(
        self,
        run_id: UUID,
        req: RunRequest,
        cases: list[BenignCase | AttackSeed],
        profiles: list[DefensePreset],
        cancel_event: asyncio.Event | None = None,
    ) -> list[CaseResult]:
        """Execute the loaded cases against the specified defense profiles."""
        if cancel_event is None:
            cancel_event = asyncio.Event()

        all_results = []
        emit = _DbEventSink(self.db, run_id)
        scenarios = {s.id: s for s in list_scenarios()}

        for profile in profiles:
            req_copy = req.model_copy()
            req_copy.defense = profile
            policy_version = "gateway_v1" if profile == DefensePreset.GATEWAY else "baseline_v1"

            for case_item in cases:
                if cancel_event.is_set():
                    break

                trial_id = uuid4()
                if isinstance(case_item, BenignCase):
                    snapshot = copy.deepcopy(case_item.fixture_snapshot)
                    candidate = None
                    scenario = case_item.scenario
                else:  # AttackSeed
                    candidate = case_item.candidate
                    scenario = scenarios[candidate.scenario_id]
                    snapshot = load_snapshot(scenario.fixture_id)
                    # Inject candidate
                    for doc in snapshot.documents:
                        if doc.id == scenario.source_id:
                            doc.body = candidate.text

                spec = CaseSpec(
                    run_id=run_id, trial_id=trial_id, scenario=scenario,
                    candidate=candidate, defense=profile, execution_mode=req.execution_mode,
                    fixture_snapshot=snapshot, budget=req.budget, seed=req.seed,
                    model_settings=ModelSettings(
                        provider="anthropic", target_model_id="claude", attacker_model_id="claude",
                        temperature=0.0, max_tokens=1024
                    ),
                    policy_version=policy_version,
                )
                
                self.db.save_case_spec(run_id, spec)
                if candidate:
                    self.db.save_candidate(run_id, candidate.model_dump_json(), str(candidate.id))

                case_client = _get_case_client(self._app, req_copy, spec)
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
                except Exception as exc:  # noqa: BLE001
                    result = _make_error_result(spec, exc)

                self.db.save_case_result(run_id, result)
                all_results.append(result)

        return all_results
