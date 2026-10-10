# Module B (Target Sandbox & Oracle) Handoff

## Changed Files
The following files were created or modified by Module B:
- `backend/agentbreak/sandbox/world.py` (Mock tool world and outbox)
- `backend/agentbreak/sandbox/oracle.py` (Independent outcome judge)
- `backend/agentbreak/sandbox/runner.py` (`TargetRunner` implementation)
- `backend/agentbreak/sandbox/__init__.py`
- `backend/agentbreak/policies/gateway.py` (Server-side tool gateway & schema validation)
- `backend/agentbreak/policies/__init__.py`
- `backend/agentbreak/fixtures/data.py` (Raw synthetic scenario/seed/fixture data)
- `backend/agentbreak/fixtures/traces.py` (Static model traces for CI)
- `backend/agentbreak/fixtures/__init__.py`
- `backend/tests/test_sandbox_support.py` (Test utilities)
- `backend/tests/test_sandbox_fixtures.py` (Fixture tests)
- `backend/tests/test_policy_gateway.py` (Gateway policy tests)
- `backend/tests/test_sandbox_runner.py` (TargetRunner simulation tests)
- `backend/tests/test_oracle.py` (Oracle deterministic outcome tests)

## Public Interfaces
**Target Sandbox** (`agentbreak.sandbox`):
- `TargetRunner(model: ModelClient)`
- `async def run_case(self, spec: CaseSpec, emit: EventSink) -> CaseResult`

**Fixtures** (`agentbreak.fixtures`):
- `list_scenarios() -> list[ScenarioSpec]`
- `load_snapshot(fixture_id: str) -> FixtureSnapshot`
- `list_attack_seeds(split: Literal["discovery", "held_out"]) -> list[AttackSeed]`
- `list_benign_cases() -> list[BenignCase]`

## Scenario IDs and Fixtures
- **Canonical Scenario IDs:** `doc_exfil` (Document-driven disclosure) and `email_bola` (Email-driven cross-account access).
- **Fixture IDs:** `support_v1` and `support_v1_noise`.

## Actual Commands and Results
Run tests from the `backend/` directory:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock -r requirements-dev.lock
python -m pytest tests/test_sandbox_fixtures.py tests/test_policy_gateway.py tests/test_sandbox_runner.py tests/test_oracle.py
```
**Results:** `72 passed` (No errors, all tests pass).

## Remaining Integration Requirements
- **Integration with D:** The `TargetRunner.run_case` function must be hooked up to the orchestrator/worker so that it can run end-to-end tasks with proper context.
- **Integration with A:** The `list_scenarios` and `list_attack_seeds` methods should be consumed by A's candidate generator logic.
- **Live Model Testing:** Currently tested with `FixtureModelClient`. Real API calls via D's `ModelClient` are next to verify actual live execution.
- **Deferred:** Persistent-memory attacks are intentionally deferred until the core two-scenario flow is accepted.
