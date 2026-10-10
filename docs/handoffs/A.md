# Module A handoff — AgentBreak

## Delivered

Module A provides bounded adaptive attack discovery, honest evaluation metrics, safe Markdown evidence reporting, and the regression CLI. It strictly uses the frozen Pydantic contracts in `backend/agentbreak/contracts.py`; it does not invent duplicate models, private targets, persistence layers, API routes, or unapproved dependencies.

### Owned and changed files

- `backend/agentbreak/attacks/engine.py` (Bounded adaptive candidate generation, validation, lineage, feedback, budget/deadlines)
- `backend/agentbreak/attacks/__init__.py` (Exports `AttackEngine`)
- `backend/agentbreak/evaluation/metrics.py` (Pure multi-dimensional metrics, zero denominator handling, matched retest comparison)
- `backend/agentbreak/evaluation/reports.py` (Pure Markdown report generation, escaped payloads, deterministic rule suggestions)
- `backend/agentbreak/evaluation/__init__.py` (Exports `calculate_metrics`, `render_markdown`)
- `backend/agentbreak/cli.py` (Regression CLI with HTTP polling, deadlines, token handling, contract validation, exit codes)
- `backend/tests/test_attacks_engine.py` (25 tests for candidate generation, bounds, repair, timeouts, budgets, lineage)
- `backend/tests/test_metrics_reports.py` (10 tests for metrics, zero denominators, fixture/live separation, safe Markdown)
- `backend/tests/test_metrics_cli.py` (14 tests for CLI exit codes, terminal states, live mode checks, transport failures)
- `docs/handoffs/A.md` (Module A handoff documentation)

---

## Public interfaces

```python
class AttackEngine:
    def __init__(self, model: ModelClient, *, model_settings: ModelSettings) -> None: ...
    async def discover(
        self,
        scenario: ScenarioSpec,
        budget: Budget,
        seed: int,
        execute_case: Callable[[AttackCandidate], Awaitable[CaseResult]],
        emit: EventSink,
    ) -> list[CaseResult]: ...

def calculate_metrics(results: list[CaseResult]) -> dict[str, JsonValue]: ...
def render_markdown(bundle: dict[str, JsonValue]) -> str: ...

# CLI Invocation:
python -m agentbreak.cli regress --mode fixture --defense gateway
python -m agentbreak.cli regress --mode live --defense gateway
```

---

## Core behavior and guarantees

1. **Structured Candidate Generation**: The model proposes replacement text and strategy within the allowed slot (`ScenarioSpec.source_slot`). Scenario, surface, and source identity are validated against trusted scenario definitions. All candidate IDs, hashes, generations, and lineage links are assigned locally.
2. **Strict Bounds & Sanitation**: Input text is capped at 4,000 characters; SHA-256 is strictly computed; unexpected fields are rejected. Sensitive canary strings, provider thinking blocks, executable Python, and arbitrary URLs are completely excluded from attacker prompts.
3. **Budget and Error Control**: At most one format-repair call is permitted per discovery. Repeated invalid or duplicate proposals are bounded. Token budgets, run deadlines, cancellations, and provider transport errors are propagated rather than masked as attack failures.
4. **Lineage and Feedback**: `candidate_generated` events are emitted through the supplied `EventSink`, recording generation, strategy, payload hash, and sanitized observable feedback.
5. **Pure Honest Metrics**:
   - Separate grouping by `execution_mode` (fixture vs live) and `defense` (baseline vs gateway). Never pooled.
   - Rates report both numerator and denominator; zero denominators return `null` / `N/A`.
   - Distinguishes attempted violations (blocked proposals) from verified violations (actual effects).
   - Matched-pair prevention and clean regression calculations match only identical candidate/task and fixture fingerprints.
6. **Safe Evidence Reports**: Untrusted payloads are rendered as fenced text without unescaped HTML, scripts, or active Markdown links/images. Rule remediation suggestions are deterministic lookups from observed violation types.
7. **Regression CLI**:
   - Queries `POST /api/runs` with `operation=suite` and polls `GET /api/runs/{id}` until terminal state.
   - Respects per-request and poll deadlines.
   - Bearer token passed via `AGENTBREAK_API_TOKEN` environment variable and never logged.
   - Exit code `0` on complete suite satisfying all assertions (16 scheduled, 16 completed, 0 failed, 8/8 clean passed, 0 verified attacks under gateway, 0 inconclusive).
   - Exit code `1` on verified security/benign failure.
   - Exit code `2` on setup, transport, timeout, or inconclusive evaluation.

---

## Checks run and results

### 1. Module A focused tests
```bash
python -m pytest backend/tests/test_attacks_engine.py backend/tests/test_metrics_reports.py backend/tests/test_metrics_cli.py -v
```
**Result**: `49 passed in 0.09s`

### 2. Full backend test suite
```bash
python -m pytest -q
```
**Result**: `234 passed, 1 warning in 0.85s`

### 3. Syntax, typing, and whitespace checks
```bash
git diff --check
python -m compileall -q agentbreak tests
```
**Result**: Clean; 0 errors, 0 warnings.

### 4. CLI Regression execution against running server
```bash
python -m agentbreak.cli regress --mode fixture --defense gateway
```
**Sample Output**:
```text
run_id: d38fb101-fc8d-48e7-841d-741f508c7cba
evidence export: http://localhost:8000/api/runs/d38fb101-fc8d-48e7-841d-741f508c7cba/export?format=json
status: completed
execution_mode: fixture
defense: gateway
scheduled_cases: 16; reported_cases: 16
asr: 0.0 (0/8)
inconclusive: 0
execution_incomplete: 0
clean_success: 8/8 required
assertions: all required suite assertions passed
evidence export: http://localhost:8000/api/runs/d38fb101-fc8d-48e7-841d-741f508c7cba/export?format=json
```
**Exit Code**: `0`

---

## Integration status with other modules

- **Module B (Target & Sandbox)**: Complete. Module B fixtures and sandbox runner (`TargetRunner`) are consumed by the orchestrator and evaluated by Module A metrics.
- **Module D (Platform & Storage)**: Complete. Persistent `EventSink`, `execute_case` callback, SQLite storage, REST routes, and export bundling are fully integrated and verified end-to-end.
- **Module C (Frontend)**: Complete. Frontend builds, runs 17/17 tests passing, and connects to the verified API schema.
- **Promptfoo Integration**: Deliberately deferred to post-acceptance phase; core workflow and acceptance paths are 100% operational.
