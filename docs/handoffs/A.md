# Module A handoff — AgentBreak

## Delivered

Module A now provides a bounded adaptive attacker, pure evaluation metrics,
safe Markdown evidence rendering, and the regression CLI. It uses the frozen
Pydantic contracts in `backend/agentbreak/contracts.py`; it does not add a
second model, target, storage layer, API route, or dependency.

### Changed files

- `backend/agentbreak/attacks/engine.py`
- `backend/agentbreak/attacks/__init__.py`
- `backend/agentbreak/evaluation/metrics.py`
- `backend/agentbreak/evaluation/reports.py`
- `backend/agentbreak/evaluation/__init__.py`
- `backend/agentbreak/cli.py`
- `backend/tests/test_attacks_engine.py`
- `backend/tests/test_metrics_reports.py`
- `backend/tests/test_metrics_cli.py`

## Public interfaces

```python
AttackEngine(model: ModelClient, *, model_settings: ModelSettings)
await AttackEngine.discover(
    scenario: ScenarioSpec,
    budget: Budget,
    seed: int,
    execute_case: ExecuteCase,
    emit: EventSink,
) -> list[CaseResult]

calculate_metrics(results: list[CaseResult]) -> dict[str, JsonValue]
render_markdown(bundle: dict[str, JsonValue]) -> str
python -m agentbreak.cli regress --mode fixture --defense gateway
python -m agentbreak.cli regress --mode live --defense gateway
```

The engine only lets the model propose replacement source text plus a strategy.
Scenario/source/surface are checked against trusted `ScenarioSpec`; candidate
IDs, lineage, hashes, and all trusted fields are assigned locally. It excludes
grants, fixture snapshots, expected predicates, canaries, provider thinking,
Python, executable configuration, and arbitrary URLs from the attacker prompt.
Invalid JSON receives at most one repair call per discovery. Invalid fields,
oversized text, duplicates, token budgets, run deadlines, cancellation, and
provider errors are bounded/propagated rather than converted into attack
failures. Candidate-generated events contain sanitized feedback and persisted
parent-event links.

Metrics keep fixture/live and defense groups separate, expose numerator and
denominator for rates, preserve incomplete cases and verified effects observed
before timeout, distinguish attempts from effects, and only pair exact
scenario/task/candidate/hash/fixture identities. Results alone cannot identify
scheduled-but-unstarted cases; the group therefore exposes `reported_case_count`
and a scheduling note, while D's `RunSummary.progress.scheduled` remains the
source of truth.

Reports preserve exact injected text and actual effects as fenced text, render
metadata as Markdown entities, include event IDs, fingerprints/configuration,
mode labels, comparisons, clean regressions, reproducer instructions,
limitations, and deterministic violation-to-rule suggestions. It creates no
live links or images from payloads and performs no LLM judging or source edits.

The CLI submits a `suite` operation to the operator's AgentBreak server,
defaults to `http://localhost:8000`, polls with per-request and overall
deadlines, validates response contracts, prints the run ID/counts/export URL,
and returns 0 only for a complete 8-clean + 8-held-out suite with no verified
effects or clean failures. It returns 1 for verified security/benign failures
and 2 for setup, transport, malformed, or inconclusive evaluation. Live mode
checks server health and never falls back to fixture mode. Tokens are sent only
as an Authorization header and are never printed.

## Checks actually run

Using a temporary, uncommitted virtual environment at
`/var/folders/b1/jqg6kkdx1ns14rd0szgmr8lh0000gn/T/omnirush/agentbreak-venv`:

```text
python -m pytest -q
156 passed, 1 warning in 0.27s

python -m pytest tests/test_attacks_engine.py tests/test_metrics_reports.py tests/test_metrics_cli.py -q
49 passed in 0.13s

git diff --check
python -m compileall -q agentbreak tests
```

The warning is an upstream Starlette deprecation warning about its TestClient
and `httpx`; no test failed. The documented live CLI command was also invoked
against the default URL. No AgentBreak server was running, so it correctly
returned exit 2 with a sanitized transport error; this is not live evaluation.

## Integration dependencies / remaining gaps

- D must supply the `execute_case` closure that allocates a fresh `CaseSpec`,
  calls B, persists the candidate/snapshot/result, and returns a contract-valid
  `CaseResult`. It must preserve a verified effect if a later timeout occurs.
- D's event sink must persist IDs, sequences, timestamps, and parent validation;
  the engine emits only `EventDraft`.
- B/D must provide the actual fixture and live suite API. The CLI intentionally
  does not fabricate local suite results or start a server.
- `CaseResult.tool_counts` does not expose forbidden-vs-allowed call-level
  breakdowns, so metrics report total proposed/denied calls and explicitly mark
  forbidden proposal/denial counts unavailable rather than guessing.
- Promptfoo integration was intentionally omitted: the core acceptance path was
  prioritized and no new API surface or dependency was requested from D.
- The repository remains on its pre-existing Python 3.12 contract; the checks
  above used Python 3.11 only because that is the available host interpreter.
  Contract/runtime compatibility should be rerun in the project's supported
  Python 3.12 environment before integration.

No commit or push was performed.
