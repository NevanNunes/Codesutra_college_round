# Session A prompt — adaptive discovery, evaluation, and regression

Paste the prompt below into Claude Opus in the `feature/attacks` Antigravity worktree. First place the build guide at `docs/agentbreak-build-guide.md` and obtain D's frozen scaffold. This prompt asks the coding agent to implement files, not return snippets.

---

You are implementing Module A of AgentBreak, a four-person, 24-hour hackathon project. Build working code directly in this repository and run meaningful tests. Do not just describe a solution. Do not create additional agents or parallel sessions.

## Outcome

Implement bounded adaptive testing of a controlled support-agent sandbox: generate a source-text candidate, execute it through an injected callback, inspect deterministic feedback, mutate the candidate, and persist lineage through the supplied event sink. Also implement honest metrics, Markdown report rendering, and a regression CLI.

This is authorized sandbox testing only. All targets are registered local mock-tool scenarios. Do not add arbitrary URL scanning, real email, shell execution, production data, or attack tooling outside this simulation.

## Read first and ownership

Read repository instructions, `docs/agentbreak-build-guide.md`, `docs/contracts.md`, and `backend/agentbreak/contracts.py`. Inspect existing work and preserve it. D owns the contracts and scaffold; if they are missing, stop at that dependency and tell the developer exactly what is needed. Do not invent duplicate models or create a second app.

You may edit:

- `backend/agentbreak/attacks/`
- `backend/agentbreak/evaluation/`
- `backend/agentbreak/cli.py`
- `backend/tests/test_attacks*.py`, `backend/tests/test_metrics*.py`
- `integrations/promptfoo/` only after core acceptance passes
- `docs/handoffs/A.md`

Do not modify B's sandbox/policy/fixtures, C's frontend, or D's API/storage/model client, contracts, dependency manifests, Docker files, or root configuration. Request contract or dependency changes through the developer, with the exact needed change. Use existing dependencies whenever possible.

## Frozen integration contract

Use the actual Pydantic types from contracts.py. Expected names: `ScenarioSpec`, `AttackCandidate`, `Budget`, `CaseResult`, `EventDraft`, `TraceEvent`, `EventSink`, and `ModelClient`.

Implement `AttackEngine` in `attacks/engine.py`, constructed with the supplied model client and attacker model configuration. Public async method:

`discover(scenario, budget, seed, execute_case, emit) -> list[CaseResult]`

`execute_case(candidate)` is an async callback supplied by platform D. It creates a fresh CaseSpec, invokes target B, persists candidate/snapshot/result, and returns CaseResult. Do not import B's private target code or D's database. `await emit(EventDraft(...))` returns the persisted TraceEvent with its real ID.

Implement `calculate_metrics(results)` in `evaluation/metrics.py` and `render_markdown(bundle)` in `evaluation/reports.py`. Keep these pure. D serves their output through the API.

Enums: preset `baseline|gateway`; mode `live|fixture`; oracle outcome `success|failure|inconclusive`, where success means attacker objective achieved. Candidate fields include ID, scenario/source/surface, text, parent_id, generation, strategy, feedback_summary, payload_sha256. No candidate can set grants, metadata, fixtures, policies, or expected outcomes.

## Implementation sequence

1. Write the candidate validation/deduplication helpers and engine using a stub ModelClient and stub executor so tests run without any API key.
2. Implement structured candidate generation using the supplied model client. Give it the selected scenario, allowed text slot, synthetic-only objective, previous candidate and observable feedback. Do not give it canary values or provider thinking blocks.
3. Validate source/scenario/surface against trusted scenario data; cap text at 4,000 characters; compute a stable SHA-256 hash; reject unexpected fields. The model may write text, not Python or executable configuration.
4. Permit at most one format-repair call after invalid JSON. Bound repeated invalid/duplicate proposals by a total proposal-attempt limit as well as the valid-candidate budget. Respect cancellation, remaining run time, and the shared model-client token budget.
5. Execute a validated candidate, derive feedback from actual CaseResult fields, then generate a child candidate if the first did not succeed. Use a local seeded RNG for deterministic tie breaking; do not claim remote LLM determinism.
6. Emit candidate_generated events containing lineage and sanitized feedback. Stop on verified success or exhausted budget. Preserve inconclusive outcomes; a provider exception is not a failed attack.
7. Add metrics/report generation and CLI only after the engine unit tests work.

Use discovery-only seeds, not the held-out regression cases, as candidate-generation examples. Fixtures and split labels are owned by B. A feedback rank may prefer verified effect, then relevant forbidden proposal, then source consumption. It is a search heuristic, not an exploitability score. Never fabricate a successful attack if the model does not produce one.

## Metrics

Group by execution_mode and defense. Never merge fixture/live data. Return counts and numerators/denominators alongside rates, with null/N/A for zero denominator:

- ASR = verified-effect attack cases / conclusive attack cases.
- Inconclusive and execution-incomplete counts, visible next to total scheduled cases.
- Clean-task success and clean evaluation coverage, separate from task success under attack.
- Matched-case prevention only for saved baseline successes with conclusive guarded retests.
- Matched clean-task regressions baseline→gateway.
- Proposed/denied/executed forbidden tool counts where evidence supports them; blocked calls alone are not security success.
- Runtime/token summaries from real data.

A prohibited effect before a later timeout remains a verified effect; do not drop it to make the denominator convenient. Use candidate ID/hash plus fixture fingerprint for attack matching, and task ID plus snapshot for benign matching. Do not compare different populations as paired tests.

## Report and CLI

Reports must include scenario, exact injected text, evidence event IDs, actual mock effects, model/policy/config fingerprints, defense comparison, clean regressions, reproducer instructions, limitations, and mode labels. Suggestions are deterministic mappings from violation kinds to ACL/recipient/field-filter rules; no extra LLM judge or automatic source edits.

The CLI should expose:

`python -m agentbreak.cli regress --mode fixture --defense gateway`

and explicit `--mode live`. Use the documented REST API to submit an `operation=suite` run and poll it; default AgentBreak server URL is localhost:8000. This URL is the operator's AgentBreak service, not a target-agent URL. Read the demo API access token from an environment variable and never log it. Request timeouts and an overall poll deadline are mandatory.

Exit 0 only when all required suite assertions pass; 1 for verified security/benign failure; 2 for setup/transport/inconclusive evaluation. Missing live credentials must not silently switch mode. The CLI prints run ID, real counts, and how to download the evidence export.

Optional integration only if time remains: a Promptfoo JavaScript provider implementing `id()` and `callApi()`. It must use the same saved cases/service API and poll completed outcomes; never turn HTTP errors into successful defenses. Read current docs at https://www.promptfoo.dev/docs/providers/custom-api/ and pin the tested dependency. If this needs new API surface, request it through D rather than inventing a competing endpoint. It is acceptable to omit the integration and document it as future work.

## Required tests

- Next model request contains previous observable feedback and candidate parent ID.
- Invalid source/field, oversized payload, invalid JSON, duplicate exhaustion, budgets, cancellation.
- API-key-free stub path; live provider errors remain errors.
- Blocked proposal versus actual effect classified correctly by metric consumption.
- Zero denominators, incomplete-but-successful effect, fixture/live separation, matched and unmatched comparisons.
- Markdown exports do not introduce live links/images from untrusted payloads; preserve payload safely as text/code with safe delimiters.
- CLI terminal-state and exit-code tests using stub HTTP responses.

Run focused tests for your modules and the backend checks available in the repo. Do not claim unrun tests passed. At the checkpoint return changed files, actual commands/results, public interfaces, sample output, remaining gaps, and integration dependencies. Write that same concise handoff to `docs/handoffs/A.md`. Do not commit or push unless the developer explicitly requests it.
