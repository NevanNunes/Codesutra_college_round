# Session D prompt — scaffold, contracts, API, persistence, and integration

Paste the prompt below into Claude Opus in the team's AgentBreak repository first. This session creates the shared scaffold in its first phase, then continues platform work while A/B/C implement their modules in separate worktrees. Place the guide at `docs/agentbreak-build-guide.md` before starting.

---

You are implementing Module D and integration infrastructure for AgentBreak, a four-person, 24-hour hackathon. Implement working files and tests rather than returning snippets. Do not create additional agents or sessions. You are one of four coding sessions, not an agent that should recursively recreate the team.

## Product

AgentBreak is a controlled support-agent security workbench. A produces bounded adaptive document/email attack candidates and metrics; B provides the tool-using target, synthetic fixtures, independent permission gateway and deterministic oracle; C builds the React UI. You own the shared contract, API, model transport, orchestration/persistence, packaging and end-to-end integration.

Read repository instructions and `docs/agentbreak-build-guide.md` first. Preserve existing work. If this is already a working application with a different stack, tell the developer how to adapt rather than replacing it without permission. Otherwise use Python 3.12/FastAPI/Pydantic v2/Uvicorn/SQLite, one async worker, and a React/Vite frontend built separately by C.

## Ownership

You own `backend/agentbreak/contracts.py`, `llm.py`, `main.py`, `api/`, `storage/`, backend packaging/dependency manifests/locks, `backend/tests/test_api*.py`, model-client/contract tests, `tests/e2e/`, root Docker/Compose/ignore/environment/readme files, `docs/contracts.md`, and `docs/handoffs/D.md`.

A owns attacks/, evaluation/, cli.py and optional integrations/promptfoo/. B owns sandbox/, policies/, fixtures/. C owns frontend/. Do not overwrite those modules or change their APIs unilaterally. You may create minimal empty package scaffolding before branches split, but later implementation belongs to the assigned session.

You alone edit shared contracts and backend dependencies. Provide exact change notifications through the developer. Do not implement the entire app yourself while the other sessions are working.

## Phase 1 — contract/scaffold checkpoint, first 60–90 minutes

1. Create the minimal package structure from the guide, `.gitignore` excluding secrets/runtime DB/logs/build outputs, placeholder-only `.env.example`, dependency manifest, pytest config, and a health endpoint.
2. Materialize guide section 7 into Pydantic v2 models with strict enum values, constrained budgets/text sizes, extra-field rejection for command and tool inputs, and JSON-safe serialization. Define public views separately where internal grants/canaries should not be exposed.
3. Include Grant, ScenarioSpec, AttackCandidate, Budget, CaseSpec, PolicyDecision, Violation, CaseResult, EventDraft, TraceEvent, RunRequest, RunSummary, and normalized ModelReply/ToolCall/usage contracts. Use UTC ISO timestamps and server-assigned UUIDs plus monotonic event sequences.
4. Publish async ModelClient and EventSink protocols. Normalize model tool calls and visible text; do not expose SDK-specific response objects to A/B.
5. Publish JSON examples, API request/response schemas, canonical IDs doc_exfil/email_bola, import paths and function signatures in docs/contracts.md. Add contract tests validating those examples.
6. Provide minimal ModelClient stub fixtures for module testing, but do not duplicate B's full target fixture adapter.
7. Notify the developer of the checkpoint and ask them to distribute the scaffold commit to A/B/C. Do not commit without their explicit request. Then continue Phase 2 in your platform branch/worktree.

Do not block the team on complete persistence or model-provider integration before publishing the contract. Conversely, do not let four modules proceed with four incompatible schemas.

## Internal seams to freeze

- `await model.complete(messages, tools, *, model_id, temperature, max_tokens) -> ModelReply`.
- `await emit(EventDraft) -> TraceEvent`, assigning run_id/id/seq/time server-side.
- B: `TargetRunner(model).run_case(CaseSpec, emit) -> CaseResult`.
- B fixtures: list_scenarios(), load_snapshot(fixture_id), list_attack_seeds(split), list_benign_cases(); agree exact typed return values with B.
- A: `AttackEngine(model, ...).discover(scenario, budget, seed, execute_case, emit) -> list[CaseResult]`; execute_case is your async closure accepting a validated candidate.
- A: calculate_metrics(results) -> dict; render_markdown(bundle) -> str.

Use dependency injection to test API/orchestration against stubs. Avoid circular imports: contracts import no modules; A/B depend on contracts; your composition root imports A/B. Constructor details beyond these seams must be documented at freeze.

## Phase 2 — platform

Implement the REST contract from the guide:

GET /api/health, GET /api/scenarios, POST/GET /api/runs, GET /api/runs/{id}, GET /api/runs/{id}/events with after_seq/limit pagination, POST /api/runs/{id}/retest, POST /api/runs/{id}/cancel, GET /api/runs/{id}/export?format=json|markdown.

POST returns 202 quickly with run_id. Validate scenario/preset/mode and budgets; accept no arbitrary tool grants, model endpoint URLs, fixture files, target URLs, or user-supplied executable code. Resolve trusted scenario/grants server-side. API errors have stable code/message and proper status; do not expose tracebacks/secrets. Health can be unauthenticated but reveals only status/schema/live readiness.

Protect non-health API routes in public deployment with a configured demo bearer token; compare safely. It is operator access control, not a complete multi-user identity system. Keys stay server-side. Support same-origin frontend and narrowly scoped development proxy/CORS only. Set bounded body size, rate limits, queue caps and no browser model credentials.

Use SQLite tables runs/candidates/cases/events with JSON payload columns as appropriate. Index (run_id, seq) uniquely. Persist immutable candidate/snapshot/model/policy fingerprints and result state diffs. Use short serialized writes, WAL and no open transaction around network awaits. Persist the run before enqueueing.

Consume one bounded asyncio.Queue in FastAPI lifespan; MAX_ACTIVE_RUNS=1, MAX_QUEUED_RUNS=4. Track cancellation tokens/task handles. On restart mark unfinished runs interrupted; do not silently rerun them. Never launch a second Uvicorn worker with this queue design.

Use a browser-generated Idempotency-Key on mutating run/retest requests if feasible; document a small scoped deduplication contract and persist its mapping. Otherwise clearly document ambiguous request recovery and provide enough run metadata for UI reconciliation. Do not auto-repeat an uncertain run creation.

## Model transport and budgets

Use the official Anthropic Python SDK once, behind ModelClient. Read ANTHROPIC_API_KEY, ATTACKER_MODEL_ID and TARGET_MODEL_ID from server environment; do not invent model IDs. Opus used by Antigravity is not automatically a runtime credential. If credentials/model choices are missing, keep fixture mode usable and report live_ready=false.

Normalize multi-turn messages and tool-use/tool-result sequences correctly. Preserve tool call IDs. Exclude provider thinking blocks from logs/events/exports. Handle provider refusals, truncated output, non-tool responses, malformed calls, rate limits and errors explicitly.

Budget defaults: 6 candidates per scenario (server max 12), 6 model turns and 8 tool proposals per case, 60-second case deadline, 300-second run deadline, 60000 aggregate token budget. Enforce the aggregate budget across attacker and target clients with a shared per-run limiter. Use conservative pre-call reservation and report actual usage afterwards; provider account caps are the financial backstop. One bounded retry only for clearly retryable model transport errors within budget. No automatic retries of effects.

Missing credentials or live failures must never silently switch to fixture mode. A live provider error is inconclusive unless the oracle already verified an effect. Do not log real keys, environment dumps, authorization headers or raw provider errors that contain secrets.

## Composition and replay

Every discover/suite run first schedules the eight clean tasks once under its selected preset, saving the exact snapshots and results for usability comparison. Stable task IDs identify clean variants. All phases share the run budget; scheduled-but-uncompleted cases stay visible. For discovery's attack phase, load selected trusted scenarios, construct A's engine, and pass a callback that assigns trial ID, validates/saves candidate, deep-copies the snapshot, builds CaseSpec, invokes B's target and persists CaseResult. Emit ordered candidate/case/run events through your store. A performs no direct database writes.

For operation=suite, run B's eight held-out attack fixtures with fixed payloads after the clean phase. Do not regenerate attacks or schedule the clean tasks twice. Preserve correct mode labels and feed all results to A's metrics.

Retest accepts only a completed run with saved candidates/snapshots. It creates a new linked run, preserving candidate IDs/text/hash and fixture snapshot/hash, selecting gateway policy and fresh trial IDs/state copies. Do not mutate the original baseline, reuse a contaminated outbox, or regenerate candidates. include_benign=true replays the original clean tasks with their saved snapshots. Compare matched clean baseline cases; missing or inconclusive baseline results remain explicitly unavailable/inconclusive, never fake prior passes. Include per-case payload/fixture hashes, policy_version, source_consumed and tool_counts in results so A can compute comparisons without private database access.

For exports, assemble schema version, exact trusted task/source/candidate, snapshot and hashes, model/provider/settings, policy version/hash, app revision when known, events, outcomes, state diffs, mode, timestamps and usage. API keys are never exported. Synthetic canaries in controlled evidence are acceptable and must be labeled synthetic. JSON is downloadable and Markdown uses A's pure renderer. Do not claim deterministic live re-execution.

## Packaging and deployment

Single Docker multi-stage build: Node 22 frontend build, Python runtime, non-root, built frontend served by FastAPI. Coordinate frontend build path with C. Preserve /api 404/errors before SPA fallback. Uvicorn listens on 0.0.0.0:$PORT (default 8000), one worker, no auto-reload. Compose mounts /data for SQLite. No real action credentials, privileged mode, host socket or executable uploads.

Write README with local backend/frontend steps, actual scripts, environment variables, fixture/live distinctions, CLI use, and known limitations. Render deployment instructions: Docker service, secrets in platform settings, disk /data on a supporting paid plan, /api/health, one instance, HTTPS, authenticated fixture smoke test then explicitly enable live mode. Without a disk, label storage ephemeral. Local Docker is the fallback if hosting cannot be completed.

## Verification and delivery

Contract tests, API validation, queued state, queue saturation, cancellation, event ordering/pagination, retest exact payload/snapshot, live errors, aggregate limits, secret handling, restart interruption, and persisted completed runs. Use stub A/B implementations for early platform tests; switch to their actual modules at checkpoints without duplicating their code.

Add one Playwright end-to-end path once C is ready: fixture run → evidence → apply guard → comparison → export. Coordinate stable accessible labels with C and make the test actually exercise API/worker/target/policy, not just mocked browser responses.

Run backend tests, frontend checks with C's scripts, Docker build and a local smoke test when available. Do not claim live/deployed success without running it. Keep the roadmap features out of the core build. Summarize changed files, actual commands/results, integration gaps and the exact next step in docs/handoffs/D.md and your final response. Do not commit/push/deploy to a paid account unless the developer explicitly authorizes that action.
