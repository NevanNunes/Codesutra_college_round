# Session C prompt — dashboard, evidence path, and comparison UI

Paste the prompt below into Claude Opus in the `feature/dashboard` Antigravity worktree after obtaining D's scaffold and placing the guide at `docs/agentbreak-build-guide.md`.

---

You are implementing Module C of AgentBreak for a four-person, 24-hour hackathon. Build the functioning frontend directly in this repo, with tests. Do not just return designs or code snippets. Do not create additional agents or sessions.

## Product outcome

Let a developer run an authorized sandbox attack, inspect verified effects and the recorded execution path, apply a predefined server-side guard and rerun the same candidate, then compare security with legitimate task completion. The UI should make evidence trustworthy and understandable, not imply that a dramatic red graph proves exploitation.

## Read first and scope

Read repo instructions, `docs/agentbreak-build-guide.md`, `docs/contracts.md`, shared JSON examples and backend public schemas. Inspect existing code and preserve it. Use React, TypeScript, Vite and @xyflow/react. Use existing styling if present, otherwise straightforward CSS. No Next.js migration, frontend model calls, auth service, or cloud database.

You own `frontend/` including its package manifest/lock and frontend tests. You may also write `docs/handoffs/C.md`. Do not modify backend contracts/API, root Docker/config, other modules, or the research guide. If a schema/API is missing, request it through the developer; do not implement a competing backend.

D owns the shared API contract. Use its example JSON as development fixtures and freeze matching TS types. Do not generate different field names. Fixtures are test/development-only and must be visibly labeled. Never silently substitute them when the actual API fails.

## API you consume

All request/response fields are snake_case. API base path `/api`; Vite proxies to localhost:8000 in development and production is same-origin.

- GET /health: readiness including live_ready.
- GET /scenarios: items with public scenario definitions.
- POST /runs: scenario_ids, operation discover/suite, defense baseline/gateway, execution_mode live/fixture, budget, seed. Returns 202 run_id/status.
- GET /runs: bounded recent-run list.
- GET /runs/{id}: run summary and public case results.
- GET /runs/{id}/events?after_seq=0&limit=200: items, next_after_seq, has_more.
- POST /runs/{id}/retest: defense gateway, include_benign true; returns new run_id.
- POST /runs/{id}/cancel.
- GET /runs/{id}/export?format=json or markdown.

Use the precise schemas from docs/contracts.md if they elaborate this overview. Terminal states: completed, failed, cancelled, interrupted. Oracle success means attacker success—not defense success. Result states success/failure/inconclusive are distinct from run execution status.

If deployed API access requires a demo token, provide a simple operator token field, retain it in memory only, and add Authorization headers. Never put the token in URLs, localStorage, exports, source, screenshots, or VITE build variables. API/provider credentials are not the same thing; the browser never receives a model API key.

## Screens/components

Implement a compact single-app workflow, not a large marketing site:

1. Header: AgentBreak, “sandbox only”, mode badge LIVE / FIXTURE SIMULATION / RECORDED LIVE EVIDENCE, readiness and access state.
2. Run setup: scenario selection, baseline/gateway preset, bounded candidate budget, seed, start button. Display “This replaces one mock source; no real tools or email.” Disable live mode with an explanation if backend is not ready.
3. Run overview: queued/running/terminal state, progress, cancel, elapsed time, exact model/config identifiers if provided, cost/usage only if known.
4. Candidate list: parent/child lineage, strategy, outcome and brief feedback. Distinguish generated, executed, invalid, inconclusive, and confirmed-effect cases using actual data.
5. Case evidence: original legitimate task, source text, candidate hash, fixture fingerprint, proposed call, policy reason, executed effect or denial, final outcome and evidence IDs.
6. Recorded dependency graph with clickable nodes and an accessible chronological event list.
7. Guard & retest panel: explain the predefined permission/recipient/protected-field policy, then explicitly submit retest. Do not call it “automatic code repair.”
8. Paired comparison: before/after verified effects plus clean-task results; exports to JSON/Markdown.

Use one strong visual language: neutral background, high-contrast status badges, red only for verified forbidden effects, amber for attempts/inconclusive, green for validated prevention or permitted task completion. Provide labels, not just color. Keyboard accessible controls and a readable layout matter more than animation.

## Graph and evidence semantics

Graph nodes derive from persisted TraceEvents; keys use server event IDs. Edges derive only from parent_event_ids. Sequence number determines timeline order; do not infer a causal link merely because two timestamps are close.

Useful node categories: source injected/consumed, model request/visible response, tool proposal, policy decision, executed/blocked tool, oracle result. Collapse noisy intermediate model events if necessary without losing the full timeline. A bounded left-to-right layout is enough; no automatic layout service is needed.

Show this explanation: “Edges show recorded context and execution dependencies, not the model's private reasoning or proof of semantic causality.” Never display chain-of-thought placeholders as if captured. An attacker proposal is not an executed effect, and a denial is not automatically a completed legitimate task.

All payload/model/report content is hostile text for rendering purposes. Do not use dangerouslySetInnerHTML, execute HTML/Markdown scripts, auto-load remote images, or automatically fetch payload links. Plain text/code blocks are fine. Format arbitrary backticks safely. No outbound images that could create accidental exfiltration.

## Polling and state correctness

Create a typed API client and run-data hook. Poll summaries/events every second while active. Request remaining event pages using next_after_seq/has_more. Merge/deduplicate by event ID and sequence. Recover from temporary failures without duplicating nodes; show a disconnected/error state instead of fake progress. Stop on terminal state and cancel subscriptions on unmount/run change.

Preserve selected run in URL state if practical, not credentials. A refresh should retrieve persisted evidence. Retest creates a new run linked to the original; do not overwrite baseline data. Disable repeat retest submissions while pending, and on ambiguous request failure check whether a run was created before encouraging a retry. Coordinate idempotency support with D if needed.

## Metrics and comparison

Render backend metrics rather than recomputing verdicts in the browser. Show numerator/denominator and execution mode for every rate, N/A for no conclusive cases, and explicit inconclusive/uncompleted counts. Never mix fixture and live results. Do not display a made-up “98% secure” score.

Paired comparisons must indicate identical candidate/fixture hashes and the changed policy version. Clean-task success is separate from task success under attack. Highlight clean tasks that passed baseline but fail guarded mode. A defense that blocks everything must visibly look bad on the legitimate-email check.

Use static example metrics only in test fixtures with a simulation badge; no hardcoded demo successes in production paths.

## Tests and delivery

Use Vitest/Testing Library with contract-shaped fixtures. Test loading/empty/error/unauthorized states, oracle success label meaning, attempts versus actual effects, duplicate/out-of-order event delivery, polling stop/cancel, mode separation, N/A denominators, retest body/new-run navigation, and export download errors. Include a malicious text fixture and assert it renders as text without image/script execution.

Run typecheck, unit tests and production build using the real project scripts. Provide the URLs for local development only if actually started. D owns the cross-app Playwright test; provide stable accessible selectors/labels and a frontend test fixture for it.

Return changed files, actual commands/results, components/API expectations, any backend mismatches, and screenshots only if actually captured. Record a concise handoff in docs/handoffs/C.md. Do not commit or push unless requested. Defer fancy animation and graph layout until the full API workflow works.
