# Module D (Platform, Persistence, API, and Integration) Handoff

## Overview
Module D implements the platform layer for AgentBreak, providing the persistent SQLite storage, strict monotonic `EventSink`, async task orchestrator, model transport adapters, REST API endpoints, evidence export bundling, Docker multi-stage packaging, and end-to-end integration across Modules A, B, and C.

---

## Changed and Added Files
- `backend/agentbreak/storage/db.py`: SQLite persistence layer (`runs`, `cases`, `events` tables with WAL mode, unique `(run_id, seq)` index, query pagination, and crash recovery marking unfinished runs as `interrupted`).
- `backend/agentbreak/storage/sink.py`: `PersistentEventSink` enforcing monotonic sequence numbering, server UUIDs, UTC timestamps, schema versioning, and parent event precedence/validation.
- `backend/agentbreak/storage/__init__.py`: Public exports for database and event sink primitives.
- `backend/agentbreak/llm.py`: Model clients implementing the `ModelClient` protocol:
  - `DeterministicFixtureTargetClient`: Scripted multi-turn responses for all 8 benign tasks and 8 held-out attack seeds under both baseline and gateway policies.
  - `DeterministicFixtureAttackerClient`: Structured mutation candidates for discovery mode.
  - `LiveAnthropicModelClient`: Anthropic Python SDK client with token usage accounting and sanitization.
- `backend/agentbreak/orchestrator.py`: Async queue orchestrator with `MAX_ACTIVE_RUNS=1`, `MAX_QUEUED_RUNS=4`, cooperative cancellation, `suite` phase execution (8 clean + 8 held-out cases), `discover` phase execution via `AttackEngine.discover` callback (`execute_case`), and `retest` phase execution preserving candidate snapshots.
- `backend/agentbreak/api/routes.py`: FastAPI router implementing all frozen API routes:
  - `GET /api/health`
  - `GET /api/scenarios`
  - `POST /api/runs`
  - `GET /api/runs`
  - `GET /api/runs/{id}`
  - `GET /api/runs/{id}/events` (with pagination via `after_seq` and `limit`)
  - `POST /api/runs/{id}/retest`
  - `POST /api/runs/{id}/cancel`
  - `GET /api/runs/{id}/export?format=json|markdown`
- `backend/agentbreak/main.py`: Lifespan startup/shutdown, database initialization, background worker lifecycle, sanitized error handlers (no secret leakage, stable HTTP status codes 404/405/422/401/409/500), and optional SPA static file serving.
- `backend/tests/test_api_health.py`: Health endpoint and sanitized error response tests.
- `backend/tests/test_api_platform.py`: Comprehensive API tests covering scenario listing, suite run queueing, retest flow, bearer token authentication, run cancellation, and restart interruption.
- `tests/e2e/test_e2e_integration.py`: End-to-end integration tests verifying baseline-to-gateway retest lifecycle, monotonic event sequences, and CLI regression execution.
- `Dockerfile`: Multi-stage build (Node 22 frontend builder + Python 3.12 slim runtime, non-root `agentbreak` user, `/data` volume, lockfile-based pip install).
- `compose.yaml`: Configured persistent volume `agentbreak-data:/data`, database path `/data/agentbreak.db`, and frontend distribution path `/app/frontend/dist`.
- `pytest.ini`: Configured test runner with `asyncio_mode = auto` and `pythonpath = backend`.
- `frontend/src/api.ts`: Aligned contract schemas (`schema_version: 1`, `RunsResponse.items`, `RetestAccepted.run_id`, `CancelResponse.run_id`).

---

## Frozen REST API Verification
All endpoints adhere strictly to the frozen contracts:
- `GET /api/health`: Returns `{"status": "ok", "schema_version": 1, "live_ready": bool}` without requiring authentication.
- `GET /api/scenarios`: Returns available scenarios (`doc_exfil`, `email_bola`) without disclosing secret canaries.
- `POST /api/runs`: Validates `RunRequest`, validates budgets against server limits, saves run, and queues for worker execution with 202 Accepted.
- `GET /api/runs`: Lists summarized runs ordered newest first.
- `GET /api/runs/{id}`: Returns complete `RunDetailResponse` including summary, metrics, and case results.
- `GET /api/runs/{id}/events`: Supports sequence pagination via `after_seq` and `limit`.
- `POST /api/runs/{id}/retest`: Creates a new run referencing the baseline run, replaying identical candidates and initial fixture snapshots under the `gateway` defense.
- `POST /api/runs/{id}/cancel`: Requests cancellation of queued or running suites/discoveries.
- `GET /api/runs/{id}/export?format=json`: Returns full `ReplayBundle` with schema version, scenario, candidates, events, and metrics.
- `GET /api/runs/{id}/export?format=markdown`: Renders audit-ready markdown evidence using Module A's `render_markdown`.

---

## Suite Regression & Verification Results

### 1. Backend Pytest Suites
All 234 unit, contract, platform, and e2e integration tests pass:
```bash
python -m pytest -q
```
**Result**: `234 passed, 1 warning in 0.87s`

### 2. CLI Regression Suite
Running the CLI regression against the live server:
```bash
python -m agentbreak.cli regress --mode fixture --defense gateway
```
**Output**:
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
```
**Exit code**: `0`

### 3. Frontend Validation
```bash
cd frontend
npm ci
npm run typecheck
npm run test -- --run
npm run build
```
**Results**:
- TypeScript typecheck passed cleanly (`tsc --noEmit`).
- Vitest test suite: `17 passed (17)` in `656ms`.
- Vite production build: `dist/index.html`, `dist/assets/index-*.css`, `dist/assets/index-*.js` built cleanly in `119ms`.

---

## Security and Production Safeguards
1. **Zero Secret Leakage**: No API keys, Authorization headers, or internal credentials are logged or exported.
2. **Deterministic Fixture Mode**: Fixture mode never falls back to live models or contacts external networks.
3. **Monotonic Event Log**: Every event assigned a monotonic sequence number `(run_id, seq)` indexed uniquely in SQLite.
4. **Crash Recovery**: Server process restart detects any active/queued runs and marks them `interrupted` rather than re-executing unsafely.
5. **Sanitized Error Responses**: Internal tracebacks are caught and converted to standard structured error envelopes (`code`, `message`).
