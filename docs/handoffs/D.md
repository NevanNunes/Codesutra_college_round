# D — initial scaffold and contract checkpoint

Date: 2026-10-10. Scope: supplied guide sections 6 and 7 only.

## Repository state

- New isolated repository at `agentbreak/` in the parent OmniRush workspace.
- Git initialized on `main`; no commits, remote, pushes, deployment, or worktrees.
- Original guide, prompts and OmniRush configuration remain untouched.
- `docs/agentbreak-build-guide.md` is an explicitly scoped sections 6/7 companion,
  not a verbatim full-guide copy. Distribute the full supplied guide/session
  prompts alongside this checkpoint before later feature implementation.

## Delivered

- Python package scaffold and A/B/C/D ownership directories; empty module
  scaffolds do not claim working attack/target/frontend functionality.
- Strict Pydantic contracts in `backend/agentbreak/contracts.py`, typed mock
  snapshots/predicates, public projections, async ModelClient/EventSink seams,
  ordered model/tool-result blocks, budget bounds, exact hashes, UTC/UUIDs.
- API envelopes, event pagination and replay bundle models. Cross-mode/defense
  replay labeling and cross-trial evidence references are rejected.
- `docs/contracts.md`, twelve original synthetic JSON examples, generated
  `docs/contract-openapi.json`, plus an exporter and schema drift/reference test.
- Reusable test-only scripted model and memory event sink; no provider requests
  or scripted target/gateway implementation.
- Health-only ASGI app and sanitized validation/HTTP/internal-error responses.
  `GET /api/health` returns status ok, schema_version 1, live_ready false.
- Backend packaging, tested runtime/dev version constraints, ignored local venv,
  secret/runtime/build ignores, placeholder-only environment, health-only
  non-root Docker/Compose, README and preliminary third-party inventory.

## Contract decisions for review

- Canonical scenarios: `doc_exfil`, `email_bola`.
- Stable `task_id` supplements scenario identity for clean-task matching.
- `ModelReply.content` preserves ordered blocks; `.text` and `.tool_calls` are
  Python projections, not duplicate wire fields.
- Candidate IDs/hashes are required; trusted code assigns UUIDs. CaseSpec checks
  scenario/source/surface and fresh snapshot consistency.
- `EventSink` is an async callable, not an `.emit()` object. The returned
  TraceEvent supplies server-assigned IDs for subsequent dependency links.
- Model/settings and fixture hash canonicalization is specified in contracts.md;
  policy hash is of the versioned artifact bytes, not merely its label.
- Public projections omit initial snapshots/grants/predicates. Controlled
  evidence exports may include explicitly synthetic canaries; real credentials
  are never allowed. Free-text redaction remains an adapter/emitter obligation.
- Pending A/B constructors and helper import paths are specified in
  `docs/contracts.md`; no duplicate implementations were created.

## Actual verification

Commands run from repository root unless noted:

| Check | Actual result |
|---|---|
| `py -3.12 -m venv .venv` | Created isolated Python 3.12.0 environment |
| `.\.venv\Scripts\python.exe -m pip install -c backend/requirements-dev.lock -e './backend[dev]'` | Passed |
| `.\.venv\Scripts\python.exe -m pip check` | No broken requirements |
| `.\.venv\Scripts\python.exe -m agentbreak.api.contract_schema --output docs/contract-openapi.json` | Generated design-time OpenAPI artifact |
| `.\.venv\Scripts\python.exe -m pytest backend/tests -q` | 107 passed; one Starlette TestClient HTTPX deprecation warning |
| `.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir ./dist ./backend` | Built `dist/agentbreak-0.1.0-py3-none-any.whl` |
| `docker compose config --quiet` | Passed |
| `docker info --format '{{.ServerVersion}}'` | Failed: Docker Desktop Linux engine pipe unavailable |
| Local Uvicorn socket smoke on 127.0.0.1:18941 | GET health returned exact expected JSON; spawned server stopped afterward |
| CLI placeholder exit assertion | Exit 2, explicit unimplemented message |
| `git check-ignore` on .env/venv/cache/database paths | All checked private/runtime paths ignored |

No Docker image build/container smoke, frontend checks, live calls, full fixture
runs, persistence checks or end-to-end workflow tests were run. They are not
claimed to pass. The version constraints were tested on Windows/Python 3.12;
Linux image resolution and transitive license review remain unverified. Build
toolchain/container base are not immutably locked. The HTTPX deprecation is
visible and not suppressed; reconcile the test transport in a later dependency
update rather than treating it as a failed test or hiding it.

## Next step

Have A/B/C review `docs/contracts.md`, examples and OpenAPI, then explicitly
authorize the scaffold commit for distribution. Create separate clones/worktrees
from that common checkpoint before concurrent module implementation.

D next implements real model transport/budgeting, SQLite store/emitter,
single worker/queue and REST orchestration against A/B. Auth/rate/body-size
limits, cancellation, retest, exports and UI integration remain pending. Only
health is runnable: non-health business routes currently return 404; live_ready
stays false even when environment variables are set. Do not deploy this scaffold
as a completed or publicly runnable security workbench.
