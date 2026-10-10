# AgentBreak

**Initial contract-first scaffold.** AgentBreak is planned as a sandbox-first
agent security regression workbench. The current runnable application provides
only `GET /api/health`. A healthy response confirms the HTTP process is serving;
it does not mean the security-testing workflow is implemented.

## Implemented now

- Python 3.12+ package with FastAPI, Pydantic v2, and Uvicorn.
- `agentbreak.main:create_app` and `agentbreak.main:app` ASGI entry points.
- Health response: `{"status":"ok","schema_version":1,"live_ready":false}`.
- Stable JSON error envelope: `{"error":{"code":"not_found","message":"Resource not found."}}`.
  Request validation uses HTTP 422 and `validation_error`; unknown routes use
  404 and `not_found`. Messages do not reflect request input or exception details.
- Shared contracts and examples under `backend/agentbreak/contracts.py` and
  `docs/` are maintained by D. `llm.py` only re-exports `ModelClient`.
- `docs/contract-openapi.json` publishes the design-time API schema, explicitly
  distinguishing the implemented health route from pending operations.
- Transport tests and a backend-only Docker configuration.

No API docs UI, root landing page, or other HTTP routes are enabled. In
particular, `/api/runs` and `/api/scenarios` return 404. `live_ready` remains
false even if all environment variables are supplied: no live adapter exists.

## Local setup (PowerShell)

Run from this repository root, using an installed Python 3.12 or newer:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c backend/requirements-dev.lock -e ".\backend[dev]"
.\.venv\Scripts\python.exe -m uvicorn agentbreak.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
```

On POSIX, use `python3.12 -m venv .venv`, `.venv/bin/python -m pip install -c
backend/requirements-dev.lock -e './backend[dev]'`, and `.venv/bin/python -m uvicorn agentbreak.main:app --host
127.0.0.1 --port 8000` from the root.

The server does not need credentials. `.env.example` documents future
configuration with live runs disabled; this scaffold does not load a `.env`
file. Tested runtime/dev versions are pinned in `backend/requirements.lock`
and `backend/requirements-dev.lock`. These are version constraints, not
hash-locked manifests; the container base and build tools are not locked.

## Checks

From the root after the isolated development install:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests
.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir .\dist .\backend
```

The health transport tests verify readiness with and without environment
configuration, real 404/405 behavior, validation sanitization through test-only
routes, and sanitized unexpected errors. Contract tests validate the shared
schema independently. There are no frontend or end-to-end checks yet.

The reserved CLI, `python -m agentbreak.cli` (or `agentbreak` after installing),
prints an explicit unimplemented message to stderr and exits with status 2.
It does not run a regression suite or claim a passing evaluation.

## Docker: backend health only

From the root with Docker and Compose installed:

```powershell
docker compose up --build
Invoke-RestMethod http://127.0.0.1:8000/api/health
docker compose down
```

The Python runtime runs as a non-root user, binds the host port to localhost,
and exposes a healthcheck. No credentials, database volumes, or frontend are
required. Runtime dependencies use the tested version constraints; the base
image and build toolchain are not pinned to immutable digests/versions.
The planned production build will add a Node 22 frontend builder stage and
copy C's built assets into the Python runtime for a single origin. That
two-stage build and UI serving remain pending.

## Ownership and integration seams

Sections 6 and 7 of `docs/agentbreak-build-guide.md` define the team boundaries;
`docs/contracts.md` and `backend/agentbreak/contracts.py` define the shared
interfaces. Complete contract review before implementing business workflows.

The repository-local guide is a scoped sections 6/7 companion, not a verbatim
copy of the full supplied plan. The original guide/prompts in the parent
workspace were preserved. See `docs/handoffs/D.md` for verified checkpoint
results and the next integration step.

| Session | Owns next |
| --- | --- |
| A — attack/evaluation | `attacks/`, `evaluation/`, `cli.py`, attack/metric tests, `integrations/promptfoo/` |
| B — target/security | `sandbox/`, `policies/`, `fixtures/`, sandbox/policy/oracle tests |
| C — frontend | `frontend/`, including its future manifest and lock |
| D — integration/platform | Contracts, `llm.py`, `api/`, `storage/`, `main.py`, backend dependencies, API tests, e2e, root packaging and docs |

Package directories contain docstrings only; their presence does not signal
implemented behavior. Only D changes contracts or backend dependencies. A/B
request dependency and schema changes through D; C owns frontend dependencies.
Handoffs in `docs/handoffs/` record pending work rather than completion claims.

## Current limitations and next work

No attack generation, model calls, target runner, fixture execution, policy
gateway, outcome oracle, metrics, reports, persistence, worker queue,
cancellation, retest, regression runner, Promptfoo adapter, or dashboard is
implemented. Fixture simulation and recorded-evidence playback are also
pending. No live security findings or full application readiness are claimed.

Next: agree on the contract freeze; A/B/C implement their owned modules while
D implements model transport, storage, and the run API. Keep all tools mock
and all data synthetic. Preserve an explicit fixture label and keep fixture
results separate from live evidence. Review exact dependency versions and
licenses before deployment or redistribution; see `THIRD_PARTY.md`.
