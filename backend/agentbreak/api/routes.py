"""REST API routes for the AgentBreak platform.

Implements the frozen contract from docs/contracts.md:
- GET /api/health
- GET /api/scenarios
- POST /api/runs
- GET /api/runs
- GET /api/runs/{id}
- GET /api/runs/{id}/events
- POST /api/runs/{id}/retest
- POST /api/runs/{id}/cancel
- GET /api/runs/{id}/export
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse, Response

from agentbreak.contracts import (
    Budget,
    CancelResponse,
    DefensePreset,
    ErrorDetail,
    ErrorResponse,
    EventsQuery,
    EventsResponse,
    ExecutionMode,
    HealthResponse,
    RetestAccepted,
    RetestRequest,
    RunAccepted,
    RunDetailResponse,
    RunRequest,
    RunSummary,
    RunStatus,
    RunsQuery,
    RunsResponse,
    ScenariosResponse,
)
from agentbreak.fixtures import list_scenarios

if TYPE_CHECKING:
    from agentbreak.storage.database import Database

logger = logging.getLogger(__name__)

MAX_QUEUED_RUNS = int(os.environ.get("MAX_QUEUED_RUNS", "4"))


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(error=ErrorDetail(code=code, message=message)).model_dump(mode="json"),
    )


def _check_auth(authorization: str | None) -> JSONResponse | None:
    """Validate demo bearer token if configured. Returns error response or None."""
    token = os.environ.get("DEMO_ACCESS_TOKEN", "").strip()
    if not token:
        return None  # no auth required if token not configured
    if not authorization:
        return _error(401, "unauthorized", "Authorization header required.")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return _error(401, "unauthorized", "Bearer token required.")
    # Constant-time comparison
    import hmac
    if not hmac.compare_digest(parts[1], token):
        return _error(401, "unauthorized", "Invalid access token.")
    return None


def create_router() -> APIRouter:
    router = APIRouter(prefix="/api")

    # ------------------------------------------------------------------ health
    @router.get("/health", response_model=HealthResponse)
    async def health(request: Request) -> HealthResponse:
        live_ready = getattr(request.app.state, "live_ready", False)
        return HealthResponse(status="ok", schema_version=1, live_ready=live_ready)

    # ------------------------------------------------------------------ scenarios
    @router.get("/scenarios", response_model=ScenariosResponse)
    async def scenarios(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> ScenariosResponse | JSONResponse:
        auth_err = _check_auth(authorization)
        if auth_err:
            return auth_err
        specs = list_scenarios()
        return ScenariosResponse(items=[s.to_public() for s in specs])

    # ------------------------------------------------------------------ create run
    @router.post("/runs", status_code=202, response_model=RunAccepted)
    async def create_run(
        body: RunRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        auth_err = _check_auth(authorization)
        if auth_err:
            return auth_err

        db: Database = request.app.state.db
        queue: asyncio.Queue = request.app.state.run_queue

        # Validate live mode
        if body.execution_mode == ExecutionMode.LIVE:
            live_ready = getattr(request.app.state, "live_ready", False)
            if not live_ready:
                return _error(409, "live_not_ready", "Live mode is not available. Credentials or SDK missing.")

        # Check queue capacity
        running, queued = db.count_active_runs()
        if queued >= MAX_QUEUED_RUNS:
            return _error(409, "queue_full", f"Run queue is full ({MAX_QUEUED_RUNS} max).")

        # Create the run in the database BEFORE enqueueing
        run_id = uuid4()
        run = db.create_run(run_id, body)

        # Enqueue for the background worker
        try:
            queue.put_nowait(run_id)
        except asyncio.QueueFull:
            db.update_run_status(run_id, RunStatus.FAILED,
                                 ErrorDetail(code="queue_full", message="Worker queue was full."))
            return _error(409, "queue_full", "Worker queue is full.")

        return JSONResponse(
            status_code=202,
            content=RunAccepted(run_id=run_id, status="queued").model_dump(mode="json"),
        )

    # ------------------------------------------------------------------ list runs
    @router.get("/runs", response_model=RunsResponse)
    async def list_runs(
        request: Request,
        authorization: str | None = Header(default=None),
        limit: int = Query(default=20, ge=1, le=100),
    ) -> RunsResponse | JSONResponse:
        auth_err = _check_auth(authorization)
        if auth_err:
            return auth_err
        db: Database = request.app.state.db
        items = db.list_runs(limit=limit)
        return RunsResponse(items=items)

    # ------------------------------------------------------------------ get run
    @router.get("/runs/{run_id}", response_model=RunDetailResponse)
    async def get_run(
        run_id: UUID,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> RunDetailResponse | JSONResponse:
        auth_err = _check_auth(authorization)
        if auth_err:
            return auth_err
        db: Database = request.app.state.db
        run = db.get_run(run_id)
        if run is None:
            return _error(404, "not_found", "Run not found.")
        cases = db.get_cases(run_id)
        return RunDetailResponse(run=run, cases=cases)

    # ------------------------------------------------------------------ events
    @router.get("/runs/{run_id}/events", response_model=EventsResponse)
    async def get_events(
        run_id: UUID,
        request: Request,
        authorization: str | None = Header(default=None),
        after_seq: int = Query(default=0, ge=0),
        limit: int = Query(default=200, ge=1, le=500),
    ) -> EventsResponse | JSONResponse:
        auth_err = _check_auth(authorization)
        if auth_err:
            return auth_err
        db: Database = request.app.state.db
        run = db.get_run(run_id)
        if run is None:
            return _error(404, "not_found", "Run not found.")
        return db.get_events(run_id, after_seq=after_seq, limit=limit)

    # ------------------------------------------------------------------ retest
    @router.post("/runs/{run_id}/retest", status_code=202, response_model=RetestAccepted)
    async def retest(
        run_id: UUID,
        body: RetestRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        auth_err = _check_auth(authorization)
        if auth_err:
            return auth_err

        db: Database = request.app.state.db
        queue: asyncio.Queue = request.app.state.run_queue

        source_run = db.get_run(run_id)
        if source_run is None:
            return _error(404, "not_found", "Source run not found.")
        if source_run.status != RunStatus.COMPLETED:
            return _error(409, "invalid_transition", "Retest requires a completed source run.")

        # Check queue capacity
        running, queued = db.count_active_runs()
        if queued >= MAX_QUEUED_RUNS:
            return _error(409, "queue_full", f"Run queue is full ({MAX_QUEUED_RUNS} max).")

        # Create a new run linked to the source
        new_run_id = uuid4()
        new_request = RunRequest(
            scenario_ids=source_run.request.scenario_ids,
            operation="suite",  # retest always uses suite mode
            defense=DefensePreset.GATEWAY,  # retest always applies gateway
            execution_mode=source_run.request.execution_mode,
            budget=source_run.request.budget,
            seed=source_run.request.seed,
        )
        db.create_run(new_run_id, new_request, source_run_id=run_id)

        # Store retest metadata in app state for the worker to pick up
        if not hasattr(request.app.state, "retest_configs"):
            request.app.state.retest_configs = {}
        request.app.state.retest_configs[new_run_id] = {
            "source_run_id": run_id,
            "include_benign": body.include_benign,
        }

        try:
            queue.put_nowait(new_run_id)
        except asyncio.QueueFull:
            db.update_run_status(new_run_id, RunStatus.FAILED,
                                 ErrorDetail(code="queue_full", message="Worker queue was full."))
            return _error(409, "queue_full", "Worker queue is full.")

        return JSONResponse(
            status_code=202,
            content=RetestAccepted(run_id=new_run_id).model_dump(mode="json"),
        )

    # ------------------------------------------------------------------ cancel
    @router.post("/runs/{run_id}/cancel", status_code=202, response_model=CancelResponse)
    async def cancel(
        run_id: UUID,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> CancelResponse | JSONResponse:
        auth_err = _check_auth(authorization)
        if auth_err:
            return auth_err
        db: Database = request.app.state.db
        run = db.get_run(run_id)
        if run is None:
            return _error(404, "not_found", "Run not found.")

        terminal = {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED, RunStatus.INTERRUPTED}
        if run.status in terminal:
            return _error(409, "invalid_transition", "Run is already in a terminal state.")

        # Signal cancellation
        cancel_tokens: dict = getattr(request.app.state, "cancel_tokens", {})
        if run_id in cancel_tokens:
            cancel_tokens[run_id].set()

        # If queued (not yet picked up by worker), mark cancelled immediately
        if run.status == RunStatus.QUEUED:
            db.update_run_status(run_id, RunStatus.CANCELLED)
            return CancelResponse(run_id=run_id, status=RunStatus.CANCELLED)

        # For running, we set the token; worker will pick it up
        return CancelResponse(run_id=run_id, status=run.status)

    # ------------------------------------------------------------------ export
    @router.get("/runs/{run_id}/export", response_model=None)
    async def export(
        run_id: UUID,
        request: Request,
        authorization: str | None = Header(default=None),
        format: str = Query(default="json", pattern="^(json|markdown)$"),
    ) -> Response | JSONResponse:
        auth_err = _check_auth(authorization)
        if auth_err:
            return auth_err
        db: Database = request.app.state.db
        run = db.get_run(run_id)
        if run is None:
            return _error(404, "not_found", "Run not found.")

        terminal = {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED, RunStatus.INTERRUPTED}
        if run.status not in terminal:
            return _error(409, "invalid_transition", "Export requires a terminal run.")

        bundle = db.build_replay_bundle(run_id)
        if bundle is None:
            return _error(404, "not_found", "No completed cases to export.")

        if format == "markdown":
            # Try to use A's renderer if available, otherwise basic markdown
            try:
                from agentbreak.evaluation import render_markdown
                md_bundle = bundle.model_dump(mode="json")
                md_text = render_markdown(md_bundle)
            except (ImportError, AttributeError):
                md_text = _fallback_markdown(bundle)
            return Response(
                content=md_text,
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="run-{run_id}.md"'},
            )

        # JSON export
        return Response(
            content=bundle.model_dump_json(indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="run-{run_id}.json"'},
        )

    return router


def _fallback_markdown(bundle) -> str:
    """Basic markdown export when A's renderer is not available."""
    lines = [
        f"# AgentBreak Run Export",
        f"",
        f"- **Run ID:** `{bundle.run.id}`",
        f"- **Status:** {bundle.run.status.value}",
        f"- **Created:** {bundle.run.created_at.isoformat()}",
        f"- **Scenarios:** {', '.join(bundle.run.request.scenario_ids)}",
        f"- **Operation:** {bundle.run.request.operation}",
        f"- **Defense:** {bundle.run.request.defense.value}",
        f"- **Mode:** {bundle.run.request.execution_mode.value}",
        f"- **Cases:** {len(bundle.cases)}",
        f"- **Events:** {len(bundle.events)}",
        f"",
        f"## Cases",
        f"",
    ]
    for i, case in enumerate(bundle.cases, 1):
        r = case.result
        lines.append(f"### Case {i}: {r.scenario_id} / {r.task_id}")
        lines.append(f"- Status: {r.status.value}")
        lines.append(f"- Oracle: {r.oracle_outcome.value}")
        lines.append(f"- Duration: {r.duration_ms}ms")
        lines.append(f"- Tokens: {r.usage.input_tokens + r.usage.output_tokens}")
        if r.violations:
            lines.append(f"- Violations: {len(r.violations)}")
        lines.append("")
    lines.append("---")
    lines.append("*Exported by AgentBreak. All data is synthetic.*")
    return "\n".join(lines)
