"""API route handlers for AgentBreak platform."""

from __future__ import annotations

import hmac
import os
import subprocess
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from fastapi.responses import JSONResponse

from agentbreak.contracts import (
    CancelResponse,
    DefensePreset,
    EventsQuery,
    EventsResponse,
    HealthResponse,
    ReplayBundle,
    ReplayCase,
    ReplayFingerprints,
    RetestAccepted,
    RetestRequest,
    RunAccepted,
    RunDetailResponse,
    RunProgress,
    RunRequest,
    RunsQuery,
    RunsResponse,
    ScenarioSpecPublic,
    ScenariosResponse,
    canonical_sha256,
    payload_sha256,
)
from agentbreak.evaluation.reports import render_markdown
from agentbreak.fixtures import list_scenarios
from agentbreak.llm import is_live_ready
from agentbreak.orchestrator import (
    InvalidTransitionError,
    Orchestrator,
    QueueFullError,
)
from agentbreak.storage.db import Database, get_db

router = APIRouter()

_ORCHESTRATOR: Orchestrator | None = None


def get_orchestrator() -> Orchestrator:
    global _ORCHESTRATOR
    if _ORCHESTRATOR is None:
        db = get_db()
        _ORCHESTRATOR = Orchestrator(db)
        _ORCHESTRATOR.start()
    return _ORCHESTRATOR


def set_orchestrator(orchestrator: Orchestrator) -> None:
    global _ORCHESTRATOR
    _ORCHESTRATOR = orchestrator


def _verify_auth(authorization: str | None = Header(None)) -> None:
    expected_token = (
        os.environ.get("DEMO_ACCESS_TOKEN")
        or os.environ.get("AGENTBREAK_TOKEN")
        or ""
    ).strip()
    if not expected_token:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
        )
    provided = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(provided, expected_token):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
        )


@router.get("/health", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    return HealthResponse(status="ok", schema_version=1, live_ready=is_live_ready())


@router.get(
    "/scenarios",
    response_model=ScenariosResponse,
    dependencies=[Depends(_verify_auth)],
)
async def get_scenarios() -> ScenariosResponse:
    scenarios = [s.to_public() for s in list_scenarios()]
    return ScenariosResponse(items=scenarios)


@router.post(
    "/runs",
    status_code=202,
    response_model=RunAccepted,
    dependencies=[Depends(_verify_auth)],
)
async def post_runs(
    request: RunRequest,
    db: Database = Depends(get_db),
    orchestrator: Orchestrator = Depends(get_orchestrator),
) -> RunAccepted:
    if request.execution_mode.value == "live" and not is_live_ready():
        raise HTTPException(
            status_code=409,
            detail="live_not_ready",
        )

    summary = db.create_run(request)
    try:
        orchestrator.enqueue(summary.id)
    except QueueFullError:
        raise HTTPException(
            status_code=409,
            detail="queue_full",
        )

    return RunAccepted(run_id=summary.id, status="queued")


@router.get(
    "/runs",
    response_model=RunsResponse,
    dependencies=[Depends(_verify_auth)],
)
async def get_runs(
    limit: int = Query(20, ge=1, le=100),
    db: Database = Depends(get_db),
) -> RunsResponse:
    runs = db.list_runs(limit=limit)
    return RunsResponse(items=runs)


@router.get(
    "/runs/{id}",
    response_model=RunDetailResponse,
    dependencies=[Depends(_verify_auth)],
)
async def get_run_by_id(
    id: UUID,
    db: Database = Depends(get_db),
) -> RunDetailResponse:
    detail = db.get_run_detail(id)
    if not detail:
        raise HTTPException(status_code=404, detail="not_found")
    summary, cases = detail
    return RunDetailResponse(run=summary, cases=cases)


@router.get(
    "/runs/{id}/events",
    response_model=EventsResponse,
    dependencies=[Depends(_verify_auth)],
)
async def get_run_events(
    id: UUID,
    after_seq: int = Query(0, ge=0, le=1_000_000_000),
    limit: int = Query(200, ge=1, le=500),
    db: Database = Depends(get_db),
) -> EventsResponse:
    events, next_after_seq, has_more = db.get_events_page(
        id, after_seq=after_seq, limit=limit
    )
    if not events and after_seq == 0:
        summary = db.get_run_summary(id)
        if not summary:
            raise HTTPException(status_code=404, detail="not_found")
    return EventsResponse(
        items=events, next_after_seq=next_after_seq, has_more=has_more
    )


@router.post(
    "/runs/{id}/retest",
    status_code=202,
    response_model=RetestAccepted,
    dependencies=[Depends(_verify_auth)],
)
async def post_retest(
    id: UUID,
    body: RetestRequest,
    db: Database = Depends(get_db),
    orchestrator: Orchestrator = Depends(get_orchestrator),
) -> RetestAccepted:
    orig = db.get_run_summary(id)
    if not orig:
        raise HTTPException(status_code=404, detail="not_found")
    if orig.status.value != "completed":
        raise HTTPException(
            status_code=409,
            detail="invalid_transition",
        )

    retest_req = RunRequest(
        scenario_ids=orig.request.scenario_ids,
        operation="suite",
        defense=DefensePreset.GATEWAY,
        execution_mode=orig.request.execution_mode,
        budget=orig.request.budget,
        seed=orig.request.seed,
    )

    new_summary = db.create_run(retest_req, source_run_id=id)
    try:
        orchestrator.enqueue(new_summary.id)
    except QueueFullError:
        raise HTTPException(
            status_code=409,
            detail="queue_full",
        )

    return RetestAccepted(run_id=new_summary.id)


@router.post(
    "/runs/{id}/cancel",
    status_code=202,
    response_model=CancelResponse,
    dependencies=[Depends(_verify_auth)],
)
async def post_cancel(
    id: UUID,
    db: Database = Depends(get_db),
    orchestrator: Orchestrator = Depends(get_orchestrator),
) -> CancelResponse:
    summary = db.get_run_summary(id)
    if not summary:
        raise HTTPException(status_code=404, detail="not_found")
    try:
        status = orchestrator.cancel(id)
    except InvalidTransitionError:
        raise HTTPException(
            status_code=409,
            detail="invalid_transition",
        )
    return CancelResponse(run_id=id, status=status)


@router.get(
    "/runs/{id}/export",
    dependencies=[Depends(_verify_auth)],
)
async def get_export(
    id: UUID,
    format: Literal["json", "markdown"] = Query("json"),
    db: Database = Depends(get_db),
) -> Response:
    summary = db.get_run_summary(id)
    if not summary:
        raise HTTPException(status_code=404, detail="not_found")

    cases = db.get_replay_cases(id)
    events = db.get_all_events(id)

    git_rev = None
    try:
        raw_rev = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()
        if len(raw_rev) >= 7:
            git_rev = raw_rev[:40]
    except Exception:
        pass

    bundle = ReplayBundle(
        schema_version=1,
        synthetic_data=True,
        run=summary,
        exported_at=datetime.now(timezone.utc),
        app_git_revision=git_rev,
        cases=cases,
        events=events,
    )

    if format == "json":
        data = bundle.model_dump_json(indent=2)
        return Response(
            content=data,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="agentbreak-run-{id}.json"',
            },
        )

    md = render_markdown(bundle.model_dump(mode="json"))
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="agentbreak-run-{id}.md"',
        },
    )
