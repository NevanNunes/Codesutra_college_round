"""AgentBreak ASGI application with background run worker and full API.

Phase 2 implementation: SQLite persistence, async run queue, model transport,
and the full REST contract. Single Uvicorn worker only.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from agentbreak.api.routes import create_router
from agentbreak.contracts import (
    Budget,
    CaseResult,
    CaseSpec,
    CaseStatus,
    DefensePreset,
    ErrorDetail,
    EventDraft,
    EventType,
    ExecutionMode,
    ModelSettings,
    RunProgress,
    RunRequest,
    RunStatus,
    RunSummary,
    TraceEvent,
    canonical_sha256,
)
from agentbreak.llm import BudgetLimiter, StubModelClient, create_model_client
from agentbreak.storage import Database

logger = logging.getLogger(__name__)

MAX_ACTIVE_RUNS = int(os.environ.get("MAX_ACTIVE_RUNS", "1"))
MAX_QUEUED_RUNS = int(os.environ.get("MAX_QUEUED_RUNS", "4"))


def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


class _DbEventSink:
    """EventSink backed by SQLite. Assigns run_id, id, seq, and timestamp server-side."""

    def __init__(self, db: Database, run_id: UUID) -> None:
        self._db = db
        self._run_id = run_id
        self._lock = asyncio.Lock()

    async def __call__(self, event_draft: EventDraft) -> TraceEvent:
        async with self._lock:
            seq = self._db.next_seq(self._run_id)
            event = TraceEvent(
                **event_draft.model_dump(),
                id=uuid4(),
                run_id=self._run_id,
                seq=seq,
                timestamp=datetime.now(timezone.utc),
            )
            self._db.save_event(event)
            return event


async def _run_worker(app: FastAPI) -> None:
    """Background worker that consumes runs from the queue one at a time."""
    db: Database = app.state.db
    queue: asyncio.Queue = app.state.run_queue

    while True:
        try:
            run_id: UUID = await queue.get()
        except asyncio.CancelledError:
            break

        # Check if cancelled before we even start
        cancel_tokens: dict = getattr(app.state, "cancel_tokens", {})
        cancel_event = asyncio.Event()
        cancel_tokens[run_id] = cancel_event

        run = db.get_run(run_id)
        if run is None or run.status != RunStatus.QUEUED:
            queue.task_done()
            continue

        # Check if this is a retest
        retest_configs: dict = getattr(app.state, "retest_configs", {})
        retest_config = retest_configs.pop(run_id, None)

        db.update_run_status(run_id, RunStatus.RUNNING)
        try:
            if retest_config:
                await _execute_retest(app, run_id, run, retest_config, cancel_event)
            else:
                await _execute_run(app, run_id, run, cancel_event)
        except asyncio.CancelledError:
            db.update_run_status(run_id, RunStatus.CANCELLED,
                                 ErrorDetail(code="run_cancelled", message="Run was cancelled."))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Run %s failed with %s", run_id, type(exc).__name__)
            db.update_run_status(run_id, RunStatus.FAILED,
                                 ErrorDetail(code="run_error", message=f"Run failed: {type(exc).__name__}"))
        finally:
            cancel_tokens.pop(run_id, None)
            queue.task_done()


async def _execute_run(app: FastAPI, run_id: UUID, run: RunSummary, cancel_event: asyncio.Event) -> None:
    """Execute a discover or suite run with benign + attack phases."""
    db: Database = app.state.db
    emit = _DbEventSink(db, run_id)
    req = run.request

    # Emit run_started
    await emit(EventDraft(type=EventType.RUN_STARTED, data={
        "scenario_ids": list(req.scenario_ids),
        "operation": req.operation,
        "defense": req.defense.value,
        "execution_mode": req.execution_mode.value,
    }))

    # Determine model client
    model_client = getattr(app.state, "model_client", None)
    if req.execution_mode == ExecutionMode.LIVE and model_client is None:
        db.update_run_status(run_id, RunStatus.FAILED,
                             ErrorDetail(code="live_not_ready", message="No live model client available."))
        await emit(EventDraft(type=EventType.RUN_ERROR, data={"code": "live_not_ready"}))
        return

    # For fixture mode, we need a scripted model — use B's fixture traces
    from agentbreak.fixtures import list_benign_cases, list_scenarios, list_attack_seeds, load_snapshot
    from agentbreak.fixtures.traces import FixtureModelClient, list_fixture_traces

    scenarios = {s.id: s for s in list_scenarios()}
    selected_scenarios = [scenarios[sid] for sid in req.scenario_ids if sid in scenarios]

    if not selected_scenarios:
        db.update_run_status(run_id, RunStatus.FAILED,
                             ErrorDetail(code="no_scenarios", message="No valid scenarios selected."))
        await emit(EventDraft(type=EventType.RUN_ERROR, data={"code": "no_scenarios"}))
        return

    model_settings = _build_model_settings(req)
    policy_version = _get_policy_version(req.defense)
    budget_limiter = BudgetLimiter(req.budget.max_total_tokens)

    # Phase 1: Benign cases
    benign_cases = list_benign_cases()
    relevant_benign = [bc for bc in benign_cases if bc.scenario.id in req.scenario_ids]

    total_scheduled = len(relevant_benign)
    attack_seeds = []
    if req.operation == "discover":
        attack_seeds = list_attack_seeds("discovery")
    elif req.operation == "suite":
        attack_seeds = list_attack_seeds("held_out")
    relevant_seeds = [s for s in attack_seeds if s.candidate.scenario_id in req.scenario_ids]
    if req.execution_mode == ExecutionMode.LIVE:
        total_scheduled += len(selected_scenarios) * req.budget.max_candidates
    else:
        total_scheduled += len(relevant_seeds)

    progress = RunProgress(scheduled=total_scheduled, phase="benign")
    db.update_run_progress(run_id, progress)

    # Run benign phase
    from agentbreak.sandbox import TargetRunner

    completed_count = 0
    failed_count = 0
    all_results: list[CaseResult] = []

    for bc in relevant_benign:
        if cancel_event.is_set():
            db.update_run_status(run_id, RunStatus.CANCELLED,
                                 ErrorDetail(code="run_cancelled", message="Run cancelled by user."))
            await emit(EventDraft(type=EventType.RUN_CANCELLED, data={}))
            return

        trial_id = uuid4()
        snapshot = copy.deepcopy(bc.fixture_snapshot)
        spec = CaseSpec(
            run_id=run_id, trial_id=trial_id, scenario=bc.scenario,
            candidate=None, defense=req.defense, execution_mode=req.execution_mode,
            fixture_snapshot=snapshot, budget=req.budget, seed=req.seed,
            model_settings=model_settings, policy_version=policy_version,
        )
        db.save_case_spec(run_id, spec)

        try:
            case_client = _get_case_client(app, req, spec)
            runner = TargetRunner(case_client)
            result = await asyncio.wait_for(
                runner.run_case(spec, emit),
                timeout=req.budget.case_timeout_s,
            )
            completed_count += 1
            all_results.append(result)
        except (TimeoutError, asyncio.TimeoutError):
            failed_count += 1
            result = _make_timeout_result(spec)
            all_results.append(result)
        except asyncio.CancelledError:
            # Grab attached result if available
            raise
        except Exception as exc:  # noqa: BLE001
            failed_count += 1
            result = _make_error_result(spec, exc)
            all_results.append(result)

        db.save_case_result(run_id, result)
        progress = RunProgress(scheduled=total_scheduled, completed=completed_count, failed=failed_count, phase="benign")
        db.update_run_progress(run_id, progress)

    # Phase 2: Attack phase
    progress = RunProgress(scheduled=total_scheduled, completed=completed_count, failed=failed_count, phase="attack")
    db.update_run_progress(run_id, progress)

    if req.execution_mode == ExecutionMode.LIVE:
        from agentbreak.attacks.generator import AttackGenerator
        from agentbreak.attacks.engine import AdaptiveAttackEngine
        
        attacker_client = getattr(app.state, "model_client", None)
        if not attacker_client:
            from agentbreak.llm import StubModelClient
            attacker_client = StubModelClient()
            
        generator = AttackGenerator(attacker_client, model_settings)
        engine = AdaptiveAttackEngine(generator)
        
        for scenario in selected_scenarios:
            if cancel_event.is_set():
                db.update_run_status(run_id, RunStatus.CANCELLED,
                                     ErrorDetail(code="run_cancelled", message="Run cancelled by user."))
                await emit(EventDraft(type=EventType.RUN_CANCELLED, data={}))
                return
                
            def progress_updater(completed: int, is_fail: bool):
                nonlocal completed_count, failed_count
                if is_fail:
                    failed_count += 1
                else:
                    completed_count += 1
                db.update_run_progress(run_id, RunProgress(
                    scheduled=total_scheduled, completed=completed_count, failed=failed_count, phase="attack"
                ))

            snapshot = load_snapshot(scenario.fixture_id)
            
            # Need a dummy spec for getting client (only relevant if fixture mode, but we are in live)
            dummy_spec = CaseSpec(
                run_id=run_id, trial_id=uuid4(), scenario=scenario, candidate=None,
                defense=req.defense, execution_mode=req.execution_mode, fixture_snapshot=snapshot,
                budget=req.budget, seed=req.seed, model_settings=model_settings, policy_version=policy_version
            )
            case_client = _get_case_client(app, req, dummy_spec)
            
            results = await engine.run_campaign(
                db, emit, run_id, req, scenario, snapshot, policy_version, case_client, cancel_event, progress_updater
            )
            all_results.extend(results)
    else:
        for seed in relevant_seeds:
            if cancel_event.is_set():
                db.update_run_status(run_id, RunStatus.CANCELLED,
                                     ErrorDetail(code="run_cancelled", message="Run cancelled by user."))
                await emit(EventDraft(type=EventType.RUN_CANCELLED, data={}))
                return

            trial_id = uuid4()
            scenario = scenarios[seed.candidate.scenario_id]
            snapshot = load_snapshot(scenario.fixture_id)

            # Inject attack candidate text into the source document
            injected_snapshot = copy.deepcopy(snapshot)
            for doc in injected_snapshot.documents:
                if doc.id == scenario.source_id:
                    doc.body = seed.candidate.text

            spec = CaseSpec(
                run_id=run_id, trial_id=trial_id, scenario=scenario,
                candidate=seed.candidate, defense=req.defense, execution_mode=req.execution_mode,
                fixture_snapshot=injected_snapshot, budget=req.budget, seed=req.seed,
                model_settings=model_settings, policy_version=policy_version,
            )
            db.save_case_spec(run_id, spec)
            db.save_candidate(run_id, seed.candidate.model_dump_json(), str(seed.candidate.id))

            # Emit candidate_generated
            await emit(EventDraft(
                trial_id=trial_id, type=EventType.CANDIDATE_GENERATED, data={
                    "candidate_id": str(seed.candidate.id),
                    "scenario_id": seed.candidate.scenario_id,
                    "strategy": seed.candidate.strategy,
                    "generation": seed.candidate.generation,
                    "payload_sha256": seed.candidate.payload_sha256,
                }
            ))

            try:
                case_client = _get_case_client(app, req, spec)
                runner = TargetRunner(case_client)
                result = await asyncio.wait_for(
                    runner.run_case(spec, emit),
                    timeout=req.budget.case_timeout_s,
                )
                completed_count += 1
                all_results.append(result)
            except (TimeoutError, asyncio.TimeoutError):
                failed_count += 1
                result = _make_timeout_result(spec)
                all_results.append(result)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                failed_count += 1
                result = _make_error_result(spec, exc)
                all_results.append(result)

            db.save_case_result(run_id, result)
            progress = RunProgress(scheduled=total_scheduled, completed=completed_count, failed=failed_count, phase="attack")
            db.update_run_progress(run_id, progress)

    # Finalize
    progress = RunProgress(scheduled=total_scheduled, completed=completed_count, failed=failed_count, phase="done")
    db.update_run_progress(run_id, progress)

    # Compute metrics if A's module is available
    metrics = _compute_metrics(all_results)
    if metrics:
        db.update_run_metrics(run_id, metrics)

    db.update_run_status(run_id, RunStatus.COMPLETED)
    await emit(EventDraft(type=EventType.RUN_COMPLETED, data={
        "total_cases": total_scheduled,
        "completed": completed_count,
        "failed": failed_count,
    }))


async def _execute_retest(app: FastAPI, run_id: UUID, run: RunSummary, config: dict, cancel_event: asyncio.Event) -> None:
    """Execute a retest run: replay completed candidates with gateway defense."""
    db: Database = app.state.db
    emit = _DbEventSink(db, run_id)
    req = run.request
    source_run_id = config["source_run_id"]
    include_benign = config.get("include_benign", True)

    await emit(EventDraft(type=EventType.RUN_STARTED, data={
        "operation": "retest",
        "source_run_id": str(source_run_id),
        "defense": req.defense.value,
    }))

    # Load source cases
    source_pairs = db.get_full_cases(source_run_id)
    if not source_pairs:
        db.update_run_status(run_id, RunStatus.FAILED,
                             ErrorDetail(code="no_source_cases", message="No completed cases in source run."))
        return

    model_settings = _build_model_settings(req)
    policy_version = _get_policy_version(req.defense)

    from agentbreak.sandbox import TargetRunner
    from agentbreak.fixtures import load_snapshot

    cases_to_run = []
    for spec, result in source_pairs:
        is_benign = spec.candidate is None
        if is_benign and not include_benign:
            continue
        cases_to_run.append((spec, result))

    total = len(cases_to_run)
    progress = RunProgress(scheduled=total, phase="retest")
    db.update_run_progress(run_id, progress)

    completed_count = 0
    failed_count = 0
    all_results: list[CaseResult] = []

    for orig_spec, orig_result in cases_to_run:
        if cancel_event.is_set():
            db.update_run_status(run_id, RunStatus.CANCELLED)
            return

        trial_id = uuid4()
        # Fresh snapshot, same fixture
        snapshot = load_snapshot(orig_spec.scenario.fixture_id)
        if orig_spec.candidate is not None:
            for doc in snapshot.documents:
                if doc.id == orig_spec.scenario.source_id:
                    doc.body = orig_spec.candidate.text

        new_spec = CaseSpec(
            run_id=run_id, trial_id=trial_id, scenario=orig_spec.scenario,
            candidate=orig_spec.candidate, defense=req.defense,
            execution_mode=req.execution_mode, fixture_snapshot=snapshot,
            budget=req.budget, seed=req.seed,
            model_settings=model_settings, policy_version=policy_version,
        )
        db.save_case_spec(run_id, new_spec)

        try:
            case_client = _get_case_client(app, req, new_spec)
            runner = TargetRunner(case_client)
            result = await asyncio.wait_for(
                runner.run_case(new_spec, emit),
                timeout=req.budget.case_timeout_s,
            )
            completed_count += 1
            all_results.append(result)
        except (TimeoutError, asyncio.TimeoutError):
            failed_count += 1
            result = _make_timeout_result(new_spec)
            all_results.append(result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            failed_count += 1
            result = _make_error_result(new_spec, exc)
            all_results.append(result)

        db.save_case_result(run_id, result)
        progress = RunProgress(scheduled=total, completed=completed_count, failed=failed_count, phase="retest")
        db.update_run_progress(run_id, progress)

    progress = RunProgress(scheduled=total, completed=completed_count, failed=failed_count, phase="done")
    db.update_run_progress(run_id, progress)

    metrics = _compute_metrics(all_results)
    if metrics:
        db.update_run_metrics(run_id, metrics)

    db.update_run_status(run_id, RunStatus.COMPLETED)
    await emit(EventDraft(type=EventType.RUN_COMPLETED, data={
        "total_cases": total, "completed": completed_count, "failed": failed_count,
    }))


# ------------------------------------------------------------------ helpers

def _build_model_settings(req: RunRequest) -> ModelSettings:
    return ModelSettings(
        provider="anthropic",
        target_model_id=os.environ.get("TARGET_MODEL_ID", "claude-sonnet-4-20250514"),
        attacker_model_id=os.environ.get("ATTACKER_MODEL_ID", "claude-sonnet-4-20250514"),
        temperature=0.0,
        max_tokens=1024,
    )


def _get_policy_version(defense: DefensePreset) -> str:
    from agentbreak.policies import BASELINE_POLICY_VERSION, GATEWAY_POLICY_VERSION
    return GATEWAY_POLICY_VERSION if defense == DefensePreset.GATEWAY else BASELINE_POLICY_VERSION


def _get_case_client(app: FastAPI, req: RunRequest, spec: CaseSpec):
    """Get the appropriate model client for a case."""
    if req.execution_mode == ExecutionMode.FIXTURE:
        from agentbreak.fixtures.traces import (
            FixtureModelClient,
            FixtureTraceNotFoundError,
            list_fixture_traces,
        )

        traces = list_fixture_traces()
        matching = [
            t for t in traces
            if t.scenario_id == spec.scenario.id and t.task_id == spec.scenario.task_id
        ]
        if not matching:
            raise FixtureTraceNotFoundError(
                f"No fixture trace found for scenario '{spec.scenario.id}' and task '{spec.scenario.task_id}'."
            )

        # If scenario/task has only one matching trace, preserve existing behavior
        if len(matching) == 1:
            return FixtureModelClient(matching[0])

        # Distinguish benign from malicious trials:
        # spec.candidate is None identifies benign trials; candidate is not None identifies attacks.
        is_benign = spec.candidate is None
        if is_benign:
            benign_trace = next(
                (t for t in matching if t.name.endswith("_benign_success") or "benign" in t.name),
                None,
            )
            if benign_trace is not None:
                return FixtureModelClient(benign_trace)
            return FixtureModelClient(matching[0])
        else:
            attack_trace = next(
                (t for t in matching if t.name.endswith("_insecure_failure") or "insecure" in t.name or "attack" in t.name or "failure" in t.name or "cross_account" in t.name),
                None,
            )
            if attack_trace is not None:
                return FixtureModelClient(attack_trace)
            return FixtureModelClient(matching[0])

    return getattr(app.state, "model_client", StubModelClient())



def _compute_metrics(results: list[CaseResult]) -> dict[str, Any]:
    """Calculate formal evaluation metrics using the authoritative evaluator."""
    if not results:
        return {}
    try:
        from agentbreak.evaluation import calculate_metrics

        metrics = calculate_metrics(results)
        if isinstance(metrics, dict):
            return metrics
        return metrics.model_dump(mode="json")
    except Exception as exc:
        logger.error("Failed to calculate evaluation metrics: %s", exc, exc_info=True)
        raise




def _make_timeout_result(spec: CaseSpec) -> CaseResult:
    """Create a timeout result for a case that exceeded its deadline."""
    from agentbreak.contracts import OracleOutcome, ToolCounts, Usage, StateDiff
    return CaseResult(
        run_id=spec.run_id, trial_id=spec.trial_id, scenario_id=spec.scenario.id,
        task_id=spec.scenario.task_id,
        candidate_id=spec.candidate.id if spec.candidate else None,
        payload_sha256=spec.candidate.payload_sha256 if spec.candidate else None,
        fixture_sha256=canonical_sha256(spec.fixture_snapshot),
        policy_version=spec.policy_version,
        defense=spec.defense, execution_mode=spec.execution_mode,
        status=CaseStatus.TIMED_OUT, oracle_outcome=OracleOutcome.INCONCLUSIVE,
        final_output="", source_consumed=False,
        tool_counts=ToolCounts(), duration_ms=spec.budget.case_timeout_s * 1000,
        usage=Usage(), error=ErrorDetail(code="case_timeout", message="Case exceeded deadline."),
        state_diff=StateDiff(),
    )


def _make_error_result(spec: CaseSpec, exc: Exception) -> CaseResult:
    """Create an error result for a case that failed."""
    from agentbreak.contracts import OracleOutcome, ToolCounts, Usage, StateDiff
    return CaseResult(
        run_id=spec.run_id, trial_id=spec.trial_id, scenario_id=spec.scenario.id,
        task_id=spec.scenario.task_id,
        candidate_id=spec.candidate.id if spec.candidate else None,
        payload_sha256=spec.candidate.payload_sha256 if spec.candidate else None,
        fixture_sha256=canonical_sha256(spec.fixture_snapshot),
        policy_version=spec.policy_version,
        defense=spec.defense, execution_mode=spec.execution_mode,
        status=CaseStatus.FAILED, oracle_outcome=OracleOutcome.INCONCLUSIVE,
        final_output="", source_consumed=False,
        tool_counts=ToolCounts(), duration_ms=0,
        usage=Usage(), error=ErrorDetail(code="case_error", message=f"{type(exc).__name__}"),
        state_diff=StateDiff(),
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: init DB, start worker, cleanup on shutdown."""
    # Initialize database
    db_path = os.environ.get("DATABASE_PATH", "agentbreak.db")
    db = Database(db_path)
    db.initialize()
    app.state.db = db

    # Initialize model client
    model_client, live_ready = create_model_client()
    app.state.model_client = model_client
    app.state.live_ready = live_ready

    # Run queue
    app.state.run_queue = asyncio.Queue(maxsize=MAX_QUEUED_RUNS)
    app.state.cancel_tokens = {}
    app.state.retest_configs = {}

    # Start background worker
    worker_task = asyncio.create_task(_run_worker(app))

    logger.info(
        "AgentBreak started: db=%s, live_ready=%s, max_active=%d, max_queued=%d",
        db_path, live_ready, MAX_ACTIVE_RUNS, MAX_QUEUED_RUNS,
    )

    yield

    # Shutdown: cancel the worker
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass


def create_app() -> FastAPI:
    """Construct the full AgentBreak application."""
    app = FastAPI(
        title="AgentBreak",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    # CORS for development proxy
    cors_origins = os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in cors_origins],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Exception handlers
    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error_response(422, "validation_error", "Request validation failed.")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        errors = {
            404: ("not_found", "Resource not found."),
            405: ("method_not_allowed", "Method not allowed."),
        }
        code, message = errors.get(exc.status_code, ("http_error", "Request failed."))
        response = _error_response(exc.status_code, code, message)
        if exc.status_code == 405 and exc.headers and "Allow" in exc.headers:
            response.headers["Allow"] = exc.headers["Allow"]
        return response

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error")
        return _error_response(500, "internal_error", "Internal server error.")

    # Mount API router
    router = create_router()
    app.include_router(router)
    
    from agentbreak.api.report_routes import report_router
    app.include_router(report_router)

    return app


app = create_app()
