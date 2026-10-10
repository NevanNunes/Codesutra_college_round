"""Execution queue and orchestration engine for AgentBreak."""

from __future__ import annotations

import asyncio
import copy
import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

from agentbreak.attacks.engine import AttackEngine
from agentbreak.contracts import (
    AttackCandidate,
    CaseResult,
    CaseSpec,
    DefensePreset,
    EventDraft,
    EventType,
    ExecutionMode,
    ModelSettings,
    ReplayFingerprints,
    RunProgress,
    RunStatus,
    canonical_sha256,
    payload_sha256,
)
from agentbreak.evaluation.metrics import calculate_metrics
from agentbreak.fixtures import (
    list_attack_seeds,
    list_benign_cases,
    list_scenarios,
    load_snapshot,
)
from agentbreak.llm import (
    DeterministicFixtureAttackerClient,
    DeterministicFixtureTargetClient,
    LiveAnthropicModelClient,
)
from agentbreak.sandbox.runner import TargetRunner
from agentbreak.storage.db import Database
from agentbreak.storage.sink import PersistentEventSink

logger = logging.getLogger("agentbreak.orchestrator")

MAX_QUEUED_RUNS = 4
MAX_ACTIVE_RUNS = 1


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class QueueFullError(Exception):
    pass


class InvalidTransitionError(Exception):
    pass


class Orchestrator:
    """Manages the run queue, execution lifecycle, and retests."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._queue: asyncio.Queue[UUID] | None = None
        self.cancellation_events: dict[UUID, asyncio.Event] = {}
        self.active_runs: set[UUID] = set()
        self._worker_task: asyncio.Task[None] | None = None

    @property
    def queue(self) -> asyncio.Queue[UUID]:
        if self._queue is None:
            self._queue = asyncio.Queue(maxsize=MAX_QUEUED_RUNS)
        return self._queue

    def start(self) -> None:
        self.db.mark_unfinished_interrupted()
        try:
            loop = asyncio.get_running_loop()
            if self._queue is not None and getattr(self._queue, "_loop", None) not in (None, loop):
                self._queue = asyncio.Queue(maxsize=MAX_QUEUED_RUNS)
        except RuntimeError:
            pass
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._worker_loop())

    async def stop(self) -> None:
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
        self._queue = None

    def enqueue(self, run_id: UUID) -> None:
        """Enqueue a run ID, raising QueueFullError if queue is full."""
        try:
            self.queue.put_nowait(run_id)
            self.cancellation_events[run_id] = asyncio.Event()
        except asyncio.QueueFull as exc:
            raise QueueFullError("Queue capacity reached.") from exc

    def cancel(self, run_id: UUID) -> RunStatus:
        """Request cooperative cancellation of a run."""
        summary = self.db.get_run_summary(run_id)
        if not summary:
            raise KeyError("Run not found.")
        if summary.status in (
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
            RunStatus.INTERRUPTED,
        ):
            raise InvalidTransitionError("Run is already in a terminal state.")

        if run_id in self.cancellation_events:
            self.cancellation_events[run_id].set()

        # If queued and not active yet, cancel immediately
        if summary.status == RunStatus.QUEUED and run_id not in self.active_runs:
            now = _now_utc()
            self.db.update_run(
                run_id,
                status=RunStatus.CANCELLED,
                completed_at=now,
            )
            return RunStatus.CANCELLED

        return RunStatus.CANCELLED

    async def _worker_loop(self) -> None:
        while True:
            run_id = await self.queue.get()
            try:
                self.active_runs.add(run_id)
                await self.execute_run(run_id)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Unexpected error in worker loop for run %s", run_id)
            finally:
                self.active_runs.discard(run_id)
                self.cancellation_events.pop(run_id, None)
                self.queue.task_done()

    async def execute_run(self, run_id: UUID) -> None:
        summary = self.db.get_run_summary(run_id)
        if not summary or summary.status != RunStatus.QUEUED:
            return

        cancel_event = self.cancellation_events.get(run_id) or asyncio.Event()
        if cancel_event.is_set():
            self.db.update_run(
                run_id, status=RunStatus.CANCELLED, completed_at=_now_utc()
            )
            return

        # Mark as RUNNING
        self.db.update_run(run_id, status=RunStatus.RUNNING)
        event_sink = PersistentEventSink(run_id, self.db)

        # Emit RUN_STARTED
        await event_sink(
            EventDraft(
                type=EventType.RUN_STARTED,
                data={
                    "run_id": str(run_id),
                    "operation": summary.request.operation,
                    "defense": summary.request.defense.value,
                    "execution_mode": summary.request.execution_mode.value,
                },
            )
        )

        # Select model clients
        if summary.request.execution_mode == ExecutionMode.FIXTURE:
            target_model = DeterministicFixtureTargetClient()
            attacker_model = DeterministicFixtureAttackerClient()
            model_settings = ModelSettings(
                provider="fixture",
                target_model_id="fixture-target",
                attacker_model_id="fixture-attacker",
            )
        else:
            import os

            target_id = os.environ.get("TARGET_MODEL_ID", "claude-3-5-sonnet-20241022")
            attacker_id = os.environ.get("ATTACKER_MODEL_ID", "claude-3-5-haiku-20241022")
            target_model = LiveAnthropicModelClient()
            attacker_model = LiveAnthropicModelClient()
            model_settings = ModelSettings(
                provider="anthropic",
                target_model_id=target_id,
                attacker_model_id=attacker_id,
            )

        policy_version = (
            "gateway_v1"
            if summary.request.defense == DefensePreset.GATEWAY
            else "baseline_v1"
        )
        policy_hash = payload_sha256(policy_version)

        all_results: list[CaseResult] = []
        is_retest = summary.source_run_id is not None

        try:
            async with asyncio.timeout(summary.request.budget.run_timeout_s):
                if is_retest:
                    await self._execute_retest_phases(
                        run_id=run_id,
                        summary=summary,
                        target_model=target_model,
                        model_settings=model_settings,
                        policy_version=policy_version,
                        policy_hash=policy_hash,
                        event_sink=event_sink,
                        cancel_event=cancel_event,
                        all_results=all_results,
                    )
                elif summary.request.operation == "suite":
                    await self._execute_suite_phases(
                        run_id=run_id,
                        summary=summary,
                        target_model=target_model,
                        model_settings=model_settings,
                        policy_version=policy_version,
                        policy_hash=policy_hash,
                        event_sink=event_sink,
                        cancel_event=cancel_event,
                        all_results=all_results,
                    )
                else:
                    await self._execute_discover_phases(
                        run_id=run_id,
                        summary=summary,
                        target_model=target_model,
                        attacker_model=attacker_model,
                        model_settings=model_settings,
                        policy_version=policy_version,
                        policy_hash=policy_hash,
                        event_sink=event_sink,
                        cancel_event=cancel_event,
                        all_results=all_results,
                    )

            if cancel_event.is_set():
                now = _now_utc()
                metrics = calculate_metrics(all_results)
                progress = RunProgress(
                    scheduled=summary.progress.scheduled,
                    completed=len(all_results),
                    failed=summary.progress.scheduled - len(all_results),
                    phase="done",
                )
                self.db.update_run(
                    run_id,
                    status=RunStatus.CANCELLED,
                    completed_at=now,
                    progress=progress,
                    metrics=metrics,
                )
                await event_sink(
                    EventDraft(
                        type=EventType.RUN_CANCELLED,
                        data={"run_id": str(run_id)},
                    )
                )
                return

            # Completed normally
            now = _now_utc()
            metrics = calculate_metrics(all_results)
            progress = RunProgress(
                scheduled=len(all_results),
                completed=len(all_results),
                failed=0,
                phase="done",
            )
            self.db.update_run(
                run_id,
                status=RunStatus.COMPLETED,
                completed_at=now,
                progress=progress,
                metrics=metrics,
            )
            await event_sink(
                EventDraft(
                    type=EventType.RUN_COMPLETED,
                    data={"run_id": str(run_id), "status": "completed"},
                )
            )

        except (asyncio.CancelledError, TimeoutError) as exc:
            now = _now_utc()
            metrics = calculate_metrics(all_results)
            err_msg = "run_timeout" if isinstance(exc, TimeoutError) else "run_cancelled"
            status = RunStatus.FAILED if isinstance(exc, TimeoutError) else RunStatus.CANCELLED
            progress = RunProgress(
                scheduled=summary.progress.scheduled or len(all_results),
                completed=len(all_results),
                failed=(summary.progress.scheduled or len(all_results)) - len(all_results),
                phase="done",
            )
            self.db.update_run(
                run_id,
                status=status,
                completed_at=now,
                progress=progress,
                metrics=metrics,
                error=err_msg,
            )
            ev_type = EventType.RUN_ERROR if isinstance(exc, TimeoutError) else EventType.RUN_CANCELLED
            await event_sink(
                EventDraft(
                    type=ev_type,
                    data={"run_id": str(run_id), "error": err_msg},
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Execution failed for run %s", run_id)
            now = _now_utc()
            metrics = calculate_metrics(all_results)
            progress = RunProgress(
                scheduled=summary.progress.scheduled or len(all_results),
                completed=len(all_results),
                failed=(summary.progress.scheduled or len(all_results)) - len(all_results),
                phase="done",
            )
            self.db.update_run(
                run_id,
                status=RunStatus.FAILED,
                completed_at=now,
                progress=progress,
                metrics=metrics,
                error=f"{type(exc).__name__}: {exc}",
            )
            await event_sink(
                EventDraft(
                    type=EventType.RUN_ERROR,
                    data={"run_id": str(run_id), "error": str(exc)},
                )
            )

    async def _execute_suite_phases(
        self,
        *,
        run_id: UUID,
        summary: Any,
        target_model: Any,
        model_settings: ModelSettings,
        policy_version: str,
        policy_hash: str,
        event_sink: PersistentEventSink,
        cancel_event: asyncio.Event,
        all_results: list[CaseResult],
    ) -> None:
        benign_cases = list_benign_cases()
        held_out_seeds = list_attack_seeds("held_out")
        total_scheduled = len(benign_cases) + len(held_out_seeds)

        progress = RunProgress(
            scheduled=total_scheduled,
            completed=0,
            failed=0,
            phase="benign",
        )
        self.db.update_run(run_id, progress=progress)

        runner = TargetRunner(target_model)

        # Phase 1: 8 Clean tasks
        for b_case in benign_cases:
            if cancel_event.is_set():
                return
            spec = CaseSpec(
                run_id=run_id,
                trial_id=uuid4(),
                scenario=b_case.scenario,
                candidate=None,
                defense=summary.request.defense,
                execution_mode=summary.request.execution_mode,
                fixture_snapshot=load_snapshot(b_case.scenario.fixture_id),
                budget=summary.request.budget,
                seed=summary.request.seed,
                model_settings=model_settings,
                policy_version=policy_version,
            )
            result = await runner.run_case(spec, event_sink)
            fingerprints = ReplayFingerprints(
                fixture_sha256=canonical_sha256(spec.fixture_snapshot),
                model_settings_sha256=canonical_sha256(spec.model_settings),
                policy_sha256=policy_hash,
            )
            self.db.save_case(spec, result, fingerprints)
            all_results.append(result)
            progress.completed += 1
            self.db.update_run(run_id, progress=progress)

        # Phase 2: 8 Held-out attack seeds
        progress.phase = "attack"
        self.db.update_run(run_id, progress=progress)

        scenarios_by_id = {s.id: s for s in list_scenarios()}
        for seed in held_out_seeds:
            if cancel_event.is_set():
                return
            scenario = scenarios_by_id[seed.candidate.scenario_id]
            spec = CaseSpec(
                run_id=run_id,
                trial_id=uuid4(),
                scenario=scenario,
                candidate=seed.candidate,
                defense=summary.request.defense,
                execution_mode=summary.request.execution_mode,
                fixture_snapshot=load_snapshot(scenario.fixture_id),
                budget=summary.request.budget,
                seed=summary.request.seed,
                model_settings=model_settings,
                policy_version=policy_version,
            )
            result = await runner.run_case(spec, event_sink)
            fingerprints = ReplayFingerprints(
                fixture_sha256=canonical_sha256(spec.fixture_snapshot),
                model_settings_sha256=canonical_sha256(spec.model_settings),
                policy_sha256=policy_hash,
            )
            self.db.save_case(spec, result, fingerprints)
            all_results.append(result)
            progress.completed += 1
            self.db.update_run(run_id, progress=progress)

    async def _execute_discover_phases(
        self,
        *,
        run_id: UUID,
        summary: Any,
        target_model: Any,
        attacker_model: Any,
        model_settings: ModelSettings,
        policy_version: str,
        policy_hash: str,
        event_sink: PersistentEventSink,
        cancel_event: asyncio.Event,
        all_results: list[CaseResult],
    ) -> None:
        benign_cases = list_benign_cases()
        selected_scenario_ids = summary.request.scenario_ids
        scenarios_by_id = {s.id: s for s in list_scenarios()}

        total_scheduled = len(benign_cases) + (
            len(selected_scenario_ids) * summary.request.budget.max_candidates
        )
        progress = RunProgress(
            scheduled=total_scheduled,
            completed=0,
            failed=0,
            phase="benign",
        )
        self.db.update_run(run_id, progress=progress)

        runner = TargetRunner(target_model)

        # Phase 1: 8 Clean tasks
        for b_case in benign_cases:
            if cancel_event.is_set():
                return
            spec = CaseSpec(
                run_id=run_id,
                trial_id=uuid4(),
                scenario=b_case.scenario,
                candidate=None,
                defense=summary.request.defense,
                execution_mode=summary.request.execution_mode,
                fixture_snapshot=load_snapshot(b_case.scenario.fixture_id),
                budget=summary.request.budget,
                seed=summary.request.seed,
                model_settings=model_settings,
                policy_version=policy_version,
            )
            result = await runner.run_case(spec, event_sink)
            fingerprints = ReplayFingerprints(
                fixture_sha256=canonical_sha256(spec.fixture_snapshot),
                model_settings_sha256=canonical_sha256(spec.model_settings),
                policy_sha256=policy_hash,
            )
            self.db.save_case(spec, result, fingerprints)
            all_results.append(result)
            progress.completed += 1
            self.db.update_run(run_id, progress=progress)

        # Phase 2: Adaptive discovery per scenario
        progress.phase = "attack"
        self.db.update_run(run_id, progress=progress)

        engine = AttackEngine(attacker_model, model_settings=model_settings)

        for scenario_id in selected_scenario_ids:
            if cancel_event.is_set():
                return
            scenario = scenarios_by_id[scenario_id]

            async def execute_case(candidate: AttackCandidate) -> CaseResult:
                if cancel_event.is_set():
                    raise asyncio.CancelledError("Run was cancelled.")
                fresh_snapshot = load_snapshot(scenario.fixture_id)
                trial_id = uuid4()
                spec = CaseSpec(
                    run_id=run_id,
                    trial_id=trial_id,
                    scenario=scenario,
                    candidate=candidate,
                    defense=summary.request.defense,
                    execution_mode=summary.request.execution_mode,
                    fixture_snapshot=fresh_snapshot,
                    budget=summary.request.budget,
                    seed=summary.request.seed,
                    model_settings=model_settings,
                    policy_version=policy_version,
                )
                res = await runner.run_case(spec, event_sink)
                fingerprints = ReplayFingerprints(
                    fixture_sha256=canonical_sha256(spec.fixture_snapshot),
                    model_settings_sha256=canonical_sha256(spec.model_settings),
                    policy_sha256=policy_hash,
                )
                self.db.save_case(spec, res, fingerprints)
                all_results.append(res)
                progress.completed += 1
                self.db.update_run(run_id, progress=progress)
                return res

            await engine.discover(
                scenario=scenario,
                budget=summary.request.budget,
                seed=summary.request.seed,
                execute_case=execute_case,
                emit=event_sink,
            )

    async def _execute_retest_phases(
        self,
        *,
        run_id: UUID,
        summary: Any,
        target_model: Any,
        model_settings: ModelSettings,
        policy_version: str,
        policy_hash: str,
        event_sink: PersistentEventSink,
        cancel_event: asyncio.Event,
        all_results: list[CaseResult],
    ) -> None:
        source_run_id = summary.source_run_id
        orig_cases = self.db.get_replay_cases(source_run_id)

        clean_orig = [c for c in orig_cases if c.spec.candidate is None]
        attack_orig = [c for c in orig_cases if c.spec.candidate is not None]

        total_scheduled = len(clean_orig) + len(attack_orig)
        progress = RunProgress(
            scheduled=total_scheduled,
            completed=0,
            failed=0,
            phase="retest",
        )
        self.db.update_run(run_id, progress=progress)

        runner = TargetRunner(target_model)

        # 1. Clean cases replay if present
        for rc in clean_orig:
            if cancel_event.is_set():
                return
            spec = CaseSpec(
                run_id=run_id,
                trial_id=uuid4(),
                scenario=rc.spec.scenario,
                candidate=None,
                defense=summary.request.defense,
                execution_mode=summary.request.execution_mode,
                fixture_snapshot=load_snapshot(rc.spec.scenario.fixture_id),
                budget=summary.request.budget,
                seed=summary.request.seed,
                model_settings=model_settings,
                policy_version=policy_version,
            )
            result = await runner.run_case(spec, event_sink)
            fingerprints = ReplayFingerprints(
                fixture_sha256=canonical_sha256(spec.fixture_snapshot),
                model_settings_sha256=canonical_sha256(spec.model_settings),
                policy_sha256=policy_hash,
            )
            self.db.save_case(spec, result, fingerprints)
            all_results.append(result)
            progress.completed += 1
            self.db.update_run(run_id, progress=progress)

        # 2. Attack cases replay with gateway
        for rc in attack_orig:
            if cancel_event.is_set():
                return
            spec = CaseSpec(
                run_id=run_id,
                trial_id=uuid4(),
                scenario=rc.spec.scenario,
                candidate=rc.spec.candidate,
                defense=summary.request.defense,
                execution_mode=summary.request.execution_mode,
                fixture_snapshot=load_snapshot(rc.spec.scenario.fixture_id),
                budget=summary.request.budget,
                seed=summary.request.seed,
                model_settings=model_settings,
                policy_version=policy_version,
            )
            result = await runner.run_case(spec, event_sink)
            fingerprints = ReplayFingerprints(
                fixture_sha256=canonical_sha256(spec.fixture_snapshot),
                model_settings_sha256=canonical_sha256(spec.model_settings),
                policy_sha256=policy_hash,
            )
            self.db.save_case(spec, result, fingerprints)
            all_results.append(result)
            progress.completed += 1
            self.db.update_run(run_id, progress=progress)
