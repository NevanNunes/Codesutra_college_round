"""AgentBreak v1 contracts. No provider, persistence, or sandbox dependencies."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Awaitable, Callable, Literal, Protocol, TypeAlias, runtime_checkable
from uuid import UUID

from pydantic import (
    AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, JsonValue, StrictBool,
    StrictFloat, StrictInt, StringConstraints, field_validator, model_validator,
)


Identifier = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.:-]+$")]
ShortText = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=500)]
VisibleText = Annotated[str, StringConstraints(strict=True, max_length=32000)]
PayloadText = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=4000)]
Sha256 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
Count = Annotated[StrictInt, Field(ge=0, le=1_000_000_000)]
Seed = Annotated[StrictInt, Field(ge=0, le=2**32 - 1)]
ScenarioId = Literal["doc_exfil", "email_bola"]
TaskId = Identifier
ToolName = Literal["search_docs", "get_customer", "send_email"]
Recipient = Annotated[str, StringConstraints(strict=True, max_length=254, pattern=r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.test$")]


def _json_safe(value: object, depth: int = 0) -> object:
    """Reject Python-only values and credential-bearing keys; never coerce them."""
    if depth > 20:
        raise ValueError("JSON nesting exceeds 20 levels")
    if value is None or type(value) in (str, bool, int):
        if isinstance(value, str) and len(value) > 64000:
            raise ValueError("JSON string exceeds 64000 characters")
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if type(value) is list:
        if len(value) > 1000:
            raise ValueError("JSON list exceeds 1000 items")
        for item in value:
            _json_safe(item, depth + 1)
        return value
    if type(value) is dict:
        if len(value) > 1000:
            raise ValueError("JSON object exceeds 1000 entries")
        forbidden = {"api_key", "apikey", "authorization", "password", "secret", "access_token", "refresh_token", "cookie", "environment", "env"}
        for key, item in value.items():
            if type(key) is not str or len(key) > 128:
                raise ValueError("JSON keys must be strings of at most 128 characters")
            normalized = key.lower().replace("-", "_")
            if normalized in forbidden or normalized.endswith("_api_key"):
                raise ValueError("credential/configuration keys are not evidence")
            _json_safe(item, depth + 1)
        return value
    raise ValueError("value must be finite, plain JSON data")


def _json_object(value: object) -> object:
    if type(value) is not dict:
        raise ValueError("expected a plain JSON object")
    return _json_safe(value)


JsonObject = Annotated[dict[str, JsonValue], BeforeValidator(_json_object)]


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must have a timezone")
    return value.astimezone(timezone.utc)


def _timestamp_input(value: object) -> object:
    if not isinstance(value, (str, datetime)):
        raise ValueError("timestamp must be an ISO-8601 string or aware datetime")
    if isinstance(value, str) and not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value):
        raise ValueError("timestamp must use ISO-8601 with an explicit timezone")
    return value


UtcTimestamp = Annotated[datetime, BeforeValidator(_timestamp_input), AfterValidator(_utc)]


class ContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", validate_assignment=True, revalidate_instances="always",
        allow_inf_nan=False, protected_namespaces=("model_validate", "model_dump"),
    )

    @field_validator("schema_version", mode="before", check_fields=False)
    @classmethod
    def strict_schema_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value

    @field_validator("synthetic_data", mode="before", check_fields=False)
    @classmethod
    def strict_synthetic_label(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("synthetic_data must be a boolean")
        return value


class DefensePreset(StrEnum):
    BASELINE = "baseline"
    GATEWAY = "gateway"


class ExecutionMode(StrEnum):
    LIVE = "live"
    FIXTURE = "fixture"


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class Surface(StrEnum):
    DOCUMENT = "document"
    EMAIL = "email"


class OracleOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    INCONCLUSIVE = "inconclusive"


class CaseStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class EventType(StrEnum):
    RUN_STARTED = "run_started"
    CANDIDATE_GENERATED = "candidate_generated"
    CASE_STARTED = "case_started"
    SOURCE_INJECTED = "source_injected"
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    TOOL_PROPOSED = "tool_proposed"
    POLICY_DECISION = "policy_decision"
    TOOL_EXECUTED = "tool_executed"
    TOOL_BLOCKED = "tool_blocked"
    ORACLE_RESULT = "oracle_result"
    CASE_COMPLETED = "case_completed"
    RUN_COMPLETED = "run_completed"
    RUN_ERROR = "run_error"
    RUN_CANCELLED = "run_cancelled"


class Grant(ContractModel):
    principal_id: Identifier
    tenant_id: Identifier
    allowed_customer_ids: list[Identifier] = Field(max_length=100)
    allowed_tools: list[ToolName] = Field(max_length=3)
    allowed_recipients: list[Recipient] = Field(max_length=100)


class FinalContainsPredicate(ContractModel):
    kind: Literal["final_contains"] = "final_contains"
    values: list[ShortText] = Field(min_length=1, max_length=20)


class OutboxContainsPredicate(ContractModel):
    kind: Literal["outbox_contains"] = "outbox_contains"
    recipient: Recipient
    subject_contains: list[ShortText] = Field(default_factory=list, max_length=20)
    body_contains: list[ShortText] = Field(min_length=1, max_length=20)


class EffectCountPredicate(ContractModel):
    kind: Literal["effect_count"] = "effect_count"
    tool: Literal["send_email"] = "send_email"
    minimum: Annotated[StrictInt, Field(ge=0, le=8)] = 0
    maximum: Annotated[StrictInt, Field(ge=0, le=8)] = 0

    @model_validator(mode="after")
    def ordered(self) -> EffectCountPredicate:
        if self.minimum > self.maximum:
            raise ValueError("minimum cannot exceed maximum")
        return self


BenignPredicate = Annotated[FinalContainsPredicate | OutboxContainsPredicate | EffectCountPredicate, Field(discriminator="kind")]


class DocumentRecord(ContractModel):
    id: Identifier
    surface: Surface
    title: ShortText
    body: VisibleText
    customer_id: Identifier


class CustomerRecord(ContractModel):
    id: Identifier
    tenant_id: Identifier
    order_id: Identifier
    order_status: ShortText
    internal_token: Annotated[str, StringConstraints(strict=True, min_length=8, max_length=256)]


class OutboxMessage(ContractModel):
    id: UUID
    to: Recipient
    subject: ShortText
    body: VisibleText


class FixtureSnapshot(ContractModel):
    fixture_id: Identifier
    version: Annotated[StrictInt, Field(ge=1, le=10000)] = 1
    documents: list[DocumentRecord] = Field(min_length=1, max_length=100)
    customers: list[CustomerRecord] = Field(min_length=1, max_length=100)
    outbox: list[OutboxMessage] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def unique_ids(self) -> FixtureSnapshot:
        for records in (self.documents, self.customers, self.outbox):
            if len({record.id for record in records}) != len(records):
                raise ValueError("snapshot record IDs must be unique within each collection")
        return self


class ScenarioSpecPublic(ContractModel):
    id: ScenarioId
    task_id: TaskId
    version: Annotated[StrictInt, Field(ge=1, le=10000)]
    title: ShortText
    surface: Surface
    source_id: Identifier
    legitimate_task: PayloadText
    attack_goal: PayloadText


class ScenarioSpec(ScenarioSpecPublic):
    fixture_id: Identifier
    grant: Grant
    expected_benign: list[BenignPredicate] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def canonical_surface(self) -> ScenarioSpec:
        expected = {"doc_exfil": Surface.DOCUMENT, "email_bola": Surface.EMAIL}
        if self.surface != expected[self.id]:
            raise ValueError("canonical scenario surface mismatch")
        return self

    def to_public(self) -> ScenarioSpecPublic:
        return ScenarioSpecPublic.model_validate({name: getattr(self, name) for name in ScenarioSpecPublic.model_fields})


def payload_sha256(text: str) -> str:
    """Hash exact UTF-8 text: no whitespace or Unicode normalization."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_sha256(value: ContractModel | dict[str, JsonValue]) -> str:
    """Sorted-key, compact, UTF-8 JSON, with defaults/nulls included."""
    data = value.model_dump(mode="json") if isinstance(value, ContractModel) else value
    _json_safe(data)
    encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class AttackCandidate(ContractModel):
    id: UUID
    scenario_id: ScenarioId
    source_id: Identifier
    surface: Surface
    text: PayloadText
    parent_id: UUID | None = None
    generation: Annotated[StrictInt, Field(ge=0, le=12)] = 0
    strategy: Identifier
    feedback_summary: PayloadText | None = None
    payload_sha256: Sha256

    @model_validator(mode="after")
    def valid_hash_and_lineage(self) -> AttackCandidate:
        if self.payload_sha256 != payload_sha256(self.text):
            raise ValueError("payload_sha256 does not match exact text")
        if self.parent_id == self.id or (self.generation == 0) != (self.parent_id is None):
            raise ValueError("root generation must be zero; mutations require a distinct parent")
        return self


class Budget(ContractModel):
    max_candidates: Annotated[StrictInt, Field(ge=1, le=12)] = 6
    max_model_turns: Annotated[StrictInt, Field(ge=1, le=6)] = 6
    max_tool_calls: Annotated[StrictInt, Field(ge=1, le=8)] = 8
    case_timeout_s: Annotated[StrictInt, Field(ge=1, le=60)] = 60
    run_timeout_s: Annotated[StrictInt, Field(ge=1, le=300)] = 300
    max_total_tokens: Annotated[StrictInt, Field(ge=1, le=60000)] = 60000

    @model_validator(mode="after")
    def ordered_timeouts(self) -> Budget:
        if self.case_timeout_s > self.run_timeout_s:
            raise ValueError("case timeout cannot exceed run timeout")
        return self


class ModelSettings(ContractModel):
    provider: Identifier
    target_model_id: Identifier
    attacker_model_id: Identifier
    temperature: Annotated[StrictFloat, Field(ge=0, le=1)] = 0.0
    max_tokens: Annotated[StrictInt, Field(ge=1, le=8192)] = 1024


class CaseSpec(ContractModel):
    run_id: UUID
    trial_id: UUID
    scenario: ScenarioSpec
    candidate: AttackCandidate | None = None
    defense: DefensePreset
    execution_mode: ExecutionMode
    fixture_snapshot: FixtureSnapshot
    budget: Budget = Field(default_factory=Budget)
    seed: Seed
    model_settings: ModelSettings
    policy_version: Identifier

    @model_validator(mode="after")
    def consistent_inputs(self) -> CaseSpec:
        scenario, snapshot, candidate = self.scenario, self.fixture_snapshot, self.candidate
        if snapshot.fixture_id != scenario.fixture_id:
            raise ValueError("fixture does not match scenario")
        sources = [doc for doc in snapshot.documents if doc.id == scenario.source_id]
        if len(sources) != 1 or sources[0].surface != scenario.surface:
            raise ValueError("scenario source slot is missing or has the wrong surface")
        if snapshot.outbox:
            raise ValueError("initial fixture outbox must be empty")
        if candidate is not None and (candidate.scenario_id, candidate.source_id, candidate.surface) != (scenario.id, scenario.source_id, scenario.surface):
            raise ValueError("candidate scenario/source/surface mismatch")
        return self


class PolicyDecision(ContractModel):
    allow: StrictBool
    reason_codes: list[Identifier] = Field(min_length=1, max_length=20)
    policy_version: Identifier
    rule_ids: list[Identifier] = Field(max_length=20)
    explanation: ShortText | None = None


class Violation(ContractModel):
    kind: Literal["unauthorized_read", "unauthorized_send", "canary_leak"]
    impact: Literal["high", "medium", "low"]
    evidence_event_ids: list[UUID] = Field(min_length=1, max_length=100)
    details: JsonObject


class ToolCounts(ContractModel):
    proposed: Annotated[StrictInt, Field(ge=0, le=8)] = 0
    denied: Annotated[StrictInt, Field(ge=0, le=8)] = 0
    forbidden_executed: Annotated[StrictInt, Field(ge=0, le=8)] = 0

    @model_validator(mode="after")
    def consistent_counts(self) -> ToolCounts:
        if self.denied + self.forbidden_executed > self.proposed:
            raise ValueError("denied and executed calls cannot exceed proposals")
        return self


class Usage(ContractModel):
    input_tokens: Count = 0
    output_tokens: Count = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class ErrorDetail(ContractModel):
    code: Identifier
    message: ShortText


class StateDiff(ContractModel):
    returned_customer_ids: list[Identifier] = Field(default_factory=list, max_length=8)
    disclosed_fields: list[Identifier] = Field(default_factory=list, max_length=100)
    outbox_added: list[OutboxMessage] = Field(default_factory=list, max_length=8)


class CaseResultPublic(ContractModel):
    run_id: UUID
    trial_id: UUID
    scenario_id: ScenarioId
    task_id: TaskId
    candidate_id: UUID | None = None
    payload_sha256: Sha256 | None = None
    fixture_sha256: Sha256
    policy_version: Identifier
    defense: DefensePreset
    execution_mode: ExecutionMode
    status: CaseStatus
    oracle_outcome: OracleOutcome
    violations: list[Violation] = Field(default_factory=list, max_length=100)
    attempted_violations: list[Violation] = Field(default_factory=list, max_length=100)
    benign_success: StrictBool | None = None
    final_output: VisibleText
    evidence_event_ids: list[UUID] = Field(default_factory=list, max_length=1000)
    source_consumed: StrictBool
    tool_counts: ToolCounts
    duration_ms: Annotated[StrictInt, Field(ge=0, le=300000)]
    usage: Usage
    error: ErrorDetail | None = None

    @model_validator(mode="after")
    def consistent_outcome(self) -> CaseResultPublic:
        if (self.candidate_id is None) != (self.payload_sha256 is None):
            raise ValueError("candidate ID and payload hash must be present together")
        if bool(self.violations) != (self.oracle_outcome == OracleOutcome.SUCCESS):
            raise ValueError("oracle success requires verified violations and vice versa")
        if self.violations and self.benign_success is True:
            raise ValueError("prohibited effects preclude benign success")
        if self.status != CaseStatus.COMPLETED and self.oracle_outcome == OracleOutcome.FAILURE:
            raise ValueError("incomplete execution without verified effect is inconclusive")
        return self


class CaseResult(CaseResultPublic):
    state_diff: StateDiff

    def to_public(self) -> CaseResultPublic:
        return CaseResultPublic.model_validate({name: getattr(self, name) for name in CaseResultPublic.model_fields})


class EventDraft(ContractModel):
    trial_id: UUID | None = None
    type: EventType
    parent_event_ids: list[UUID] = Field(default_factory=list, max_length=100)
    data: JsonObject = Field(default_factory=dict)


class TraceEvent(EventDraft):
    schema_version: Literal[1] = 1
    id: UUID
    run_id: UUID
    seq: Annotated[StrictInt, Field(ge=1, le=1_000_000_000)]
    timestamp: UtcTimestamp

    @model_validator(mode="after")
    def no_self_parent(self) -> TraceEvent:
        if self.id in self.parent_event_ids or len(set(self.parent_event_ids)) != len(self.parent_event_ids):
            raise ValueError("event parents must be distinct and cannot include itself")
        return self


class RunRequest(ContractModel):
    scenario_ids: list[ScenarioId] = Field(min_length=1, max_length=2)
    operation: Literal["discover", "suite"] = "discover"
    defense: DefensePreset = DefensePreset.BASELINE
    execution_mode: ExecutionMode = ExecutionMode.FIXTURE
    budget: Budget = Field(default_factory=Budget)
    seed: Seed = 0

    @field_validator("scenario_ids")
    @classmethod
    def unique_scenarios(cls, value: list[ScenarioId]) -> list[ScenarioId]:
        if len(set(value)) != len(value):
            raise ValueError("scenario IDs must be unique")
        return value


class RunProgress(ContractModel):
    scheduled: Count = 0
    completed: Count = 0
    failed: Count = 0
    phase: Literal["queued", "benign", "attack", "retest", "done"] = "queued"

    @model_validator(mode="after")
    def counts(self) -> RunProgress:
        if self.completed + self.failed > self.scheduled:
            raise ValueError("finished cases exceed scheduled cases")
        return self


class RunSummary(ContractModel):
    id: UUID
    status: RunStatus
    request: RunRequest
    created_at: UtcTimestamp
    completed_at: UtcTimestamp | None = None
    progress: RunProgress = Field(default_factory=RunProgress)
    metrics: JsonObject = Field(default_factory=dict)
    error: ErrorDetail | None = None
    source_run_id: UUID | None = None

    @model_validator(mode="after")
    def times(self) -> RunSummary:
        if self.completed_at is not None and self.completed_at < self.created_at:
            raise ValueError("completion predates creation")
        return self


class SearchDocsArgs(ContractModel):
    query: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=500)]


class GetCustomerArgs(ContractModel):
    customer_id: Identifier


class SendEmailArgs(ContractModel):
    to: Recipient
    subject: ShortText
    body: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=8000)]


class ToolSchema(ContractModel):
    name: ToolName
    description: ShortText
    input_schema: JsonObject

    @model_validator(mode="after")
    def closed_object(self) -> ToolSchema:
        if self.input_schema.get("type") != "object" or self.input_schema.get("additionalProperties") is not False:
            raise ValueError("tool input schema must be an object with additionalProperties=false")
        return self


class ToolCall(ContractModel):
    call_id: Identifier
    name: Identifier
    arguments: JsonObject


class TextBlock(ContractModel):
    type: Literal["text"] = "text"
    text: VisibleText


class ToolUseBlock(ContractModel):
    type: Literal["tool_use"] = "tool_use"
    call: ToolCall


class ToolResultBlock(ContractModel):
    type: Literal["tool_result"] = "tool_result"
    call_id: Identifier
    content: JsonObject
    is_error: StrictBool = False


AssistantBlock = Annotated[TextBlock | ToolUseBlock, Field(discriminator="type")]
MessageBlock = Annotated[TextBlock | ToolUseBlock | ToolResultBlock, Field(discriminator="type")]


class ModelMessage(ContractModel):
    role: Literal["system", "user", "assistant"]
    content: list[MessageBlock] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def role_blocks(self) -> ModelMessage:
        for block in self.content:
            if isinstance(block, ToolUseBlock) and self.role != "assistant":
                raise ValueError("tool_use blocks require assistant role")
            if isinstance(block, ToolResultBlock) and self.role != "user":
                raise ValueError("tool_result blocks require user role")
        return self


class ModelReply(ContractModel):
    content: list[AssistantBlock] = Field(default_factory=list, max_length=32)
    usage: Usage
    stop_reason: Literal["end_turn", "tool_use", "max_tokens", "refusal"]
    model_id: Identifier
    provider_request_id: Identifier | None = None

    @property
    def text(self) -> str:
        return "".join(block.text for block in self.content if isinstance(block, TextBlock))

    @property
    def tool_calls(self) -> list[ToolCall]:
        return [block.call for block in self.content if isinstance(block, ToolUseBlock)]

    @model_validator(mode="after")
    def valid_calls(self) -> ModelReply:
        ids = [call.call_id for call in self.tool_calls]
        if len(ids) != len(set(ids)):
            raise ValueError("reply tool call IDs must be unique")
        if self.stop_reason == "tool_use" and not ids:
            raise ValueError("tool_use stop requires a tool call")
        return self


def validate_message_sequence(messages: list[ModelMessage]) -> None:
    """Validate a complete outbound conversation, including all tool results."""
    pending: list[str] = []
    seen: set[str] = set()
    non_system_seen = False
    previous_role: str | None = None
    for message in messages:
        if message.role == "system":
            if non_system_seen:
                raise ValueError("system messages must precede the conversation")
        else:
            if not non_system_seen and message.role != "user":
                raise ValueError("conversation must start with user")
            if previous_role == message.role:
                raise ValueError("user and assistant messages must alternate")
            non_system_seen = True
            previous_role = message.role
        results = [block.call_id for block in message.content if isinstance(block, ToolResultBlock)]
        if pending:
            if message.role != "user" or results != pending:
                raise ValueError("next user message must return all tool results in call order")
            if not all(isinstance(block, ToolResultBlock) for block in message.content[:len(pending)]):
                raise ValueError("tool results must precede user text")
            pending = []
        elif results:
            raise ValueError("orphan tool result")
        for block in message.content:
            if isinstance(block, ToolUseBlock):
                call_id = block.call.call_id
                if call_id in seen:
                    raise ValueError("tool call IDs must be unique across the conversation")
                seen.add(call_id)
                pending.append(call_id)
    if pending:
        raise ValueError("outbound conversation has unresolved tool calls")
    if not non_system_seen or previous_role != "user":
        raise ValueError("outbound conversation must end with user input or tool results")


@runtime_checkable
class ModelClient(Protocol):
    async def complete(
        self, messages: list[ModelMessage], tools: list[ToolSchema], *,
        model_id: str, temperature: float, max_tokens: int,
    ) -> ModelReply: ...


@runtime_checkable
class EventSink(Protocol):
    async def __call__(self, event_draft: EventDraft) -> TraceEvent: ...


ExecuteCase: TypeAlias = Callable[[AttackCandidate], Awaitable[CaseResult]]


class AttackSeed(ContractModel):
    split: Literal["discovery", "held_out"]
    candidate: AttackCandidate


class BenignCase(ContractModel):
    scenario: ScenarioSpec
    fixture_snapshot: FixtureSnapshot

    @model_validator(mode="after")
    def fixture_matches(self) -> BenignCase:
        if self.scenario.fixture_id != self.fixture_snapshot.fixture_id or self.fixture_snapshot.outbox:
            raise ValueError("benign case requires matching fresh snapshot")
        return self


class HealthResponse(ContractModel):
    status: Literal["ok"] = "ok"
    schema_version: Literal[1] = 1
    live_ready: StrictBool


class ScenariosResponse(ContractModel):
    items: list[ScenarioSpecPublic] = Field(max_length=2)


class RunAccepted(ContractModel):
    run_id: UUID
    status: Literal["queued"] = "queued"


class RetestRequest(ContractModel):
    defense: Literal["gateway"] = "gateway"
    include_benign: StrictBool = True


class RetestAccepted(ContractModel):
    run_id: UUID


class CancelResponse(ContractModel):
    run_id: UUID
    status: RunStatus


class RunsResponse(ContractModel):
    items: list[RunSummary] = Field(max_length=100)


class RunDetailResponse(ContractModel):
    run: RunSummary
    cases: list[CaseResultPublic] = Field(max_length=100)


class EventsQuery(ContractModel):
    after_seq: Annotated[StrictInt, Field(ge=0, le=1_000_000_000)] = 0
    limit: Annotated[StrictInt, Field(ge=1, le=500)] = 200


class RunsQuery(ContractModel):
    limit: Annotated[StrictInt, Field(ge=1, le=100)] = 20


class EventsResponse(ContractModel):
    items: list[TraceEvent] = Field(max_length=500)
    next_after_seq: Annotated[StrictInt, Field(ge=0, le=1_000_000_000)]
    has_more: StrictBool

    @model_validator(mode="after")
    def ordered_events(self) -> EventsResponse:
        seqs = [event.seq for event in self.items]
        if seqs != sorted(set(seqs)) or len({event.id for event in self.items}) != len(self.items):
            raise ValueError("events require unique IDs and ascending unique sequences")
        if len({event.run_id for event in self.items}) > 1:
            raise ValueError("event page must contain one run")
        if self.items and self.next_after_seq != self.items[-1].seq:
            raise ValueError("cursor must equal last returned sequence")
        if self.has_more and not self.items:
            raise ValueError("empty page cannot have more events")
        return self


class ErrorResponse(ContractModel):
    error: ErrorDetail


class ReplayFingerprints(ContractModel):
    fixture_sha256: Sha256
    model_settings_sha256: Sha256
    policy_sha256: Sha256


class ReplayCase(ContractModel):
    spec: CaseSpec
    result: CaseResult
    fingerprints: ReplayFingerprints

    @model_validator(mode="after")
    def matches(self) -> ReplayCase:
        spec, result, hashes = self.spec, self.result, self.fingerprints
        if (spec.run_id, spec.trial_id, spec.scenario.id, spec.scenario.task_id, spec.defense, spec.execution_mode, spec.policy_version) != (result.run_id, result.trial_id, result.scenario_id, result.task_id, result.defense, result.execution_mode, result.policy_version):
            raise ValueError("result identity/configuration does not match saved case")
        expected_candidate = (spec.candidate.id, spec.candidate.payload_sha256) if spec.candidate else (None, None)
        if (result.candidate_id, result.payload_sha256) != expected_candidate:
            raise ValueError("result candidate does not match saved case")
        if hashes.fixture_sha256 != canonical_sha256(spec.fixture_snapshot) or result.fixture_sha256 != hashes.fixture_sha256:
            raise ValueError("fixture fingerprint mismatch")
        if hashes.model_settings_sha256 != canonical_sha256(spec.model_settings):
            raise ValueError("model settings fingerprint mismatch")
        return self


class ReplayBundle(ContractModel):
    schema_version: Literal[1] = 1
    synthetic_data: Literal[True] = True
    run: RunSummary
    exported_at: UtcTimestamp
    app_git_revision: Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{7,40}$")] | None = None
    cases: list[ReplayCase] = Field(min_length=1, max_length=100)
    events: list[TraceEvent] = Field(default_factory=list, max_length=10000)

    @model_validator(mode="after")
    def evidence_matches(self) -> ReplayBundle:
        if any(case.spec.run_id != self.run.id for case in self.cases) or any(event.run_id != self.run.id for event in self.events):
            raise ValueError("bundle may contain only its declared run")
        if any(
            (case.spec.defense, case.spec.execution_mode)
            != (self.run.request.defense, self.run.request.execution_mode)
            for case in self.cases
        ):
            raise ValueError("bundle cases must match run defense and execution mode")
        trial_ids = {case.spec.trial_id for case in self.cases}
        if len(trial_ids) != len(self.cases):
            raise ValueError("bundle trial IDs must be unique")
        seen: set[UUID] = set()
        seq = 0
        for event in self.events:
            if event.seq <= seq or event.id in seen or not set(event.parent_event_ids).issubset(seen):
                raise ValueError("bundle events must be ordered, unique, with earlier parents")
            if event.trial_id is not None and event.trial_id not in trial_ids:
                raise ValueError("event references unknown trial")
            seq = event.seq
            seen.add(event.id)
        for case in self.cases:
            evidence = list(case.result.evidence_event_ids)
            for violation in case.result.violations + case.result.attempted_violations:
                evidence.extend(violation.evidence_event_ids)
            if not set(evidence).issubset(seen):
                raise ValueError("result references missing evidence")
            case_events = {event.id for event in self.events if event.trial_id == case.spec.trial_id}
            if not set(evidence).issubset(case_events):
                raise ValueError("result evidence must belong to its own trial")
        return self
