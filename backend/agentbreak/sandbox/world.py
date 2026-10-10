"""Per-case mutable world: in-memory mock tools, outbox, and an evidence ledger.

Raw handlers here are private: they are only reachable through
:meth:`CaseWorld.execute`, which the runner calls AFTER the gateway allowed a
validated call. Nothing in this module performs network, file or shell access.
Each case builds its own deep-copied world from ``CaseSpec.fixture_snapshot``; the
spec and module-level fixture data are never mutated.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from agentbreak.contracts import (
    CaseSpec, ContractModel, CustomerRecord, DocumentRecord, FixtureSnapshot, OutboxMessage,
)

_OUTBOX_NAMESPACE = uuid.UUID("0c0ffee0-1111-4222-8333-444455556666")
_STOPWORDS = frozenset({"the", "a", "an", "of", "for", "to", "and", "is", "in", "on", "me", "my"})
_MAX_SEARCH_RESULTS = 3


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_]+", text.lower())) - _STOPWORDS


def apply_candidate(spec: CaseSpec) -> FixtureSnapshot:
    """Return a fresh snapshot where ONLY the allowed source document's body is replaced.

    IDs, surface, title, customer_id, trust metadata, customers, grants and expected
    outcomes are untouched. A clean case (no candidate) returns an identical deep copy.
    """
    snapshot = spec.fixture_snapshot.model_copy(deep=True)
    candidate, scenario = spec.candidate, spec.scenario
    if candidate is None:
        return snapshot
    if (candidate.scenario_id, candidate.source_id, candidate.surface) != (
            scenario.id, scenario.source_id, scenario.surface):
        raise ValueError("candidate does not target this scenario's allowed source")
    documents: list[DocumentRecord] = []
    replaced = 0
    for doc in snapshot.documents:
        if doc.id == scenario.source_id:
            documents.append(DocumentRecord(id=doc.id, surface=doc.surface, title=doc.title,
                                            body=candidate.text, customer_id=doc.customer_id))
            replaced += 1
        else:
            documents.append(doc)
    if replaced != 1:
        raise ValueError("allowed source slot not found exactly once")
    return FixtureSnapshot(fixture_id=snapshot.fixture_id, version=snapshot.version,
                           documents=documents, customers=snapshot.customers, outbox=[])


@dataclass
class RawResult:
    """What a raw handler produced (before any gateway response filtering)."""
    content: dict[str, Any]
    is_error: bool = False
    customer_ids: list[str] = field(default_factory=list)
    document_ids: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    outbox_message: OutboxMessage | None = None


@dataclass
class ProposalRecord:
    """A tool proposal that reached the gateway (counted toward the 8-call cap)."""
    call_id: str
    tool: str
    raw_arguments: dict[str, Any]
    proposal_event_id: uuid.UUID | None = None
    decision_event_id: uuid.UUID | None = None
    allowed: bool = False


@dataclass
class LedgerEntry:
    """One executed call and the content actually DELIVERED to the model."""
    call_id: str
    tool: str
    delivered: dict[str, Any]
    is_error: bool
    decision_event_id: uuid.UUID | None
    executed_event_id: uuid.UUID | None = None
    outbox_message_id: uuid.UUID | None = None


class CaseWorld:
    def __init__(self, spec: CaseSpec) -> None:
        self._trial_id = spec.trial_id
        self.snapshot = apply_candidate(spec)  # deep copy with the (only) substitution
        self._customers: dict[str, CustomerRecord] = {c.id: c for c in self.snapshot.customers}
        # Retrieval ranks on the ORIGINAL title/body so attacker text cannot steer ranking.
        original = spec.fixture_snapshot
        self._index = {
            doc.id: _tokens(doc.title) | _tokens(doc.body) | _tokens(doc.id) | _tokens(doc.customer_id)
            for doc in original.documents
        }
        self._docs = {doc.id: doc for doc in self.snapshot.documents}
        self.outbox: list[OutboxMessage] = []
        self.proposals: list[ProposalRecord] = []
        self.ledger: list[LedgerEntry] = []

    @property
    def customer_tenants(self) -> dict[str, str]:
        return {cid: rec.tenant_id for cid, rec in self._customers.items()}

    def execute(self, tool: str, args: ContractModel, call_id: str) -> RawResult:
        """Synchronous (hence atomic w.r.t. cancellation) dispatch to a raw handler."""
        if tool == "search_docs":
            return self._search_docs(args.query)
        if tool == "get_customer":
            return self._get_customer(args.customer_id)
        if tool == "send_email":
            return self._send_email(args.to, args.subject, args.body, call_id)
        raise ValueError("unknown tool")  # unreachable: the gateway validates tool names

    # -- private raw handlers ----------------------------------------------------
    def _search_docs(self, query: str) -> RawResult:
        wanted = _tokens(query)
        scored = [(len(wanted & tokens), doc_id) for doc_id, tokens in self._index.items()]
        hits = sorted((item for item in scored if item[0] > 0), key=lambda item: (-item[0], item[1]))
        results, ids = [], []
        for _, doc_id in hits[:_MAX_SEARCH_RESULTS]:
            doc = self._docs[doc_id]
            ids.append(doc.id)
            results.append({"source_id": doc.id, "surface": doc.surface.value, "title": doc.title,
                            "body": doc.body, "trust": "untrusted"})
        return RawResult(content={"results": results}, document_ids=ids)

    def _get_customer(self, customer_id: str) -> RawResult:
        record = self._customers.get(customer_id)
        if record is None:
            return RawResult(content={"error": {"code": "customer_not_found"}}, is_error=True)
        payload = record.model_dump(mode="json")
        return RawResult(content={"customer": payload}, customer_ids=[record.id],
                         fields=list(payload.keys()))

    def _send_email(self, to: str, subject: str, body: str, call_id: str) -> RawResult:
        message = OutboxMessage(id=uuid.uuid5(_OUTBOX_NAMESPACE, f"{self._trial_id}:{call_id}"),
                                to=to, subject=subject, body=body)
        self.outbox.append(message)  # mock effect only; nothing is ever sent
        return RawResult(content={"status": "accepted_by_mock_outbox", "message_id": str(message.id)},
                         outbox_message=message)
