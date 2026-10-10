"""Persistent EventSink implementation for AgentBreak."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import UUID, uuid4

from agentbreak.contracts import EventDraft, TraceEvent
from agentbreak.storage.db import Database


class PersistentEventSink:
    """Async event sink that assigns IDs/seqs and persists TraceEvents to SQLite."""

    def __init__(self, run_id: UUID, db: Database) -> None:
        self.run_id = run_id
        self.db = db
        self._lock = asyncio.Lock()
        self._seq = db.get_max_event_seq(run_id)

    async def __call__(self, draft: EventDraft) -> TraceEvent:
        async with self._lock:
            self._seq += 1
            seq = self._seq
            now = datetime.now(timezone.utc)
            event_id = uuid4()

            # Validate parent event IDs:
            # 1. Reject unknown parents in this run
            # 2. Ensure parent events precede this event in seq
            for parent_id in draft.parent_event_ids:
                parent = self.db.get_event(self.run_id, parent_id)
                if parent is None:
                    raise ValueError(f"unknown parent event ID: {parent_id}")
                if parent.seq >= seq:
                    raise ValueError(
                        f"parent event seq {parent.seq} does not precede child seq {seq}"
                    )

            event = TraceEvent(
                schema_version=1,
                id=event_id,
                run_id=self.run_id,
                trial_id=draft.trial_id,
                seq=seq,
                timestamp=now,
                type=draft.type,
                parent_event_ids=draft.parent_event_ids,
                data=draft.data,
            )
            self.db.save_event(event)
            return event
