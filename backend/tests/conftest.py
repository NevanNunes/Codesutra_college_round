"""Reusable, explicitly simulated model/event doubles for A/B/D unit tests.

No network, database, target scripts, tool execution or hidden fallback.
These fixtures are test-only, not production implementations.
"""

import asyncio
from collections import deque
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from agentbreak.contracts import EventDraft, ModelReply, TraceEvent, validate_message_sequence


class ScriptedModelClient:
    def __init__(self, replies):
        self.replies = deque(reply.model_copy(deep=True) for reply in replies)
        self.calls = []

    async def complete(self, messages, tools, *, model_id, temperature, max_tokens):
        validate_message_sequence(messages)
        self.calls.append({
            "messages": [message.model_copy(deep=True) for message in messages],
            "tools": [tool.model_copy(deep=True) for tool in tools],
            "model_id": model_id, "temperature": temperature, "max_tokens": max_tokens,
        })
        if not self.replies:
            raise AssertionError("Scripted model exhausted; no live/fixture fallback")
        return ModelReply.model_validate(self.replies.popleft())


class MemoryEventSink:
    def __init__(self, run_id):
        self.run_id = run_id
        self.events = []
        self._lock = asyncio.Lock()

    async def __call__(self, event_draft):
        draft = EventDraft.model_validate(event_draft)
        async with self._lock:
            known = {event.id for event in self.events}
            if not set(draft.parent_event_ids).issubset(known):
                raise ValueError("Unknown event parent")
            event = TraceEvent(
                **draft.model_dump(), run_id=self.run_id, id=uuid4(),
                seq=len(self.events) + 1, timestamp=datetime.now(timezone.utc),
            )
            self.events.append(event.model_copy(deep=True))
            return event


@pytest.fixture
def scripted_model():
    """Factory: scripted_model([ModelReply(...), ...]) -> ModelClient double."""
    return ScriptedModelClient


@pytest.fixture
def memory_event_sink():
    """Factory: memory_event_sink(run_id) -> in-memory EventSink double."""
    return MemoryEventSink
