import asyncio
from uuid import uuid4

import pytest

from agentbreak.contracts import EventDraft, EventSink, ModelClient, ModelMessage, ModelReply, TextBlock, Usage


async def test_scripted_model_records_calls_and_never_falls_back(scripted_model):
    model = scripted_model([ModelReply(
        content=[TextBlock(text="Simulated reply")], usage=Usage(),
        stop_reason="end_turn", model_id="fixture-only",
    )])
    assert isinstance(model, ModelClient)
    messages = [ModelMessage(role="user", content=[TextBlock(text="Synthetic task")])]
    args = {"model_id": "fixture-only", "temperature": 0.0, "max_tokens": 100}
    assert (await model.complete(messages, [], **args)).text == "Simulated reply"
    messages[0].content[0].text = "Changed"
    assert model.calls[0]["messages"][0].content[0].text == "Synthetic task"
    with pytest.raises(AssertionError, match="exhausted"):
        await model.complete(messages, [], **args)


async def test_memory_sink_assigns_order_ids_and_isolates_records(memory_event_sink):
    sink = memory_event_sink(uuid4())
    assert isinstance(sink, EventSink)
    root = await sink(EventDraft(type="run_started"))
    events = await asyncio.gather(*[
        sink(EventDraft(type="case_started", parent_event_ids=[root.id]))
        for _ in range(5)
    ])
    assert [event.seq for event in events] == list(range(2, 7))
    assert len({event.id for event in sink.events}) == 6
    root.data["changed"] = True
    assert sink.events[0].data == {}
    with pytest.raises(ValueError, match="Unknown"):
        await sink(EventDraft(type="run_completed", parent_event_ids=[uuid4()]))
