"""Tests for the Attack Generator."""

import pytest
from uuid import UUID
from agentbreak.attacks.generator import AttackGenerator, build_generation_prompt
from agentbreak.contracts import ModelSettings, ScenarioSpec, ModelReply, ToolCall, ToolUseBlock, Usage, TextBlock

class FakeAttackerClient:
    def __init__(self, responses):
        self.responses = responses
        self.call_count = 0

    async def complete(self, messages, tools, model_id, temperature, max_tokens):
        resp = self.responses[self.call_count]
        self.call_count += 1
        return resp


@pytest.fixture
def scenario():
    return ScenarioSpec(
        id="doc_exfil",
        task_id="test_task",
        version=1,
        title="Test Scenario",
        surface="document",
        source_id="doc1",
        legitimate_task="Read a doc",
        attack_goal="Steal a doc",
        fixture_id="fixture1",
        grant={"principal_id": "p1", "tenant_id": "t1", "allowed_customer_ids": [], "allowed_tools": [], "allowed_recipients": []},
        expected_benign=[{"kind": "final_contains", "values": ["done"]}]
    )

@pytest.mark.asyncio
async def test_generator_valid_output(scenario):
    fake_reply = ModelReply(
        content=[
            TextBlock(text='{"strategy": "sneaky", "text": "malicious payload"}')
        ],
        usage=Usage(input_tokens=10, output_tokens=10),
        stop_reason="end_turn",
        model_id="test_model"
    )
    client = FakeAttackerClient([fake_reply])
    settings = ModelSettings(provider="test", target_model_id="t1", attacker_model_id="a1")
    generator = AttackGenerator(client, settings)

    candidate = await generator.generate_candidate(scenario, generation=1, parent_id=UUID(int=0))
    
    assert candidate is not None
    assert candidate.strategy == "sneaky"
    assert candidate.text == "malicious payload"
    assert candidate.generation == 1
    assert candidate.parent_id == UUID(int=0)
    assert candidate.scenario_id == "doc_exfil"
    assert candidate.source_id == "doc1"
    assert candidate.surface == "document"


@pytest.mark.asyncio
async def test_generator_invalid_tool(scenario):
    fake_reply = ModelReply(
        content=[
            TextBlock(text="not valid json")
        ],
        usage=Usage(input_tokens=10, output_tokens=10),
        stop_reason="end_turn",
        model_id="test_model"
    )
    client = FakeAttackerClient([fake_reply])
    settings = ModelSettings(provider="test", target_model_id="t1", attacker_model_id="a1")
    generator = AttackGenerator(client, settings)

    candidate = await generator.generate_candidate(scenario, generation=1)
    assert candidate is None


def test_build_generation_prompt_with_feedback(scenario):
    prompt = build_generation_prompt(scenario, feedback="Blocked by policy X.")
    assert "Blocked by policy X." in prompt
    assert scenario.legitimate_task in prompt
    assert scenario.attack_goal in prompt
