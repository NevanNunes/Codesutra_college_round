"""Generator module for the Adaptive Attack Engine."""

from __future__ import annotations

import logging
from uuid import UUID, uuid4

from agentbreak.attacks.prompts import SYSTEM_PROMPT, build_generation_prompt
from agentbreak.contracts import (
    AttackCandidate, ModelClient, ModelMessage, ModelSettings, ScenarioSpec,
    TextBlock, ToolSchema, payload_sha256
)

logger = logging.getLogger(__name__)


def _extract_json_from_text(text: str) -> dict | None:
    import json
    import re
    # Try to find JSON block
    match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Fallback try to parse the whole text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None

class AttackGenerator:
    """Generates attack candidates using a ModelClient."""

    def __init__(self, client: ModelClient, settings: ModelSettings):
        self._client = client
        self._settings = settings

    async def generate_candidate(
        self,
        scenario: ScenarioSpec,
        generation: int,
        parent_id: UUID | None = None,
        feedback: str | None = None,
    ) -> AttackCandidate | None:
        """Generate a single attack candidate."""
        prompt = build_generation_prompt(scenario, feedback)
        # Instruct to use JSON
        prompt += "\n\nYou MUST respond with exactly ONE valid JSON object, and nothing else. The JSON object must have two string keys: 'strategy' (a short name) and 'text' (the payload text)."
        
        messages = [
            ModelMessage(role="system", content=[TextBlock(text=SYSTEM_PROMPT)]),
            ModelMessage(role="user", content=[TextBlock(text=prompt)])
        ]
        
        try:
            reply = await self._client.complete(
                messages,
                tools=[],
                model_id=self._settings.attacker_model_id,
                temperature=self._settings.temperature,
                max_tokens=self._settings.max_tokens,
            )
        except Exception as exc:
            logger.error("Attack generator model failed: %s", exc)
            return None

        if not reply.text:
            logger.error("Attack generator failed to provide text output.")
            return None

        args = _extract_json_from_text(reply.text)
        if not args:
            logger.error("Attack generator output was not valid JSON.")
            return None
            
        strategy = args.get("strategy", "unknown")
        text = args.get("text", "")
        
        if not text:
            logger.error("Attack generator provided empty text payload.")
            return None

        # Sanitize strategy to be an Identifier
        strategy = "".join(c if c.isalnum() or c in "_.-" else "_" for c in strategy)[:128]
        if not strategy:
            strategy = "default_strategy"

        # Truncate text if needed to fit PayloadText constraint
        text = text[:4000]

        try:
            return AttackCandidate(
                id=uuid4(),
                scenario_id=scenario.id,
                source_id=scenario.source_id,
                surface=scenario.surface,
                text=text,
                parent_id=parent_id,
                generation=generation,
                strategy=strategy,
                feedback_summary=feedback,
                payload_sha256=payload_sha256(text)
            )
        except ValueError as exc:
            logger.error("Failed to construct AttackCandidate: %s", exc)
            return None
