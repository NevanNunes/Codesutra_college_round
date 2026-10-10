"""Model transport: Anthropic SDK adapter and shared token budget limiter.

The ModelClient protocol is re-exported from contracts. This module provides:
- AnthropicModelClient: real Anthropic SDK adapter
- BudgetLimiter: per-run shared token tracking across attacker & target
- StubModelClient: for fixture mode (raises if called)
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from agentbreak.contracts import (
    AssistantBlock,
    ModelClient,
    ModelMessage,
    ModelReply,
    TextBlock,
    ToolCall,
    ToolSchema,
    ToolUseBlock,
    Usage,
    validate_message_sequence,
)

__all__ = ["ModelClient", "AnthropicModelClient", "BudgetLimiter", "StubModelClient", "create_model_client"]

logger = logging.getLogger(__name__)


class BudgetLimiter:
    """Shared per-run token limiter. Thread-safe via asyncio.Lock."""

    def __init__(self, max_total_tokens: int) -> None:
        self._max = max_total_tokens
        self._used = 0
        self._lock = asyncio.Lock()

    @property
    def remaining(self) -> int:
        return max(0, self._max - self._used)

    @property
    def used(self) -> int:
        return self._used

    async def reserve(self, estimated: int) -> bool:
        """Try to reserve tokens. Returns False if budget would be exceeded."""
        async with self._lock:
            if self._used + estimated > self._max:
                return False
            self._used += estimated
            return True

    async def report(self, reserved: int, actual: int) -> None:
        """Adjust from reserved estimate to actual usage."""
        async with self._lock:
            self._used = self._used - reserved + actual


class StubModelClient:
    """Fixture-mode client that raises if called — fixtures use scripted traces."""
    simulated = True

    async def complete(
        self, messages: list[ModelMessage], tools: list[ToolSchema], *,
        model_id: str, temperature: float, max_tokens: int,
    ) -> ModelReply:
        # For fixture mode, the runner uses scripted model clients from conftest.
        # This stub exists for the case where no real client is needed.
        raise RuntimeError("StubModelClient: no real model calls in fixture mode")


class AnthropicModelClient:
    """Anthropic SDK adapter behind the ModelClient protocol.

    Translates contract ModelMessage/ToolSchema to Anthropic SDK format and back.
    Strips thinking blocks from provider responses. One bounded retry for
    clearly retryable transport errors.
    """

    def __init__(self, api_key: str) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError("anthropic SDK is required for live mode: pip install anthropic") from exc
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

    async def complete(
        self, messages: list[ModelMessage], tools: list[ToolSchema], *,
        model_id: str, temperature: float, max_tokens: int,
    ) -> ModelReply:
        validate_message_sequence(messages)

        # Translate to Anthropic format
        system_text = ""
        sdk_messages: list[dict[str, Any]] = []
        for msg in messages:
            if msg.role == "system":
                system_text = " ".join(
                    block.text for block in msg.content if isinstance(block, TextBlock)
                )
                continue
            sdk_content: list[dict[str, Any]] = []
            for block in msg.content:
                if isinstance(block, TextBlock):
                    sdk_content.append({"type": "text", "text": block.text})
                elif isinstance(block, ToolUseBlock):
                    sdk_content.append({
                        "type": "tool_use",
                        "id": block.call.call_id,
                        "name": block.call.name,
                        "input": dict(block.call.arguments),
                    })
                else:
                    # ToolResultBlock
                    from agentbreak.contracts import ToolResultBlock
                    if isinstance(block, ToolResultBlock):
                        import json as _json
                        sdk_content.append({
                            "type": "tool_result",
                            "tool_use_id": block.call_id,
                            "content": _json.dumps(block.content, ensure_ascii=False),
                            "is_error": block.is_error,
                        })
            sdk_messages.append({"role": msg.role, "content": sdk_content})

        sdk_tools = []
        for tool in tools:
            sdk_tools.append({
                "name": tool.name,
                "description": tool.description,
                "input_schema": dict(tool.input_schema),
            })

        kwargs: dict[str, Any] = {
            "model": model_id,
            "messages": sdk_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_text:
            kwargs["system"] = system_text
        if sdk_tools:
            kwargs["tools"] = sdk_tools

        # One bounded retry for clearly retryable errors
        import anthropic
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                response = await self._client.messages.create(**kwargs)
                break
            except (anthropic.RateLimitError, anthropic.InternalServerError, anthropic.APIConnectionError) as exc:
                last_exc = exc
                if attempt == 0:
                    logger.warning("Retryable model error (attempt %d): %s", attempt + 1, type(exc).__name__)
                    await asyncio.sleep(1)
                    continue
                raise
            except anthropic.APIStatusError as exc:
                raise
        else:
            raise last_exc  # type: ignore[misc]

        # Translate response back to contract format
        content_blocks: list[AssistantBlock] = []
        for block in response.content:
            if block.type == "text":
                content_blocks.append(TextBlock(text=block.text[:32000]))
            elif block.type == "tool_use":
                content_blocks.append(ToolUseBlock(call=ToolCall(
                    call_id=block.id,
                    name=block.name,
                    arguments=block.input if isinstance(block.input, dict) else {},
                )))
            # Skip thinking blocks — never stored

        stop_map = {
            "end_turn": "end_turn",
            "tool_use": "tool_use",
            "max_tokens": "max_tokens",
        }
        raw_reason = stop_map.get(response.stop_reason, "refusal")
        from typing import Literal, cast
        stop_reason = cast(Literal["end_turn", "tool_use", "max_tokens", "refusal"], raw_reason)

        return ModelReply(
            content=content_blocks,
            usage=Usage(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            ),
            stop_reason=stop_reason,
            model_id=response.model,
            provider_request_id=response.id if hasattr(response, "id") else None,
        )


def create_model_client() -> tuple[ModelClient | None, bool]:
    """Create a model client from environment. Returns (client, live_ready).

    If ANTHROPIC_API_KEY is set and ALLOW_LIVE_RUNS is true, returns a real client.
    Otherwise returns None and live_ready=False.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    allow_live = os.environ.get("ALLOW_LIVE_RUNS", "false").lower() == "true"

    if api_key and allow_live:
        try:
            client = AnthropicModelClient(api_key=api_key)
            return client, True
        except ImportError:
            logger.warning("anthropic SDK not installed; live mode unavailable")
            return None, False
    return None, False
