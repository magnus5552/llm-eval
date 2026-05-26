"""
LLM provider abstraction.

Two concrete implementations:
  AnthropicProvider   – uses Anthropic SDK + tools API (forced tool call)
  OpenAICompatProvider– uses OpenAI SDK + function calling
                        Works for: OpenAI, Google Gemini (via compat), DeepSeek

Both providers force a single structured tool call, parse the result with
Pydantic, and return (T, ProviderMeta).
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Type, TypeVar

from pydantic import BaseModel

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


@dataclass
class ProviderMeta:
    """Token usage and latency metadata returned alongside the structured result."""
    model:              str
    provider:           str
    prompt_tokens:      int
    completion_tokens:  int
    total_tokens:       int
    extra:              dict = field(default_factory=dict)  # provider-specific fields


class LLMProvider(ABC):
    @abstractmethod
    def generate_structured(
        self,
        system: str,
        user: str,
        schema: Type[T],
        tool_name: str = "output",
        tool_description: str = "Return the structured result.",
    ) -> tuple[T, ProviderMeta]:
        """Call the LLM, force it to fill *schema*, return (instance, meta)."""
        ...

    @property
    @abstractmethod
    def model_id(self) -> str:
        """Canonical model identifier for artifact naming."""
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Anthropic
# ─────────────────────────────────────────────────────────────────────────────

class AnthropicProvider(LLMProvider):
    """
    Uses Anthropic's tools API with tool_choice={"type":"tool"} to guarantee
    a single structured tool call.

    Requires: ANTHROPIC_API_KEY in environment.
    """

    def __init__(
        self,
        model: str = "claude-opus-4-5",
        max_tokens: int = 4096,
        temperature: float = 1.0,
    ):
        import anthropic  # late import – optional dependency
        self._client = anthropic.Anthropic()
        self._model  = model
        self._max_tokens = max_tokens
        self._temperature = temperature

    @property
    def model_id(self) -> str:
        return self._model

    def generate_structured(
        self,
        system: str,
        user: str,
        schema: Type[T],
        tool_name: str = "output",
        tool_description: str = "Return the structured result.",
    ) -> tuple[T, ProviderMeta]:
        json_schema = schema.model_json_schema()
        # Anthropic requires additionalProperties to not be present at root
        json_schema.pop("additionalProperties", None)

        response = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            system=system,
            tools=[{
                "name": tool_name,
                "description": tool_description,
                "input_schema": json_schema,
            }],
            tool_choice={"type": "tool", "name": tool_name},
            messages=[{"role": "user", "content": user}],
        )

        # Extract tool use block
        tool_block = next(
            (b for b in response.content if b.type == "tool_use"),
            None,
        )
        if tool_block is None:
            raise ValueError(f"Anthropic returned no tool_use block: {response}")

        result = schema.model_validate(tool_block.input)

        meta = ProviderMeta(
            model=self._model,
            provider="anthropic",
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
            total_tokens=response.usage.input_tokens + response.usage.output_tokens,
        )
        return result, meta


# ─────────────────────────────────────────────────────────────────────────────
# OpenAI-compatible  (OpenAI, Google Gemini, DeepSeek, Mistral, …)
# ─────────────────────────────────────────────────────────────────────────────

class OpenAICompatProvider(LLMProvider):
    """
    Uses the OpenAI SDK with function calling to produce structured output.

    Compatible with any OpenAI-compatible API:
      - OpenAI:  base_url=None, api_key from OPENAI_API_KEY
      - Gemini:  base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
                 api_key from GOOGLE_API_KEY
      - DeepSeek:base_url="https://api.deepseek.com", api_key from DEEPSEEK_API_KEY
    """

    def __init__(
        self,
        model: str = "gpt-4o",
        base_url: str | None = None,
        api_key: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 1.0,
    ):
        from openai import OpenAI  # late import
        self._client = OpenAI(
            base_url=base_url,
            api_key=api_key,  # None → read from env
        )
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature

    @property
    def model_id(self) -> str:
        return self._model

    def generate_structured(
        self,
        system: str,
        user: str,
        schema: Type[T],
        tool_name: str = "output",
        tool_description: str = "Return the structured result.",
    ) -> tuple[T, ProviderMeta]:
        json_schema = schema.model_json_schema()

        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            tools=[{
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": tool_description,
                    "parameters": json_schema,
                },
            }],
            tool_choice={"type": "function", "function": {"name": tool_name}},
        )

        choice = response.choices[0]
        tool_call = choice.message.tool_calls[0] if choice.message.tool_calls else None
        if tool_call is None:
            raise ValueError(f"No tool call in response: {choice}")

        raw = json.loads(tool_call.function.arguments)
        result = schema.model_validate(raw)

        usage = response.usage
        meta = ProviderMeta(
            model=self._model,
            provider="openai-compat",
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            total_tokens=usage.total_tokens if usage else 0,
        )
        return result, meta


# ─────────────────────────────────────────────────────────────────────────────
# Registry  — model_alias → provider factory
# ─────────────────────────────────────────────────────────────────────────────

def _make_google_provider(model: str, **kw) -> OpenAICompatProvider:
    import os
    return OpenAICompatProvider(
        model=model,
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        api_key=os.environ.get("GOOGLE_API_KEY"),
        **kw,
    )


def _make_deepseek_provider(model: str, **kw) -> OpenAICompatProvider:
    import os
    return OpenAICompatProvider(
        model=model,
        base_url="https://api.deepseek.com",
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        **kw,
    )


# alias → (factory, canonical_model_name)
MODEL_REGISTRY: dict[str, tuple] = {
    # Anthropic
    "claude-opus-4":      (AnthropicProvider,    "claude-opus-4-5"),
    "claude-sonnet-4":    (AnthropicProvider,    "claude-sonnet-4-5"),
    "claude-sonnet-3-5":  (AnthropicProvider,    "claude-3-5-sonnet-20241022"),
    # OpenAI
    "gpt-4o":             (OpenAICompatProvider, "gpt-4o"),
    "gpt-4.1":            (OpenAICompatProvider, "gpt-4.1"),
    "gpt-4o-mini":        (OpenAICompatProvider, "gpt-4o-mini"),
    # Google Gemini (via OpenAI-compat endpoint)
    "gemini-2.0-flash":   (_make_google_provider, "gemini-2.0-flash"),
    "gemini-2.5-pro":     (_make_google_provider, "gemini-2.5-pro-preview-05-06"),
    # DeepSeek
    "deepseek-chat":      (_make_deepseek_provider, "deepseek-chat"),
    "deepseek-r1":        (_make_deepseek_provider, "deepseek-reasoner"),
}


def build_provider(alias: str, **kwargs) -> LLMProvider:
    """
    Build a provider from a registry alias.
    Extra kwargs (temperature, max_tokens) are forwarded to the constructor.
    """
    if alias not in MODEL_REGISTRY:
        raise ValueError(
            f"Unknown model alias {alias!r}. "
            f"Available: {', '.join(MODEL_REGISTRY)}"
        )

    factory, model_name = MODEL_REGISTRY[alias]

    # Factories that take model + extra kwargs
    if factory in (AnthropicProvider, OpenAICompatProvider):
        return factory(model=model_name, **kwargs)
    else:
        # Custom factory functions (google, deepseek)
        return factory(model_name, **kwargs)


def list_models() -> list[str]:
    return sorted(MODEL_REGISTRY.keys())
