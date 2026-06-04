"""
LLM provider via polza.ai — OpenAI-compatible proxy for 400+ models.

All models (OpenAI, Anthropic, Google, DeepSeek, …) are reached through
a single endpoint using one API key:

    Base URL : https://polza.ai/api/v1
    Auth     : Authorization: Bearer <POLZA_API_KEY>
    Model IDs: provider/model-name  (e.g. "anthropic/claude-opus-4-5")

Structured output is implemented with OpenAI function-calling (tool_choice
forced to a single tool), which polza.ai forwards correctly to every
underlying model that supports it.

Required environment variable (either name works):
    POLZA_API_KEY   — from https://polza.ai/dashboard/api-keys
    POLZA_KEY       — alternative name
"""
from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Type, TypeVar

from pydantic import BaseModel

log = logging.getLogger(__name__)

# Load .env from the same directory as this file (optional, no-op if missing)
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(Path(__file__).parent / ".env", override=True)
except ImportError:
    pass

T = TypeVar("T", bound=BaseModel)

_POLZA_BASE_URL = "https://polza.ai/api/v1"


# ─────────────────────────────────────────────────────────────────────────────
# Shared metadata
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProviderMeta:
    """Token usage and latency metadata returned alongside the structured result."""
    model:             str
    provider:          str
    prompt_tokens:     int
    completion_tokens: int
    total_tokens:      int
    extra:             dict = field(default_factory=dict)


class LLMProvider(ABC):
    @abstractmethod
    def generate_structured(
        self,
        system: str,
        user: str,
        schema: Type[T],
        tool_name: str = "output",
        tool_description: str = "Return the structured result.",
    ) -> tuple[T, ProviderMeta]: ...

    @property
    @abstractmethod
    def model_id(self) -> str:
        """Short model identifier used for artifact directory naming."""
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Polza provider  (the only provider needed)
# ─────────────────────────────────────────────────────────────────────────────

class PolzaProvider(LLMProvider):
    """
    Calls polza.ai via the OpenAI SDK.

    polza_model  — full polza model ID, e.g. "anthropic/claude-opus-4-5"
    display_name — short alias used in artifact paths, e.g. "claude-opus-4"
    """

    def __init__(
        self,
        polza_model:  str,
        display_name: str,
        max_tokens:   int   = 4096,
        temperature:  float = 1.0,
    ):
        from openai import OpenAI
        api_key = (
            os.environ.get("POLZA_API_KEY")
            or os.environ.get("POLZA_KEY")
            or ""
        )
        self._client = OpenAI(
            base_url=_POLZA_BASE_URL,
            api_key=api_key,
        )
        self._polza_model  = polza_model
        self._display_name = display_name
        self._max_tokens   = max_tokens
        self._temperature  = temperature

    @property
    def model_id(self) -> str:
        return self._display_name

    def generate_structured(
        self,
        system: str,
        user: str,
        schema: Type[T],
        tool_name: str = "output",
        tool_description: str = "Return the structured result.",
    ) -> tuple[T, ProviderMeta]:
        response = self._client.chat.completions.create(
            model=self._polza_model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            tools=[{
                "type": "function",
                "function": {
                    "name":        tool_name,
                    "description": tool_description,
                    "parameters":  schema.model_json_schema(),
                },
            }],
            tool_choice={"type": "function", "function": {"name": tool_name}},
        )

        choice    = response.choices[0]
        tool_call = choice.message.tool_calls[0] if choice.message.tool_calls else None
        if tool_call is None:
            raise ValueError(
                f"polza/{self._polza_model} returned no tool call.\n"
                f"finish_reason={choice.finish_reason!r}\n"
                f"content={choice.message.content!r}"
            )

        result = schema.model_validate(json.loads(tool_call.function.arguments))

        usage = response.usage
        meta = ProviderMeta(
            model=self._polza_model,
            provider="polza",
            prompt_tokens=usage.prompt_tokens     if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            total_tokens=usage.total_tokens       if usage else 0,
        )
        return result, meta


# ─────────────────────────────────────────────────────────────────────────────
# Model registry  — alias → (polza_model_id, display_name)
# ─────────────────────────────────────────────────────────────────────────────
# Model IDs follow polza's "provider/model-name" format.
# Add / remove entries freely; display_name is used for results/ directory names.

MODEL_REGISTRY: dict[str, tuple[str, str]] = {
    # ── Anthropic ──────────────────────────────────────────────────────────────
    "claude-haiku-3":    ("anthropic/claude-3-haiku",             "claude-haiku-3"),
    "claude-haiku-3-5":  ("anthropic/claude-3.5-haiku",          "claude-haiku-3-5"),
    "claude-haiku-4":    ("anthropic/claude-haiku-4.5",          "claude-haiku-4"),
    "claude-sonnet-4":   ("anthropic/claude-sonnet-4",           "claude-sonnet-4"),
    "claude-sonnet-4-5": ("anthropic/claude-sonnet-4.5",         "claude-sonnet-4-5"),
    "claude-opus-4":     ("anthropic/claude-opus-4",             "claude-opus-4"),
    # ── OpenAI ────────────────────────────────────────────────────────────────
    "gpt-4o-mini":       ("openai/gpt-4o-mini",                  "gpt-4o-mini"),
    "gpt-4o":            ("openai/gpt-4o",                       "gpt-4o"),
    "gpt-4.1-mini":      ("openai/gpt-4.1-mini",                 "gpt-4.1-mini"),
    "gpt-4.1":           ("openai/gpt-4.1",                      "gpt-4.1"),
    # ── Google ────────────────────────────────────────────────────────────────
    "gemini-2.5-flash":      ("google/gemini-2.5-flash",         "gemini-2.5-flash"),
    "gemini-2.5-flash-lite": ("google/gemini-2.5-flash-lite",    "gemini-2.5-flash-lite"),
    "gemini-2.5-pro":        ("google/gemini-2.5-pro",           "gemini-2.5-pro"),
    "gemini-3-flash":        ("google/gemini-3-flash-preview",   "gemini-3-flash"),
    # ── DeepSeek ──────────────────────────────────────────────────────────────
    "deepseek-chat":     ("deepseek/deepseek-chat",              "deepseek-chat"),
    "deepseek-v3":       ("deepseek/deepseek-chat-v3-0324",      "deepseek-v3"),
    "deepseek-r1":       ("deepseek/deepseek-r1",                "deepseek-r1"),
    # ── Qwen (Alibaba) ────────────────────────────────────────────────────────
    "qwen3-32b":         ("qwen/qwen3-32b",                      "qwen3-32b"),
    "qwen3-max":         ("qwen/qwen3-max",                      "qwen3-max"),
}


def build_provider(alias: str, **kwargs) -> PolzaProvider:
    """
    Instantiate a PolzaProvider from a registry alias.
    Extra kwargs (temperature, max_tokens) are forwarded to the constructor.
    """
    if alias not in MODEL_REGISTRY:
        available = ", ".join(sorted(MODEL_REGISTRY))
        raise ValueError(f"Unknown model {alias!r}. Available: {available}")

    polza_id, display = MODEL_REGISTRY[alias]
    return PolzaProvider(polza_model=polza_id, display_name=display, **kwargs)


def list_models() -> list[str]:
    return sorted(MODEL_REGISTRY.keys())
