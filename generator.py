"""
Prompt building and structured LLM generation.

GenerationArtifact bundles everything produced for one LLM call:
  - the raw GenerationResult (reasoning + config + predictions)
  - serialized YAML config
  - token usage and provider metadata
  - timestamps

TASK_VARIANTS are rotated across runs to maximise diversity of generated configs.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from string import Template

from providers import LLMProvider, ProviderMeta
from schemas import GenerationResult, TunnelConfig
from serializer import config_to_yaml

log = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load_prompt(name: str) -> str:
    return (_PROMPTS_DIR / name).read_text(encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Task variants  — rotated across runs for parameter diversity
# ─────────────────────────────────────────────────────────────────────────────

TASK_VARIANTS: list[dict] = [
    {
        "domain":          "www.google.com",
        "port":            9443,
        "handshake_hint":  "Use tls-token for maximum active-probe resistance (M8).",
        "padding_hint":    "Use mimicry/chrome-browsing to pass M4/M6.",
    },
    {
        "domain":          "www.cloudflare.com",
        "port":            443,
        "handshake_hint":  "Use noise NNpsk2 for forward secrecy without pre-shared static keys.",
        "padding_hint":    "Use random padding with wide range [40, 1400] to pass M6.",
    },
    {
        "domain":          "www.microsoft.com",
        "port":            8443,
        "handshake_hint":  "Combine tls-token with a browser fingerprint from a less common browser (safari-17).",
        "padding_hint":    "Use mimicry/video-streaming to simulate different traffic profile.",
    },
    {
        "domain":          "www.github.com",
        "port":            443,
        "handshake_hint":  "Use noise NNpsk0 — PSK at first message, extra entropy from the start.",
        "padding_hint":    "Use random padding [64, 1200] — avoid near-MTU sizes to reduce M5 score.",
    },
    {
        "domain":          "www.amazon.com",
        "port":            9443,
        "handshake_hint":  "Try handshake=none for the simplest possible surface — pure TLS with mimicry.",
        "padding_hint":    "Use mimicry/chrome-browsing but experiment with ssh-interactive for low-traffic sessions.",
    },
    {
        "domain":          "login.microsoftonline.com",
        "port":            443,
        "handshake_hint":  "Use tls-token with length=32 (shorter token, still 256 bits).",
        "padding_hint":    "Use random [100, 1300] to mimic API call distributions.",
    },
    {
        "domain":          "api.twitter.com",
        "port":            443,
        "handshake_hint":  "Use noise NNpsk2 with aes-256-gcm cipher suite variant.",
        "padding_hint":    "Use mimicry/chrome-browsing — social media API traffic is already variable.",
    },
    {
        "domain":          "www.wikipedia.org",
        "port":            9443,
        "handshake_hint":  "Use tls-token; combine with ALPN containing only h2 (HTTP/2 only).",
        "padding_hint":    "Use random [30, 1450] — very wide range to maximise KL divergence tolerance.",
    },
    {
        "domain":          "cdn.jsdelivr.net",
        "port":            443,
        "handshake_hint":  "Use noise NN (no PSK, no auth) — simplest noise for comparison.",
        "padding_hint":    "Use mimicry/video-streaming to test a different length distribution.",
    },
    {
        "domain":          "storage.googleapis.com",
        "port":            443,
        "handshake_hint":  "Use tls-token with hkdf-sha256 and length=48 (standard).",
        "padding_hint":    "Use mimicry/chrome-browsing. This run: optimise for M7 (no timing).",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Artifact
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GenerationArtifact:
    run_id:            str
    model_id:          str
    variant_index:     int
    variant:           dict

    generation_result: GenerationResult
    config_yaml:       str
    provider_meta:     ProviderMeta

    started_at:        float   # Unix timestamp
    elapsed_s:         float


# ─────────────────────────────────────────────────────────────────────────────
# Core generation function
# ─────────────────────────────────────────────────────────────────────────────

def generate_config(
    provider:      LLMProvider,
    run_index:     int   = 0,
    total_runs:    int   = 1,
    variant_index: int | None = None,
) -> GenerationArtifact:
    """
    Run one structured generation.

    variant_index selects the task variant (default: run_index % len(TASK_VARIANTS)).
    """
    if variant_index is None:
        variant_index = run_index % len(TASK_VARIANTS)

    variant = TASK_VARIANTS[variant_index]

    # Build prompts
    system_text = _load_prompt("system.md")
    task_template = _load_prompt("task.md")
    user_text = task_template.format(
        domain=variant["domain"],
        port=variant["port"],
        handshake_hint=variant["handshake_hint"],
        padding_hint=variant["padding_hint"],
        run_index=run_index + 1,
        total_runs=total_runs,
    )

    log.info(
        "[%s] run %d/%d — variant %d (%s, port %s)",
        provider.model_id, run_index + 1, total_runs,
        variant_index, variant["domain"], variant["port"],
    )

    started_at = time.time()
    gen_result, meta = provider.generate_structured(
        system=system_text,
        user=user_text,
        schema=GenerationResult,
        tool_name="output",
        tool_description="Return the complete GenerationResult with config, reasoning, and predictions.",
    )
    elapsed = time.time() - started_at

    log.info(
        "[%s] run %d done in %.1fs — %d tokens (in:%d out:%d)",
        provider.model_id, run_index + 1, elapsed,
        meta.total_tokens, meta.prompt_tokens, meta.completion_tokens,
    )

    yaml_str = config_to_yaml(gen_result.config)

    return GenerationArtifact(
        run_id=str(uuid.uuid4()),
        model_id=provider.model_id,
        variant_index=variant_index,
        variant=variant,
        generation_result=gen_result,
        config_yaml=yaml_str,
        provider_meta=meta,
        started_at=started_at,
        elapsed_s=elapsed,
    )
