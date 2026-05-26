"""
TunnelConfig → YAML string.

Rules:
  - Enum values are serialized as their string literals (not enum names).
  - None / empty string / empty list fields are omitted (mirror DSL defaults).
  - The 'tls' sub-section is only included when transport.type == 'tls'.
  - CustomStep uses 'validate' as the YAML key (Pydantic alias).
  - Key ordering matches the tunnel-gen examples for readability.
"""
from __future__ import annotations

from typing import Any

import yaml

from schemas import TunnelConfig


def _clean(obj: Any) -> Any:
    """Recursively remove None, empty strings, and empty lists."""
    if isinstance(obj, dict):
        return {
            k: _clean(v)
            for k, v in obj.items()
            if v is not None and v != "" and v != []
        }
    if isinstance(obj, list):
        cleaned = [_clean(i) for i in obj]
        return [i for i in cleaned if i is not None]
    return obj


def _step_to_dict(step: Any) -> dict:
    """CustomStep → dict using alias 'validate' for validate_ field."""
    d: dict = {"type": step.type}
    if step.payload is not None:
        d["payload"] = step.payload
    if step.length is not None:
        d["length"] = step.length
    if step.validate_ is not None:          # Pydantic field validate_  → YAML key validate
        d["validate"] = step.validate_
    if step.derive_as is not None:
        d["derive_as"] = step.derive_as
    if step.delay_ms is not None:
        d["delay_ms"] = step.delay_ms
    return d


def config_to_dict(cfg: TunnelConfig) -> dict:
    """Convert TunnelConfig to a plain dict ready for yaml.dump."""

    # ── transport ────────────────────────────────────────────────────────────
    transport: dict = {
        "type": cfg.transport.type,
        "host": cfg.transport.host,
        "port": cfg.transport.port,
    }
    if cfg.transport.type == "tls" and cfg.transport.tls:
        tls = cfg.transport.tls
        tls_d: dict = {
            "version":     tls.version,
            "fingerprint": tls.fingerprint,
        }
        if tls.alpn:
            tls_d["alpn"] = list(tls.alpn)
        if tls.sni:
            tls_d["sni"] = tls.sni
        if tls.cert_file:
            tls_d["cert_file"] = tls.cert_file
        if tls.key_file:
            tls_d["key_file"] = tls.key_file
        tls_d["insecure"] = tls.insecure
        transport["tls"] = tls_d

    # ── handshake ────────────────────────────────────────────────────────────
    handshake: dict = {"type": cfg.handshake.type}

    if cfg.handshake.type == "noise" and cfg.handshake.noise:
        n = cfg.handshake.noise
        nd: dict = {
            "pattern":      n.pattern,
            "cipher_suite": n.cipher_suite,
        }
        if n.prologue:
            nd["prologue"] = n.prologue
        if n.psk:
            nd["psk"] = n.psk
        if n.local_key:
            nd["local_key"] = n.local_key
        if n.remote_key:
            nd["remote_key"] = n.remote_key
        handshake["noise"] = nd

    elif cfg.handshake.type == "tls-token" and cfg.handshake.tls_token:
        t = cfg.handshake.tls_token
        handshake["tls_token"] = {
            "field":  t.field,
            "kdf":    t.kdf,
            "psk":    t.psk,
            "length": t.length,
        }

    elif cfg.handshake.type == "custom" and cfg.handshake.steps:
        handshake["steps"] = [_step_to_dict(s) for s in cfg.handshake.steps]

    # ── crypto ───────────────────────────────────────────────────────────────
    crypto = {
        "aead": cfg.crypto.aead,
        "kdf":  cfg.crypto.kdf,
    }

    # ── padding ──────────────────────────────────────────────────────────────
    padding: dict = {"mode": cfg.padding.mode}
    if cfg.padding.mode == "fixed" and cfg.padding.fixed_size:
        padding["fixed_size"] = cfg.padding.fixed_size
    elif cfg.padding.mode == "random":
        if cfg.padding.random_min:
            padding["random_min"] = cfg.padding.random_min
        if cfg.padding.random_max:
            padding["random_max"] = cfg.padding.random_max
    elif cfg.padding.mode == "mimicry" and cfg.padding.profile:
        padding["profile"] = cfg.padding.profile

    # ── timing ───────────────────────────────────────────────────────────────
    timing: dict = {"mode": cfg.timing.mode}
    if cfg.timing.mode == "batch" and cfg.timing.batch_interval_ms:
        timing["batch_interval_ms"] = cfg.timing.batch_interval_ms
    elif cfg.timing.mode == "delay":
        if cfg.timing.delay_min_ms is not None:
            timing["delay_min_ms"] = cfg.timing.delay_min_ms
        if cfg.timing.delay_max_ms is not None:
            timing["delay_max_ms"] = cfg.timing.delay_max_ms

    # ── fallback ─────────────────────────────────────────────────────────────
    fallback: dict = {"enabled": cfg.fallback.enabled}
    if cfg.fallback.enabled:
        fallback["mode"]   = cfg.fallback.mode
        fallback["target"] = cfg.fallback.target

    return {
        "protocol":  cfg.protocol,
        "version":   cfg.version,
        "transport": transport,
        "handshake": handshake,
        "crypto":    crypto,
        "padding":   padding,
        "timing":    timing,
        "fallback":  fallback,
    }


def config_to_yaml(cfg: TunnelConfig) -> str:
    d = config_to_dict(cfg)
    return yaml.dump(
        d,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=100,
    )
