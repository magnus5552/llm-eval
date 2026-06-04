"""
Pydantic v2 models for the tunnel-gen DSL and LLM generation results.

TunnelConfig mirrors the Go structs in tunnel-gen/dsl/schema.go exactly
(same YAML keys, same enum values, same validation constraints).

GenerationResult is the structured output format used with all LLM providers:
  - reasoning     : chain-of-thought explaining design choices
  - config        : the actual TunnelConfig to serialize to YAML
  - stealth_pred  : per-metric prediction (what the model thinks will pass/fail)
  - weaknesses    : known detection vectors the model is aware of
"""
from __future__ import annotations

import secrets
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ─────────────────────────────────────────────────────────────────────────────
# Enum literals  (must match parser.go valid values exactly)
# ─────────────────────────────────────────────────────────────────────────────

TransportType  = Literal["tls", "raw-tcp", "raw-udp"]
TLSVersion     = Literal["1.2", "1.3"]
TLSFingerprint = Literal["chrome-120", "firefox-120", "safari-17", "go", "random"]

HandshakeType  = Literal["noise", "tls-token", "custom", "none"]

NoisePattern = Literal[
    "NN", "NNpsk0", "NNpsk2",
    "NK", "NKpsk0", "NKpsk2",
    "XX", "XXpsk3",
    "IK", "IKpsk2",
    "KK", "KN", "XN", "IN",
]
NoiseCipherSuite = Literal[
    "25519:ChaChaPoly:BLAKE2s",
    "25519:ChaChaPoly:SHA256",
    "25519:AESGCM:SHA256",
    "25519:AESGCM:SHA512",
]

AEAD = Literal["chacha20-poly1305", "aes-256-gcm"]
KDF  = Literal["hkdf-sha256", "hkdf-sha512"]

PaddingMode   = Literal["none", "fixed", "random", "mimicry"]
MimicryProfile = Literal["chrome-browsing", "video-streaming", "ssh-interactive"]
TimingMode    = Literal["none", "batch", "delay"]
FallbackMode  = Literal["reverse-proxy", "static"]
StepType      = Literal["send", "recv", "derive", "sleep"]


# ─────────────────────────────────────────────────────────────────────────────
# DSL sub-models
# ─────────────────────────────────────────────────────────────────────────────

class TLSConf(BaseModel):
    version:     TLSVersion     = "1.3"
    fingerprint: TLSFingerprint = "chrome-120"
    alpn:        List[str]      = Field(default_factory=lambda: ["h2", "http/1.1"])
    sni:         str            = "www.google.com"
    cert_file:   str            = "server.crt"
    key_file:    str            = "server.key"
    insecure:    bool           = True


class TransportConf(BaseModel):
    type: TransportType = "tls"
    host: str           = "127.0.0.1"
    port: int           = Field(default=9443, ge=1, le=65535)
    tls:  Optional[TLSConf] = None

    @model_validator(mode="after")
    def tls_required_for_tls_transport(self) -> "TransportConf":
        if self.type == "tls" and self.tls is None:
            self.tls = TLSConf()
        return self


class NoiseConf(BaseModel):
    pattern:      NoisePattern      = "NNpsk2"
    cipher_suite: NoiseCipherSuite  = "25519:ChaChaPoly:BLAKE2s"
    prologue:     str               = ""
    psk:          str               = ""   # injected by evaluator if empty
    local_key:    str               = "generate"
    remote_key:   str               = ""

    @field_validator("psk", "local_key", "remote_key", mode="before")
    @classmethod
    def allow_empty_or_generate(cls, v: str) -> str:
        return v or ""


class TLSTokenConf(BaseModel):
    field:  str = "session_ticket"
    kdf:    KDF = "hkdf-sha256"
    psk:    str = ""   # injected by evaluator if empty
    length: int = Field(default=48, ge=16, le=64)


class CustomStep(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type:       StepType
    payload:    Optional[str] = None
    length:     Optional[int] = Field(default=None, ge=1)
    validate_:  Optional[str] = Field(default=None, alias="validate")
    derive_as:  Optional[str] = None
    delay_ms:   Optional[int] = Field(default=None, ge=0)


class HandshakeConf(BaseModel):
    type:      HandshakeType        = "tls-token"
    noise:     Optional[NoiseConf]  = None
    tls_token: Optional[TLSTokenConf] = None
    steps:     Optional[List[CustomStep]] = None

    @model_validator(mode="after")
    def populate_sub_conf(self) -> "HandshakeConf":
        if self.type == "noise" and self.noise is None:
            self.noise = NoiseConf()
        if self.type == "tls-token" and self.tls_token is None:
            self.tls_token = TLSTokenConf()
        return self


class CryptoConf(BaseModel):
    aead: AEAD = "chacha20-poly1305"
    kdf:  KDF  = "hkdf-sha256"


class PaddingConf(BaseModel):
    mode:       PaddingMode              = "mimicry"
    fixed_size: Optional[int]            = Field(default=None, ge=1)
    random_min: Optional[int]            = Field(default=None, ge=1)
    random_max: Optional[int]            = Field(default=None, ge=1)
    profile:    Optional[MimicryProfile] = "chrome-browsing"

    @model_validator(mode="after")
    def check_mode_fields(self) -> "PaddingConf":
        if self.mode == "fixed" and not self.fixed_size:
            self.fixed_size = 1200
        if self.mode == "random":
            if not self.random_min:
                self.random_min = 200
            if not self.random_max:
                self.random_max = 1400
        return self


class TimingConf(BaseModel):
    mode:              TimingMode   = "none"
    batch_interval_ms: Optional[int] = Field(default=None, ge=1)
    delay_min_ms:      Optional[int] = Field(default=None, ge=0)
    delay_max_ms:      Optional[int] = Field(default=None, ge=0)


class FallbackConf(BaseModel):
    enabled: bool                  = True
    mode:    FallbackMode          = "reverse-proxy"
    target:  Optional[str]         = "https://www.google.com"


# ─────────────────────────────────────────────────────────────────────────────
# Root DSL document
# ─────────────────────────────────────────────────────────────────────────────

class TunnelConfig(BaseModel):
    """Complete tunnel-gen DSL document."""
    protocol:  str          = Field(description="Short human-readable protocol name, e.g. 'llm-gen-v1'")
    version:   int          = 1
    transport: TransportConf
    handshake: HandshakeConf
    crypto:    CryptoConf   = Field(default_factory=CryptoConf)
    padding:   PaddingConf  = Field(default_factory=PaddingConf)
    timing:    TimingConf   = Field(default_factory=TimingConf)
    fallback:  FallbackConf = Field(default_factory=FallbackConf)


# ─────────────────────────────────────────────────────────────────────────────
# LLM generation result  (structured output schema)
# ─────────────────────────────────────────────────────────────────────────────

Verdict = Literal["PASS", "FAIL", "UNCERTAIN"]


class MetricPrediction(BaseModel):
    """LLM's self-assessment for a single detection metric."""
    verdict:     Verdict = "UNCERTAIN"
    explanation: str     = ""


class _DefaultPrediction:
    """Factory that returns a default MetricPrediction — used as Field default."""
    def __call__(self) -> MetricPrediction:
        return MetricPrediction()


class StealthPrediction(BaseModel):
    """LLM's prediction of which metrics its config will pass."""
    m1_ndpi:     MetricPrediction = Field(default_factory=MetricPrediction,
                     description="nDPI classification — should not classify as VPN")
    m2_suricata: MetricPrediction = Field(default_factory=MetricPrediction,
                     description="Suricata IDS — should produce zero alerts")
    m3_zeek:     MetricPrediction = Field(default_factory=MetricPrediction,
                     description="Zeek JA3 / payload entropy — browser fingerprint or no raw-noise")
    m4_ml:       MetricPrediction = Field(default_factory=MetricPrediction,
                     description="Flow ML classifier — vpn_prob < 0.65")
    m6_kl_len:   MetricPrediction = Field(default_factory=MetricPrediction,
                     description="KL divergence of packet lengths vs HTTPS")
    m8_probe:    MetricPrediction = Field(default_factory=MetricPrediction,
                     description="Active probe resistance — fallback must return legit HTTPS")


def _parse_stealth_string(text: str) -> dict:
    """
    Gemini sometimes returns stealth_prediction as a plain-text string like:
      "M1: PASS (TLS on standard port)\nM2: PASS ..."
    Convert it to the expected dict structure.
    """
    mapping = {
        "M1": "m1_ndpi", "M2": "m2_suricata",
        "M3": "m3_zeek", "M4": "m4_ml",
        "M6": "m6_kl_len", "M8": "m8_probe",
    }
    result: dict = {}
    for line in text.splitlines():
        for key, field in mapping.items():
            if line.strip().upper().startswith(key):
                verdict = "UNCERTAIN"
                if "PASS" in line.upper():
                    verdict = "PASS"
                elif "FAIL" in line.upper():
                    verdict = "FAIL"
                result[field] = {"verdict": verdict, "explanation": line.strip()}
                break
    return result


class GenerationResult(BaseModel):
    """
    Structured output returned by the LLM.
    The 'config' field is serialized to YAML and passed to tunnel-gen.
    """
    reasoning: str = Field(
        default="",
        description=(
            "Step-by-step design rationale: why each section was chosen. "
            "Cover transport, handshake, padding, fallback decisions."
        ),
    )
    config: TunnelConfig = Field(
        description="The complete tunnel DSL configuration."
    )
    stealth_prediction: StealthPrediction = Field(
        default_factory=StealthPrediction,
        description="Per-metric PASS/FAIL/UNCERTAIN prediction with justification.",
    )
    known_weaknesses: List[str] = Field(
        default_factory=list,
        description=(
            "List of potential detection vectors this config may still trigger. "
            "Be honest about trade-offs."
        ),
    )

    @field_validator("config", mode="before")
    @classmethod
    def coerce_config_from_string(cls, v: object) -> object:
        if isinstance(v, str):
            import yaml as _yaml
            return _yaml.safe_load(v)
        return v

    @field_validator("stealth_prediction", mode="before")
    @classmethod
    def coerce_stealth_from_string(cls, v: object) -> object:
        if isinstance(v, str):
            return _parse_stealth_string(v)
        return v

    @field_validator("known_weaknesses", mode="before")
    @classmethod
    def coerce_weaknesses_to_list(cls, v: object) -> list:
        if isinstance(v, str):
            # Model returned a plain string — wrap it
            return [v] if v.strip() else []
        return v if isinstance(v, list) else []
