"""
Tunnel-testing integration.

evaluate_config()  prepares the YAML (injects certs, PSK, ports) and
calls tunnel-testing/run_test.py, returning the M1–M8 report dict.

evaluate_reference()  runs tunnel-testing on one of the pre-existing
tunnel-gen example configs (useful for building the comparison baseline).
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import yaml

log = logging.getLogger(__name__)

# Paths relative to this file's location (llm-eval/)
_HERE              = Path(__file__).parent
TUNNEL_TESTING_DIR = _HERE.parent / "tunnel-testing"
TUNNEL_GEN_DIR     = _HERE.parent / "tunnel-gen"

_RUN_TEST   = TUNNEL_TESTING_DIR / "run_test.py"
_EXAMPLES   = TUNNEL_GEN_DIR / "examples"

# Port range for automated runs  (avoids conflicts with user services)
_BASE_PORT  = 19400


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_config(
    config_yaml: str,
    work_dir:    Path,
    port:        int   = _BASE_PORT,
    scenario:    str   = "web",
    duration:    int   = 30,
) -> dict:
    """
    Prepare config, run tunnel-testing, return report dict.

    On any failure the returned dict contains an 'error' key.
    work_dir is used for cert files and tunnel-testing output.
    """
    work_dir.mkdir(parents=True, exist_ok=True)

    try:
        prepared_path = _prepare_config(config_yaml, work_dir, port)
    except Exception as exc:
        log.error("config preparation failed: %s", exc, exc_info=True)
        return {"error": f"config_prepare: {exc}"}

    return _run_tunnel_test(prepared_path, work_dir / "test_out", scenario, duration)


def evaluate_reference(
    config_name: str,
    work_dir:    Path,
    port:        int  = _BASE_PORT + 50,
    scenario:    str  = "web",
    duration:    int  = 30,
) -> dict:
    """
    Run tunnel-testing on an existing example config from tunnel-gen/examples/.
    config_name is just the stem, e.g. 'baseline-plain-tls'.
    """
    src = _EXAMPLES / f"{config_name}.yaml"
    if not src.exists():
        return {"error": f"reference config not found: {src}"}

    raw_yaml = src.read_text(encoding="utf-8")
    return evaluate_config(raw_yaml, work_dir, port=port, scenario=scenario, duration=duration)


def list_reference_configs() -> list[str]:
    """Return stems of all example configs in tunnel-gen/examples/."""
    return sorted(p.stem for p in _EXAMPLES.glob("*.yaml"))


# ─────────────────────────────────────────────────────────────────────────────
# Config preparation
# ─────────────────────────────────────────────────────────────────────────────

def _prepare_config(config_yaml: str, work_dir: Path, port: int) -> Path:
    """
    Parse YAML, inject:
      - TLS cert/key  (generated on demand)
      - Noise PSK and local_key if missing
      - TLS-token PSK if missing
      - Port (override with caller-supplied value)

    Returns path to the modified config.yaml.
    """
    cfg = yaml.safe_load(config_yaml)

    # Override port to avoid conflicts
    cfg.setdefault("transport", {})["port"] = port

    transport_type = cfg["transport"].get("type", "tls")

    # ── TLS cert ─────────────────────────────────────────────────────────────
    if transport_type == "tls":
        tls = cfg["transport"].setdefault("tls", {})
        sni = tls.get("sni") or "localhost"
        cert_p, key_p = _ensure_cert(work_dir, sni)
        tls["cert_file"] = str(cert_p)
        tls["key_file"]  = str(key_p)
        tls.setdefault("insecure", True)

    # ── Handshake key material ───────────────────────────────────────────────
    hs   = cfg.setdefault("handshake", {})
    hs_type = hs.get("type", "none")

    if hs_type == "tls-token":
        tt = hs.setdefault("tls_token", {})
        if not tt.get("psk"):
            tt["psk"] = secrets.token_hex(32)

    elif hs_type == "noise":
        cfg = _prepare_noise(cfg)

    # ── Write final config ───────────────────────────────────────────────────
    config_path = work_dir / "config.yaml"
    config_path.write_text(
        yaml.dump(cfg, default_flow_style=False, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    log.debug("Prepared config → %s", config_path)
    return config_path


def _is_valid_pem(path: Path) -> bool:
    try:
        return b"-----BEGIN" in path.read_bytes()
    except Exception:
        return False


def _ensure_cert(work_dir: Path, cn: str) -> tuple[Path, Path]:
    """
    Generate a self-signed TLS cert/key in work_dir using the `cryptography`
    library (pure Python — no openssl subprocess, no system openssl.cnf conflicts).
    Re-generates if the files are missing or not valid PEM.
    """
    cert_p = work_dir / "server.crt"
    key_p  = work_dir / "server.key"

    if _is_valid_pem(cert_p) and _is_valid_pem(key_p):
        return cert_p, key_p

    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    safe_cn = cn[:64] or "localhost"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, safe_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, safe_cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(safe_cn)]),
            critical=False,
        )
    )
    cert = builder.sign(key, hashes.SHA256())

    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    log.debug("Generated cert CN=%s → %s", safe_cn, cert_p)
    return cert_p, key_p


def _prepare_noise(cfg: dict) -> dict:
    """Inject PSK and build/call keygen for static-key patterns."""
    noise = cfg["handshake"].setdefault("noise", {})
    pattern = noise.get("pattern", "NNpsk2")

    # PSK for psk-patterns
    if "psk" in pattern.lower() and not noise.get("psk"):
        noise["psk"] = secrets.token_hex(32)

    # Static-key patterns need a real keypair
    # NN/NNpsk* work with local_key="generate" (ephemeral only)
    if pattern in ("NN", "NNpsk0", "NNpsk2"):
        noise.setdefault("local_key", "generate")
        return cfg

    # For other patterns (XX, IK, NK, …) attempt to generate via keygen binary
    if not noise.get("local_key") or noise["local_key"] == "generate":
        keypair = _run_keygen()
        if keypair:
            priv, pub = keypair
            noise["local_key"] = priv
            # For IK/IKpsk2 the remote_key is the OTHER side's public key.
            # Since we use the same config for both sides in test runs, set
            # remote_key to the same pub — the runtime will handle role separation.
            if pattern in ("IK", "IKpsk2", "NK") and not noise.get("remote_key"):
                noise["remote_key"] = pub
        else:
            # Fall back to ephemeral
            log.warning("keygen failed; falling back to local_key=generate")
            noise["local_key"] = "generate"

    return cfg


def _run_keygen() -> Optional[tuple[str, str]]:
    """
    Run tunnel-gen's keygen and return (private_hex, public_hex).
    Returns None on any error.
    """
    keygen_bin = TUNNEL_GEN_DIR / "keygen"
    if not keygen_bin.exists():
        # Try to build it
        res = subprocess.run(
            ["go", "build", "-o", str(keygen_bin), "./keygen"],
            cwd=TUNNEL_GEN_DIR,
            capture_output=True,
            timeout=60,
        )
        if res.returncode != 0 or not keygen_bin.exists():
            log.warning("go build keygen failed: %s", res.stderr.decode()[:300])
            return None

    try:
        res = subprocess.run(
            [str(keygen_bin)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        priv = pub = None
        for line in res.stdout.splitlines():
            if line.startswith("private:"):
                priv = line.split(":", 1)[1].strip()
            elif line.startswith("public:"):
                pub = line.split(":", 1)[1].strip()
        if priv and pub:
            return priv, pub
    except Exception as exc:
        log.warning("keygen error: %s", exc)

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Tunnel-testing runner
# ─────────────────────────────────────────────────────────────────────────────

def _run_tunnel_test(
    config_path: Path,
    output_dir:  Path,
    scenario:    str,
    duration:    int,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    if not _RUN_TEST.exists():
        return {"error": f"run_test.py not found at {_RUN_TEST}"}

    cmd = [
        "python", str(_RUN_TEST),
        "--config",   str(config_path),
        "--root",     str(TUNNEL_GEN_DIR),
        "--scenario", scenario,
        "--duration", str(duration),
        "--output",   str(output_dir),
    ]

    timeout_s = duration * 4 + 180
    log.info("Running: %s  (timeout %ds)", " ".join(cmd[2:]), timeout_s)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=TUNNEL_TESTING_DIR,
            env={**os.environ},
        )
    except subprocess.TimeoutExpired:
        return {"error": "tunnel-testing timeout", "timeout_s": timeout_s}
    except Exception as exc:
        return {"error": str(exc)}

    report_path = output_dir / "report.json"
    if not report_path.exists():
        return {
            "error":      "no report.json produced",
            "returncode": proc.returncode,
            "stdout":     proc.stdout[-2000:],
            "stderr":     proc.stderr[-2000:],
        }

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"error": f"report parse error: {exc}"}

    log.info(
        "Verdict: %s  (rc=%d)",
        report.get("verdict", "?"), proc.returncode,
    )
    return report
