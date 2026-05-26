"""
LLM Tunnel Config Generation + Testing Pipeline
================================================

Usage examples
--------------

# Generate 5 configs with claude-opus-4, then test each one:
python pipeline.py generate --model claude-opus-4 --runs 5

# Test the reference configs from tunnel-gen/examples/ (baseline):
python pipeline.py reference

# Run everything for multiple models in one shot:
python pipeline.py run-all --models claude-opus-4 gpt-4o deepseek-chat --runs 5

# Just show available models:
python pipeline.py models

Artifacts are written to:
  results/{model_id}/{run_id}/
    config.yaml          — final prepared config (cert paths injected)
    generation.json      — GenerationResult + provider metadata
    report.json          — M1–M8 test report from tunnel-testing
  results/reference/{config_name}/
    report.json

All generation.json files use the GenerationResult Pydantic schema (structured output).
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from evaluator import evaluate_config, evaluate_reference, list_reference_configs
from generator import GenerationArtifact, TASK_VARIANTS, generate_config
from providers import build_provider, list_models
from serializer import config_to_yaml

log = logging.getLogger(__name__)

RESULTS_DIR = Path(__file__).parent / "results"


# ─────────────────────────────────────────────────────────────────────────────
# Artifact I/O
# ─────────────────────────────────────────────────────────────────────────────

def _save_generation(artifact: GenerationArtifact, run_dir: Path) -> None:
    """Write generation.json (structured output) and config.yaml to run_dir."""
    run_dir.mkdir(parents=True, exist_ok=True)

    # generation.json — everything the LLM produced + metadata
    generation_doc = {
        "run_id":         artifact.run_id,
        "timestamp":      datetime.fromtimestamp(artifact.started_at, tz=timezone.utc).isoformat(),
        "elapsed_s":      round(artifact.elapsed_s, 2),
        "model":          artifact.model_id,
        "provider":       artifact.provider_meta.provider,
        "tokens": {
            "prompt":     artifact.provider_meta.prompt_tokens,
            "completion": artifact.provider_meta.completion_tokens,
            "total":      artifact.provider_meta.total_tokens,
        },
        "variant": {
            "index":         artifact.variant_index,
            **artifact.variant,
        },
        # The full GenerationResult (structured output schema)
        "generation_result": artifact.generation_result.model_dump(mode="json"),
    }
    (run_dir / "generation.json").write_text(
        json.dumps(generation_doc, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # config.yaml — the YAML that will be (or was) submitted to tunnel-testing
    (run_dir / "config.yaml").write_text(artifact.config_yaml, encoding="utf-8")


def _save_report(report: dict, run_dir: Path) -> None:
    (run_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _run_dir(model_id: str, run_id: str) -> Path:
    safe_model = model_id.replace("/", "_").replace(":", "_")
    return RESULTS_DIR / safe_model / run_id


def _ref_dir(config_name: str) -> Path:
    return RESULTS_DIR / "reference" / config_name


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_generate(args: argparse.Namespace) -> None:
    """Generate N configs with one model, optionally test each one."""
    provider = build_provider(
        args.model,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
    )
    model_id = provider.model_id

    print(f"\n{'─'*60}")
    print(f"  Model  : {model_id}")
    print(f"  Runs   : {args.runs}")
    print(f"  Test   : {'yes' if args.test else 'no'}")
    print(f"  Output : {RESULTS_DIR / model_id.replace('/', '_')}")
    print(f"{'─'*60}\n")

    for i in range(args.runs):
        port = args.base_port + i

        # ── Generate ─────────────────────────────────────────────────────────
        try:
            artifact = generate_config(
                provider=provider,
                run_index=i,
                total_runs=args.runs,
            )
        except Exception as exc:
            log.error("Generation %d/%d failed: %s", i + 1, args.runs, exc, exc_info=True)
            continue

        run_dir = _run_dir(model_id, artifact.run_id)
        _save_generation(artifact, run_dir)
        _print_generation_summary(artifact, i + 1, args.runs)

        # ── Test ──────────────────────────────────────────────────────────────
        if args.test:
            print(f"  ↳ running tunnel-testing (port {port}, {args.duration}s)…")
            report = evaluate_config(
                config_yaml=artifact.config_yaml,
                work_dir=run_dir,
                port=port,
                scenario=args.scenario,
                duration=args.duration,
            )
            _save_report(report, run_dir)
            _print_report_summary(report)
        else:
            print("  ↳ skipping test (use --test to enable)\n")


def cmd_reference(args: argparse.Namespace) -> None:
    """Run tunnel-testing on all reference configs from tunnel-gen/examples/."""
    names = list_reference_configs()
    if not names:
        print("No reference configs found in tunnel-gen/examples/")
        return

    print(f"\nRunning {len(names)} reference configs:\n")
    for i, name in enumerate(names):
        port = args.base_port + i
        print(f"  [{i+1}/{len(names)}] {name}  (port {port})")
        ref_dir = _ref_dir(name)
        ref_dir.mkdir(parents=True, exist_ok=True)

        report = evaluate_reference(
            config_name=name,
            work_dir=ref_dir,
            port=port,
            scenario=args.scenario,
            duration=args.duration,
        )
        _save_report(report, ref_dir)
        _print_report_summary(report)


def cmd_run_all(args: argparse.Namespace) -> None:
    """Generate + test configs for multiple models sequentially."""
    for model_alias in args.models:
        print(f"\n{'='*60}")
        print(f"  MODEL: {model_alias}")
        print(f"{'='*60}")
        # Reuse cmd_generate with a synthetic namespace
        sub = argparse.Namespace(
            model=model_alias,
            runs=args.runs,
            test=True,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            base_port=args.base_port,
            scenario=args.scenario,
            duration=args.duration,
        )
        try:
            cmd_generate(sub)
        except Exception as exc:
            log.error("Model %s failed: %s", model_alias, exc, exc_info=True)

    if args.reference:
        print(f"\n{'='*60}")
        print("  REFERENCE CONFIGS")
        print(f"{'='*60}")
        cmd_reference(argparse.Namespace(
            base_port=args.base_port + 100,
            scenario=args.scenario,
            duration=args.duration,
        ))


def cmd_models(_args: argparse.Namespace) -> None:
    """List available model aliases."""
    print("\nAvailable models:")
    for m in list_models():
        print(f"  {m}")


# ─────────────────────────────────────────────────────────────────────────────
# Terminal output helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_generation_summary(art: GenerationArtifact, n: int, total: int) -> None:
    cfg = art.generation_result.config
    pred = art.generation_result.stealth_prediction
    print(f"\n  [{n}/{total}] run_id={art.run_id[:8]}…")
    print(f"        protocol : {cfg.protocol}")
    print(f"        transport: {cfg.transport.type}  port={cfg.transport.port}")
    if cfg.transport.tls:
        print(f"        tls      : fp={cfg.transport.tls.fingerprint}  sni={cfg.transport.tls.sni}")
    print(f"        handshake: {cfg.handshake.type}")
    print(f"        padding  : {cfg.padding.mode}")
    print(f"        fallback : {cfg.fallback.enabled}  target={cfg.fallback.target}")
    print(f"        tokens   : {art.provider_meta.total_tokens}  ({art.elapsed_s:.1f}s)")
    # Predicted verdicts
    preds_str = "  ".join([
        f"M1={pred.m1_ndpi.verdict[0]}",
        f"M2={pred.m2_suricata.verdict[0]}",
        f"M3={pred.m3_zeek.verdict[0]}",
        f"M4={pred.m4_ml.verdict[0]}",
        f"M6={pred.m6_kl_len.verdict[0]}",
        f"M8={pred.m8_probe.verdict[0]}",
    ])
    print(f"        predicted: {preds_str}")
    if art.generation_result.known_weaknesses:
        for w in art.generation_result.known_weaknesses[:2]:
            print(f"        ⚠  {w}")


def _print_report_summary(report: dict) -> None:
    if "error" in report:
        print(f"  ✗ ERROR: {report['error']}\n")
        return

    verdict = report.get("verdict", "?")
    mark = "✓" if verdict == "PASS" else "✗"
    checks = report.get("checks", {})
    check_line = "  ".join(
        f"{k.split('_')[0]}={'✓' if v.get('result') == 'PASS' else ('?' if v.get('result') == 'SKIP' else '✗')}"
        for k, v in sorted(checks.items())
    )
    print(f"  {mark} VERDICT: {verdict}")
    print(f"     {check_line}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="LLM Tunnel Config Generation + Testing Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    sub = p.add_subparsers(dest="command", required=True)

    # ── generate ──────────────────────────────────────────────────────────────
    g = sub.add_parser("generate", help="Generate (and optionally test) N configs with one model")
    g.add_argument("--model",       required=True,  help="Model alias (see 'models' subcommand)")
    g.add_argument("--runs",        type=int, default=5, help="Number of configs to generate")
    g.add_argument("--test",        action="store_true", help="Run tunnel-testing on each generated config")
    g.add_argument("--scenario",    default="web",  choices=["web", "bulk", "idle"])
    g.add_argument("--duration",    type=int, default=30)
    g.add_argument("--base-port",   type=int, default=19443, dest="base_port")
    g.add_argument("--temperature", type=float, default=1.0)
    g.add_argument("--max-tokens",  type=int, default=4096, dest="max_tokens")

    # ── reference ─────────────────────────────────────────────────────────────
    r = sub.add_parser("reference", help="Run tunnel-testing on tunnel-gen example configs")
    r.add_argument("--scenario",  default="web", choices=["web", "bulk", "idle"])
    r.add_argument("--duration",  type=int, default=30)
    r.add_argument("--base-port", type=int, default=19500, dest="base_port")

    # ── run-all ───────────────────────────────────────────────────────────────
    ra = sub.add_parser("run-all", help="Generate + test for multiple models; optionally include reference")
    ra.add_argument("--models",     nargs="+", required=True)
    ra.add_argument("--runs",       type=int, default=5)
    ra.add_argument("--reference",  action="store_true", help="Also run reference configs")
    ra.add_argument("--scenario",   default="web", choices=["web", "bulk", "idle"])
    ra.add_argument("--duration",   type=int, default=30)
    ra.add_argument("--base-port",  type=int, default=19443, dest="base_port")
    ra.add_argument("--temperature",type=float, default=1.0)
    ra.add_argument("--max-tokens", type=int, default=4096, dest="max_tokens")

    # ── models ────────────────────────────────────────────────────────────────
    sub.add_parser("models", help="List available model aliases")

    return p


def main() -> None:
    p = _build_parser()
    args = p.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    dispatch = {
        "generate":  cmd_generate,
        "reference": cmd_reference,
        "run-all":   cmd_run_all,
        "models":    cmd_models,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
