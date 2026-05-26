"""
Cross-model comparison analysis.

Loads all run artifacts from results/ and produces:
  1. Per-model summary table  (pass rate, token cost, check breakdown)
  2. Full runs table           (one row per run)
  3. Model prediction accuracy (how well each model predicted its own scores)
  4. Comparison with reference configs
  5. Diversity metrics         (unique fingerprints, handshake types, SNI domains)
  6. comparison_report.json    (machine-readable, for thesis tables)

Usage:
    python comparison.py
    python comparison.py --results-dir results/ --output comparison_report.json
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

RESULTS_DIR = Path(__file__).parent / "results"

CHECKS = ["M1_ndpi", "M2_suricata", "M3_ja3", "M4_vpn_prob",
          "M5_vpn_prob_seq", "M6_kl_len", "M7_kl_iat", "M8_probe"]

SHORT = {
    "M1_ndpi":        "M1",
    "M2_suricata":    "M2",
    "M3_ja3":         "M3",
    "M4_vpn_prob":    "M4",
    "M5_vpn_prob_seq":"M5",
    "M6_kl_len":      "M6",
    "M7_kl_iat":      "M7",
    "M8_probe":       "M8",
}


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RunRecord:
    """One test run — either LLM-generated or reference."""
    source:      str            # model_id or "reference"
    label:       str            # short display name
    run_id:      str
    verdict:     Optional[str]  # PASS / FAIL / None (no report)
    checks:      dict           # check_key → "PASS" | "FAIL" | "SKIP" | None
    error:       Optional[str]

    # LLM-specific fields (None for reference configs)
    protocol:    Optional[str]  = None
    fingerprint: Optional[str]  = None
    handshake:   Optional[str]  = None
    sni:         Optional[str]  = None
    padding:     Optional[str]  = None
    has_fallback: Optional[bool] = None
    tokens_total: Optional[int] = None
    elapsed_s:   Optional[float] = None

    # Prediction accuracy
    pred_correct: Optional[int] = None   # checks where prediction matched actual
    pred_total:   Optional[int] = None


def _check_result(checks: dict, key: str) -> Optional[str]:
    v = checks.get(key)
    if v is None:
        return None
    return v.get("result")   # "PASS" | "FAIL" | "SKIP"


def _load_llm_runs(results_dir: Path) -> list[RunRecord]:
    records: list[RunRecord] = []
    for model_dir in sorted(results_dir.iterdir()):
        if model_dir.name == "reference" or not model_dir.is_dir():
            continue
        for run_dir in sorted(model_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            gen_path    = run_dir / "generation.json"
            report_path = run_dir / "report.json"
            if not gen_path.exists():
                continue

            gen = json.loads(gen_path.read_text(encoding="utf-8"))
            result = gen.get("generation_result", {})
            cfg = result.get("config", {})
            transport = cfg.get("transport", {})
            tls = transport.get("tls", {})
            hs  = cfg.get("handshake", {})
            padding = cfg.get("padding", {})
            fallback = cfg.get("fallback", {})

            # Report
            verdict = error = None
            checks: dict = {}
            if report_path.exists():
                rep = json.loads(report_path.read_text(encoding="utf-8"))
                error = rep.get("error")
                if not error:
                    verdict = rep.get("verdict")
                    raw_checks = rep.get("checks", {})
                    checks = {k: _check_result(raw_checks, k) for k in CHECKS}

            # Prediction accuracy
            pred_correct = pred_total = None
            preds = result.get("stealth_prediction", {})
            # Map LLM prediction fields to check keys
            pred_map = {
                "M1_ndpi":         preds.get("m1_ndpi", {}).get("verdict"),
                "M2_suricata":     preds.get("m2_suricata", {}).get("verdict"),
                "M3_ja3":          preds.get("m3_zeek", {}).get("verdict"),
                "M4_vpn_prob":     preds.get("m4_ml", {}).get("verdict"),
                "M8_probe":        preds.get("m8_probe", {}).get("verdict"),
            }
            if verdict and preds:
                correct = total = 0
                for ck, pv in pred_map.items():
                    av = checks.get(ck)
                    if av in ("PASS", "FAIL") and pv in ("PASS", "FAIL"):
                        total += 1
                        if pv == av:
                            correct += 1
                pred_correct, pred_total = correct, total

            records.append(RunRecord(
                source=gen.get("model", model_dir.name),
                label=run_dir.name[:8],
                run_id=gen.get("run_id", run_dir.name),
                verdict=verdict,
                checks=checks,
                error=error,
                protocol=cfg.get("protocol"),
                fingerprint=tls.get("fingerprint"),
                handshake=hs.get("type"),
                sni=tls.get("sni"),
                padding=padding.get("mode"),
                has_fallback=fallback.get("enabled"),
                tokens_total=gen.get("tokens", {}).get("total"),
                elapsed_s=gen.get("elapsed_s"),
                pred_correct=pred_correct,
                pred_total=pred_total,
            ))
    return records


def _load_reference_runs(results_dir: Path) -> list[RunRecord]:
    ref_dir = results_dir / "reference"
    if not ref_dir.exists():
        return []
    records: list[RunRecord] = []
    for cfg_dir in sorted(ref_dir.iterdir()):
        if not cfg_dir.is_dir():
            continue
        report_path = cfg_dir / "report.json"
        verdict = error = None
        checks: dict = {}
        if report_path.exists():
            rep = json.loads(report_path.read_text(encoding="utf-8"))
            error = rep.get("error")
            if not error:
                verdict = rep.get("verdict")
                raw_checks = rep.get("checks", {})
                checks = {k: _check_result(raw_checks, k) for k in CHECKS}
        records.append(RunRecord(
            source="reference",
            label=cfg_dir.name,
            run_id=cfg_dir.name,
            verdict=verdict,
            checks=checks,
            error=error,
        ))
    return records


# ─────────────────────────────────────────────────────────────────────────────
# Statistics
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ModelStats:
    model:           str
    n_runs:          int
    n_tested:        int       # runs that have a report
    n_pass:          int
    pass_rate:       float
    check_pass:      dict      # check_key → pass count
    check_fail:      dict
    avg_tokens:      Optional[float]
    avg_elapsed:     Optional[float]
    pred_accuracy:   Optional[float]   # 0.0–1.0
    unique_fps:      list[str]
    unique_hs:       list[str]
    unique_snis:     list[str]


def _compute_model_stats(model: str, records: list[RunRecord]) -> ModelStats:
    n_runs   = len(records)
    tested   = [r for r in records if r.verdict is not None]
    n_tested = len(tested)
    n_pass   = sum(1 for r in tested if r.verdict == "PASS")

    check_pass: dict[str, int] = defaultdict(int)
    check_fail: dict[str, int] = defaultdict(int)
    for r in tested:
        for ck in CHECKS:
            v = r.checks.get(ck)
            if v == "PASS":
                check_pass[ck] += 1
            elif v == "FAIL":
                check_fail[ck] += 1

    tokens   = [r.tokens_total for r in records if r.tokens_total]
    elapsed  = [r.elapsed_s    for r in records if r.elapsed_s]
    preds    = [(r.pred_correct, r.pred_total) for r in records
                if r.pred_correct is not None and r.pred_total]
    if preds:
        tot_c = sum(c for c, _ in preds)
        tot_t = sum(t for _, t in preds)
        pred_acc = tot_c / tot_t if tot_t else None
    else:
        pred_acc = None

    return ModelStats(
        model=model,
        n_runs=n_runs,
        n_tested=n_tested,
        n_pass=n_pass,
        pass_rate=n_pass / n_tested if n_tested else 0.0,
        check_pass=dict(check_pass),
        check_fail=dict(check_fail),
        avg_tokens=sum(tokens) / len(tokens) if tokens else None,
        avg_elapsed=sum(elapsed) / len(elapsed) if elapsed else None,
        pred_accuracy=pred_acc,
        unique_fps=sorted({r.fingerprint for r in records if r.fingerprint}),
        unique_hs=sorted({r.handshake   for r in records if r.handshake}),
        unique_snis=sorted({r.sni       for r in records if r.sni}),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Rendering
# ─────────────────────────────────────────────────────────────────────────────

def _cell(v: Optional[str]) -> str:
    if v == "PASS":
        return "✓"
    if v == "FAIL":
        return "✗"
    if v == "SKIP":
        return "~"
    return "?"


def _render_runs_table(records: list[RunRecord], title: str = "") -> str:
    col_w = 22
    chk_w = 3
    lines = []
    if title:
        lines.append(f"\n{'─'*60}")
        lines.append(f"  {title}")
        lines.append(f"{'─'*60}")

    hdr = f"{'Config':<{col_w}}  {'Src':<16}"
    for ck in CHECKS:
        hdr += f" {SHORT[ck]:>{chk_w}}"
    hdr += f"  {'Verdict':<8}"
    lines.append(hdr)
    lines.append("─" * (col_w + 16 + len(CHECKS) * 4 + 12))

    prev_source = None
    for r in records:
        if r.source != prev_source and prev_source is not None:
            lines.append("")
        prev_source = r.source

        label = f"{r.source[:16]}/{r.label}" if r.source != "reference" else r.label
        row = f"{label[:col_w]:<{col_w}}  {r.source[:16]:<16}"
        for ck in CHECKS:
            row += f" {_cell(r.checks.get(ck)):>{chk_w}}"
        v = r.verdict or ("ERR" if r.error else "?")
        row += f"  {v:<8}"
        lines.append(row)

    return "\n".join(lines)


def _render_model_summary(stats: list[ModelStats]) -> str:
    lines = [f"\n{'═'*70}", "  MODEL SUMMARY", f"{'═'*70}"]

    col = 24
    hdr = f"{'Model':<{col}}  {'Runs':>5}  {'Tested':>6}  {'Pass%':>6}"
    for ck in CHECKS:
        hdr += f"  {SHORT[ck]:>3}"
    hdr += f"  {'Tok/run':>7}  {'PredAcc':>7}"
    lines.append(hdr)
    lines.append("─" * len(hdr))

    for st in stats:
        row = f"{st.model[:col]:<{col}}  {st.n_runs:>5}  {st.n_tested:>6}  {st.pass_rate*100:>5.0f}%"
        for ck in CHECKS:
            n = st.n_tested
            p = st.check_pass.get(ck, 0)
            row += f"  {p:>2}/{n}" if n else "   ?"
        tok = f"{int(st.avg_tokens):>7}" if st.avg_tokens else "      ?"
        pa  = f"{st.pred_accuracy*100:.0f}%" if st.pred_accuracy is not None else "     ?"
        row += f"  {tok}  {pa:>7}"
        lines.append(row)

    return "\n".join(lines)


def _render_diversity(llm_records: list[RunRecord]) -> str:
    by_model: dict[str, list[RunRecord]] = defaultdict(list)
    for r in llm_records:
        by_model[r.source].append(r)

    lines = [f"\n{'─'*60}", "  DIVERSITY (LLM-generated configs)", f"{'─'*60}"]
    for model, recs in sorted(by_model.items()):
        fps  = sorted({r.fingerprint for r in recs if r.fingerprint})
        hss  = sorted({r.handshake   for r in recs if r.handshake})
        sns  = sorted({r.sni         for r in recs if r.sni})
        pads = sorted({r.padding     for r in recs if r.padding})
        lines.append(f"\n  {model}:")
        lines.append(f"    fingerprints : {fps}")
        lines.append(f"    handshakes   : {hss}")
        lines.append(f"    sni_domains  : {sns[:5]}{'…' if len(sns) > 5 else ''}")
        lines.append(f"    padding_modes: {pads}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def build_comparison_report(results_dir: Path) -> dict:
    llm_records = _load_llm_runs(results_dir)
    ref_records = _load_reference_runs(results_dir)

    # Per-model stats
    models = sorted({r.source for r in llm_records})
    stats  = [_compute_model_stats(m, [r for r in llm_records if r.source == m])
              for m in models]

    # JSON report
    report = {
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "models": [
            {
                "model":        st.model,
                "n_runs":       st.n_runs,
                "n_tested":     st.n_tested,
                "pass_rate":    round(st.pass_rate, 3),
                "check_pass":   st.check_pass,
                "check_fail":   st.check_fail,
                "avg_tokens":   round(st.avg_tokens) if st.avg_tokens else None,
                "avg_elapsed_s":round(st.avg_elapsed, 1) if st.avg_elapsed else None,
                "pred_accuracy":round(st.pred_accuracy, 3) if st.pred_accuracy is not None else None,
                "diversity": {
                    "unique_fingerprints": st.unique_fps,
                    "unique_handshakes":   st.unique_hs,
                    "unique_snis":         st.unique_snis,
                },
            }
            for st in stats
        ],
        "reference": [
            {
                "name":    r.label,
                "verdict": r.verdict,
                "checks":  r.checks,
                "error":   r.error,
            }
            for r in ref_records
        ],
        "all_runs": [
            {
                "source":       r.source,
                "run_id":       r.run_id,
                "verdict":      r.verdict,
                "checks":       r.checks,
                "protocol":     r.protocol,
                "fingerprint":  r.fingerprint,
                "handshake":    r.handshake,
                "sni":          r.sni,
                "padding":      r.padding,
                "has_fallback": r.has_fallback,
                "tokens_total": r.tokens_total,
                "pred_correct": r.pred_correct,
                "pred_total":   r.pred_total,
            }
            for r in llm_records + ref_records
        ],
    }
    return report


def main() -> None:
    p = argparse.ArgumentParser(description="Comparison analysis of LLM tunnel generation results")
    p.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    p.add_argument("--output", type=Path, default=None,
                   help="Path to write comparison_report.json (default: results/comparison_report.json)")
    args = p.parse_args()

    results_dir: Path = args.results_dir
    output_path: Path = args.output or (results_dir / "comparison_report.json")

    llm_records = _load_llm_runs(results_dir)
    ref_records = _load_reference_runs(results_dir)

    if not llm_records and not ref_records:
        print("No results found. Run pipeline.py first.")
        return

    # ── Build stats ───────────────────────────────────────────────────────────
    models = sorted({r.source for r in llm_records})
    stats  = [_compute_model_stats(m, [r for r in llm_records if r.source == m])
              for m in models]

    # ── Print tables ──────────────────────────────────────────────────────────
    all_records = sorted(llm_records, key=lambda r: (r.source, r.run_id)) + ref_records
    print(_render_runs_table(all_records, "ALL RUNS"))
    if stats:
        print(_render_model_summary(stats))
    if ref_records:
        print(_render_runs_table(ref_records, "REFERENCE CONFIGS"))
    if llm_records:
        print(_render_diversity(llm_records))

    # ── Save JSON ─────────────────────────────────────────────────────────────
    report = build_comparison_report(results_dir)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  Saved → {output_path}")


if __name__ == "__main__":
    main()
