"""
Deep analysis of 20-run results for the 4 flagship models.
Run after all 20-run batches complete.
"""
from __future__ import annotations

import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"
MODELS_20 = ["claude-opus-4", "gpt-4o", "deepseek-r1", "gemini-2.5-pro"]


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_model_runs(model_id: str) -> list[dict]:
    d = RESULTS_DIR / model_id
    rows = []
    if not d.exists():
        return rows
    for run_dir in sorted(d.iterdir()):
        if not run_dir.is_dir():
            continue
        gp = run_dir / "generation.json"
        rp = run_dir / "report.json"
        if not gp.exists():
            continue
        gen = json.loads(gp.read_text(encoding="utf-8"))
        result = gen.get("generation_result", {})
        cfg = result.get("config", {})
        tls = cfg.get("transport", {}).get("tls", {})
        hs = cfg.get("handshake", {})
        pad = cfg.get("padding", {})
        timing = cfg.get("timing", {})
        fallback = cfg.get("fallback", {})
        weaknesses = result.get("known_weaknesses", [])
        preds = result.get("stealth_prediction", {})

        verdict = error = None
        kl_iat = kl_len = vpn_prob = None
        m_checks = {}
        if rp.exists():
            rep = json.loads(rp.read_text(encoding="utf-8"))
            error = rep.get("error")
            if not error:
                verdict = rep.get("verdict")
                checks = rep.get("checks", {})
                for k, v in checks.items():
                    m_checks[k] = v.get("result")
                flow = rep.get("raw", {}).get("m4_m7_flow", {})
                kl_iat = flow.get("kl_iat")
                kl_len = flow.get("kl_len")
                vpn_prob = flow.get("vpn_prob")

        rows.append({
            "model": model_id,
            "run_id": gen.get("run_id", run_dir.name)[:8],
            "tokens": gen.get("tokens", {}).get("total"),
            "elapsed_s": gen.get("elapsed_s"),
            "variant": gen.get("variant_index"),
            "fp": tls.get("fingerprint"),
            "sni": tls.get("sni", ""),
            "port": cfg.get("transport", {}).get("port"),
            "handshake": hs.get("type"),
            "noise_pattern": hs.get("noise", {}).get("pattern") if hs.get("type") == "noise" else None,
            "padding": pad.get("mode"),
            "pad_min": pad.get("random_min"),
            "pad_max": pad.get("random_max"),
            "mimicry_profile": pad.get("mimicry_profile"),
            "timing": timing.get("mode", "none"),
            "fallback_target": fallback.get("target", ""),
            "n_weaknesses": len(weaknesses),
            "weakness_text": " ".join(weaknesses).lower(),
            "preds": preds,
            "verdict": verdict,
            "error": error,
            "kl_iat": kl_iat,
            "kl_len": kl_len,
            "vpn_prob": vpn_prob,
            "checks": m_checks,
        })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Statistics helpers
# ─────────────────────────────────────────────────────────────────────────────

def pass_rate(rows: list[dict]) -> tuple[int, int, float]:
    tested = [r for r in rows if r["verdict"] is not None]
    n_pass = sum(1 for r in tested if r["verdict"] == "PASS")
    rate = n_pass / len(tested) if tested else 0.0
    return n_pass, len(tested), rate


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for a proportion."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def check_rates(rows: list[dict], check: str) -> tuple[int, int]:
    tested = [r for r in rows if r["checks"].get(check) in ("PASS", "FAIL")]
    n_pass = sum(1 for r in tested if r["checks"].get(check) == "PASS")
    return n_pass, len(tested)


# ─────────────────────────────────────────────────────────────────────────────
# Main analysis
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    all_rows: dict[str, list[dict]] = {}
    for m in MODELS_20:
        rows = load_model_runs(m)
        all_rows[m] = rows

    # ── 1. Summary table ──────────────────────────────────────────────────────
    print("\n" + "═" * 80)
    print("  20-RUN DEEP-DIVE SUMMARY")
    print("═" * 80)
    hdr = f"{'Model':<22} {'n':>4} {'PASS%':>6}  {'95% CI':>14}  {'M6':>5}  {'M7':>5}  {'tok/r':>6}  {'s/r':>5}"
    print(hdr)
    print("─" * len(hdr))

    for m in MODELS_20:
        rows = all_rows[m]
        k, n, rate = pass_rate(rows)
        lo, hi = wilson_ci(k, n)
        m6_p, m6_n = check_rates(rows, "M6_kl_len")
        m7_p, m7_n = check_rates(rows, "M7_kl_iat")
        tok = [r["tokens"] for r in rows if r["tokens"]]
        ela = [r["elapsed_s"] for r in rows if r["elapsed_s"]]
        avg_tok = statistics.mean(tok) if tok else 0
        avg_ela = statistics.mean(ela) if ela else 0
        ci_str = f"[{lo*100:.0f}%–{hi*100:.0f}%]"
        m6_str = f"{m6_p}/{m6_n}"
        m7_str = f"{m7_p}/{m7_n}"
        print(f"  {m:<20} {n:>4} {rate*100:>5.0f}%  {ci_str:>14}  {m6_str:>5}  {m7_str:>5}  {avg_tok:>6.0f}  {avg_ela:>5.1f}s")

    # ── 2. KL distributions ───────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("  KL_IAT distribution (PASS vs FAIL runs)")
    print("─" * 60)
    for m in MODELS_20:
        rows = all_rows[m]
        pass_iats = [r["kl_iat"] for r in rows if r["kl_iat"] and r["verdict"] == "PASS"]
        fail_iats = [r["kl_iat"] for r in rows if r["kl_iat"] and r["verdict"] == "FAIL"]
        if pass_iats:
            print(f"  {m} PASS  n={len(pass_iats):2d}  "
                  f"μ={statistics.mean(pass_iats):.3f}  "
                  f"σ={statistics.pstdev(pass_iats):.3f}  "
                  f"[{min(pass_iats):.3f}–{max(pass_iats):.3f}]")
        if fail_iats:
            print(f"  {m} FAIL  n={len(fail_iats):2d}  "
                  f"μ={statistics.mean(fail_iats):.3f}  "
                  f"σ={statistics.pstdev(fail_iats):.3f}  "
                  f"[{min(fail_iats):.3f}–{max(fail_iats):.3f}]")
        print()

    # ── 3. Design choice breakdown ────────────────────────────────────────────
    print("─" * 60)
    print("  DESIGN CHOICES (per model)")
    print("─" * 60)
    for m in MODELS_20:
        rows = all_rows[m]
        tested = [r for r in rows if r["verdict"]]
        combos = defaultdict(lambda: {"pass": 0, "total": 0})
        for r in tested:
            k = (r["fp"], r["handshake"], r["padding"])
            combos[k]["total"] += 1
            if r["verdict"] == "PASS":
                combos[k]["pass"] += 1
        print(f"\n  {m}:")
        for k, s in sorted(combos.items(), key=lambda x: -x[1]["total"]):
            pr = f"{s['pass']}/{s['total']}={s['pass']/s['total']*100:.0f}%"
            print(f"    {str(k):<55} {pr}")

    # ── 4. Convergence / entropy of choices ──────────────────────────────────
    print("\n" + "─" * 60)
    print("  DESIGN ENTROPY (Shannon entropy of fp+hs+pad combinations)")
    print("─" * 60)
    for m in MODELS_20:
        rows = all_rows[m]
        combo_counts: dict = defaultdict(int)
        for r in rows:
            combo_counts[(r["fp"], r["handshake"], r["padding"])] += 1
        n_total = sum(combo_counts.values())
        if n_total == 0:
            continue
        entropy = -sum((c / n_total) * math.log2(c / n_total)
                       for c in combo_counts.values() if c > 0)
        n_unique = len(combo_counts)
        max_entropy = math.log2(n_total) if n_total > 1 else 1
        print(f"  {m:<22} unique_combos={n_unique:2d}  "
              f"H={entropy:.2f} bits  "
              f"H_max={max_entropy:.2f} bits  "
              f"norm={entropy/max_entropy:.2f}")

    # ── 5. Noise pattern breakdown ────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("  NOISE PATTERN CHOICES")
    print("─" * 60)
    pattern_stats: dict = defaultdict(lambda: {"pass": 0, "total": 0})
    for m in MODELS_20:
        for r in all_rows[m]:
            if r["handshake"] == "noise" and r["verdict"]:
                p = r["noise_pattern"] or "unknown"
                pattern_stats[p]["total"] += 1
                if r["verdict"] == "PASS":
                    pattern_stats[p]["pass"] += 1
    for p, s in sorted(pattern_stats.items()):
        pr = s["pass"] / s["total"] * 100 if s["total"] else 0
        print(f"  {p:<12}  {s['pass']}/{s['total']}  {pr:.0f}%")

    # ── 6. Padding range analysis ─────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("  RANDOM PADDING RANGE ANALYSIS")
    print("─" * 60)
    range_stats: dict = defaultdict(lambda: {"kl_iats": [], "pass": 0, "total": 0})
    for m in MODELS_20:
        for r in all_rows[m]:
            if r["padding"] == "random" and r["kl_iat"] is not None:
                key = f"[{r['pad_min']}-{r['pad_max']}]"
                range_stats[key]["kl_iats"].append(r["kl_iat"])
                range_stats[key]["total"] += 1
                if r["verdict"] == "PASS":
                    range_stats[key]["pass"] += 1
    for key, s in sorted(range_stats.items(), key=lambda x: -x[1]["total"])[:8]:
        avg_iat = statistics.mean(s["kl_iats"])
        std_iat = statistics.pstdev(s["kl_iats"])
        pr = s["pass"] / s["total"] * 100 if s["total"] else 0
        print(f"  {key:<15}  n={s['total']:2d}  PASS={s['pass']}/{s['total']}={pr:.0f}%  "
              f"μ_iat={avg_iat:.3f}  σ_iat={std_iat:.3f}")

    # ── 7. Weakness self-awareness ────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("  WEAKNESS COUNT vs PASS RATE")
    print("─" * 60)
    wcount_stats: dict = defaultdict(lambda: {"pass": 0, "total": 0})
    for m in MODELS_20:
        for r in all_rows[m]:
            if r["verdict"]:
                wcount_stats[r["n_weaknesses"]]["total"] += 1
                if r["verdict"] == "PASS":
                    wcount_stats[r["n_weaknesses"]]["pass"] += 1
    for n_w in sorted(wcount_stats.keys()):
        s = wcount_stats[n_w]
        pr = s["pass"] / s["total"] * 100 if s["total"] else 0
        print(f"  {n_w} weaknesses: n={s['total']:2d}  PASS={s['pass']}/{s['total']}  {pr:.0f}%")

    # ── 8. M7 failure KL threshold exploration ────────────────────────────────
    print("\n" + "─" * 60)
    print("  KL_IAT VALUE DISTRIBUTION (all tested runs, 4 models)")
    print("─" * 60)
    all_kl_iats = []
    for m in MODELS_20:
        for r in all_rows[m]:
            if r["kl_iat"] is not None and r["verdict"]:
                all_kl_iats.append((r["kl_iat"], r["verdict"]))
    all_kl_iats.sort()
    thresholds = [0.20, 0.25, 0.30, 0.35, 0.40]
    print(f"  Total tested: {len(all_kl_iats)}")
    print(f"  KL_IAT: min={min(x for x,_ in all_kl_iats):.3f}  "
          f"median={statistics.median(x for x,_ in all_kl_iats):.3f}  "
          f"max={max(x for x,_ in all_kl_iats):.3f}")
    print(f"  PASS/FAIL split at threshold:")
    for thr in thresholds:
        below_pass = sum(1 for v, verdict in all_kl_iats if v < thr and verdict == "PASS")
        below_fail = sum(1 for v, verdict in all_kl_iats if v < thr and verdict == "FAIL")
        above_pass = sum(1 for v, verdict in all_kl_iats if v >= thr and verdict == "PASS")
        above_fail = sum(1 for v, verdict in all_kl_iats if v >= thr and verdict == "FAIL")
        print(f"    thr={thr:.2f}: below=[{below_pass}P+{below_fail}F]  above=[{above_pass}P+{above_fail}F]")

    print(f"\n  Saved analysis complete.")


if __name__ == "__main__":
    main()
