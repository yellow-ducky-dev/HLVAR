#!/usr/bin/env python3
"""Aggregate lab runs: mean ± 95% CI table + free-pool timeline figure.  usage: lab_analyze.py results_lab"""
import csv, glob, json, math, os, sys
from collections import defaultdict
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt

R = sys.argv[1] if len(sys.argv) > 1 else "results_lab"
T = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228, 15: 2.131, 20: 2.093, 30: 2.045}
def tc(df):
    for k in sorted(T):
        if df <= k: return T[k]
    return 1.96
def ms(v):
    v = [x for x in v if x is not None]; n = len(v)
    if n == 0: return float("nan"), float("nan"), 0
    m = sum(v) / n
    if n < 2: return m, float("nan"), n
    sd = math.sqrt(sum((x - m) ** 2 for x in v) / (n - 1)); return m, tc(n - 1) * sd / math.sqrt(n), n

# Runs invalidated by a documented PROCEDURAL defect (never by their outcome) are listed in <R>/excluded.txt:
#   one per line:  S3_hlvar_1   reason text
excluded = {}
if os.path.exists(f"{R}/excluded.txt"):
    for ln in open(f"{R}/excluded.txt"):
        if ln.strip() and not ln.startswith("#"):
            k, _, why = ln.strip().partition(" "); excluded[k] = why.strip()
runs = [r for r in (json.load(open(f)) for f in sorted(glob.glob(f"{R}/*.json"))) if f"{r['scenario']}_{r['policy']}_{r['seed']}" not in excluded]
if not runs: sys.exit("no runs found in " + R)
g = defaultdict(list)
for r in runs: g[(r["scenario"], r["policy"])].append(r)
cols = [("success_pct", "Legit success (%)"), ("lat_p95", "p95 wait (s)"), ("exhausted_pct", "Pool exhausted (% time)"),
        ("atk_held_mean", "Attacker-held leases"), ("stale_held_mean", "Stale leases held"),
        ("disrupted_pct", "Disrupted clients (%)"), ("stale_reclaimed", "Stale reclaimed"), ("atk_reclaimed", "Attacker reclaimed")]
L = ["| Scenario | Policy | n | " + " | ".join(c[1] for c in cols) + " |", "|---|---|---|" + "---|" * len(cols)]
for (s, p) in sorted(g):
    row = [s, p, str(len(g[(s, p)]))]
    for k, _ in cols:
        m, ci, n = ms([r[k] for r in g[(s, p)]]); row.append(f"{m:.1f}" + ("" if math.isnan(ci) else f" ± {ci:.1f}"))
    L.append("| " + " | ".join(row) + " |")
if excluded: L += ["", "Excluded runs (procedural defect, not outcome-based):"] + [f"- {k}: {v}" for k, v in excluded.items()]
open(f"{R}/lab_summary.md", "w").write("\n".join(L)); print("\n".join(L))

scs = sorted({s for s, _ in g}); fig, axes = plt.subplots(1, len(scs), figsize=(6 * len(scs), 3.8), sharey=True, squeeze=False)
for ax, s in zip(axes[0], scs):
    for p, c in [("baseline", "#888"), ("hlvar", "#2e7d5b")]:
        acc = defaultdict(list)
        for r in g.get((s, p), []):
            for row in csv.DictReader(open(f"{R}/{s}_{p}_{r['seed']}_timeseries.csv")): acc[round(float(row["t"]))].append(float(row["free"]))
        ts = sorted(acc)
        if ts: ax.plot(ts, [sum(acc[t]) / len(acc[t]) for t in ts], color=c, label=f"{p} (n={len(g[(s, p)])})")
    ax.set_title(s); ax.set_xlabel("time (s)"); ax.grid(alpha=.3)
axes[0][0].set_ylabel("Free addresses (pool = 29)"); axes[0][0].legend()
plt.tight_layout(); plt.savefig(f"{R}/lab_fig_free_pool.png", dpi=200)

# ---------- summary bar chart (paper figure): baseline vs HLVAR, mean ± 95% CI
panels = [("success_pct", "Legit allocation success (%)"), ("exhausted_pct", "Pool exhausted (% of time)"),
          ("stale_held_mean", "Stale leases held (mean)"), ("disrupted_pct", "Valid clients wrongly reclaimed (%)")]
fig, axes = plt.subplots(1, 4, figsize=(14, 3.6))
for ax, (k, lab) in zip(axes, panels):
    w_ = 0.36
    for j, (p, c) in enumerate([("baseline", "#888"), ("hlvar", "#2e7d5b")]):
        for i, s in enumerate(scs):
            m, ci, n = ms([r[k] for r in g.get((s, p), [])])
            ax.bar(i + (j - 0.5) * w_, 0 if math.isnan(m) else m, w_, yerr=0 if math.isnan(ci) else ci, capsize=3, color=c, label=p if i == 0 else None)
    ax.set_xticks(range(len(scs))); ax.set_xticklabels(scs); ax.set_title(lab, fontsize=9); ax.grid(axis="y", alpha=.3)
axes[0].legend(fontsize=8); axes[0].set_ylim(0, 105)
plt.tight_layout(); plt.savefig(f"{R}/lab_fig_summary.png", dpi=200)
