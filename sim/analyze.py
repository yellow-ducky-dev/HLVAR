#!/usr/bin/env python3
"""Summarise simulator output: mean +/- 95% CI tables and publication-style figures."""
import csv, json, math, os, sys
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = sys.argv[1] if len(sys.argv) > 1 else "../results"
T975 = {10: 2.228, 20: 2.093, 30: 2.045, 40: 2.021, 50: 2.009, 100: 1.984}

def tcrit(n):
    for k in sorted(T975):
        if n - 1 <= k: return T975[k]
    return 1.96

def load(name):
    with open(os.path.join(R, name)) as f: return list(csv.DictReader(f))

def stats(vals):
    vals = [v for v in vals if not math.isnan(v)]
    n = len(vals)
    if n == 0: return float("nan"), float("nan"), 0
    m = sum(vals) / n
    if n < 2: return m, 0.0, n
    sd = math.sqrt(sum((v - m) ** 2 for v in vals) / (n - 1))
    return m, tcrit(n) * sd / math.sqrt(n), n

def group(rows, keys, metric):
    g = defaultdict(list)
    for r in rows: g[tuple(r[k] for k in keys)].append(float(r[metric]))
    return g

def fmt(m, ci, d=1): return f"{m:.{d}f} ± {ci:.{d}f}"

main = load("main_runs.csv")
scen = list(dict.fromkeys(r["scenario"] for r in main))
pols = list(dict.fromkeys(r["policy"] for r in main))
metrics = [("success_pct", "Legit success (%)", 1), ("lat_p95", "p95 wait (s)", 1),
           ("exhausted_pct", "Pool exhausted (% time)", 1), ("atk_held_mean", "Attacker-held leases", 1),
           ("fpr_pct", "FPR (%)", 1), ("disrupted_pct", "Disrupted clients (%)", 1), ("msgs", "DHCP msgs", 0), ("probes", "Probes", 0)]

lines = []
for s in scen:
    lines.append(f"\n### {s}\n")
    lines.append("| Policy | " + " | ".join(m[1] for m in metrics) + " |")
    lines.append("|---|" + "---|" * len(metrics))
    for p in pols:
        row = [p]
        for key, _, d in metrics:
            g = group([r for r in main if r["scenario"] == s and r["policy"] == p], ["policy"], key)
            m, ci, _ = stats(list(g.values())[0]); row.append(fmt(m, ci, d))
        lines.append("| " + " | ".join(row) + " |")
open(os.path.join(R, "summary_tables.md"), "w").write("\n".join(lines))
print("\n".join(lines))

# ---------- Fig 1: legit success + disrupted clients per scenario/policy
show = ["Baseline", "ShortLease(300s)", "Snooping+RL", "NaiveProbe", "HLVAR", "Existing+HLVAR"]
cols = ["#888", "#aaa", "#6a8caf", "#c97b63", "#2e7d5b", "#1b5e45"]
fig, axes = plt.subplots(2, 4, figsize=(15, 6.2), sharey="row")
for row, (key, lab, ylim) in enumerate([("success_pct", "Legitimate allocation success (%)", 105), ("disrupted_pct", "Valid leases wrongly reclaimed\n(% of legit clients)", 130)]):
    for ax, s in zip(axes[row], scen):
        ms, cis = [], []
        for p in show:
            g = group([r for r in main if r["scenario"] == s and r["policy"] == p], ["policy"], key)
            m, ci, _ = stats(list(g.values())[0]); ms.append(m); cis.append(ci)
        ax.bar(range(len(show)), ms, yerr=cis, capsize=3, color=cols)
        ax.set_xticks(range(len(show))); ax.set_xticklabels(show if row else [], rotation=60, ha="right", fontsize=8)
        if row == 0: ax.set_title(s, fontsize=9)
        ax.set_ylim(0, ylim); ax.grid(axis="y", alpha=.3)
    axes[row][0].set_ylabel(lab)
plt.tight_layout(); plt.savefig(os.path.join(R, "fig1_success.png"), dpi=200); plt.close()

# ---------- Fig 2: free-pool timeline
ts = json.load(open(os.path.join(R, "free_timeseries.json")))
fig, axes = plt.subplots(1, 2, figsize=(11, 3.8), sharey=True)
for ax, s in zip(axes, [scen[2], scen[3]]):
    for p, c in [("Baseline", "#888"), ("NaiveProbe", "#c97b63"), ("Snooping+RL", "#6a8caf"), ("HLVAR", "#2e7d5b")]:
        ax.plot(ts[f"{s}|{p}"], label=p, color=c, lw=1.5)
    ax.axvline(900, ls="--", color="k", lw=.8); ax.set_title(s, fontsize=9)
    ax.set_xlabel("time (s)"); ax.grid(alpha=.3)
axes[0].set_ylabel("Mean free addresses (pool = 254)"); axes[0].legend(fontsize=8)
plt.tight_layout(); plt.savefig(os.path.join(R, "fig2_free_pool.png"), dpi=200); plt.close()

# ---------- Fig 3: sensitivity to attacker station budget K
sk = load("sweep_K.csv")
Ks = sorted({int(r["scenario"].split("=")[1]) for r in sk})
fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
for p, c in [("Baseline", "#888"), ("NaiveProbe", "#c97b63"), ("HLVAR", "#2e7d5b")]:
    for ax, key in zip(axes, ["success_pct", "fpr_pct"]):
        ms, cis = [], []
        for K in Ks:
            m, ci, _ = stats([float(r[key]) for r in sk if r["scenario"] == f"B_K={K}" and r["policy"] == p]); ms.append(m); cis.append(ci)
        ax.errorbar(Ks, ms, yerr=cis, label=p, color=c, marker="o", capsize=3)
axes[0].set_ylabel("Legit success (%)"); axes[1].set_ylabel("False-positive reclaim rate (%)")
for ax in axes: ax.set_xlabel("attacker simultaneous associated stations (K)"); ax.grid(alpha=.3)
axes[0].legend(fontsize=8); plt.tight_layout(); plt.savefig(os.path.join(R, "fig3_sweep_K.png"), dpi=200); plt.close()

sk_lines = ["\n### Sweep: attacker station budget K (attack B)\n", "| K | Policy | Success % | FPR % | Atk-held |", "|---|---|---|---|---|"]
for K in Ks:
    for p in ("Baseline", "NaiveProbe", "HLVAR"):
        rows = [r for r in sk if r["scenario"] == f"B_K={K}" and r["policy"] == p]
        sm = stats([float(r["success_pct"]) for r in rows]); fm = stats([float(r["fpr_pct"]) for r in rows]); am = stats([float(r["atk_held_mean"]) for r in rows])
        sk_lines.append(f"| {K} | {p} | {fmt(*sm[:2])} | {fmt(*fm[:2])} | {fmt(*am[:2])} |")

# ---------- grace sweep + restrict sweep tables
for fname, title in [("sweep_grace.csv", "Sweep: HLVAR grace period (stress: 50% temporary dropouts, mean 30 s)"),
                     ("sweep_restrict.csv", "Sweep: restriction duration (attack A, standalone HLVAR)")]:
    rows = load(fname); order = list(dict.fromkeys(r["policy"] for r in rows))
    sk_lines += [f"\n### {title}\n", "| Config | Success % | FPR % | Disrupted clients % | Attacker leases granted | Legit restricted (ids) | Attacker restricted (ids) |", "|---|---|---|---|---|---|---|"]
    for p in order:
        rr = [r for r in rows if r["policy"] == p]
        c = [fmt(*stats([float(r[k]) for r in rr])[:2], d) for k, d in [("success_pct", 1), ("fpr_pct", 2), ("disrupted_pct", 1), ("atk_leases_granted", 0), ("legit_restricted", 1), ("atk_restricted", 1)]]
        sk_lines.append(f"| {p} | " + " | ".join(c) + " |")
open(os.path.join(R, "summary_sweeps.md"), "w").write("\n".join(sk_lines))
print("\n".join(sk_lines))

# ---------- Fig 4: grace-period trade-off
sg = load("sweep_grace.csv"); gs = [int(r["policy"].split("=")[1]) for r in sg]; gl = sorted(set(gs))
fig, ax = plt.subplots(figsize=(5.5, 3.8)); ax2 = ax.twinx()
f = [stats([float(r["fpr_pct"]) for r in sg if r["policy"] == f"HLVAR grace={g}"]) for g in gl]
s = [stats([float(r["success_pct"]) for r in sg if r["policy"] == f"HLVAR grace={g}"]) for g in gl]
ax.errorbar(gl, [x[0] for x in f], yerr=[x[1] for x in f], color="#c97b63", marker="o", label="False-positive reclaim rate")
ax2.errorbar(gl, [x[0] for x in s], yerr=[x[1] for x in s], color="#2e7d5b", marker="s", label="Legit allocation success")
ax.set_xscale("log"); ax.set_xlabel("grace period (s)"); ax.set_ylabel("FPR (%)", color="#c97b63"); ax2.set_ylabel("Success (%)", color="#2e7d5b")
ax.grid(alpha=.3); plt.tight_layout(); plt.savefig(os.path.join(R, "fig4_grace_tradeoff.png"), dpi=200); plt.close()
