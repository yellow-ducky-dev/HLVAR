#!/usr/bin/env python3
"""
Forensics for ONE lab run: when did reclaims happen and were the 'premature' ones expected by design?

usage:  python3 lab_inspect.py results_lab/S3_hlvar_6          (needs ..._stations.csv, ..._audit.jsonl, ..._.json)
        python3 lab_inspect.py --audit /tmp/hlvar-lab/S3_hlvar_1/audit.jsonl   (older runs: timing only, no ground truth)

A 'premature' reclaim = lease reclaimed while the client was still present. Two very different cases:
  by-design : the client was in a temporary out-of-range gap longer than the grace period (known trade-off, Fig 4)
  UNEXPLAINED: the client was associated at that moment  -> harness/daemon timing problem, must be investigated
"""
import csv, json, sys
from collections import Counter

def load_audit(path):
    out = []
    for line in open(path):
        r = json.loads(line)
        if r.get("action") == "reclaim" and r.get("executed"): out.append(r)
    return out

def bursts(ts, width=3.0):
    ts = sorted(ts); best = (0, 0.0); j = 0
    for i in range(len(ts)):
        while ts[i] - ts[j] > width: j += 1
        if i - j + 1 > best[0]: best = (i - j + 1, ts[j])
    return best

def main():
    a = sys.argv[1:]
    if not a: sys.exit(__doc__)
    if a[0] == "--audit":
        rec = load_audit(a[1]); base = None
    else:
        base = a[0]; rec = load_audit(base + "_audit.jsonl")
    if not rec: sys.exit("no executed reclaims in this audit log")
    if base:
        t0 = json.load(open(base + ".json"))["t0_epoch"]; grace = json.load(open(base + ".json"))["params"]["grace"]
    else:
        t0 = min(r["t"] for r in rec); grace = None
    old = [r for r in rec if r["t"] < t0]
    if old: print(f"WARNING: {len(old)} audit records predate this run (from an earlier run that reused the folder); ignored.")
    rec = [r for r in rec if r["t"] >= t0]
    if not rec: sys.exit("no reclaims left after removing records from earlier runs")
    ts = [r["t"] - t0 for r in rec]
    print(f"executed reclaims: {len(rec)}   first at {min(ts):.1f}s  last at {max(ts):.1f}s")
    hist = Counter(int(t // 10) * 10 for t in ts)
    print("reclaims per 10 s: " + "  ".join(f"{k}s:{hist[k]}" for k in sorted(hist)))
    n, at = bursts(ts)
    print(f"largest burst: {n} reclaims within 3 s starting at {at:.1f}s" + ("   <-- suspicious (stall?)" if n >= 8 else ""))
    if not base: return
    st = {}
    for r in csv.DictReader(open(base + "_stations.csv")): st[r["mac"]] = r
    by_design = unexplained = stale = atk = 0; rows = []
    for r in rec:
        s = st.get(r["mac"])
        if s is None: continue
        t = r["t"] - t0; depart = float(s["depart"]) if s["depart"] else 1e9
        if s["kind"] == "B": atk += 1; continue
        if t >= depart: stale += 1; continue
        gaps = [(float(s["t_req"]) + x, float(s["t_req"]) + x + d) for x, d in json.loads(s["dropouts"])]
        in_gap = [g for g in gaps if g[0] <= t < g[1]]
        if in_gap:
            by_design += 1; rows.append((t, r["mac"], f"by design: in dropout {t - in_gap[0][0]:.1f}s (grace {grace}s)"))
        else:
            unexplained += 1; rows.append((t, r["mac"], "UNEXPLAINED: client was associated"))
    print(f"\nclassification: stale={stale}  attacker={atk}  premature by-design={by_design}  premature UNEXPLAINED={unexplained}")
    for t, mac, why in sorted(rows): print(f"  t={t:7.1f}s  {mac}  {why}")
    if unexplained: print("\n-> UNEXPLAINED premature reclaims exist: check machine load / daemon poll timing for this run.")

if __name__ == "__main__":
    main()
