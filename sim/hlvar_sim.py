#!/usr/bin/env python3
"""
HLVAR discrete-time simulator (1-second resolution).

Models a single-subnet public Wi-Fi DHCPv4 service and compares:
  Baseline, ShortLease, RateLimit, Snooping+RL ("existing controls"),
  NaiveProbe (the original "ping everything" concept), HLVAR (standalone),
  Existing+HLVAR, plus HLVAR ablations.

IMPORTANT: this is a *model*. Parameters are assumptions (see Params), not
measurements. It supports design-space exploration and hypothesis testing; it
does not replace the real-server evaluation in ../prototype.
"""
import random, heapq, math, csv, os, sys, json, argparse
from collections import deque, defaultdict
from dataclasses import dataclass, replace

# ----------------------------------------------------------------- parameters
@dataclass(frozen=True)
class Params:
    pool: int = 254
    horizon: int = 3600
    warmup: int = 300
    attack_start: int = 900
    stay_mean: float = 900.0      # legit session length (s)
    p_release: float = 0.30       # legit clients that send DHCPRELEASE on leaving
    p_sleep: float = 0.30         # legit client unresponsive to ICMP probe (doze/firewall)
    p_dropout: float = 0.20       # legit client has one temporary out-of-range gap
    dropout_mean: float = 20.0
    p_roam: float = 0.30          # brief roaming gap 1-4 s
    p_aggr: float = 0.02          # buggy legit clients retrying every second
    give_up: int = 60             # user gives up after 60 s
    retry: int = 4
    scan_cooldown: int = 5
    trigger_frac: float = 0.10    # recovery activation threshold
    target_frac: float = 0.20     # reclaim until this much is free
    probation_free_frac: float = 0.30
    rl_threshold: int = 10        # >10 DISCOVER in 10 s -> restriction
    bucket_cap: int = 10
    bucket_rate: float = 2.0

@dataclass(frozen=True)
class Policy:
    name: str
    lease_time: int = 3600
    bucket: bool = False
    snoop_verify: bool = False
    naive_probe: bool = False
    assoc: bool = False           # HLVAR: association-evidence reclamation
    probation: bool = False       # HLVAR: adaptive probationary leases
    restrict: bool = False        # HLVAR: fixed-duration restriction
    grace: float = 10.0
    restrict_secs: int = 300
    probation_secs: int = 120

HL = dict(assoc=True, probation=True, restrict=True)
POLICIES = {
    "Baseline":        Policy("Baseline"),
    "ShortLease(300s)": Policy("ShortLease(300s)", lease_time=300),
    "RateLimit":       Policy("RateLimit", bucket=True),
    "Snooping+RL":     Policy("Snooping+RL", bucket=True, snoop_verify=True),
    "NaiveProbe":      Policy("NaiveProbe", naive_probe=True),
    "HLVAR":           Policy("HLVAR", **HL),
    "Existing+HLVAR":  Policy("Existing+HLVAR", bucket=True, snoop_verify=True, **HL),
    "HLVAR-noAssoc":   Policy("HLVAR-noAssoc", probation=True, restrict=True),
    "HLVAR-noProb":    Policy("HLVAR-noProb", assoc=True, restrict=True),
    "HLVAR-noRestrict": Policy("HLVAR-noRestrict", assoc=True, probation=True),
}

@dataclass(frozen=True)
class Scenario:
    name: str
    lam: float                    # legit arrivals / s
    attack: str = "none"          # none | A | B
    A_rate: int = 30              # spoofed DISCOVER / s (attack A)
    B_K: int = 40                 # simultaneously associated attacker stations (attack B)

SCENARIOS = {
    "S0 normal":        Scenario("S0 normal", 0.08),
    "S1 high demand":   Scenario("S1 high demand", 0.20),
    "S2 attackA (chaddr flood)": Scenario("S2 attackA (chaddr flood)", 0.08, "A"),
    "S3 attackB (identity rotation)": Scenario("S3 attackB (identity rotation)", 0.08, "B"),
}

# ------------------------------------------------------------------ entities
class Station:
    """A wireless station (legit or attacker) with an association timeline."""
    __slots__ = ("id", "l2", "arr", "depart", "release", "aggr", "gaps", "lease",
                 "first_req", "served", "done", "attack", "kind", "counted", "disrupted")
    def associated(self, t):
        if t >= self.depart: return False
        for a, b in self.gaps:
            if a <= t < b: return False
        return True
    def unassoc_since(self, t):
        if t >= self.depart: return self.depart
        for a, b in self.gaps:
            if a <= t < b: return a
        return None
    def present(self, t): return t < self.depart

class SpoofOwner:
    """Owner of leases created by attack-A spoofed chaddrs: the *real* radio is
    associated, but no client behind the chaddr exists (never renews/responds)."""
    __slots__ = ("l2", "attack", "kind")
    def __init__(self): self.l2 = "ATK"; self.attack = True; self.kind = "spoof"
    def associated(self, t): return True       # attacker's real radio stays associated
    def unassoc_since(self, t): return None
    def present(self, t): return True

class Lease:
    __slots__ = ("addr", "owner", "expiry", "probation", "dead")
    def __init__(self, addr, owner, expiry, probation):
        self.addr, self.owner, self.expiry, self.probation, self.dead = addr, owner, expiry, probation, False

def poisson(rng, lam):
    L, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= L: return k
        k += 1

# ----------------------------------------------------------------------- run
def run(scn: Scenario, pol: Policy, seed: int, P: Params = Params()):
    rng = random.Random(seed)
    free = list(range(P.pool)); leases = {}; heap = []
    ev = defaultdict(list)           # t -> [(kind, obj)]
    restricted_until = {}; recent = defaultdict(deque); tokens = {}
    spoof_owner = SpoofOwner()
    stations = []; nid = 0
    activeB = []                     # heap of dwell ends for attack-B stations
    last_scan = -999; alloc_fail = False
    st = defaultdict(int); valid_seen = set(); wrongly = set()
    legit_restricted = set(); atk_restricted = set()
    free_series = []; exhausted = 0; atk_held_sum = 0; ticks_meas = 0

    def l2_of(o): return o.l2

    def new_station(t, attack=False):
        nonlocal nid
        s = Station(); nid += 1
        s.id = nid; s.l2 = ("B%d" if attack else "L%d") % nid; s.arr = t; s.attack = attack
        s.kind = "B" if attack else "legit"
        s.lease = None; s.first_req = t; s.served = None; s.done = False
        s.counted = (t >= P.warmup) and not attack; s.disrupted = False
        s.aggr = False; s.release = False; s.gaps = []
        if attack:
            s.depart = t + rng.uniform(30, 120)
        else:
            s.depart = t + max(30.0, rng.expovariate(1.0 / P.stay_mean))
            s.release = rng.random() < P.p_release
            s.aggr = rng.random() < P.p_aggr
            if rng.random() < P.p_dropout:
                a = t + rng.uniform(0, s.depart - t); s.gaps.append((a, a + rng.expovariate(1.0 / P.dropout_mean)))
            if rng.random() < P.p_roam:
                a = t + rng.uniform(0, s.depart - t); s.gaps.append((a, a + rng.uniform(1, 4)))
            ev[int(s.depart)].append(("depart", s))
        stations.append(s)
        ev[t].append(("try", s))
        return s

    def free_count(): return len(free)

    def grant(owner, t):
        if not free: return None
        addr = free.pop()
        prob = pol.probation and (len(free) + 1) <= P.probation_free_frac * P.pool
        dur = pol.probation_secs if prob else pol.lease_time
        l = Lease(addr, owner, t + dur, prob)
        leases[addr] = l; heapq.heappush(heap, (l.expiry, addr, id(l)))
        return l, dur

    def reclaim(l, t, why):
        l.dead = True; leases.pop(l.addr, None); free.append(l.addr); st["reclaimed"] += 1
        o = l.owner
        if not o.attack:
            if o.present(t):
                st["premature"] += 1; wrongly.add(id(l)); o.disrupted = True
        else:
            st["atk_reclaimed"] += 1

    def over_rate(key, t):
        """HLVAR restriction counter / existing-control token bucket. True => drop."""
        if pol.restrict:
            if restricted_until.get(key, -1) > t: return True
            q = recent[key]; q.append(t)
            while q and q[0] <= t - 10: q.popleft()
            if len(q) > P.rl_threshold:
                restricted_until[key] = t + pol.restrict_secs; st["restrictions"] += 1
                (atk_restricted if key in ("ATK",) or key.startswith("B") else legit_restricted).add(key)
                return True
        if pol.bucket:
            tk, last = tokens.get(key, (P.bucket_cap, t))
            tk = min(P.bucket_cap, tk + (t - last) * P.bucket_rate)
            if tk < 1:
                tokens[key] = (tk, t); st["rl_drop"] += 1; return True
            tokens[key] = (tk - 1, t)
        return False

    def sched_try(s, t):
        step = 1 if s.aggr else (2 if s.attack else P.retry)
        ev[t + step].append(("try", s))

    # ------------------------------------------------------------ main loop
    for t in range(P.horizon):
        # 1. lease expiry
        while heap and heap[0][0] <= t:
            e, addr, lid = heapq.heappop(heap)
            l = leases.get(addr)
            if l is not None and id(l) == lid and l.expiry == e and not l.dead:
                leases.pop(addr); free.append(addr); st["expired"] += 1
        # 2. arrivals
        for _ in range(poisson(rng, scn.lam)): new_station(t)
        if scn.attack == "B" and t >= P.attack_start:
            while activeB and activeB[0] <= t: heapq.heappop(activeB)
            while len(activeB) < scn.B_K:
                s = new_station(t, attack=True); heapq.heappush(activeB, s.depart)
        # 3. events at this tick
        reqs = []
        for kind, s in ev.pop(t, ()):
            if kind == "depart":
                s.done = True
                if s.release and s.lease is not None and leases.get(s.lease.addr) is s.lease:
                    st["msgs"] += 1; l = s.lease; l.dead = True; leases.pop(l.addr); free.append(l.addr); st["released"] += 1
            elif kind == "renew":
                if not s.present(t): continue
                l = s.lease
                if not s.associated(t): ev[t + 5].append(("renew", s)); continue
                if l is None or leases.get(l.addr) is not l or l.dead:
                    # lease lost (expired or reclaimed): fall back to DISCOVER
                    s.lease = None; s.first_req = t; s.counted = False; s.done = False
                    reqs.append((s.l2, s)); continue
                st["msgs"] += 1; st["renewals"] += 1
                l.expiry = t + pol.lease_time; l.probation = False
                heapq.heappush(heap, (l.expiry, l.addr, id(l)))
                ev[t + pol.lease_time // 2].append(("renew", s))
            elif kind == "try":
                if s.done or s.lease is not None or not s.present(t): continue
                if t - s.first_req > P.give_up and not s.attack: s.done = True; continue
                if s.attack and not s.present(t): continue
                if not s.associated(t): sched_try(s, t); continue
                reqs.append((s.l2, s))
        if scn.attack == "A" and t >= P.attack_start:
            for _ in range(scn.A_rate): reqs.append(("ATK", spoof_owner))
        rng.shuffle(reqs)
        # 4. DISCOVER processing
        for l2, o in reqs:
            chaddr_ok = not (o is spoof_owner)
            if pol.snoop_verify and not chaddr_ok: st["snoop_drop"] += 1; continue
            if over_rate(l2, t): st["rate_drop"] += 1; continue
            st["msgs"] += 1
            g = grant(o, t)
            if g is None:
                alloc_fail = True; st["alloc_fail"] += 1
                if o is not spoof_owner and not o.done: sched_try(o, t)
                continue
            l, dur = g
            if o is spoof_owner:
                st["atk_leases"] += 1; continue
            o.lease = l; o.served = t - o.first_req; o.done = True
            if o.attack: st["atk_leases"] += 1
            ev[t + dur // 2].append(("renew", o))
        # 5. recovery
        pressure = free_count() <= P.trigger_frac * P.pool or alloc_fail
        if pressure and t - last_scan >= P.scan_cooldown and leases and (pol.naive_probe or pol.assoc):
            last_scan = t; st["scans"] += 1
            if pol.naive_probe:
                for l in list(leases.values()):
                    st["probes"] += 1; st["evals"] += 1; o = l.owner
                    if not o.attack and o.present(t): valid_seen.add(id(l))
                    if o.kind == "spoof": resp = False
                    elif o.attack: resp = o.associated(t)
                    else: resp = o.associated(t) and rng.random() > P.p_sleep
                    if not resp: reclaim(l, t, "naive")
            else:
                cands = []
                for l in list(leases.values()):
                    st["evals"] += 1; o = l.owner
                    if not o.attack and o.present(t): valid_seen.add(id(l))
                    us = o.unassoc_since(t)
                    if us is not None and t - us >= pol.grace: cands.append((us, l))
                cands.sort(key=lambda x: x[0])
                for us, l in cands:
                    if free_count() >= P.target_frac * P.pool: break
                    reclaim(l, t, "hlvar")
        alloc_fail = False
        # 6. bookkeeping
        free_series.append(free_count())
        if t >= P.warmup:
            ticks_meas += 1
            if free_count() == 0: exhausted += 1
            atk_held_sum += sum(1 for l in leases.values() if l.owner.attack)

    # ------------------------------------------------------------ metrics
    cl = [s for s in stations if s.counted]
    ok = [s for s in cl if s.served is not None and s.served <= P.give_up]
    lat = sorted(s.served for s in ok)
    p95 = lat[int(0.95 * (len(lat) - 1))] if lat else float("nan")
    out = dict(
        scenario=scn.name, policy=pol.name, seed=seed,
        legit_n=len(cl), success_pct=100.0 * len(ok) / max(1, len(cl)),
        lat_mean=(sum(lat) / len(lat)) if lat else float("nan"), lat_p95=p95,
        exhausted_pct=100.0 * exhausted / max(1, ticks_meas),
        atk_held_mean=atk_held_sum / max(1, ticks_meas),
        atk_leases_granted=st["atk_leases"],
        premature=st["premature"], disrupted_pct=100.0 * st["premature"] / max(1, len(cl)), fpr_pct=100.0 * len(wrongly) / max(1, len(valid_seen)) if valid_seen else 0.0,
        valid_evaluated=len(valid_seen), scans=st["scans"], evals=st["evals"], probes=st["probes"],
        reclaimed=st["reclaimed"], atk_reclaimed=st["atk_reclaimed"], msgs=st["msgs"], renewals=st["renewals"],
        restrictions=st["restrictions"], legit_restricted=len(legit_restricted), atk_restricted=len(atk_restricted),
        dropped_by_controls=st["snoop_drop"] + st["rate_drop"] + st["rl_drop"],
    )
    return out, free_series

# -------------------------------------------------------------- experiments
def _job(args):
    scn, pol, seed, P = args
    o, fs = run(scn, pol, seed, P)
    return o, fs

def run_grid(jobs, label):
    res = []
    n = len(jobs)
    for i, j in enumerate(jobs):
        res.append(_job(j))
        if (i + 1) % 50 == 0: print(f"  {label}: {i+1}/{n}", flush=True)
    return res

def write_csv(path, rows):
    keys = list(rows[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(rows)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--sweep-runs", type=int, default=20)
    ap.add_argument("--out", default="../results")
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    P = Params()
    if a.quick: P = replace(P, horizon=1800, warmup=200, attack_start=500)
    # main grid
    jobs = [(s, p, 1000 + k, P) for s in SCENARIOS.values() for p in POLICIES.values() for k in range(a.runs)]
    main = run_grid(jobs, "main")
    write_csv(os.path.join(a.out, "main_runs.csv"), [m[0] for m in main])
    # free-pool time series (mean over runs)
    ts = defaultdict(lambda: [0.0] * P.horizon); cnt = defaultdict(int)
    for o, fs in main:
        k = (o["scenario"], o["policy"]); cnt[k] += 1
        for i, v in enumerate(fs): ts[k][i] += v
    with open(os.path.join(a.out, "free_timeseries.json"), "w") as f:
        json.dump({f"{k[0]}|{k[1]}": [v / cnt[k] for v in vals] for k, vals in ts.items()}, f)
    # sweep 1: attacker-B station budget K
    sw = []
    for K in (10, 20, 40, 80, 120, 200):
        scn = Scenario(f"B_K={K}", 0.08, "B", B_K=K)
        for pn in ("Baseline", "NaiveProbe", "HLVAR"):
            for k in range(a.sweep_runs): sw.append((scn, POLICIES[pn], 5000 + k, P))
    r = run_grid(sw, "sweep-K"); write_csv(os.path.join(a.out, "sweep_K.csv"), [x[0] for x in r])
    # sweep 2: grace period. Needs sustained pool pressure so scans actually run (K=120),
    # plus heavy temporary dropouts so that the grace period matters.
    sw = []
    PS = replace(P, p_dropout=0.5, dropout_mean=30.0)
    for g in (2, 5, 10, 30, 60, 120):
        scn = Scenario("B_K=120 + dropouts", 0.08, "B", B_K=120)
        pol = replace(POLICIES["HLVAR"], name=f"HLVAR grace={g}", grace=float(g))
        for k in range(a.sweep_runs): sw.append((scn, pol, 7000 + k, PS))
    r = run_grid(sw, "sweep-grace"); write_csv(os.path.join(a.out, "sweep_grace.csv"), [x[0] for x in r])
    # sweep 3: restriction duration (attack A, standalone HLVAR)
    sw = []
    for rs in (30, 60, 300, 900):
        scn = SCENARIOS["S2 attackA (chaddr flood)"]
        pol = replace(POLICIES["HLVAR"], name=f"HLVAR restrict={rs}s", restrict_secs=rs)
        for k in range(a.sweep_runs): sw.append((scn, pol, 9000 + k, P))
    r = run_grid(sw, "sweep-restrict"); write_csv(os.path.join(a.out, "sweep_restrict.csv"), [x[0] for x in r])
    print("done")
