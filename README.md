# HLVAR — simulation + prototype

```
sim/hlvar_sim.py      discrete-event model (4 scenarios x 10 policies, 50 runs each) + 3 sweeps
sim/analyze.py        mean ± 95% CI tables and figures
prototype/            REAL Kea integration: hlvar_daemon.py, tests, Kea configs, namespace lab
results/              CSVs (every run), summary_tables.md, summary_sweeps.md, fig1-4
```

## Reproduce
```bash
cd sim && python3 hlvar_sim.py --runs 50 --sweep-runs 30 --out ../results && python3 analyze.py ../results
cd ../prototype && python3 test_hlvar.py        # 9 tests, mock Kea Control Agent
```

## What the model is (and is not)
A 1-second-resolution model of one /24 pool (254 addresses), Poisson legitimate arrivals, 15-min sessions,
30% of clients release on exit, 30% unresponsive to ICMP, 20% temporary out-of-range gaps, 30% brief roaming gaps.
Attack A = spoofed-chaddr flood (30 req/s, never renews). Attack B = identity rotation: up to K genuinely
associated stations, each dwelling 30-120 s and leaving silently. **All parameters are assumptions, fixed before
running. The model supports design-space exploration, not performance claims for real deployments.**
Association evidence is assumed perfect and instantaneous; a persistently renewing attacker is not modelled.

## Findings (n=50 runs/cell, 95% CI in summary_tables.md)
1. **The original "probe everything" idea is harmful.** NaiveProbe restores availability but wrongly reclaims
   valid leases: 12% of evaluated leases in normal operation, 57% under attack B, 98% under attack A
   (repeated scans keep re-exposing sleeping clients). Supports H2 and the redesign in Sec. 4.1.
2. **HLVAR (association evidence + adaptive probation + 300 s restriction) kept success at 100% with 0 false
   reclaims in all four scenarios** at default settings (grace 10 s).
3. **Against attack A, existing snooping with chaddr verification already wins** (0 attacker leases vs 30 for
   standalone HLVAR). Do NOT claim HLVAR beats snooping here. Ablation: the restriction policy is what stops A
   (HLVAR-noRestrict: 49.9% success).
4. **Attack B is where HLVAR adds something**: snooping+rate-limit gives 26.9% success (identities look legitimate);
   HLVAR gives 100% because disassociated holders become reclaimable. Ablation: without association evidence
   success is 29.4%.
5. **Short leases are a strong baseline you must compare against.** 300 s leases reach 99.8-100% in S1/S3, but cost
   ~4x DHCP messages in normal operation (1506 vs 369 baseline, 423 HLVAR) and fail against A (37.7%).
6. **Limits.** At K=200 attacker stations (pool 254) HLVAR success falls to 88.8% with 7.5% FPR: an attacker that
   keeps many stations genuinely associated cannot be beaten by lease evidence alone (needs AP-side limits).
7. **Grace period is a real trade-off** (stress: 50% dropouts, K=120): grace 5-10 s -> ~18% FPR, 100% success;
   60 s -> 4% FPR, 87% success; 120 s -> 0.5% FPR, 64% success. Pick per deployment; report the curve.
8. **Restriction duration** controls attacker leakage ~1/duration (leases granted to attacker over the run:
   30 s -> 900, 60 s -> 450, 300 s -> 90, 900 s -> 30). Legit false restrictions were not exercised in these
   runs (aggressive legit clients rarely trigger it); test that on the real lab.

## Prototype status (be precise in the paper)
- `hlvar_daemon.py` is tested (10 tests: mock Kea Control Agent) AND was run against **live ISC Kea 2.4.1** with real
  dhclient clients in network namespaces. The live test found a real bug (tiny-pool rounding) which is fixed + regression-tested.
- `lab_experiment.py` runs the full real-server experiment (see LAB_GUIDE.md). Pipeline validated with short runs
  (S3, 90 s, 1 seed: stock 73.3% success / pool exhausted 53% of time; HLVAR 100% / 0%). That is a pipeline check,
  NOT paper data - run `run_all.sh` for n>=5 seeds.
- Tested by me on Kea 2.4.1 only. Kea 3.0.x (Kali) needs path overrides (handled in code, untested by me): run `sudo python3 lab_experiment.py --check` first.
- Wi-Fi association is emulated by a file; attack A, probation and restriction are simulation-only.

## Next steps to make it publishable
1. Install Kea (+ lease_cmds hook), run the lab, run daemon in monitor-only, then --apply.
2. Repeat scenarios S0-S3 on the real lab; compare against the simulator (validate the model).
3. Add persistent-renewing attacker and DHCPv6 (Kea dhcp6 + lease6-* commands) to simulator and lab.
4. Replace paper Sec. 9 with Results: simulation (Sec. A) + testbed validation (Sec. B).
