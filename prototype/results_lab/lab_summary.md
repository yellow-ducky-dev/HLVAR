| Scenario | Policy | n | Legit success (%) | p95 wait (s) | Pool exhausted (% time) | Attacker-held leases | Stale leases held | Disrupted clients (%) | Stale reclaimed | Attacker reclaimed |
|---|---|---|---|---|---|---|---|---|---|---|
| S1 | baseline | 10 | 86.2 ± 9.7 | 3.3 ± 4.1 | 19.6 ± 10.2 | 0.0 ± 0.0 | 15.1 ± 2.2 | 0.0 ± 0.0 | 0.0 ± 0.0 | 0.0 ± 0.0 |
| S1 | hlvar | 10 | 100.0 ± 0.0 | 0.0 ± 0.0 | 0.0 ± 0.0 | 0.0 ± 0.0 | 12.8 ± 1.1 | 0.0 ± 0.0 | 13.5 ± 5.9 | 0.0 ± 0.0 |
| S3 | baseline | 10 | 32.9 ± 4.9 | 1.2 ± 1.8 | 68.5 ± 2.0 | 11.7 ± 1.5 | 20.4 ± 1.0 | 0.0 ± 0.0 | 0.0 ± 0.0 | 0.0 ± 0.0 |
| S3 | hlvar | 10 | 100.0 ± 0.0 | 0.0 ± 0.0 | 0.4 ± 0.6 | 12.7 ± 0.9 | 7.6 ± 1.0 | 0.8 ± 0.9 | 29.0 ± 5.1 | 66.6 ± 2.2 |

Excluded runs (procedural defect, not outcome-based):
- S3_hlvar_1: audit log contaminated by earlier runs that reused the same work folder (harness bug, verified from audit timestamps)