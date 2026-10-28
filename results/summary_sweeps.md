
### Sweep: attacker station budget K (attack B)

| K | Policy | Success % | FPR % | Atk-held |
|---|---|---|---|---|
| 10 | Baseline | 48.2 ± 0.8 | 0.0 ± 0.0 | 94.3 ± 1.5 |
| 10 | NaiveProbe | 100.0 ± 0.0 | 35.1 ± 1.3 | 52.4 ± 1.1 |
| 10 | HLVAR | 100.0 ± 0.0 | 0.0 ± 0.0 | 72.6 ± 1.6 |
| 20 | Baseline | 34.9 ± 1.0 | 0.0 ± 0.0 | 122.9 ± 1.5 |
| 20 | NaiveProbe | 100.0 ± 0.0 | 43.9 ± 1.7 | 67.9 ± 0.8 |
| 20 | HLVAR | 100.0 ± 0.0 | 0.0 ± 0.0 | 94.5 ± 1.5 |
| 40 | Baseline | 26.5 ± 0.9 | 0.0 ± 0.0 | 142.6 ± 2.0 |
| 40 | NaiveProbe | 100.0 ± 0.0 | 56.9 ± 1.1 | 86.9 ± 0.5 |
| 40 | HLVAR | 100.0 ± 0.0 | 0.0 ± 0.0 | 109.9 ± 1.4 |
| 80 | Baseline | 21.9 ± 1.0 | 0.0 ± 0.0 | 155.3 ± 2.1 |
| 80 | NaiveProbe | 100.0 ± 0.0 | 73.9 ± 1.2 | 113.2 ± 0.3 |
| 80 | HLVAR | 100.0 ± 0.0 | 0.5 ± 0.2 | 120.2 ± 1.5 |
| 120 | Baseline | 20.8 ± 0.8 | 0.0 ± 0.0 | 158.8 ± 2.1 |
| 120 | NaiveProbe | 100.0 ± 0.0 | 85.1 ± 0.6 | 134.6 ± 0.2 |
| 120 | HLVAR | 100.0 ± 0.0 | 5.3 ± 0.4 | 124.5 ± 1.0 |
| 200 | Baseline | 18.0 ± 0.9 | 0.0 ± 0.0 | 163.9 ± 2.2 |
| 200 | NaiveProbe | 100.0 ± 0.0 | 97.5 ± 0.3 | 173.3 ± 0.0 |
| 200 | HLVAR | 88.8 ± 1.0 | 7.5 ± 0.7 | 160.3 ± 1.2 |

### Sweep: HLVAR grace period (stress: 50% temporary dropouts, mean 30 s)

| Config | Success % | FPR % | Disrupted clients % | Attacker leases granted | Legit restricted (ids) | Attacker restricted (ids) |
|---|---|---|---|---|---|---|
| HLVAR grace=2 | 100.0 ± 0.0 | 17.97 ± 1.32 | 18.6 ± 1.4 | 4355 ± 9 | 0.0 ± 0.0 | 0.0 ± 0.0 |
| HLVAR grace=5 | 100.0 ± 0.0 | 17.93 ± 1.29 | 18.5 ± 1.4 | 4356 ± 9 | 0.0 ± 0.0 | 0.0 ± 0.0 |
| HLVAR grace=10 | 100.0 ± 0.0 | 17.85 ± 1.26 | 18.5 ± 1.3 | 4356 ± 9 | 0.0 ± 0.0 | 0.0 ± 0.0 |
| HLVAR grace=30 | 100.0 ± 0.0 | 11.62 ± 0.75 | 11.8 ± 0.8 | 4352 ± 8 | 0.0 ± 0.0 | 0.0 ± 0.0 |
| HLVAR grace=60 | 87.4 ± 0.9 | 4.09 ± 0.45 | 3.5 ± 0.4 | 4220 ± 15 | 0.0 ± 0.0 | 0.0 ± 0.0 |
| HLVAR grace=120 | 64.3 ± 0.9 | 0.45 ± 0.18 | 0.3 ± 0.1 | 3637 ± 21 | 0.0 ± 0.0 | 0.0 ± 0.0 |

### Sweep: restriction duration (attack A, standalone HLVAR)

| Config | Success % | FPR % | Disrupted clients % | Attacker leases granted | Legit restricted (ids) | Attacker restricted (ids) |
|---|---|---|---|---|---|---|
| HLVAR restrict=30s | 100.0 ± 0.0 | 0.71 ± 0.34 | 0.6 ± 0.3 | 900 ± 0 | 0.0 ± 0.0 | 1.0 ± 0.0 |
| HLVAR restrict=60s | 100.0 ± 0.0 | 0.00 ± 0.00 | 0.0 ± 0.0 | 450 ± 0 | 0.0 ± 0.0 | 1.0 ± 0.0 |
| HLVAR restrict=300s | 100.0 ± 0.0 | 0.00 ± 0.00 | 0.0 ± 0.0 | 90 ± 0 | 0.0 ± 0.0 | 1.0 ± 0.0 |
| HLVAR restrict=900s | 100.0 ± 0.0 | 0.00 ± 0.00 | 0.0 ± 0.0 | 30 ± 0 | 0.0 ± 0.0 | 1.0 ± 0.0 |