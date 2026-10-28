#!/usr/bin/env bash
# Full lab campaign. Run as root on an ISOLATED Linux machine/VM:  sudo ./run_all.sh
# Kali/Debian with AppArmor blocking Kea:  LAB_FLAGS=--relax-apparmor sudo -E ./run_all.sh
# Default: 2 scenarios x 2 policies x 5 seeds x ~6.5 min  ≈ 2.2 hours.  Quick test: SEEDS=1 DURATION=120 sudo -E ./run_all.sh
set -euo pipefail
export MPLCONFIGDIR=${MPLCONFIGDIR:-/tmp/mplcfg-hlvar}   # avoid root-owned ~/.config/matplotlib
SEEDS=${SEEDS:-1,2,3,4,5}; DURATION=${DURATION:-360}; OUT=${OUT:-results_lab}
for sc in S1 S3; do for pol in baseline hlvar; do
  python3 lab_experiment.py --scenario $sc --policy $pol --seeds "$SEEDS" --duration "$DURATION" --out "$OUT" ${LAB_FLAGS:-}
done; done
python3 lab_analyze.py "$OUT"
if [ -n "${SUDO_USER:-}" ]; then chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$OUT"; fi   # results belong to you, not root
