# HLVAR real-server lab guide (Ubuntu 24.04)

## 0. Which OS?
Any Linux works. **Ubuntu 24.04 is recommended** (Kea 2.4.1 is in its normal repositories). Kali is Debian-based and
can run this, but it is a rolling attack-tools distro; package names/versions drift and it adds nothing here.
Windows: use a **VirtualBox/VMware VM with Ubuntu 24.04 (2 CPU, 4 GB RAM)**. WSL2 may work but is not tested.
Run ONLY inside the VM / an isolated network. Never on a shared or production network.

## 1. Install (inside the Ubuntu VM)
    sudo apt update
    sudo apt install -y kea-dhcp4-server kea-ctrl-agent isc-dhcp-client iproute2 python3-matplotlib unzip   # (same on Kali)
    ls /usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so      # must exist
    sudo systemctl disable --now kea-dhcp4-server kea-ctrl-agent       # the experiment starts its own instances
(The script auto-detects the hook path; see 1b for Kea 3.x.)


## 1b. Kali / Kea 3.x notes (what changed vs. the Ubuntu 24.04 / Kea 2.4.1 I tested)
Kali's repository gives **Kea 3.0.4**. Kea 3.x refuses to write lease files, logs and control sockets outside its approved
directories, and only loads hook libraries from its own hook directory (ISC "Things to be aware of when upgrading to Kea 3.0.0").
`lab_experiment.py` handles this by setting the documented overrides (KEA_DHCP_DATA_DIR, KEA_LOG_FILE_DIR,
KEA_CONTROL_SOCKET_DIR, KEA_HOOKS_PATH) for its own Kea processes, auto-detecting the lease_cmds hook, and trying both
control-socket config syntaxes. **I could only test this on Kea 2.4.1, so the 3.0.4 path is untested by me.**
Therefore ALWAYS run the preflight first and send me its output if it fails:

    sudo python3 lab_experiment.py --check

Expected: version line, hook path, dhclient path, "Kea API : OK", "PREFLIGHT OK".
Useful checks if it fails:
    dpkg -L kea-common | grep lease_cmds        # where is the hook?
    sudo cat /tmp/hlvar-lab/preflight/kea4.out  # why Kea refused to start
    sudo cat /tmp/hlvar-lab/preflight/agent.out
If NetworkManager grabs the lab bridge/veths:  sudo nmcli dev set br-lab managed no
The lab creates bridge br-lab (10.99.0.0/27), namespaces hl*, veths hv*; it deletes them at the end and kills any
`kea-dhcp4 -c` / `dhclient -1 -d` processes, so do not run it on a machine that runs its own Kea/dhclient.

## 2. Copy the project in and self-test
    unzip hlvar_project.zip && cd hlvar/prototype
    python3 test_hlvar.py                       # expect: Ran 10 tests ... OK
    sudo python3 lab_experiment.py --scenario S3 --policy hlvar --seeds 1 --duration 90 --warmup 20 \
         --attack-start 30 --lease 120 --lam 0.2 --stay 25 --dropout 5 --K 6 --dwell-lo 10 --dwell-hi 25 \
         --grace 4 --give-up 12 --out results_try
You should see one line with success / exhausted / atk_held / disrupted. (~100 s)

## 3. Full campaign (this is the paper data)
    sudo ./run_all.sh                           # 2 scenarios x 2 policies x 5 seeds ≈ 2.2 h; leave it running
    # more seeds: sudo SEEDS=1,2,3,4,5,6,7,8,9,10 ./run_all.sh
Output in results_lab/: one JSON + one time-series CSV per run, `lab_summary.md` (mean ± 95% CI), `lab_fig_free_pool.png`.

## 4. What each policy/scenario means
- baseline = daemon MONITOR-ONLY (nothing deleted) -> stock Kea behaviour. hlvar = daemon `--apply`.
- S1: busy network, no attacker; 70% of clients vanish without DHCPRELEASE.
- S3: S1 + K=10 genuinely associated stations that get a lease, dwell 15-45 s, then vanish silently, repeatedly.
Time is scaled (lease 300 s, sessions ~45 s) so a run takes 6 minutes instead of hours; state this in the paper.

## 5. Columns
success / p95 wait (legit clients getting a lease within 20 s), pool-exhausted % of time, attacker-held leases,
stale leases (held by stations that already left), disrupted clients % (valid leases wrongly reclaimed, judged against
ground truth the script knows), stale/attacker reclaimed counts.

## 6. What is real and what is emulated (write this in the paper)
REAL: Kea DHCPv4 server, lease database, Control Agent REST API, ISC dhclient clients, DHCP packets on a Linux bridge,
the HLVAR daemon deleting leases via lease4-del.
EMULATED: Wi-Fi association (a text file the script keeps updated, in the same format the daemon would read from an AP).
Next level of realism: Linux `mac80211_hwsim` + `hostapd` and run the daemon with `--iw-iface wlan0`
(or a real AP / OpenWrt router exposing `iw station dump`).

## 7. Not covered by this lab
Attack A (spoofed-chaddr flood) and the restriction/probation components are simulated only; the daemon implements
association-evidence reclamation. Existing switch features (DHCP snooping chaddr verification) already stop attack A.
Use an established open-source DHCP stress tool in your isolated lab if you want to test it; I did not include one.
