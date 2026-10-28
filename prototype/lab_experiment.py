#!/usr/bin/env python3
"""
HLVAR real-server lab experiment (Linux, run as root, ISOLATED machine/VM only).

Stack under test: real ISC Kea DHCPv4 + lease_cmds hook + Control Agent, real ISC dhclient
clients (one network namespace per station), real hlvar_daemon.py.
Wi-Fi association is EMULATED by a file (assoc.txt) maintained by this script; with a real AP
use `hlvar_daemon.py --iw-iface wlan0` instead (see README).

Scenarios (time-scaled versions of the simulator's S1/S3):
  S1  high demand, no attack   : legit clients arrive, 30% release, 70% leave silently
  S3  identity rotation attack : S1 + K stations that associate, get a lease, dwell, vanish silently
Policies:
  baseline : daemon in MONITOR-ONLY mode (nothing is reclaimed; Kea behaves as stock)
  hlvar    : daemon with --apply

Outputs (per run): <out>/<scenario>_<policy>_<seed>.json  and  ..._timeseries.csv
"""
import argparse, atexit, csv, glob, json, math, os, random, shutil, signal, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hlvar_daemon as H

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "dhcp-script.sh")
POOL_SIZE = 29                                  # 10.99.0.2 - 10.99.0.30
KEA_URL = "http://127.0.0.1:8000"

def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)

# ------------------------------------------------------------------ lab plumbing
def cleanup():
    for f in glob.glob('/run/kea/hlvar-lab-*.pid') + glob.glob('/etc/kea/hlvar-lab-*.json'):
        try: os.remove(f)
        except Exception: pass
    sh("pkill", "-f", "kea-dhcp4 -c", check=False); sh("pkill", "-f", "kea-ctrl-agent -c", check=False)
    sh("pkill", "-f", "dhclient -1 -d", check=False)
    for ns in sh("ip", "netns", "list", check=False).stdout.split("\n"):
        if ns.startswith("hl"): sh("ip", "netns", "del", ns.split()[0], check=False)
    for l in sh("ip", "-o", "link", check=False).stdout.split("\n"):
        parts = l.split(": ")
        if len(parts) > 1 and (parts[1].split("@")[0].startswith("hv") or parts[1] == "br-lab"):
            sh("ip", "link", "del", parts[1].split("@")[0], check=False)

def kea_version():
    out = sh("kea-dhcp4", "-V", check=False).stdout.split()
    return out[0] if out else "unknown"

def find_hook():
    for pat in ("/usr/lib/*/kea/hooks/libdhcp_lease_cmds.so", "/usr/lib/kea/hooks/libdhcp_lease_cmds.so",
                "/usr/lib64/kea/hooks/libdhcp_lease_cmds.so", "/usr/local/lib/kea/hooks/libdhcp_lease_cmds.so"):
        m = glob.glob(pat)
        if m: return m[0]
    out = sh("find", "/usr", "-name", "libdhcp_lease_cmds.so", check=False).stdout.split()
    if out: return out[0]
    raise RuntimeError("lease_cmds hook library not found. Try: dpkg -L kea-common | grep lease_cmds  (or: sudo find / -name 'libdhcp_lease_cmds*')")

# ---- AppArmor: Debian/Kali ship profiles that confine kea-dhcp4 / kea-ctrl-agent to default paths.
# Our lab uses its own file names/locations, so the profile blocks Kea ("Permission denied" on
# /run/kea/logger_lockfile, "Unable to open PID file", "Unable to open file /tmp/..."). With --relax-apparmor the
# Kea profiles are put into COMPLAIN mode (violations are logged, not blocked) and restored at exit.
RELAX_AA = False
_aa_relaxed = []

def kea_aa_profiles():
    return sorted(p for p in glob.glob("/etc/apparmor.d/*kea*") if os.path.isfile(p))

def apparmor_relax():
    if not kea_aa_profiles(): return
    if not shutil.which("apparmor_parser"):
        print("  warning: Kea AppArmor profiles exist but apparmor_parser is missing; cannot relax them"); return
    for p in kea_aa_profiles():
        if p in _aa_relaxed: continue
        r = sh("apparmor_parser", "-r", "-C", p, check=False)
        if r.returncode == 0: _aa_relaxed.append(p)
        else: print(f"  warning: could not set {p} to complain mode: {(r.stderr or r.stdout).strip()[:200]}")
    if _aa_relaxed: print(f"  note: AppArmor profiles for Kea set to COMPLAIN mode for this run (restored at exit): {[os.path.basename(p) for p in _aa_relaxed]}")

def apparmor_restore():
    for p in list(_aa_relaxed):
        sh("apparmor_parser", "-r", p, check=False); _aa_relaxed.remove(p)
atexit.register(apparmor_restore)

def apparmor_hint():
    profs = kea_aa_profiles()
    if not profs or RELAX_AA: return ""
    return ("\nHINT: AppArmor profiles for Kea exist (" + ", ".join(os.path.basename(p) for p in profs) + "). "
            "The errors above are typical of AppArmor blocking Kea. Re-run with:  sudo python3 lab_experiment.py ... --relax-apparmor")

def kea_user():
    """(uid, gid) of the dedicated Kea service user (_kea on Debian/Kali/Ubuntu) or None."""
    import pwd
    for name in ("_kea", "kea"):
        try: pw = pwd.getpwnam(name); return pw.pw_uid, pw.pw_gid
        except KeyError: pass
    return None

def tail(path, n=15):
    try: return "".join(open(path).readlines()[-n:])
    except Exception: return "(no file)"

def diagnostics(w, attempts):
    out = [f"user id: {os.geteuid()}  kea: {kea_version()}"]
    for name, rc, msg in attempts: out.append(f"- {name}: rc={rc}  {msg!r}")
    out.append("kea-dhcp4 -W: " + (sh("kea-dhcp4", "-W", check=False).stdout.strip()[:600] or "(no output)"))
    for pth in ("/tmp", "/tmp/hlvar-lab", w, "/etc/kea"):
        out.append(sh("ls", "-ld", pth, check=False).stdout.strip() or f"(missing: {pth})")
    out.append(sh("ls", "-l", w, check=False).stdout.strip())
    out.append(sh("ls", "-ld", "/run/kea", check=False).stdout.strip() or "(missing: /run/kea)")
    out.append("kea user: " + str(kea_user()))
    out.append("kea processes: " + sh("sh", "-c", "ps -eo user,pid,cmd | grep -E 'kea-(dhcp4|ctrl)' | grep -v grep", check=False).stdout.strip())
    out.append("root can write /run/kea: " + str(sh("touch", "/run/kea/.hlvar_probe", check=False).returncode == 0))
    out.append("kernel AppArmor denials for kea: " + (sh("sh", "-c", "dmesg 2>/dev/null | grep -i apparmor | grep -i kea | tail -4", check=False).stdout.strip() or "(none found)"))
    out.append("kea AppArmor profiles: " + str([os.path.basename(p) for p in kea_aa_profiles()]))
    out.append("MAC: " + (sh("sh", "-c", "aa-status 2>&1 | head -2; getenforce 2>&1", check=False).stdout.strip() or "none"))
    return "\n".join(out)

def lab_up(w, lease_time):
    if RELAX_AA: apparmor_relax()
    # Kea >= 3.0 only writes leases/logs/sockets under approved dirs and only loads hooks from its hook dir.
    # ISC-documented overrides are environment variables; we point them all at this run's work dir.
    os.makedirs(w, exist_ok=True); os.chmod(w, 0o750)
    os.makedirs("/run/kea", exist_ok=True); os.chmod("/run/kea", 0o750)   # PID + logger lock files (normally made by systemd)
    ku = kea_user()
    if ku:                                                                  # Kea 3.x expects its own service user to own these
        for d in ("/run/kea", w): os.chown(d, *ku)
    hook = find_hook(); sock = f"{w}/kea4-ctrl.sock"
    env = dict(os.environ, KEA_DHCP_DATA_DIR=w, KEA_LOG_FILE_DIR=w, KEA_LEGAL_LOG_DIR=w, KEA_CONTROL_SOCKET_DIR=w,
               KEA_HOOKS_PATH=os.path.dirname(hook))
    sh("ip", "link", "add", "br-lab", "type", "bridge"); sh("ip", "addr", "add", "10.99.0.1/27", "dev", "br-lab")
    sh("ip", "link", "set", "br-lab", "up")
    def kea_conf(plural):
        d = {"interfaces-config": {"interfaces": ["br-lab"]},
             "lease-database": {"type": "memfile", "persist": True, "name": f"{w}/leases4.csv", "lfc-interval": 3600},
             "valid-lifetime": lease_time, "hooks-libraries": [{"library": hook}],
             "loggers": [{"name": "kea-dhcp4", "output_options": [{"output": f"{w}/kea4.log"}], "severity": "INFO"}],
             "subnet4": [{"id": 1, "subnet": "10.99.0.0/27", "pools": [{"pool": "10.99.0.2 - 10.99.0.30"}]}]}
        sk = {"socket-type": "unix", "socket-name": sock}
        d["control-sockets" if plural else "control-socket"] = [sk] if plural else sk
        return {"Dhcp4": d}
    agent = {"Control-agent": {"http-host": "127.0.0.1", "http-port": 8000,
        "control-sockets": {"dhcp4": {"socket-type": "unix", "socket-name": sock}},
        "loggers": [{"name": "kea-ctrl-agent", "output_options": [{"output": f"{w}/agent.log"}], "severity": "INFO"}]}}
    json.dump(agent, open(f"{w}/agent.json", "w"))
    # Kea 3.x may refuse the config for path/permission reasons. Try, in order of preference:
    #   secure defaults -> relaxed security (-X, documented by ISC) -> config copied into /etc/kea.
    attempts, chosen = [], None
    cfgdirs = [w] + (["/etc/kea"] if os.path.isdir("/etc/kea") else [])
    for cfgdir in cfgdirs:
        for flags in ([], ["-X"]):
            for plural in (False, True):
                kp = f"{cfgdir}/kea4.json" if cfgdir == w else f"{cfgdir}/hlvar-lab-kea4.json"
                ap_ = f"{cfgdir}/agent.json" if cfgdir == w else f"{cfgdir}/hlvar-lab-agent.json"
                json.dump(kea_conf(plural), open(kp, "w")); json.dump(agent, open(ap_, "w"))
                os.chmod(kp, 0o644); os.chmod(ap_, 0o644)
                t = subprocess.run(["kea-dhcp4", "-t", kp] + flags, capture_output=True, text=True, env=env)
                attempts.append((f"cfg in {cfgdir}, flags={flags or 'none'}, control-socket{'s' if plural else ''}", t.returncode, (t.stdout + t.stderr).strip()[-300:]))
                if t.returncode == 0: chosen = (kp, ap_, flags); break
            if chosen: break
        if chosen: break
    if chosen is None:
        raise RuntimeError("Kea rejected every generated config variant. DIAGNOSTICS:\n" + diagnostics(w, attempts) + apparmor_hint())
    kp, ap_, flags = chosen
    if flags or kp != f"{w}/kea4.json": print(f"  note: Kea needed non-default mode: config={kp} flags={flags}")
    def launch(prefix):
        for f in glob.glob("/run/kea/hlvar-lab-*.pid"): os.remove(f)
        procs = [subprocess.Popen(prefix + ["kea-dhcp4", "-c", kp] + flags, stdout=open(f"{w}/kea4.out", "w"), stderr=subprocess.STDOUT, env=env, start_new_session=True)]
        time.sleep(2)
        procs.append(subprocess.Popen(prefix + ["kea-ctrl-agent", "-c", ap_] + flags, stdout=open(f"{w}/agent.out", "w"), stderr=subprocess.STDOUT, env=env, start_new_session=True))
        k = H.Kea(KEA_URL)
        for _ in range(20):
            try: k.leases(); return procs, k
            except Exception: time.sleep(0.5)
        for p in procs:
            try: os.killpg(p.pid, signal.SIGTERM)
            except Exception: pass
        time.sleep(1)
        return None
    prefixes = [("root", [])]
    if ku:
        prefixes.append((f"user uid={ku[0]} via setpriv", ["setpriv", f"--reuid={ku[0]}", f"--regid={ku[1]}", "--init-groups",
                          "--inh-caps=+net_raw,+net_bind_service", "--ambient-caps=+net_raw,+net_bind_service"]))
    if os.environ.get("HLVAR_FORCE_KEA_USER") and len(prefixes) > 1: prefixes = prefixes[1:]   # testing aid
    logs = []
    for label, pre in prefixes:
        if label != "root": sh("chown", "-R", f"{ku[0]}:{ku[1]}", w, check=False)
        r = launch(pre)
        if r:
            if label != "root": print(f"  note: Kea had to run as {label}")
            return r
        logs.append(f"[run as {label}]\n--- kea4.out ---\n{tail(w+'/kea4.out')}--- agent.out ---\n{tail(w+'/agent.out')}")
    raise RuntimeError(f"Kea control agent did not answer on {KEA_URL}.\n" + "\n".join(logs) + "\nDIAGNOSTICS:\n" + diagnostics(w, attempts) + apparmor_hint())

def preflight():
    """Quick environment check (about 10 s). Run this FIRST: sudo python3 lab_experiment.py --check"""
    print("Kea version  :", kea_version())
    print("lease_cmds   :", find_hook())
    print("dhclient     :", sh("which", "dhclient", check=False).stdout.strip() or "MISSING (apt install isc-dhcp-client)")
    print("AppArmor     :", [os.path.basename(p) for p in kea_aa_profiles()] or "no Kea profiles", "(relax requested)" if RELAX_AA else "")
    w = "/tmp/hlvar-lab/preflight"; cleanup(); procs = []
    try:
        procs, k = lab_up(w, 60)
        print("Kea API      : OK (lease4-get-all answered; leases =", len(k.leases()), ")")
        print("PREFLIGHT OK - you can run the experiments.")
    except Exception as e:
        print("PREFLIGHT FAILED:\n", e); sys.exit(1)
    finally:
        for p in procs:
            try: os.killpg(p.pid, signal.SIGTERM)
            except Exception: pass
        cleanup()

# ---------------------------------------------------------------------- stations
class Ctx:
    def __init__(s, w, give_up):
        s.w, s.give_up = w, give_up; s.lock = threading.Lock(); s.assoc = set()
        s.assoc_file = f"{w}/assoc.txt"; s.stations = []; s.mac_kind = {}; s.t0 = time.time(); s.stop = False
        open(s.assoc_file, "w").close()
    def set_assoc(s, mac, on):
        with s.lock:
            (s.assoc.add if on else s.assoc.discard)(mac)
            tmp = s.assoc_file + ".tmp"
            with open(tmp, "w") as f: f.write("\n".join(sorted(s.assoc)) + "\n")
            os.replace(tmp, s.assoc_file)

class Station:
    def __init__(s, n, kind, stay, release, dropouts):
        s.n, s.kind, s.stay, s.release, s.dropouts = n, kind, stay, release, dropouts
        s.mac = f"02:00:00:00:{n >> 8:02x}:{n & 255:02x}"
        s.t_req = s.t_bound = s.depart_t = None; s.ok = False; s.counted = False

def sleep_until(t):
    d = t - time.time()
    if d > 0: time.sleep(d)

def run_station(st, ctx):
    n = st.n; ns, ve, ie = f"hl{n}", f"hv{n}", f"he{n}"; lf, pf = f"{ctx.w}/c{n}.lease", f"{ctx.w}/c{n}.pid"
    p = None
    try:
        sh("ip", "netns", "add", ns)
        sh("ip", "link", "add", ve, "type", "veth", "peer", "name", ie)
        sh("ip", "link", "set", ve, "master", "br-lab"); sh("ip", "link", "set", ve, "up")
        sh("ip", "link", "set", ie, "netns", ns, "name", "eth0")
        sh("ip", "netns", "exec", ns, "ip", "link", "set", "eth0", "address", st.mac)
        sh("ip", "netns", "exec", ns, "ip", "link", "set", "eth0", "up")
        st.t_req = time.time(); ctx.set_assoc(st.mac, True)                # associate, then DHCP
        p = subprocess.Popen(["ip", "netns", "exec", ns, "dhclient", "-1", "-d", "-v", "-sf", SCRIPT, "-lf", lf, "-pf", pf, "eth0"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        bound = threading.Event()
        def rd():
            for line in p.stdout:
                if "bound to" in line and not bound.is_set(): st.t_bound = time.time(); bound.set()
        threading.Thread(target=rd, daemon=True).start()
        st.ok = bound.wait(ctx.give_up)
        if st.ok:
            end = st.t_req + st.stay
            for a, d in sorted(st.dropouts):                                # temporary out-of-range gaps
                if st.t_req + a >= end: break
                sleep_until(st.t_req + a); ctx.set_assoc(st.mac, False)
                sleep_until(min(end, st.t_req + a + d)); ctx.set_assoc(st.mac, True)
            sleep_until(end)
        st.depart_t = time.time()
        if st.ok and st.release:
            sh("ip", "netns", "exec", ns, "dhclient", "-r", "-sf", SCRIPT, "-lf", lf, "-pf", pf, "eth0", check=False)
        ctx.set_assoc(st.mac, False)
    finally:
        if st.depart_t is None: st.depart_t = time.time()
        if p is not None:
            try: os.killpg(p.pid, signal.SIGKILL)                           # silent departure: no DHCPRELEASE
            except Exception: pass
        sh("ip", "netns", "del", ns, check=False); sh("ip", "link", "del", ve, check=False)

def spawn(ctx, st):
    ctx.stations.append(st); ctx.mac_kind[st.mac] = st.kind
    t = threading.Thread(target=run_station, args=(st, ctx), daemon=True); t.start(); return t

# ------------------------------------------------------------------- experiment
def experiment(a, seed, outdir):
    rng = random.Random(seed); w = f"/tmp/hlvar-lab/{a.scenario}_{a.policy}_{seed}"
    cleanup(); shutil.rmtree(w, ignore_errors=True)      # NEVER reuse a work dir: audit.jsonl is append-mode, leases persist
    procs, kea = lab_up(w, a.lease)
    ctx = Ctx(w, a.give_up); threads = []; nid = [0]; series = []
    audit = f"{w}/audit.jsonl"
    dcmd = [sys.executable, os.path.join(HERE, "hlvar_daemon.py"), "--kea-url", KEA_URL, "--pool-size", str(POOL_SIZE),
            "--assoc-file", ctx.assoc_file, "--grace", str(a.grace), "--interval", "1", "--log", audit] + (["--apply"] if a.policy == "hlvar" else [])
    daemon = subprocess.Popen(dcmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time(); ctx.t0 = t0

    def new_n(): nid[0] += 1; return nid[0] + (1000 if False else 0)

    def legit_gen():
        while time.time() - t0 < a.duration and not ctx.stop:
            time.sleep(rng.expovariate(a.lam))
            if time.time() - t0 >= a.duration: break
            stay = max(20.0, rng.expovariate(1.0 / a.stay)); dr = []
            if rng.random() < 0.2: dr.append((rng.uniform(0, stay), rng.expovariate(1.0 / a.dropout)))
            st = Station(new_n(), "legit", stay, rng.random() < 0.3, dr)
            st.counted = (time.time() - t0) >= a.warmup
            threads.append(spawn(ctx, st))

    def attacker_gen():
        while time.time() - t0 < a.attack_start and not ctx.stop: time.sleep(0.5)
        active = []
        while time.time() - t0 < a.duration and not ctx.stop:
            active = [x for x in active if x[1].depart_t is None]
            while len(active) < a.K:
                st = Station(new_n(), "B", rng.uniform(a.dwell_lo, a.dwell_hi), False, [])
                active.append((spawn(ctx, st), st)); threads.append(active[-1][0])
            time.sleep(0.5)

    def sampler():
        nxt = t0
        while time.time() - t0 < a.duration + 2:
            nxt += 1; sleep_until(nxt)
            try: ls = kea.leases()
            except Exception: continue
            now = time.time(); live = [l for l in ls if l["expiry"] > now]
            atk = sum(1 for l in live if ctx.mac_kind.get(l["mac"]) == "B")
            stale = sum(1 for l in live if any(s.mac == l["mac"] and s.depart_t is not None and s.depart_t < now for s in ctx.stations))
            series.append((round(now - t0, 1), POOL_SIZE - len(live), atk, stale))

    try:
        gens = [threading.Thread(target=legit_gen, daemon=True), threading.Thread(target=sampler, daemon=True)]
        if a.scenario == "S3": gens.append(threading.Thread(target=attacker_gen, daemon=True))
        for g in gens: g.start()
        for g in gens: g.join()
        ctx.stop = True; time.sleep(2)
        for t in threads: t.join(timeout=a.give_up + 5)
    finally:
        daemon.terminate()
        for p in procs:
            try: os.killpg(p.pid, signal.SIGTERM)
            except Exception: pass
    # ----------------------------------------------------------------- metrics
    legit = [s for s in ctx.stations if s.kind == "legit" and s.counted]
    ok = [s for s in legit if s.ok and s.t_bound - s.t_req <= a.give_up]
    lat = sorted(s.t_bound - s.t_req for s in ok)
    after = [r for r in series if r[0] >= a.warmup]
    by_mac = {s.mac: s for s in ctx.stations}
    prem = stale_rec = atk_rec = 0; premature_macs = set()
    if os.path.exists(audit):
        for line in open(audit):
            r = json.loads(line)
            if r.get("t", 0) < t0: continue                      # record from an earlier run -> never count
            if r.get("action") == "reclaim" and r.get("executed"):
                s = by_mac.get(r["mac"])
                if s is None: continue
                if s.kind == "B": atk_rec += 1
                elif s.depart_t is None or r["t"] < s.depart_t: prem += 1; premature_macs.add(s.mac)
                else: stale_rec += 1
    res = dict(scenario=a.scenario, policy=a.policy, seed=seed, params=vars(a),
               legit_n=len(legit), success_pct=100.0 * len(ok) / max(1, len(legit)),
               lat_mean=sum(lat) / len(lat) if lat else None, lat_p95=lat[int(0.95 * (len(lat) - 1))] if lat else None,
               exhausted_pct=100.0 * sum(1 for r in after if r[1] == 0) / max(1, len(after)),
               atk_held_mean=sum(r[2] for r in after) / max(1, len(after)),
               stale_held_mean=sum(r[3] for r in after) / max(1, len(after)),
               premature_reclaims=prem, premature_clients=len(premature_macs),
               disrupted_pct=100.0 * len(premature_macs) / max(1, len(legit)),
               stale_reclaimed=stale_rec, atk_reclaimed=atk_rec, stations=len(ctx.stations), t0_epoch=t0)
    os.makedirs(outdir, exist_ok=True); base = f"{outdir}/{a.scenario}_{a.policy}_{seed}"
    json.dump(res, open(base + ".json", "w"), indent=1)
    with open(base + "_stations.csv", "w", newline="") as f:          # ground truth for forensics
        cw = csv.writer(f); cw.writerow(["mac", "kind", "counted", "t_req", "t_bound", "depart", "ok", "release", "dropouts"])
        for st_ in ctx.stations:
            cw.writerow([st_.mac, st_.kind, int(st_.counted), None if st_.t_req is None else round(st_.t_req - t0, 2),
                         None if st_.t_bound is None else round(st_.t_bound - t0, 2), None if st_.depart_t is None else round(st_.depart_t - t0, 2),
                         int(st_.ok), int(st_.release), json.dumps([[round(a_, 2), round(d_, 2)] for a_, d_ in st_.dropouts])])
    if os.path.exists(audit): shutil.copy(audit, base + "_audit.jsonl")
    with open(base + "_timeseries.csv", "w", newline="") as f:
        cw = csv.writer(f); cw.writerow(["t", "free", "attacker_held", "stale_held"]); cw.writerows(series)
    cleanup()
    return res

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="environment preflight only")
    ap.add_argument("--scenario", choices=["S1", "S3"])
    ap.add_argument("--policy", choices=["baseline", "hlvar"])
    ap.add_argument("--seeds", default="1", help="comma list, e.g. 1,2,3")
    ap.add_argument("--duration", type=float, default=360); ap.add_argument("--warmup", type=float, default=60)
    ap.add_argument("--attack-start", dest="attack_start", type=float, default=120)
    ap.add_argument("--lease", type=int, default=300, help="Kea valid-lifetime (s)")
    ap.add_argument("--lam", type=float, default=0.12, help="legit arrivals per second")
    ap.add_argument("--stay", type=float, default=45); ap.add_argument("--dropout", type=float, default=8)
    ap.add_argument("--K", type=int, default=10); ap.add_argument("--dwell-lo", dest="dwell_lo", type=float, default=15)
    ap.add_argument("--dwell-hi", dest="dwell_hi", type=float, default=45)
    ap.add_argument("--grace", type=float, default=5); ap.add_argument("--give-up", dest="give_up", type=float, default=20)
    ap.add_argument("--out", default="results_lab")
    ap.add_argument("--relax-apparmor", dest="relax_apparmor", action="store_true",
                    help="temporarily put Kea's AppArmor profiles in complain mode (restored at exit)")
    a = ap.parse_args()
    global RELAX_AA; RELAX_AA = a.relax_apparmor
    if os.geteuid() != 0: sys.exit("run as root (sudo) on an ISOLATED lab machine/VM")
    if a.check: return preflight()
    if not a.scenario or not a.policy: ap.error("--scenario and --policy are required (or use --check)")
    def give_back():                                     # files made under sudo must stay usable by the normal user
        su, sg = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        if su and os.path.isdir(a.out):
            for root_, dirs_, files_ in os.walk(a.out):
                for n_ in [root_] + [os.path.join(root_, f) for f in files_]:
                    try: os.chown(n_, int(su), int(sg))
                    except Exception: pass
    for sd in [int(x) for x in a.seeds.split(",")]:
        r = experiment(a, sd, a.out); give_back()
        print(f"[{a.scenario}/{a.policy}/seed {sd}] success={r['success_pct']:.1f}% exhausted={r['exhausted_pct']:.1f}% "
              f"atk_held={r['atk_held_mean']:.1f} stale_held={r['stale_held_mean']:.1f} disrupted={r['disrupted_pct']:.1f}% "
              f"(premature={r['premature_reclaims']}, stale_reclaimed={r['stale_reclaimed']}, atk_reclaimed={r['atk_reclaimed']})", flush=True)

if __name__ == "__main__":
    main()
