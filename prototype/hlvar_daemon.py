#!/usr/bin/env python3
"""
HLVAR daemon for ISC Kea DHCPv4 (prototype).

Design rules taken from the paper:
  * never writes to Kea's lease database directly - only the supported
    `lease4-del` command through the Kea Control Agent (lease_cmds hook);
  * default is MONITOR-ONLY (dry-run): decisions are logged, nothing is deleted;
  * a lease is reclaimed only if (a) pool pressure is active, (b) its client
    has been continuously un-associated from the AP for >= grace seconds, and
    (c) a fresh `lease4-get` just before deletion shows the lease unchanged
    (race check). Silence/ICMP timeouts are never used as evidence.

Requires: Kea with kea-ctrl-agent and the lease_cmds hook; stdlib only.
Association source: `iw dev <iface> station dump` on the AP, or a text file
with one MAC per line (for namespace labs without a real radio).
"""
import argparse, json, math, subprocess, sys, time, urllib.request
from dataclasses import dataclass, field

# ----------------------------------------------------------------- core logic
@dataclass
class Decision:
    ip: str
    mac: str
    action: str        # preserve | candidate | reclaim
    reason: str

@dataclass
class Engine:
    pool_size: int
    trigger: float = 0.10
    target: float = 0.20
    grace: float = 10.0
    unassoc_since: dict = field(default_factory=dict)   # ip -> first time seen un-associated
    last_scan: float = -1e9
    cooldown: float = 5.0

    def step(self, now, leases, associated):
        """leases: list of dicts (ip, mac, expiry, cltt); associated: set of lower-case MACs.
        Returns (pressure, [Decision])."""
        live = [l for l in leases if l["expiry"] > now]
        # keep association timeline up to date on every poll (cheap, event-like)
        seen = set()
        for l in live:
            seen.add(l["ip"])
            if l["mac"] in associated: self.unassoc_since.pop(l["ip"], None)
            else: self.unassoc_since.setdefault(l["ip"], now)
        for ip in list(self.unassoc_since):
            if ip not in seen: del self.unassoc_since[ip]
        free = self.pool_size - len(live)
        pressure = free <= self.trigger * self.pool_size
        out = []
        if not pressure or now - self.last_scan < self.cooldown:
            return pressure, out
        self.last_scan = now
        cands = []
        for l in live:
            us = self.unassoc_since.get(l["ip"])
            if us is None:
                out.append(Decision(l["ip"], l["mac"], "preserve", "associated")); continue
            if now - us >= self.grace: cands.append((us, l))
            else: out.append(Decision(l["ip"], l["mac"], "preserve", f"unassociated {now-us:.0f}s < grace"))
        cands.sort(key=lambda x: x[0])
        need = max(1, math.ceil(self.target * self.pool_size)) - free   # ceil: tiny pools must still free >=1
        for i, (us, l) in enumerate(cands):
            if i < need: out.append(Decision(l["ip"], l["mac"], "reclaim", f"unassociated {now-us:.0f}s >= grace; pressure"))
            else: out.append(Decision(l["ip"], l["mac"], "candidate", "target free already reached"))
        return pressure, out

# ----------------------------------------------------------------- Kea client
class Kea:
    def __init__(self, url): self.url = url
    def cmd(self, name, args=None):
        body = {"command": name, "service": ["dhcp4"]}
        if args: body["arguments"] = args
        req = urllib.request.Request(self.url, json.dumps(body).encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r: resp = json.load(r)
        return resp[0] if isinstance(resp, list) else resp
    def leases(self, subnet_id=None):
        r = self.cmd("lease4-get-all", {"subnets": [subnet_id]} if subnet_id else None)
        out = []
        for l in r.get("arguments", {}).get("leases", []):
            if l.get("state", 0) != 0: continue            # only default-state (active) leases
            out.append(dict(ip=l["ip-address"], mac=l["hw-address"].lower(), cltt=l["cltt"], expiry=l["cltt"] + l["valid-lft"]))
        return out
    def get(self, ip):
        r = self.cmd("lease4-get", {"ip-address": ip})
        return r.get("arguments") if r.get("result") == 0 else None
    def delete(self, ip): return self.cmd("lease4-del", {"ip-address": ip})

# ---------------------------------------------------------- association source
def assoc_iw(iface):
    out = subprocess.run(["iw", "dev", iface, "station", "dump"], capture_output=True, text=True, check=True).stdout
    return {ln.split()[1].lower() for ln in out.splitlines() if ln.startswith("Station ")}

def assoc_file(path):
    with open(path) as f: return {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}

# ------------------------------------------------------------------------ main
def reclaim_safely(kea, d, associated_now, snapshot):
    """Race check immediately before deletion (paper Sec. 6.3)."""
    fresh = kea.get(d.ip)
    if fresh is None: return False, "lease already gone"
    if fresh["hw-address"].lower() in associated_now(): return False, "client re-associated"
    if fresh["cltt"] != snapshot[d.ip]["cltt"]: return False, "lease renewed during review"
    r = kea.delete(d.ip)
    return r.get("result") == 0, r.get("text", "")

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kea-url", default="http://127.0.0.1:8000")
    ap.add_argument("--pool-size", type=int, required=True)
    ap.add_argument("--subnet-id", type=int)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--iw-iface"); g.add_argument("--assoc-file")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--grace", type=float, default=10.0)
    ap.add_argument("--trigger", type=float, default=0.10)
    ap.add_argument("--target", type=float, default=0.20)
    ap.add_argument("--apply", action="store_true", help="actually delete leases (default: monitor-only)")
    ap.add_argument("--log", default="hlvar_audit.jsonl")
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args(argv)
    kea = Kea(a.kea_url)
    eng = Engine(a.pool_size, a.trigger, a.target, a.grace)
    get_assoc = (lambda: assoc_iw(a.iw_iface)) if a.iw_iface else (lambda: assoc_file(a.assoc_file))
    log = open(a.log, "a", buffering=1)
    while True:
        now = time.time()
        try:
            leases = kea.leases(a.subnet_id); snap = {l["ip"]: l for l in leases}
            pressure, decisions = eng.step(now, leases, get_assoc())
            for d in decisions:
                rec = dict(t=now, ip=d.ip, mac=d.mac, action=d.action, reason=d.reason, mode="apply" if a.apply else "monitor")
                if d.action == "reclaim":
                    if a.apply:
                        ok, msg = reclaim_safely(kea, d, get_assoc, snap); rec.update(executed=ok, result=msg)
                    else: rec.update(executed=False, result="dry-run")
                if d.action != "preserve" or pressure: log.write(json.dumps(rec) + "\n")
        except Exception as e:                       # fail safe: never act on errors
            log.write(json.dumps(dict(t=now, error=repr(e))) + "\n")
        if a.once: break
        time.sleep(a.interval)

if __name__ == "__main__":
    main()
