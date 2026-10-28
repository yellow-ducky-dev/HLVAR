import json, os, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
import hlvar_daemon as H

NOW = 10_000.0
def lease(ip, mac, left=3000):  # lease with `left` seconds remaining
    return dict(ip=ip, mac=mac, cltt=NOW - 100, expiry=NOW + left)

class EngineTests(unittest.TestCase):
    def mk(self, **kw): return H.Engine(pool_size=10, grace=10, **kw)

    def test_no_pressure_no_action(self):
        e = self.mk(); ls = [lease(f"10.0.0.{i}", f"aa:{i:02x}") for i in range(5)]
        p, d = e.step(NOW, ls, set())             # nobody associated but pool is only 50% used
        self.assertFalse(p); self.assertEqual(d, [])

    def test_associated_leases_always_preserved_under_pressure(self):
        e = self.mk(); ls = [lease(f"10.0.0.{i}", f"aa:{i:02x}") for i in range(10)]
        p, d = e.step(NOW, ls, {l["mac"] for l in ls})
        self.assertTrue(p); self.assertTrue(all(x.action == "preserve" for x in d))

    def test_silence_is_not_evidence_grace_applies(self):
        e = self.mk(); ls = [lease(f"10.0.0.{i}", f"aa:{i:02x}") for i in range(10)]
        assoc = {l["mac"] for l in ls[1:]}                      # client 0 just dropped off
        e.step(NOW - 1, ls, assoc)                             # first sighting of un-association
        p, d = e.step(NOW + 3, ls, assoc)                      # 4 s < grace
        self.assertFalse(any(x.action == "reclaim" for x in d))
        p, d = e.step(NOW + 20, ls, assoc)                     # 21 s >= grace
        rec = [x for x in d if x.action == "reclaim"]
        self.assertEqual([x.ip for x in rec], ["10.0.0.0"])

    def test_returning_client_resets_timer(self):
        e = self.mk(); ls = [lease(f"10.0.0.{i}", f"aa:{i:02x}") for i in range(10)]
        allm = {l["mac"] for l in ls}
        e.step(NOW, ls, allm - {"aa:00"}); e.step(NOW + 8, ls, allm)       # back after 8 s
        e.step(NOW + 9, ls, allm - {"aa:00"})                              # drops again: timer restarts
        p, d = e.step(NOW + 15, ls, allm - {"aa:00"})
        self.assertFalse(any(x.action == "reclaim" for x in d))

    def test_reclaims_only_up_to_target(self):
        e = self.mk(); ls = [lease(f"10.0.0.{i}", f"aa:{i:02x}") for i in range(10)]
        e.step(NOW, ls, set())
        p, d = e.step(NOW + 60, ls, set())                     # everyone un-associated
        self.assertEqual(sum(x.action == "reclaim" for x in d), 2)          # target 20% of 10

class SmallPoolRegression(unittest.TestCase):
    def test_tiny_pool_still_reclaims(self):       # found by live-Kea test: int(0.2*1)==0 blocked reclaim
        e = H.Engine(pool_size=1, grace=0.0, cooldown=0.0); ls = [lease("10.0.0.2", "aa:01")]
        e.step(NOW - 1, ls, set()); p, d = e.step(NOW, ls, set())
        self.assertEqual([x.action for x in d], ["reclaim"])

class MockKea(BaseHTTPRequestHandler):
    leases = {}; deleted = []; hook = None
    def log_message(self, *a): pass
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        c, a = req["command"], req.get("arguments", {})
        if c == "lease4-get-all":
            body = [{"result": 0, "arguments": {"leases": [
                {"ip-address": ip, "hw-address": l["mac"], "cltt": l["cltt"], "valid-lft": l["expiry"] - l["cltt"], "state": 0}
                for ip, l in MockKea.leases.items()]}}]
        elif c == "lease4-get":
            if MockKea.hook: MockKea.hook()
            l = MockKea.leases.get(a["ip-address"])
            body = [{"result": 0, "arguments": {"ip-address": a["ip-address"], "hw-address": l["mac"], "cltt": l["cltt"]}} if l else {"result": 3}]
        elif c == "lease4-del":
            MockKea.deleted.append(a["ip-address"]); MockKea.leases.pop(a["ip-address"], None)
            body = [{"result": 0, "text": "deleted"}]
        else: body = [{"result": 2}]
        data = json.dumps(body).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(data)

class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), MockKea); cls.url = f"http://127.0.0.1:{cls.srv.server_port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def setUp(self):
        import time
        t = time.time()
        # 10-address pool, all full; aa:00 is gone from the AP
        MockKea.leases = {f"10.0.0.{i}": dict(mac=f"aa:{i:02x}", cltt=t - 100, expiry=t + 3000) for i in range(10)}
        MockKea.deleted = []; MockKea.hook = None
        self.d = tempfile.mkdtemp(); self.af = os.path.join(self.d, "assoc.txt"); self.log = os.path.join(self.d, "a.jsonl")
        self.write_assoc([f"aa:{i:02x}" for i in range(1, 10)])
    def write_assoc(self, macs):
        with open(self.af, "w") as f: f.write("\n".join(macs))
    def run_daemon(self, apply, cycles=3, gap=0.0, grace=0.0):
        import time
        args = ["--kea-url", self.url, "--pool-size", "10", "--assoc-file", self.af, "--grace", str(grace), "--log", self.log, "--once"] + (["--apply"] if apply else [])
        for _ in range(cycles): H.main(args); time.sleep(gap)
    def test_monitor_only_never_deletes(self):
        self.run_daemon(apply=False); self.assertEqual(MockKea.deleted, [])
        self.assertIn('"action": "reclaim"', open(self.log).read())

    def test_apply_deletes_only_disassociated_lease(self):
        # separate process per cycle -> engine state resets, so use one long-lived main loop instead:
        import time
        eng = H.Engine(10, grace=0.0, cooldown=0.0); kea = H.Kea(self.url)
        assoc = H.assoc_file(self.af)
        eng.step(time.time() - 1, kea.leases(), assoc)
        _, dec = eng.step(time.time(), kea.leases(), assoc)
        snap = {l["ip"]: l for l in kea.leases()}
        for d in dec:
            if d.action == "reclaim": H.reclaim_safely(kea, d, lambda: H.assoc_file(self.af), snap)
        self.assertEqual(MockKea.deleted, ["10.0.0.0"])

    def test_race_client_reassociates_before_delete(self):
        import time
        eng = H.Engine(10, grace=0.0, cooldown=0.0); kea = H.Kea(self.url)
        eng.step(time.time() - 1, kea.leases(), H.assoc_file(self.af))
        _, dec = eng.step(time.time(), kea.leases(), H.assoc_file(self.af))
        snap = {l["ip"]: l for l in kea.leases()}
        MockKea.hook = lambda: self.write_assoc([f"aa:{i:02x}" for i in range(10)])    # client returns mid-review
        for d in dec:
            if d.action == "reclaim":
                ok, why = H.reclaim_safely(kea, d, lambda: H.assoc_file(self.af), snap)
                self.assertFalse(ok); self.assertEqual(why, "client re-associated")
        self.assertEqual(MockKea.deleted, [])

    def test_race_lease_renewed_before_delete(self):
        import time
        eng = H.Engine(10, grace=0.0, cooldown=0.0); kea = H.Kea(self.url)
        eng.step(time.time() - 1, kea.leases(), H.assoc_file(self.af))
        _, dec = eng.step(time.time(), kea.leases(), H.assoc_file(self.af))
        snap = {l["ip"]: l for l in kea.leases()}
        MockKea.hook = lambda: MockKea.leases["10.0.0.0"].update(cltt=time.time())     # renewed mid-review
        for d in dec:
            if d.action == "reclaim":
                ok, why = H.reclaim_safely(kea, d, lambda: H.assoc_file(self.af), snap)
                self.assertFalse(ok); self.assertEqual(why, "lease renewed during review")
        self.assertEqual(MockKea.deleted, [])

if __name__ == "__main__":
    unittest.main(verbosity=2)
