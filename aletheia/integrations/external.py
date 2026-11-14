"""Optional integration with free, open-source security tools.

Aletheia never installs these; if a tool is on PATH and enabled with `--with <name>`
(or `--with all`), it runs in a strictly read-only mode and its raw output is preserved
as evidence. Each tool declares its *footprint* honestly: tools that write their own
log/state files on the examined system are refused unless `--allow-tool-footprint`.
"""

from __future__ import annotations

import os

from aletheia.core.util import IS_WINDOWS

TOOLS = {
    "clamscan": {
        "project": "ClamAV (GPL-2.0) - https://www.clamav.net",
        "purpose": "Signature-based malware scan of the triaged locations",
        "footprint": "none (scan-only; --remove/--move are never passed)",
        "writes_to_system": False,
    },
    "chkrootkit": {
        "project": "chkrootkit (BSD-like) - https://www.chkrootkit.org",
        "purpose": "Rootkit / LKM / log-wiper checks",
        "footprint": "none (read-only checks)",
        "writes_to_system": False, "os": "posix",
    },
    "rkhunter": {
        "project": "Rootkit Hunter (GPL) - https://rkhunter.sourceforge.net",
        "purpose": "Rootkit, backdoor and local-exploit checks",
        "footprint": "writes /var/log/rkhunter.log and may update its property DB",
        "writes_to_system": True, "os": "posix",
    },
    "lynis": {
        "project": "Lynis (GPL-3.0) - https://cisofy.com/lynis",
        "purpose": "Security hardening audit (CIS-style posture)",
        "footprint": "writes /var/log/lynis.log and /var/log/lynis-report.dat",
        "writes_to_system": True, "os": "posix",
    },
    "osqueryi": {
        "project": "osquery (Apache-2.0/GPL-2.0) - https://osquery.io",
        "purpose": "Cross-check processes, listening ports and startup items via SQL",
        "footprint": "none (interactive shell, no daemon, no database persisted)",
        "writes_to_system": False,
    },
    "hayabusa": {
        "project": "Hayabusa (AGPL-3.0) - https://github.com/Yamato-Security/hayabusa",
        "purpose": "Sigma-rule based Windows event-log threat hunting",
        "footprint": "none on the examined system (reads .evtx, writes CSV into the case folder)",
        "writes_to_system": False, "os": "windows",
    },
    "chainsaw": {
        "project": "Chainsaw (GPL-3.0) - https://github.com/WithSecureLabs/chainsaw",
        "purpose": "Sigma-rule based Windows event-log hunting",
        "footprint": "none on the examined system",
        "writes_to_system": False, "os": "windows",
    },
    "autorunsc": {
        "project": "Sysinternals Autoruns (Microsoft, freeware) - https://learn.microsoft.com/sysinternals",
        "purpose": "Exhaustive Windows autostart enumeration with signature verification",
        "footprint": "-accepteula writes HKCU\\Software\\Sysinternals\\AutoRuns\\EulaAccepted",
        "writes_to_system": True, "os": "windows",
    },
    "capa": {
        "project": "capa (Apache-2.0) - https://github.com/mandiant/capa",
        "purpose": "Identify capabilities (ATT&CK-mapped) of suspicious executables",
        "footprint": "none",
        "writes_to_system": False,
    },
}


def detect() -> dict:
    import shutil

    out = {}
    for name, meta in TOOLS.items():
        osreq = meta.get("os")
        if osreq == "windows" and not IS_WINDOWS:
            continue
        if osreq == "posix" and IS_WINDOWS:
            continue
        path = shutil.which(name) or (shutil.which(name + "64") if name == "autorunsc" else None)
        out[name] = {**meta, "path": path, "installed": bool(path)}
    return out


def run_enabled(ctx) -> list:
    """Run every enabled+installed tool. Returns additional findings."""
    if not ctx.external_tools:
        return []
    available = detect()
    wanted = set(available) if "all" in ctx.external_tools else set(ctx.external_tools)
    findings, summary = [], []
    for name in sorted(wanted):
        meta = available.get(name)
        if not meta or not meta["installed"]:
            summary.append({"tool": name, "status": "not installed"})
            continue
        if meta["writes_to_system"] and not ctx.allow_tool_footprint:
            summary.append({"tool": name, "status": "skipped - writes to examined system; "
                                                    "use --allow-tool-footprint to permit and document it"})
            continue
        ctx.audit.record("external_tool_start", {"tool": name, "path": meta["path"], "footprint": meta["footprint"]})
        try:
            fn = globals().get("_run_" + name)
            res = fn(ctx, meta["path"]) if fn else []
            findings += res
            summary.append({"tool": name, "status": "completed", "findings": len(res)})
        except Exception as exc:
            ctx.error(f"external:{name}", exc)
            summary.append({"tool": name, "status": f"error: {exc}"})
    ctx.add_artifact("external_tools", summary, "Third-party open-source tools executed")
    return findings


def _targets(ctx) -> list:
    return (ctx.artifacts.get("filesystem_scope") or {}).get("targets", [])


def _run_clamscan(ctx, exe):
    from aletheia.detection.rules import finding

    out = []
    for t in _targets(ctx):
        res = ctx.runner.run([exe, "-r", "-i", "--no-summary", "--stdout", t], label=f"clamscan_{os.path.basename(t)}",
                             timeout=7200, ok_codes=(0, 1))
        for line in res.get("stdout", "").splitlines():
            if line.endswith(" FOUND"):
                path, _, sig = line[:-6].rpartition(": ")
                out.append(finding("EXT-CLAM", f"ClamAV: {sig} in {path}", "high", "T1204",
                                   f"ClamAV signature {sig} matched.", [{"artifact": "clamscan", "ref": path,
                                                                         "excerpt": line}],
                                   "Quarantine and confirm with a second engine.",
                                   [{"type": "quarantine_file", "path": path}], confidence="high", category="external"))
    return out


def _run_chkrootkit(ctx, exe):
    from aletheia.detection.rules import finding

    res = ctx.runner.run([exe, "-q"], label="chkrootkit", timeout=3600, ok_codes=(0, 1))
    out = []
    for line in res.get("stdout", "").splitlines():
        if "INFECTED" in line or "Possible" in line or "Warning" in line:
            out.append(finding("EXT-CHKRK", f"chkrootkit: {line.strip()[:150]}",
                               "critical" if "INFECTED" in line else "medium", "T1014",
                               "chkrootkit reported a possible rootkit indicator (it is prone to false positives).",
                               [{"artifact": "chkrootkit", "ref": "stdout", "excerpt": line}],
                               "Validate manually.", [], confidence="low", category="external"))
    return out


def _run_rkhunter(ctx, exe):
    from aletheia.detection.rules import finding

    res = ctx.runner.run([exe, "--check", "--sk", "--nocolors", "--rwo", "--no-mail-on-warning"], label="rkhunter",
                         timeout=3600, ok_codes=(0, 1))
    return [finding("EXT-RKH", f"rkhunter: {l.strip()[:150]}", "medium", "T1014", "rkhunter warning.",
                    [{"artifact": "rkhunter", "ref": "stdout", "excerpt": l}], "Validate manually.", [],
                    confidence="low", category="external")
            for l in res.get("stdout", "").splitlines() if l.strip()]


def _run_lynis(ctx, exe):
    ctx.runner.run([exe, "audit", "system", "--quick", "--no-colors"], label="lynis", timeout=3600)
    return []  # hardening suggestions preserved as evidence, not IOC findings


def _run_osqueryi(ctx, exe):
    queries = {
        "osq_listening": "SELECT p.pid, p.name, p.path, l.port, l.address FROM listening_ports l JOIN processes p USING(pid);",
        "osq_no_binary": "SELECT pid, name, path, cmdline FROM processes WHERE on_disk = 0;",
        "osq_startup": "SELECT * FROM startup_items;",
    }
    from aletheia.detection.rules import finding

    out = []
    for label, q in queries.items():
        res = ctx.runner.run([exe, "--json", q], label=label, timeout=600)
        if label == "osq_no_binary":
            import json

            try:
                for r in json.loads(res.get("stdout") or "[]"):
                    out.append(finding("EXT-OSQ", f"osquery: process {r.get('name')} ({r.get('pid')}) has no on-disk binary",
                                       "high", "T1620", "osquery reports the executable is not on disk.",
                                       [{"artifact": "osquery", "ref": label, "excerpt": str(r)}],
                                       "Acquire memory then terminate.", [{"type": "kill_process",
                                                                          "pid": int(r.get("pid", 0)),
                                                                          "name": r.get("name")}],
                                       category="external"))
            except ValueError:
                pass
    return out


def _run_hayabusa(ctx, exe):
    out_csv = os.path.join(ctx.case_dir, "evidence", "hayabusa_timeline.csv")
    logs = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "winevt", "Logs")
    ctx.runner.run([exe, "csv-timeline", "-d", logs, "-o", out_csv, "-q", "-w", "-m", "high"], label="hayabusa",
                   timeout=7200)
    return _sigma_csv(out_csv, "Hayabusa")


def _run_chainsaw(ctx, exe):
    out_dir = os.path.join(ctx.case_dir, "evidence", "chainsaw")
    logs = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "winevt", "Logs")
    ctx.runner.run([exe, "hunt", logs, "--csv", "--output", out_dir, "-q"], label="chainsaw", timeout=7200)
    return []


def _run_autorunsc(ctx, exe):
    ctx.runner.run([exe, "-a", "*", "-c", "-h", "-s", "-nobanner", "-accepteula", "*"], label="autorunsc",
                   timeout=1800)
    return []


def _run_capa(ctx, exe):
    from aletheia.detection.rules import finding

    out = []
    sus = [f for f in ctx.findings if f.get("category") in ("filesystem", "process", "ioc")]
    paths = set()
    for f in sus:
        for r in f.get("remediation", []):
            if r.get("type") == "quarantine_file" and r.get("path") and os.path.isfile(r["path"]):
                paths.add(r["path"])
    for p in sorted(paths)[:25]:
        res = ctx.runner.run([exe, "-q", p], label=f"capa_{os.path.basename(p)}", timeout=600, ok_codes=(0, 1, 13, 14))
        if res.get("stdout"):
            out.append(finding("EXT-CAPA", f"capa capability analysis for {p}", "info", [],
                               "Capabilities identified by Mandiant capa (see evidence).",
                               [{"artifact": "capa", "ref": p, "excerpt": res["stdout"][:1500]}], "Review.", [],
                               category="external"))
    return out


def _sigma_csv(path: str, engine: str) -> list:
    import csv

    from aletheia.detection.rules import finding

    out = []
    if not os.path.exists(path):
        return out
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        for r in list(csv.DictReader(fh))[:500]:
            level = (r.get("Level") or "").lower()
            sev = {"crit": "critical", "critical": "critical", "high": "high", "med": "medium", "medium": "medium"}.get(level)
            if not sev:
                continue
            out.append(finding("EXT-SIGMA", f"{engine}/Sigma: {r.get('RuleTitle')}", sev,
                               [t for t in (r.get("MitreTags") or "").replace("attack.", "").upper().split()
                                if t.startswith("T")] or [],
                               r.get("Details", "")[:500],
                               [{"artifact": engine.lower(), "ref": f"{r.get('Channel')}#{r.get('RecordID')}",
                                 "excerpt": str(r)[:600], "time": r.get("Timestamp")}],
                               "Investigate the event in context.", [], confidence="medium", category="external",
                               when=r.get("Timestamp")))
    return out
