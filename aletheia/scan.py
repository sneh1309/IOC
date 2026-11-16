"""Analysis-stage orchestrator: collect -> preserve -> detect -> report -> seal."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from aletheia import __version__
from aletheia.collectors import (accounts, filesystem, logs, macos_forensics, network, persistence, processes, software,
                                 system)
from aletheia.core.audit import AuditLog
from aletheia.core.context import CaseInfo, ScanContext
from aletheia.core.evidence import EvidenceStore, safe_name
from aletheia.core.runner import SafeRunner
from aletheia.core.util import utc_now
from aletheia.detection import ioc as ioc_mod
from aletheia.detection import rules, yara_scan
from aletheia.integrations import external
from aletheia.remediation.planner import build_plan
from aletheia.report import builder, html as html_report

# RFC 3227 order of volatility: most volatile first.
COLLECTION_ORDER = [
    ("system", system.collect, "clock reference, host identity, security posture"),
    ("processes", processes.collect, "running processes"),
    ("network", network.collect, "network sockets, DNS/ARP caches, hosts file"),
    ("accounts", accounts.collect, "accounts, sessions, SSH keys"),
    ("persistence", persistence.collect, "autostart / persistence mechanisms"),
    ("filesystem", filesystem.collect, "file-system triage and hashing"),
    ("logs", logs.collect, "authentication & security logs, shell history"),
    ("software", software.collect, "installed software"),
]


def run_scan(case: CaseInfo, output: str, profile: str = "standard", paths=None, iocs=None, yara=None,
             tools=None, allow_tool_footprint=False, pdf=False, sign_key=None, min_remediation_severity="medium",
             log=print, options=None) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    case_dir = os.path.abspath(os.path.join(output, f"{safe_name(case.case_id)}_{stamp}"))
    os.makedirs(case_dir, exist_ok=False)
    store = EvidenceStore(case_dir)
    audit = AuditLog(os.path.join(store.logs_dir, "audit.jsonl"), case.case_id)
    runner = SafeRunner(audit=audit, store=store)
    ctx = ScanContext(case=case, case_dir=case_dir, profile=profile, extra_paths=list(paths or []),
                      ioc_sources=list(iocs or []), yara_sources=list(yara or []), external_tools=list(tools or []),
                      allow_tool_footprint=allow_tool_footprint, audit=audit, store=store, runner=runner, log=log,
                      options=dict(options or {}))
    started = utc_now()
    fp = builder.tool_fingerprint()
    audit.record("case_opened", {"case": case.__dict__, "argv": sys.argv, "profile": profile, "case_dir": case_dir,
                                 "tool_version": __version__, "tool_build_sha256": fp["build_sha256"],
                                 "mode": "analysis (read-only)"})
    store.save_json("case", {"case": case.__dict__, "opened_utc": started, "tool": {k: v for k, v in fp.items()
                                                                                    if k != "file_hashes"}},
                    subdir=".")
    _warn_output_location(ctx, log)

    mac_root = ctx.options.get("mac_root")
    offline = bool(mac_root) and os.path.abspath(mac_root) != os.path.abspath(os.sep)
    order = COLLECTION_ORDER
    if offline:
        # The evidence is a mounted volume: never examine the host this tool happens to run on.
        log(f"[*] OFFLINE mode - examining mounted volume {mac_root} only (no live collection on this computer)")
        audit.record("offline_mode", {"evidence_root": os.path.abspath(mac_root)})
        ctx.extra_paths = macos_forensics.offline_targets(mac_root) + ctx.extra_paths
        ctx.options["offline"] = True
        order = [("offline_source", macos_forensics.offline_source, "evidence volume identity"),
                 ("persistence", macos_forensics.offline_persistence, "launch agents/daemons on the volume"),
                 ("filesystem", filesystem.collect, "file-system triage of the volume")]
    for name, fn, desc in order:
        log(f"[*] Collecting {desc} ...")
        audit.record("collector_start", {"collector": name})
        try:
            fn(ctx)
        except Exception as exc:
            ctx.error(f"collector:{name}", exc)
            log(f"    [!] {name}: {exc}")

    if ctx.options.get("mac_investigation"):
        log("[*] macOS investigation (mail, messages, usage, networks, spyware, remote access) ...")
        audit.record("collector_start", {"collector": "macos_investigation", "options": {
            k: v for k, v in ctx.options.items() if k != "watch"}, "watch_terms": len(ctx.options.get("watch") or [])})
        try:
            macos_forensics.collect(ctx)
        except Exception as exc:
            ctx.error("collector:macos_investigation", exc)
            log(f"    [!] macOS investigation: {exc}")

    log("[*] Loading threat intelligence (IOC feeds) ...")
    db = ioc_mod.load_database(ctx.ioc_sources)
    audit.record("ioc_database_loaded", {"counts": db.stats(), "sources": db.sources})
    log(f"    {len(db):,} indicators loaded: {db.stats()}")

    log("[*] Running detection rules (MITRE ATT&CK mapped) ...")
    ctx.findings = rules.run_all(ctx.artifacts, db)
    log("[*] YARA signature scan ...")
    try:
        ctx.findings += yara_scan.findings_from(ctx, yara_scan.scan(ctx))
    except Exception as exc:
        ctx.error("yara", exc)
    if ctx.external_tools:
        log(f"[*] Running external open-source tools: {', '.join(ctx.external_tools)} ...")
        ctx.findings += external.run_enabled(ctx)
    ctx.findings = _renumber(ctx.findings)
    ended = utc_now()
    audit.record("analysis_completed", {"findings": len(ctx.findings), "errors": len(ctx.errors)})

    log("[*] Building remediation PLAN (proposal only - nothing is executed) ...")
    plan = build_plan(case.case_id, ctx.findings, min_remediation_severity)
    log("[*] Writing reports ...")
    data = builder.build_report_data(ctx, db, started, ended, plan)
    tl = builder.timeline(ctx)
    rd = "report"
    store.save_text("report", json.dumps(data, indent=2, default=str, ensure_ascii=False), subdir=rd, ext=".json")
    html_rec = store.save_text("report", html_report.render(data, tl), subdir=rd, ext=".html")
    store.save_text("findings", builder.findings_csv(ctx.findings), subdir=rd, ext=".csv")
    store.save_text("timeline", builder.timeline_csv(tl), subdir=rd, ext=".csv")
    store.save_text("iocs_stix21", json.dumps(builder.stix_bundle(ctx), indent=2), subdir=rd, ext=".json")
    store.save_text("remediation_plan", json.dumps(plan, indent=2, default=str), subdir=rd, ext=".json")
    for name, csv_text in builder.investigation_csvs(ctx).items():
        store.save_text(name, csv_text, subdir=os.path.join(rd, "investigation"), ext=".csv")
    html_path = os.path.join(case_dir, html_rec["path"])
    pdf_path = _pdf(html_path, log) if pdf else None
    if pdf_path:
        audit.record("pdf_rendered", {"file": os.path.relpath(pdf_path, case_dir)})

    audit.record("case_sealing", {"note": "SHA256SUMS manifest is computed over every file after this entry"})
    digest = store.build_manifest()
    store.lock_all()
    sig = _sign(case_dir, sign_key, log) if sign_key else None

    v = data["verdict"]
    summary = {"case_dir": case_dir, "report_html": html_path, "report_pdf": pdf_path, "verdict": v["verdict"],
               "counts": v["counts"], "manifest_sha256": digest, "signature": sig,
               "findings": [{"id": f["id"], "severity": f["severity"], "title": f["title"]} for f in ctx.findings],
               "plan_sha256": plan["plan_sha256"], "planned_actions": len(plan["actions"])}
    return {"summary": summary, "plan": plan}


def _renumber(findings: list) -> list:
    seen, out = set(), []
    for f in findings:
        k = (f["rule_id"], f["title"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    out.sort(key=lambda f: (-rules.SEV_ORDER.get(f["severity"], 0), f["rule_id"], f["title"]))
    for i, f in enumerate(out, 1):
        f["id"] = f"F-{i:04d}"
    return out


def _warn_output_location(ctx, log) -> None:
    note = None
    try:
        if os.name != "nt":
            if os.stat(ctx.case_dir).st_dev == os.stat("/").st_dev:
                note = "Output folder is on the system disk being examined"
        else:
            if os.path.splitdrive(ctx.case_dir)[0].upper() == os.environ.get("SystemDrive", "C:").upper():
                note = "Output folder is on the system drive being examined"
    except OSError:
        pass
    if note:
        msg = note + " - best practice is to write to external/forensic media (--output E:\\cases)."
        log("    [i] " + msg)
        ctx.audit.record("examiner_advisory", {"message": msg})


def _pdf(html_path: str, log):
    import glob

    candidates = [shutil.which(b) for b in ("chrome-headless-shell", "chromium", "chromium-browser", "google-chrome",
                                            "chrome", "msedge", "microsoft-edge")]
    candidates += sorted(glob.glob("/opt/pw-browsers/chromium_headless_shell-*/*/chrome-headless-shell"))
    candidates += [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                   r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                   "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                   "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"]
    exes = list(dict.fromkeys(c for c in candidates if c and os.path.isfile(c)))
    if not exes:
        log("    [i] No Chrome/Chromium/Edge found - open report.html and Print -> Save as PDF.")
        return None
    pdf_path = html_path[:-5] + ".pdf"
    for exe in exes:  # try each browser until one produces the PDF
        if _render_pdf(exe, html_path, pdf_path, timeout=60 if len(exes) > 1 else 120):
            return pdf_path
    log("    [!] PDF rendering failed - open report.html and Print -> Save as PDF.")
    return None


def _render_pdf(exe: str, html_path: str, pdf_path: str, timeout: int) -> bool:
    import time

    url = "file:///" + html_path.replace("\\", "/").lstrip("/")
    with tempfile.TemporaryDirectory(prefix="aletheia_pdf_") as prof:
        try:
            proc = subprocess.Popen([exe, "--headless", "--disable-gpu", "--no-sandbox", f"--user-data-dir={prof}",
                                     "--disable-dev-shm-usage", "--no-pdf-header-footer", "--no-first-run",
                                     f"--print-to-pdf={pdf_path}", url],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        except OSError:
            return False
        # Some headless builds keep running after printing: stop once the PDF is complete.
        last, stable, deadline = -1, 0, time.time() + timeout
        while time.time() < deadline and proc.poll() is None:
            size = os.path.getsize(pdf_path) if os.path.exists(pdf_path) else -1
            stable = stable + 1 if size > 0 and size == last else 0
            last = size
            if stable >= 3:
                break
            time.sleep(0.5)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
    ok = os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0
    if not ok and os.path.exists(pdf_path):
        os.remove(pdf_path)
    return ok


def _sign(case_dir: str, key: str, log):
    gpg = shutil.which("gpg")
    if not gpg:
        log("    [!] gpg not found - SHA256SUMS not signed.")
        return None
    sig = os.path.join(case_dir, "SHA256SUMS.sig")
    res = subprocess.run([gpg, "--batch", "--yes", "--armor", "--local-user", key, "--output", sig, "--detach-sign",
                          os.path.join(case_dir, "SHA256SUMS")], capture_output=True)
    if res.returncode != 0:
        log("    [!] gpg signing failed: " + res.stderr.decode("utf-8", "replace")[:300])
        return None
    return sig
