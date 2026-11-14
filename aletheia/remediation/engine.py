"""Human-in-the-loop remediation stage.

Hard rules enforced here:
  * Runs ONLY from an interactive terminal (a human at a keyboard). Piped input,
    CI jobs, AI agents and the MCP server are refused - there is no override flag.
  * The sealed analysis case must pass integrity verification first.
  * The plan shown is the sealed plan; its SHA-256 is displayed and recorded.
  * The approver must type the exact phrase  APPROVE <CASE-ID>  and then EXECUTE.
  * Every action re-checks its target, backs up, executes, verifies and records rollback.
  * Results go to a NEW folder (remediation_<UTC>) - the analysis evidence is never edited.
"""

from __future__ import annotations

import html
import json
import os
import sys
from datetime import datetime, timezone

from aletheia.core.audit import AuditLog
from aletheia.core.evidence import EvidenceStore, verify_manifest
from aletheia.core.util import utc_now
from aletheia.remediation import actions as A
from aletheia.remediation.planner import plan_digest

BAR = "=" * 78


def load_plan(case_dir: str) -> dict:
    with open(os.path.join(case_dir, "report", "remediation_plan.json"), encoding="utf-8") as fh:
        return json.load(fh)


def verify_case(case_dir: str) -> dict:
    m_ok, m_problems, n = verify_manifest(case_dir)
    a_ok, a_problems, entries, head = AuditLog.verify(os.path.join(case_dir, "logs", "audit.jsonl"))
    return {"ok": m_ok and a_ok, "manifest_ok": m_ok, "files_checked": n, "audit_ok": a_ok, "audit_entries": entries,
            "audit_head": head, "problems": m_problems + a_problems}


def print_plan(plan: dict, out=print) -> None:
    out(BAR)
    out(f" REMEDIATION PLAN  case {plan['case_id']}   plan SHA-256 {plan['plan_sha256'][:16]}...")
    out(BAR)
    if not plan["actions"]:
        out(" No automated actions proposed.")
    for a in plan["actions"]:
        out(f" [{a['id']}] {a['type'].upper():<24} severity={a['severity']:<8} reversible={'yes' if a['reversible'] else 'NO'}")
        out(f"        WHAT : {A.describe(a)}")
        out(f"        WHY  : findings {', '.join(a['findings'])}")
        out(f"        RISK : {a['risk']}")
        if a.get("warning"):
            out(f"        !!!  : {a['warning']}")
    if plan.get("manual"):
        out("-" * 78)
        out(" Manual recommendations (never automated):")
        for m in plan["manual"]:
            out(f"   - {m['text']}  ({', '.join(m['findings'])})")
    out(BAR)


def _interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def remediate(case_dir: str, dry_run: bool = False, workspace: str = None, _io=None) -> int:
    """Entry point for `aletheia remediate`. Returns a process exit code."""
    ask = _io["input"] if _io else input
    out = _io["print"] if _io else print
    case_dir = os.path.abspath(case_dir)

    out("Verifying integrity of the sealed analysis case before anything else ...")
    v = verify_case(case_dir)
    if not v["ok"]:
        out("REFUSED: the analysis case failed integrity verification:")
        for p in v["problems"]:
            out("   " + p)
        return 3
    out(f"  OK - {v['files_checked']} files match SHA256SUMS; audit chain intact ({v['audit_entries']} entries).")

    plan = load_plan(case_dir)
    if plan_digest(plan) != plan["plan_sha256"]:
        out("REFUSED: remediation_plan.json does not match its recorded SHA-256.")
        return 3
    print_plan(plan, out)

    if dry_run:
        out("DRY RUN - nothing was changed. To execute, a human must run (in an interactive terminal):")
        out(f"   aletheia remediate \"{case_dir}\"")
        return 0
    if not plan["actions"]:
        out("Nothing to execute.")
        return 0
    if _io is None and not _interactive():
        out("REFUSED: remediation requires a human at an interactive terminal (no TTY detected).")
        out("If you are using Claude Code, run it yourself by typing at the prompt:")
        out(f"   ! aletheia remediate \"{case_dir}\"")
        return 4

    out("\nThis will MODIFY the live system. Review every action above.")
    approver = ask("Approver full name (recorded in the audit log): ").strip()
    if not approver:
        out("Aborted - no approver name given. Nothing was changed.")
        return 1
    phrase = f"APPROVE {plan['case_id']}"
    if ask(f"Type exactly  {phrase}  to authorise remediation: ").strip() != phrase:
        out("Approval phrase not matched. Nothing was changed.")
        return 1
    mode = ask("Execute [A]ll actions, [S]elect individually, or [Q]uit? ").strip().lower()
    if mode not in ("a", "s"):
        out("Quit. Nothing was changed.")
        return 1
    selected = []
    for a in plan["actions"]:
        if mode == "a":
            selected.append(a)
        elif ask(f"  {a['id']} {A.describe(a)}  -> execute? [y/N] ").strip().lower() == "y":
            selected.append(a)
    if not selected:
        out("No actions selected. Nothing was changed.")
        return 1
    out(f"\nSelected {len(selected)} action(s): {', '.join(a['id'] for a in selected)}")
    if ask("Final confirmation - type EXECUTE to proceed: ").strip() != "EXECUTE":
        out("Not confirmed. Nothing was changed.")
        return 1

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ws = os.path.abspath(workspace or os.path.join(case_dir, f"remediation_{stamp}"))
    os.makedirs(ws, exist_ok=True)
    audit = AuditLog(os.path.join(ws, "remediation_audit.jsonl"), plan["case_id"])
    audit.record("remediation_approved", {
        "approver": approver, "approval_phrase": phrase, "mode": "all" if mode == "a" else "select",
        "plan_sha256": plan["plan_sha256"], "analysis_audit_head": v["audit_head"],
        "selected_actions": [a["id"] for a in selected],
        "declined_actions": [a["id"] for a in plan["actions"] if a not in selected]})

    results = []
    for a in selected:
        handler = A.HANDLERS.get(a["type"])
        rec = {"id": a["id"], "type": a["type"], "target": a["target"], "findings": a["findings"],
               "started_utc": utc_now()}
        audit.record("action_start", {"id": a["id"], "type": a["type"], "target": a["target"]})
        try:
            if handler is None:
                raise A.Skip("no handler for this action type on this platform")
            rec.update(handler(a["params"], ws, audit))
            rec["status"] = "DONE"
        except A.Skip as s:
            rec["status"], rec["detail"] = "SKIPPED", str(s)
        except Exception as exc:  # keep going; report every failure
            rec["status"], rec["detail"] = "FAILED", f"{type(exc).__name__}: {exc}"
        rec["ended_utc"] = utc_now()
        audit.record("action_result", rec)
        results.append(rec)
        out(f"  [{rec['status']:<7}] {a['id']} {a['type']}: {rec.get('detail', '')}")

    report = {"case_id": plan["case_id"], "approver": approver, "plan_sha256": plan["plan_sha256"],
              "analysis_case": case_dir, "executed_utc": stamp, "results": results,
              "manual_recommendations": plan.get("manual", []),
              "next_steps": ["Re-run `aletheia scan` with a new case ID to verify the device is clean.",
                             "Rotate credentials for all accounts used on this device.",
                             "Patch and close the initial access vector."]}
    with open(os.path.join(ws, "remediation_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    with open(os.path.join(ws, "remediation_report.html"), "w", encoding="utf-8") as fh:
        fh.write(_html(report))
    audit.record("remediation_completed", {"done": sum(r["status"] == "DONE" for r in results),
                                           "skipped": sum(r["status"] == "SKIPPED" for r in results),
                                           "failed": sum(r["status"] == "FAILED" for r in results)})
    store = EvidenceStore.__new__(EvidenceStore)
    store.case_dir = ws
    digest = store.build_manifest()
    store.lock_all()
    out(BAR)
    out(f"Remediation finished. Report: {os.path.join(ws, 'remediation_report.html')}")
    out(f"Remediation manifest SHA-256: {digest}")
    out("Recommended: run a fresh `aletheia scan` (new case ID) to confirm the device is clean.")
    return 0 if all(r["status"] != "FAILED" for r in results) else 2


def _html(r: dict) -> str:
    E = html.escape
    rows = "".join(
        f"<tr><td>{E(x['id'])}</td><td>{E(x['type'])}</td><td><code>{E(x['target'])}</code></td>"
        f"<td><b>{E(x['status'])}</b></td><td>{E(str(x.get('detail', '')))}</td>"
        f"<td><code>{E(str(x.get('rollback', '')))}</code></td></tr>" for x in r["results"])
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>Remediation {E(r['case_id'])}</title>"
            "<style>body{font:14px Segoe UI,Arial,sans-serif;margin:32px;color:#14181f}table{border-collapse:collapse;"
            "width:100%}td,th{border:1px solid #ccc;padding:5px;vertical-align:top;font-size:12.5px}th{background:#f2f4f7}"
            "code{font-size:12px}</style></head><body>"
            f"<h1>Remediation Report - case {E(r['case_id'])}</h1>"
            f"<p>Approved by <b>{E(r['approver'])}</b> at {E(r['executed_utc'])} for plan SHA-256 "
            f"<code>{E(r['plan_sha256'])}</code>. Analysis evidence was not modified; this report and its backups "
            "are sealed in <code>SHA256SUMS</code> in this folder, and every step is in "
            "<code>remediation_audit.jsonl</code>.</p>"
            "<table><tr><th>ID</th><th>Action</th><th>Target</th><th>Status</th><th>Detail</th><th>Rollback</th></tr>"
            f"{rows}</table><h2>Next steps</h2><ul>" + "".join(f"<li>{E(s)}</li>" for s in r["next_steps"]) +
            "</ul><div style='margin-top:60px;border-top:1px solid #000;width:45%'>Approver signature &amp; date</div>"
            "</body></html>")
