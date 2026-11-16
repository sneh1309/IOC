"""Aletheia command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from aletheia import TOOL_NAME, __version__

BANNER = rf"""
    _    _      _   _          _
   / \  | | ___| |_| |__   ___(_) __ _    {TOOL_NAME} v{__version__}
  / _ \ | |/ _ \ __| '_ \ / _ \ |/ _` |   read-only IOC hunting & forensic triage
 / ___ \| |  __/ |_| | | |  __/ | (_| |   court-ready reporting
/_/   \_\_|\___|\__|_| |_|\___|_|\__,_|   human-approved remediation
"""


def _p(*a, **k):
    print(*a, **k, flush=True)


def cmd_scan(args) -> int:
    from aletheia.core.context import CaseInfo
    from aletheia.remediation import engine
    from aletheia.scan import run_scan

    log = (lambda *a, **k: print(*a, **k, file=sys.stderr, flush=True)) if args.json else _p
    if not args.json:
        _p(BANNER)
    case_id = args.case_id or "ALE-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    examiner = args.examiner
    if not examiner:
        if sys.stdin.isatty() and not args.json:
            examiner = input("Examiner name (recorded in the chain of custody): ").strip()
        if not examiner:
            log("error: --examiner is required (it is recorded in the chain of custody)")
            return 2
    case = CaseInfo(case_id=case_id, examiner=examiner, organization=args.org or "", client=args.client or "",
                    purpose=args.purpose or "", evidence_item=args.evidence_item or "", notes=args.notes or "")
    os.makedirs(args.output, exist_ok=True)
    from aletheia.core.util import IS_MACOS

    options = {"mac_investigation": bool(args.mac_root) or (IS_MACOS and not args.no_mac_investigation),
               "mac_root": args.mac_root, "watch": [w for item in (args.watch or []) for w in item.split(",")],
               "days": args.days, "include_content": args.include_content}
    res = run_scan(case, args.output, profile=args.profile, paths=args.path, iocs=args.ioc, yara=args.yara,
                   tools=args.with_tools, allow_tool_footprint=args.allow_tool_footprint, pdf=args.pdf,
                   sign_key=args.sign, min_remediation_severity=args.remediation_min_severity, log=log,
                   options=options)
    s, plan = res["summary"], res["plan"]
    if args.json:
        print(json.dumps(s, indent=2))
        return 0
    _p("\n" + "=" * 78)
    _p(f" VERDICT: {s['verdict']}")
    _p(" " + "  ".join(f"{k}={v}" for k, v in s["counts"].items()))
    _p("=" * 78)
    for f in s["findings"][:25]:
        _p(f"  {f['id']}  [{f['severity'].upper():<8}] {f['title'][:110]}")
    if len(s["findings"]) > 25:
        _p(f"  ... {len(s['findings']) - 25} more in the report")
    _p("\nReport (HTML)   : " + s["report_html"])
    if s.get("report_pdf"):
        _p("Report (PDF)    : " + s["report_pdf"])
    _p("Case folder     : " + s["case_dir"])
    _p("Manifest SHA-256: " + s["manifest_sha256"] + "   <- record this in your case notes")
    _p("\nAnalysis is complete and sealed. NOTHING on this device was changed.")
    if plan["actions"] and args.analysis_only:
        _p(f"{len(plan['actions'])} recommended clean-up action(s) are listed in report section 8 for review. "
           "Analysis-only mode: nothing will be executed.")
    elif plan["actions"]:
        _p(f"A remediation plan with {len(plan['actions'])} action(s) was prepared (plan {plan['plan_sha256'][:16]}...).")
        if not args.no_prompt and not args.analysis_only and sys.stdin.isatty() and sys.stdout.isatty():
            ans = input("Review the remediation plan and decide whether to approve it now? [y/N] ").strip().lower()
            if ans == "y":
                return engine.remediate(s["case_dir"])
        _p(f"To review/approve later:  aletheia plan \"{s['case_dir']}\"   then   aletheia remediate \"{s['case_dir']}\"")
    return 0


def cmd_verify(args) -> int:
    from aletheia.remediation.engine import verify_case

    v = verify_case(args.case_dir)
    if args.json:
        print(json.dumps(v, indent=2))
    else:
        _p(f"Manifest : {'OK' if v['manifest_ok'] else 'FAILED'} ({v['files_checked']} files)")
        _p(f"Audit log: {'OK' if v['audit_ok'] else 'FAILED'} ({v['audit_entries']} entries, head {v['audit_head']})")
        for p in v["problems"]:
            _p("  ! " + p)
        _p("INTEGRITY VERIFIED" if v["ok"] else "INTEGRITY CHECK FAILED")
    return 0 if v["ok"] else 1


def cmd_plan(args) -> int:
    from aletheia.remediation import engine

    if args.json:
        print(json.dumps(engine.load_plan(args.case_dir), indent=2))
        return 0
    return engine.remediate(args.case_dir, dry_run=True)


def cmd_remediate(args) -> int:
    from aletheia.remediation import engine

    _p(BANNER)
    return engine.remediate(args.case_dir, workspace=args.workspace)


def cmd_restore(args) -> int:
    from aletheia.remediation.actions import restore_quarantine

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        _p("REFUSED: restoring a quarantined file requires an interactive terminal.")
        return 4
    with open(args.quarantine_file + ".json", encoding="utf-8") as fh:
        meta = json.load(fh)
    _p(f"Restore {meta['original_path']} (sha256 {meta['hashes']['sha256']})?")
    if input("Type RESTORE to confirm: ").strip() != "RESTORE":
        _p("Cancelled.")
        return 1
    _p("Restored to " + restore_quarantine(args.quarantine_file))
    return 0


def cmd_summary(args) -> int:
    path = os.path.join(args.case_dir, "report", "report.json")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out = {"case": data["case"], "host": {k: (data.get("host") or {}).get(k) for k in
                                          ("hostname", "os", "distribution", "ip_addresses", "running_as_admin")},
           "verdict": data["verdict"], "acquisition": data["acquisition"],
           "findings": [{k: f.get(k) for k in ("id", "severity", "confidence", "title", "description",
                                                "recommendation")} | {"attack": [a["id"] for a in f["attack"]],
                                                                      "evidence": f["evidence"][:3]}
                        for f in data["findings"][: args.limit]],
           "remediation_plan": {"plan_sha256": data["remediation_plan"]["plan_sha256"],
                                "actions": [{k: a[k] for k in ("id", "type", "target", "findings", "reversible", "risk")}
                                            for a in data["remediation_plan"]["actions"]],
                                "manual": data["remediation_plan"]["manual"]}}
    print(json.dumps(out, indent=2, default=str))
    return 0


def cmd_feeds(args) -> int:
    from aletheia import feeds

    if args.action == "update":
        _p("Downloading free threat-intelligence feeds (abuse.ch, CC0) to " + feeds.feeds_dir())
        feeds.update(_p)
    else:
        for k, v in feeds.snapshot().items():
            _p(f"{k:<36} {v.get('downloaded_utc', v.get('error', '-'))}  {v.get('desc', '')}")
        if not feeds.snapshot():
            _p("No feeds downloaded yet. Run: aletheia feeds update")
    return 0


def cmd_tools(args) -> int:
    from aletheia.integrations.external import detect

    for name, m in detect().items():
        _p(f"{'[x]' if m['installed'] else '[ ]'} {name:<11} {m['purpose']}")
        _p(f"      {m['project']}  | footprint: {m['footprint']}")
    try:
        import yara  # noqa: F401

        _p("[x] yara-python module available")
    except ImportError:
        _p("[ ] yara-python (pip install yara-python) - or install the yara CLI")
    return 0


def cmd_ioc_check(args) -> int:
    from aletheia.detection.ioc import classify, load_database

    db = load_database(args.ioc or [])
    rc = 0
    for v in args.values:
        t = classify(v)
        m = None
        if t in ("md5", "sha1", "sha256"):
            m = db.match_hash(v)
        elif t in ("ipv4", "ipv6"):
            m = db.match_ip(v)
        elif t == "domain":
            m = db.match_domain(v)
        elif t == "url":
            m = (db.scan_text(v) or [None])[0]
        _p(f"{v}  type={t}  -> {'MATCH ' + json.dumps(m) if m else 'no match'}")
        rc = rc or (1 if m else 0)
    return rc


def cmd_mcp(args) -> int:
    from aletheia.mcp_server import serve

    serve()
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="aletheia", description="Read-only IOC & forensic triage with court-ready "
                                 "reports and human-approved remediation.")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="analyse this device (read-only) and produce sealed reports")
    s.add_argument("--case-id", help="case / matter number (default: auto)")
    s.add_argument("--examiner", help="examiner full name (chain of custody)")
    s.add_argument("--org", help="examiner organisation")
    s.add_argument("--client", help="client / matter name")
    s.add_argument("--purpose", help="reason for examination / authority")
    s.add_argument("--evidence-item", help="evidence item description (asset tag, serial no.)")
    s.add_argument("--notes", help="authority, instructions, warrant/consent reference")
    s.add_argument("--output", "-o", default="aletheia_cases", help="output folder (use external media)")
    s.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
    s.add_argument("--path", action="append", help="extra path to triage (repeatable)")
    s.add_argument("--ioc", action="append", help="IOC file/dir: txt, csv, json, STIX 2.1, MISP (repeatable)")
    s.add_argument("--yara", action="append", help="YARA rule file/dir (repeatable)")
    s.add_argument("--with", dest="with_tools", action="append",
                   help="run optional open-source tool (clamscan, chkrootkit, osqueryi, hayabusa, capa ... or 'all')")
    s.add_argument("--allow-tool-footprint", action="store_true",
                   help="permit tools that write their own logs on the examined system (rkhunter, lynis, autorunsc)")
    s.add_argument("--remediation-min-severity", choices=["critical", "high", "medium", "low"], default="medium")
    s.add_argument("--pdf", action="store_true", help="also render report.pdf using local Chrome/Chromium/Edge")
    s.add_argument("--sign", metavar="GPG_KEY", help="detach-sign SHA256SUMS with this GPG key")
    s.add_argument("--no-prompt", action="store_true", help="do not offer remediation at the end")
    s.add_argument("--analysis-only", action="store_true",
                   help="pure read-only examination: never offer or mention executing remediation")
    s.add_argument("--watch", action="append", metavar="TERM",
                   help="e-mail address / name / phone / keyword to look for in mail, messages, browser history "
                        "(repeatable or comma-separated)")
    s.add_argument("--days", type=int, default=90, help="how far back to search system logs (default 90)")
    s.add_argument("--include-content", action="store_true",
                   help="also collect message text (default: metadata only, for privacy)")
    s.add_argument("--no-mac-investigation", action="store_true", help="skip the macOS investigation module")
    s.add_argument("--mac-root", metavar="PATH",
                   help="OFFLINE: analyse a mounted Mac volume/image (e.g. '/Volumes/Macintosh HD') instead of the live system")
    s.add_argument("--json", action="store_true", help="print machine-readable summary (for Claude / automation)")
    s.set_defaults(fn=cmd_scan)

    v = sub.add_parser("verify", help="verify integrity of a sealed case folder")
    v.add_argument("case_dir")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_verify)

    p = sub.add_parser("plan", help="show the proposed remediation plan (changes nothing)")
    p.add_argument("case_dir")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_plan)

    r = sub.add_parser("remediate", help="HUMAN-APPROVED remediation (interactive terminal only)")
    r.add_argument("case_dir")
    r.add_argument("--workspace", help="where to write backups/quarantine (default: <case>/remediation_<UTC>)")
    r.set_defaults(fn=cmd_remediate)

    q = sub.add_parser("restore-quarantine", help="restore a quarantined file (interactive)")
    q.add_argument("quarantine_file")
    q.set_defaults(fn=cmd_restore)

    sm = sub.add_parser("summary", help="print a JSON summary of a case (for Claude / automation)")
    sm.add_argument("case_dir")
    sm.add_argument("--limit", type=int, default=50)
    sm.set_defaults(fn=cmd_summary)

    f = sub.add_parser("feeds", help="download / list free threat-intel feeds")
    f.add_argument("action", choices=["update", "list"])
    f.set_defaults(fn=cmd_feeds)

    t = sub.add_parser("tools", help="list optional open-source tools detected on this machine")
    t.set_defaults(fn=cmd_tools)

    c = sub.add_parser("ioc-check", help="check indicators against loaded IOC feeds")
    c.add_argument("values", nargs="+")
    c.add_argument("--ioc", action="append")
    c.set_defaults(fn=cmd_ioc_check)

    m = sub.add_parser("mcp", help="run the MCP server (Claude Desktop / Claude Code integration)")
    m.set_defaults(fn=cmd_mcp)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        _p("\nInterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
