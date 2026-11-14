"""Self-contained, printable HTML forensic report (no JavaScript, no external resources).

Open in any browser and use "Print -> Save as PDF" for a court bundle, or run
`aletheia scan ... --pdf` when Chrome/Chromium/Edge is installed.
"""

from __future__ import annotations

import html
import json

from aletheia.detection.frameworks import D3FEND

E = html.escape

CSS = """
:root{--ink:#14181f;--muted:#5b6472;--line:#d9dee6;--bg:#ffffff;--soft:#f5f7fa;--accent:#1f3a5f;
--crit:#8b0000;--high:#c0392b;--med:#d68910;--low:#2471a3;--info:#5d6d7e;--ok:#1e8449}
*{box-sizing:border-box}body{font:14px/1.5 "Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);
background:var(--bg);margin:0}main{max-width:1050px;margin:0 auto;padding:32px 24px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;border-bottom:2px solid var(--accent);padding-bottom:4px;
margin-top:36px;color:var(--accent)}h3{font-size:15px;margin:18px 0 6px}
table{width:100%;border-collapse:collapse;margin:8px 0 16px;font-size:12.5px}
th,td{border:1px solid var(--line);padding:5px 7px;text-align:left;vertical-align:top;word-break:break-word}
th{background:var(--soft)}code,pre{font:12px/1.4 Consolas,"Courier New",monospace}
pre{background:var(--soft);border:1px solid var(--line);padding:8px;white-space:pre-wrap;word-break:break-all;margin:4px 0}
.cover{border:2px solid var(--accent);padding:24px;margin-bottom:24px}.muted{color:var(--muted)}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:600;
text-transform:uppercase;white-space:nowrap}.nw{white-space:nowrap}.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}
.low{background:var(--low)}.info{background:var(--info)}
.verdict{font-size:18px;font-weight:700;padding:12px 16px;border-left:6px solid var(--accent);background:var(--soft)}
.finding{border:1px solid var(--line);border-left:5px solid var(--info);padding:10px 14px;margin:12px 0;
page-break-inside:avoid}.finding.sev-critical{border-left-color:var(--crit)}.finding.sev-high{border-left-color:var(--high)}
.finding.sev-medium{border-left-color:var(--med)}.finding.sev-low{border-left-color:var(--low)}
.kv td:first-child{width:28%;font-weight:600;background:var(--soft)}
.sig{display:grid;grid-template-columns:1fr 1fr;gap:28px;margin-top:20px}.sig div{border-top:1px solid var(--ink);
padding-top:4px;margin-top:48px}.notice{border:1px solid var(--med);background:#fff8e6;padding:10px 14px}
.toc a{color:var(--accent);text-decoration:none}footer{margin-top:40px;font-size:11px;color:var(--muted);
border-top:1px solid var(--line);padding-top:8px}
@media print{main{padding:0}h2{page-break-before:auto}.pb{page-break-before:always}a{color:inherit}}
@page{size:A4;margin:16mm 14mm 18mm}
"""


def _sev(s):
    return f'<span class="badge {E(s)}">{E(s)}</span>'


def _kv(rows):
    return '<table class="kv">' + "".join(f"<tr><td>{E(str(k))}</td><td>{v}</td></tr>" for k, v in rows) + "</table>"


def _pre(x, limit=3000):
    s = x if isinstance(x, str) else json.dumps(x, indent=1, default=str)
    if len(s) > limit:
        s = s[:limit] + "\n...[truncated - full data in evidence/*.json]"
    return f"<pre>{E(s)}</pre>"


def render(data: dict, timeline: list) -> str:
    case, host, v = data["case"], data.get("host") or {}, data["verdict"]
    acq, tool = data["acquisition"], data["tool"]
    findings = data["findings"]
    plan = data.get("remediation_plan") or {}
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' "
           f"content='width=device-width,initial-scale=1'><title>Forensic Report {E(case['case_id'])}</title>"
           f"<style>{CSS}</style></head><body><main>"]

    # ---------------------------------------------------------------- cover
    out.append("<section class='cover'><div class='muted'>DIGITAL FORENSIC EXAMINATION &amp; IOC ASSESSMENT REPORT"
               "</div><h1>Case " + E(case["case_id"]) + "</h1>")
    out.append(_kv([
        ("Client / Matter", E(case.get("client") or "-")),
        ("Purpose of examination", E(case.get("purpose") or "-")),
        ("Evidence item", E(case.get("evidence_item") or f"Live system {host.get('hostname', '')}")),
        ("Examiner", E(case["examiner"])),
        ("Organization", E(case.get("organization") or "-")),
        ("Acquisition window (UTC)", E(f"{acq['started_utc']}  ->  {acq['ended_utc']}")),
        ("Acquisition mode", E(acq["mode"]) + f" &middot; profile <b>{E(acq['profile'])}</b>"),
        ("Tool", E(f"{tool['name']} v{tool['version']}") + f" &middot; build SHA-256 <code>{E(tool['build_sha256'])}</code>"),
        ("Audit chain head (SHA-256)", f"<code>{E(data['audit_chain_head'])}</code>"),
        ("Report generated (UTC)", E(data["generated_utc"])),
    ]))
    out.append("<p class='muted'>" + E(case.get("timezone_note", "")) + " The integrity of this report and every "
               "evidence file is protected by the <code>SHA256SUMS</code> manifest and the hash-chained "
               "<code>logs/audit.jsonl</code>; run <code>aletheia verify &lt;case-folder&gt;</code> to re-validate."
               "</p></section>")

    sections = [("summary", "1. Executive Summary"), ("scope", "2. Scope, Authority & Limitations"),
                ("method", "3. Methodology & Standards"), ("findings", "4. Detailed Findings"),
                ("attack", "5. MITRE ATT&CK Coverage"), ("timeline", "6. Timeline of Events"),
                ("system", "7. System Profile"), ("remediation", "8. Proposed Remediation (NOT executed)"),
                ("custody", "9. Chain of Custody & Actions Log"), ("evidence", "10. Evidence Manifest"),
                ("tools", "11. Tools, Intelligence & Versions"), ("errors", "12. Collection Errors"),
                ("attest", "13. Examiner Declaration"), ("glossary", "14. Glossary")]
    out.append("<nav class='toc'><b>Contents</b><ol>" + "".join(
        f"<li><a href='#{a}'>{E(t.split('. ', 1)[1])}</a></li>" for a, t in sections) + "</ol></nav>")

    # ------------------------------------------------------------- summary
    c = v["counts"]
    out.append(f"<h2 id='summary' class='pb'>1. Executive Summary</h2><div class='verdict'>{E(v['verdict'])}</div>"
               f"<p>{E(v['statement'])}</p>")
    out.append("<table><tr>" + "".join(f"<th>{_sev(s)}</th>" for s in c) + "</tr><tr>" +
               "".join(f"<td style='text-align:center;font-size:18px'>{n}</td>" for n in c.values()) + "</tr></table>")
    top = [f for f in findings if f["severity"] in ("critical", "high")][:10]
    if top:
        out.append("<h3>Key findings</h3><table><tr><th>ID</th><th>Severity</th><th>Finding</th><th>ATT&amp;CK</th></tr>")
        for f in top:
            out.append(f"<tr><td class='nw'><a href='#{E(f['id'])}'>{E(f['id'])}</a></td><td>{_sev(f['severity'])}</td>"
                       f"<td>{E(f['title'])}</td><td>{E(', '.join(a['id'] for a in f['attack']))}</td></tr>")
        out.append("</table>")
    out.append(f"<p><b>Host:</b> {E(str(host.get('hostname')))} &middot; {E(str(host.get('distribution') or host.get('os')))}"
               f" &middot; IPs {E(', '.join(host.get('ip_addresses') or []))}</p>")

    # --------------------------------------------------------------- scope
    scope = data.get("scope") or {}
    out.append("<h2 id='scope'>2. Scope, Authority &amp; Limitations</h2>")
    out.append(_kv([
        ("Authority / instructions", E(case.get("notes") or "Recorded by examiner at case creation.")),
        ("Ran with admin/root rights", "Yes" if host.get("running_as_admin") else
         "<b>No</b> - some artefacts were inaccessible (see SCOPE-001)"),
        ("File-system locations triaged", "<br>".join(E(t) for t in scope.get("targets", [])) or "-"),
        ("Files triaged", E(str(scope.get("files", 0))) + (" (limit reached - truncated)" if scope.get("truncated") else "")),
        ("Profile limits", E(json.dumps(scope.get("limits", {})))),
    ]))
    out.append("<div class='notice'><b>Live-response limitations.</b> This examination was performed on a running "
               "system (live triage) in accordance with RFC 3227's order of volatility. Executing any program on a "
               "live system has an unavoidable, minimal footprint (process creation, memory use); Aletheia minimises "
               "it by opening files strictly read-only (O_RDONLY, O_NOATIME where supported), never following "
               "symlinks or opening device/FIFO files, using an allow-list of read-only system commands, and writing "
               "output only to the case folder. Kernel-level rootkits can hide data from any live tool; where "
               "rootkit activity is suspected a full disk image and memory capture analysed offline is recommended. "
               "Absence of a finding is not proof of absence.</div>")

    # -------------------------------------------------------------- method
    out.append("<h2 id='method'>3. Methodology &amp; Standards</h2><ol>"
               "<li><b>Preparation</b> - case created, examiner identified, output folder isolated from targets.</li>"
               "<li><b>Volatile collection</b> (RFC 3227 order): clock &amp; system identity &rarr; network sockets "
               "&rarr; processes &rarr; sessions/accounts.</li>"
               "<li><b>Non-volatile triage</b>: persistence/autostart locations, file-system metadata and "
               "cryptographic hashes (SHA-256 evidentiary; MD5/SHA-1 for intel matching), logs, shell history, software.</li>"
               "<li><b>Preservation</b>: each artefact written once (exclusive-create), set read-only, hashed and "
               "logged in a SHA-256 hash-chained audit log; every system command and its output hash recorded.</li>"
               "<li><b>Analysis</b>: IOC matching against documented threat-intelligence sources; heuristic rules "
               "mapped to MITRE ATT&amp;CK; YARA signatures; optional open-source scanners.</li>"
               "<li><b>Reporting</b>: findings with evidence references, timeline, STIX 2.1 export; whole case "
               "sealed with a SHA-256 manifest.</li>"
               "<li><b>Remediation</b> is a separate stage and is only proposed here. Nothing is changed without "
               "explicit, recorded human approval.</li></ol>")
    out.append("<table><tr><th>Standard / framework</th><th>Application</th></tr>" + "".join(
        f"<tr><td>{E(a)}</td><td>{E(b)}</td></tr>" for a, b in data["standards"]) + "</table>")
    out.append("<h3>Legal admissibility considerations</h3><ul>" +
               "".join(f"<li>{E(n)}</li>" for n in data["legal_notes"]) + "</ul>")

    # ------------------------------------------------------------ findings
    out.append("<h2 id='findings' class='pb'>4. Detailed Findings</h2>")
    if not findings:
        out.append("<p>No findings.</p>")
    for f in findings:
        out.append(f"<div class='finding sev-{E(f['severity'])}' id='{E(f['id'])}'><h3>{E(f['id'])} &middot; "
                   f"{_sev(f['severity'])} {E(f['title'])}</h3>")
        out.append(_kv([
            ("Rule", E(f["rule_id"]) + f" &middot; category {E(str(f.get('category')))} &middot; confidence "
                                       f"<b>{E(f['confidence'])}</b>"),
            ("MITRE ATT&CK", "<br>".join(f"<a href='{E(a['url'])}'>{E(a['id'])}</a> {E(a['name'])} "
                                         f"<span class='muted'>({E(a['tactic'])})</span>" for a in f["attack"]) or "-"),
            ("Description", E(f["description"])),
            ("Event time (UTC)", E(str(f.get("event_time_utc") or "unknown"))),
            ("Recommendation", E(f.get("recommendation") or "-")),
        ]))
        for ev in f.get("evidence", [])[:20]:
            meta = {k: v for k, v in ev.items() if k not in ("excerpt",)}
            out.append(f"<div class='muted'>Evidence: <code>{E(json.dumps(meta, default=str))}</code></div>")
            if ev.get("excerpt"):
                out.append(_pre(ev["excerpt"], 1200))
        out.append("</div>")

    # -------------------------------------------------------------- attack
    out.append("<h2 id='attack'>5. MITRE ATT&amp;CK Coverage</h2>")
    tactics: dict = {}
    for f in findings:
        for a in f["attack"]:
            tactics.setdefault(a["tactic"] or "Unclassified", {}).setdefault(a["id"], [a["name"], []])[1].append(f["id"])
    if tactics:
        out.append("<table><tr><th>Tactic</th><th>Technique</th><th>Findings</th></tr>")
        for t in sorted(tactics):
            for tid, (name, fids) in sorted(tactics[t].items()):
                out.append(f"<tr><td>{E(t)}</td><td>{E(tid)} {E(name)}</td><td>{E(', '.join(sorted(set(fids))))}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p>No techniques observed.</p>")

    # ------------------------------------------------------------ timeline
    out.append("<h2 id='timeline'>6. Timeline of Events</h2>")
    if timeline:
        out.append("<table><tr><th>Time (UTC)</th><th>Source</th><th>Event</th><th>Finding</th></tr>")
        for e in timeline[:500]:
            out.append(f"<tr><td class='nw'>{E(str(e['time']))}</td><td>{E(str(e.get('source')))}</td><td>{E(str(e['event']))}</td>"
                       f"<td class='nw'>{E(e.get('finding', ''))}</td></tr>")
        out.append("</table>" + ("<p class='muted'>Truncated to 500 rows; full timeline in timeline.csv.</p>"
                                 if len(timeline) > 500 else ""))
    else:
        out.append("<p>No timestamped events.</p>")

    # -------------------------------------------------------------- system
    out.append("<h2 id='system'>7. System Profile</h2>")
    out.append(_kv([(k, E(str(v))) for k, v in host.items() if k not in ("security_posture",)]))
    if host.get("security_posture"):
        out.append("<h3>Security posture</h3>" + _pre(host["security_posture"], 4000))

    # --------------------------------------------------------- remediation
    out.append("<h2 id='remediation' class='pb'>8. Proposed Remediation (NOT executed)</h2>")
    out.append("<div class='notice'>The actions below are a <b>proposal only</b>. Aletheia performs no "
               "remediation during analysis. Execution requires a separate command "
               "(<code>aletheia remediate</code>) run by a human in an interactive terminal, who must review this "
               "exact plan (identified by its SHA-256) and type an explicit approval phrase. Every executed action is "
               "backed up, logged and reported separately so this analysis report remains unaltered.</div>")
    acts = plan.get("actions", [])
    out.append(f"<p>Plan SHA-256: <code>{E(plan.get('plan_sha256', '-'))}</code> &middot; {len(acts)} automated "
               f"action(s), {len(plan.get('manual', []))} manual recommendation(s).</p>")
    if acts:
        out.append("<table><tr><th>#</th><th>Action</th><th>Target</th><th>Reason (findings)</th><th>Reversible</th>"
                   "<th>D3FEND</th></tr>")
        for a in acts:
            d3 = D3FEND.get(a["type"], ("", ""))
            out.append(f"<tr><td class='nw'>{E(a['id'])}</td><td class='nw'>{E(a['type'])}</td><td><code>{E(a['target'])}</code></td>"
                       f"<td>{E(', '.join(a['findings']))}</td><td>{'Yes' if a.get('reversible') else 'No'}</td>"
                       f"<td>{E(d3[0])} {E(d3[1])}</td></tr>")
        out.append("</table>")
    if plan.get("manual"):
        out.append("<h3>Manual recommendations</h3><ul>" + "".join(
            f"<li>{E(m['text'])} <span class='muted'>({E(', '.join(m['findings']))})</span></li>" for m in plan["manual"])
                   + "</ul>")
    out.append("<h3>Recovery checklist</h3><ul><li>Rotate credentials of every account that logged on to this "
               "device; revoke SSH keys and API tokens.</li><li>Patch the OS and all applications; close the initial "
               "access vector.</li><li>Where rootkit, credential theft or ransomware is indicated, prefer re-imaging "
               "from known-good media over in-place cleaning.</li><li>Re-run Aletheia after remediation and compare."
               "</li><li>Notify stakeholders / regulators as required (e.g. PIPEDA breach reporting, GDPR Art. 33).</li></ul>")

    # ------------------------------------------------------------- custody
    out.append("<h2 id='custody' class='pb'>9. Chain of Custody &amp; Actions Log</h2>")
    out.append("<p>Every action of the tool is recorded in <code>logs/audit.jsonl</code>; each entry embeds the "
               "SHA-256 of the previous entry so any modification breaks the chain. The commands executed on the "
               "examined system are listed below with the SHA-256 of their output (output preserved under "
               "<code>evidence/commands/</code>).</p>")
    cmds = data.get("commands_executed", [])
    out.append("<table><tr><th>Started (UTC)</th><th>Command</th><th>RC</th><th>Output SHA-256</th></tr>")
    for cmd in cmds[:400]:
        out.append(f"<tr><td>{E(cmd['started_utc'])}</td><td><code>{E(' '.join(map(str, cmd['argv']))[:300])}</code></td>"
                   f"<td>{E(str(cmd.get('rc') if cmd.get('error') is None else cmd['error']))}</td>"
                   f"<td><code>{E(cmd['stdout_sha256'][:16])}&hellip;</code></td></tr>")
    out.append("</table>")
    out.append("<h3>Transfer of custody</h3><table><tr><th>Date/time</th><th>Released by</th><th>Received by</th>"
               "<th>Purpose</th><th>Signature</th></tr>" + "<tr><td>&nbsp;</td><td></td><td></td><td></td><td></td></tr>" * 4
               + "</table>")

    # ------------------------------------------------------------ evidence
    out.append("<h2 id='evidence'>10. Evidence Manifest</h2><table><tr><th>File</th><th>SHA-256</th><th>Bytes</th></tr>")
    for e in data.get("evidence_index", []):
        out.append(f"<tr><td><code>{E(e['path'])}</code></td><td><code>{E(e['sha256'])}</code></td>"
                   f"<td>{e['size']}</td></tr>")
    out.append("</table><p class='muted'>The final <code>SHA256SUMS</code> additionally covers this report, the "
               "JSON/CSV/STIX exports and the audit log.</p>")

    # --------------------------------------------------------------- tools
    intel = data.get("intel", {})
    out.append("<h2 id='tools'>11. Tools, Intelligence &amp; Versions</h2>")
    out.append(_kv([
        ("Aletheia", E(f"v{tool['version']} - {tool['files']} source/rule files, build SHA-256 {tool['build_sha256']}")),
        ("Python", E(str(host.get("python")))),
        ("IOC indicators loaded", E(json.dumps(intel.get("ioc_counts", {})))),
        ("IOC sources", "<br>".join(E(f"{s['source']} (+{s['indicators_added']})") for s in intel.get("ioc_sources", []))),
        ("Threat-feed snapshot", "<br>".join(E(f"{k}: sha256 {v.get('sha256', '-')} @ {v.get('downloaded_utc', '-')}")
                                             for k, v in (intel.get("feeds_snapshot") or {}).items()) or "none"),
        ("YARA", E(json.dumps(intel.get("yara") or {}))),
        ("External tools", E(json.dumps(data.get("external_tools") or "none requested"))),
    ]))

    # -------------------------------------------------------------- errors
    out.append("<h2 id='errors'>12. Collection Errors</h2>")
    errs = data.get("errors", [])
    if errs:
        out.append("<table><tr><th>Where</th><th>Error</th></tr>" + "".join(
            f"<tr><td>{E(e['where'])}</td><td>{E(e['error'])}</td></tr>" for e in errs[:300]) + "</table>")
    else:
        out.append("<p>None.</p>")

    # --------------------------------------------------------------- attest
    out.append("<h2 id='attest' class='pb'>13. Examiner Declaration</h2>")
    out.append(f"<p>I, <b>{E(case['examiner'])}</b>, declare that: (1) I conducted the examination described in this "
               "report using the methods stated; (2) to the best of my knowledge the tool operated in a read-only "
               "manner and did not alter, delete or add to the data under examination other than the unavoidable "
               "footprint of live response documented in section 2; (3) the evidence files, hashes and audit log "
               "referenced herein are true copies of the data collected; and (4) the findings and opinions expressed "
               "are my own, are within my expertise, and are given impartially.</p>")
    out.append("<div class='sig'><div>Examiner signature &amp; date</div><div>Reviewer / witness signature &amp; date</div>"
               "<div>Printed name &amp; credentials</div><div>Printed name &amp; credentials</div></div>")

    # ------------------------------------------------------------- glossary
    out.append("<h2 id='glossary'>14. Glossary</h2>" + _kv([
        ("IOC", "Indicator of Compromise - an observable (hash, IP, domain, URL, file) associated with malicious activity."),
        ("SHA-256", "Cryptographic hash; any change to a file changes its hash, proving integrity."),
        ("MITRE ATT&CK", "Public knowledge base of adversary tactics and techniques."),
        ("D3FEND", "MITRE knowledge graph of defensive countermeasures."),
        ("Live triage", "Examination of a running system to capture volatile data before shutdown."),
        ("Persistence", "Mechanism used by an attacker to survive reboots or log-offs."),
        ("STIX 2.1", "OASIS standard format for sharing threat intelligence."),
        ("Chain of custody", "Documented, unbroken record of evidence handling from collection to court."),
    ]))
    out.append(f"<footer>Generated by {E(tool['name'])} v{E(tool['version'])} - open-source (Apache-2.0). "
               f"Case {E(case['case_id'])}. Page integrity: see SHA256SUMS.</footer></main></body></html>")
    return "".join(out)
