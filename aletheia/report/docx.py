"""Dependency-free .docx writer + the automatic Case Documentation generator.

Produces `report/Case_Documentation_<case>.docx` (editable Word document) and a Markdown
twin (`.md`, e.g. for ITGlue / tickets) automatically at the end of every scan.
"""

from __future__ import annotations

import io
import re
import zipfile
from xml.sax.saxutils import escape

BULLET = "\u2022  "
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
W_NS = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"')


def _x(text) -> str:
    return escape(_CTRL.sub("", "" if text is None else str(text)))


class Docx:
    def __init__(self, title: str, footer: str = ""):
        self.title, self.footer, self.body = title, footer, []

    # ---------------------------------------------------------------- blocks
    def _run(self, text, bold=False, size=None, color=None, italic=False, mono=False) -> str:
        rpr = ""
        if bold:
            rpr += "<w:b/>"
        if italic:
            rpr += "<w:i/>"
        if mono:
            rpr += '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>'
        if color:
            rpr += f'<w:color w:val="{color}"/>'
        if size:
            rpr += f'<w:sz w:val="{size}"/>'
        parts = str(text if text is not None else "").split("\n")
        out = []
        for i, part in enumerate(parts):
            if i:
                out.append("<w:r><w:br/></w:r>")
            out.append(f'<w:r>{"<w:rPr>" + rpr + "</w:rPr>" if rpr else ""}<w:t xml:space="preserve">{_x(part)}</w:t></w:r>')
        return "".join(out)

    def heading(self, text, level=1):
        self.body.append(f'<w:p><w:pPr><w:pStyle w:val="Heading{level}"/></w:pPr>{self._run(text)}</w:p>')

    def title_block(self, text, subtitle=""):
        self.body.append(f'<w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr>{self._run(text)}</w:p>')
        if subtitle:
            self.body.append(f'<w:p>{self._run(subtitle, color="5B6472", size=22)}</w:p>')

    def para(self, text="", bold=False, italic=False, color=None, size=None):
        self.body.append(f"<w:p>{self._run(text, bold=bold, italic=italic, color=color, size=size)}</w:p>")

    def rich(self, runs: list):
        """runs: list of (text, {bold, italic, color, mono})."""
        self.body.append("<w:p>" + "".join(self._run(t, **o) for t, o in runs) + "</w:p>")

    def bullet(self, text, level=0):
        ind = 360 + 360 * level
        run = self._run(BULLET + str(text))
        self.body.append(f'<w:p><w:pPr><w:ind w:left="{ind}" w:hanging="240"/><w:spacing w:after="40"/></w:pPr>'
                         f'{run}</w:p>')

    def notice(self, text):
        self.body.append('<w:p><w:pPr><w:pBdr><w:left w:val="single" w:sz="24" w:space="8" w:color="D68910"/></w:pBdr>'
                         f'<w:shd w:val="clear" w:color="auto" w:fill="FFF8E6"/><w:ind w:left="200"/></w:pPr>'
                         f'{self._run(text, size=19)}</w:p>')

    def page_break(self):
        self.body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    def table(self, headers: list, rows: list, widths: list = None, size=17):
        n = len(headers)
        total = 9638
        widths = widths or [total // n] * n
        grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)
        border = '<w:{0} w:val="single" w:sz="4" w:space="0" w:color="C9D1DB"/>'
        borders = "".join(border.format(b) for b in ("top", "left", "bottom", "right", "insideH", "insideV"))

        def cell(text, w, head=False):
            shd = '<w:shd w:val="clear" w:color="auto" w:fill="EEF2F6"/>' if head else ""
            return (f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{shd}</w:tcPr><w:p><w:pPr><w:spacing w:after="0"/>'
                    f'</w:pPr>{self._run(text, bold=head, size=size)}</w:p></w:tc>')
        out = [f'<w:tbl><w:tblPr><w:tblW w:w="{total}" w:type="dxa"/><w:tblBorders>{borders}</w:tblBorders>'
               f'<w:tblLayout w:type="fixed"/><w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" '
               f'w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>{grid}</w:tblGrid>']
        out.append('<w:tr><w:trPr><w:tblHeader/></w:trPr>' + "".join(cell(h, widths[i], True) for i, h in enumerate(headers)) + "</w:tr>")
        for r in rows:
            vals = [("" if v is None else (", ".join(map(str, v)) if isinstance(v, list) else str(v)))[:600] for v in r]
            out.append("<w:tr>" + "".join(cell(vals[i] if i < len(vals) else "", widths[i]) for i in range(n)) + "</w:tr>")
        out.append("</w:tbl>")
        self.body.append("".join(out))
        self.para("")

    def kv(self, rows: list):
        self.table(["Item", "Detail"], rows, widths=[2900, 6738], size=18)

    # ----------------------------------------------------------------- save
    def to_bytes(self) -> bytes:
        footer = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr {W_NS}><w:p><w:pPr><w:jc w:val="center"/>'
                  f'</w:pPr>{self._run(self.footer + "   |   Page ", size=16, color="5B6472")}'
                  '<w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r>'
                  '<w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
                  '<w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>')
        sect = ('<w:sectPr><w:footerReference w:type="default" r:id="rIdFooter"/><w:pgSz w:w="11906" w:h="16838"/>'
                '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" '
                'w:gutter="0"/></w:sectPr>')
        document = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {W_NS}><w:body>'
                    + "".join(self.body) + sect + "</w:body></w:document>")
        styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                  '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                  '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>'
                  '<w:sz w:val="21"/><w:lang w:val="en-CA"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr>'
                  '<w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
                  '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
                  '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/>'
                  '<w:pPr><w:spacing w:after="60"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="40"/></w:rPr></w:style>'
                  + "".join(f'<w:style w:type="paragraph" w:styleId="Heading{i}"><w:name w:val="heading {i}"/>'
                            f'<w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/>'
                            f'<w:spacing w:before="{280 - i * 40}" w:after="80"/><w:outlineLvl w:val="{i - 1}"/>'
                            + ('<w:pBdr><w:bottom w:val="single" w:sz="8" w:space="2" w:color="1F3A5F"/></w:pBdr>' if i == 1 else "")
                            + f'</w:pPr><w:rPr><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="{32 - i * 4}"/></w:rPr></w:style>'
                            for i in (1, 2, 3))
                  + "</w:styles>")
        content_types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                         '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                         '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                         '<Default Extension="xml" ContentType="application/xml"/>'
                         '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                         '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
                         '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
                         '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
                         '</Types>')
        rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
                '</Relationships>')
        doc_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                    '<Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
                    '</Relationships>')
        core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties '
                'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>' + _x(self.title) + '</dc:title>'
                '<dc:creator>Aletheia</dc:creator></cp:coreProperties>')
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in (("[Content_Types].xml", content_types), ("_rels/.rels", rels),
                               ("word/document.xml", document), ("word/styles.xml", styles),
                               ("word/footer1.xml", footer), ("word/_rels/document.xml.rels", doc_rels),
                               ("docProps/core.xml", core)):
                zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))  # deterministic container
                zi.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(zi, data.encode("utf-8"))
        return buf.getvalue()


class _Md:
    def __init__(self):
        self.lines = []

    def h(self, t, lvl=1):
        self.lines += ["", "#" * lvl + " " + t, ""]

    def p(self, t=""):
        self.lines.append(t)

    def b(self, t):
        self.lines.append(f"- {t}")

    def table(self, headers, rows):
        esc = lambda v: ("" if v is None else (", ".join(map(str, v)) if isinstance(v, list) else str(v))).replace("|", "\\|").replace("\n", " ")[:300]  # noqa: E731
        self.lines += ["", "| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
        self.lines += ["| " + " | ".join(esc(v) for v in r) + " |" for r in rows]
        self.lines.append("")


# ============================================================ case document
ONLINE_CHECKS = [
    ("Server-side e-mail forwarding", "outlook.live.com > Settings > Mail > Forwarding (Gmail: Settings > Forwarding)"),
    ("Inbox rules that forward/delete", "outlook.live.com > Settings > Mail > Rules (Gmail: Filters)"),
    ("Sign-in activity (IP addresses, locations)", "account.microsoft.com > Security > Sign-in activity"),
    ("Recoverable deleted e-mails", "Outlook.com > Deleted Items > Recover items deleted from this folder"),
    ("Devices on the same Apple ID", "System Settings > [name] > Devices, or appleid.apple.com"),
]


def build_case_document(data: dict, timeline: list) -> tuple:
    """Return (docx_bytes, markdown_text) for the case."""
    case, host, v = data["case"], data.get("host") or {}, data["verdict"]
    acq, tool, inv = data["acquisition"], data["tool"], data.get("investigation")
    findings, plan = data["findings"], data.get("remediation_plan") or {}
    rng = (inv or {}).get("range") or {}
    d = Docx(f"Case Documentation {case['case_id']}", footer=f"Case {case['case_id']} - Aletheia v{tool['version']}")
    m = _Md()

    d.title_block("Investigation Case Documentation",
                  f"Case {case['case_id']}  -  generated automatically by Aletheia on {data['generated_utc']} (UTC)")
    m.h(f"Investigation Case Documentation - Case {case['case_id']}")
    m.p(f"_Generated automatically by Aletheia on {data['generated_utc']} (UTC)._")

    info = [("Case / ticket", case["case_id"]), ("Client / owner", case.get("client") or "-"),
            ("Purpose / authority", case.get("purpose") or "-"), ("Evidence item", case.get("evidence_item") or "-"),
            ("Examiner", case["examiner"]), ("Organization", case.get("organization") or "-"),
            ("Device", f"{host.get('hostname')} - {host.get('distribution') or host.get('os')}"),
            ("Examination window (UTC)", f"{acq['started_utc']}  to  {acq['ended_utc']}"),
            ("Mode", f"{acq['mode']}, profile {acq['profile']}" + (f", {inv.get('mode')}" if inv else "")),
            ("Period examined", rng.get("label") or "n/a"),
            ("Watched terms", ", ".join((inv or {}).get("watch") or []) or "none"),
            ("Tool", f"Aletheia v{tool['version']} (build SHA-256 {tool['build_sha256']})")]
    d.heading("1. Case information")
    d.kv(info)
    m.h("1. Case information", 2)
    m.table(["Item", "Detail"], info)

    d.heading("2. Result summary")
    d.rich([("Verdict: ", {"bold": True}), (v["verdict"], {"bold": True, "color": "8B0000" if v["counts"]["critical"]
                                                           else "C0392B" if v["counts"]["high"] else "1E8449"})])
    d.para(v["statement"])
    counts = ", ".join(f"{k}: {n}" for k, n in v["counts"].items())
    d.para("Findings by severity - " + counts)
    m.h("2. Result summary", 2)
    m.p(f"**Verdict: {v['verdict']}** - {v['statement']}")
    m.p("Findings by severity - " + counts)
    top = [f for f in findings if f["severity"] in ("critical", "high", "medium")][:25]
    if top:
        rows = [[f["id"], f["severity"].upper(), f["title"], ", ".join(a["id"] for a in f["attack"])] for f in top]
        d.heading("Key findings", 2)
        d.table(["ID", "Severity", "Finding", "ATT&CK"], rows, widths=[900, 1100, 6338, 1300])
        m.h("Key findings", 3)
        m.table(["ID", "Severity", "Finding", "ATT&CK"], rows)

    if inv and inv.get("questions"):
        d.heading("3. Answers to the investigation questions")
        m.h("3. Answers to the investigation questions", 2)
        d.para(f"Times are the examined Mac's local time. Period examined: {rng.get('label', 'n/a')}. Full tables: "
               "report/investigation/*.csv; full detail: report/report.html section 1A.", italic=True, color="5B6472")
        for q in inv["questions"]:
            d.heading(f"{q['id']}. {q['question']}", 2)
            m.h(f"{q['id']}. {q['question']}", 3)
            for a in q.get("answer", []):
                d.bullet(a)
                m.b(a)
            for title, t in q.get("tables", {}).items():
                if not t["rows"]:
                    continue
                n = len(t["columns"])
                cols = t["columns"][:6]
                rows = [r[:6] for r in t["rows"][:10]]
                d.para(f"{title} ({t.get('total', len(t['rows']))} record(s){', first 10 shown' if t.get('total', 0) > 10 else ''})",
                       bold=True, size=19)
                d.table(cols, rows, size=16)
                m.p(f"**{title}** ({t.get('total', len(t['rows']))} record(s))")
                m.table(cols, rows)
                _ = n

    sec = 4 if inv else 3
    d.heading(f"{sec}. Work performed")
    m.h(f"{sec}. Work performed", 2)
    steps = ["Created the case and recorded the examiner, client and authority in a hash-chained audit log.",
             "Collected volatile and non-volatile information in RFC 3227 order using read-only methods only "
             "(files opened read-only, databases copied byte-for-byte and analysed only as copies, commands from a "
             "read-only allow-list).",
             f"Ran {len(data.get('commands_executed') or [])} read-only system command(s); output of each is preserved "
             "and hashed under evidence/commands/.",
             "Matched indicators of compromise, MITRE ATT&CK-mapped detection rules and YARA signatures.",
             "Generated the HTML report, CSV/JSON/STIX exports and this document, then sealed the whole case "
             "folder with a SHA-256 manifest (SHA256SUMS)."]
    if inv:
        steps.insert(2, "Ran the macOS investigation (Mail, Messages, browser history, downloads, app usage, power and "
                        "unlock history, Wi-Fi/IP history, privacy permissions, remote-access settings, system logs).")
    steps.append("No data on the device was deleted, changed or reset; no remediation was performed.")
    for s in steps:
        d.bullet(s)
        m.b(s)

    sec += 1
    d.heading(f"{sec}. Recommendations and next steps")
    m.h(f"{sec}. Recommendations and next steps", 2)
    recs = [f"{a['id']}: {a['type'].replace('_', ' ')} - {a['target']} (findings {', '.join(a['findings'])})"
            for a in plan.get("actions", [])[:30]]
    recs += [x["text"] for x in plan.get("manual", [])[:30]]
    if recs:
        d.para("Proposed actions (NOT executed - require the owner's decision):", bold=True)
        m.p("**Proposed actions (NOT executed - require the owner's decision):**")
        for r in recs:
            d.bullet(r)
            m.b(r)
    general = ["Review each finding with the device owner and confirm which items they recognise.",
               "Change the passwords of the e-mail account, Apple ID and Mac from a different, trusted device and "
               "enable two-factor authentication.",
               "Keep the sealed case folder unchanged; work from a verified copy."]
    for g in general:
        d.bullet(g)
        m.b(g)
    if inv:
        d.para("Online checks to complete (evidence that is stored on servers, not on the Mac):", bold=True)
        d.table(["Check", "Where", "Done / screenshot ref."], [[a, b, ""] for a, b in ONLINE_CHECKS],
                widths=[2800, 5000, 1838])
        m.p("**Online checks to complete:**")
        m.table(["Check", "Where", "Done"], [[a, b, ""] for a, b in ONLINE_CHECKS])

    sec += 1
    d.heading(f"{sec}. Evidence integrity and chain of custody")
    m.h(f"{sec}. Evidence integrity and chain of custody", 2)
    integ = [("Case folder", acq.get("case_dir")),
             ("Audit-log chain head (SHA-256)", data["audit_chain_head"]),
             ("Integrity manifest", "SHA256SUMS in the case folder (covers this document). Record the manifest "
                                    "SHA-256 shown at the end of the scan in your notes."),
             ("How to verify", "python3 run_aletheia.py verify \"<case folder>\"  ->  must report INTEGRITY VERIFIED")]
    d.kv(integ)
    m.table(["Item", "Detail"], integ)
    dbs = (inv or {}).get("databases") or []
    if dbs:
        rows = [[db["original"], f["file"], f["sha256"]] for db in dbs for f in db.get("files", [])][:60]
        d.para("Databases preserved (byte-for-byte copies, analysed only as copies):", bold=True)
        d.table(["Original location", "File", "SHA-256"], rows, widths=[4300, 1500, 3838], size=15)
        m.table(["Original location", "File", "SHA-256"], rows)
    d.para("Transfer of custody:", bold=True)
    d.table(["Date / time", "Released by", "Received by", "Purpose", "Signature"], [[""] * 5 for _ in range(4)])

    sec += 1
    d.heading(f"{sec}. Limitations")
    m.h(f"{sec}. Limitations", 2)
    lims = ["Live examination of a running system; kernel-level malware can hide from any live tool.",
            "Absence of a finding is not proof of absence."]
    if inv:
        lims += ["E-mail forwarding configured on the provider's website, and deleted data that has been "
                 "overwritten, are not visible on the device (see online checks)."]
        lims += [f"Access problem: {p['path']} - {p['error']}" for p in (inv.get("access_problems") or [])[:15]]
    lims += [f"Collection error: {e['where']} - {e['error']}" for e in (data.get("errors") or [])[:10]]
    for limitation in lims:
        d.bullet(limitation)
        m.b(limitation)

    sec += 1
    d.heading(f"{sec}. Examiner sign-off")
    d.para(f"I, {case['examiner']}, confirm that this examination was performed as described above using "
           "read-only methods, and that the attached report and evidence are a true record of the results.")
    d.table(["", "Name", "Signature", "Date"], [["Examiner", case["examiner"], "", ""], ["Reviewer", "", "", ""]],
            widths=[1500, 3000, 3138, 2000], size=18)
    m.h(f"{sec}. Examiner sign-off", 2)
    m.p(f"Examiner: {case['examiner']}  -  Signature: ________  Date: ________")
    _ = timeline
    return d.to_bytes(), "\n".join(m.lines).strip() + "\n"
