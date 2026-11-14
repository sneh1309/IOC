"""YARA scanning of triaged files and running executables (read-only).

Uses the `yara-python` module when installed, otherwise the `yara` CLI if on PATH.
Bundled rules live in aletheia/data/yara; add community rule sets (e.g. Neo23x0
signature-base, YARA-Forge) with --yara <dir>.
"""

from __future__ import annotations

import glob
import os

from aletheia.core.util import truncate

BUNDLED = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "yara")


def rule_files(sources: list) -> list:
    files = []
    for src in [BUNDLED] + list(sources):
        if os.path.isdir(src):
            for ext in ("*.yar", "*.yara"):
                files += glob.glob(os.path.join(src, "**", ext), recursive=True)
        elif os.path.isfile(src):
            files.append(src)
    return sorted(set(files))


def scan(ctx) -> list:
    files = rule_files(ctx.yara_sources)
    targets = [f["path"] for f in ctx.artifacts.get("filesystem", []) if f.get("type") == "file"
               and (f.get("size") or 0) <= ctx.limits["max_hash_size"]]
    targets += [p["exe"] for p in ctx.artifacts.get("processes", []) if p.get("exe") and not p.get("exe_deleted")]
    targets = sorted(set(targets))
    matches: list = []
    status = {"engine": None, "rule_files": len(files), "targets": len(targets), "errors": 0}
    try:
        import yara  # type: ignore

        status["engine"] = f"yara-python {getattr(yara, '__version__', '')}"
        compiled = []
        for f in files:
            try:
                compiled.append((f, yara.compile(filepath=f)))
            except Exception as exc:
                ctx.error(f"yara compile {f}", exc)
        for path in targets:
            for f, rules in compiled:
                try:
                    for m in rules.match(path, timeout=30):
                        matches.append({"path": path, "rule": m.rule, "rule_file": os.path.basename(f),
                                        "tags": list(m.tags), "meta": dict(m.meta)})
                except Exception:
                    status["errors"] += 1
    except ImportError:
        if ctx.runner.available("yara") and files:
            status["engine"] = "yara CLI"
            # write the target list into the case dir so the run is reproducible
            listing = ctx.store.save_text("yara_targets", "\n".join(targets), subdir="evidence")
            list_path = os.path.join(ctx.case_dir, listing["path"])
            for f in files:
                res = ctx.runner.run(["yara", "-w", "-m", "--scan-list", f, list_path], label="yara_" +
                                     os.path.basename(f), timeout=1800, ok_codes=(0, 1))
                for line in res.get("stdout", "").splitlines():
                    parts = line.split(" ")
                    if len(parts) >= 2:
                        matches.append({"path": parts[-1], "rule": parts[0], "rule_file": os.path.basename(f),
                                        "meta_raw": truncate(" ".join(parts[1:-1]), 300)})
        else:
            status["engine"] = "unavailable (pip install yara-python, or install the yara CLI)"
    ctx.add_artifact("yara", {"status": status, "matches": matches}, "YARA signature matches")
    return matches


def findings_from(ctx, matches: list) -> list:
    from aletheia.detection.rules import finding

    fs = {f["path"]: f for f in ctx.artifacts.get("filesystem", []) if f.get("type") == "file"}
    out = []
    for m in matches:
        meta = m.get("meta", {})
        sev = str(meta.get("severity", "high")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "high"
        f = fs.get(m["path"], {})
        out.append(finding("YARA-001", f"YARA rule {m['rule']} matched {m['path']}", sev,
                           meta.get("mitre", "T1204"),
                           meta.get("description", "File content matched a YARA signature."),
                           [{"artifact": "yara", "ref": m["path"], "rule": m["rule"], "rule_file": m.get("rule_file"),
                             "sha256": f.get("sha256")}],
                           "Validate the match (YARA rules can false-positive) then quarantine.",
                           [{"type": "quarantine_file", "path": m["path"], "sha256": f.get("sha256")}],
                           confidence="medium", category="yara", when=f.get("mtime")))
    return out
