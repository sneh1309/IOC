"""Write-once evidence store.

Layout of a case directory::

    <output>/<CASE-ID>_<UTC-stamp>/
        case.json                 case metadata + examiner + host identity
        evidence/*.json           raw artifacts collected from the device
        evidence/commands/*.txt   verbatim stdout of every command run
        logs/audit.jsonl          hash-chained chain-of-custody log
        report/                   HTML / JSON / CSV / STIX outputs
        SHA256SUMS                manifest of every file above
        SHA256SUMS.sig            (optional) detached GPG signature

Every artifact is opened with exclusive-create ('x') so nothing is ever overwritten,
and is made read-only (0444) once written.
"""

from __future__ import annotations

import json
import os
import re
import stat
from typing import Any, Optional

from aletheia.core.util import canonical_json, sha256_bytes, sha256_file, utc_now

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(name: str) -> str:
    return _SAFE.sub("_", name).strip("_")[:120] or "artifact"


def make_readonly(path: str) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass


class EvidenceStore:
    def __init__(self, case_dir: str):
        self.case_dir = os.path.abspath(case_dir)
        self.evidence_dir = os.path.join(self.case_dir, "evidence")
        self.commands_dir = os.path.join(self.evidence_dir, "commands")
        self.logs_dir = os.path.join(self.case_dir, "logs")
        self.report_dir = os.path.join(self.case_dir, "report")
        for d in (self.evidence_dir, self.commands_dir, self.logs_dir, self.report_dir):
            os.makedirs(d, exist_ok=True)
        self.index: list = []

    # -- writing -------------------------------------------------------------
    def _write_once(self, path: str, data: bytes) -> dict:
        with open(path, "xb") as fh:  # 'x' = fail if it already exists: no overwrite, ever
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        make_readonly(path)
        rec = {
            "path": os.path.relpath(path, self.case_dir).replace(os.sep, "/"),
            "sha256": sha256_bytes(data),
            "size": len(data),
            "written_utc": utc_now(),
        }
        self.index.append(rec)
        return rec

    def save_json(self, name: str, obj: Any, subdir: Optional[str] = None) -> dict:
        target_dir = os.path.join(self.case_dir, subdir) if subdir else self.evidence_dir
        os.makedirs(target_dir, exist_ok=True)
        path = os.path.join(target_dir, safe_name(name) + ".json")
        data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        return self._write_once(path, data)

    def save_text(self, name: str, text: str, subdir: Optional[str] = None, ext: str = ".txt") -> dict:
        target_dir = os.path.join(self.case_dir, subdir) if subdir else self.evidence_dir
        os.makedirs(target_dir, exist_ok=True)
        path = os.path.join(target_dir, safe_name(name) + ext)
        n, base = 1, path
        while os.path.exists(path):
            root, e = os.path.splitext(base)
            path = f"{root}_{n}{e}"
            n += 1
        return self._write_once(path, text.encode("utf-8", errors="replace"))

    def copy_file_once(self, src: str, subdir: str, name: str, max_bytes: int = 4 * 1024 ** 3) -> dict:
        """Stream a byte-exact copy of `src` (opened read-only) into the case folder.
        Returns the index record including the SHA-256 of the bytes read from the original."""
        import hashlib

        from aletheia.core.util import open_readonly

        target_dir = os.path.join(self.case_dir, subdir)
        os.makedirs(target_dir, exist_ok=True)
        path = os.path.join(target_dir, safe_name(name))
        h, size = hashlib.sha256(), 0
        with open_readonly(src) as fin, open(path, "xb") as fout:
            for chunk in iter(lambda: fin.read(1024 * 1024), b""):
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError(f"{src} exceeds {max_bytes} bytes - not copied")
                h.update(chunk)
                fout.write(chunk)
            fout.flush()
            os.fsync(fout.fileno())
        make_readonly(path)
        rec = {"path": os.path.relpath(path, self.case_dir).replace(os.sep, "/"), "sha256": h.hexdigest(),
               "size": size, "written_utc": utc_now(), "source": src}
        self.index.append(rec)
        return rec

    def save_command_output(self, label: str, stdout: str) -> dict:
        return self.save_text(label, stdout, subdir=os.path.join("evidence", "commands"))

    # -- manifest ------------------------------------------------------------
    def build_manifest(self, exclude: tuple = ("SHA256SUMS", "SHA256SUMS.sig")) -> str:
        """Hash every file in the case directory and write SHA256SUMS (sha256sum format)."""
        lines = []
        for root, _dirs, files in os.walk(self.case_dir):
            for f in sorted(files):
                full = os.path.join(root, f)
                rel = os.path.relpath(full, self.case_dir).replace(os.sep, "/")
                if rel in exclude:
                    continue
                lines.append(f"{sha256_file(full)}  {rel}")
        lines.sort(key=lambda l: l.split("  ", 1)[1])
        manifest = "\n".join(lines) + "\n"
        path = os.path.join(self.case_dir, "SHA256SUMS")
        with open(path, "x", encoding="utf-8") as fh:
            fh.write(manifest)
        make_readonly(path)
        return sha256_bytes(manifest.encode("utf-8"))

    def lock_all(self) -> None:
        """Make every file in the case directory read-only."""
        for root, _dirs, files in os.walk(self.case_dir):
            for f in files:
                make_readonly(os.path.join(root, f))


def verify_manifest(case_dir: str) -> tuple:
    """Return (ok, problems, files_checked)."""
    path = os.path.join(case_dir, "SHA256SUMS")
    problems = []
    if not os.path.exists(path):
        return False, ["SHA256SUMS manifest is missing"], 0
    listed = set()
    count = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            digest, rel = line.split("  ", 1)
            listed.add(rel)
            full = os.path.join(case_dir, rel.replace("/", os.sep))
            count += 1
            if not os.path.exists(full):
                problems.append(f"MISSING: {rel}")
            elif sha256_file(full) != digest:
                problems.append(f"ALTERED: {rel}")
    for root, _dirs, files in os.walk(case_dir):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), case_dir).replace(os.sep, "/")
            if rel in ("SHA256SUMS", "SHA256SUMS.sig") or rel.startswith("remediation_"):
                continue
            if rel not in listed:
                problems.append(f"UNLISTED (added after sealing): {rel}")
    return not problems, problems, count


def json_digest(obj: Any) -> str:
    return sha256_bytes(canonical_json(obj))
