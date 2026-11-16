"""File-system triage: metadata + hashes of files in high-risk locations.

Only regular files are opened (FIFOs, sockets and devices are never read, which could
block or alter state). Symlinks are recorded but never followed. Reads use O_NOATIME.
"""

from __future__ import annotations

import os
import stat

from aletheia.core.util import (IS_LINUX, IS_WINDOWS, file_kind, hash_file, home_dirs, safe_stat)


def default_targets(profile: str) -> list:
    t = []
    homes = home_dirs()
    if IS_WINDOWS:
        sysdrive = os.environ.get("SystemDrive", "C:") + "\\"
        windir = os.environ.get("WINDIR", r"C:\Windows")
        t += [os.path.join(windir, "Temp"), os.path.join(sysdrive, "Users", "Public"),
              os.environ.get("ProgramData", r"C:\ProgramData"), os.path.join(sysdrive, "PerfLogs"),
              os.path.join(sysdrive, "Recovery") if profile == "deep" else ""]
        for h in homes:
            t += [os.path.join(h, r"AppData\Local\Temp"), os.path.join(h, r"AppData\Roaming"),
                  os.path.join(h, "Downloads"), os.path.join(h, "Desktop"), os.path.join(h, r"AppData\Local\Microsoft\Windows\INetCache") if profile == "deep" else ""]
        if profile == "deep":
            t += [os.path.join(windir, "System32", "Tasks"), os.path.join(windir, "System32", "drivers"),
                  os.path.join(sysdrive, "Program Files"), os.path.join(sysdrive, "Program Files (x86)")]
    else:
        t += ["/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv", "/usr/local/bin", "/usr/local/sbin", "/root",
              "/etc/cron.d", "/etc/init.d", "/var/spool/cron", "/private/tmp", "/Users/Shared"]
        for h in homes:
            if profile == "deep":
                t.append(h)
            else:
                t += [os.path.join(h, d) for d in ("Downloads", "Desktop", ".local/bin", ".config/autostart",
                                                   ".ssh", "bin", "Library/LaunchAgents",
                                                   "Library/Application Support")]
        if profile == "deep":
            t += ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/opt", "/boot", "/lib/modules", "/etc"]
    return [p for p in dict.fromkeys(t) if p and os.path.isdir(p)]


TEMP_MARKERS = ("/tmp", "/var/tmp", "/dev/shm", "\\temp", "\\appdata\\local\\temp", "\\users\\public",
                "/private/tmp", "\\perflogs", "\\windows\\temp", "\\downloads", "/downloads")


def collect(ctx) -> None:
    lim = ctx.limits
    extra = [p for p in ctx.extra_paths if os.path.exists(p)]
    targets = extra if ctx.options.get("offline") else default_targets(ctx.profile) + extra
    files, truncated = [], False
    for root in targets:
        if len(files) >= lim["max_files"]:
            truncated = True
            break
        for rec in _walk(ctx, root, lim):
            files.append(rec)
            if len(files) >= lim["max_files"]:
                truncated = True
                break
    ctx.add_artifact("filesystem", files, f"{len(files)} files triaged in {len(targets)} locations")
    meta = {"targets": targets, "truncated": truncated, "limits": lim, "files": len(files)}
    if IS_LINUX and ctx.profile != "quick":
        meta["suid_sgid"] = _suid_scan(ctx)
    ctx.add_artifact("filesystem_scope", meta, "Scope and limits of the file-system triage")


def _walk(ctx, root: str, lim: dict):
    root_depth = root.rstrip("\\/").count(os.sep)
    stack = [root]
    while stack:
        d = stack.pop()
        if ctx.is_inside_case_dir(d):
            continue  # never analyse our own output
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError as exc:
            ctx.error(f"scandir {d}", exc)
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                if e.path.count(os.sep) - root_depth < lim["max_depth"] and e.name not in (
                        "node_modules", ".git", "__pycache__", "proc", "sys"):
                    stack.append(e.path)
                continue
            if stat.S_ISLNK(st.st_mode):
                try:
                    target = os.readlink(e.path)
                except OSError:
                    target = None
                yield {"path": e.path, "type": "symlink", "target": target}
                continue
            if not stat.S_ISREG(st.st_mode):
                continue  # never open FIFOs/sockets/devices
            rec = {"path": e.path, "type": "file", "name": e.name}
            rec.update(safe_stat(e.path) or {})
            rec["hidden"] = e.name.startswith(".") or _win_hidden(st)
            low = e.path.lower()
            rec["in_temp_location"] = any(m in low for m in TEMP_MARKERS)
            rec["kind"] = file_kind(e.path)
            if st.st_size <= lim["max_hash_size"]:
                try:
                    rec.update(hash_file(e.path, max_bytes=lim["max_hash_size"]))
                except OSError as exc:
                    rec["hash_error"] = str(exc)
            else:
                rec["hash_error"] = "exceeds profile max_hash_size"
            yield rec


def _win_hidden(st) -> bool:
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & 0x2) if attrs else False


SUID_ROOTS = ("/usr", "/bin", "/sbin", "/opt", "/tmp", "/var", "/home", "/dev/shm", "/root", "/srv", "/etc")


def _suid_scan(ctx) -> list:
    out = []
    for root in SUID_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if ctx.is_inside_case_dir(dirpath):
                dirnames[:] = []
                continue
            for f in filenames:
                p = os.path.join(dirpath, f)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    rec = {"path": p, "mode": stat.filemode(st.st_mode), "uid": st.st_uid,
                           "suid": bool(st.st_mode & stat.S_ISUID)}
                    rec.update({k: v for k, v in (safe_stat(p) or {}).items() if k in ("mtime", "ctime", "size")})
                    out.append(rec)
    return out
