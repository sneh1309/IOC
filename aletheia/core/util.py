"""Low-level helpers: time, hashing, canonical JSON and strictly read-only file access."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import platform
import re
import stat
from typing import Any, Iterable, Optional

CHUNK = 1024 * 1024

OS_NAME = platform.system().lower()  # 'linux', 'windows', 'darwin'
IS_WINDOWS = OS_NAME == "windows"
IS_LINUX = OS_NAME == "linux"
IS_MACOS = OS_NAME == "darwin"


def utc_now() -> str:
    """ISO-8601 UTC timestamp with microseconds and explicit 'Z'."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ts_to_iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for every hash we compute over structured data."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def open_readonly(path: str):
    """Open a file strictly read-only.

    * O_RDONLY - the descriptor can never be used to write.
    * O_NOATIME (Linux) - avoids updating the last-access timestamp, which is itself
      evidence. Falls back silently when the kernel refuses it (non-owner, non-root).
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY  # type: ignore[attr-defined]
    noatime = getattr(os, "O_NOATIME", 0)
    if noatime:
        try:
            fd = os.open(path, flags | noatime)
            return os.fdopen(fd, "rb")
        except PermissionError:
            pass
        except OSError:
            pass
    fd = os.open(path, flags)
    return os.fdopen(fd, "rb")


def hash_file(path: str, max_bytes: Optional[int] = None) -> dict:
    """Return md5/sha1/sha256 of a file, read-only. md5/sha1 are kept only because
    many threat-intel feeds still publish them; sha256 is the evidentiary hash."""
    md5, sha1, sha256 = _new_md5(), hashlib.sha1(), hashlib.sha256()
    total = 0
    with open_readonly(path) as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            if max_bytes is not None and total > max_bytes:
                return {"skipped": "file larger than max hash size", "size_read": total}
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest(), "size": total}


def _new_md5():
    try:
        return hashlib.md5(usedforsecurity=False)  # type: ignore[call-arg]
    except TypeError:  # Python < 3.9 on some builds
        return hashlib.md5()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open_readonly(path) as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path: str, max_bytes: int = 4 * 1024 * 1024) -> Optional[str]:
    """Read a (possibly large) text file read-only; returns None if unreadable."""
    try:
        with open_readonly(path) as fh:
            data = fh.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def safe_stat(path: str, follow: bool = False) -> Optional[dict]:
    try:
        st = os.stat(path, follow_symlinks=follow)
    except (OSError, ValueError):
        return None
    return {
        "size": st.st_size,
        "mode": stat.filemode(st.st_mode),
        "mode_octal": oct(st.st_mode & 0o7777),
        "uid": getattr(st, "st_uid", None),
        "gid": getattr(st, "st_gid", None),
        "inode": getattr(st, "st_ino", None),
        "mtime": ts_to_iso(st.st_mtime),
        "atime": ts_to_iso(st.st_atime),
        "ctime": ts_to_iso(st.st_ctime),  # metadata change on POSIX, creation on Windows
        "birthtime": ts_to_iso(getattr(st, "st_birthtime", None)),
        "is_suid": bool(st.st_mode & stat.S_ISUID),
        "is_sgid": bool(st.st_mode & stat.S_ISGID),
        "is_symlink": stat.S_ISLNK(st.st_mode),
        "is_file": stat.S_ISREG(st.st_mode),
    }


EXEC_MAGIC = {
    b"\x7fELF": "ELF",
    b"MZ": "PE",
    b"\xcf\xfa\xed\xfe": "Mach-O",
    b"\xce\xfa\xed\xfe": "Mach-O",
    b"\xca\xfe\xba\xbe": "Mach-O/Java",
    b"#!": "script",
}


def file_kind(path: str) -> Optional[str]:
    try:
        with open_readonly(path) as fh:
            head = fh.read(4)
    except OSError:
        return None
    for magic, kind in EXEC_MAGIC.items():
        if head.startswith(magic):
            return kind
    return None


# --- indicator helpers -----------------------------------------------------

RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_URL = re.compile(r"\bhttps?://[^\s'\"<>|;)]+", re.I)
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.I)
RE_MD5 = re.compile(r"^[a-f0-9]{32}$", re.I)
RE_SHA1 = re.compile(r"^[a-f0-9]{40}$", re.I)
RE_SHA256 = re.compile(r"^[a-f0-9]{64}$", re.I)


def is_private_ip(ip: str) -> bool:
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def truncate(text: Any, limit: int = 400) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def uniq(seq: Iterable) -> list:
    seen, out = set(), []
    for item in seq:
        key = json.dumps(item, sort_keys=True, default=str) if isinstance(item, (dict, list)) else item
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def home_dirs() -> list:
    """All user home directories we can see (read-only enumeration)."""
    homes = set()
    if IS_WINDOWS:
        base = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users")
        try:
            for e in os.scandir(base):
                if e.is_dir(follow_symlinks=False) and e.name not in ("All Users", "Default User"):
                    homes.add(e.path)
        except OSError:
            pass
    else:
        try:
            with open_readonly("/etc/passwd") as fh:
                for line in fh.read().decode("utf-8", "replace").splitlines():
                    parts = line.split(":")
                    if len(parts) >= 6 and parts[5] and os.path.isdir(parts[5]) and parts[5] != "/":
                        homes.add(parts[5])
        except OSError:
            pass
        for base in ("/home", "/Users"):
            try:
                for e in os.scandir(base):
                    if e.is_dir(follow_symlinks=False):
                        homes.add(e.path)
            except OSError:
                pass
        homes.add(os.path.expanduser("~"))
    return sorted(h for h in homes if h)
