"""Running processes (volatile) with executable hashes."""

from __future__ import annotations

import os
import time

from aletheia.core.util import IS_LINUX, IS_WINDOWS, hash_file, read_text, ts_to_iso


def collect(ctx) -> None:
    if IS_LINUX and os.path.isdir("/proc"):
        procs = _linux()
    elif IS_WINDOWS:
        procs = _windows(ctx)
    else:
        procs = _ps(ctx)

    # Hash each distinct executable once (read-only).
    cache: dict = {}
    max_size = ctx.limits["max_hash_size"]
    for p in procs:
        exe = p.get("exe")
        if not exe or p.get("exe_deleted"):
            continue
        if exe not in cache:
            try:
                cache[exe] = hash_file(exe, max_bytes=max_size)
            except OSError as exc:
                cache[exe] = {"error": str(exc)}
        h = cache[exe]
        p["exe_sha256"] = h.get("sha256")
        p["exe_md5"] = h.get("md5")
        p["exe_sha1"] = h.get("sha1")
    ctx.add_artifact("processes", procs, f"{len(procs)} running processes with executable hashes")


def _linux() -> list:
    out = []
    try:
        clk = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError, AttributeError):
        clk = 100
    uptime_txt = read_text("/proc/uptime") or "0"
    boot = time.time() - float(uptime_txt.split()[0])
    users = _uid_map()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        base = f"/proc/{entry}"
        p = {"pid": int(entry)}
        try:
            status = read_text(f"{base}/status") or ""
            fields = dict(l.split(":", 1) for l in status.splitlines() if ":" in l)
            p["name"] = fields.get("Name", "").strip()
            p["ppid"] = int(fields.get("PPid", "0").strip() or 0)
            uid = int(fields.get("Uid", "0").split()[0])
            p["uid"] = uid
            p["user"] = users.get(uid, str(uid))
            raw = read_text(f"{base}/cmdline") or ""
            p["cmdline"] = raw.replace("\x00", " ").strip()
            try:
                exe = os.readlink(f"{base}/exe")
                p["exe_deleted"] = exe.endswith(" (deleted)")
                p["exe"] = exe[:-10] if p["exe_deleted"] else exe
            except OSError:
                p["exe"] = None
            try:
                p["cwd"] = os.readlink(f"{base}/cwd")
            except OSError:
                p["cwd"] = None
            stat = read_text(f"{base}/stat") or ""
            rparen = stat.rfind(")")
            if rparen > 0:
                parts = stat[rparen + 2:].split()
                if len(parts) > 19:
                    p["start_time_utc"] = ts_to_iso(boot + int(parts[19]) / clk)
            env_ld = _ld_preload_env(base)
            if env_ld:
                p["env_ld_preload"] = env_ld
        except (OSError, ValueError):
            continue
        out.append(p)
    return out


def _ld_preload_env(base: str):
    raw = read_text(f"{base}/environ", max_bytes=256 * 1024)
    if not raw:
        return None
    for var in raw.split("\x00"):
        if var.startswith("LD_PRELOAD="):
            return var[len("LD_PRELOAD="):]
    return None


def _uid_map() -> dict:
    users = {}
    text = read_text("/etc/passwd") or ""
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) > 2 and parts[2].isdigit():
            users[int(parts[2])] = parts[0]
    return users


def _windows(ctx) -> list:
    rows = ctx.runner.powershell_json(
        "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,"
        "@{n='Start';e={if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}}},"
        "@{n='Owner';e={try{$o=Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop;"
        "if($o.User){$o.Domain+'\\'+$o.User}}catch{$null}}}",
        label="processes_win", timeout=300,
    )
    out = []
    for r in rows:
        out.append({
            "pid": r.get("ProcessId"),
            "ppid": r.get("ParentProcessId"),
            "name": r.get("Name"),
            "exe": r.get("ExecutablePath"),
            "cmdline": r.get("CommandLine") or "",
            "start_time_utc": r.get("Start"),
            "user": r.get("Owner"),
        })
    return out


def _ps(ctx) -> list:
    # lstart is always 5 tokens ("Sat Nov 14 15:23:09 2026"); args is last so spaces in paths are safe
    res = ctx.runner.run(["ps", "-axww", "-o", "pid=,ppid=,user=,lstart=,args="], label="ps")
    out = []
    for line in res.get("stdout", "").splitlines():
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        pid, ppid, user = parts[0], parts[1], parts[2]
        args = parts[8]
        first = args.split(" -", 1)[0].strip() if args.startswith("/") else args.split()[0]
        out.append({
            "pid": int(pid) if pid.isdigit() else pid,
            "ppid": int(ppid) if ppid.isdigit() else ppid,
            "user": user,
            "start_time_local": " ".join(parts[3:8]),
            "name": os.path.basename(first),
            "exe": first if first.startswith("/") and os.path.isfile(first) else None,
            "cmdline": args,
        })
    return out
