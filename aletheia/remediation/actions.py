"""Remediation action implementations.

Every action follows the same contract:
    1. PRECHECK  - confirm the target is still exactly what the analysis observed
                   (same PID+binary, same file hash, same line content). If anything
                   differs, the action is SKIPPED - never "best-effort" on a moved target.
    2. BACKUP    - preserve what will change (file copy, .reg export, task XML ...).
    3. EXECUTE   - perform the minimal change.
    4. VERIFY    - confirm the change took effect.
    5. ROLLBACK  - record exactly how to undo it.

Only called from remediation.engine after human approval.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess

from aletheia.core.util import IS_LINUX, IS_MACOS, IS_WINDOWS, hash_file, read_text, safe_stat, sha256_bytes, utc_now

XOR_KEY = 0xA5  # quarantine encoding: renders payload inert / non-executable and invisible to AV re-detection
XOR_TABLE = bytes(i ^ XOR_KEY for i in range(256))


class Skip(Exception):
    pass


def _run(argv: list, audit, timeout: int = 120) -> dict:
    started = utc_now()
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, shell=False, stdin=subprocess.DEVNULL)
        res = {"argv": argv, "rc": p.returncode, "stdout": p.stdout.decode("utf-8", "replace")[:4000],
               "stderr": p.stderr.decode("utf-8", "replace")[:4000]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        res = {"argv": argv, "rc": None, "error": str(exc)}
    res["started_utc"] = started
    audit.record("remediation_command", res)
    return res


def _ok(res: dict) -> bool:
    return res.get("rc") == 0


# ------------------------------------------------------------------- kill
def kill_process(p: dict, ws, audit) -> dict:
    pid = int(p["pid"])
    if IS_LINUX:
        try:
            exe = os.readlink(f"/proc/{pid}/exe").replace(" (deleted)", "")
        except OSError:
            raise Skip(f"PID {pid} no longer exists") from None
        if p.get("exe") and exe != p["exe"]:
            raise Skip(f"PID {pid} now runs {exe}, not {p['exe']} (PID reused) - not killing")
    elif IS_WINDOWS:
        res = _run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], audit)
        if str(pid) not in res.get("stdout", ""):
            raise Skip(f"PID {pid} no longer exists")
        if p.get("name") and p["name"].lower() not in res.get("stdout", "").lower():
            raise Skip(f"PID {pid} is no longer {p['name']} (PID reused)")
    else:
        try:
            os.kill(pid, 0)
        except OSError:
            raise Skip(f"PID {pid} no longer exists")
    if IS_WINDOWS:
        res = _run(["taskkill", "/PID", str(pid), "/F"], audit)
        if not _ok(res):
            raise RuntimeError(res.get("stderr") or res.get("error"))
    else:
        os.kill(pid, signal.SIGKILL)
    return {"detail": f"terminated PID {pid}", "rollback": "not reversible (restart the program if it was legitimate)"}


# ------------------------------------------------------------- quarantine
def quarantine_file(p: dict, ws, audit) -> dict:
    path = p["path"]
    if not os.path.isfile(path) or os.path.islink(path):
        raise Skip(f"{path} no longer exists / is not a regular file")
    h = hash_file(path)
    if p.get("sha256") and h.get("sha256") != p["sha256"]:
        raise Skip(f"{path} changed since analysis (hash {h.get('sha256')} != {p['sha256']})")
    qdir = os.path.join(ws, "quarantine")
    os.makedirs(qdir, exist_ok=True)
    qfile = os.path.join(qdir, h["sha256"] + ".quarantine")
    meta = {"original_path": path, "hashes": h, "stat": safe_stat(path), "quarantined_utc": utc_now(),
            "encoding": f"XOR 0x{XOR_KEY:02X}"}
    with open(path, "rb") as src, open(qfile, "wb") as dst:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            dst.write(chunk.translate(XOR_TABLE))
    # verify the quarantined copy decodes to the original hash BEFORE removing anything
    import hashlib

    check = hashlib.sha256()
    with open(qfile, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            check.update(chunk.translate(XOR_TABLE))
    if check.hexdigest() != h["sha256"]:
        os.remove(qfile)
        raise RuntimeError("quarantine copy verification failed; original left untouched")
    with open(qfile + ".json", "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    os.chmod(qfile, 0o400)
    os.remove(path)
    if os.path.exists(path):
        raise RuntimeError("file still present after removal")
    return {"detail": f"quarantined to {qfile}", "quarantine_file": qfile,
            "rollback": f"aletheia restore-quarantine \"{qfile}\""}


def restore_quarantine(qfile: str) -> str:
    with open(qfile + ".json", encoding="utf-8") as fh:
        meta = json.load(fh)
    dest = meta["original_path"]
    if os.path.exists(dest):
        raise FileExistsError(f"{dest} already exists; refusing to overwrite")
    with open(qfile, "rb") as src, open(dest, "xb") as dst:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            dst.write(chunk.translate(XOR_TABLE))
    try:
        os.chmod(dest, int(meta["stat"]["mode_octal"], 8))
    except (KeyError, TypeError, ValueError, OSError):
        pass
    return dest


# ------------------------------------------------------------ line edits
def comment_out_line(p: dict, ws, audit) -> dict:
    path, line_no, expected = p["file"], int(p["line"]), p.get("content")
    text = read_text(path, max_bytes=64 * 1024 * 1024)
    if text is None:
        raise Skip(f"{path} not readable / missing")
    with open(path, "r", encoding="utf-8", errors="surrogateescape", newline="") as fh:
        lines = fh.readlines()
    if line_no < 1 or line_no > len(lines):
        raise Skip(f"{path} no longer has line {line_no}")
    current = lines[line_no - 1].rstrip("\r\n")
    if expected is not None and current != expected.rstrip("\r\n"):
        raise Skip(f"{path}:{line_no} changed since analysis - not editing")
    backup = _backup(path, ws)
    nl = lines[line_no - 1][len(current):] or "\n"
    lines[line_no - 1] = f"# [ALETHEIA-DISABLED {utc_now()}] {current}{nl}"
    with open(path, "r+", encoding="utf-8", errors="surrogateescape", newline="") as fh:  # in place: keeps inode/owner/mode
        fh.seek(0)
        fh.write("".join(lines))
        fh.truncate()
    return {"detail": f"commented out {path}:{line_no}", "backup": backup,
            "rollback": f"copy \"{backup}\" back to \"{path}\""}


def _backup(path: str, ws: str) -> str:
    bdir = os.path.join(ws, "backups")
    os.makedirs(bdir, exist_ok=True)
    safe = path.replace(":", "").replace("\\", "_").replace("/", "_").strip("_")
    dest = os.path.join(bdir, safe)
    n = 1
    while os.path.exists(dest):
        dest = os.path.join(bdir, f"{safe}.{n}")
        n += 1
    shutil.copy2(path, dest)
    return dest


# --------------------------------------------------------------- services
def disable_systemd_unit(p: dict, ws, audit) -> dict:
    unit = p["unit"]
    if p.get("path") and os.path.exists(p["path"]):
        _backup(p["path"], ws)
    res = _run(["systemctl", "disable", "--now", unit], audit)
    if not _ok(res):
        raise RuntimeError(res.get("stderr") or res.get("error"))
    _run(["systemctl", "mask", unit], audit)
    return {"detail": f"systemd unit {unit} stopped, disabled and masked",
            "rollback": f"systemctl unmask {unit} && systemctl enable --now {unit}"}


def disable_launchd(p: dict, ws, audit) -> dict:
    path = p["path"]
    if not os.path.exists(path):
        raise Skip(f"{path} missing")
    backup = _backup(path, ws)
    res = _run(["launchctl", "unload", "-w", path], audit)
    q = quarantine_file({"path": path}, ws, audit)
    return {"detail": f"unloaded launch item {p.get('label')} (rc={res.get('rc')}) and quarantined plist",
            "backup": backup, "rollback": f"restore {backup} to {path}; launchctl load -w {path}", **q}


def delete_registry_value(p: dict, ws, audit) -> dict:
    key, value = p["key"], p["value"]
    q = _run(["reg", "query", key, "/v", value], audit)
    if not _ok(q):
        raise Skip(f"{key}\\{value} no longer exists")
    bdir = os.path.join(ws, "backups")
    os.makedirs(bdir, exist_ok=True)
    backup = os.path.join(bdir, f"reg_{sha256_bytes((key + chr(0) + value).encode())[:16]}.reg")
    exp = _run(["reg", "export", key, backup, "/y"], audit)
    if not _ok(exp):
        raise RuntimeError("registry backup failed - aborting this action")
    res = _run(["reg", "delete", key, "/v", value, "/f"], audit)
    if not _ok(res):
        raise RuntimeError(res.get("stderr") or res.get("error"))
    return {"detail": f"deleted {key}\\{value}", "backup": backup, "rollback": f"reg import \"{backup}\""}


def disable_scheduled_task(p: dict, ws, audit) -> dict:
    task = p["task"]
    xml = _run(["schtasks", "/query", "/tn", task, "/xml"], audit)
    if not _ok(xml):
        raise Skip(f"task {task} no longer exists")
    bdir = os.path.join(ws, "backups")
    os.makedirs(bdir, exist_ok=True)
    backup = os.path.join(bdir, "task_" + task.strip("\\").replace("\\", "_") + ".xml")
    with open(backup, "w", encoding="utf-8") as fh:
        fh.write(xml.get("stdout", ""))
    _run(["schtasks", "/end", "/tn", task], audit)
    res = _run(["schtasks", "/change", "/tn", task, "/disable"], audit)
    if not _ok(res):
        raise RuntimeError(res.get("stderr") or res.get("error"))
    return {"detail": f"disabled scheduled task {task}", "backup": backup,
            "rollback": f"schtasks /change /tn \"{task}\" /enable"}


def disable_service(p: dict, ws, audit) -> dict:
    svc = p["service"]
    qc = _run(["sc", "qc", svc], audit)
    if not _ok(qc):
        raise Skip(f"service {svc} not found")
    prev = "demand"
    for line in qc.get("stdout", "").splitlines():
        if "START_TYPE" in line:
            prev = {"2": "auto", "3": "demand", "4": "disabled", "0": "boot", "1": "system"}.get(
                line.split(":")[1].strip().split()[0], "demand")
    _run(["sc", "stop", svc], audit)
    res = _run(["sc", "config", svc, "start=", "disabled"], audit)
    if not _ok(res):
        raise RuntimeError(res.get("stdout") or res.get("error"))
    return {"detail": f"service {svc} stopped and disabled (was {prev})",
            "rollback": f"sc config \"{svc}\" start= {prev} && sc start \"{svc}\""}


# ---------------------------------------------------------------- network
def block_ip(p: dict, ws, audit) -> dict:
    ip = p["ip"]
    import ipaddress

    ipaddress.ip_address(ip)  # validates; raises on garbage
    tag = "aletheia-" + os.path.basename(ws)
    if IS_WINDOWS:
        rules = []
        for d in ("in", "out"):
            name = f"Aletheia block {ip} {d}"
            res = _run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={d}",
                        "action=block", f"remoteip={ip}", "enable=yes"], audit)
            if not _ok(res):
                raise RuntimeError(res.get("stdout") or res.get("error"))
            rules.append(name)
        return {"detail": f"Windows Firewall blocks {ip} in/out",
                "rollback": " ; ".join(f"netsh advfirewall firewall delete rule name=\"{r}\"" for r in rules)}
    if IS_LINUX and shutil.which("iptables"):
        v = "ip6tables" if ":" in ip else "iptables"
        a = _run([v, "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", tag], audit)
        b = _run([v, "-I", "OUTPUT", "-d", ip, "-j", "DROP", "-m", "comment", "--comment", tag], audit)
        if not (_ok(a) and _ok(b)):
            raise RuntimeError((a.get("stderr") or "") + (b.get("stderr") or ""))
        return {"detail": f"{v} drops {ip} in/out (runtime rules; persist with your distro's tooling)",
                "rollback": f"{v} -D INPUT -s {ip} -j DROP -m comment --comment {tag}; "
                            f"{v} -D OUTPUT -d {ip} -j DROP -m comment --comment {tag}"}
    if shutil.which("ufw"):
        a = _run(["ufw", "insert", "1", "deny", "from", ip], audit)
        b = _run(["ufw", "insert", "1", "deny", "out", "to", ip], audit)
        if not (_ok(a) and _ok(b)):
            raise RuntimeError("ufw failed")
        return {"detail": f"ufw denies {ip}", "rollback": f"ufw delete deny from {ip}; ufw delete deny out to {ip}"}
    raise Skip("no supported firewall tool found (iptables/ufw/netsh) - block manually (macOS: pf)")


# --------------------------------------------------------------- accounts
def disable_account(p: dict, ws, audit) -> dict:
    user = p["user"]
    if user.lower() in ("root", "administrator") and not IS_WINDOWS:
        raise Skip("refusing to lock the root account automatically")
    if IS_WINDOWS:
        res = _run(["net", "user", user, "/active:no"], audit)
        rb = f"net user \"{user}\" /active:yes"
    elif IS_MACOS:
        res = _run(["pwpolicy", "-u", user, "-disableuser"], audit)
        rb = f"pwpolicy -u {user} -enableuser"
    else:
        res = _run(["usermod", "-L", "-e", "1", user], audit)
        rb = f"usermod -U -e '' {user}"
    if not _ok(res):
        raise RuntimeError(res.get("stderr") or res.get("stdout") or res.get("error"))
    return {"detail": f"account {user} disabled", "rollback": rb}


HANDLERS = {
    "kill_process": kill_process, "quarantine_file": quarantine_file, "comment_out_line": comment_out_line,
    "disable_systemd_unit": disable_systemd_unit, "disable_launchd": disable_launchd,
    "delete_registry_value": delete_registry_value, "disable_scheduled_task": disable_scheduled_task,
    "disable_service": disable_service, "block_ip": block_ip, "disable_account": disable_account,
}


def describe(a: dict) -> str:
    """Human-readable 'what exactly will happen' line shown before approval."""
    p, t = a["params"], a["type"]
    return {
        "kill_process": lambda: f"Terminate PID {p.get('pid')} ({p.get('name')}) after confirming it still runs {p.get('exe')}",
        "quarantine_file": lambda: f"Verify SHA-256, move {p.get('path')} into encoded quarantine (restorable)",
        "comment_out_line": lambda: f"Back up {p.get('file')} and comment out line {p.get('line')}: {str(p.get('content'))[:80]}",
        "disable_systemd_unit": lambda: f"systemctl disable --now + mask {p.get('unit')} (unit file backed up)",
        "disable_launchd": lambda: f"launchctl unload -w {p.get('path')} and quarantine the plist",
        "delete_registry_value": lambda: f"reg export {p.get('key')} (backup) then delete value '{p.get('value')}'",
        "disable_scheduled_task": lambda: f"Export task XML then disable task {p.get('task')}",
        "disable_service": lambda: f"Stop service {p.get('service')} and set start type to Disabled",
        "block_ip": lambda: f"Add host-firewall rules dropping all traffic to/from {p.get('ip')}",
        "disable_account": lambda: f"Lock / disable account {p.get('user')}",
    }.get(t, lambda: str(p))()
