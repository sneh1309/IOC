"""Autostart / persistence locations (MITRE ATT&CK TA0003).

Every entry is normalised to::

    {mechanism, attack, location, name, command, user, mtime, line, raw, remediation_hint}

`remediation_hint` tells the remediation planner HOW this entry could be disabled,
but nothing here changes anything.
"""

from __future__ import annotations

import glob
import os
import plistlib
import re

from aletheia.core.util import IS_LINUX, IS_MACOS, IS_WINDOWS, home_dirs, open_readonly, read_text, safe_stat


def collect(ctx) -> None:
    entries: list = []
    try:
        if IS_WINDOWS:
            entries += _windows(ctx)
        else:
            entries += _cron()
            entries += _shell_profiles()
            if IS_LINUX:
                entries += _systemd()
                entries += _linux_misc()
            if IS_MACOS:
                entries += _launchd()
    except Exception as exc:  # never let one mechanism abort collection
        ctx.error("persistence", exc)
    ctx.add_artifact("persistence", entries, f"{len(entries)} autostart / persistence entries")


def _entry(mechanism, attack, location, name, command, **kw):
    st = safe_stat(location) if location and os.path.exists(location) else None
    e = {
        "mechanism": mechanism, "attack": attack, "location": location, "name": name,
        "command": command or "", "mtime": st.get("mtime") if st else None,
    }
    e.update(kw)
    return e


# --------------------------------------------------------------------- POSIX
def _cron() -> list:
    out = []
    files = ["/etc/crontab"] + glob.glob("/etc/cron.d/*")
    files += glob.glob("/var/spool/cron/*") + glob.glob("/var/spool/cron/crontabs/*")
    files += glob.glob("/var/spool/cron/tabs/*") + glob.glob("/usr/lib/cron/tabs/*")
    for f in files:
        text = read_text(f)
        if text is None or os.path.isdir(f):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#") or "=" in s.split()[0]:
                continue
            out.append(_entry("cron", "T1053.003", f, f"{os.path.basename(f)}:{i}", s, line=i, raw=line,
                              remediation_hint={"type": "comment_out_line", "file": f, "line": i, "content": line}))
    for d in ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
        for f in glob.glob(d + "/*"):
            out.append(_entry("cron-script", "T1053.003", f, os.path.basename(f), (read_text(f) or "")[:2000],
                              remediation_hint={"type": "quarantine_file", "path": f}))
    for f in glob.glob("/var/spool/cron/atjobs/*") + glob.glob("/var/spool/at/*"):
        if os.path.isfile(f):
            out.append(_entry("at-job", "T1053.002", f, os.path.basename(f), (read_text(f) or "")[-2000:],
                              remediation_hint={"type": "quarantine_file", "path": f}))
    return out


PROFILE_FILES = (".bashrc", ".bash_profile", ".profile", ".bash_login", ".bash_logout", ".zshrc", ".zprofile",
                 ".zshenv", ".zlogin", ".config/fish/config.fish")


def _shell_profiles() -> list:
    out = []
    files = ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zshrc", "/etc/zprofile", "/etc/environment"]
    files += glob.glob("/etc/profile.d/*")
    for h in home_dirs():
        files += [os.path.join(h, p) for p in PROFILE_FILES]
    for f in files:
        text = read_text(f)
        if not text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(_entry("shell-profile", "T1546.004", f, f"{f}:{i}", s, line=i, raw=line,
                              remediation_hint={"type": "comment_out_line", "file": f, "line": i, "content": line}))
    return out


def _systemd() -> list:
    out = []
    dirs = ["/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/lib/systemd/system",
            "/usr/lib/systemd/system", "/etc/systemd/user"]
    dirs += [os.path.join(h, ".config/systemd/user") for h in home_dirs()]
    seen = set()
    for d in dirs:
        for f in glob.glob(d + "/*.service") + glob.glob(d + "/*.timer") + glob.glob(d + "/*/*.service"):
            real = os.path.realpath(f)
            if real in seen:
                continue
            seen.add(real)
            text = read_text(real) or ""
            execs = [l.split("=", 1)[1].strip() for l in text.splitlines()
                     if l.strip().startswith(("ExecStart=", "ExecStartPre=", "ExecStartPost=", "ExecStop="))]
            vendor = real.startswith(("/lib/systemd", "/usr/lib/systemd"))
            out.append(_entry("systemd", "T1543.002", real, os.path.basename(f), " ; ".join(execs),
                              vendor_dir=vendor, enabled_link=f if f != real else None,
                              remediation_hint={"type": "disable_systemd_unit", "unit": os.path.basename(f),
                                                "path": real, "user_unit": "/.config/systemd/user" in real}))
    return out


def _linux_misc() -> list:
    out = []
    pre = read_text("/etc/ld.so.preload")
    if pre is not None:
        for i, line in enumerate(pre.splitlines(), 1):
            if line.strip() and not line.strip().startswith("#"):
                out.append(_entry("ld.so.preload", "T1574.006", "/etc/ld.so.preload", line.strip(), line.strip(),
                                  line=i, raw=line,
                                  remediation_hint={"type": "comment_out_line", "file": "/etc/ld.so.preload",
                                                    "line": i, "content": line}))
    rc = read_text("/etc/rc.local")
    if rc:
        for i, line in enumerate(rc.splitlines(), 1):
            s = line.strip()
            if s and not s.startswith("#") and s not in ("exit 0",):
                out.append(_entry("rc.local", "T1037.004", "/etc/rc.local", f"rc.local:{i}", s, line=i, raw=line,
                                  remediation_hint={"type": "comment_out_line", "file": "/etc/rc.local", "line": i,
                                                    "content": line}))
    for f in glob.glob("/etc/init.d/*"):
        out.append(_entry("sysv-init", "T1037", f, os.path.basename(f), "", vendor_dir=True))
    for f in glob.glob("/etc/xdg/autostart/*.desktop") + [
            p for h in home_dirs() for p in glob.glob(os.path.join(h, ".config/autostart/*.desktop"))]:
        text = read_text(f) or ""
        cmd = next((l.split("=", 1)[1] for l in text.splitlines() if l.startswith("Exec=")), "")
        out.append(_entry("xdg-autostart", "T1547.013", f, os.path.basename(f), cmd,
                          remediation_hint={"type": "quarantine_file", "path": f}))
    for f in glob.glob("/etc/udev/rules.d/*.rules"):
        text = read_text(f) or ""
        runs = [l.strip() for l in text.splitlines() if "RUN" in l and not l.strip().startswith("#")]
        if runs:
            out.append(_entry("udev-rule", "T1546", f, os.path.basename(f), " ; ".join(runs),
                              remediation_hint={"type": "quarantine_file", "path": f}))
    for f in glob.glob("/etc/update-motd.d/*"):
        out.append(_entry("motd", "T1546", f, os.path.basename(f), (read_text(f) or "")[:1500], vendor_dir=True))
    mods = read_text("/proc/modules") or ""
    for line in mods.splitlines():
        parts = line.split()
        if parts:
            out.append({"mechanism": "kernel-module", "attack": "T1547.006", "location": "/proc/modules",
                        "name": parts[0], "command": line, "mtime": None,
                        "taint": parts[-1] if parts[-1].startswith("(") else ""})
    for f in glob.glob("/etc/pam.d/*"):
        text = read_text(f) or ""
        for i, line in enumerate(text.splitlines(), 1):
            if "pam_exec" in line and not line.strip().startswith("#"):
                out.append(_entry("pam_exec", "T1556.003", f, f"{os.path.basename(f)}:{i}", line.strip(), line=i,
                                  raw=line))
    return out


def _launchd() -> list:
    out = []
    dirs = ["/Library/LaunchAgents", "/Library/LaunchDaemons", "/System/Library/LaunchAgents",
            "/System/Library/LaunchDaemons"]
    dirs += [os.path.join(h, "Library/LaunchAgents") for h in home_dirs()]
    for d in dirs:
        for f in glob.glob(d + "/*.plist"):
            cmd = ""
            label = os.path.basename(f)
            try:
                with open_readonly(f) as fh:
                    pl = plistlib.load(fh)
                label = pl.get("Label", label)
                prog = pl.get("Program") or ""
                args = pl.get("ProgramArguments") or []
                cmd = " ".join([prog] + [str(a) for a in args]).strip()
            except Exception:
                pass
            out.append(_entry("launchd", "T1543.004" if "Daemons" in d else "T1543.001", f, label, cmd,
                              vendor_dir=f.startswith("/System/"),
                              remediation_hint={"type": "disable_launchd", "path": f, "label": label}))
    return out


# ------------------------------------------------------------------- Windows
RUN_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
]
SINGLE_VALUES = [
    (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", "T1547.004"),
    (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "T1547.004"),
    (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", "T1546.010"),
    (r"HKLM\System\CurrentControlSet\Control\Session Manager", "BootExecute", "T1547.001"),
    (r"HKLM\System\CurrentControlSet\Control\Lsa", "Security Packages", "T1547.005"),
    (r"HKLM\System\CurrentControlSet\Control\Lsa", "Authentication Packages", "T1547.002"),
]


def _reg_values(ctx, key: str) -> list:
    res = ctx.runner.run(["reg", "query", key], label="reg_" + key.split("\\")[-1], ok_codes=(0, 1))
    vals = []
    for line in res.get("stdout", "").splitlines():
        m = _REG_LINE.match(line)
        if m:
            name, typ, data = m.group(1), m.group(2), (m.group(3) or "").strip()
            if name == "(Default)" and not data:
                continue
            vals.append((name, typ, data))
    return vals


# "    <name>    REG_<TYPE>    <data>"  (value names may contain single spaces)
_REG_LINE = re.compile(r"^ {4}(.+?) {4}(REG_[A-Z_]+)(?: {4}(.*))?$")


def _windows(ctx) -> list:
    out = []
    for key in RUN_KEYS:
        for name, _typ, data in _reg_values(ctx, key):
            out.append({"mechanism": "registry-run", "attack": "T1547.001", "location": key, "name": name,
                        "command": data, "mtime": None,
                        "remediation_hint": {"type": "delete_registry_value", "key": key, "value": name}})
    for key, value, attack in SINGLE_VALUES:
        for name, _typ, data in _reg_values(ctx, key):
            if name.lower() == value.lower():
                out.append({"mechanism": "registry-" + value.lower().replace(" ", "_"), "attack": attack,
                            "location": key, "name": name, "command": data, "mtime": None})
    ifeo = ctx.runner.run(["reg", "query",
                           r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                           "/s", "/v", "Debugger"], label="ifeo_debugger", ok_codes=(0, 1))
    current = None
    for line in ifeo.get("stdout", "").splitlines():
        if line.startswith("HKEY_"):
            current = line.strip()
        elif "Debugger" in line and "REG_" in line and current:
            m = _REG_LINE.match(line)
            data = (m.group(3) or "") if m else line.strip().split(None, 2)[-1]
            out.append({"mechanism": "ifeo-debugger", "attack": "T1546.012", "location": current, "name": "Debugger",
                        "command": data, "mtime": None,
                        "remediation_hint": {"type": "delete_registry_value", "key": current, "value": "Debugger"}})
    tasks = ctx.runner.run(["schtasks", "/query", "/fo", "CSV", "/v"], label="scheduled_tasks", timeout=300)
    import csv
    import io

    seen = set()
    rows = list(csv.reader(io.StringIO(tasks.get("stdout", ""))))
    header = None
    for row in rows:
        if row and row[0] == "HostName":
            header = row
            continue
        if not header or len(row) != len(header):
            continue
        r = dict(zip(header, row))
        tn = r.get("TaskName", "")
        if tn in seen:
            continue
        seen.add(tn)
        out.append({"mechanism": "scheduled-task", "attack": "T1053.005", "location": "Task Scheduler", "name": tn,
                    "command": r.get("Task To Run", ""), "user": r.get("Run As User", ""),
                    "author": r.get("Author", ""), "status": r.get("Scheduled Task State", r.get("Status", "")),
                    "mtime": None, "vendor_dir": tn.startswith("\\Microsoft\\"),
                    "remediation_hint": {"type": "disable_scheduled_task", "task": tn}})
    services = ctx.runner.powershell_json(
        "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,State,StartName",
        label="services")
    for s in services:
        out.append({"mechanism": "service", "attack": "T1543.003", "location": "Service Control Manager",
                    "name": s.get("Name"), "command": s.get("PathName") or "", "user": s.get("StartName"),
                    "start_mode": s.get("StartMode"), "state": s.get("State"), "mtime": None,
                    "remediation_hint": {"type": "disable_service", "service": s.get("Name")}})
    startup_dirs = [os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                                 r"Microsoft\Windows\Start Menu\Programs\StartUp")]
    startup_dirs += [os.path.join(h, r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
                     for h in home_dirs()]
    for d in startup_dirs:
        for f in glob.glob(os.path.join(d, "*")):
            if os.path.basename(f).lower() == "desktop.ini":
                continue
            out.append(_entry("startup-folder", "T1547.001", f, os.path.basename(f), f,
                              remediation_hint={"type": "quarantine_file", "path": f}))
    for cls in ("__EventFilter", "CommandLineEventConsumer", "ActiveScriptEventConsumer", "__FilterToConsumerBinding"):
        rows = ctx.runner.powershell_json(
            f"Get-CimInstance -Namespace root/subscription -ClassName {cls} -ErrorAction SilentlyContinue | "
            "Select-Object Name,Query,CommandLineTemplate,ScriptText,Filter,Consumer",
            label=f"wmi_{cls}")
        for r in rows:
            cmd = r.get("CommandLineTemplate") or r.get("ScriptText") or r.get("Query") or ""
            out.append({"mechanism": "wmi-subscription", "attack": "T1546.003", "location": f"root/subscription:{cls}",
                        "name": r.get("Name") or str(r.get("Filter")), "command": str(cmd), "mtime": None})
    return out
