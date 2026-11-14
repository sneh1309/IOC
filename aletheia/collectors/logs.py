"""Authentication / security logs and shell histories (read-only parsing)."""

from __future__ import annotations

import glob
import gzip
import os
import re
import xml.etree.ElementTree as ET

from aletheia.core.util import IS_LINUX, IS_WINDOWS, home_dirs, open_readonly, read_text

RE_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
RE_ACCEPT = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
RE_INVALID = re.compile(r"Invalid user (\S+) from (\S+)")
RE_SUDO = re.compile(r"sudo:\s+(\S+) : .*COMMAND=(.*)$")
RE_USERADD = re.compile(r"(useradd|usermod|groupadd|passwd)\[\d+\]: (.*)$")

# Windows events of forensic interest -> (log, ids)
WIN_EVENTS = {
    "Security": [1102, 4624, 4625, 4648, 4672, 4697, 4698, 4699, 4702, 4719, 4720, 4722, 4724, 4728, 4732, 4738,
                 4756, 4688],
    "System": [104, 7034, 7036, 7040, 7045],
    "Microsoft-Windows-PowerShell/Operational": [4103, 4104],
    "Microsoft-Windows-Windows Defender/Operational": [1006, 1007, 1008, 1015, 1116, 1117, 1118, 5001, 5004, 5007,
                                                       5010, 5012],
    "Microsoft-Windows-TaskScheduler/Operational": [106, 140, 141, 200],
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": [1149],
    "Microsoft-Windows-Sysmon/Operational": [1, 3, 7, 8, 10, 11, 12, 13, 22],
}


def collect(ctx) -> None:
    data = {"auth_summary": {}, "auth_events": [], "history_lines": [], "windows_events": []}
    max_events = ctx.limits["log_events"]
    if IS_WINDOWS:
        data["windows_events"] = _windows(ctx, max_events)
    else:
        _auth_logs(data, max_events)
        if IS_LINUX and not data["auth_events"] and ctx.runner.available("journalctl"):
            res = ctx.runner.run(["journalctl", "--no-pager", "-q", "-o", "short-iso", "-n", str(max_events * 5),
                                  "_COMM=sshd", "+", "_COMM=sudo", "+", "_COMM=useradd"], label="journal_auth",
                                 ok_codes=(0, 1))
            _parse_auth_lines(data, res.get("stdout", "").splitlines(), "journalctl", max_events)
    _histories(data)
    ctx.add_artifact("logs", data, "Authentication events, security event logs, shell histories")


def _auth_logs(data: dict, max_events: int) -> None:
    files = []
    for base in ("/var/log/auth.log", "/var/log/secure", "/var/log/system.log"):
        files += sorted(glob.glob(base + "*"))
    for f in files:
        try:
            if f.endswith(".gz"):
                with open_readonly(f) as raw, gzip.GzipFile(fileobj=raw) as gz:
                    text = gz.read(32 * 1024 * 1024).decode("utf-8", "replace")
            else:
                text = read_text(f, max_bytes=64 * 1024 * 1024) or ""
        except (OSError, EOFError):
            continue
        _parse_auth_lines(data, text.splitlines(), f, max_events)


def _parse_auth_lines(data: dict, lines: list, source: str, max_events: int) -> None:
    summ = data["auth_summary"]
    failed = summ.setdefault("failed_by_ip", {})
    accepted = summ.setdefault("accepted", {})
    for line in lines:
        m = RE_FAILED.search(line) or RE_INVALID.search(line)
        if m:
            ip = m.group(2)
            failed[ip] = failed.get(ip, 0) + 1
            continue
        m = RE_ACCEPT.search(line)
        if m:
            key = f"{m.group(2)}@{m.group(3)}"
            accepted[key] = accepted.get(key, 0) + 1
            if len(data["auth_events"]) < max_events:
                data["auth_events"].append({"type": "login_success", "method": m.group(1), "user": m.group(2),
                                            "ip": m.group(3), "source": source, "raw": line[:500]})
            continue
        m = RE_SUDO.search(line)
        if m and len(data["auth_events"]) < max_events:
            data["auth_events"].append({"type": "sudo", "user": m.group(1), "command": m.group(2)[:500],
                                        "source": source, "raw": line[:500]})
            continue
        m = RE_USERADD.search(line)
        if m and len(data["auth_events"]) < max_events:
            data["auth_events"].append({"type": "account_change", "tool": m.group(1), "detail": m.group(2)[:500],
                                        "source": source, "raw": line[:500]})


HISTORY_FILES = (".bash_history", ".zsh_history", ".sh_history", ".history", ".python_history",
                 ".mysql_history", ".psql_history", ".local/share/fish/fish_history",
                 r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")


def _histories(data: dict) -> None:
    for h in home_dirs():
        for rel in HISTORY_FILES:
            p = os.path.join(h, rel)
            text = read_text(p, max_bytes=16 * 1024 * 1024)
            if not text:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if line.strip():
                    data["history_lines"].append({"file": p, "line": i, "command": line[:2000]})


def _windows(ctx, max_events: int) -> list:
    out = []
    for log, ids in WIN_EVENTS.items():
        query = "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + ")]]"
        res = ctx.runner.run(["wevtutil", "qe", log, f"/q:{query}", f"/c:{max_events}", "/rd:true", "/f:xml"],
                             label="evt_" + log.split("/")[0].split("-")[-1], timeout=300, ok_codes=(0, 15007))
        xml = res.get("stdout", "")
        if not xml.strip():
            continue
        try:
            root = ET.fromstring("<Events>" + xml + "</Events>")
        except ET.ParseError:
            continue
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        for ev in root.findall(f"{ns}Event"):
            sysn = ev.find(f"{ns}System")
            if sysn is None:
                continue
            eid = sysn.findtext(f"{ns}EventID")
            tc = sysn.find(f"{ns}TimeCreated")
            fields = {}
            ed = ev.find(f"{ns}EventData")
            if ed is not None:
                for d in ed.findall(f"{ns}Data"):
                    fields[d.get("Name") or f"data{len(fields)}"] = (d.text or "")[:2000]
            out.append({"log": log, "event_id": int(eid) if eid and eid.isdigit() else eid,
                        "time_utc": tc.get("SystemTime") if tc is not None else None,
                        "record_id": sysn.findtext(f"{ns}EventRecordID"),
                        "computer": sysn.findtext(f"{ns}Computer"), "data": fields})
    return out
