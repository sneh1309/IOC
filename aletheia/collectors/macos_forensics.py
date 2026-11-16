"""macOS investigation module - answers the usual "was my Mac misused / spied on?" questions.

STRICTLY READ-ONLY:
  * No original database is ever opened by SQLite. Every database (Mail, Messages, Safari,
    Chrome, Firefox, Screen Time / knowledgeC, TCC, Quarantine) and its -wal/-shm journal
    is first streamed byte-for-byte (read-only handle) into the sealed case folder; the
    SHA-256 of the original bytes is recorded. Queries run on a throw-away working copy
    in <case>/_work, which is deleted before the case is sealed.
  * Property lists are parsed from read-only handles.
  * Commands are restricted by the runner to read-only sub-commands
    (`log show`, `pmset -g`, `profiles show/status`, `sfltool dumpbtm`, `systemsetup -get*` ...).
  * Works live (mac_root="/") or OFFLINE against a mounted Mac volume / image
    (mac_root="/Volumes/Macintosh HD") - in offline mode no commands run on the evidence.
"""

from __future__ import annotations

import datetime as _dt
import glob
import os
import plistlib
import re
import shutil
import sqlite3
from typing import Optional

from aletheia.core.util import open_readonly, safe_stat, utc_now

MAC_EPOCH = 978307200          # 2001-01-01 (Cocoa / Core Data epoch)
CHROME_EPOCH = 11644473600     # 1601-01-01 (WebKit epoch), microseconds
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
FWD_RE = re.compile(r"^\s*(fwd?|fw)\s*:", re.I)

# Remote-control, monitoring and stalkerware products seen on macOS (name fragment -> category).
REMOTE_SPY = {
    "teamviewer": "remote access", "anydesk": "remote access", "splashtop": "remote access",
    "logmein": "remote access", "gotomypc": "remote access", "screenconnect": "remote access",
    "connectwise": "remote access", "rustdesk": "remote access", "realvnc": "remote access",
    "vnc server": "remote access", "jump desktop": "remote access", "chrome remote desktop": "remote access",
    "remotedesktop": "remote access", "parallels access": "remote access", "remotepc": "remote access",
    "zoho assist": "remote access", "bomgar": "remote access", "beyondtrust": "remote access",
    "ammyy": "remote access", "supremo": "remote access", "dwservice": "remote access",
    "nomachine": "remote access", "ngrok": "tunnel", "tailscale": "remote network", "zerotier": "remote network",
    "mspy": "stalkerware", "flexispy": "stalkerware", "spyrix": "stalkerware", "refog": "stalkerware",
    "elite keylogger": "stalkerware", "aobo": "stalkerware", "kidlogger": "stalkerware",
    "webwatcher": "stalkerware", "spyera": "stalkerware", "cocospy": "stalkerware", "hoverwatch": "stalkerware",
    "realtime-spy": "stalkerware", "spytech": "stalkerware", "keylogger": "keylogger", "imonitor": "stalkerware",
    "perfect keylogger": "stalkerware", "spector": "stalkerware", "teramind": "employee monitoring",
    "activtrak": "employee monitoring", "hubstaff": "employee monitoring", "veriato": "employee monitoring",
    "interguard": "employee monitoring", "insightful": "employee monitoring", "controlio": "employee monitoring",
    "qustodio": "parental monitoring", "net nanny": "parental monitoring", "bark": "parental monitoring",
    "mobicip": "parental monitoring", "kaspersky safe kids": "parental monitoring",
}

TCC_SENSITIVE = {
    "kTCCServiceListenEvent": "Input Monitoring (can record every keystroke)",
    "kTCCServiceScreenCapture": "Screen Recording (can see the screen)",
    "kTCCServiceAccessibility": "Accessibility (can control the Mac)",
    "kTCCServicePostEvent": "Synthetic input (can type/click)",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access (can read all data)",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceAddressBook": "Contacts",
    "kTCCServiceAppleEvents": "Automation (control other apps)",
    "kTCCServiceLocation": "Location",
}

MAIL_SETTINGS_URL = re.compile(r"(outlook\.(live|office|office365)\.com|mail\.google\.com|account\.microsoft\.com|"
                               r"mail\.yahoo\.com|icloud\.com/mail|login\.live\.com).*(forward|rule|inboxrule|"
                               r"filters|automaticrepl|options/mail|settings)", re.I)

UNIFIED_LOG_QUERIES = {
    "screen_lock_unlock": ('process == "loginwindow" AND (eventMessage CONTAINS "screenIsUnlocked" OR '
                           'eventMessage CONTAINS "screenIsLocked" OR eventMessage CONTAINS "sessionDidLogin" OR '
                           'eventMessage CONTAINS "sessionDidLogout")'),
    "remote_access": ('(process == "screensharingd" OR process == "sshd" OR process == "sshd-session" OR '
                      'process == "ARDAgent" OR process == "AppleVNCServer") AND (eventMessage CONTAINS[c] "auth" '
                      'OR eventMessage CONTAINS[c] "accepted" OR eventMessage CONTAINS[c] "failed" OR '
                      'eventMessage CONTAINS[c] "connection" OR eventMessage CONTAINS[c] "client")'),
    "privacy_permission_changes": 'subsystem == "com.apple.TCC" AND eventMessage CONTAINS[c] "update access record"',
    "usb_and_disks": ('(process == "kernel" AND eventMessage CONTAINS "USBMSC") OR '
                      '(process == "diskarbitrationd" AND eventMessage CONTAINS[c] "mounted")'),
    "airdrop": ('process == "sharingd" AND eventMessage CONTAINS[c] "airdrop" AND (eventMessage CONTAINS[c] '
                '"receiv" OR eventMessage CONTAINS[c] "send" OR eventMessage CONTAINS[c] "transfer")'),
    "boot_shutdown": ('eventMessage CONTAINS "BOOT_TIME" OR eventMessage CONTAINS "SHUTDOWN_TIME" OR '
                      '(process == "kernel" AND eventMessage CONTAINS "Previous shutdown cause")'),
    "tamper_indicators": ('(process == "log" AND eventMessage CONTAINS[c] "erase") OR '
                          'eventMessage CONTAINS[c] "settimeofday" OR (process == "tccutil")'),
}
SYSLOG_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)?([+-]\d{4})\s+\S+\s+([^\[:]+?)(?:\[\d+\])?:\s*(.*)$")
PMSET_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) ([+-]\d{4})\s+(\S+)\s+(.*)$")


# ------------------------------------------------------------------ helpers
def fmt(unix: Optional[float]) -> Optional[str]:
    """Local time of the examining machine, with UTC offset (what the client experienced)."""
    if unix is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(float(unix)).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def mac_time(v) -> Optional[float]:
    """Cocoa timestamp (seconds or nanoseconds since 2001) -> unix seconds."""
    if v in (None, "", 0):
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if v > 1e14:  # nanoseconds (Messages on macOS 10.13+)
        v = v / 1e9
    return v + MAC_EPOCH


def chrome_time(v) -> Optional[float]:
    try:
        return float(v) / 1e6 - CHROME_EPOCH if v else None
    except (TypeError, ValueError):
        return None


def unix_time(v) -> Optional[float]:
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if v > 1e14:
        return v / 1e6  # microseconds (Firefox)
    if v > 1e11:
        return v / 1e3  # milliseconds
    return v or None


def parse_local(ts: str, offset: str) -> Optional[float]:
    try:
        return _dt.datetime.strptime(f"{ts} {offset}", "%Y-%m-%d %H:%M:%S %z").timestamp()
    except ValueError:
        return None


def parse_day(text: str, end_of_day: bool = False) -> _dt.datetime:
    """'YYYY-MM-DD' (local time of the examined Mac) -> aware datetime at 00:00:00 or 23:59:59."""
    d = _dt.datetime.strptime(text.strip(), "%Y-%m-%d")
    if end_of_day:
        d = d.replace(hour=23, minute=59, second=59)
    return d.astimezone()


def read_plist(path: str):
    try:
        with open_readonly(path) as fh:
            return plistlib.load(fh)
    except Exception:
        return None


def plist_text(obj) -> str:
    """Flatten a plist into searchable text."""
    out = []

    def walk(o, key=""):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{key}.{k}" if key else str(k))
        elif isinstance(o, (list, tuple)):
            for i, v in enumerate(o):
                walk(v, f"{key}[{i}]")
        elif isinstance(o, bytes):
            out.append(f"{key}=<{len(o)} bytes>")
        else:
            out.append(f"{key}={o}")
    walk(obj)
    return "\n".join(out)


def matches(text, watch: list) -> list:
    low = (text or "").lower()
    return [w for w in watch if w and w in low]


class Investigator:
    def __init__(self, ctx, root: str = "/", days: int = 90, watch=None, include_content: bool = False,
                 date_from: Optional[str] = None, date_to: Optional[str] = None):
        self.ctx = ctx
        self.root = root
        self.live = os.path.abspath(root) == "/"
        self.days = days
        # Time window: an explicit --from/--to date range (local dates, inclusive) or the last N days.
        self.explicit_range = bool(date_from or date_to)
        now = _dt.datetime.now().astimezone()
        end = parse_day(date_to, end_of_day=True) if date_to else now
        start = parse_day(date_from) if date_from else end - _dt.timedelta(days=days)
        if start > end:
            raise ValueError(f"--from {date_from} is after --to {date_to}")
        self.start_dt, self.end_dt = start, end
        self.since, self.until = start.timestamp(), end.timestamp()
        self.watch = [w.strip().lower() for w in (watch or []) if w and w.strip()]
        self.include_content = include_content
        self.work = os.path.join(ctx.case_dir, "_work")
        self.inv: dict = {"generated_utc": utc_now(), "mode": "live" if self.live else f"offline ({root})",
                          "days": days, "watch": self.watch,
                          "range": {"from": start.strftime("%Y-%m-%d %H:%M:%S %z"), "to": end.strftime("%Y-%m-%d %H:%M:%S %z"),
                                    "explicit": self.explicit_range,
                                    "label": (f"{start:%Y-%m-%d} to {end:%Y-%m-%d}" if self.explicit_range
                                              else f"last {days} days ({start:%Y-%m-%d} to {end:%Y-%m-%d})")}, "include_content": include_content,
                          "access_problems": [], "databases": [], "users": {}, "system": {}}

    def keep(self, ts) -> bool:
        """True if a timestamp falls inside the selected window (undated records are kept unless a range was set)."""
        if not ts:
            return not self.explicit_range
        return self.since <= ts <= self.until

    # ---------------------------------------------------------- path utils
    def p(self, *parts) -> str:
        return os.path.join(self.root, *[x.lstrip("/") for x in parts])

    def homes(self) -> list:
        base = self.p("Users")
        out = []
        try:
            for e in os.scandir(base):
                if e.is_dir(follow_symlinks=False) and e.name not in ("Shared", "Guest", ".localized") \
                        and not e.name.startswith("."):
                    out.append(e.path)
        except OSError as exc:
            self.problem(base, exc)
        return sorted(out)

    def problem(self, path, exc) -> None:
        msg = str(exc)
        if isinstance(exc, PermissionError) or "Operation not permitted" in msg or "Permission denied" in msg:
            msg = "permission denied - grant Full Disk Access to Terminal and run with sudo"
        self.inv["access_problems"].append({"path": path, "error": msg})

    # ------------------------------------------------------- sqlite snapshot
    def open_db(self, src: str, label: str):
        """Preserve DB (+wal/shm) into evidence, return sqlite connection on a disposable working copy."""
        if not os.path.isfile(src):
            return None
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", label)
        sub = os.path.join("evidence", "databases", safe)
        rec = {"label": label, "original": src, "files": []}
        try:
            os.makedirs(self.work, exist_ok=True)
            wdir = os.path.join(self.work, safe)
            os.makedirs(wdir, exist_ok=True)
            base = os.path.basename(src)
            for suffix in ("", "-wal", "-shm", "-journal"):
                f = src + suffix
                if not os.path.isfile(f):
                    continue
                st = safe_stat(f) or {}
                r = self.ctx.store.copy_file_once(f, sub, base + suffix)
                rec["files"].append({"file": base + suffix, "sha256": r["sha256"], "size": r["size"],
                                     "evidence": r["path"], "mtime": st.get("mtime"), "birthtime": st.get("birthtime")})
                shutil.copyfile(os.path.join(self.ctx.case_dir, r["path"]), os.path.join(wdir, base + suffix))
                os.chmod(os.path.join(wdir, base + suffix), 0o600)
        except Exception as exc:
            self.problem(src, exc)
            return None
        self.inv["databases"].append(rec)
        self.ctx.audit.record("database_preserved", {"label": label, "original": src,
                                                     "sha256": [f["sha256"] for f in rec["files"]]})
        try:
            conn = sqlite3.connect(os.path.join(wdir, os.path.basename(src)))
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as exc:
            self.problem(src, exc)
            return None

    def q(self, conn, sql: str, params=()) -> list:
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        except sqlite3.Error as exc:
            self.ctx.error(f"sqlite: {sql[:60]}", exc)
            return []

    @staticmethod
    def cols(conn, table: str) -> set:
        try:
            return {r[1] for r in conn.execute(f"PRAGMA table_info('{table}')")}
        except sqlite3.Error:
            return set()

    # ================================================================ USER
    def mail(self, home: str) -> dict:
        out = {"rules": [], "accounts_seen": [], "messages_total": 0, "watched": [], "forwarded": [],
               "deleted": [], "sent": []}
        # --- rules (local + iCloud-synced). Server-side rules (outlook.com/Gmail) are NOT on the Mac.
        rule_files = glob.glob(os.path.join(home, "Library/Mail/V*/MailData/*Rules*.plist"))
        rule_files += glob.glob(os.path.join(home, "Library/Mobile Documents/com~apple~mail/Data/*/MailData/*Rules*.plist"))
        rule_files += glob.glob(os.path.join(home, "Library/Mobile Documents/com~apple~mail/Data/MailData/*Rules*.plist"))
        for rf in sorted(set(rule_files)):
            pl = read_plist(rf)
            if pl is None:
                if os.path.exists(rf):
                    self.problem(rf, PermissionError("unreadable"))
                continue
            st = safe_stat(rf) or {}
            rules = pl if isinstance(pl, list) else pl.get("rules", [pl]) if isinstance(pl, dict) else []
            for r in rules if isinstance(rules, list) else []:
                text = plist_text(r)
                fwd = bool(re.search(r"(forward|redirect|resend)\w*=(?!False|0\b|$)", text, re.I))
                out["rules"].append({"file": rf, "file_modified": st.get("mtime"), "name": r.get("RuleName")
                                     if isinstance(r, dict) else None, "forwards_or_redirects": fwd,
                                     "addresses": sorted(set(EMAIL_RE.findall(text))),
                                     "watched_hits": matches(text, self.watch), "raw": text[:3000]})
        # --- Envelope Index
        envs = sorted(glob.glob(os.path.join(home, "Library/Mail/V*/MailData/Envelope Index")))
        if not envs:
            if os.path.isdir(os.path.join(home, "Library/Mail")) and not os.access(os.path.join(home, "Library/Mail"), os.R_OK):
                self.problem(os.path.join(home, "Library/Mail"), PermissionError())
            return out
        conn = self.open_db(envs[-1], f"{os.path.basename(home)}_mail_envelope_index")
        if conn is None:
            return out
        mcols = self.cols(conn, "messages")
        prefix = "m.subject_prefix" if "subject_prefix" in mcols else "''"
        deleted = "m.deleted" if "deleted" in mcols else "0"
        rows = self.q(conn, f"""SELECT m.ROWID id, m.date_sent, m.date_received, {prefix} prefix, s.subject subject,
                                a.address sender, mb.url mailbox, {deleted} deleted
                                FROM messages m LEFT JOIN subjects s ON m.subject = s.ROWID
                                LEFT JOIN addresses a ON m.sender = a.ROWID
                                LEFT JOIN mailboxes mb ON m.mailbox = mb.ROWID""")
        rcpt: dict = {}
        for r in self.q(conn, "SELECT r.message, a.address, r.type FROM recipients r "
                              "JOIN addresses a ON r.address = a.ROWID"):
            rcpt.setdefault(r["message"], []).append(r["address"])
        conn.close()
        out["messages_total"] = len(rows)
        for r in rows:
            to = rcpt.get(r["id"], [])
            subj = f"{r.get('prefix') or ''}{r.get('subject') or ''}"
            box = r.get("mailbox") or ""
            when = unix_time(r.get("date_sent")) or unix_time(r.get("date_received"))
            if not self.keep(when):
                continue
            item = {"date": fmt(when), "_ts": when, "from": r.get("sender"), "to": ", ".join(to), "subject": subj,
                    "mailbox": box.split("/")[-1] if box else "", "mailbox_url": box}
            hits = matches(" ".join(to + [r.get("sender") or ""]), self.watch)
            if hits:
                item["watched"] = ", ".join(hits)
                item["direction"] = "sent TO watched" if matches(" ".join(to), self.watch) else "received FROM watched"
                out["watched"].append(item)
            if FWD_RE.match(subj):
                out["forwarded"].append(item)
            if r.get("deleted") or re.search(r"trash|deleted|bin\b|corbeille", box, re.I):
                out["deleted"].append(item)
            if re.search(r"sent", box, re.I):
                out["sent"].append(item)
        for k in ("watched", "forwarded", "deleted", "sent"):
            out[k].sort(key=lambda x: x.get("_ts") or 0)
            out[k + "_count"] = len(out[k])
        out["sent"] = out["sent"][-3000:]
        return out

    def messages(self, home: str) -> dict:
        out = {"total": 0, "by_contact": [], "by_day": [], "watched": [], "attachments": [], "recent": []}
        db = os.path.join(home, "Library/Messages/chat.db")
        if os.path.exists(db) and not os.access(db, os.R_OK):
            self.problem(db, PermissionError())
            return out
        conn = self.open_db(db, f"{os.path.basename(home)}_messages_chat")
        if conn is None:
            return out
        text_col = "m.text" if self.include_content else "NULL"
        rows = self.q(conn, f"""SELECT m.ROWID id, m.date, m.is_from_me, m.service, h.id handle,
                                m.cache_has_attachments att, {text_col} text
                                FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID""")
        atts = self.q(conn, """SELECT a.created_date, a.filename, a.transfer_name, a.mime_type, a.total_bytes,
                               a.is_outgoing, maj.message_id FROM attachment a
                               LEFT JOIN message_attachment_join maj ON maj.attachment_id = a.ROWID""")
        conn.close()
        contacts, days = {}, {}
        for r in rows:
            t = mac_time(r.get("date"))
            if not self.keep(t):
                continue
            r["_ts"] = t
            h = r.get("handle") or "(unknown / group)"
            c = contacts.setdefault(h, {"contact": h, "messages": 0, "sent": 0, "received": 0, "first": t, "last": t,
                                        "service": r.get("service")})
            c["messages"] += 1
            c["sent" if r.get("is_from_me") else "received"] += 1
            if t:
                c["first"] = min(c["first"] or t, t)
                c["last"] = max(c["last"] or t, t)
                d = fmt(t)[:10]
                dd = days.setdefault(d, {"date": d, "messages": 0, "sent": 0, "received": 0})
                dd["messages"] += 1
                dd["sent" if r.get("is_from_me") else "received"] += 1
            if matches(h + " " + (r.get("text") or ""), self.watch):
                out["watched"].append({"date": fmt(t), "_ts": t, "contact": h,
                                       "direction": "sent" if r.get("is_from_me") else "received",
                                       "service": r.get("service"), "text": r.get("text") if self.include_content else
                                       "(content not collected - use --include-content)"})
        out["total"] = sum(c["messages"] for c in contacts.values())
        out["by_contact"] = sorted(({**c, "first": fmt(c["first"]), "last": fmt(c["last"])} for c in contacts.values()),
                                   key=lambda x: -x["messages"])
        out["by_day"] = sorted(days.values(), key=lambda x: x["date"], reverse=True)
        for a in atts:
            t = mac_time(a.get("created_date"))
            if not self.keep(t):
                continue
            out["attachments"].append({"date": fmt(t), "_ts": t, "name": a.get("transfer_name") or
                                       os.path.basename(a.get("filename") or ""), "type": a.get("mime_type"),
                                       "bytes": a.get("total_bytes"),
                                       "direction": "sent" if a.get("is_outgoing") else "received"})
        out["attachments"].sort(key=lambda x: x.get("_ts") or 0, reverse=True)
        out["attachments"] = out["attachments"][:3000]
        out["watched"].sort(key=lambda x: x.get("_ts") or 0)
        return out

    def browsers(self, home: str) -> dict:
        out = {"history": [], "downloads": [], "summary": [], "mail_settings_visits": [], "watched": [],
               "remote_spy_visits": []}
        sources = []
        sources.append(("Safari", os.path.join(home, "Library/Safari/History.db"), "safari"))
        for name, rel in (("Chrome", "Google/Chrome"), ("Edge", "Microsoft Edge"), ("Brave", "BraveSoftware/Brave-Browser"),
                          ("Opera", "com.operasoftware.Opera"), ("Arc", "Arc/User Data"), ("Vivaldi", "Vivaldi")):
            for h in glob.glob(os.path.join(home, "Library/Application Support", rel, "*", "History")):
                sources.append((f"{name} ({os.path.basename(os.path.dirname(h))})", h, "chrome"))
        for h in glob.glob(os.path.join(home, "Library/Application Support/Firefox/Profiles/*/places.sqlite")):
            sources.append((f"Firefox ({os.path.basename(os.path.dirname(h))})", h, "firefox"))
        for label, path, kind in sources:
            if os.path.exists(path) and not os.access(path, os.R_OK):
                self.problem(path, PermissionError())
                continue
            conn = self.open_db(path, f"{os.path.basename(home)}_{label}_history")
            if conn is None:
                continue
            if kind == "safari":
                rows = self.q(conn, "SELECT hv.visit_time t, hi.url url, hv.title title FROM history_visits hv "
                                    "JOIN history_items hi ON hv.history_item = hi.id ORDER BY hv.visit_time DESC LIMIT 50000")
                conv = mac_time
            elif kind == "chrome":
                rows = self.q(conn, "SELECT v.visit_time t, u.url url, u.title title FROM visits v JOIN urls u "
                                    "ON v.url = u.id ORDER BY v.visit_time DESC LIMIT 50000")
                conv = chrome_time
                for d in self.q(conn, "SELECT start_time, target_path, tab_url, total_bytes FROM downloads"):
                    t = chrome_time(d.get("start_time"))
                    if not self.keep(t):
                        continue
                    out["downloads"].append({"date": fmt(t), "_ts": t, "browser": label, "file": d.get("target_path"),
                                             "from": d.get("tab_url"), "bytes": d.get("total_bytes")})
            else:
                rows = self.q(conn, "SELECT v.visit_date t, p.url url, p.title title FROM moz_historyvisits v JOIN "
                                    "moz_places p ON v.place_id = p.id ORDER BY v.visit_date DESC LIMIT 50000")
                conv = unix_time
            conn.close()
            ts = []
            for r in rows:
                t = conv(r.get("t"))
                if not self.keep(t):
                    continue
                ts.append(t or 0)
                url = r.get("url") or ""
                item = {"date": fmt(t), "_ts": t, "browser": label, "url": url[:500], "title": (r.get("title") or "")[:200]}
                out["history"].append(item)
                if MAIL_SETTINGS_URL.search(url):
                    out["mail_settings_visits"].append(item)
                if matches(url + " " + (r.get("title") or ""), self.watch):
                    out["watched"].append(item)
                low = url.lower()
                if any(k.replace(" ", "") in low.replace("-", "") for k in REMOTE_SPY if len(k) > 4):
                    out["remote_spy_visits"].append(item)
            nz = [t for t in ts if t]
            out["summary"].append({"browser": label, "visits": len(ts), "first": fmt(min(nz)) if nz else None,
                                   "last": fmt(max(nz)) if nz else None})
        for k in ("history", "downloads", "mail_settings_visits", "watched", "remote_spy_visits"):
            out[k].sort(key=lambda x: x.get("_ts") or 0, reverse=True)
        out["history"] = out["history"][:20000]
        return out

    def quarantine(self, home: str) -> list:
        db = os.path.join(home, "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
        conn = self.open_db(db, f"{os.path.basename(home)}_quarantine_downloads")
        if conn is None:
            return []
        rows = self.q(conn, "SELECT LSQuarantineTimeStamp t, LSQuarantineAgentName agent, LSQuarantineDataURLString url, "
                            "LSQuarantineOriginURLString origin, LSQuarantineSenderName sender FROM LSQuarantineEvent")
        conn.close()
        out = [{"date": fmt(mac_time(r["t"])), "_ts": mac_time(r["t"]), "app": r.get("agent"), "url": r.get("url"),
                "origin": r.get("origin"), "sender": r.get("sender")} for r in rows if self.keep(mac_time(r["t"]))]
        return sorted(out, key=lambda x: x.get("_ts") or 0, reverse=True)

    def knowledge(self, path: str, label: str) -> dict:
        out = {"app_usage": [], "apps_summary": [], "lock_events": [], "available": False}
        conn = self.open_db(path, label)
        if conn is None:
            return out
        rows = self.q(conn, "SELECT ZSTREAMNAME stream, ZVALUESTRING value, ZVALUEINTEGER ival, ZSTARTDATE s, ZENDDATE e "
                            "FROM ZOBJECT WHERE ZSTREAMNAME IN ('/app/usage','/app/inFocus','/device/isLocked',"
                            "'/display/isBacklit') ORDER BY ZSTARTDATE")
        conn.close()
        out["available"] = bool(rows)
        apps: dict = {}
        for r in rows:
            s, e = mac_time(r.get("s")), mac_time(r.get("e"))
            if not self.keep(s):
                continue
            if r["stream"] in ("/app/usage", "/app/inFocus") and r.get("value"):
                dur = max(0, (e or s or 0) - (s or 0))
                out["app_usage"].append({"start": fmt(s), "end": fmt(e), "_ts": s, "app": r["value"],
                                         "minutes": round(dur / 60, 1)})
                a = apps.setdefault(r["value"], {"app": r["value"], "sessions": 0, "minutes": 0.0, "first": s, "last": e})
                a["sessions"] += 1
                a["minutes"] += dur / 60
                a["first"] = min(a["first"] or s, s or a["first"])
                a["last"] = max(a["last"] or 0, e or 0)
            elif r["stream"] == "/device/isLocked":
                out["lock_events"].append({"date": fmt(s), "_ts": s, "event": "locked" if r.get("ival") else "unlocked"})
        out["apps_summary"] = sorted(({**a, "minutes": round(a["minutes"], 1), "first": fmt(a["first"]),
                                       "last": fmt(a["last"])} for a in apps.values()), key=lambda x: -x["minutes"])
        out["app_usage"] = sorted(out["app_usage"], key=lambda x: x.get("_ts") or 0, reverse=True)[:20000]
        return out

    def recent_files(self, home: str) -> list:
        out = []
        for sub in ("Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music"):
            base = os.path.join(home, sub)
            for dirpath, dirnames, files in os.walk(base, followlinks=False):
                if self.ctx.is_inside_case_dir(dirpath):
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames if not d.endswith((".photoslibrary", ".app", ".musiclibrary"))]
                for f in files:
                    fp = os.path.join(dirpath, f)
                    st = safe_stat(fp)
                    if not st:
                        continue
                    try:
                        m = os.lstat(fp).st_mtime
                        b = getattr(os.lstat(fp), "st_birthtime", None)
                    except OSError:
                        continue
                    if self.since <= max(m, b or 0) <= self.until:
                        out.append({"path": fp, "modified": fmt(m), "created": fmt(b), "_ts": max(m, b or 0),
                                    "size": st.get("size")})
                if len(out) > 20000:
                    break
        return sorted(out, key=lambda x: x["_ts"], reverse=True)[:10000]

    def user_tcc_and_accounts(self, home: str) -> dict:
        acc = read_plist(os.path.join(home, "Library/Preferences/MobileMeAccounts.plist")) or {}
        apple_ids = []
        for a in acc.get("Accounts", []) if isinstance(acc, dict) else []:
            apple_ids.append({"apple_id": a.get("AccountID"), "name": a.get("DisplayName"),
                              "services_enabled": [s.get("Name") for s in a.get("Services", []) if s.get("Enabled")]})
        internet_accounts = []
        for f in glob.glob(os.path.join(home, "Library/Accounts/Accounts*.sqlite")):
            conn = self.open_db(f, f"{os.path.basename(home)}_internet_accounts")
            if conn:
                internet_accounts = self.q(conn, "SELECT ZACCOUNTDESCRIPTION description, ZUSERNAME username, "
                                                 "ZDATE created FROM ZACCOUNT")
                for r in internet_accounts:
                    r["created"] = fmt(mac_time(r.get("created")))
                conn.close()
        return {"apple_ids": apple_ids, "internet_accounts": internet_accounts,
                "tcc": self.tcc(os.path.join(home, "Library/Application Support/com.apple.TCC/TCC.db"),
                                f"{os.path.basename(home)}_user_TCC")}

    # ============================================================== SYSTEM
    def tcc(self, path: str, label: str) -> list:
        conn = self.open_db(path, label)
        if conn is None:
            if os.path.exists(path):
                self.problem(path, PermissionError())
            return []
        c = self.cols(conn, "access")
        auth = "auth_value" if "auth_value" in c else ("allowed" if "allowed" in c else "NULL")
        lm = "last_modified" if "last_modified" in c else "NULL"
        rows = self.q(conn, f"SELECT service, client, client_type, {auth} auth, {lm} lm FROM access")
        conn.close()
        out = []
        for r in rows:
            granted = (r.get("auth") == 2) if auth == "auth_value" else bool(r.get("auth"))
            out.append({"service": r.get("service"), "permission": TCC_SENSITIVE.get(r.get("service"), r.get("service")),
                        "app": r.get("client"), "granted": granted, "changed": fmt(unix_time(r.get("lm"))),
                        "_ts": unix_time(r.get("lm")), "sensitive": r.get("service") in TCC_SENSITIVE,
                        "apple": str(r.get("client") or "").startswith(("com.apple.", "/System/", "/usr/"))})
        return sorted(out, key=lambda x: x.get("_ts") or 0, reverse=True)

    def installs_and_apps(self) -> dict:
        hist = read_plist(self.p("Library/Receipts/InstallHistory.plist")) or []
        installs = []
        for h in hist if isinstance(hist, list) else []:
            d = h.get("date")
            ts = d.timestamp() if isinstance(d, _dt.datetime) else None
            installs.append({"date": fmt(ts), "_ts": ts, "name": h.get("displayName"),
                             "version": h.get("displayVersion"), "installer": h.get("processName"),
                             "packages": ", ".join(h.get("packageIdentifiers") or [])[:300]})
        installs.sort(key=lambda x: x.get("_ts") or 0, reverse=True)
        apps = []
        dirs = [self.p("Applications"), self.p("Applications/Utilities")] + [os.path.join(h, "Applications")
                                                                            for h in self.homes()]
        for d in dirs:
            for app in glob.glob(os.path.join(d, "*.app")):
                info = read_plist(os.path.join(app, "Contents/Info.plist")) or {}
                st = os.lstat(app) if os.path.exists(app) else None
                b = getattr(st, "st_birthtime", None) if st else None
                apps.append({"app": os.path.basename(app)[:-4], "bundle_id": info.get("CFBundleIdentifier"),
                             "version": info.get("CFBundleShortVersionString"), "path": app,
                             "added": fmt(b or (st.st_ctime if st else None)), "_ts": b or (st.st_ctime if st else None)})
        apps.sort(key=lambda x: x.get("_ts") or 0, reverse=True)
        flagged = []
        for item in apps + installs:
            hay = " ".join(str(item.get(k) or "") for k in ("app", "name", "bundle_id", "packages", "path")).lower()
            for k, cat in REMOTE_SPY.items():
                if k in hay:
                    flagged.append({**item, "match": k, "category": cat})
                    break
        return {"install_history": installs, "applications": apps, "remote_or_monitoring_software": flagged}

    def networks(self) -> dict:
        wifi = []
        kn = read_plist(self.p("Library/Preferences/com.apple.wifi.known-networks.plist"))
        if isinstance(kn, dict):
            for key, v in kn.items():
                if not isinstance(v, dict):
                    continue
                dates = {k: fmt(x.timestamp()) for k, x in v.items() if isinstance(x, _dt.datetime)}
                ssid = v.get("SSID")
                if isinstance(ssid, bytes):
                    ssid = ssid.decode("utf-8", "replace")
                last = max((x.timestamp() for x in v.values() if isinstance(x, _dt.datetime)), default=None)
                wifi.append({"network": ssid or key.replace("wifi.network.ssid.", ""), "security": v.get("SupportedSecurityTypes"),
                             "added": dates.get("AddedAt"), "joined_by_user": dates.get("JoinedByUserAt"),
                             "last_seen": fmt(last), "_ts": last, "all_dates": dates})
        old = read_plist(self.p("Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"))
        if isinstance(old, dict):
            for key, v in (old.get("KnownNetworks") or {}).items():
                lc = v.get("LastConnected") or v.get("LastAutoJoinAt")
                ts = lc.timestamp() if isinstance(lc, _dt.datetime) else None
                wifi.append({"network": v.get("SSIDString"), "last_seen": fmt(ts), "_ts": ts, "added": None,
                             "joined_by_user": None, "security": v.get("SecurityType")})
        wifi.sort(key=lambda x: x.get("_ts") or 0, reverse=True)
        leases = []
        for f in glob.glob(self.p("private/var/db/dhcpclient/leases/*")):
            pl = read_plist(f)
            if isinstance(pl, dict):
                st = pl.get("LeaseStartDate")
                ts = st.timestamp() if isinstance(st, _dt.datetime) else None
                rhw = pl.get("RouterHardwareAddress")
                leases.append({"interface": os.path.basename(f).split("-")[0], "ip_address": pl.get("IPAddress"),
                               "router_ip": pl.get("RouterIPAddress"), "network": pl.get("SSID"),
                               "router_mac": rhw.hex(":") if isinstance(rhw, bytes) else rhw,
                               "lease_start": fmt(ts), "_ts": ts})
        leases.sort(key=lambda x: x.get("_ts") or 0, reverse=True)
        return {"wifi_known_networks": wifi, "dhcp_leases": leases}

    def run(self, argv, label, timeout=900):
        if not self.live:
            return ""
        try:
            res = self.ctx.runner.run(argv, label=label, timeout=timeout, ok_codes=(0, 1))
        except Exception as exc:
            self.ctx.error(f"cmd {argv[0]}", exc)
            return ""
        if res.get("error"):
            self.ctx.error(f"cmd {' '.join(argv[:2])}", res["error"])
        return res.get("stdout", "")

    def remote_and_management(self) -> dict:
        out = {"services": {}, "profiles_raw": "", "mdm_enrollment_raw": "", "profiles_installed": None,
               "background_items_raw": "", "system_extensions_raw": "", "third_party_kexts": []}
        if not self.live:
            return out
        for flag, name in (("-getremotelogin", "Remote Login (SSH)"), ("-getremoteappleevents", "Remote Apple Events")):
            txt = self.run(["systemsetup", flag], f"systemsetup{flag}", 60)
            out["services"][name] = "On" if re.search(r":\s*On\b", txt) else ("Off" if re.search(r":\s*Off\b", txt) else
                                                                             txt.strip()[:200] or "unknown")
        for svc, name in (("system/com.apple.screensharing", "Screen Sharing / Remote Management (VNC)"),
                          ("system/com.apple.smbd", "File Sharing (SMB)")):
            try:
                res = self.ctx.runner.run(["launchctl", "print", svc], label="launchctl_" + svc.split(".")[-1],
                                          timeout=60, ok_codes=(0, 113))
                out["services"][name] = "On (service loaded)" if res.get("rc") == 0 else "Off (not loaded)"
            except Exception as exc:
                self.ctx.error("launchctl print", exc)
        procs = {(p.get("name") or "").lower() for p in self.ctx.artifacts.get("processes", [])}
        out["services"]["Apple Remote Desktop agent running"] = "Yes" if "ardagent" in procs else "No"
        out["services"]["Sharing (sharing -l)"] = self.run(["sharing", "-l"], "sharing_list", 60)[:1500] or "n/a"
        out["profiles_raw"] = self.run(["profiles", "show", "-type", "configuration"], "profiles_configuration", 120)
        out["mdm_enrollment_raw"] = self.run(["profiles", "status", "-type", "enrollment"], "mdm_enrollment", 120)
        p = out["profiles_raw"]
        out["profiles_installed"] = bool(p.strip()) and "no configuration profiles" not in p.lower() \
            and "attribute" in p.lower()
        out["mdm_enrolled"] = bool(re.search(r"MDM enrollment:\s*Yes", out["mdm_enrollment_raw"], re.I))
        out["background_items_raw"] = self.run(["sfltool", "dumpbtm"], "background_login_items", 300)
        out["system_extensions_raw"] = self.run(["systemextensionsctl", "list"], "system_extensions", 60)
        kx = self.run(["kmutil", "showloaded"], "kernel_extensions", 300)
        out["third_party_kexts"] = [l.strip() for l in kx.splitlines() if "com.apple" not in l and re.search(r"\w+\.\w+\.\w+", l)]
        hits = []
        for blob, src in ((out["background_items_raw"], "Login/Background items"),
                          (out["system_extensions_raw"], "System extensions"), (p, "Configuration profiles")):
            low = blob.lower()
            for k, cat in REMOTE_SPY.items():
                if k in low:
                    hits.append({"source": src, "match": k, "category": cat})
        out["remote_or_monitoring_hits"] = hits
        return out

    def power_and_logins(self) -> dict:
        out = {"power_events": [], "logins_raw": "", "logins": []}
        txt = self.run(["pmset", "-g", "log"], "pmset_log", 600)
        for line in txt.splitlines():
            m = PMSET_LINE.match(line)
            if not m:
                continue
            kind = m.group(3)
            if kind not in ("Sleep", "Wake", "DarkWake", "Start", "Shutdown", "ShutdownCause", "Restart",
                            "Notification", "WakeRequests", "UserWake"):
                continue
            msg = m.group(4).strip()
            if kind == "Notification" and "Display is turned" not in msg:
                continue
            t = parse_local(m.group(1), m.group(2))
            if not self.keep(t):
                continue
            out["power_events"].append({"date": fmt(t), "_ts": t, "event": kind, "detail": msg[:200]})
        out["logins_raw"] = self.run(["last"], "last_logins", 120)
        for line in out["logins_raw"].splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] not in ("wtmp", "reboot", "shutdown") and not line.startswith("wtmp"):
                out["logins"].append({"user": parts[0], "terminal": parts[1], "raw": line.strip()})
            elif parts and parts[0] in ("reboot", "shutdown"):
                out["logins"].append({"user": parts[0], "terminal": "", "raw": line.strip()})
        return out

    def unified_logs(self) -> dict:
        out = {}
        if not self.live:
            return out
        for label, pred in UNIFIED_LOG_QUERIES.items():
            self.ctx.log(f"    - unified log: {label} ({self.inv['range']['label']}) ...")
            self._tick(0, f"reading system log: {label.replace('_', ' ')}")
            window = ["--start", self.start_dt.strftime("%Y-%m-%d %H:%M:%S"),
                      "--end", self.end_dt.strftime("%Y-%m-%d %H:%M:%S")]
            txt = self.run(["log", "show", "--style", "syslog", "--info"] + window +
                           ["--predicate", pred], f"unifiedlog_{label}", 1800)
            events = []
            for line in txt.splitlines():
                m = SYSLOG_LINE.match(line)
                if m:
                    t = parse_local(m.group(1), m.group(2))
                    events.append({"date": fmt(t), "_ts": t, "process": m.group(3).strip(), "message": m.group(4)[:400]})
            out[label] = events[-20000:]
            self._tick(4, f"system log: {label.replace('_', ' ')} done ({len(events)} events)")
        return out

    # ============================================================== RUN
    def _tick(self, units: float, detail: str) -> None:
        """Advance the progress bar by `units` of the investigation's total work."""
        self._done = getattr(self, "_done", 0.0) + units
        prog = getattr(self.ctx, "progress", None)
        if prog is not None:
            prog.update(self._done / max(self._total, 1), detail)

    def collect(self) -> dict:
        inv = self.inv
        homes = self.homes()
        # work units: 7 per user, 6 system sources, 4 per unified-log query (the slow part on a live Mac)
        self._total = 7 * len(homes) + 6 + (4 * len(UNIFIED_LOG_QUERIES) if self.live else 0)
        self._done = 0.0
        labels = {"mail": "Mail", "messages": "Messages", "browsers": "browser history",
                  "downloads_quarantine": "downloads", "recent_files": "recent files", "accounts": "accounts & permissions"}
        for home in homes:
            user = os.path.basename(home)
            self.ctx.log(f"    - user {user}: Mail, Messages, browsers, downloads, app usage, files ...")
            u = {"home": home}
            for key, fn in (("mail", self.mail), ("messages", self.messages), ("browsers", self.browsers),
                            ("downloads_quarantine", self.quarantine), ("recent_files", self.recent_files),
                            ("accounts", self.user_tcc_and_accounts)):
                self._tick(0, f"user {user}: {labels[key]}")
                try:
                    u[key] = fn(home)
                except Exception as exc:
                    self.ctx.error(f"mac:{user}:{key}", exc)
                self._tick(1, f"user {user}: {labels[key]} done")
            u["knowledge"] = self.knowledge(os.path.join(home, "Library/Application Support/Knowledge/knowledgeC.db"),
                                            f"{user}_knowledgeC")
            self._tick(1, f"user {user}: app usage done")
            inv["users"][user] = u
        s = inv["system"]
        self.ctx.log("    - system: privacy permissions, installs, Wi-Fi/IP history, sharing, profiles ...")
        for key, fn in (("tcc", lambda: self.tcc(self.p("Library/Application Support/com.apple.TCC/TCC.db"), "system_TCC")),
                        ("software", self.installs_and_apps), ("networks", self.networks),
                        ("remote", self.remote_and_management), ("power", self.power_and_logins),
                        ("knowledge", lambda: self.knowledge(self.p("private/var/db/CoreDuet/Knowledge/knowledgeC.db"),
                                                             "system_knowledgeC"))):
            self._tick(0, f"system: {key}")
            try:
                s[key] = fn()
            except Exception as exc:
                self.ctx.error(f"mac:system:{key}", exc)
            self._tick(1, f"system: {key} done")
        s["unified_logs"] = self.unified_logs()
        inv["questions"] = build_questions(inv)
        shutil.rmtree(self.work, ignore_errors=True)  # disposable working copies only
        return inv


# ===================================================================== Q&A
def _t(rows, cols, limit=20000):
    return {"columns": cols, "rows": [[r.get(c) for c in cols] for r in rows[:limit]], "total": len(rows)}


def _first_last(rows):
    ts = [r["_ts"] for r in rows if r.get("_ts")]
    return (fmt(min(ts)), fmt(max(ts))) if ts else (None, None)


def build_questions(inv: dict) -> list:
    users = inv.get("users", {})
    s = inv.get("system", {})
    watch = inv.get("watch", [])
    W = ", ".join(watch) or "(no watched addresses/keywords given - use --watch)"
    Q = []

    def all_u(path):
        out = []
        for u, d in users.items():
            cur = d
            for p in path:
                cur = (cur or {}).get(p) if isinstance(cur, dict) else None
            for r in cur or []:
                out.append({**r, "user": u})
        return out

    # Q1 forwarding
    rules = all_u(["mail", "rules"])
    fwd_rules = [r for r in rules if r["forwards_or_redirects"] or r["watched_hits"]]
    watched_mail = all_u(["mail", "watched"])
    sent_to = [m for m in watched_mail if m.get("direction", "").startswith("sent")]
    settings = all_u(["browsers", "mail_settings_visits"])
    first, last = _first_last(sent_to)
    a = []
    a.append(f"Watched: {W}.")
    a.append(f"{len(sent_to)} message(s) in Apple Mail were sent/forwarded TO a watched address"
             + (f" - first {first}, most recent {last}." if first else "."))
    a.append(f"{len(fwd_rules)} Apple Mail rule(s) forward/redirect mail or reference a watched address."
             if rules else "No Apple Mail rules found on this Mac.")
    if settings:
        f2, l2 = _first_last(settings)
        a.append(f"{len(settings)} browser visit(s) to webmail forwarding/rules/settings pages (first {f2}, last {l2}) "
                 "- compare these dates with when forwarding began.")
    a.append("IMPORTANT: forwarding configured on the email provider's website (Outlook.com/Hotmail, Gmail, iCloud) "
             "is stored on the server, not the Mac. Check Outlook.com > Settings > Mail > Forwarding and Rules, and "
             "account.microsoft.com > Security > Sign-in activity, and screenshot them for the file.")
    Q.append({"id": "Q1", "question": "Is email being forwarded to another address, and when did it start?",
              "answer": a, "tables": {
                  "Mail sent/forwarded to watched addresses": _t(sent_to, ["date", "user", "from", "to", "subject", "mailbox"]),
                  "Mail rules that forward/redirect": _t(fwd_rules, ["user", "name", "addresses", "file_modified", "file"]),
                  "Visits to webmail forwarding/rules pages": _t(settings, ["date", "user", "browser", "url"])}})

    # Q2 apps / Messages
    apps = []
    for u, d in users.items():
        apps += [{**x, "user": u} for x in (d.get("knowledge") or {}).get("apps_summary", [])]
    apps += [{**x, "user": "(system)"} for x in (s.get("knowledge") or {}).get("apps_summary", [])]
    msgs_c = all_u(["messages", "by_contact"])
    msgs_d = all_u(["messages", "by_day"])
    a = [f"App-usage history (Screen Time / knowledgeC): {len(apps)} app(s) with recorded use."
         if apps else "No app-usage database available (macOS 14+ keeps most app usage in Biome; see browser, "
                      "Messages and unlock tables instead, or enable Screen Time history).",
         f"Messages: {sum(c['messages'] for c in msgs_c)} message(s) with {len(msgs_c)} contact(s); "
         f"{len(all_u(['messages', 'attachments']))} attachment(s)."
         + ("" if inv.get("include_content") else " Message text was NOT collected (privacy) - metadata only."),
         "Messages may also sync to other devices on the same Apple ID (iPhone/iPad/other Macs) - check System "
         "Settings > Apple ID > Devices."]
    Q.append({"id": "Q2", "question": "What apps were used (including Messages) and when?", "answer": a, "tables": {
        "App usage summary": _t(apps, ["app", "user", "minutes", "sessions", "first", "last"]),
        "Messages by contact": _t(msgs_c, ["contact", "user", "service", "messages", "sent", "received", "first", "last"]),
        "Messages per day": _t(msgs_d, ["date", "user", "messages", "sent", "received"]),
        "Messages involving watched keywords": _t(all_u(["messages", "watched"]), ["date", "user", "contact", "direction", "service", "text"])}})

    # Q3 opened / transferred
    dl = all_u(["downloads_quarantine"]) + all_u(["browsers", "downloads"])
    dl.sort(key=lambda x: x.get("_ts") or 0, reverse=True)
    att = all_u(["messages", "attachments"])
    rf = all_u(["recent_files"])
    ul = s.get("unified_logs", {})
    a = [f"{len(dl)} downloaded file record(s), {len(att)} Messages attachment(s), {len(rf)} user file(s) created or "
         f"modified in the period {(inv.get('range') or {}).get('label')}, {len(ul.get('usb_and_disks', []))} USB/disk mount event(s), "
         f"{len(ul.get('airdrop', []))} AirDrop event(s).",
         f"Forwarded e-mails in Mail: {sum(len(d.get('mail', {}).get('forwarded', [])) for d in users.values())} "
         "(see Q8)."]
    Q.append({"id": "Q3", "question": "What was opened, downloaded or transferred?", "answer": a, "tables": {
        "Downloads": _t(dl, ["date", "user", "app", "browser", "url", "file", "origin"]),
        "USB / external disk events": _t(ul.get("usb_and_disks", []), ["date", "process", "message"]),
        "AirDrop events": _t(ul.get("airdrop", []), ["date", "process", "message"]),
        "Messages attachments": _t(att, ["date", "user", "direction", "name", "type", "bytes"]),
        "Recently created/modified user files": _t(rf, ["modified", "created", "user", "path", "size"])}})

    # Q4 dates & times used
    power = (s.get("power") or {}).get("power_events", [])
    locks = ul.get("screen_lock_unlock", [])
    for d in users.values():
        locks = locks + [{"date": e["date"], "_ts": e["_ts"], "process": "knowledgeC", "message": e["event"]}
                         for e in (d.get("knowledge") or {}).get("lock_events", [])]
    activity = [e for e in power if e["event"] in ("Wake", "UserWake", "Start") or "turned on" in e.get("detail", "")]
    activity += [e for e in locks if "unlock" in e.get("message", "").lower() or "login" in e.get("message", "").lower()]
    for u, d in users.items():
        activity += [{"_ts": x["_ts"], "date": x["start"]} for x in (d.get("knowledge") or {}).get("app_usage", [])]
        activity += [{"_ts": x["_ts"], "date": x["date"]} for x in d.get("browsers", {}).get("history", []) if x.get("_ts")]
        activity += [{"_ts": x["_ts"], "date": x.get("date")} for x in d.get("messages", {}).get("attachments", []) if x.get("_ts")]
    days: dict = {}
    for e in activity:
        if not e.get("_ts"):
            continue
        k = fmt(e["_ts"])[:10]
        dd = days.setdefault(k, {"date": k, "first_activity": e["_ts"], "last_activity": e["_ts"], "events": 0})
        dd["first_activity"] = min(dd["first_activity"], e["_ts"])
        dd["last_activity"] = max(dd["last_activity"], e["_ts"])
        dd["events"] += 1
    daily = sorted(({**v, "first_activity": fmt(v["first_activity"])[11:], "last_activity": fmt(v["last_activity"])[11:]}
                    for v in days.values()), key=lambda x: x["date"], reverse=True)
    a = [f"Activity found on {len(daily)} day(s). Daily first/last activity combines wake-ups, screen unlocks/logins, "
         "app use, web browsing and message attachments.",
         f"{len(power)} power event(s) (pmset), {len(locks)} lock/unlock/login event(s)."]
    Q.append({"id": "Q4", "question": "On which dates and times was the computer used?", "answer": a, "tables": {
        "Daily usage (local time)": _t(daily, ["date", "first_activity", "last_activity", "events"]),
        "Screen unlock / login events": _t(sorted(locks, key=lambda x: x.get("_ts") or 0, reverse=True),
                                           ["date", "process", "message"]),
        "Wake / sleep / power events": _t(sorted(power, key=lambda x: x.get("_ts") or 0, reverse=True),
                                          ["date", "event", "detail"]),
        "Logins (last)": _t((s.get("power") or {}).get("logins", []), ["user", "terminal", "raw"])}})

    # Q5 IPs / locations
    net = s.get("networks") or {}
    wifi, leases = net.get("wifi_known_networks", []), net.get("dhcp_leases", [])
    a = [f"{len(wifi)} remembered Wi-Fi network(s) and {len(leases)} recorded IP address lease(s). Networks that are "
         "not the owner's home/work Wi-Fi (e.g. another house, café, hotel) show the Mac was used elsewhere - the "
         "'added' / 'joined' dates show when.",
         "Public (internet) IP addresses are not stored on the Mac; obtain them from the e-mail/Apple ID provider's "
         "sign-in activity pages."]
    Q.append({"id": "Q5", "question": "Which networks / IP addresses were used - was the computer taken elsewhere?",
              "answer": a, "tables": {
                  "Known Wi-Fi networks": _t(wifi, ["network", "added", "joined_by_user", "last_seen"]),
                  "IP address leases (DHCP)": _t(leases, ["lease_start", "interface", "ip_address", "router_ip", "router_mac", "network"])}})

    # Q6 spyware
    sw = s.get("software") or {}
    rm = s.get("remote") or {}
    tcc_all = list(s.get("tcc") or [])
    for u, d in users.items():
        tcc_all += [{**x, "user": u} for x in (d.get("accounts") or {}).get("tcc", [])]
    risky = [t for t in tcc_all if t["granted"] and t["sensitive"] and not t["apple"]]
    flagged = sw.get("remote_or_monitoring_software", []) + rm.get("remote_or_monitoring_hits", [])
    a = [f"{len(flagged)} remote-access / monitoring / stalkerware product match(es).",
         f"{len(risky)} non-Apple app(s) hold sensitive privacy permissions (keystrokes, screen, control, all files, "
         "mic, camera) - each must be recognised by the owner.",
         "Configuration profiles installed: " + ("YES - review" if rm.get("profiles_installed") else "none detected")
         + "; MDM enrolment: " + ("YES" if rm.get("mdm_enrolled") else "no") + ".",
         f"{len(rm.get('third_party_kexts', []))} third-party kernel extension(s) loaded.",
         "Also see the Detailed Findings section for persistence (LaunchAgents/Daemons), suspicious processes and "
         "network connections."]
    Q.append({"id": "Q6", "question": "Is there any hidden spyware or monitoring software?", "answer": a, "tables": {
        "Remote/monitoring software matches": _t(flagged, ["app", "name", "match", "category", "source", "added", "date", "path"]),
        "Sensitive privacy permissions granted to non-Apple apps": _t(risky, ["app", "permission", "changed", "user"]),
        "Privacy permission changes (unified log)": _t(ul.get("privacy_permission_changes", []), ["date", "process", "message"]),
        "Software installed (InstallHistory)": _t(sw.get("install_history", []), ["date", "name", "version", "installer"]),
        "Applications (newest first)": _t(sw.get("applications", []), ["added", "app", "bundle_id", "version", "path"])}})

    # Q7 remote access
    services = [{"service": k, "status": v} for k, v in (rm.get("services") or {}).items()]
    remote_ev = ul.get("remote_access", [])
    a = ["Sharing services: " + "; ".join(f"{x['service']}: {str(x['status'])[:40]}" for x in services[:5])
         if services else "Sharing service status not collected (offline mode).",
         f"{len(remote_ev)} remote-session event(s) (Screen Sharing / SSH / Apple Remote Desktop) in the log.",
         "Also review Q6 (remote-access apps such as TeamViewer/AnyDesk and Screen Recording/Accessibility "
         "permissions) and the Network findings for live connections.",
         "Check Apple ID devices (System Settings > Apple ID) - a device signed into the same Apple ID can read "
         "Messages, Photos, Notes and iCloud Drive without touching this Mac."]
    apple_ids = []
    for u, d in users.items():
        apple_ids += [{**x, "user": u, "services_enabled": ", ".join(x.get("services_enabled") or [])}
                      for x in (d.get("accounts") or {}).get("apple_ids", [])]
    Q.append({"id": "Q7", "question": "Is someone accessing the computer remotely?", "answer": a, "tables": {
        "Sharing / remote services": _t(services, ["service", "status"]),
        "Remote session log events": _t(remote_ev, ["date", "process", "message"]),
        "Apple IDs signed in (sync to other devices)": _t(apple_ids, ["user", "apple_id", "name", "services_enabled"])}})

    # Q8 forwarded / deleted
    fwd = all_u(["mail", "forwarded"])
    dele = all_u(["mail", "deleted"])
    a = [f"{len(fwd)} forwarded e-mail(s) (subject 'Fwd:'/'FW:') and {len(dele)} e-mail(s) in Trash/Deleted or "
         "flagged deleted are still recorded in Apple Mail's index.",
         "Permanently erased messages may still be recoverable from the mail server (Outlook.com 'Recover items "
         "deleted from this folder') or from Time Machine backups."]
    Q.append({"id": "Q8", "question": "What was forwarded or deleted in e-mail?", "answer": a, "tables": {
        "Forwarded e-mails": _t(sorted(fwd, key=lambda x: x.get("_ts") or 0, reverse=True), ["date", "user", "from", "to", "subject", "mailbox"]),
        "Deleted / Trash e-mails": _t(sorted(dele, key=lambda x: x.get("_ts") or 0, reverse=True), ["date", "user", "from", "to", "subject", "mailbox"])}})

    # Q9 tampering
    tamper = ul.get("tamper_indicators", [])
    a = [f"{len(tamper)} log-erase / clock-change / privacy-reset event(s) found.",
         "History tampering (cleared shell history, HISTFILE unset) and other anti-forensic actions appear in "
         "Detailed Findings.", "Access problems during collection (missing permissions) are listed below; they are "
         "limitations, not evidence of tampering."]
    Q.append({"id": "Q9", "question": "Is there any sign that logs or settings were tampered with?", "answer": a,
              "tables": {"Tamper indicators": _t(tamper, ["date", "process", "message"]),
                         "Boot / shutdown events": _t(ul.get("boot_shutdown", []), ["date", "process", "message"]),
                         "Collection access problems": _t(inv.get("access_problems", []), ["path", "error"])}})
    return Q


def collect(ctx) -> None:
    opt = ctx.options
    inv = Investigator(ctx, root=opt.get("mac_root") or "/", days=int(opt.get("days") or 90),
                       watch=opt.get("watch") or [], include_content=bool(opt.get("include_content")),
                       date_from=opt.get("date_from"), date_to=opt.get("date_to")).collect()
    ctx.add_artifact("mac_investigation", inv, "macOS investigation: mail, messages, usage, networks, spyware, remote access")


# ============================================================ OFFLINE MODE
def offline_targets(root: str) -> list:
    t = [os.path.join(root, p) for p in ("private/tmp", "private/var/tmp", "Users/Shared", "Library/LaunchAgents",
                                         "Library/LaunchDaemons", "Library/Application Support", "usr/local/bin")]
    for h in glob.glob(os.path.join(root, "Users", "*")):
        if os.path.basename(h) in ("Shared", "Guest"):
            continue
        t += [os.path.join(h, d) for d in ("Downloads", "Desktop", "Documents", "Library/LaunchAgents",
                                           "Library/Application Support")]
    return [p for p in t if os.path.isdir(p)]


def offline_source(ctx) -> None:
    root = os.path.abspath(ctx.options["mac_root"])
    ver = read_plist(os.path.join(root, "System/Library/CoreServices/SystemVersion.plist")) or {}
    host = read_plist(os.path.join(root, "Library/Preferences/SystemConfiguration/preferences.plist")) or {}
    name = (((host.get("System") or {}).get("System") or {}).get("ComputerName")) if isinstance(host, dict) else None
    ctx.add_artifact("system", {
        "collected_utc": utc_now(), "mode": "OFFLINE - mounted volume", "evidence_root": root,
        "hostname": name or f"(offline volume {os.path.basename(root)})", "os": "macOS",
        "distribution": " ".join(x for x in (ver.get("ProductName", "macOS"), ver.get("ProductVersion"),
                                             f"({ver['ProductBuildVersion']})" if ver.get("ProductBuildVersion") else None) if x),
        "running_as_admin": True, "security_posture": {}, "ip_addresses": [],
        "note": "Live state (processes, connections, logged-in users) does not exist for an offline volume."},
        "Identity of the offline evidence volume")


def offline_persistence(ctx) -> None:
    root = os.path.abspath(ctx.options["mac_root"])
    entries = []
    dirs = [os.path.join(root, d) for d in ("Library/LaunchAgents", "Library/LaunchDaemons")]
    dirs += glob.glob(os.path.join(root, "Users", "*", "Library/LaunchAgents"))
    for d in dirs:
        for f in glob.glob(os.path.join(d, "*.plist")):
            pl = read_plist(f) or {}
            args = pl.get("ProgramArguments") or []
            cmd = " ".join([str(pl.get("Program") or "")] + [str(a) for a in args]).strip()
            st = safe_stat(f) or {}
            entries.append({"mechanism": "launchd", "attack": "T1543.004" if "Daemons" in d else "T1543.001",
                            "location": f, "name": pl.get("Label", os.path.basename(f)), "command": cmd,
                            "mtime": st.get("mtime")})
    ctx.add_artifact("persistence", entries, f"{len(entries)} launch agents/daemons on the offline volume")
