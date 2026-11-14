"""Heuristic detection rules mapped to MITRE ATT&CK.

Every rule receives the collected artifacts (read-only data) plus the IOC database and
returns findings. Rules NEVER touch the live system except for read-only content
inspection of files already enumerated (e.g. web-shell heuristics).
"""

from __future__ import annotations

import os
import re
from typing import Callable

from aletheia.core.util import IS_WINDOWS, is_private_ip, read_text, truncate
from aletheia.detection.frameworks import attack_info

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

RULES: list = []


def rule(rule_id: str, title: str, category: str):
    def deco(fn: Callable):
        RULES.append({"id": rule_id, "title": title, "category": category, "fn": fn})
        return fn
    return deco


def finding(rule_id, title, severity, attack, description, evidence, recommendation, remediation=None,
            confidence="medium", category="", when=None):
    return {
        "rule_id": rule_id, "title": title, "severity": severity, "confidence": confidence, "category": category,
        "attack": [attack_info(a) for a in ([attack] if isinstance(attack, str) else attack) if a],
        "description": description, "evidence": evidence, "recommendation": recommendation,
        "remediation": remediation or [], "event_time_utc": when,
    }


# ----------------------------------------------------------------- patterns
TEMP_RE = re.compile(r"(^|[\\/])(tmp|var[\\/]tmp|dev[\\/]shm|temp|users[\\/]public|perflogs|appdata[\\/]local[\\/]temp|"
                     r"windows[\\/]temp|programdata[\\/][^\\/]+\.exe|downloads)([\\/]|$)", re.I)
REVSHELL = [
    (re.compile(r"/dev/(tcp|udp)/\d", re.I), "bash /dev/tcp reverse shell"),
    (re.compile(r"\b(nc|ncat|netcat)\b[^|;]*\s-(e|c)\s", re.I), "netcat with -e/-c (shell binding)"),
    (re.compile(r"socat\b.*exec:", re.I), "socat exec shell"),
    (re.compile(r"mkfifo\b.*\b(nc|ncat|sh)\b", re.I), "named-pipe reverse shell"),
    (re.compile(r"python[23]?\b.*socket.*(subprocess|pty\.spawn|os\.dup2)", re.I), "python reverse shell"),
    (re.compile(r"perl\b.*-e.*socket", re.I), "perl reverse shell"),
    (re.compile(r"php\b.*fsockopen", re.I), "php reverse shell"),
    (re.compile(r"\bsh\s+-i\b.*[<>]&", re.I), "interactive shell redirected to socket"),
    (re.compile(r"New-Object\s+System\.Net\.Sockets\.TCPClient", re.I), "PowerShell TCP reverse shell"),
]
DOWNLOAD_EXEC = [
    (re.compile(r"(curl|wget)\b[^|;]*\|\s*(ba|z|da)?sh\b", re.I), "download piped to shell"),
    (re.compile(r"(curl|wget)\b.*(-o|-O|--output)\s*\S*(/tmp|/dev/shm|/var/tmp)", re.I), "download into temp dir"),
    (re.compile(r"base64\s+(-d|--decode)\b.*\|\s*(ba)?sh", re.I), "base64-decoded script executed"),
    (re.compile(r"chmod\s+(\+x|[0-7]*7[0-7]*)\s+(/tmp|/dev/shm|/var/tmp)", re.I), "making temp file executable"),
    (re.compile(r"(DownloadString|DownloadFile|Invoke-WebRequest|iwr |Net\.WebClient|Start-BitsTransfer)", re.I),
     "PowerShell download cradle"),
    (re.compile(r"\b(IEX|Invoke-Expression)\b", re.I), "PowerShell Invoke-Expression"),
    (re.compile(r"FromBase64String", re.I), "Base64 decoding in script"),
]
PS_ENCODED = re.compile(r"powershell(\.exe)?\b.*\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I)
PS_HIDDEN = re.compile(r"powershell(\.exe)?\b.*(-w(indowstyle)?\s+hid|-nop\b.*-w\s+1|bypass.*hidden)", re.I)
LOLBINS = [
    (re.compile(r"certutil(\.exe)?\b.*(-urlcache|-decode|-encode|verifyctl)", re.I), "certutil download/decode", "T1105"),
    (re.compile(r"mshta(\.exe)?\b.*(https?:|javascript:|vbscript:)", re.I), "mshta remote/script execution", "T1218"),
    (re.compile(r"regsvr32(\.exe)?\b.*/i:\s*https?", re.I), "regsvr32 squiblydoo", "T1218"),
    (re.compile(r"rundll32(\.exe)?\b.*(javascript:|http)", re.I), "rundll32 script/remote execution", "T1218"),
    (re.compile(r"bitsadmin(\.exe)?\b.*/transfer", re.I), "bitsadmin download", "T1105"),
    (re.compile(r"wmic(\.exe)?\b.*process\s+call\s+create", re.I), "wmic process creation", "T1218"),
    (re.compile(r"msiexec(\.exe)?\b.*/i\s*https?:", re.I), "msiexec remote package", "T1218"),
    (re.compile(r"vssadmin(\.exe)?\b.*delete\s+shadows", re.I), "shadow copy deletion (ransomware precursor)", "T1486"),
    (re.compile(r"wbadmin(\.exe)?\b.*delete\s+catalog", re.I), "backup catalog deletion", "T1486"),
    (re.compile(r"bcdedit(\.exe)?\b.*recoveryenabled\s+no", re.I), "recovery disabled", "T1486"),
    (re.compile(r"(procdump|rundll32).*(lsass|comsvcs\.dll.*minidump)", re.I), "LSASS memory dump", "T1003.001"),
    (re.compile(r"reg(\.exe)?\s+save\s+hklm\\(sam|security|system)", re.I), "registry hive credential dump", "T1003"),
]
OFFENSIVE_TOOLS = {
    "mimikatz": ("T1003", "critical"), "rubeus": ("T1003", "critical"), "lazagne": ("T1003", "critical"),
    "sharphound": ("T1588", "high"), "bloodhound": ("T1588", "high"), "pwdump": ("T1003", "critical"),
    "wce.exe": ("T1003", "critical"), "gsecdump": ("T1003", "critical"), "nanodump": ("T1003", "critical"),
    "xmrig": ("T1496", "high"), "kinsing": ("T1496", "critical"), "kdevtmpfsi": ("T1496", "critical"),
    "minerd": ("T1496", "high"), "cpuminer": ("T1496", "high"), "nbminer": ("T1496", "high"),
    "chisel": ("T1219", "high"), "ligolo": ("T1219", "high"), "frpc": ("T1219", "medium"),
    "ngrok": ("T1219", "medium"), "meterpreter": ("T1059", "critical"), "beacon.exe": ("T1059", "critical"),
    "cobaltstrike": ("T1059", "critical"), "sliver": ("T1059", "high"), "psexesvc": ("T1569.002", "medium"),
    "pspy": ("T1588", "medium"), "linpeas": ("T1588", "high"), "winpeas": ("T1588", "high"),
    "tsunami": ("T1059", "critical"), "kaiten": ("T1059", "critical"), "mirai": ("T1059", "critical"),
}
MINER = re.compile(r"(stratum\+(tcp|ssl)://|--donate-level|\bnicehash\b|\bmoneroocean\b|\bminexmr\b|"
                   r"supportxmr|\bxmrpool\b|--cpu-priority)", re.I)
WIN_SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
                    "wininit.exe", "spoolsv.exe", "explorer.exe", "taskhostw.exe", "lsm.exe", "conhost.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe", "mspub.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "bash", "sh", "dash", "zsh"}
C2_PORTS = {4444, 4445, 1337, 31337, 6666, 6667, 6697, 12345, 54321, 9001, 9050, 1080, 3333, 5555, 7777, 14444,
            45700}
HIST_SUSPICIOUS = [
    (re.compile(r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|export\s+HISTSIZE=0", re.I),
     "command history tampering", "T1070.003"),
    (re.compile(r"rm\s+-rf?\s+/var/log|>\s*/var/log/(auth|secure|syslog|wtmp|lastlog)|shred\b.*log", re.I),
     "log destruction", "T1070.003"),
    (re.compile(r"(useradd|adduser)\b.*(-o\s+-u\s*0|-u\s*0\b)", re.I), "UID-0 account creation", "T1136.001"),
    (re.compile(r"echo\s+.*>>\s*\S*authorized_keys", re.I), "SSH key planted via shell", "T1098.004"),
    (re.compile(r"(iptables\s+-F|ufw\s+disable|systemctl\s+(stop|disable)\s+(firewalld|auditd|apparmor))", re.I),
     "security control disabled", "T1562.004"),
    (re.compile(r"Set-MpPreference\s+.*-Disable|Add-MpPreference\s+-ExclusionPath", re.I),
     "Defender disabled/excluded", "T1562.001"),
]
WEBSHELL = re.compile(r"(eval\s*\(\s*(base64_decode|gzinflate|str_rot13|\$_(POST|GET|REQUEST|COOKIE))|"
                      r"(system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|"
                      r"assert\s*\(\s*\$_(POST|GET|REQUEST)|Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter|"
                      r"Process\.Start\(\s*Request|cmd\.exe\s*/c\s*\"\s*\+\s*Request)", re.I)
WEB_EXT = (".php", ".phtml", ".php5", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cfm")


def _ev(artifact, ref, excerpt=None, **extra):
    d = {"artifact": artifact, "ref": ref}
    if excerpt is not None:
        d["excerpt"] = truncate(excerpt, 600)
    d.update(extra)
    return d


def _kill(p):
    return {"type": "kill_process", "pid": p.get("pid"), "name": p.get("name"), "exe": p.get("exe"),
            "start_time_utc": p.get("start_time_utc"), "exe_sha256": p.get("exe_sha256")}


def _quarantine(path, sha256=None):
    return {"type": "quarantine_file", "path": path, "sha256": sha256}


def _text_hits(text: str):
    hits = []
    for rx, label in REVSHELL:
        if rx.search(text):
            hits.append(("revshell", label))
    for rx, label in DOWNLOAD_EXEC:
        if rx.search(text):
            hits.append(("download", label))
    if PS_ENCODED.search(text):
        hits.append(("encoded", "encoded PowerShell command"))
    for rx, label, _t in LOLBINS:
        if rx.search(text):
            hits.append(("lolbin", label))
    if MINER.search(text):
        hits.append(("miner", "crypto-miner configuration"))
    return hits


# ================================================================= PROCESSES
@rule("PROC-001", "Process running from a deleted executable", "process")
def proc_deleted(a, db):
    out = []
    for p in a.get("processes", []):
        exe = p.get("exe") or ""
        if not p.get("exe_deleted") or exe.startswith("/memfd:runc_cloned"):
            continue  # runc legitimately re-executes itself from a memfd
        if exe.startswith("/memfd:"):
            sev = "high"  # fileless execution
        elif exe.startswith(("/usr/", "/bin/", "/sbin/", "/lib")):
            sev = "low"  # typically a binary replaced by a package upgrade while running
        else:
            sev = "high"
        out.append(finding("PROC-001", f"Process {p.get('name')} (PID {p.get('pid')}) runs from a deleted/fileless binary",
                           sev, ["T1620", "T1027"],
                           "The on-disk executable for this running process has been deleted or is memory-only "
                           "(memfd). Malware commonly deletes itself after launch to evade file-based detection.",
                           [_ev("processes", f"pid={p.get('pid')}", p.get("cmdline"), exe=p.get("exe"))],
                           "Acquire process memory with a dedicated tool (e.g. AVML/LiME + Volatility) BEFORE "
                           "terminating, then terminate the process.",
                           [_kill(p)], confidence="high", category="process"))
    return out


@rule("PROC-002", "Process executing from a temporary / user-writable location", "process")
def proc_temp(a, db):
    out = []
    for p in a.get("processes", []):
        exe = p.get("exe") or ""
        if exe and TEMP_RE.search(exe):
            out.append(finding("PROC-002", f"{p.get('name')} (PID {p.get('pid')}) runs from {exe}", "high",
                               ["T1036.005", "T1204"],
                               "Legitimate software rarely executes from temporary or world-writable directories; "
                               "this is a common staging location for droppers and implants.",
                               [_ev("processes", f"pid={p.get('pid')}", p.get("cmdline"), exe=exe,
                                    sha256=p.get("exe_sha256"), user=p.get("user"))],
                               "Verify the binary (hash reputation, signature). If malicious terminate and quarantine.",
                               [_kill(p), _quarantine(exe, p.get("exe_sha256"))], category="process"))
    return out


@rule("PROC-003", "Suspicious command line (reverse shell, download-exec, LOLBin, miner)", "process")
def proc_cmdline(a, db):
    out = []
    for p in a.get("processes", []):
        cmd = p.get("cmdline") or ""
        hits = _text_hits(cmd)
        if PS_HIDDEN.search(cmd):
            hits.append(("hidden", "hidden-window PowerShell"))
        if not hits:
            continue
        kinds = {h[0] for h in hits}
        sev = "critical" if kinds & {"revshell", "miner"} else "high"
        techniques = []
        if "revshell" in kinds:
            techniques += ["T1059.004" if not IS_WINDOWS else "T1059.001"]
        if "download" in kinds:
            techniques += ["T1105"]
        if "encoded" in kinds or "hidden" in kinds:
            techniques += ["T1059.001", "T1027"]
        if "lolbin" in kinds:
            techniques += [t for rx, _l, t in LOLBINS if rx.search(cmd)]
        if "miner" in kinds:
            techniques += ["T1496"]
        out.append(finding("PROC-003", f"Suspicious command line in PID {p.get('pid')} ({p.get('name')}): "
                           + ", ".join(sorted({h[1] for h in hits})), sev, sorted(set(techniques)),
                           "The process command line matches patterns used by attackers for remote shells, "
                           "payload download/execution, defense evasion or crypto-mining.",
                           [_ev("processes", f"pid={p.get('pid')}", cmd, exe=p.get("exe"), user=p.get("user"),
                                start=p.get("start_time_utc"))],
                           "Terminate the process, identify the parent/launcher and remove its persistence.",
                           [_kill(p)], confidence="high" if sev == "critical" else "medium", category="process",
                           when=p.get("start_time_utc")))
    return out


@rule("PROC-004", "Known offensive / crypto-mining tool running", "process")
def proc_tools(a, db):
    out = []
    for p in a.get("processes", []):
        hay = f"{p.get('name') or ''} {p.get('exe') or ''}".lower()
        for tool, (tech, sev) in OFFENSIVE_TOOLS.items():
            if re.search(r"(^|[\\/\s])" + re.escape(tool), hay):
                out.append(finding("PROC-004", f"Known attacker tool '{tool}' running (PID {p.get('pid')})", sev,
                                   tech, f"A process name/path matches the known tool '{tool}'.",
                                   [_ev("processes", f"pid={p.get('pid')}", p.get("cmdline"), exe=p.get("exe"))],
                                   "Confirm by hash; terminate and quarantine; investigate initial access.",
                                   [_kill(p)] + ([_quarantine(p["exe"], p.get("exe_sha256"))] if p.get("exe") else []),
                                   category="process"))
                break
    return out


@rule("PROC-005", "LD_PRELOAD injected into a running process", "process")
def proc_ldpreload(a, db):
    return [finding("PROC-005", f"PID {p.get('pid')} ({p.get('name')}) has LD_PRELOAD={p['env_ld_preload']}", "high",
                    "T1574.006", "LD_PRELOAD forces a shared library into the process and is used by userland "
                    "rootkits to hide files, processes and connections.",
                    [_ev("processes", f"pid={p.get('pid')}", p.get("cmdline"), ld_preload=p["env_ld_preload"])],
                    "Inspect the preloaded library; if malicious quarantine it and restart affected services.",
                    [_quarantine(p["env_ld_preload"].split(":")[0])], category="process")
            for p in a.get("processes", []) if p.get("env_ld_preload")]


@rule("PROC-006", "System process name masquerading", "process")
def proc_masq(a, db):
    out = []
    for p in a.get("processes", []):
        name = (p.get("name") or "").lower()
        exe = (p.get("exe") or "").lower()
        if name in WIN_SYSTEM_NAMES and exe:
            if "\\windows\\system32\\" not in exe and "\\windows\\syswow64\\" not in exe and \
                    not (name == "explorer.exe" and exe.endswith("\\windows\\explorer.exe")):
                out.append(finding("PROC-006", f"{name} running from unexpected path {p.get('exe')}", "critical",
                                   "T1036.005", "A Windows system process name is running outside System32.",
                                   [_ev("processes", f"pid={p.get('pid')}", p.get("cmdline"), exe=p.get("exe"))],
                                   "Terminate and quarantine the impostor binary.",
                                   [_kill(p), _quarantine(p["exe"], p.get("exe_sha256"))], confidence="high",
                                   category="process"))
        if not IS_WINDOWS and name.startswith("[") and p.get("exe"):
            out.append(finding("PROC-006", f"User-space process disguised as kernel thread: {p.get('cmdline')}",
                               "high", "T1036.005", "Kernel threads have no executable; a bracketed name with a "
                               "backing binary is a classic Linux malware disguise.",
                               [_ev("processes", f"pid={p.get('pid')}", p.get("cmdline"), exe=p.get("exe"))],
                               "Terminate and quarantine.", [_kill(p), _quarantine(p["exe"], p.get("exe_sha256"))],
                               category="process"))
        if not IS_WINDOWS and (p.get("cmdline") or "").startswith("[") and p.get("exe") and not name.startswith("["):
            out.append(finding("PROC-006", f"Process {name} rewrote argv to look like a kernel thread",
                               "high", "T1036.005", "argv[0] was overwritten with a bracketed kernel-thread name.",
                               [_ev("processes", f"pid={p.get('pid')}", p.get("cmdline"), exe=p.get("exe"))],
                               "Terminate and quarantine.", [_kill(p), _quarantine(p["exe"], p.get("exe_sha256"))],
                               category="process"))
    return out


@rule("PROC-007", "Office application spawned a shell/script host", "process")
def proc_office(a, db):
    procs = a.get("processes", [])
    by_pid = {p.get("pid"): p for p in procs}
    out = []
    for p in procs:
        parent = by_pid.get(p.get("ppid"))
        if parent and (parent.get("name") or "").lower() in OFFICE and (p.get("name") or "").lower() in SHELLS:
            out.append(finding("PROC-007", f"{parent.get('name')} spawned {p.get('name')} (PID {p.get('pid')})",
                               "high", ["T1204", "T1059"], "Office documents launching shells are a hallmark of "
                               "macro/phishing payloads.",
                               [_ev("processes", f"pid={p.get('pid')}", p.get("cmdline"), parent=parent.get("cmdline"))],
                               "Terminate the child; collect the originating document; reset user credentials.",
                               [_kill(p)], category="process"))
    return out


@rule("PROC-008", "Process executable hash matches IOC", "ioc")
def proc_ioc(a, db):
    out = []
    for p in a.get("processes", []):
        m = db.match_hash(p.get("exe_sha256"), p.get("exe_sha1"), p.get("exe_md5"))
        if m:
            out.append(finding("PROC-008", f"Running process {p.get('name')} matches IOC ({m.get('threat') or m['source']})",
                               "critical", "T1204", "The SHA-256/SHA-1/MD5 of the running executable is listed in a "
                               "loaded threat-intelligence feed.",
                               [_ev("processes", f"pid={p.get('pid')}", p.get("cmdline"), exe=p.get("exe"), ioc=m)],
                               "Terminate, quarantine and hunt for the same hash enterprise-wide.",
                               [_kill(p), _quarantine(p["exe"], p.get("exe_sha256"))], confidence="high",
                               category="ioc"))
    return out


# ================================================================== NETWORK
@rule("NET-001", "Connection to IOC IP address", "ioc")
def net_ioc(a, db):
    out = []
    for c in a.get("network_connections", []):
        ip = c.get("remote_addr") or ""
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        m = db.match_ip(ip) if ip else None
        if m:
            out.append(finding("NET-001", f"Connection to known-malicious {ip}:{c.get('remote_port')} by "
                               f"{c.get('process') or c.get('pid')}", "critical", "T1071",
                               "The remote endpoint is listed in a loaded threat-intelligence feed (e.g. botnet C2).",
                               [_ev("network_connections", f"pid={c.get('pid')}", None, connection=c, ioc=m)],
                               "Block the address at host and perimeter firewall; terminate the owning process.",
                               [{"type": "block_ip", "ip": ip}] +
                               ([{"type": "kill_process", "pid": c.get("pid"), "name": c.get("process")}] if c.get("pid") else []),
                               confidence="high", category="ioc"))
    return out


@rule("NET-002", "Established connection on a port commonly used by backdoors / C2 / miners", "network")
def net_ports(a, db):
    out = []
    for c in a.get("network_connections", []):
        if c.get("state") == "ESTABLISHED" and c.get("remote_port") in C2_PORTS and \
                not is_private_ip((c.get("remote_addr") or "").replace("::ffff:", "")):
            out.append(finding("NET-002", f"{c.get('process') or 'PID ' + str(c.get('pid'))} connected to "
                               f"{c.get('remote_addr')}:{c.get('remote_port')}", "medium", "T1571",
                               "Outbound connection to a non-standard port frequently used by Metasploit, IRC "
                               "botnets, Tor or mining pools.",
                               [_ev("network_connections", f"pid={c.get('pid')}", None, connection=c)],
                               "Validate the business purpose; block if not legitimate.",
                               [{"type": "block_ip", "ip": c.get("remote_addr").replace("::ffff:", "")}],
                               confidence="low", category="network"))
    return out


@rule("NET-003", "Shell or interpreter owns a network socket", "network")
def net_shell(a, db):
    procs = {p.get("pid"): p for p in a.get("processes", [])}
    out = []
    for c in a.get("network_connections", []):
        p = procs.get(c.get("pid"))
        if not p:
            continue
        n = (p.get("name") or "").lower()
        if n in ("bash", "sh", "dash", "zsh", "ksh", "nc", "ncat", "netcat", "socat", "cmd.exe") and \
                c.get("state") in ("ESTABLISHED", "LISTEN"):
            out.append(finding("NET-003", f"{n} (PID {p.get('pid')}) holds a {c.get('state')} socket "
                               f"{c.get('local_port')}->{c.get('remote_addr')}:{c.get('remote_port')}", "critical",
                               ["T1059.004", "T1071"], "Shells do not normally own network sockets; this is the "
                               "signature of a bind or reverse shell.",
                               [_ev("network_connections", f"pid={c.get('pid')}", p.get("cmdline"), connection=c)],
                               "Terminate the shell, block the remote address, find how it was launched.",
                               [_kill(p)] + ([{"type": "block_ip", "ip": c["remote_addr"]}]
                                             if c.get("remote_addr") and not is_private_ip(c["remote_addr"]) else []),
                               confidence="high", category="network"))
    return out


SECURITY_DOMAINS = ("microsoft.com", "windowsupdate.com", "update.microsoft", "defender", "symantec", "mcafee",
                    "sophos", "kaspersky", "eset", "bitdefender", "malwarebytes", "crowdstrike", "sentinelone",
                    "virustotal", "google.com", "apple.com", "ubuntu.com", "debian.org", "github.com")


@rule("NET-004", "Hosts-file hijack or IOC domain in DNS data", "network")
def net_hosts(a, db):
    out = []
    cfg = a.get("network_config", {}) or {}
    for h in cfg.get("hosts_entries", []):
        for name in h.get("names", []):
            nl = name.lower()
            m = db.match_domain(nl)
            if m or (any(s in nl for s in SECURITY_DOMAINS) and h.get("ip") not in ("127.0.0.1", "::1", "0.0.0.0")):
                out.append(finding("NET-004", f"Hosts file maps {name} -> {h.get('ip')}",
                                   "high" if m else "medium", ["T1565.001", "T1562.001"],
                                   "Hosts-file entries can redirect security/update traffic or point at attacker "
                                   "infrastructure.",
                                   [_ev("network_config", f"{cfg.get('hosts_file')}:{h.get('line')}", h.get("raw"), ioc=m)],
                                   "Remove the entry after confirming it is not an approved override.",
                                   [{"type": "comment_out_line", "file": cfg.get("hosts_file"), "line": h.get("line"),
                                     "content": h.get("raw")}], category="network"))
    for name in cfg.get("dns_cache_names", []) or []:
        m = db.match_domain(name)
        if m:
            out.append(finding("NET-004", f"DNS cache contains IOC domain {name}", "high", "T1071",
                               "The host recently resolved a domain listed in threat intelligence.",
                               [_ev("network_config", "dns_cache", name, ioc=m)],
                               "Identify the process that resolved it (enable DNS logging/Sysmon 22).",
                               [{"type": "manual", "text": f"Sinkhole/block domain {name} at DNS resolver"}],
                               confidence="high", category="ioc"))
    return out


# ============================================================== PERSISTENCE
@rule("PERS-001", "Malicious-looking persistence entry", "persistence")
def pers_suspicious(a, db):
    out = []
    for e in a.get("persistence", []):
        if e.get("mechanism") == "kernel-module":
            continue
        cmd = e.get("command") or ""
        hits = _text_hits(cmd)
        temp = bool(TEMP_RE.search(cmd))
        ioc_hits = db.scan_text(cmd)
        hidden_exec = bool(re.search(r"[\\/]\.[^\\/\s]+[\\/]?[^\\/\s]*\s*$|[\\/]\.[a-z0-9_-]+[\\/]", cmd, re.I)) and \
            e.get("mechanism") in ("cron", "systemd", "launchd", "registry-run", "scheduled-task", "service",
                                   "xdg-autostart")
        if e.get("vendor_dir") and not (hits or ioc_hits):
            continue
        if e.get("mechanism") == "shell-profile" and not (hits or ioc_hits):
            continue  # profiles legitimately contain many commands; only flag clear abuse
        if not (hits or temp or ioc_hits or hidden_exec):
            continue
        reasons = sorted({h[1] for h in hits})
        if temp:
            reasons.append("executes from temp/user-writable path")
        if hidden_exec:
            reasons.append("executes a hidden file/directory")
        if ioc_hits:
            reasons.append("contains IOC " + ", ".join(h["value"] for h in ioc_hits))
        sev = "critical" if (ioc_hits or any(h[0] in ("revshell", "miner") for h in hits)) else "high"
        rem = [e["remediation_hint"]] if e.get("remediation_hint") else [
            {"type": "manual", "text": f"Remove {e.get('mechanism')} entry {e.get('name')} at {e.get('location')}"}]
        out.append(finding("PERS-001", f"Suspicious {e.get('mechanism')} persistence: {truncate(e.get('name'), 80)}",
                           sev, e.get("attack") or "T1547", "Autostart entry: " + "; ".join(reasons) + ".",
                           [_ev("persistence", f"{e.get('location')}", cmd, mechanism=e.get("mechanism"),
                                mtime=e.get("mtime"), user=e.get("user"))],
                           "Confirm the entry is not authorised, then disable it and remove the referenced payload.",
                           rem, confidence="high" if sev == "critical" else "medium", category="persistence",
                           when=e.get("mtime")))
    return out


@rule("PERS-002", "Dynamic-linker preload configured (/etc/ld.so.preload)", "persistence")
def pers_ldpreload(a, db):
    return [finding("PERS-002", f"/etc/ld.so.preload loads {e.get('name')}", "critical", "T1574.006",
                    "Every dynamically-linked program on the system will load this library. This is the primary "
                    "mechanism of userland rootkits (e.g. Azazel, Jynx, libprocesshider).",
                    [_ev("persistence", "/etc/ld.so.preload", e.get("raw"), mtime=e.get("mtime"))],
                    "Remove the entry, quarantine the library, then re-scan (rootkits hide while loaded).",
                    [e["remediation_hint"], _quarantine(e.get("name"))], confidence="high", category="persistence",
                    when=e.get("mtime"))
            for e in a.get("persistence", []) if e.get("mechanism") == "ld.so.preload"]


@rule("PERS-003", "Windows autostart hijack (Winlogon / AppInit / IFEO / LSA / WMI)", "persistence")
def pers_windows_hijack(a, db):
    out = []
    for e in a.get("persistence", []):
        m, cmd = e.get("mechanism"), (e.get("command") or "").strip()
        bad = None
        if m == "registry-shell" and cmd.lower() not in ("explorer.exe", ""):
            bad = ("critical", "Winlogon Shell is not explorer.exe")
        elif m == "registry-userinit" and cmd.lower().rstrip(",") not in (
                r"c:\windows\system32\userinit.exe", "userinit.exe"):
            bad = ("critical", "Winlogon Userinit has extra programs")
        elif m == "registry-appinit_dlls" and cmd:
            bad = ("high", "AppInit_DLLs is populated")
        elif m == "ifeo-debugger":
            bad = ("high", "Image File Execution Options debugger hijack")
        elif m == "wmi-subscription" and "consumer" in (e.get("location") or "").lower():
            bad = ("high", "WMI event consumer executes code")
        elif m == "registry-bootexecute" and cmd.lower() not in ("autocheck autochk *", "autocheck autochk /q /v *"):
            bad = ("high", "BootExecute modified")
        if bad:
            out.append(finding("PERS-003", bad[1] + f": {truncate(cmd, 120)}", bad[0], e.get("attack"),
                               "Windows autostart extension point used for stealthy persistence.",
                               [_ev("persistence", e.get("location"), cmd, name=e.get("name"))],
                               "Restore the default value after confirming it is not legitimate software.",
                               [e.get("remediation_hint") or {"type": "manual",
                                                              "text": f"Restore default value of {e.get('location')}\\{e.get('name')}"}],
                               category="persistence"))
    return out


@rule("PERS-004", "Unsigned / out-of-tree kernel module loaded", "persistence")
def pers_kmod(a, db):
    out = []
    for e in a.get("persistence", []):
        if e.get("mechanism") == "kernel-module" and ("E" in (e.get("taint") or "") or "O" in (e.get("taint") or "")):
            out.append(finding("PERS-004", f"Kernel module {e.get('name')} is out-of-tree/unsigned {e.get('taint')}",
                               "medium" if "E" in e.get("taint", "") else "low", ["T1547.006", "T1014"],
                               "Out-of-tree or unsigned modules are legitimate for some drivers (GPU, VM tools) but "
                               "are also how kernel rootkits load.",
                               [_ev("persistence", "/proc/modules", e.get("command"))],
                               "Verify the module's origin and signature (modinfo).",
                               [{"type": "manual", "text": f"Validate kernel module {e.get('name')} (modinfo); "
                                 "if malicious remove with rmmod and delete from /lib/modules + rebuild initramfs"}],
                               confidence="low", category="persistence"))
    return out


@rule("PERS-005", "PAM module executes external program", "persistence")
def pers_pam(a, db):
    return [finding("PERS-005", f"pam_exec configured in {e.get('location')}", "medium", "T1556.003",
                    "pam_exec runs a program during authentication and can capture plaintext passwords.",
                    [_ev("persistence", e.get("location"), e.get("command"))],
                    "Verify the referenced script is authorised.", [e.get("remediation_hint") or
                                                                    {"type": "comment_out_line", "file": e.get("location"),
                                                                     "line": e.get("line"), "content": e.get("raw")}],
                    category="persistence") for e in a.get("persistence", []) if e.get("mechanism") == "pam_exec"]


# ================================================================= ACCOUNTS
@rule("ACCT-001", "Multiple accounts with UID 0 (root-equivalent)", "accounts")
def acct_uid0(a, db):
    users = (a.get("accounts") or {}).get("users", [])
    roots = [u for u in users if isinstance(u, dict) and u.get("uid") == 0]
    if len(roots) > 1:
        extra = [u for u in roots if u.get("name") != "root"]
        return [finding("ACCT-001", "Additional UID-0 account(s): " + ", ".join(u["name"] for u in extra), "critical",
                        ["T1136.001", "T1078"], "Any account with UID 0 has full root privileges.",
                        [_ev("accounts", "/etc/passwd", str(extra))],
                        "Lock the account(s) immediately and investigate when they were created.",
                        [{"type": "disable_account", "user": u["name"]} for u in extra], confidence="high",
                        category="accounts")]
    return []


@rule("ACCT-002", "Passwordless sudo for non-root principals", "accounts")
def acct_sudo(a, db):
    out = []
    for r in (a.get("accounts") or {}).get("sudoers_rules", []):
        rule_txt = r.get("rule", "")
        if "NOPASSWD" in rule_txt and "ALL" in rule_txt and not rule_txt.startswith("root"):
            out.append(finding("ACCT-002", f"NOPASSWD sudo rule: {truncate(rule_txt, 100)}", "medium", "T1548.003",
                               "Unrestricted passwordless sudo lets anyone controlling the account become root.",
                               [_ev("accounts", f"{r.get('file')}:{r.get('line')}", rule_txt)],
                               "Confirm it is authorised; otherwise remove it (validate with visudo).",
                               [{"type": "manual", "text": f"Review/remove sudo rule in {r.get('file')} line "
                                 f"{r.get('line')} using visudo"}], confidence="low", category="accounts"))
    return out


@rule("ACCT-003", "SSH authorized_keys with forced command or planted keys", "accounts")
def acct_keys(a, db):
    out = []
    for k in (a.get("accounts") or {}).get("authorized_keys", []):
        opts = k.get("options") or ""
        if "command=" in opts or db.scan_text(k.get("raw", "")):
            out.append(finding("ACCT-003", f"authorized_keys entry with options in {k.get('file')}", "medium",
                               "T1098.004", "Keys with forced commands or environment options can provide a hidden "
                               "backdoor.", [_ev("accounts", f"{k.get('file')}:{k.get('line')}", k.get("raw"),
                                                 mtime=k.get("mtime"))],
                               "Remove the key if the owner does not recognise it.",
                               [{"type": "comment_out_line", "file": k.get("file"), "line": k.get("line"),
                                 "content": k.get("raw")}], category="accounts"))
    keys = (a.get("accounts") or {}).get("authorized_keys", [])
    if keys:
        out.append(finding("ACCT-004", f"{len(keys)} SSH authorized key(s) present - review required", "info",
                           "T1098.004", "Inventory of SSH public keys that can log in without a password. Each key "
                           "should be attributable to a known person.",
                           [_ev("accounts", f"{k.get('file')}:{k.get('line')}", k.get("comment"), mtime=k.get("mtime"))
                            for k in keys[:50]],
                           "Validate every key against an access register.", [], confidence="high",
                           category="accounts"))
    return out


@rule("AUTH-001", "Brute-force activity and possible successful compromise", "logs")
def auth_bruteforce(a, db):
    logs = a.get("logs") or {}
    out = []
    failed = (logs.get("auth_summary") or {}).get("failed_by_ip", {})
    accepted = (logs.get("auth_summary") or {}).get("accepted", {})
    accepted_ips = {k.split("@", 1)[1]: k for k in accepted}
    for ip, n in sorted(failed.items(), key=lambda x: -x[1]):
        if n < 20:
            continue
        success = accepted_ips.get(ip)
        out.append(finding("AUTH-001", f"{n} failed logins from {ip}" + (f" followed by SUCCESS ({success})" if success else ""),
                           "critical" if success else "medium", ["T1110", "T1021.004"] + (["T1078"] if success else []),
                           "Repeated authentication failures from one source indicate password guessing."
                           + (" A later successful login from the same source suggests the guess succeeded." if success else ""),
                           [_ev("logs", "auth_summary", f"failed={n}; accepted={success}")],
                           "Block the source; if a login succeeded, reset that account's credentials and review its "
                           "activity.", [{"type": "block_ip", "ip": ip}] if not is_private_ip(ip) else
                           [{"type": "manual", "text": f"Investigate internal host {ip}"}],
                           confidence="high" if success else "medium", category="logs"))
    win = [e for e in logs.get("windows_events", []) if e.get("event_id") == 4625]
    if len(win) >= 20:
        by_ip: dict = {}
        for e in win:
            ip = (e.get("data") or {}).get("IpAddress", "-")
            by_ip[ip] = by_ip.get(ip, 0) + 1
        out.append(finding("AUTH-001", f"{len(win)} failed Windows logons (4625)", "medium", "T1110",
                           "Repeated failed logons recorded in the Security log.",
                           [_ev("logs", "Security/4625", str(dict(sorted(by_ip.items(), key=lambda x: -x[1])[:10])))],
                           "Block offending sources and enforce account lockout.",
                           [{"type": "block_ip", "ip": ip} for ip, n in by_ip.items()
                            if n >= 20 and ip not in ("-", "") and not is_private_ip(ip)], category="logs"))
    return out


WIN_EVENT_RULES = {
    1102: ("critical", "Security audit log was cleared", ["T1070.001"]),
    104: ("high", "An event log was cleared", ["T1070.001"]),
    4720: ("medium", "Local user account created", ["T1136.001"]),
    4732: ("medium", "Member added to a security-enabled local group", ["T1098"]),
    4728: ("medium", "Member added to a global security group", ["T1098"]),
    4719: ("high", "System audit policy was changed", ["T1562.001"]),
    4698: ("medium", "Scheduled task created", ["T1053.005"]),
    7045: ("medium", "New service installed", ["T1543.003", "T1569.002"]),
    1116: ("high", "Microsoft Defender detected malware", ["T1204"]),
    1117: ("medium", "Microsoft Defender took action on malware", ["T1204"]),
    5001: ("high", "Defender real-time protection disabled", ["T1562.001"]),
    5010: ("high", "Defender anti-spyware scanning disabled", ["T1562.001"]),
    5012: ("high", "Defender anti-virus scanning disabled", ["T1562.001"]),
    5007: ("low", "Defender configuration changed", ["T1562.001"]),
    1149: ("info", "RDP authentication succeeded", ["T1021.001"]),
}


@rule("EVT-001", "Security-relevant Windows events", "logs")
def evt_windows(a, db):
    out = []
    groups: dict = {}
    for e in (a.get("logs") or {}).get("windows_events", []):
        eid = e.get("event_id")
        if eid in WIN_EVENT_RULES:
            groups.setdefault(eid, []).append(e)
        if eid == 4104:
            text = " ".join((e.get("data") or {}).values())
            hits = _text_hits(text)
            if hits or re.search(r"Invoke-Mimikatz|AmsiUtils|amsiInitFailed|VirtualAlloc|Invoke-Shellcode", text, re.I):
                out.append(finding("EVT-002", "Malicious PowerShell script block logged (4104)", "high",
                                   ["T1059.001", "T1027"], "Script-block logging captured attacker tradecraft: "
                                   + ", ".join(sorted({h[1] for h in hits}) or ["AMSI bypass / shellcode"]),
                                   [_ev("logs", f"{e.get('log')}#{e.get('record_id')}", text, time=e.get("time_utc"))],
                                   "Trace the originating process/user and contain the host.", [],
                                   category="logs", when=e.get("time_utc")))
        if eid == 7045:
            path = (e.get("data") or {}).get("ImagePath", "")
            if TEMP_RE.search(path) or _text_hits(path) or "%comspec%" in path.lower():
                out.append(finding("EVT-003", f"Suspicious service installed: {(e.get('data') or {}).get('ServiceName')}",
                                   "high", ["T1543.003", "T1569.002"], "Service binary path points to a temp dir or "
                                   "a command interpreter (PsExec/Cobalt Strike style).",
                                   [_ev("logs", f"System#{e.get('record_id')}", path, time=e.get("time_utc"))],
                                   "Disable and delete the service; quarantine its binary.",
                                   [{"type": "disable_service", "service": (e.get("data") or {}).get("ServiceName")}],
                                   category="logs", when=e.get("time_utc")))
    for eid, evs in groups.items():
        sev, title, tech = WIN_EVENT_RULES[eid]
        out.append(finding("EVT-001", f"{title} (Event {eid}) x{len(evs)}", sev, tech,
                           f"{len(evs)} occurrence(s) of Windows event {eid} in the collected window. Most recent: "
                           f"{evs[0].get('time_utc')}.",
                           [_ev("logs", f"{e.get('log')}#{e.get('record_id')}", str(e.get("data")), time=e.get("time_utc"))
                            for e in evs[:15]],
                           "Correlate with change records to determine whether the activity was authorised.", [],
                           confidence="medium", category="logs", when=evs[0].get("time_utc")))
    return out


@rule("HIST-001", "Attacker tradecraft in shell history", "logs")
def hist(a, db):
    out = []
    for h in (a.get("logs") or {}).get("history_lines", []):
        cmd = h.get("command", "")
        reasons, techs = [], []
        for rx, label, t in HIST_SUSPICIOUS:
            if rx.search(cmd):
                reasons.append(label)
                techs.append(t)
        for kind, label in _text_hits(cmd):
            reasons.append(label)
            techs.append({"revshell": "T1059.004", "download": "T1105", "miner": "T1496"}.get(kind, "T1059"))
        iocs = db.scan_text(cmd)
        if iocs:
            reasons.append("IOC: " + ", ".join(i["value"] for i in iocs))
            techs.append("T1071")
        if reasons:
            sev = "high" if iocs or any(t in ("T1070.003", "T1136.001", "T1059.004") for t in techs) else "medium"
            out.append(finding("HIST-001", f"{', '.join(sorted(set(reasons)))} in {os.path.basename(h.get('file'))}",
                               sev, sorted(set(techs)), "A command in a user's shell history matches attacker "
                               "behaviour. History has no timestamps unless HISTTIMEFORMAT was set.",
                               [_ev("logs", f"{h.get('file')}:{h.get('line')}", cmd)],
                               "Determine who ran the command and whether it was authorised.", [],
                               category="logs"))
    return out


# =============================================================== FILESYSTEM
@rule("FILE-001", "File hash matches IOC", "ioc")
def file_ioc(a, db):
    out = []
    for f in a.get("filesystem", []):
        if f.get("type") != "file":
            continue
        m = db.match_hash(f.get("sha256"), f.get("sha1"), f.get("md5")) or db.match_filename(f.get("name") or "")
        if m:
            is_hash = m["type"] in ("sha256", "sha1", "md5")
            sev = "critical" if is_hash else "medium"
            if "eicar" in (m.get("threat") or "").lower():
                sev = "low"
            out.append(finding("FILE-001", f"{f.get('path')} matches IOC {m['type']} ({m.get('threat') or m.get('source')})",
                               sev, "T1204", "The file is listed in a loaded threat-intelligence source.",
                               [_ev("filesystem", f.get("path"), None, sha256=f.get("sha256"), mtime=f.get("mtime"),
                                    ctime=f.get("ctime"), size=f.get("size"), ioc=m)],
                               "Quarantine the file and hunt for the hash across the estate.",
                               [_quarantine(f.get("path"), f.get("sha256"))],
                               confidence="high" if is_hash else "low", category="ioc", when=f.get("mtime")))
    return out


@rule("FILE-002", "Executable or hidden binary in temp/user-writable location", "filesystem")
def file_temp_exec(a, db):
    out = []
    for f in a.get("filesystem", []):
        if f.get("type") != "file" or f.get("kind") not in ("ELF", "PE", "Mach-O", "Mach-O/Java"):
            continue
        if not f.get("in_temp_location") and not f.get("hidden"):
            continue
        if "\\downloads\\" in f["path"].lower() or "/downloads/" in f["path"].lower():
            sev = "low"
        elif f.get("hidden"):
            sev = "high"
        else:
            sev = "medium"
        out.append(finding("FILE-002", f"{f.get('kind')} binary {'(hidden) ' if f.get('hidden') else ''}at {f.get('path')}",
                           sev, ["T1036", "T1564.001"] if f.get("hidden") else ["T1036", "T1105"],
                           "Compiled executables in temp/hidden locations are commonly droppers or implants.",
                           [_ev("filesystem", f.get("path"), None, sha256=f.get("sha256"), mtime=f.get("mtime"),
                                size=f.get("size"), mode=f.get("mode"))],
                           "Check the SHA-256 reputation (e.g. VirusTotal hash lookup); quarantine if unknown.",
                           [_quarantine(f.get("path"), f.get("sha256"))], confidence="low", category="filesystem",
                           when=f.get("mtime")))
    return out


STD_SUID_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/usr/lib64/",
                 "/lib/", "/snap/", "/opt/google/chrome/", "/usr/share/", "/var/lib/docker/", "/var/lib/snapd/")


@rule("FILE-003", "SUID/SGID binary in non-standard location or SUID shell", "filesystem")
def file_suid(a, db):
    out = []
    for s in (a.get("filesystem_scope") or {}).get("suid_sgid", []):
        p = s.get("path", "")
        name = os.path.basename(p)
        shell = name in ("bash", "sh", "dash", "zsh", "python", "python3", "perl", "find", "vim", "nmap", "cp")
        nonstd = not p.startswith(STD_SUID_DIRS)
        if s.get("suid") and (nonstd or (shell and p not in ("/usr/bin/su",))):
            out.append(finding("FILE-003", f"SUID binary {p} (owner uid {s.get('uid')})",
                               "critical" if shell and s.get("uid") == 0 else "high", "T1548.001",
                               "A set-uid binary outside system directories, or a set-uid shell/interpreter, is a "
                               "classic root backdoor.",
                               [_ev("filesystem_scope", p, None, mode=s.get("mode"), mtime=s.get("mtime"))],
                               "Remove the SUID bit / quarantine the binary.",
                               [_quarantine(p)], confidence="medium", category="filesystem", when=s.get("mtime")))
    return out


@rule("FILE-004", "Web shell indicators", "filesystem")
def file_webshell(a, db):
    out = []
    for f in a.get("filesystem", []):
        p = f.get("path", "")
        if f.get("type") != "file" or not p.lower().endswith(WEB_EXT) or (f.get("size") or 0) > 2 * 1024 * 1024:
            continue
        text = read_text(p, max_bytes=2 * 1024 * 1024) or ""
        m = WEBSHELL.search(text)
        if m:
            out.append(finding("FILE-004", f"Web shell pattern in {p}", "critical", "T1505.003",
                               "Server-side script evaluates attacker-supplied request parameters as code/commands.",
                               [_ev("filesystem", p, m.group(0), sha256=f.get("sha256"), mtime=f.get("mtime"))],
                               "Quarantine the file, review web-server access logs for requests to it, patch the "
                               "upload/RCE vector.", [_quarantine(p, f.get("sha256"))], confidence="high",
                               category="filesystem", when=f.get("mtime")))
    return out


@rule("FILE-005", "Double-extension / disguised executable", "filesystem")
def file_double_ext(a, db):
    rx = re.compile(r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|zip)\.(exe|scr|com|bat|cmd|js|vbs|ps1|hta|lnk)$", re.I)
    return [finding("FILE-005", f"Disguised executable {f.get('path')}", "high", "T1036",
                    "A double extension hides the true executable type from users.",
                    [_ev("filesystem", f.get("path"), None, sha256=f.get("sha256"), mtime=f.get("mtime"))],
                    "Quarantine.", [_quarantine(f.get("path"), f.get("sha256"))], category="filesystem",
                    when=f.get("mtime"))
            for f in a.get("filesystem", []) if f.get("type") == "file" and rx.search(f.get("name") or "")]


# =================================================================== POSTURE
@rule("POST-001", "Security controls disabled or weakened", "posture")
def posture(a, db):
    out = []
    sp = (a.get("system") or {}).get("security_posture", {}) or {}
    for d in sp.get("defender") or []:
        if d.get("RealTimeProtectionEnabled") is False or d.get("AntivirusEnabled") is False:
            out.append(finding("POST-001", "Microsoft Defender real-time protection is OFF", "high", "T1562.001",
                               "Endpoint protection is disabled.", [_ev("system", "defender", str(d))],
                               "Re-enable Defender (and Tamper Protection).",
                               [{"type": "manual", "text": "Set-MpPreference -DisableRealtimeMonitoring $false"}],
                               category="posture"))
    for d in sp.get("defender_exclusions") or []:
        ex = [x for x in (d.get("ExclusionPath") or []) + (d.get("ExclusionProcess") or []) if x and "N/A" not in str(x)]
        if ex:
            out.append(finding("POST-002", f"Defender exclusions configured: {truncate(ex, 150)}", "medium",
                               "T1562.001", "Attackers add exclusions so their tools are never scanned.",
                               [_ev("system", "defender_exclusions", str(ex))], "Review and remove unknown exclusions.",
                               [{"type": "manual", "text": f"Remove-MpPreference -ExclusionPath <path> for: {ex}"}],
                               category="posture"))
    fw = sp.get("firewall") or ""
    if fw and re.search(r"State\s+OFF", fw):
        out.append(finding("POST-003", "Windows Firewall disabled for at least one profile", "medium", "T1562.004",
                           "Host firewall is off.", [_ev("system", "firewall", fw)],
                           "Enable the firewall for all profiles.",
                           [{"type": "manual", "text": "netsh advfirewall set allprofiles state on"}],
                           category="posture"))
    if sp.get("aslr") == "0":
        out.append(finding("POST-004", "ASLR disabled (kernel.randomize_va_space=0)", "low", "T1562.001",
                           "Address-space randomisation is disabled, easing exploitation.",
                           [_ev("system", "aslr", "0")], "sysctl -w kernel.randomize_va_space=2",
                           [{"type": "manual", "text": "sysctl -w kernel.randomize_va_space=2 and persist in /etc/sysctl.d"}],
                           category="posture"))
    if not (a.get("system") or {}).get("running_as_admin"):
        out.append(finding("SCOPE-001", "Scan was NOT run with administrative privileges", "info", [],
                           "Without root/Administrator rights some processes, sockets, logs and files could not be "
                           "inspected; absence of findings in those areas is not evidence of absence.",
                           [_ev("system", "running_as_admin", "false")], "Re-run elevated for full coverage.", [],
                           confidence="high", category="scope"))
    return out


# =================================================================== RUNNER
def run_all(artifacts: dict, db, log=None) -> list:
    findings = []
    for r in RULES:
        try:
            findings += r["fn"](artifacts, db) or []
        except Exception as exc:  # a broken rule must never stop the analysis
            findings.append(finding("ENGINE", f"Rule {r['id']} failed: {exc}", "info", [], str(exc), [], "", [],
                                    category="engine"))
    # deduplicate identical titles
    seen, unique = set(), []
    for f in findings:
        key = (f["rule_id"], f["title"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: (-SEV_ORDER.get(f["severity"], 0), f["rule_id"], f["title"]))
    for i, f in enumerate(unique, 1):
        f["id"] = f"F-{i:04d}"
    return unique
