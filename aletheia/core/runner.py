"""Safe command execution for the ANALYSIS stage.

* Never uses a shell (no injection, no globbing surprises).
* Only binaries on an explicit read-only allow-list may run; anything else raises.
* Every invocation (argv, start/end time, return code, SHA-256 of output) is written
  to the chain-of-custody audit log, and the verbatim stdout is preserved as evidence.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

from aletheia.core.util import IS_WINDOWS, sha256_bytes, utc_now

# Commands that only *read* system state. Remediation uses a different runner.
READ_ONLY_COMMANDS = {
    # cross-platform / POSIX
    "ps", "netstat", "lsof", "who", "w", "last", "lastb", "lastlog", "uname", "uptime", "id",
    "getent", "dpkg-query", "rpm", "systemctl", "journalctl", "crontab", "ss", "ip", "ifconfig",
    "lsmod", "mount", "df", "getenforce", "sestatus", "ufw", "iptables-save", "nft", "sw_vers",
    "launchctl", "dscl", "csrutil", "spctl", "fdesetup", "pkgutil", "system_profiler", "kextstat",
    "profiles", "sysctl", "hostname", "date", "timedatectl", "loginctl", "aa-status", "pfctl",
    # Windows
    "reg", "schtasks", "sc", "wevtutil", "net", "netsh", "ipconfig", "tasklist", "whoami",
    "systeminfo", "wmic", "powershell", "powershell.exe", "query", "quser", "arp", "route",
    "driverquery", "bcdedit", "manage-bde", "auditpol", "cmdkey",
    # optional third-party read-only scanners (see integrations/external.py)
    "yara", "clamscan", "chkrootkit", "rkhunter", "osqueryi", "hayabusa", "chainsaw",
    "autorunsc", "autorunsc64", "sigcheck", "sigcheck64", "lynis", "loki", "capa", "gpg",
}

# Sub-commands that would change state, refused even for allow-listed binaries.
FORBIDDEN_TOKENS = {
    "reg": {"add", "delete", "import", "restore", "load", "unload", "copy"},
    "schtasks": {"/create", "/delete", "/change", "/run", "/end"},
    "sc": {"create", "delete", "config", "start", "stop", "pause", "failure", "sdset"},
    "net": {"stop", "start", "pause", "continue"},
    "systemctl": {"start", "stop", "restart", "enable", "disable", "mask", "kill", "reload", "daemon-reload", "isolate"},
    "launchctl": {"load", "unload", "bootout", "bootstrap", "kill", "remove", "start", "stop", "enable", "disable"},
    "crontab": {"-r", "-e"},
    "clamscan": {"--remove", "--move", "--copy"},
    "wevtutil": {"cl", "clear-log", "sl", "set-log", "im", "install-manifest", "um", "uninstall-manifest"},
    "netsh": {"add", "delete", "set", "reset"},
    "nft": {"add", "delete", "flush", "insert", "replace", "create"},
    "ufw": {"enable", "disable", "allow", "deny", "reject", "delete", "reset", "insert"},
}

POWERSHELL_FORBIDDEN = (
    "remove-", "set-", "stop-", "start-", "new-", "clear-", "disable-", "enable-", "invoke-webrequest",
    "invoke-expression", "iex ", "restart-", "rename-", "move-", "copy-", "out-file", "add-", "install-",
    "uninstall-", "register-", "unregister-", "suspend-", "resume-", "format-volume", "-encodedcommand",
)


class CommandRefused(RuntimeError):
    pass


class SafeRunner:
    def __init__(self, audit=None, store=None, default_timeout: int = 120):
        self.audit = audit
        self.store = store
        self.default_timeout = default_timeout
        self.history: list = []

    @staticmethod
    def available(binary: str) -> Optional[str]:
        return shutil.which(binary)

    def _check(self, argv: list) -> None:
        base = os.path.basename(argv[0]).lower()
        if base.endswith(".exe"):
            base_noext = base[:-4]
        else:
            base_noext = base
        if base not in READ_ONLY_COMMANDS and base_noext not in READ_ONLY_COMMANDS:
            raise CommandRefused(f"'{base}' is not on the read-only allow-list")
        lowered = [a.lower() for a in argv[1:]]
        forbidden = FORBIDDEN_TOKENS.get(base_noext, set())
        if forbidden and any(tok in forbidden for tok in lowered):
            raise CommandRefused(f"state-changing arguments refused for '{base}': {argv[1:]}")
        if base_noext in ("powershell", "pwsh"):
            script = " ".join(lowered)
            for bad in POWERSHELL_FORBIDDEN:
                if bad in script:
                    raise CommandRefused(f"PowerShell verb '{bad.strip()}' refused in analysis mode")

    def run(self, argv: list, label: Optional[str] = None, timeout: Optional[int] = None,
            preserve: bool = True, ok_codes: tuple = (0,)) -> dict:
        self._check(argv)
        exe = shutil.which(argv[0]) or argv[0]
        started = utc_now()
        result = {"argv": argv, "started_utc": started, "rc": None, "stdout": "", "stderr": "", "error": None}
        creationflags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
        try:
            proc = subprocess.run(
                [exe] + argv[1:],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout or self.default_timeout,
                shell=False,
                creationflags=creationflags,
            )
            result["rc"] = proc.returncode
            result["stdout"] = proc.stdout.decode("utf-8", errors="replace")
            result["stderr"] = proc.stderr.decode("utf-8", errors="replace")[:4000]
        except FileNotFoundError:
            result["error"] = "not found"
        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
        except OSError as exc:
            result["error"] = str(exc)
        result["ended_utc"] = utc_now()
        result["stdout_sha256"] = sha256_bytes(result["stdout"].encode("utf-8"))
        record = {k: v for k, v in result.items() if k not in ("stdout", "stderr")}
        if preserve and self.store is not None and result["stdout"]:
            saved = self.store.save_command_output(label or "_".join(argv[:3]), result["stdout"])
            record["evidence_file"] = saved["path"]
        self.history.append(record)
        if self.audit is not None:
            self.audit.record("command_executed", record)
        result["ok"] = result["error"] is None and result["rc"] in ok_codes
        return result

    def powershell_json(self, script: str, label: str, timeout: int = 180):
        """Run a read-only PowerShell pipeline and parse ConvertTo-Json output."""
        import json

        res = self.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
             script + " | ConvertTo-Json -Depth 4 -Compress"],
            label=label, timeout=timeout,
        )
        if not res["stdout"].strip():
            return []
        try:
            data = json.loads(res["stdout"])
        except ValueError:
            return []
        return data if isinstance(data, list) else [data]
