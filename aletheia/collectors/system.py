"""System identity, clock and security posture (collected first: it anchors the timeline)."""

from __future__ import annotations

import datetime as _dt
import os
import platform
import socket
import sys
import time

from aletheia import __version__
from aletheia.core.util import IS_LINUX, IS_MACOS, IS_WINDOWS, is_admin, read_text, utc_now


def collect(ctx) -> None:
    now_local = _dt.datetime.now().astimezone()
    info = {
        "collected_utc": utc_now(),
        "local_time": now_local.isoformat(),
        "utc_offset": now_local.strftime("%z"),
        "timezone_name": time.tzname,
        "hostname": socket.gethostname(),
        "fqdn": _safe(socket.getfqdn),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "aletheia_version": __version__,
        "running_as_admin": is_admin(),
        "ip_addresses": _ip_addresses(),
        "boot_time_utc": None,
        "security_posture": {},
    }
    if IS_LINUX:
        osr = read_text("/etc/os-release") or ""
        info["distribution"] = dict(
            line.split("=", 1) for line in osr.splitlines() if "=" in line
        ).get("PRETTY_NAME", "").strip('"')
        uptime = read_text("/proc/uptime")
        if uptime:
            secs = float(uptime.split()[0])
            info["boot_time_utc"] = _dt.datetime.fromtimestamp(time.time() - secs, _dt.timezone.utc).isoformat()
            info["uptime_seconds"] = secs
        info["machine_id"] = (read_text("/etc/machine-id") or "").strip()
        posture = info["security_posture"]
        posture["ld_so_preload_present"] = os.path.exists("/etc/ld.so.preload")
        posture["kernel_tainted"] = (read_text("/proc/sys/kernel/tainted") or "").strip()
        posture["aslr"] = (read_text("/proc/sys/kernel/randomize_va_space") or "").strip()
        posture["selinux"] = (read_text("/sys/fs/selinux/enforce") or "n/a").strip()
        if ctx.runner.available("ufw"):
            posture["ufw"] = ctx.runner.run(["ufw", "status"], label="ufw_status").get("stdout", "")[:2000]
        if ctx.runner.available("timedatectl"):
            posture["time_sync"] = ctx.runner.run(["timedatectl"], label="timedatectl").get("stdout", "")[:2000]
    elif IS_WINDOWS:
        posture = info["security_posture"]
        posture["defender"] = ctx.runner.powershell_json(
            "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
            "BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated,IsTamperProtected",
            label="defender_status",
        )
        posture["defender_exclusions"] = ctx.runner.powershell_json(
            "Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension",
            label="defender_exclusions",
        )
        fw = ctx.runner.run(["netsh", "advfirewall", "show", "allprofiles", "state"], label="firewall_state")
        posture["firewall"] = fw.get("stdout", "")[:4000]
        os_info = ctx.runner.powershell_json(
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,"
            "@{n='LastBootUpTime';e={$_.LastBootUpTime.ToUniversalTime().ToString('o')}},"
            "@{n='InstallDate';e={$_.InstallDate.ToUniversalTime().ToString('o')}}",
            label="os_info",
        )
        if os_info:
            info["distribution"] = os_info[0].get("Caption")
            info["boot_time_utc"] = os_info[0].get("LastBootUpTime")
            info["install_date_utc"] = os_info[0].get("InstallDate")
        bl = ctx.runner.run(["manage-bde", "-status"], label="bitlocker_status")
        posture["bitlocker"] = bl.get("stdout", "")[:4000]
        audit = ctx.runner.run(["auditpol", "/get", "/category:*"], label="audit_policy")
        posture["audit_policy"] = audit.get("stdout", "")[:8000]
    elif IS_MACOS:
        posture = info["security_posture"]
        sv = ctx.runner.run(["sw_vers"], label="sw_vers")
        info["distribution"] = " ".join(sv.get("stdout", "").split())
        posture["sip"] = ctx.runner.run(["csrutil", "status"], label="sip_status").get("stdout", "").strip()
        posture["gatekeeper"] = ctx.runner.run(["spctl", "--status"], label="gatekeeper").get("stdout", "").strip()
        posture["filevault"] = ctx.runner.run(["fdesetup", "status"], label="filevault").get("stdout", "").strip()
        bt = ctx.runner.run(["sysctl", "-n", "kern.boottime"], label="boottime").get("stdout", "")
        info["boot_time_raw"] = bt.strip()
    ctx.add_artifact("system", info, "Host identity, clock reference and security posture")


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None


def _ip_addresses() -> list:
    addrs = set()
    try:
        for res in socket.getaddrinfo(socket.gethostname(), None):
            addrs.add(res[4][0])
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # TEST-NET; no packet is sent for UDP connect
        addrs.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(addrs)
