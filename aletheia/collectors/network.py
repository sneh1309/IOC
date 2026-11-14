"""Network sockets, hosts file, DNS configuration and DNS cache (volatile)."""

from __future__ import annotations

import os
import re
import socket
import struct

from aletheia.core.util import IS_LINUX, IS_WINDOWS, read_text

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
    "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


def collect(ctx) -> None:
    if IS_LINUX and os.path.exists("/proc/net/tcp"):
        conns = _linux()
    elif IS_WINDOWS:
        conns = _windows(ctx)
    else:
        conns = _lsof(ctx)
    pmap = {p.get("pid"): p.get("name") for p in ctx.artifacts.get("processes", [])}
    for c in conns:
        if c.get("pid") is not None and not c.get("process"):
            c["process"] = pmap.get(c["pid"])
    ctx.add_artifact("network_connections", conns, f"{len(conns)} sockets")

    hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if IS_WINDOWS else "/etc/hosts"
    hosts = []
    for i, line in enumerate((read_text(hosts_path) or "").splitlines(), 1):
        s = line.strip()
        if s and not s.startswith("#"):
            parts = s.split()
            if len(parts) >= 2:
                hosts.append({"line": i, "ip": parts[0], "names": parts[1:], "raw": line})
    netcfg = {"hosts_file": hosts_path, "hosts_entries": hosts}
    if not IS_WINDOWS:
        netcfg["resolv_conf"] = read_text("/etc/resolv.conf")
    else:
        dns = ctx.runner.run(["ipconfig", "/displaydns"], label="dns_cache")
        netcfg["dns_cache_names"] = sorted(set(re.findall(r"Record Name[ .]*:\s*(\S+)", dns.get("stdout", ""))))
        proxy = ctx.runner.run(["netsh", "winhttp", "show", "proxy"], label="winhttp_proxy")
        netcfg["winhttp_proxy"] = proxy.get("stdout", "")[:2000]
        arp = ctx.runner.run(["arp", "-a"], label="arp_cache")
        netcfg["arp_cache"] = arp.get("stdout", "")[:20000]
    if IS_LINUX:
        netcfg["arp_cache"] = read_text("/proc/net/arp")
        netcfg["routes"] = read_text("/proc/net/route")
    ctx.add_artifact("network_config", netcfg, "hosts file, resolvers, DNS/ARP caches")


def _hex_to_addr(hexaddr: str, v6: bool) -> str:
    if not v6:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(hexaddr, 16)))
    raw = bytes.fromhex(hexaddr)
    words = struct.unpack("<4I", raw)
    return socket.inet_ntop(socket.AF_INET6, struct.pack(">4I", *words))


def _inode_pid_map() -> dict:
    mapping = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                if target.startswith("socket:["):
                    mapping[target[8:-1]] = int(pid)
        except OSError:
            continue
    return mapping


def _linux() -> list:
    inode_pid = _inode_pid_map()
    out = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        text = read_text(f"/proc/net/{proto}")
        if not text:
            continue
        v6 = proto.endswith("6")
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                l_ip, l_port = parts[1].split(":")
                r_ip, r_port = parts[2].split(":")
                rec = {
                    "proto": proto,
                    "local_addr": _hex_to_addr(l_ip, v6),
                    "local_port": int(l_port, 16),
                    "remote_addr": _hex_to_addr(r_ip, v6),
                    "remote_port": int(r_port, 16),
                    "state": TCP_STATES.get(parts[3], parts[3]) if proto.startswith("tcp") else "UDP",
                    "uid": int(parts[7]),
                    "pid": inode_pid.get(parts[9]),
                }
            except (ValueError, OSError):
                continue
            out.append(rec)
    return out


def _split_hostport(s: str):
    if s.startswith("["):
        host, _, port = s[1:].partition("]:")
    else:
        host, _, port = s.rpartition(":")
    return host, int(port) if port.isdigit() else 0


def _windows(ctx) -> list:
    res = ctx.runner.run(["netstat", "-ano"], label="netstat")
    out = []
    for line in res.get("stdout", "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        l_ip, l_port = _split_hostport(parts[1])
        r_ip, r_port = _split_hostport(parts[2])
        state = parts[3] if parts[0] == "TCP" and len(parts) >= 5 else "UDP"
        pid = parts[-1]
        out.append({
            "proto": parts[0].lower(), "local_addr": l_ip, "local_port": l_port,
            "remote_addr": r_ip if r_ip != "*" else "", "remote_port": r_port,
            "state": state, "pid": int(pid) if pid.isdigit() else None,
        })
    return out


def _lsof(ctx) -> list:
    res = ctx.runner.run(["lsof", "-nP", "-i"], label="lsof_network")
    out = []
    for line in res.get("stdout", "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name = parts[8]
        state = parts[9].strip("()") if len(parts) > 9 else ""
        local, _, remote = name.partition("->")
        l_ip, l_port = _split_hostport(local)
        r_ip, r_port = _split_hostport(remote) if remote else ("", 0)
        out.append({
            "proto": parts[7].lower(), "local_addr": l_ip, "local_port": l_port,
            "remote_addr": r_ip, "remote_port": r_port, "state": state or "UDP",
            "pid": int(parts[1]) if parts[1].isdigit() else None, "process": parts[0], "user": parts[2],
        })
    return out
