"""User accounts, privileged groups, logged-in sessions and login history."""

from __future__ import annotations

import os

from aletheia.core.util import IS_MACOS, IS_WINDOWS, read_text, safe_stat


def collect(ctx) -> None:
    data = {"users": [], "privileged": [], "sessions": "", "login_history": "", "authorized_keys": []}
    if IS_WINDOWS:
        data["users"] = ctx.runner.powershell_json(
            "Get-LocalUser | Select-Object Name,Enabled,SID,Description,"
            "@{n='LastLogon';e={if($_.LastLogon){$_.LastLogon.ToUniversalTime().ToString('o')}}},"
            "@{n='PasswordLastSet';e={if($_.PasswordLastSet){$_.PasswordLastSet.ToUniversalTime().ToString('o')}}}",
            label="local_users",
        )
        admins = ctx.runner.run(["net", "localgroup", "administrators"], label="local_admins")
        lines = admins.get("stdout", "").splitlines()
        try:
            start = next(i for i, l in enumerate(lines) if l.startswith("---")) + 1
            data["privileged"] = [l.strip() for l in lines[start:] if l.strip() and not l.lower().startswith("the command")]
        except StopIteration:
            pass
        data["sessions"] = ctx.runner.run(["query", "user"], label="sessions", ok_codes=(0, 1)).get("stdout", "")
    else:
        passwd = read_text("/etc/passwd") or ""
        for line in passwd.splitlines():
            p = line.split(":")
            if len(p) < 7:
                continue
            data["users"].append({
                "name": p[0], "uid": int(p[2]) if p[2].isdigit() else p[2], "gid": p[3],
                "gecos": p[4], "home": p[5], "shell": p[6],
                "interactive_shell": not any(x in p[6] for x in ("nologin", "false", "sync", "shutdown", "halt")),
            })
        group = read_text("/etc/group") or ""
        for line in group.splitlines():
            g = line.split(":")
            if len(g) >= 4 and g[0] in ("sudo", "wheel", "admin", "root", "docker", "lxd"):
                data["privileged"].append({"group": g[0], "members": [m for m in g[3].split(",") if m]})
        sudoers = []
        for path in ["/etc/sudoers"] + _listdir("/etc/sudoers.d"):
            text = read_text(path)
            if text:
                for i, line in enumerate(text.splitlines(), 1):
                    s = line.strip()
                    if s and not s.startswith("#") and not s.startswith("Defaults"):
                        sudoers.append({"file": path, "line": i, "rule": s})
        data["sudoers_rules"] = sudoers
        shadow_stat = safe_stat("/etc/shadow")
        data["shadow_mtime"] = shadow_stat.get("mtime") if shadow_stat else None
        data["passwd_mtime"] = (safe_stat("/etc/passwd") or {}).get("mtime")
        data["sessions"] = ctx.runner.run(["who", "-a"], label="who").get("stdout", "")
        if ctx.runner.available("last"):
            data["login_history"] = ctx.runner.run(["last", "-F", "-n", "200"], label="last",
                                                   ok_codes=(0, 1)).get("stdout", "")
        if IS_MACOS:
            data["users_dscl"] = ctx.runner.run(["dscl", ".", "list", "/Users", "UniqueID"], label="dscl_users").get("stdout", "")
    # SSH authorized_keys (all platforms that have OpenSSH)
    from aletheia.core.util import home_dirs

    candidates = [os.path.join(h, ".ssh", "authorized_keys") for h in home_dirs()]
    candidates += ["/root/.ssh/authorized_keys", r"C:\ProgramData\ssh\administrators_authorized_keys"]
    seen = set()
    for path in candidates:
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        text = read_text(path) or ""
        st = safe_stat(path) or {}
        for i, line in enumerate(text.splitlines(), 1):
            if line.strip() and not line.strip().startswith("#"):
                parts = line.split()
                data["authorized_keys"].append({
                    "file": path, "line": i, "mtime": st.get("mtime"),
                    "options": parts[0] if not parts[0].startswith(("ssh-", "ecdsa-", "sk-")) else "",
                    "comment": parts[-1] if len(parts) >= 3 else "",
                    "key_fingerprint_src": line[-60:],
                    "raw": line,
                })
    ctx.add_artifact("accounts", data, "Accounts, privileged membership, sessions, SSH keys")


def _listdir(d: str) -> list:
    try:
        return [os.path.join(d, f) for f in sorted(os.listdir(d))]
    except OSError:
        return []
