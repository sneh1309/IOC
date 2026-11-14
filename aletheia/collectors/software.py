"""Installed software inventory (used for context and vulnerable/unwanted software review)."""

from __future__ import annotations

import os

from aletheia.core.util import IS_LINUX, IS_MACOS, IS_WINDOWS


def collect(ctx) -> None:
    items = []
    if IS_WINDOWS:
        for hive in (r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                     r"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                     r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"):
            rows = ctx.runner.powershell_json(
                f"Get-ItemProperty '{hive}' -ErrorAction SilentlyContinue | Where-Object DisplayName | "
                "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation",
                label="software")
            for r in rows:
                items.append({"name": r.get("DisplayName"), "version": r.get("DisplayVersion"),
                              "publisher": r.get("Publisher"), "install_date": r.get("InstallDate"),
                              "location": r.get("InstallLocation")})
    elif IS_LINUX:
        if ctx.runner.available("dpkg-query"):
            res = ctx.runner.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"], label="dpkg")
            for line in res.get("stdout", "").splitlines():
                p = line.split("\t")
                if len(p) >= 2:
                    items.append({"name": p[0], "version": p[1], "publisher": p[2] if len(p) > 2 else "",
                                  "manager": "dpkg"})
        elif ctx.runner.available("rpm"):
            res = ctx.runner.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\n"],
                                 label="rpm")
            for line in res.get("stdout", "").splitlines():
                p = line.split("\t")
                if len(p) >= 2:
                    items.append({"name": p[0], "version": p[1], "publisher": p[2] if len(p) > 2 else "",
                                  "install_date": p[3] if len(p) > 3 else "", "manager": "rpm"})
    elif IS_MACOS:
        for d in ("/Applications", os.path.expanduser("~/Applications")):
            try:
                for app in sorted(os.listdir(d)):
                    if app.endswith(".app"):
                        items.append({"name": app[:-4], "location": os.path.join(d, app)})
            except OSError:
                pass
    ctx.add_artifact("software", items, f"{len(items)} installed packages/applications")
