"""Turns findings into a deterministic, hash-identified remediation PLAN.

The plan is data only. It is sealed into the analysis case folder so the exact plan a
human approves can later be proven to be the plan that was produced by the analysis.
"""

from __future__ import annotations

from aletheia.core.util import canonical_json, sha256_bytes, utc_now
from aletheia.detection.frameworks import D3FEND
from aletheia.detection.rules import SEV_ORDER

ORDER = {"kill_process": 10, "block_ip": 20, "disable_service": 30, "disable_scheduled_task": 30,
         "disable_systemd_unit": 30, "disable_launchd": 30, "delete_registry_value": 35, "comment_out_line": 40,
         "disable_account": 50, "quarantine_file": 60}

REVERSIBLE = {"kill_process": False, "block_ip": True, "disable_service": True, "disable_scheduled_task": True,
              "disable_systemd_unit": True, "disable_launchd": True, "delete_registry_value": True,
              "comment_out_line": True, "disable_account": True, "quarantine_file": True}

RISK = {
    "kill_process": "Process is terminated immediately; unsaved data in it is lost. Capture memory first if needed.",
    "block_ip": "All traffic to/from the address is dropped by the host firewall.",
    "disable_service": "Service is stopped and set to Disabled; dependent software may stop working.",
    "disable_scheduled_task": "Task is disabled (not deleted); XML definition backed up.",
    "disable_systemd_unit": "Unit is stopped and disabled; unit file is kept.",
    "disable_launchd": "Launch item is unloaded and disabled; plist backed up.",
    "delete_registry_value": "Registry value removed; full key exported to .reg backup first.",
    "comment_out_line": "Line is commented out (not deleted); original file backed up.",
    "disable_account": "Account is locked/disabled; the user can no longer log in.",
    "quarantine_file": "File is moved into an inert, encoded quarantine store; restorable.",
}

PROTECTED_PREFIXES = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/usr/lib/", "/boot/",
                      "c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "/system/", "/usr/libexec/")


def _target(a: dict) -> str:
    t = a["type"]
    if t == "kill_process":
        return f"PID {a.get('pid')} {a.get('name') or ''} {a.get('exe') or ''}".strip()
    if t == "quarantine_file":
        return a.get("path") or ""
    if t == "comment_out_line":
        return f"{a.get('file')}:{a.get('line')}"
    if t == "block_ip":
        return a.get("ip") or ""
    if t == "delete_registry_value":
        return f"{a.get('key')}\\{a.get('value')}"
    if t == "disable_scheduled_task":
        return a.get("task") or ""
    if t == "disable_service":
        return a.get("service") or ""
    if t == "disable_systemd_unit":
        return a.get("unit") or ""
    if t == "disable_launchd":
        return a.get("path") or ""
    if t == "disable_account":
        return a.get("user") or ""
    return str(a)


def build_plan(case_id: str, findings: list, min_severity: str = "medium") -> dict:
    floor = SEV_ORDER[min_severity]
    actions: dict = {}
    manual: dict = {}
    for f in findings:
        if SEV_ORDER.get(f["severity"], 0) < floor:
            continue
        for r in f.get("remediation", []):
            if not r or not r.get("type"):
                continue
            if r["type"] == "manual":
                m = manual.setdefault(r["text"], {"text": r["text"], "findings": []})
                m["findings"].append(f["id"])
                continue
            if r["type"] not in ORDER:
                continue
            tgt = _target(r)
            if not tgt or tgt in ("None", "PID None"):
                continue
            key = (r["type"], tgt)
            if key not in actions:
                params = {k: v for k, v in r.items() if k != "type"}
                warn = ""
                if r["type"] == "quarantine_file" and str(r.get("path", "")).lower().startswith(PROTECTED_PREFIXES):
                    warn = "TARGET IS IN A PROTECTED SYSTEM DIRECTORY - verify carefully; removal may break the OS."
                actions[key] = {"type": r["type"], "target": tgt, "params": params, "findings": [],
                                "severity": f["severity"], "reversible": REVERSIBLE[r["type"]],
                                "risk": RISK[r["type"]], "warning": warn,
                                "d3fend": list(D3FEND.get(r["type"], ("", "")))}
            a = actions[key]
            if f["id"] not in a["findings"]:
                a["findings"].append(f["id"])
            if SEV_ORDER[f["severity"]] > SEV_ORDER[a["severity"]]:
                a["severity"] = f["severity"]
    ordered = sorted(actions.values(), key=lambda a: (ORDER[a["type"]], -SEV_ORDER[a["severity"]], a["target"]))
    for i, a in enumerate(ordered, 1):
        a["id"] = f"A{i:03d}"
    plan = {"case_id": case_id, "created_utc": utc_now(), "min_severity": min_severity, "actions": ordered,
            "manual": list(manual.values()),
            "policy": "No action is executed without interactive human approval (aletheia remediate)."}
    plan["plan_sha256"] = plan_digest(plan)
    return plan


def plan_digest(plan: dict) -> str:
    body = {k: v for k, v in plan.items() if k not in ("plan_sha256", "created_utc")}
    return sha256_bytes(canonical_json(body))
