"""Minimal, dependency-free MCP (Model Context Protocol) server over stdio.

Exposes Aletheia's READ-ONLY capabilities to Claude (Claude Desktop, Claude Code, any
MCP client). Remediation is intentionally NOT exposed: an AI assistant can prepare and
explain the plan, but only a human at an interactive terminal can execute it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from aletheia import TOOL_NAME, __version__

DEFAULT_OUTPUT = os.environ.get("ALETHEIA_OUTPUT", os.path.join(os.path.expanduser("~"), "aletheia_cases"))

TOOLS = [
    {
        "name": "aletheia_scan",
        "description": "Run a READ-ONLY forensic triage + IOC scan of this device. Collects volatile and "
                       "non-volatile artefacts, matches IOCs, YARA and MITRE ATT&CK-mapped rules, and writes a sealed, "
                       "court-ready case folder (HTML/JSON/CSV/STIX + SHA256SUMS + hash-chained audit log). "
                       "Changes nothing on the device. Returns verdict, findings and case folder path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "examiner": {"type": "string", "description": "Examiner full name (required, chain of custody)"},
                "case_id": {"type": "string", "description": "Case / matter number"},
                "organization": {"type": "string"}, "client": {"type": "string"},
                "purpose": {"type": "string", "description": "Reason / authority for the examination"},
                "evidence_item": {"type": "string"},
                "profile": {"type": "string", "enum": ["quick", "standard", "deep"], "default": "standard"},
                "paths": {"type": "array", "items": {"type": "string"}, "description": "Extra paths to triage"},
                "ioc_files": {"type": "array", "items": {"type": "string"}},
                "yara_rules": {"type": "array", "items": {"type": "string"}},
                "external_tools": {"type": "array", "items": {"type": "string"},
                                   "description": "Optional installed tools: clamscan, chkrootkit, osqueryi, "
                                                  "hayabusa, chainsaw, capa, or 'all'"},
                "output": {"type": "string", "description": f"Output folder (default {DEFAULT_OUTPUT})"},
                "pdf": {"type": "boolean", "default": False},
            },
            "required": ["examiner"],
        },
    },
    {"name": "aletheia_summary", "description": "Summarise a completed case: verdict, findings with evidence, and the "
                                                "proposed remediation plan.",
     "inputSchema": {"type": "object", "properties": {"case_dir": {"type": "string"},
                                                      "limit": {"type": "integer", "default": 50}},
                     "required": ["case_dir"]}},
    {"name": "aletheia_plan", "description": "Show the proposed remediation plan for a case (what would be "
                                             "killed/quarantined/disabled/blocked and why). Read-only. Execution "
                                             "requires the human to run `aletheia remediate <case_dir>` themselves.",
     "inputSchema": {"type": "object", "properties": {"case_dir": {"type": "string"}}, "required": ["case_dir"]}},
    {"name": "aletheia_verify", "description": "Verify the integrity of a sealed case folder (SHA256SUMS manifest + "
                                               "hash-chained audit log).",
     "inputSchema": {"type": "object", "properties": {"case_dir": {"type": "string"}}, "required": ["case_dir"]}},
    {"name": "aletheia_ioc_check", "description": "Check hashes / IPs / domains / URLs against loaded IOC feeds.",
     "inputSchema": {"type": "object", "properties": {"values": {"type": "array", "items": {"type": "string"}}},
                     "required": ["values"]}},
    {"name": "aletheia_tools", "description": "List optional open-source security tools detected on this machine.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _cli(args: list, timeout: int = 7200) -> tuple:
    p = subprocess.run([sys.executable, "-m", "aletheia"] + args, capture_output=True, timeout=timeout,
                       stdin=subprocess.DEVNULL, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def call_tool(name: str, a: dict) -> tuple:
    if name == "aletheia_scan":
        args = ["scan", "--json", "--no-prompt", "--examiner", a["examiner"], "--output", a.get("output") or DEFAULT_OUTPUT,
                "--profile", a.get("profile", "standard")]
        for k, flag in (("case_id", "--case-id"), ("organization", "--org"), ("client", "--client"),
                        ("purpose", "--purpose"), ("evidence_item", "--evidence-item")):
            if a.get(k):
                args += [flag, a[k]]
        for k, flag in (("paths", "--path"), ("ioc_files", "--ioc"), ("yara_rules", "--yara"),
                        ("external_tools", "--with")):
            for v in a.get(k) or []:
                args += [flag, v]
        if a.get("pdf"):
            args.append("--pdf")
        rc, out, err = _cli(args)
        text = out if out.strip() else err[-4000:]
        text += ("\n\nNOTE: analysis only - nothing on the device was changed. Remediation, if wanted, must be "
                 "approved by the human: they run `aletheia remediate <case_dir>` in their own terminal "
                 "(in Claude Code: type `! aletheia remediate <case_dir>`).")
        return text, rc != 0
    if name == "aletheia_summary":
        rc, out, err = _cli(["summary", a["case_dir"], "--limit", str(a.get("limit", 50))], 120)
        return out or err, rc != 0
    if name == "aletheia_plan":
        rc, out, err = _cli(["plan", a["case_dir"]], 120)
        return (out or err) + "\nTo execute, the human must run interactively: aletheia remediate \"" + \
            a["case_dir"] + "\"", rc not in (0,)
    if name == "aletheia_verify":
        rc, out, err = _cli(["verify", a["case_dir"], "--json"], 600)
        return out or err, False
    if name == "aletheia_ioc_check":
        rc, out, err = _cli(["ioc-check"] + list(a.get("values", [])), 300)
        return out or err, False
    if name == "aletheia_tools":
        rc, out, err = _cli(["tools"], 60)
        return out or err, False
    return f"unknown tool {name}", True


def _reply(msg_id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def serve() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        method, msg_id, params = req.get("method"), req.get("id"), req.get("params") or {}
        if msg_id is None:  # notification
            continue
        try:
            if method == "initialize":
                _reply(msg_id, {"protocolVersion": params.get("protocolVersion", "2024-11-05"),
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": TOOL_NAME.lower(), "version": __version__},
                                "instructions": "Aletheia performs READ-ONLY forensic analysis. Never claim that "
                                                "remediation was performed; it can only be executed by the human "
                                                "via `aletheia remediate` in an interactive terminal."})
            elif method == "tools/list":
                _reply(msg_id, {"tools": TOOLS})
            elif method == "tools/call":
                text, is_err = call_tool(params.get("name"), params.get("arguments") or {})
                _reply(msg_id, {"content": [{"type": "text", "text": text}], "isError": is_err})
            elif method == "ping":
                _reply(msg_id, {})
            else:
                _reply(msg_id, error={"code": -32601, "message": f"method not found: {method}"})
        except Exception as exc:
            _reply(msg_id, error={"code": -32603, "message": str(exc)})


if __name__ == "__main__":
    serve()
