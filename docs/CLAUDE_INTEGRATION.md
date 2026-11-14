# Using Aletheia with Claude

Claude can run the **analysis** stage, read the evidence and explain the results in plain language. Claude **cannot execute remediation**. Only you can, at your own terminal. This is enforced by the tool itself, not just by instructions.

## Option 1: Claude Code plugin (recommended)

On the machine you want to examine, start Claude Code in an elevated terminal (`sudo -E claude` on Linux/macOS, or an Administrator PowerShell on Windows). Then:

```
/plugin marketplace add sneh1309/IOC
/plugin install aletheia@aletheia
```

This installs:

* **Skill `aletheia-dfir`**: Claude uses it automatically when you ask things like *"check this PC for malware"*, *"is this server hacked?"* or *"make a forensic report for case 42"*.
* **Slash commands**:
  * `/aletheia-scan [quick|standard|deep] [case-id]`
  * `/aletheia-plan <case-folder>`
  * `/aletheia-verify <case-folder>`
  * `/aletheia-ioc <hash|ip|domain|url> ...`
* **MCP server `aletheia`**: structured tools (`aletheia_scan`, `aletheia_summary`, `aletheia_plan`, `aletheia_verify`, `aletheia_ioc_check`, `aletheia_tools`).

Typical conversation:

> **You:** Scan this laptop, I'm Jane Doe, case INC-0142, client Acme, save to E:\cases
> **Claude:** *(runs the read-only scan)* Verdict: COMPROMISE INDICATED. 2 critical findings: a scheduled task `\Updater` running an encoded PowerShell download cradle (T1053.005, T1059.001), and a connection from `svch0st.exe` to a Feodo Tracker C2 IP (T1071)…
> **You:** What would remediation do?
> **Claude:** *(shows the plan)* A001 kill PID 4412… A002 block 203.0.113.9… To execute, type: `! aletheia remediate "E:\cases\INC-0142_…"`

The `!` prefix runs the command in **your** shell, where you are prompted for your name, the `APPROVE <CASE-ID>` phrase and `EXECUTE`.

## Option 2: Claude Desktop (MCP)

Clone the repo, then add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aletheia": {
      "command": "python3",
      "args": ["/path/to/aletheia/run_aletheia.py", "mcp"],
      "env": { "ALETHEIA_OUTPUT": "/media/usb/cases" }
    }
  }
}
```

On Windows use `"command": "py"` and a Windows path. To give the scan full coverage, start Claude Desktop as Administrator/root.

## Option 3: from a project folder

Clone the repo and run `claude` inside it. The bundled `skills/` and `commands/` folders are picked up as a plugin after `/plugin marketplace add ./`.

## Why Claude can't remediate

`aletheia remediate` requires an interactive TTY and typed approval phrases. Claude's tool calls do not run in an interactive TTY, and the MCP server does not expose remediation at all. Even if an instruction told Claude to "go ahead and clean up", the tool would refuse. This is intentional: a human stays accountable for every change to the evidence system.
