---
name: aletheia-dfir
description: Forensic triage, IOC / malware / compromise scanning and court-ready incident reports for the local device using the Aletheia toolkit. Use whenever the user asks to scan this computer/server/laptop for malware, hacks, compromise, IOCs, persistence, backdoors, suspicious processes or connections; to run a forensic or incident-response analysis; to produce an evidence or court report; to verify a case folder; or to clean up / remediate threats found by Aletheia.
---

# Aletheia – DFIR assistant

Aletheia has two strictly separated stages:

1. **Analysis (read-only)** – you may run this for the user.
2. **Remediation (changes the system)** – you must **never** run this yourself. Only the human may run it, in an
   interactive terminal, after reviewing the plan. The tool refuses non-interactive execution, so do not try to work
   around it (no piping input, no `yes |`, no `expect`, no editing the plan, no `--force`).

## 0. Locate the launcher

Use the first that works:

1. `aletheia --version` (installed with `pip install .`/`pipx`)
2. `python3 "${CLAUDE_PLUGIN_ROOT}/run_aletheia.py" --version`
3. `python3 "$(find ~/.claude/plugins -name run_aletheia.py -path '*aletheia*' | head -1)" --version`

On Windows use `py` instead of `python3`. Below, `ALETHEIA` means whichever command worked.

## 1. Gather case details (ask once, briefly)

- Examiner full name (**required** – recorded in the chain of custody)
- Case / matter ID (optional, auto-generated otherwise)
- Client, purpose / authority (e.g. "IR ticket 1234, client consent"), evidence item (asset tag/serial)
- Profile: `quick` (minutes), `standard` (default), `deep` (whole home dirs, system binaries)
- Output folder – recommend external/forensic media (e.g. `E:\cases`, `/media/usb/cases`)
- Any case-specific IOC files (`--ioc`) or YARA rules (`--yara`)

Remind the user that full coverage needs **Administrator/root**. If Claude Code is not elevated, tell the user to run
the scan themselves with `! sudo ALETHEIA scan ...` (Linux/macOS) or restart Claude Code from an elevated terminal
(Windows).

## 2. Run the analysis

```
ALETHEIA scan --examiner "<name>" --case-id "<id>" --client "<client>" --purpose "<purpose>" \
   --profile standard --output "<folder>" --json --no-prompt [--ioc file] [--yara dir] [--with clamscan] [--pdf]
```

`--json` prints a summary to stdout (progress goes to stderr). The scan can take several minutes; use a long timeout.
Optional: `ALETHEIA feeds update` first to download free abuse.ch threat-intel (ask before using the network).
`ALETHEIA tools` lists installed open-source scanners usable with `--with` (clamscan, chkrootkit, osqueryi,
hayabusa, chainsaw, capa).

## 3. Explain the results

Run `ALETHEIA summary "<case_dir>"` and give the user:

- The **verdict** and severity counts
- The critical/high findings in plain language: what was found, the evidence (path/PID/IP), MITRE ATT&CK technique,
  and how confident the tool is. Point out likely false positives honestly.
- Paths to `report/report.html` (court-ready, print to PDF), `report/report.json`, `findings.csv`, `timeline.csv`,
  `iocs_stix21.json`, and the **manifest SHA-256** they should record in their case notes.
- `ALETHEIA verify "<case_dir>"` re-validates integrity at any time (e.g. before court).

Never alter files in the case folder – that would break the evidence seal.

## 4. Remediation (human-approved only)

Show the plan with `ALETHEIA plan "<case_dir>"` (read-only). Walk the user through each action – what it changes,
why (which findings), whether it is reversible, and risks (e.g. acquire memory before killing a fileless process;
consider re-imaging for rootkits/ransomware). Then tell them that **they** must run it themselves:

```
! ALETHEIA remediate "<case_dir>"
```

(In Claude Code, the leading `!` runs the command in their own interactive shell.) They will be asked for their name,
must type `APPROVE <CASE-ID>`, choose all or individual actions, and type `EXECUTE`. Results, backups and quarantine
go into `<case_dir>/remediation_<UTC>/` with their own sealed report; the original analysis evidence is untouched.
After remediation suggest a fresh scan with a new case ID to confirm the device is clean, credential rotation and
patching.

Never claim remediation happened unless the user shows you the remediation report.
