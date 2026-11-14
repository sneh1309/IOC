---
description: Read-only forensic triage & IOC scan of this device with a court-ready, hash-sealed report
argument-hint: "[quick|standard|deep] [case-id]"
---
Use the `aletheia-dfir` skill to run a READ-ONLY Aletheia analysis of this device.

Arguments from the user (may be empty): $ARGUMENTS
- If a profile (quick/standard/deep) is given use it, otherwise use `standard`.
- Ask only for missing essentials (examiner name is required; case ID, client, purpose, output folder optional).

Run the scan with `--json --no-prompt`, then summarise the verdict, critical/high findings with evidence and
MITRE ATT&CK IDs, report paths and the manifest SHA-256. Do NOT perform any remediation.
