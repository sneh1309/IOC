# Remediation Safety Model

Stage 2 changes the live system, so it is built around one rule: **nothing happens unless a human at the keyboard approves the exact plan.**

## Gates (all must pass, in order)

1. **Interactive terminal required.** `stdin` and `stdout` must be a TTY. Pipes, CI, cron, AI agents (including Claude via its Bash tool) and the MCP server are refused with exit code 4. There is **no override flag**.
2. **Evidence integrity.** The sealed analysis case must pass `verify` (manifest + audit chain). Otherwise the tool refuses with exit code 3.
3. **Plan integrity.** The SHA-256 of `remediation_plan.json` must match the hash recorded in it.
4. **Full disclosure.** Every action is printed: WHAT exactly will happen, WHY (finding IDs), RISK, whether it is reversible, and warnings (e.g. a target inside a protected system directory). Manual-only recommendations are listed separately.
5. **Identity.** The approver types their full name. It is recorded.
6. **Explicit approval.** The approver must type `APPROVE <CASE-ID>` exactly.
7. **Scope choice.** `[A]ll`, `[S]elect` each action with y/N (default **No**), or `[Q]uit`.
8. **Final confirmation.** The approver types `EXECUTE`.

Any other answer at any step ends the session with **nothing changed**. `aletheia plan <case>` is a dry run that changes nothing.

## Per-action safety

| Action | Pre-check (skip if different) | Backup | Rollback |
|---|---|---|---|
| `kill_process` | PID still runs the same executable (prevents PID-reuse accidents) | — (recommend a memory capture first) | not reversible |
| `quarantine_file` | SHA-256 still matches the analysed file | XOR-encoded copy + JSON metadata; the copy is verified to decode to the original hash **before** the original is removed | `aletheia restore-quarantine <file>` |
| `comment_out_line` (cron, hosts, ld.so.preload, rc.local, authorized_keys, profiles) | Line N still has exactly the analysed content | full file copy | copy the backup back |
| `disable_systemd_unit` | — | unit file copy | `systemctl unmask … && systemctl enable --now …` |
| `disable_launchd` | plist exists | plist copy + quarantine | restore plist, `launchctl load -w` |
| `delete_registry_value` | value still exists | `reg export` of the whole key (the action aborts if the export fails) | `reg import backup.reg` |
| `disable_scheduled_task` | task exists | task XML | `schtasks /change /tn … /enable` |
| `disable_service` | service exists | previous start type recorded | `sc config … start= <previous>` |
| `block_ip` | valid IP address | — | exact delete command recorded |
| `disable_account` | refuses to lock `root` | — | `usermod -U` / `net user /active:yes` |

The plan is ordered: stop running threats first (kill), then cut communications (block), then remove persistence, then lock accounts, then evict files.

## Output

Results go to a **new** folder, `<case>/remediation_<UTC>/`, which holds its own hash-chained audit log, an HTML/JSON report with each action's status (DONE / SKIPPED / FAILED), detail and rollback, the backups and quarantine, and its own `SHA256SUMS`. The analysis evidence is never modified, and `aletheia verify <case>` still passes afterwards.

## Using open-source tools for deeper clean-up

Aletheia deliberately keeps automated remediation minimal and reversible. For deeper eradication, use the evidence it produced together with:

* **ClamAV** (`clamscan --move=<dir>`), run manually after analysis is sealed
* **Sysinternals Autoruns** (GUI, Windows) to review and delete autostart entries
* **Microsoft Defender Offline** / **Windows Malicious Software Removal Tool**
* **rkhunter --propupd** after a rebuild, for a clean baseline
* **Re-imaging from known-good media.** This is the recommended route for rootkits, credential theft and ransomware.

After remediation: rotate credentials, patch, then run a fresh `aletheia scan` with a new case ID and compare.
