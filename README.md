# Aletheia

**Read-only IOC hunting and forensic triage, with court-ready reports and a separate remediation stage that a human must approve.**

> *Aletheia* (ἀλήθεια) is Greek for "truth", literally "un-concealment". The tool brings hidden things to light without changing them.

Aletheia examines a live Windows, Linux or macOS device for indicators of compromise and produces an evidence package you can file with a case or submit to court. It never alters, deletes or tampers with the data it examines. A **second, separate stage** can then remove the threats it found, but only after a human reviews the exact plan and approves it at a keyboard.

```
┌────────────────────── STAGE 1 · ANALYSIS (read-only) ──────────────────────┐
│ collect (RFC 3227 order) → preserve (write-once + SHA-256 + hash-chained   │
│ audit log) → detect (IOC feeds · MITRE ATT&CK rules · YARA · optional OSS  │
│ scanners) → report (HTML/PDF · JSON · CSV · STIX 2.1) → SEAL (SHA256SUMS)   │
└───────────────────────────────────┬────────────────────────────────────────┘
                                    │  remediation PLAN (proposal, SHA-256 identified)
                                    ▼
┌──────────── STAGE 2 · REMEDIATION (human-approved, interactive only) ──────┐
│ verify seal → show every action (what / why / risk / reversible) →         │
│ approver name → "APPROVE <CASE-ID>" → all or pick individually → "EXECUTE" │
│ → per action: re-check target → back up → change → verify → log rollback   │
│ → separate sealed remediation report (the analysis evidence is untouched)  │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Highlights

| | |
|---|---|
| **Forensically sound** | Files opened `O_RDONLY` (+`O_NOATIME` on Linux). Symlinks are never followed and FIFOs/devices are never opened. System commands run from a **read-only allow-list** with forbidden-argument checks. Output goes only to the case folder. |
| **Chain of custody** | Every artefact is written once (exclusive-create) and set read-only. Every action is recorded in a **SHA-256 hash-chained audit log**. Every command's output is preserved and hashed. The case is sealed with `SHA256SUMS`, with optional GPG signing. `aletheia verify` proves integrity at any time. |
| **Court-ready report** | Cover sheet, executive verdict, scope and limitations, methodology and standards, findings with evidence, ATT&CK coverage, timeline, chain-of-custody and transfer table, evidence manifest, tool build hash, examiner declaration and signature blocks. Prints straight to PDF. |
| **Detection** | 30+ heuristic rules mapped to **MITRE ATT&CK**, IOC matching (hash / IP / domain / URL / filename) from txt, CSV, JSON, **STIX 2.1** and **MISP** sources, free **abuse.ch** feeds, bundled **YARA** rules plus your own (e.g. signature-base, YARA-Forge). |
| **Open-source integrations** | ClamAV, chkrootkit, rkhunter, Lynis, osquery, Hayabusa, Chainsaw (Sigma), Sysinternals Autoruns and Mandiant capa, all optional. Each tool's footprint on the system is documented, and tools that write to the system are refused unless you allow them. |
| **Human-approved remediation** | Kill process (PID-reuse safe), quarantine (hash-verified, restorable), disable cron / systemd / launchd / service / scheduled task / Run-key, comment out hijacked lines, block IPs, lock accounts. Every action is labelled with **MITRE D3FEND**. |
| **Zero dependencies** | Pure Python standard library (3.9+), so there is nothing to install on a suspect machine. Runs from a USB stick: `python run_aletheia.py scan ...` |
| **Works with Claude** | A Claude Code plugin (skill + slash commands) and an MCP server. You ask in plain English, and Claude runs the analysis and explains it. Remediation always stays in human hands. |

## What it examines

| Area | Linux | Windows | macOS |
|---|---|---|---|
| Clock, identity, security posture | ✔ (ASLR, SELinux, ufw, ld.so.preload, taint) | ✔ (Defender + exclusions, Firewall, BitLocker, audit policy) | ✔ (SIP, Gatekeeper, FileVault) |
| Processes + executable hashes | ✔ `/proc` (deleted/memfd binaries, LD_PRELOAD env) | ✔ CIM (owner, parent, command line) | ✔ |
| Network sockets → owning process | ✔ | ✔ | ✔ |
| Hosts file, DNS cache, ARP, proxy | ✔ | ✔ | ✔ |
| Accounts, privileged groups, sudoers, sessions, SSH keys | ✔ | ✔ | ✔ |
| Persistence | cron/at, systemd, rc.local, init.d, shell profiles, XDG autostart, udev, PAM, kernel modules, ld.so.preload | Run/RunOnce, Winlogon, AppInit, IFEO, LSA, BootExecute, scheduled tasks, services, Startup folders, WMI subscriptions | LaunchAgents/Daemons, cron, shell profiles |
| File triage (hash, metadata, type, hidden, SUID) | ✔ | ✔ | ✔ |
| Logs and history | auth.log/secure (+.gz), journald, shell histories | Security / System / PowerShell 4104 / Defender / TaskScheduler / RDP / Sysmon events, PSReadLine history | shell histories |
| Installed software | dpkg / rpm | registry | /Applications |

## Install

```bash
git clone https://github.com/sneh1309/IOC.git aletheia && cd aletheia

# Option A: no install (ideal for a USB toolkit)
python3 run_aletheia.py --version          # Windows: py run_aletheia.py --version

# Option B: install the `aletheia` command
pipx install .            # or: pip install .            optional YARA engine: pip install ".[yara]"
```

Run it **elevated** (root / Administrator) for full coverage. Unprivileged runs still work, and the report says what could not be seen.

## Use

```bash
# 0. (optional) download free threat-intel feeds (abuse.ch, CC0). Scans themselves never use the network.
aletheia feeds update

# 1. ANALYSIS: read-only, sealed, court-ready
sudo aletheia scan \
  --examiner "Jane Doe, GCFA" --org "Example IT" \
  --case-id "INC-2026-0142" --client "Acme Ltd" \
  --purpose "Suspected compromise - ticket 48812, written client consent" \
  --evidence-item "Dell Latitude 7440, S/N ABC123" \
  --profile standard --output /media/usb/cases --pdf \
  [--ioc case_iocs.txt] [--yara ./signature-base/yara] [--with clamscan --with osqueryi]

# 2. Verify integrity at any time (e.g. before court)
aletheia verify /media/usb/cases/INC-2026-0142_20261114T160023Z

# 3. Review the proposed remediation (changes nothing)
aletheia plan /media/usb/cases/INC-2026-0142_20261114T160023Z

# 4. REMEDIATION: a human at the keyboard must approve
sudo aletheia remediate /media/usb/cases/INC-2026-0142_20261114T160023Z
```

At the end of `scan`, Aletheia asks whether you want to review the plan now. The default answer is **No**.

### Profiles

| Profile | Files hashed | Max file size | Depth | Typical time |
|---|---|---|---|---|
| `quick` | 5,000 | 25 MB | 4 | 1–3 min |
| `standard` | 50,000 | 100 MB | 8 | 5–15 min |
| `deep` | 500,000 | 512 MB | 32 (whole home directories, system binaries, /etc) | 30 min+ |

### Case folder

```
INC-2026-0142_20261114T160023Z/
├── case.json                      case + examiner + tool build hash
├── evidence/*.json                every raw artefact (read-only)
├── evidence/commands/*.txt        verbatim output of every command run
├── logs/audit.jsonl               hash-chained chain-of-custody log
├── report/report.html|.pdf        court-ready report
├── report/report.json             full machine-readable report
├── report/findings.csv, timeline.csv
├── report/iocs_stix21.json        STIX 2.1 bundle (indicators + sightings)
├── report/remediation_plan.json   the proposal (SHA-256 identified)
├── SHA256SUMS (+ .sig)            seal over everything above
└── remediation_<UTC>/             created ONLY if a human approves stage 2
    ├── remediation_report.html|json, remediation_audit.jsonl
    ├── backups/  quarantine/      everything needed to roll back
    └── SHA256SUMS
```

## Using it from Claude

Install it once as a Claude Code plugin straight from GitHub:

```
/plugin marketplace add sneh1309/IOC
/plugin install aletheia@aletheia
```

Then just type, for example:

> *"Scan this laptop for compromise. I'm Jane Doe, case INC-2026-0142 for Acme."*
> *"Explain the critical findings in plain English."*
> *"What would the remediation do?"*

Or use the slash commands `/aletheia-scan`, `/aletheia-plan`, `/aletheia-verify` and `/aletheia-ioc`. Claude runs the read-only analysis and explains the results. For remediation it shows and explains the plan, then asks **you** to run `! aletheia remediate <case>` yourself. The tool refuses to execute remediation without an interactive terminal, so no AI agent, script or pipe can trigger it. See [docs/CLAUDE_INTEGRATION.md](docs/CLAUDE_INTEGRATION.md) for Claude Desktop (MCP) setup.

## Documentation

* [Methodology & standards](docs/METHODOLOGY.md): ISO/IEC 27037/27041-27043, NIST SP 800-86 / 800-61r3 / CSF 2.0, RFC 3227, ACPO, SWGDE, MITRE ATT&CK / D3FEND, CIS v8
* [Court & evidence handling](docs/COURT_EVIDENCE.md): admissibility notes (Canada, US, UK), examiner checklist
* [Remediation safety model](docs/REMEDIATION.md)
* [Detection catalogue](docs/DETECTIONS.md)
* [Claude integration](docs/CLAUDE_INTEGRATION.md)
* [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Honest limitations

* **Live triage is not a disk image.** Running any program on a live system leaves a minimal footprint (process creation, memory). Aletheia minimises it and documents it. For serious matters, also take a forensic disk image and a memory capture (e.g. FTK Imager, `dc3dd`, AVML, WinPmem) and analyse them offline.
* A kernel-level rootkit can hide things from any tool running on the same system.
* Heuristics produce false positives. Every finding carries a confidence level and its evidence, so a qualified examiner can validate it.
* Aletheia supports expert testimony but does not replace it. Admissibility is decided by the court, so consult counsel.

## License

[MIT](LICENSE). Free for commercial and non-commercial use. Third-party tools it can call are licensed separately.
