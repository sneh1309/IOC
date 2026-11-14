# Methodology & Standards

Aletheia implements a **live-response triage** methodology. This page explains each step and the standard it satisfies, so an examiner can describe the process in a report or under cross-examination.

## 1. Principles (ACPO / NPCC, ISO/IEC 27037)

| Principle | How Aletheia meets it |
|---|---|
| 1. Do not change data that may be relied on in court | Read-only file handles (`O_RDONLY`, `O_NOATIME` on Linux). Symlinks are never followed and device/FIFO/socket files are never opened. Commands come from a read-only allow-list, and state-changing sub-commands are refused even for allowed binaries (`reg delete`, `systemctl stop`, `clamscan --remove`, `wevtutil cl`, PowerShell `Set-*`/`Remove-*` …). The tool never writes outside the case folder, and refuses to analyse its own case folder. |
| 2. Where originals must be accessed, the person must be competent and able to explain | Each finding states the rule, the evidence, its confidence and its ATT&CK mapping. This methodology document is the explanation. |
| 3. An audit trail must be created and preserved | `logs/audit.jsonl` records every collector, command (argv, start/end, return code, output SHA-256), artefact (file + SHA-256), error and decision. Each entry includes the hash of the previous one. |
| 4. The person in charge is responsible | The examiner name is mandatory and recorded in the case, the audit log, the report and the declaration. Remediation also records the approver's name. |

## 2. Order of volatility (RFC 3227)

Collection runs from most to least volatile:

1. System clock and identity (the timeline anchor). UTC, local time, offset and boot time are all recorded.
2. Running processes, with hashes of their executables.
3. Network sockets mapped to processes, plus DNS cache, ARP cache, routes and the hosts file.
4. Logged-on sessions and accounts.
5. Persistence / autostart locations.
6. File-system metadata and hashes.
7. Logs and shell histories.
8. Installed software.

Memory acquisition is outside the scope of a triage tool. When a fileless or rootkit finding appears, the report recommends capturing memory with a dedicated tool (AVML, LiME, WinPmem, OSXPmem) **before** remediation.

## 3. Preservation and integrity (ISO/IEC 27037 §7, NIST SP 800-86 §3.1.2)

* Every artefact is written with exclusive-create (`'x'`), so nothing is ever overwritten. It is then set read-only.
* SHA-256 is the evidentiary hash. MD5 and SHA-1 are computed only to match legacy threat-intel feeds.
* At the end, `SHA256SUMS` covers every file in the case. `aletheia verify` recomputes all hashes, checks the audit chain, and reports any file that is **ALTERED**, **MISSING** or **UNLISTED** (added after sealing).
* With `--sign <key>`, `SHA256SUMS` gets a detached GPG signature.
* The report embeds the **tool build hash**: the SHA-256 over every source and rule file of the exact Aletheia version that ran. This makes the result reproducible and verifiable (Daubert: testability).
* **Record the manifest SHA-256 printed at the end of the scan in your contemporaneous notes.**

## 4. Examination and analysis (ISO/IEC 27042, NIST SP 800-86 §3.3)

| Technique | Detail |
|---|---|
| IOC matching | Hashes (SHA-256/SHA-1/MD5), IPv4/IPv6, domains (including parent-domain matching), URLs and file names. Sources: built-in list, `--ioc` files (txt/CSV/JSON/STIX 2.1/MISP), and `~/.aletheia/feeds` (abuse.ch Feodo Tracker, URLhaus, MalwareBazaar, ThreatFox, SSLBL). The SHA-256 and download time of every feed are recorded so the intelligence used in the case can be reproduced. |
| Heuristic rules | 30+ rules covering processes, network, persistence, accounts, logs, files and posture. Each one is mapped to MITRE ATT&CK; see [DETECTIONS.md](DETECTIONS.md). |
| Signatures | YARA (bundled rules plus any community set). Optionally ClamAV, chkrootkit, rkhunter, osquery, Hayabusa / Chainsaw (Sigma) and capa. |
| Timeline | System boot, flagged process starts, file times of flagged files, and Windows events, all normalised to UTC. |

Each finding has a **severity** (critical / high / medium / low / info) and a **confidence** (high / medium / low). The overall verdict follows fixed rules:

| Verdict | Condition |
|---|---|
| COMPROMISE INDICATED | ≥1 critical |
| SUSPICIOUS – INVESTIGATION REQUIRED | ≥1 high |
| ANOMALIES DETECTED | ≥1 medium |
| NO INDICATORS OF COMPROMISE IDENTIFIED | otherwise, explicitly "within scope", and "not proof the device is clean" |

## 5. Reporting (ISO/IEC 27042 §9, NIST SP 800-61r3)

Outputs: `report.html` / `report.pdf` (for humans and court), `report.json` (complete), `findings.csv`, `timeline.csv`, `iocs_stix21.json` (OASIS STIX 2.1 indicators + sightings for sharing with ISACs and CERTs), and `remediation_plan.json`.

## 6. Framework mapping

| Framework | Mapping |
|---|---|
| **NIST CSF 2.0** | Analysis → DE.CM, DE.AE, RS.AN · Reporting → RS.CO, RS.MA · Remediation → RS.MI, RC.RP |
| **NIST SP 800-61r3** | Stage 1 = Detection & Analysis · Stage 2 = Containment, Eradication & Recovery |
| **MITRE ATT&CK** | Every finding lists technique ID, name and tactic, with links |
| **MITRE D3FEND** | Every remediation action is labelled (D3-PT Process Termination, D3-FEV File Eviction, D3-ITF Traffic Filtering, D3-AL Account Locking …) |
| **CIS Controls v8** | 1 & 2 (asset/software inventory), 8 (audit log management), 10 (malware defences), 13 (network monitoring), 17 (incident response) |
| **ISO/IEC 27043** | Readiness → initialisation → acquisitive → investigative processes, mirrored by case → collect → analyse → report |

## 7. Known error sources (Daubert "known error rate")

* Heuristic rules are tuned to favour recall. Confidence levels flag those likely to false-positive (e.g. out-of-tree kernel modules, non-standard ports).
* IOC feeds contain some stale or shared-infrastructure indicators. Feed snapshots are recorded so you can examine them.
* Live tools can be deceived by kernel-level rootkits.
* Non-English Windows locales can localise `schtasks` CSV headers. If scheduled-task coverage is empty on such a system, use `--with autorunsc`.
* The automated test-suite (`tests/`) verifies detection, tamper detection and the remediation gate on Linux, Windows and macOS in CI.
