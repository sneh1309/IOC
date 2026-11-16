# Detection Catalogue

Generated from `aletheia/detection/rules.py`. Every finding records its rule ID, evidence, severity, confidence and MITRE ATT&CK techniques.

## Heuristic & IOC rules

| Rule | Detects | Category | ATT&CK |
|---|---|---|---|
| `PROC-001` | Process running from a deleted executable | process | T1027, T1620 |
| `PROC-002` | Process executing from a temporary / user-writable location | process | T1036.005, T1204 |
| `PROC-003` | Suspicious command line (reverse shell, download-exec, LOLBin, miner) | process | T1027, T1059.001, T1059.004, T1105, T1496 |
| `PROC-004` | Known offensive / crypto-mining tool running | process | from entry |
| `PROC-005` | LD_PRELOAD injected into a running process | process | T1574.006 |
| `PROC-006` | System process name masquerading | process | T1036.005 |
| `PROC-007` | Office application spawned a shell/script host | process | T1059, T1204 |
| `PROC-008` | Process executable hash matches IOC | ioc | T1204 |
| `NET-001` | Connection to IOC IP address | ioc | T1071 |
| `NET-002` | Established connection on a port commonly used by backdoors / C2 / miners | network | T1571 |
| `NET-003` | Shell or interpreter owns a network socket | network | T1059.004, T1071 |
| `NET-004` | Hosts-file hijack or IOC domain in DNS data | network | T1071, T1562.001, T1565.001 |
| `PERS-001` | Malicious-looking persistence entry | persistence | T1547 |
| `PERS-002` | Dynamic-linker preload configured (/etc/ld.so.preload) | persistence | T1574.006 |
| `PERS-003` | Windows autostart hijack (Winlogon / AppInit / IFEO / LSA / WMI) | persistence | from entry |
| `PERS-004` | Unsigned / out-of-tree kernel module loaded | persistence | T1014, T1547.006 |
| `PERS-005` | PAM module executes external program | persistence | T1556.003 |
| `ACCT-001` | Multiple accounts with UID 0 (root-equivalent) | accounts | T1078, T1136.001 |
| `ACCT-002` | Passwordless sudo for non-root principals | accounts | T1548.003 |
| `ACCT-003` | SSH authorized_keys with forced command or planted keys | accounts | T1098.004 |
| `AUTH-001` | Brute-force activity and possible successful compromise | logs | T1021.004, T1078, T1110 |
| `EVT-001` | Security-relevant Windows events | logs | T1027, T1059.001, T1543.003, T1569.002 |
| `HIST-001` | Attacker tradecraft in shell history | logs | T1059, T1059.004, T1070.003, T1071, T1105, T1136.001, T1496 |
| `FILE-001` | File hash matches IOC | ioc | T1204 |
| `FILE-002` | Executable or hidden binary in temp/user-writable location | filesystem | T1036, T1105, T1564.001 |
| `FILE-003` | SUID/SGID binary in non-standard location or SUID shell | filesystem | T1548.001 |
| `FILE-004` | Web shell indicators | filesystem | T1505.003 |
| `FILE-005` | Double-extension / disguised executable | filesystem | T1036 |
| `POST-001` | Security controls disabled or weakened | posture | T1562.001, T1562.004 |

Related IDs raised by these rules: `ACCT-004` (SSH key inventory), `EVT-002` (malicious PowerShell 4104 script block), `EVT-003` (suspicious service install 7045), `POST-002` (Defender exclusions), `POST-003` (firewall off), `POST-004` (ASLR off), `SCOPE-001` (not elevated).

## Command-line / script patterns (PROC-003, PERS-001, HIST-001, EVT-002)

Reverse shells (bash `/dev/tcp`, netcat `-e`, socat exec, mkfifo, python/perl/php sockets, PowerShell TCPClient), download-and-execute (`curl|sh`, base64-decode-pipe-to-shell, PowerShell cradles, `IEX`, `FromBase64String`), encoded or hidden PowerShell, LOLBins (certutil, mshta, regsvr32, rundll32, bitsadmin, wmic, msiexec), ransomware precursors (vssadmin / wbadmin / bcdedit), credential dumping (LSASS minidump, `reg save` of SAM/SECURITY), crypto-miner configuration.

## Known attacker tools (PROC-004)

beacon.exe, bloodhound, chisel, cobaltstrike, cpuminer, frpc, gsecdump, kaiten, kdevtmpfsi, kinsing, lazagne, ligolo, linpeas, meterpreter, mimikatz, minerd, mirai, nanodump, nbminer, ngrok, psexesvc, pspy, pwdump, rubeus, sharphound, sliver, tsunami, wce.exe, winpeas, xmrig

## Windows event IDs (EVT-001)

| Event | Severity | Meaning | ATT&CK |
|---|---|---|---|
| 104 | high | An event log was cleared | T1070.001 |
| 1102 | critical | Security audit log was cleared | T1070.001 |
| 1116 | high | Microsoft Defender detected malware | T1204 |
| 1117 | medium | Microsoft Defender took action on malware | T1204 |
| 1149 | info | RDP authentication succeeded | T1021.001 |
| 4698 | medium | Scheduled task created | T1053.005 |
| 4719 | high | System audit policy was changed | T1562.001 |
| 4720 | medium | Local user account created | T1136.001 |
| 4728 | medium | Member added to a global security group | T1098 |
| 4732 | medium | Member added to a security-enabled local group | T1098 |
| 5001 | high | Defender real-time protection disabled | T1562.001 |
| 5007 | low | Defender configuration changed | T1562.001 |
| 5010 | high | Defender anti-spyware scanning disabled | T1562.001 |
| 5012 | high | Defender anti-virus scanning disabled | T1562.001 |
| 7045 | medium | New service installed | T1543.003, T1569.002 |

Also collected for the timeline and context: Security 4624/4625/4648/4672/4688/4697/4699/4702/4738/4756, TaskScheduler 106/140/141/200, Sysmon 1/3/7/8/10/11/12/13/22.

## YARA (bundled: `aletheia/data/yara/aletheia_core.yar`)

EICAR test file, Linux reverse-shell scripts, PHP and ASPX web shells, PowerShell download cradles, Mimikatz strings, XMRig miner, generic ransom notes, LD_PRELOAD rootkit shared objects. Add community rules with `--yara <dir>` (e.g. [signature-base](https://github.com/Neo23x0/signature-base), [YARA-Forge](https://github.com/YARAHQ/yara-forge)).

## Optional open-source tools (`--with`)

| Tool | Purpose | Footprint on the examined system |
|---|---|---|
| ClamAV `clamscan` | AV signatures | none (no `--remove`/`--move`) |
| chkrootkit | rootkit checks | none |
| rkhunter | rootkit/backdoor checks | writes its log/DB → needs `--allow-tool-footprint` |
| Lynis | hardening audit | writes `/var/log/lynis*` → needs `--allow-tool-footprint` |
| osquery `osqueryi` | SQL cross-check (fileless processes, listeners, startup items) | none |
| Hayabusa / Chainsaw | Sigma rules over Windows event logs | none (output goes to the case folder) |
| Sysinternals `autorunsc` | exhaustive Windows autostarts + signatures | EULA registry key → needs `--allow-tool-footprint` |
| Mandiant capa | capabilities of flagged binaries | none |

## Adding a rule

```python
@rule("PROC-099", "My detection", "process")
def my_rule(a, db):
    return [finding("PROC-099", "title", "high", "T1059", "description",
                    [{"artifact": "processes", "ref": "pid=1", "excerpt": "..."}],
                    "recommendation", [{"type": "kill_process", "pid": 1}])]
```

Add a test in `tests/test_aletheia.py` using synthetic artefacts. Never touch the host system in tests.

## macOS investigation rules (`collectors/macos_forensics.py`)

| Rule | Detects | ATT&CK |
|---|---|---|
| `MAC-001` | Remote-access, monitoring, keylogger or stalkerware product installed (apps, InstallHistory, login/background items, system extensions, profiles) | T1219 / T1056.001 / T1113 |
| `MAC-002` | Non-Apple app granted Input Monitoring, Screen Recording, Accessibility, synthetic input or Full Disk Access (TCC) | T1056.001 / T1113 / T1548 |
| `MAC-003` | Remote Login (SSH), Screen Sharing / Remote Management, Remote Apple Events enabled | T1021 |
| `MAC-004` | Remote session / authentication events (screensharingd, sshd, ARDAgent) in the unified log | T1021.004 / T1021.005 |
| `MAC-005` | Apple Mail rule that forwards / redirects mail or references a watched address | T1114.003 |
| `MAC-006` | Mail sent or forwarded to a watched address (first/last date) | T1114.003 |
| `MAC-007` | Log erase, system clock change or `tccutil` privacy reset events | T1070 / T1070.006 |
| `MAC-008` | Configuration profiles or MDM enrolment present | T1072 |

The investigation also produces the Q1–Q9 answer tables (report section 1A, `report/investigation/*.csv`). See [MAC_USER_GUIDE.md](MAC_USER_GUIDE.md).
