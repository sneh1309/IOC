"""Framework catalogues used to label findings and remediation actions.

* MITRE ATT&CK Enterprise (technique -> name, tactic)
* MITRE D3FEND (countermeasure applied by each remediation action type)
* NIST CSF 2.0 (function/category each stage satisfies)
* NIST SP 800-61r3 incident response life-cycle phase
"""

ATTACK = {
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1014": ("Rootkit", "Defense Evasion"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", "Defense Evasion"),
    "T1037": ("Boot or Logon Initialization Scripts", "Persistence"),
    "T1037.004": ("Boot or Logon Initialization Scripts: RC Scripts", "Persistence"),
    "T1053.002": ("Scheduled Task/Job: At", "Persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1070.003": ("Indicator Removal: Clear Command History", "Defense Evasion"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1078": ("Valid Accounts", "Initial Access / Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1204": ("User Execution", "Execution"),
    "T1218": ("System Binary Proxy Execution", "Defense Evasion"),
    "T1219": ("Remote Access Software", "Command and Control"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1543.001": ("Create or Modify System Process: Launch Agent", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1543.004": ("Create or Modify System Process: Launch Daemon", "Persistence"),
    "T1546": ("Event Triggered Execution", "Persistence"),
    "T1546.003": ("Event Triggered Execution: WMI Event Subscription", "Persistence"),
    "T1546.004": ("Event Triggered Execution: Unix Shell Configuration Modification", "Persistence"),
    "T1546.010": ("Event Triggered Execution: AppInit DLLs", "Persistence"),
    "T1546.012": ("Event Triggered Execution: Image File Execution Options Injection", "Persistence"),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence"),
    "T1547.002": ("Boot or Logon Autostart Execution: Authentication Package", "Persistence"),
    "T1547.004": ("Boot or Logon Autostart Execution: Winlogon Helper DLL", "Persistence"),
    "T1547.005": ("Boot or Logon Autostart Execution: Security Support Provider", "Persistence"),
    "T1547.006": ("Boot or Logon Autostart Execution: Kernel Modules and Extensions", "Persistence"),
    "T1547.013": ("Boot or Logon Autostart Execution: XDG Autostart Entries", "Persistence"),
    "T1548.001": ("Abuse Elevation Control Mechanism: Setuid and Setgid", "Privilege Escalation"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation"),
    "T1556.003": ("Modify Authentication Process: Pluggable Authentication Modules", "Credential Access"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "Defense Evasion"),
    "T1564.001": ("Hide Artifacts: Hidden Files and Directories", "Defense Evasion"),
    "T1565.001": ("Data Manipulation: Stored Data Manipulation", "Impact"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1574.006": ("Hijack Execution Flow: Dynamic Linker Hijacking", "Persistence / Defense Evasion"),
    "T1588": ("Obtain Capabilities", "Resource Development"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1569.002": ("System Services: Service Execution", "Execution"),
    "T1112": ("Modify Registry", "Defense Evasion"),
}

D3FEND = {
    "kill_process": ("D3-PT", "Process Termination"),
    "quarantine_file": ("D3-FEV", "File Eviction"),
    "comment_out_line": ("D3-SCF", "System Configuration Hardening / Eviction of persistence entry"),
    "disable_systemd_unit": ("D3-SCF", "Service / Startup Configuration Eviction"),
    "disable_launchd": ("D3-SCF", "Service / Startup Configuration Eviction"),
    "delete_registry_value": ("D3-RE", "Registry Eviction"),
    "disable_scheduled_task": ("D3-SCF", "Scheduled Job Eviction"),
    "disable_service": ("D3-SCF", "Service Eviction"),
    "block_ip": ("D3-ITF", "Inbound/Outbound Traffic Filtering"),
    "disable_account": ("D3-AL", "Account Locking"),
    "remove_ssh_key": ("D3-CR", "Credential Revocation"),
    "manual": ("D3-*", "Analyst-performed countermeasure"),
}

NIST_CSF = {
    "analysis": ["DE.CM (Continuous Monitoring)", "DE.AE (Adverse Event Analysis)", "RS.AN (Incident Analysis)"],
    "reporting": ["RS.CO (Incident Response Reporting & Communication)", "RS.MA (Incident Management)"],
    "remediation": ["RS.MI (Incident Mitigation)", "RC.RP (Incident Recovery Plan Execution)"],
}

NIST_IR_PHASE = {
    "analysis": "Detection & Analysis (NIST SP 800-61r3 / CSF DE, RS.AN)",
    "remediation": "Containment, Eradication & Recovery (NIST SP 800-61r3 / CSF RS.MI, RC)",
}


def attack_info(tid: str) -> dict:
    name, tactic = ATTACK.get(tid, ("", ""))
    url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
    return {"id": tid, "name": name, "tactic": tactic, "url": url}
