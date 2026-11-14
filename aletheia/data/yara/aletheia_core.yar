/*
   Aletheia bundled YARA rules - small, high-signal set.
   Extend with community rule sets via:  aletheia scan --yara /path/to/rules
   e.g. https://github.com/Neo23x0/signature-base  or  https://github.com/YARAHQ/yara-forge
*/

rule ALETHEIA_EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (harmless test signature)"
        severity = "low"
        mitre = "T1204"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0
}

rule ALETHEIA_Linux_Reverse_Shell_Script
{
    meta:
        description = "Script containing a reverse-shell one-liner"
        severity = "high"
        mitre = "T1059.004"
    strings:
        $a = "/dev/tcp/" ascii
        $b = /bash\s+-i\s+>&/ ascii
        $c = /nc(at)?\s+(-[a-z]*\s+)*-e\s+\/bin\/(ba)?sh/ ascii
        $d = "pty.spawn(" ascii
        $e = /socket\.socket\(.{0,80}connect\(/ ascii
    condition:
        filesize < 2MB and (($a and $b) or $c or ($d and $e))
}

rule ALETHEIA_PHP_Webshell_Generic
{
    meta:
        description = "Generic PHP web shell evaluating request input"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $php = "<?php" nocase
        $e1 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/ nocase
        $e2 = /(system|passthru|shell_exec|exec|popen|proc_open|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $e3 = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        filesize < 2MB and $php and any of ($e*)
}

rule ALETHEIA_ASPX_Webshell_Generic
{
    meta:
        description = "Generic ASP.NET web shell spawning processes from request input"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $a = "<%@ Page" nocase
        $b = "Process.Start" nocase
        $c = "Request" nocase
        $d = "cmd.exe" nocase
    condition:
        filesize < 2MB and $a and $b and $c and $d
}

rule ALETHEIA_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download-and-execute cradle"
        severity = "high"
        mitre = "T1059.001"
    strings:
        $d1 = "DownloadString(" nocase
        $d2 = "DownloadData(" nocase
        $d3 = "Invoke-WebRequest" nocase
        $x1 = "IEX" nocase fullword
        $x2 = "Invoke-Expression" nocase
        $x3 = "FromBase64String" nocase
    condition:
        filesize < 5MB and any of ($d*) and any of ($x*)
}

rule ALETHEIA_Mimikatz_Strings
{
    meta:
        description = "Strings characteristic of Mimikatz credential dumper"
        severity = "critical"
        mitre = "T1003"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "gentilkiwi" ascii wide
        $s3 = "mimikatz" ascii wide nocase
        $s4 = "lsadump::sam" ascii wide nocase
        $s5 = "kerberos::golden" ascii wide nocase
    condition:
        2 of them
}

rule ALETHEIA_XMRig_Miner
{
    meta:
        description = "XMRig / Monero crypto-miner"
        severity = "high"
        mitre = "T1496"
    strings:
        $a = "stratum+tcp://" ascii
        $b = "xmrig" ascii nocase
        $c = "--donate-level" ascii
        $d = "randomx" ascii nocase
        $e = "cryptonight" ascii nocase
    condition:
        3 of them
}

rule ALETHEIA_Ransom_Note_Generic
{
    meta:
        description = "Text resembling a ransomware ransom note"
        severity = "high"
        mitre = "T1486"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "bitcoin" nocase
        $c = "decrypt" nocase
        $d = ".onion" nocase
        $e = "private key" nocase
    condition:
        filesize < 1MB and $a and 2 of ($b, $c, $d, $e)
}

rule ALETHEIA_Linux_LD_Preload_Rootkit
{
    meta:
        description = "Shared object hooking readdir and referencing ld.so.preload (userland rootkit)"
        severity = "critical"
        mitre = "T1574.006"
    strings:
        $elf = { 7F 45 4C 46 }
        $a = "ld.so.preload" ascii
        $b = "readdir" ascii
        $c = "dlsym" ascii
        $d = "RTLD_NEXT" ascii
    condition:
        $elf at 0 and $a and $b and ($c or $d)
}
