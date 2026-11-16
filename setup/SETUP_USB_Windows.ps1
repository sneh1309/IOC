# Aletheia - prepare the USB stick on a WINDOWS computer (run once).
# Downloads the official portable Python builds for macOS (python-build-standalone, used by uv/Astral)
# for Apple Silicon AND Intel Macs, verifies SHA-256, and unpacks them next to the tool.
# Nothing is installed on this computer; everything goes into the aletheia folder on the USB.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Tag = '20260718'; $Ver = '3.12.13'
$Mirrors = @("https://github.com/astral-sh/python-build-standalone/releases/download/$Tag",
             "https://releases.astral.sh/github/python-build-standalone/releases/download/$Tag")
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'
Write-Host "Aletheia USB setup - target folder: $Root`n"

$sums = $null
foreach ($m in $Mirrors) { try { $sums = (Invoke-WebRequest -UseBasicParsing "$m/SHA256SUMS").Content; break } catch {} }
if ($sums -is [byte[]]) { $sums = [Text.Encoding]::UTF8.GetString($sums) }

foreach ($arch in 'aarch64', 'x86_64') {
    $name = "cpython-$Ver+$Tag-$arch-apple-darwin-install_only_stripped.tar.gz"
    $tmp = Join-Path $env:TEMP $name
    Write-Host "Downloading Python $Ver for $arch Macs ..."
    $ok = $false
    foreach ($m in $Mirrors) {
        try { Invoke-WebRequest -UseBasicParsing -Uri "$m/$($name -replace '\+', '%2B')" -OutFile $tmp; $ok = $true; break }
        catch { Write-Host "  (mirror unavailable: $m)" }
    }
    if (-not $ok) { throw "Download failed for $arch - check your internet connection / firewall." }
    $hash = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
    $line = if ($sums) { ($sums -split "`n") | Where-Object { $_ -match [regex]::Escape($name) } | Select-Object -First 1 }
    if ($line) {
        $expected = ($line.Trim() -split '\s+')[0].ToLower()
        if ($expected -ne $hash) { Remove-Item $tmp; throw "SHA-256 MISMATCH for $name - download rejected." }
        Write-Host "  SHA-256 verified: $hash"
    } else { Write-Host "  SHA-256 (record this): $hash  [official checksum list not reachable]" }

    $x = Join-Path $env:TEMP "aletheia_py_$arch"
    if (Test-Path $x) { Remove-Item -Recurse -Force $x }
    New-Item -ItemType Directory $x | Out-Null
    # 'cannot create symlink' warnings are expected (exFAT/NTFS without privilege) and harmless.
    $ErrorActionPreference = 'Continue'
    & tar.exe -xzf $tmp -C $x 2>&1 | Out-Null
    $ErrorActionPreference = 'Stop'
    $dest = Join-Path $Root "python-$arch"
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }   # only our own python folder on the USB
    Copy-Item -Recurse (Join-Path $x 'python') $dest
    Remove-Item -Recurse -Force $x; Remove-Item $tmp
    if (-not (Test-Path (Join-Path $dest 'bin\python3.12'))) { throw "Unpack failed for $arch" }
    Write-Host "  Installed to $dest`n"
}
Write-Host "DONE. The USB is ready. On the client's Mac follow the User Guide, Step 2 onwards."
