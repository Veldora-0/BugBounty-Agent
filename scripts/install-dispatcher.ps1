#
# BugBounty-Agent — Isolated Execution Dispatcher Service Installer (Windows)
#
# NOTICE: Windows production service isolation under a dedicated restricted service identity
# is NOT IMPLEMENTED in this repository. Production deployment requiring an OS-isolated
# execution authority must run on Linux under systemd with the dedicated '_bbdispatcher' identity.
#
# On Windows, Named Pipe IPC is supported strictly for development, integration testing,
# and deterministic local simulation labs.
#
[CmdletBinding()]
param(
    [switch]$DevelopmentHarnessOnly
)

Write-Warning @"
================================================================================
[!] SECURITY NOTICE: WINDOWS PRODUCTION SERVICE ISOLATION IS NOT IMPLEMENTED.
    Production execution authority isolation requires dedicated OS process
    credentials and systemd service confinement on Linux (_bbdispatcher).
    Windows Named Pipe dispatch is provided for local development/testing only.
================================================================================
"@

if (-not $DevelopmentHarnessOnly) {
    Write-Host "[*] To configure local development/test directories, rerun with: -DevelopmentHarnessOnly"
    exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] Error: Administrator elevation required to configure Windows test harness directories."
    exit 1
}

$baseDir = "C:\ProgramData\BugBounty\Dispatcher"
$keysDir = Join-Path $baseDir "Keys"
$stateDir = Join-Path $baseDir "State"
$evDir = Join-Path $baseDir "Evidence"

Write-Host "[*] 1. Creating development harness directories..."
New-Item -ItemType Directory -Path $keysDir -Force | Out-Null
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
New-Item -ItemType Directory -Path $evDir -Force | Out-Null

Write-Host "[*] 2. Enforcing restrictive Windows DACLs..."
# Keys directory: SYSTEM and Administrators only (Standard Users have NO access)
icacls.exe $keysDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" | Out-Null

# State directory: SYSTEM and Administrators only
icacls.exe $stateDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" | Out-Null

# Evidence directory: Authenticated Users can READ, SYSTEM can WRITE
icacls.exe $evDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\Authenticated Users:(OI)(CI)R" | Out-Null

Write-Host "[+] Protected development harness directories configured."
Write-Host "[+] (Note: Production service isolation remains NOT IMPLEMENTED on Windows)."
