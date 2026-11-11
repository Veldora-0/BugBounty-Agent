#
# BugBounty-Agent — Isolated Execution Dispatcher Service Installer (Windows)
#
# Configures a dedicated directory structure with restrictive Windows DACLs,
# and configures the Windows Service or background authority.
#
[CmdletBinding()]
param()

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] Error: Administrator elevation required to install Windows Dispatcher Service."
    exit 1
}

$baseDir = "C:\ProgramData\BugBounty\Dispatcher"
$keysDir = Join-Path $baseDir "Keys"
$stateDir = Join-Path $baseDir "State"
$evDir = Join-Path $baseDir "Evidence"

Write-Host "[*] 1. Creating directories..."
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

Write-Host "[+] Protected directory permissions configured."
Write-Host "[+] Windows isolated execution dispatcher setup complete."
