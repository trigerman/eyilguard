# Eyil Guard - uninstall.
#
#   powershell -ExecutionPolicy Bypass -File uninstall.ps1           # remove the install footprint
#   powershell -ExecutionPolicy Bypass -File uninstall.ps1 -Purge    # also delete the built exe + local data
#
# Default: stops the listener and removes the autostart entry, the desktop shortcut
# and the log folder. Leaves ClamAV, your keys/data and the project source intact.
# -Purge additionally deletes dist\Eyil and the runtime data (keys, allowlist,
# quarantine) — but never the source code.
[CmdletBinding()]
param([switch]$Purge)

$ErrorActionPreference = "SilentlyContinue"
$Root = $PSScriptRoot
$removed = @()

# 1. Stop any running listener / packaged app.
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe' OR Name='Eyil.exe'" |
  Where-Object { $_.CommandLine -like "*eyil*" -or $_.Name -eq "Eyil.exe" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force; $removed += "stopped PID $($_.ProcessId)" }

# 2. Autostart entries (current + the old Haven name).
$startup = [Environment]::GetFolderPath('Startup')
foreach ($n in @("EyilGuard.vbs", "HavenShield.vbs")) {
  $p = Join-Path $startup $n
  if (Test-Path $p) { [IO.File]::Delete($p); $removed += $p }
}

# 3. Desktop shortcuts (normal + OneDrive desktop, current + old Haven name).
$desktops = @([Environment]::GetFolderPath('Desktop'))
if ($env:OneDrive) { $desktops += (Join-Path $env:OneDrive 'Desktop') }
foreach ($d in ($desktops | Select-Object -Unique)) {
  foreach ($n in @("Eyil Guard.lnk", "Haven Shield.lnk")) {
    $p = Join-Path $d $n
    if (Test-Path $p) { [IO.File]::Delete($p); $removed += $p }
  }
}

# 4. Log / state folder under LOCALAPPDATA.
if ($env:LOCALAPPDATA) {
  $logDir = Join-Path $env:LOCALAPPDATA 'EyilGuard'
  if (Test-Path $logDir) { Remove-Item $logDir -Recurse -Force; $removed += $logDir }
}

# 5. -Purge: the built exe + local runtime data (NOT the source code).
if ($Purge) {
  $dist = Join-Path $Root 'dist\Eyil'
  if (Test-Path $dist) { Remove-Item $dist -Recurse -Force; $removed += $dist }
  foreach ($rel in @('data\keys.json', 'data\allowlist.json', 'data\quarantine')) {
    $p = Join-Path $Root $rel
    if (Test-Path $p) { Remove-Item $p -Recurse -Force; $removed += $p }
  }
}

Write-Host "`nEyil Guard uninstalled." -ForegroundColor Green
if ($removed.Count) { $removed | ForEach-Object { Write-Host "  removed  $_" -ForegroundColor DarkGray } }
else { Write-Host "  nothing to remove (already clean)." -ForegroundColor DarkGray }
if (-not $Purge) {
  Write-Host "ClamAV, your keys/data and the project source were left intact." -ForegroundColor DarkGray
  Write-Host "Run with -Purge to also delete the built exe and local data." -ForegroundColor DarkGray
}
Write-Host "To remove everything, delete this folder:`n  $Root" -ForegroundColor DarkGray
