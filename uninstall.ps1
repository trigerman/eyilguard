# Eyil Guard - uninstall (removes autostart + shortcut, stops the listener).
# Leaves ClamAV and your data/keys untouched.
#
#   powershell -ExecutionPolicy Bypass -File uninstall.ps1

$ErrorActionPreference = "SilentlyContinue"

# Stop the background listener
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" |
  Where-Object { $_.CommandLine -like "*eyil*--no-window*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

# Remove autostart + desktop shortcut
$startup = [Environment]::GetFolderPath('Startup')
$desktop = [Environment]::GetFolderPath('Desktop')
[System.IO.File]::Delete((Join-Path $startup "EyilGuard.vbs"))
[System.IO.File]::Delete((Join-Path $desktop "Eyil Guard.lnk"))

Write-Host "Eyil autostart + shortcut removed and the listener stopped." -ForegroundColor Green
Write-Host "ClamAV, signatures, and your keys were left intact." -ForegroundColor DarkGray
