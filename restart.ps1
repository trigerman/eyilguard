# Restart Haven Shield so the latest code (and clamd config) takes effect.
#   powershell -ExecutionPolicy Bypass -File restart.ps1
$ErrorActionPreference = "SilentlyContinue"
$Root = $PSScriptRoot
$pythonw = (Get-Command pythonw).Source
if (-not $pythonw) { $pythonw = (Get-Command python).Source }

Write-Host "Stopping all Haven windows/engines..." -ForegroundColor Yellow
Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe' OR Name='Haven.exe'" |
  Where-Object { $_.CommandLine -like "*haven*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

# Restart clamd too so clamd.conf changes (e.g. DetectPUA) apply.
Get-CimInstance Win32_Process -Filter "Name='clamd.exe'" |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

Start-Sleep -Seconds 2
Write-Host "Launching Haven with the latest code..." -ForegroundColor Yellow
Start-Process -FilePath $pythonw -ArgumentList "-m","haven" -WorkingDirectory $Root
Write-Host "Done. The Haven window will open in a few seconds (clamd reloads its signatures first)." -ForegroundColor Green
