# Restart Eyil Guard so the latest code (and clamd config) takes effect.
#   powershell -ExecutionPolicy Bypass -File restart.ps1
$ErrorActionPreference = "SilentlyContinue"
$Root = $PSScriptRoot
$pythonw = (Get-Command pythonw).Source
if (-not $pythonw) { $pythonw = (Get-Command python).Source }

Write-Host "Stopping all Eyil windows/engines..." -ForegroundColor Yellow
Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe' OR Name='Eyil.exe'" |
  Where-Object { $_.CommandLine -like "*eyil*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

# Restart clamd too so clamd.conf changes (e.g. DetectPUA) apply.
Get-CimInstance Win32_Process -Filter "Name='clamd.exe'" |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

Start-Sleep -Seconds 2
Write-Host "Launching Eyil with the latest code..." -ForegroundColor Yellow
Start-Process -FilePath $pythonw -ArgumentList "-m","eyil" -WorkingDirectory $Root
Write-Host "Done. The Eyil window will open in a few seconds (clamd reloads its signatures first)." -ForegroundColor Green
