# Eyil Guard - setup / installer (user-level; no administrator rights needed).
#
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Installs dependencies, builds the dashboard, pulls signatures + threat feeds,
# registers the always-on background listener (autostart at logon, hidden), and
# drops a desktop shortcut to open the window. Re-runnable / idempotent.
[CmdletBinding()]
param([switch]$SkipBuild, [switch]$NoAutostart)

# Continue on non-fatal errors (optional deps like yara-python may fail to build);
# we check exit codes explicitly and warn rather than aborting the whole setup.
$ErrorActionPreference = "Continue"
$Root = $PSScriptRoot
Write-Host "Eyil Guard setup  -  $Root" -ForegroundColor Cyan

function Need($n) { Get-Command $n -ErrorAction SilentlyContinue }

$py = Need python
if (-not $py) { Write-Error "Python 3.11+ is required (not found on PATH)."; exit 1 }
$python  = $py.Source
$pythonw = $python -replace 'python\.exe$','pythonw.exe'
if (-not (Test-Path $pythonw)) { $pythonw = $python }
Write-Host "Python: $python"

Write-Host "`n[1/6] Installing Python dependencies..." -ForegroundColor Yellow
& $python -m pip install --quiet -r (Join-Path $Root "requirements.txt")
Write-Host "      (optional) YARA support..." -ForegroundColor DarkGray
try { & $python -m pip install --quiet "yara-python>=4.5" 2>$null } catch {}
if ($LASTEXITCODE -ne 0) { Write-Warning "yara-python unavailable for this Python (needs a wheel; available on 3.11-3.13). YARA stays off; everything else works." }
else { Write-Host "      yara-python installed" }

if (-not $SkipBuild) {
  if (Need node) {
    Write-Host "`n[2/6] Building the dashboard..." -ForegroundColor Yellow
    Push-Location (Join-Path $Root "dashboard")
    if (-not (Test-Path "node_modules")) { npm install }
    npm run build
    Pop-Location
  } else { Write-Warning "Node.js not found - skipping UI build (run 'npm run build' in dashboard\ later)." }
} else { Write-Host "[2/6] Skipping UI build (--SkipBuild)" }

Write-Host "`n[3/6] Checking ClamAV..." -ForegroundColor Yellow
if (-not (Need clamd)) {
  if (Need scoop) { scoop install clamav }
  else { Write-Warning "ClamAV not found and scoop unavailable. Install ClamAV for signature scanning (optional - hash/behavioral/network still work)." }
}

Write-Host "`n[4/6] Pulling initial signatures + threat feeds..." -ForegroundColor Yellow
$fcConf = Join-Path $Root "data\clam\freshclam.conf"
if ((Need freshclam) -and (Test-Path $fcConf)) { try { freshclam --config-file=$fcConf } catch { Write-Warning "freshclam will retry automatically." } }
Push-Location $Root
try { & $python -c "from engine.updater import AutoUpdater; from engine.scanners import Engine; print(AutoUpdater(Engine()).run_once())" }
catch { Write-Warning "Feed update will retry automatically once the listener is up." }
Pop-Location

if (-not $NoAutostart) {
  Write-Host "`n[5/6] Installing the background listener (autostart at logon)..." -ForegroundColor Yellow
  $startup = [Environment]::GetFolderPath('Startup')
  $vbs = Join-Path $startup "EyilGuard.vbs"
  @"
' Eyil Guard background listener - starts hidden at logon
Set sh = CreateObject("WScript.Shell")
sh.CurrentDirectory = "$Root"
sh.Run """$pythonw"" -m eyil --no-window", 0, False
"@ | Set-Content -Path $vbs -Encoding ASCII
  Write-Host "  autostart: $vbs"

  $desktop = [Environment]::GetFolderPath('Desktop')
  $lnk = Join-Path $desktop "Eyil Guard.lnk"
  $ws = New-Object -ComObject WScript.Shell
  $sc = $ws.CreateShortcut($lnk)
  $sc.TargetPath = $pythonw
  $sc.Arguments  = "-m eyil"
  $sc.WorkingDirectory = $Root
  $sc.Description = "Open Eyil Guard"
  $sc.Save()
  Write-Host "  shortcut:  $lnk"
} else { Write-Host "[5/6] Skipping autostart (--NoAutostart)" }

Write-Host "`n[6/6] Starting Eyil now..." -ForegroundColor Yellow
Start-Process -FilePath $pythonw -ArgumentList "-m","eyil","--no-window" -WorkingDirectory $Root -WindowStyle Hidden
Start-Sleep -Seconds 4
try {
  $h = Invoke-RestMethod "http://127.0.0.1:8787/health" -TimeoutSec 4
  $state = if ($h.ok) { "up to date" } else { "updating" }
  Write-Host "`n  OK - Eyil is running.  Protection: $state  |  blocklist $($h.hash_feed_count) hashes  |  C2 $($h.c2_count) IPs" -ForegroundColor Green
} catch { Write-Warning "Listener is starting; give it a few seconds, then open the desktop shortcut." }

Write-Host "`nDone. Double-click 'Eyil Guard' on your desktop to open the dashboard." -ForegroundColor Cyan
Write-Host "To remove: powershell -ExecutionPolicy Bypass -File uninstall.ps1" -ForegroundColor DarkGray
