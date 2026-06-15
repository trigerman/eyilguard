# Build Haven.exe with PyInstaller.
#   powershell -ExecutionPolicy Bypass -File build_exe.ps1
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Push-Location $Root
try {
  $python = (Get-Command python).Source
  Write-Host "Installing PyInstaller + runtime deps..." -ForegroundColor Yellow
  & $python -m pip install --quiet pyinstaller -r requirements.txt

  if (-not (Test-Path "dashboard\dist\index.html")) {
    Write-Host "Building dashboard first..." -ForegroundColor Yellow
    Push-Location dashboard
    if (-not (Test-Path node_modules)) { npm install }
    npm run build
    Pop-Location
  }

  Write-Host "Running PyInstaller..." -ForegroundColor Yellow
  & $python -m PyInstaller haven.spec --noconfirm --clean

  if (Test-Path "dist\Haven\Haven.exe") {
    Write-Host "`nOK - built: dist\Haven\Haven.exe" -ForegroundColor Green
    Write-Host "Zip the dist\Haven folder to distribute. (clamd is installed separately.)" -ForegroundColor DarkGray
  } else { Write-Warning "Build finished but dist\Haven\Haven.exe was not found - check the PyInstaller output." }
} finally { Pop-Location }
