[CmdletBinding()]
param(
  [string]$PackageDir = "",
  [string]$HashFile = ""
)

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
  IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this inside the VM as Administrator." }

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $PackageDir) { $PackageDir = Join-Path $Root "out\Debug" }
if (-not $HashFile) { $HashFile = Resolve-Path (Join-Path $Root "..\data\hashes.txt") }

$inf = Join-Path $PackageDir "avfilter.inf"
$scanner = Join-Path $PackageDir "scanner_service.exe"
if (-not (Test-Path $inf)) { throw "Missing $inf. Run driver\build_vm.ps1 first." }
if (-not (Test-Path $scanner)) { throw "Missing $scanner. Run driver\build_vm.ps1 first." }

Write-Host "Installing minifilter package..." -ForegroundColor Yellow
pnputil /add-driver $inf /install

Write-Host "Loading AvFilter..." -ForegroundColor Yellow
fltmc load AvFilter

Write-Host "Installing scanner bridge service..." -ForegroundColor Yellow
$existing = sc.exe query EyilShieldScan 2>$null
if ($LASTEXITCODE -eq 0) {
  sc.exe stop EyilShieldScan | Out-Null
  Start-Sleep -Seconds 1
  sc.exe delete EyilShieldScan | Out-Null
  Start-Sleep -Seconds 1
}

$binPath = "`"$scanner`" --service --hashes `"$HashFile`""
sc.exe create EyilShieldScan binPath= $binPath start= demand obj= LocalSystem DisplayName= "Eyil Shield Scanner Bridge"
sc.exe start EyilShieldScan

Write-Host "`nDriver loaded:" -ForegroundColor Green
fltmc filters | Select-String AvFilter
Write-Host "`nScanner service:" -ForegroundColor Green
sc.exe query EyilShieldScan
