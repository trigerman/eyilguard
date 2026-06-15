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
$existing = sc.exe query HavenShieldScan 2>$null
if ($LASTEXITCODE -eq 0) {
  sc.exe stop HavenShieldScan | Out-Null
  Start-Sleep -Seconds 1
  sc.exe delete HavenShieldScan | Out-Null
  Start-Sleep -Seconds 1
}

$binPath = "`"$scanner`" --service --hashes `"$HashFile`""
sc.exe create HavenShieldScan binPath= $binPath start= demand obj= LocalSystem DisplayName= "Haven Shield Scanner Bridge"
sc.exe start HavenShieldScan

Write-Host "`nDriver loaded:" -ForegroundColor Green
fltmc filters | Select-String AvFilter
Write-Host "`nScanner service:" -ForegroundColor Green
sc.exe query HavenShieldScan
