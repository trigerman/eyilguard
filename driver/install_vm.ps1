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
$sys = Join-Path $PackageDir "avfilter.sys"
$scanner = Join-Path $PackageDir "scanner_service.exe"
if (-not (Test-Path $inf)) { throw "Missing $inf. Run driver\build_vm.ps1 first." }
if (-not (Test-Path $sys)) { throw "Missing $sys. Run driver\build_vm.ps1 first." }
if (-not (Test-Path $scanner)) { throw "Missing $scanner. Run driver\build_vm.ps1 first." }

Write-Host "Registering minifilter service..." -ForegroundColor Yellow
fltmc unload AvFilter 2>$null | Out-Null
sc.exe stop AvFilter 2>$null | Out-Null
sc.exe delete AvFilter 2>$null | Out-Null
Start-Sleep -Seconds 1

Copy-Item -LiteralPath $sys -Destination "$env:SystemRoot\System32\drivers\avfilter.sys" -Force

$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\AvFilter"
New-Item -Path $serviceKey -Force | Out-Null
New-ItemProperty -Path $serviceKey -Name Type -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $serviceKey -Name Start -Value 3 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $serviceKey -Name ErrorControl -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $serviceKey -Name Group -Value "FSFilter Anti-Virus" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $serviceKey -Name ImagePath -Value "system32\drivers\avfilter.sys" -PropertyType ExpandString -Force | Out-Null

$parametersKey = Join-Path $serviceKey "Parameters"
New-Item -Path $parametersKey -Force | Out-Null
New-ItemProperty -Path $parametersKey -Name SupportedFeatures -Value 3 -PropertyType DWord -Force | Out-Null
$instancesKey = Join-Path $serviceKey "Instances"
$instanceKey = Join-Path $instancesKey "AvFilter Instance"
New-Item -Path $instancesKey -Force | Out-Null
New-ItemProperty -Path $instancesKey -Name DefaultInstance -Value "AvFilter Instance" -PropertyType String -Force | Out-Null
New-Item -Path $instanceKey -Force | Out-Null
New-ItemProperty -Path $instanceKey -Name Altitude -Value "321410" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $instanceKey -Name Flags -Value 0 -PropertyType DWord -Force | Out-Null

Write-Host "Loading AvFilter..." -ForegroundColor Yellow
fltmc load AvFilter

Write-Host "Installing scanner bridge service..." -ForegroundColor Yellow
$existing = sc.exe query EyilGuardScan 2>$null
if ($LASTEXITCODE -eq 0) {
  sc.exe stop EyilGuardScan | Out-Null
  Start-Sleep -Seconds 1
  sc.exe delete EyilGuardScan | Out-Null
  Start-Sleep -Seconds 1
}

$binPath = "`"$scanner`" --service --hashes `"$HashFile`""
sc.exe create EyilGuardScan binPath= $binPath start= demand obj= LocalSystem DisplayName= "Eyil Guard Scanner Bridge"
sc.exe start EyilGuardScan

$labRoot = "C:\EyilScanLab"
New-Item -ItemType Directory -Force -Path $labRoot | Out-Null
Write-Host "Lab scan scope: $labRoot" -ForegroundColor Cyan

Write-Host "`nDriver loaded:" -ForegroundColor Green
fltmc filters | Select-String AvFilter
Write-Host "`nScanner service:" -ForegroundColor Green
sc.exe query EyilGuardScan
