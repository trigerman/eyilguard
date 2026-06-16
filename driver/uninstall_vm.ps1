[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
  IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this inside the VM as Administrator." }

Write-Host "Stopping scanner bridge service..." -ForegroundColor Yellow
sc.exe stop EyilGuardScan | Out-Null
Start-Sleep -Seconds 1
sc.exe delete EyilGuardScan | Out-Null

Write-Host "Unloading minifilter..." -ForegroundColor Yellow
fltmc unload AvFilter
sc.exe stop AvFilter | Out-Null
sc.exe delete AvFilter | Out-Null
Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\AvFilter" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$env:SystemRoot\System32\drivers\avfilter.sys" -Force -ErrorAction SilentlyContinue

Write-Host "If you need to remove the driver package from the driver store, run:" -ForegroundColor Cyan
Write-Host "  pnputil /enum-drivers | findstr /i avfilter"
Write-Host "  pnputil /delete-driver oemXX.inf /uninstall /force"
