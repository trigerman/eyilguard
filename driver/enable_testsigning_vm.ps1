[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
  IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this inside the VM as Administrator." }

bcdedit /set testsigning on
Write-Host "Test signing enabled. Reboot the VM before loading avfilter.sys." -ForegroundColor Yellow
