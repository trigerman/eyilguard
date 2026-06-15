# Eyil Shield minifilter — stop, unload, and remove (run ELEVATED in the VM).
#   powershell -ExecutionPolicy Bypass -File uninstall_driver.ps1
$ErrorActionPreference = "SilentlyContinue"

Write-Host "Stopping scanner service..." -ForegroundColor Yellow
sc.exe stop   EyilShieldScan | Out-Null
sc.exe delete EyilShieldScan | Out-Null

Write-Host "Unloading minifilter..." -ForegroundColor Yellow
fltmc unload avfilter

Write-Host "Removing driver service..." -ForegroundColor Yellow
sc.exe delete AvFilter | Out-Null

# For a full package removal, find the oemNN.inf and delete it:
#   pnputil /enum-drivers      (locate the one whose Original Name is avfilter.inf)
#   pnputil /delete-driver oemNN.inf /uninstall /force
Write-Host "`nDone. (Driver no longer loads. To purge the staged package, see the pnputil note in this script.)" -ForegroundColor Green
