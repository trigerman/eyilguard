# Test the FULL driver -> scanner -> SHA-256 -> blocklist round-trip on the VM.
#
# test_eicar_vm.ps1 uses an eicar-NAMED file, which trips the driver's filename
# shortcut and is blocked *before* the scanner is ever asked. This script instead
# drops a file with a NON-eicar name but EICAR *content* into the scan scope, so
# the driver has to ask the user-mode scanner, which hashes it (SHA-256 == the
# EICAR hash the scanner treats as blocklisted) and replies INFECTED.
#
# Run ELEVATED, with AvFilter loaded and the scanner running (service OR interactive).
# Tip: to watch the verdict live, stop the service and run the scanner in a console:
#     sc.exe stop EyilGuardScan
#     .\out\Debug\scanner_service.exe --hashes ..\data\hashes.txt
# then run this script in a second elevated window. (Keep Defender OFF in the VM so
# it doesn't grab the EICAR content first.)
[CmdletBinding()]
param([string]$Path = "C:\EyilScanLab\notavirus.txt")

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null

$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

Write-Host "Writing EICAR content to a NON-eicar name: $Path" -ForegroundColor Yellow
Set-Content -LiteralPath $Path -Value $eicar -NoNewline -Encoding ASCII -ErrorAction SilentlyContinue

if (-not (Test-Path -LiteralPath $Path)) {
  Write-Host "BLOCKED at write — the scanner caught the content on create." -ForegroundColor Green
  Write-Host "=> driver -> scanner -> SHA-256 -> blocklist round-trip works." -ForegroundColor Green
  return
}

Write-Host "Reading it back — the driver must now ask the scanner, which hashes + blocks:" -ForegroundColor Yellow
try {
  $null = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
  Write-Warning ("Read SUCCEEDED — the hash round-trip did NOT block it. Check: is EyilGuardScan running? " +
                 "Is the path under C:\EyilScanLab\? Did the scanner load the blocklist (it prints the count on start)?")
} catch {
  Write-Host "BLOCKED on read: $($_.Exception.Message)" -ForegroundColor Green
  Write-Host "=> driver -> scanner -> SHA-256 -> blocklist round-trip works end-to-end." -ForegroundColor Green
}
