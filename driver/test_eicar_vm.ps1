[CmdletBinding()]
param(
  [string]$Path = "$env:TEMP\eyil-eicar.com"
)

$ErrorActionPreference = "Continue"

$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -LiteralPath $Path -Value $eicar -NoNewline -Encoding ASCII

Write-Host "Created harmless EICAR test file: $Path" -ForegroundColor Yellow
Write-Host "Attempting to read it. Expected result with driver+service active: access blocked or antivirus warning."

try {
  Get-Content -LiteralPath $Path -ErrorAction Stop | Out-Null
  Write-Warning "Read succeeded. Check: fltmc filters, sc query EyilGuardScan, and scanner service logs."
} catch {
  Write-Host "Read failed as expected: $($_.Exception.Message)" -ForegroundColor Green
}
