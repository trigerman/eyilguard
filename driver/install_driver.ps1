# Eyil Guard minifilter — test-sign, install, load, and start.
# Run ELEVATED, inside a TEST VM only. Assumes you already BUILT avfilter.sys
# (VS + WDK) and scanner_service.exe (cl). See BUILD_DRIVER.md.
#
#   powershell -ExecutionPolicy Bypass -File install_driver.ps1
#
# Prereq: test signing must be ON (one-time, then reboot):
#   bcdedit /set testsigning on
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$sys  = Join-Path $Root "avfilter.sys"
$inf  = Join-Path $Root "avfilter.inf"
$cat  = Join-Path $Root "avfilter.cat"
$svc  = Join-Path $Root "scanner_service.exe"
$CN   = "EyilGuardTest"

function Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) }
if (-not (Admin)) { Write-Error "Run this elevated (Administrator)."; exit 1 }
if (-not (Test-Path $sys)) { Write-Error "avfilter.sys not found — build it first (see BUILD_DRIVER.md)."; exit 1 }

if (-not ((bcdedit | Out-String) -match "testsigning\s+Yes")) {
  Write-Warning "Test signing appears OFF. Run:  bcdedit /set testsigning on   then reboot, then re-run this."
}

# 1. Create (or reuse) a self-signed code-signing cert and trust it machine-wide.
Write-Host "[1/6] Test certificate..." -ForegroundColor Yellow
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=$CN" } | Select-Object -First 1
if (-not $cert) {
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CN" `
            -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature -HashAlgorithm SHA256
}
$pfx = Join-Path $env:TEMP "eyilguardtest.pfx"
$pw  = ConvertTo-SecureString "eyil" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pw | Out-Null
Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\LocalMachine\Root -Password $pw | Out-Null
Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -Password $pw | Out-Null

# 2. Locate signtool + inf2cat from the installed WDK/SDK.
Write-Host "[2/6] Locating WDK tools..." -ForegroundColor Yellow
$signtool = (Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -EA SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1).FullName
$inf2cat  = (Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x86\inf2cat.exe" -EA SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1).FullName
if (-not $signtool) { Write-Error "signtool.exe not found — install the Windows SDK/WDK."; exit 1 }

# 3. Build the catalog from the INF, then sign the .sys and .cat.
Write-Host "[3/6] Catalog + signing..." -ForegroundColor Yellow
if ($inf2cat) { & $inf2cat /driver:$Root /os:10_X64 /verbose }
& $signtool sign /v /fd sha256 /s My /n $CN $sys
if (Test-Path $cat) { & $signtool sign /v /fd sha256 /s My /n $CN $cat }

# 4. Install the driver package (copies .sys to System32\drivers, registers service).
Write-Host "[4/6] Installing driver package..." -ForegroundColor Yellow
pnputil /add-driver $inf /install

# 5. Load the minifilter.
Write-Host "[5/6] Loading minifilter..." -ForegroundColor Yellow
fltmc load avfilter

# 6. Install + start the user-mode scanner service.
Write-Host "[6/6] Scanner service..." -ForegroundColor Yellow
if (Test-Path $svc) {
  sc.exe create EyilGuardScan binPath= "`"$svc`" --service" start= auto DisplayName= "Eyil Guard Scanner" | Out-Null
  sc.exe start EyilGuardScan | Out-Null
} else {
  Write-Warning "scanner_service.exe not built — build it, then run elevated: scanner_service.exe (or as the EyilGuardScan service)."
}

Write-Host "`nDone. Verify:" -ForegroundColor Green
Write-Host "  fltmc filters            # 'avfilter' should be listed"
Write-Host "  Test (safe): create an EICAR file — the open should be BLOCKED (STATUS_VIRUS_INFECTED)."
Write-Host "Remove with: install_driver.ps1's companion -> uninstall_driver.ps1"
