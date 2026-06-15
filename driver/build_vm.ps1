[CmdletBinding()]
param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Debug",
  [ValidateSet("x64")]
  [string]$Platform = "x64",
  [switch]$Sign
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Out = Join-Path $Root "out\$Configuration"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Find-MsBuild {
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path $vswhere) {
    $path = & $vswhere -latest -requires Microsoft.Component.MSBuild -find "MSBuild\Current\Bin\MSBuild.exe" | Select-Object -First 1
    if ($path -and (Test-Path $path)) { return $path }
  }
  $cmd = Get-Command msbuild.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  throw "MSBuild not found. Install Visual Studio 2022 with Desktop C++ and Windows Driver Kit integration."
}

$msbuild = Find-MsBuild
& $msbuild (Join-Path $Root "EyilGuardDriver.sln") `
  /m `
  /p:Configuration=$Configuration `
  /p:Platform=$Platform `
  /t:Build

$sys = Get-ChildItem -LiteralPath (Join-Path $Root "build") -Recurse -Filter "avfilter.sys" | Select-Object -First 1
$exe = Get-ChildItem -LiteralPath (Join-Path $Root "build") -Recurse -Filter "scanner_service.exe" | Select-Object -First 1
if (-not $sys) { throw "Built avfilter.sys not found." }
if (-not $exe) { throw "Built scanner_service.exe not found." }

Copy-Item -LiteralPath $sys.FullName -Destination (Join-Path $Out "avfilter.sys") -Force
Copy-Item -LiteralPath $exe.FullName -Destination (Join-Path $Out "scanner_service.exe") -Force
Copy-Item -LiteralPath (Join-Path $Root "avfilter.inf") -Destination (Join-Path $Out "avfilter.inf") -Force

$inf2cat = Get-Command inf2cat.exe -ErrorAction SilentlyContinue
if ($inf2cat) {
  & $inf2cat.Source /driver:$Out /os:10_X64
} else {
  Write-Warning "inf2cat.exe not found. The package was built but no catalog was generated."
}

if ($Sign) {
  $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if (-not $signtool) { throw "signtool.exe not found. Install the Windows SDK/WDK tools." }
  $cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq "CN=Eyil Guard Test Driver" } |
    Select-Object -First 1
  if (-not $cert) {
    $cert = New-SelfSignedCertificate `
      -Type CodeSigningCert `
      -Subject "CN=Eyil Guard Test Driver" `
      -CertStoreLocation Cert:\LocalMachine\My
  }
  $cat = Join-Path $Out "avfilter.cat"
  if (Test-Path $cat) {
    & $signtool.Source sign /v /fd SHA256 /s My /n "Eyil Guard Test Driver" $cat
  } else {
    Write-Warning "No avfilter.cat found to sign."
  }
}

Write-Host "Built VM package: $Out" -ForegroundColor Green
