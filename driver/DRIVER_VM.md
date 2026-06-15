# Eyil Shield Kernel MVP — VM Workflow

This folder now contains a buildable first kernel-level AV MVP:

- `avfilter.c` — Windows file-system minifilter. It intercepts file opens and asks user mode for a verdict.
- `scanner_service.c` — scanner bridge. It runs as console or as the `EyilShieldScan` Windows service.
- `avscan_protocol.h` — shared request/reply structs.
- `avfilter.inf` — demand-start test INF for the minifilter.
- `EyilShieldDriver.sln` — Visual Studio solution for driver + scanner bridge.

This is still a VM-only test driver. Do not install it on your main machine.

## What This MVP Blocks

The first target is intentionally narrow:

1. A process opens a file.
2. `avfilter.sys` pauses that open.
3. The driver sends the normalized path to `EyilShieldScan`.
4. The service hashes the file and checks:
   - EICAR test hash
   - `data\hashes.txt`
5. The service replies clean/infected.
6. The driver blocks infected opens with `STATUS_VIRUS_INFECTED`.

Heavy ClamAV/YARA scanning should stay out of kernel mode. Add it later in the service path, after this hash-only path is stable.

## VM Prerequisites

Inside a Windows VM:

1. Visual Studio 2022
2. Desktop development with C++
3. Windows Driver Kit integration
4. Administrator PowerShell
5. VM snapshot before loading the driver

## Build

From an elevated PowerShell in the VM:

```powershell
cd C:\path\to\eyil\driver
.\build_vm.ps1 -Configuration Debug -Sign
```

Output:

```text
driver\out\Debug\avfilter.sys
driver\out\Debug\avfilter.inf
driver\out\Debug\avfilter.cat
driver\out\Debug\scanner_service.exe
```

## Enable Test Signing

Run once in the VM:

```powershell
.\enable_testsigning_vm.ps1
```

Reboot the VM.

## Install and Start

After reboot:

```powershell
cd C:\path\to\eyil\driver
.\install_vm.ps1
```

Verify:

```powershell
fltmc filters
sc.exe query EyilShieldScan
```

## Test Safely

Use EICAR only:

```powershell
.\test_eicar_vm.ps1
```

Expected: reading the EICAR file fails or shows an antivirus-style block. If it reads successfully, check:

```powershell
fltmc filters
sc.exe query EyilShieldScan
```

## Uninstall

```powershell
.\uninstall_vm.ps1
```

If the package remains in the driver store:

```powershell
pnputil /enum-drivers | findstr /i avfilter
pnputil /delete-driver oemXX.inf /uninstall /force
```

## Current Safety Defaults

- Demand-start, not boot-start.
- Fail-open if scanner service is absent or times out.
- 2-second driver wait timeout.
- Scanner service PID is bypassed to avoid recursive scans.
- Hash-only blocking path for the first MVP.

## Still Missing for Product Use

- Microsoft-assigned altitude.
- Production code signing / Partner Center submission.
- Full SYSTEM service integration with Eyil engine health reporting.
- More scan events: write scanning, close-after-write scanning, cache invalidation.
- Installer integration.
- Tamper protection.
