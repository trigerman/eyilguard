# Eyil Shield — Kernel Minifilter: what it is & how to build/run it on a VM

This is the **real-time, pre-execution-blocking** layer — the one piece that turns
Eyil from "detect and react" into "stop it before it runs." It is **VM-only** work:
it needs the Windows Driver Kit, administrator rights, and test-signing, none of
which exist on a normal dev box.

---

## 1. What is it? (the concept)

A **file-system minifilter** is a small kernel driver that plugs into Windows'
I/O stack. Because **every file open passes through it**, it can intercept an open
*before it completes*, ask "is this safe?", and **cancel the open** if not — so a
malicious program never gets to read/execute. That's **pre-execution blocking**.

Eyil splits the work the right way:

```
  Program tries to open/run a file
            │
            ▼
  [ avfilter.sys ]  kernel minifilter (avfilter.c)
   - intercepts IRP_MJ_CREATE (the open)
   - sends the file path UP to user mode over a filter port
   - WAITS for a verdict (2s timeout, fail-open)
   - if "infected": FltCancelFileOpen → STATUS_VIRUS_INFECTED  ← the open is DENIED
            │  (path over \AvScanPort)
            ▼
  [ scanner_service.exe ]  user-mode service (scanner_service.c)
   - computes the file's SHA-256 (BCrypt)
   - checks it against data/hashes.txt + the EICAR test hash
   - replies clean / infected
```

The kernel stays tiny and just **enforces**; the actual detection runs in user mode
where it's safe and easy to extend (the same hash list the Python engine maintains).

### The files (all present and consistent)
| File | Role |
|---|---|
| `avscan_protocol.h` | The shared request/reply contract — both sides include it so the wire layout can't drift |
| `avfilter.c` | The kernel minifilter — intercept, ask, block |
| `scanner_service.c` | The user-mode service — SHA-256 + blocklist + EICAR, replies to the kernel; runs as a console app or a Windows service (`--service`) |
| `avfilter.inf` | Test install (AntiVirus class, test altitude `321410`, depends on FltMgr) |
| `install_driver.ps1` / `uninstall_driver.ps1` | Sign + load + start / stop + unload |

## 2. What was "missing"?
Nothing in the **code** anymore — `avscan_protocol.h` (the shared header both `.c`
files include) is in place, so it compiles. What's missing is only the **build +
sign + load process**, which can't happen off a VM. This doc + the two scripts are
that process.

---

## 3. Prerequisites (one-time, in a Windows 10/11 VM)

> Use a **throwaway VM** with a snapshot. A driver bug can blue-screen the machine —
> that's normal during development, and why we never build/load this on your real PC.

1. **Visual Studio 2022** (Community is fine) + **"Desktop development with C++"**.
2. **Windows Driver Kit (WDK)** matching your Windows SDK version, plus the WDK VS
   extension (gives the driver project templates).
3. **Enable test signing** (Admin PowerShell), then **reboot**:
   ```powershell
   bcdedit /set testsigning on
   ```
   You'll see a "Test Mode" watermark on the desktop afterward — expected.
4. **Turn Windows Defender OFF in the VM** so *Eyil* is the active AV. On a normal
   machine Defender gets to malware first (it blocks/deletes test files before Eyil
   can act — which is why detection is hard to demo with Defender on). In the throwaway
   VM, disable real-time protection (Settings → Privacy & Security → Windows Security →
   Virus & threat protection → Manage settings → Real-time protection **Off**), or run:
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $true      # test VM only
   ```
   Alternatively keep Defender on but exclude your test folder:
   `Add-MpPreference -ExclusionPath "C:\eyil-test"`. With Defender out of the way, Eyil
   detects, **blocks (kernel)**, and quarantines the files itself — the real demo.

---

## 4. Build

### a) The driver (`avfilter.sys`)
The robust, version-proof way is the WDK's own template:
1. VS → **New Project** → **"Filter Driver: Filesystem Mini-Filter"** (Empty).
2. **Remove** the template's generated `.c`, then **Add → Existing Item**:
   `avfilter.c` and `avscan_protocol.h`.
3. Configuration: **Release / x64**. Build.
4. Copy the resulting `avfilter.sys` next to `avfilter.inf` (this `driver/` folder).

### b) The scanner service (`scanner_service.exe`)
From a **"x64 Native Tools Command Prompt for VS"** in this folder:
```bat
cl /W4 /Fe:scanner_service.exe scanner_service.c /link fltlib.lib bcrypt.lib advapi32.lib
```

---

## 5. Sign, install, load, run

With `avfilter.sys` and `scanner_service.exe` built, in an **elevated** PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File install_driver.ps1
```
This creates a self-signed test cert, trusts it machine-wide, builds + signs the
`.cat`, signs the `.sys`, installs the INF (`pnputil`), loads the filter
(`fltmc load avfilter`), and creates + starts the `EyilShieldScan` service.

**Verify it loaded:**
```powershell
fltmc filters          # 'avfilter' should appear with altitude 321410
sc query EyilShieldScan
```

## 6. Test it (safely, with EICAR)

The service flags the **EICAR test string** (a harmless standard AV test file) by
hash. Create one and watch the open get **blocked**:
```powershell
# EICAR test string — harmless, recognized by every AV
'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' |
  Set-Content -NoNewline eicar_test.com
type eicar_test.com      # opening it should fail: "Operation did not complete successfully
                         # because the file contains a virus" (STATUS_VIRUS_INFECTED)
```
The scanner console/service log shows `... -> INFECTED (blocking)`. To block real
known-bad files, point the service at the engine's live feed:
```powershell
sc.exe stop EyilShieldScan
# run interactively against the auto-updated blocklist:
.\scanner_service.exe --hashes ..\data\hashes.txt
```

## 7. Remove
```powershell
powershell -ExecutionPolicy Bypass -File uninstall_driver.ps1
```

---

## 8. Running the WHOLE product on the VM

The driver is the bottom layer; run it under the rest of Eyil:

1. **Engine + dashboard:** in the project root, run the normal setup —
   `powershell -ExecutionPolicy Bypass -File install.ps1` — then `python -m eyil`.
   This gives you ClamAV + hashes + YARA + behavior + network + the user-mode
   process/file scanners + the dashboard (everything already verified).
2. **Driver:** build + `install_driver.ps1` (this folder). Now file opens are
   blocked pre-execution by the same `data/hashes.txt` the engine keeps fresh.
3. (Optional) **Surface kernel blocks in the dashboard:** have `scanner_service.c`
   `POST` each blocked path to the engine's `/events` so it appears as a live
   verdict. Hook is the `ScanIsInfected` site — add a WinHTTP call to
   `http://127.0.0.1:8787/events` when `infected` is TRUE.

Result on the VM: **a real AV** — the kernel stops known-bad files *before they
run*, while the user-space layers catch variants/behavior/network and show
everything in the transparent dashboard.

---

## 9. Honest limits (read before shipping)

- **Test-signed only.** This loads only with `testsigning on`. For real users you
  need an **EV code-signing cert** + Microsoft **attestation/WHQL signing**, and a
  Microsoft-**assigned altitude** (the `321410` here is a test value).
- **Skeleton hardening.** Re-entrancy, cancellation, performance, and the 20-block
  edge cases are simplified. Don't ship as-is to third parties.
- **Develop in a VM with snapshots.** Kernel bugs = BSOD; revert and retry.
