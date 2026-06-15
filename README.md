# Eyil Guard

An **open-source (GPLv3) endpoint protection tool for Windows** that's honest about
what it does. Its difference isn't out-detecting commercial antivirus — it's
*transparency*: every file gets a calm, plain-language verdict that's one click away
from full forensic detail (paths, hashes, IPs, event log).

It does not reinvent detection. It composes mature, free, auto-updating open-source
pieces and adds the glue, the real-time Windows hook, the behavioral correlation, and
the UX.

> **Status:** a work in progress, built in the open. The user-space layers (detection,
> real-time monitoring, dashboard, auto-updating intel) work today; the kernel driver is
> test-VM-only and it isn't code-signed yet — so it's a project, not a finished product.
> See the honest [status section](#status-honest) for exactly what's real vs. in progress.

## Why I built this

I've always wanted to build a real open-source product — something people could actually
use, not a toy. And I've always been frustrated by antivirus software: it's a black box.
A red shield flashes, says *"threat blocked — trust me,"* and tells you nothing. What was
the file? What was it doing? Where did it live, what did it touch, who did it talk to?
You're not allowed to know.

**Eyil Guard is the AV I always wanted** — one where I can see exactly what every file is
doing, in plain language, one toggle away from the full forensic truth (paths, hashes, IPs,
the event log). Nothing hidden, nothing dumbed-down-and-then-lost. The same file makes sense
to a curious beginner and to a malware analyst.

It doesn't try to out-detect the commercial giants — it can't, and it's honest about that.
Instead it composes the best free, auto-updating pieces (ClamAV, YARA, abuse.ch threat feeds)
and adds the parts that were missing: a real-time Windows monitor, behavioral detection that
catches ransomware by *what it does*, network command-and-control detection, a kernel
minifilter for true on-access blocking, and above all a calm, transparent dashboard that
respects your intelligence.

It's GPLv3, it's a work in progress, and I'm building it in the open.

## What we borrow vs. what we build

| Need | Component | Ours? |
|---|---|---|
| Detection engine + signatures | **ClamAV** (via the `clamd` daemon) | borrowed |
| Automatic signature updates | **freshclam** (+ optional Fangfrisch feeds) | borrowed |
| Pattern matching | **YARA** + community rule repos | borrowed |
| Malware hash / IOC feeds | **abuse.ch** (MalwareBazaar, ThreatFox, URLhaus) | borrowed |
| System telemetry | **Sysmon** / **OSQuery** | borrowed |
| Real-time on-access blocking (Windows) | **minifilter driver** (`avfilter.c`) | **ours** |
| Engine orchestration + verdicts + API | this repo (`engine/`) | **ours** |
| Behavioral correlation (ransomware etc.) | `engine/behavior.py` (+ Sigma rules) | **ours** |
| Dual-mode dashboard | **Eyil** (`eyil_dashboard.jsx`) | **ours** |

> NOTE on VirusTotal: the VT *free public API may not be used in antivirus products* —
> its terms forbid it. So VT is never a runtime dependency here. Users can still check a
> file manually at virustotal.com; we just don't integrate the free API.

## Architecture

```
   [ minifilter driver ]        [ Sysmon / OSQuery ]
   on file open/write             process/net/registry
            \                        /
             \                      /
            ( events, tagged with PID )
                      |
              engine/service.py  ──────────────►  Eyil dashboard
              (FastAPI + WebSocket)  local API     (Simple / Technical)
                /     |       \
        scanners.py behavior.py feeds.py
        ClamAV+YARA  rules      abuse.ch + freshclam health
        +hash list
```

## Folder layout

```
eyil/
├── README.md
├── requirements.txt
├── engine/                  # the Python engine (runnable today)
│   ├── service.py           #   local API + WebSocket the dashboard consumes
│   ├── scanners.py          #   ClamAV (clamd) + YARA + hash-feed scanning
│   ├── behavior.py          #   behavioral correlation (ransomware etc.)
│   ├── feeds.py             #   abuse.ch feed fetch + update-health
│   └── models.py            #   shared data shapes
├── driver/                  # the Windows real-time layer (build on Windows + WDK)
│   ├── avfilter.c           #   minifilter: scans files on open
│   ├── avfilter.inf         #   driver install (anti-virus altitude)
│   └── scanner_service.c    #   user-mode bridge between driver and engine
├── dashboard/
│   ├── eyil_dashboard.jsx  #   the chosen UI (Simple / Technical views)
│   └── explorations/        #   earlier design directions, kept for reference
├── tools/
│   └── mini_av.py           #   standalone signature scanner (the prototype)
├── config/
│   └── freshclam.conf.sample
└── data/                    # hash feeds + state (populated at runtime)
```

## Prerequisites

1. **Python 3.11+**
2. **ClamAV** with the daemon running:
   - Windows: install ClamAV, run `freshclam` once, then start the `clamd` service.
   - Linux/macOS: `apt install clamav clamav-daemon` (or `brew install clamav`),
     run `freshclam`, start `clamav-daemon`.
   - freshclam keeps signatures current automatically — leave it running.
3. **YARA rules** (optional but recommended): clone a community ruleset, e.g.
   `git clone https://github.com/Neo23x0/signature-base` into `data/yara/`.

## Install & run

Eyil is a **single-process desktop app**: the engine serves both the local API and the
built dashboard, and a native window (`pywebview` + the Windows WebView2 runtime) opens
onto it — no browser, no separate server.

### Setup (recommended) — one command

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

`install.ps1` (user-level, **no admin needed**) installs dependencies, builds the UI,
installs/uses ClamAV, pulls the first signatures + threat feeds, registers the always-on
**background listener** (autostart at logon, hidden), and drops a **desktop shortcut**.
Remove it all with `uninstall.ps1`.

- `python -m eyil` — open the window (foreground).
- `python -m eyil --no-window` — run as the headless background listener.
The launcher **starts `clamd` itself** if it isn't already running.

### Package a standalone `Eyil.exe`

```powershell
powershell -ExecutionPolicy Bypass -File build_exe.ps1   # → dist\Eyil\Eyil.exe
```
A windowed bundle with the dashboard inside. ClamAV (clamd) is installed separately, not
bundled. (Note: the frozen app currently keeps its `data/` inside the bundle folder;
moving runtime state to `%LOCALAPPDATA%\EyilGuard` is a planned refinement.)

**Live vs. demo data (honest by default):** the dashboard talks to the engine on its own
origin. If the engine is unreachable it falls back to clearly-labelled **demo data** (a
yellow "Demo data" banner) rather than presenting mock files as real detections. Set
`VITE_USE_API=false` at build time to force the offline demo.

### Dashboard development

```bash
cd dashboard
npm run dev        # Vite dev server on :5173, proxies API + WebSocket to the engine
```
Run the engine separately (`python -m eyil --no-window`) so the dev UI has live data.

## API surface

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Update-health: last signature & feed refresh, staleness flags |
| GET | `/objects` | Currently monitored files/processes with verdicts |
| POST | `/scan` | Scan a path on demand → findings + verdict |
| POST | `/events` | Ingest a batch of events from the minifilter / Sysmon |
| WS | `/stream` | Live event + verdict feed for the dashboard |

## Status (honest)

**Built and verified — runs today:**
- **Detection** — ClamAV (`clamd`) + ~1,100 abuse.ch hashes + **~5,900 YARA rules**
  (community `signature-base` + your own custom rules) + behavioral (ransomware / temp /
  office-spawned-shell) + network command-and-control.
- **Real-time** — a user-mode file monitor *and* a live process inventory (every running app,
  threats flagged; quarantine kills the process); auto-updating threat intel.
- **Dashboard** — wired to the live engine: Simple/Technical views, update-health,
  allow / quarantine / un-allow, a whitelist panel, and **write-your-own YARA rules**.
- **Packaging** — single-process native window (pywebview + WebView2), `install.ps1` setup,
  autostart listener, and a standalone `Eyil.exe`.

**Kernel layer — build it in a VM:** the minifilter for true *pre-execution blocking* is
code-complete (`driver/`), with a full build/sign/install runbook in
[`driver/BUILD_DRIVER.md`](driver/BUILD_DRIVER.md). It needs a **Windows VM + the WDK** to
compile and test-sign — it deliberately does not build on a normal dev box.

**Not yet (for a *shipped* product):** code-signing (so users don't hit SmartScreen warnings)
and an always-on SYSTEM service. Until those land, treat Eyil as a transparent, hackable
**open-source project** — not a drop-in replacement for your primary antivirus.

## Threat-intel feeds & attribution

Eyil composes free, keyless **bulk exports** from [abuse.ch](https://abuse.ch) (now part
of Spamhaus): **MalwareBazaar** SHA-256 hashes (`data/hashes.txt`) and **Feodo Tracker**
botnet C2 IPs (`data/c2_ips.txt`). These are free under abuse.ch's *fair-use* terms for
open-source/non-commercial use (attribution expected; commercial use may need a paid
subscription). The richer **query APIs** (ThreatFox, URLhaus, MalwareBazaar `/api/`) now
require a free Auth-Key from [auth.abuse.ch](https://auth.abuse.ch) — set `ABUSE_CH_KEY`
in `engine/feeds.py` to enable them. Note: community YARA rulesets such as
`Neo23x0/signature-base` are licensed under the **Detection Rule License (DRL) 1.1**, not
GPL — bundle them as data with attribution.

## License

GPLv3 — required because we link the ClamAV ecosystem, and right for an
"open-source everything" project.
