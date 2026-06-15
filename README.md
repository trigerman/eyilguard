# Haven Shield

An **open-source (GPLv3) endpoint protection tool for Windows** that's honest about
what it does. Its difference isn't out-detecting commercial antivirus — it's
*transparency*: every file gets a calm, plain-language verdict that's one click away
from full forensic detail (paths, hashes, IPs, event log).

It does not reinvent detection. It composes mature, free, auto-updating open-source
pieces and adds the glue, the real-time Windows hook, the behavioral correlation, and
the UX.

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
| Dual-mode dashboard | **Haven** (`haven_dashboard.jsx`) | **ours** |

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
              engine/service.py  ──────────────►  Haven dashboard
              (FastAPI + WebSocket)  local API     (Simple / Technical)
                /     |       \
        scanners.py behavior.py feeds.py
        ClamAV+YARA  rules      abuse.ch + freshclam health
        +hash list
```

## Folder layout

```
haven-shield/
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
│   ├── haven_dashboard.jsx  #   the chosen UI (Simple / Technical views)
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

Haven is a **single-process desktop app**: the engine serves both the local API and the
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

- `python -m haven` — open the window (foreground).
- `python -m haven --no-window` — run as the headless background listener.
The launcher **starts `clamd` itself** if it isn't already running.

### Package a standalone `Haven.exe`

```powershell
powershell -ExecutionPolicy Bypass -File build_exe.ps1   # → dist\Haven\Haven.exe
```
A windowed bundle with the dashboard inside. ClamAV (clamd) is installed separately, not
bundled. (Note: the frozen app currently keeps its `data/` inside the bundle folder;
moving runtime state to `%LOCALAPPDATA%\HavenShield` is a planned refinement.)

**Live vs. demo data (honest by default):** the dashboard talks to the engine on its own
origin. If the engine is unreachable it falls back to clearly-labelled **demo data** (a
yellow "Demo data" banner) rather than presenting mock files as real detections. Set
`VITE_USE_API=false` at build time to force the offline demo.

### Dashboard development

```bash
cd dashboard
npm run dev        # Vite dev server on :5173, proxies API + WebSocket to the engine
```
Run the engine separately (`python -m haven --no-window`) so the dev UI has live data.

## API surface

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Update-health: last signature & feed refresh, staleness flags |
| GET | `/objects` | Currently monitored files/processes with verdicts |
| POST | `/scan` | Scan a path on demand → findings + verdict |
| POST | `/events` | Ingest a batch of events from the minifilter / Sysmon |
| WS | `/stream` | Live event + verdict feed for the dashboard |

## Status (honest)

Runnable today: the full engine — ClamAV + YARA + hash-feed scanning, the behavioral
rule engine, update-health tracking, and the local API/WebSocket the dashboard consumes —
**plus the Haven dashboard wired to that live API** (objects, update-health, and live
verdicts over the WebSocket), packaged as a single-process desktop app (`python -m haven`).

Still native work on your side: building & signing the Windows minifilter (`avfilter.c`)
so real-time events flow in, and packaging Haven + engine as one desktop app (Tauri).
Until the driver is wired, you can drive the engine with `/scan` and `/events` manually.

## Threat-intel feeds & attribution

Haven composes free, keyless **bulk exports** from [abuse.ch](https://abuse.ch) (now part
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
