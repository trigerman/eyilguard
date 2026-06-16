"""Eyil Guard engine API.

Ties the scanners, behavioral engine, and feeds together behind a small local API
that the Eyil dashboard consumes. Run:

    uvicorn engine.service:app --host 127.0.0.1 --port 8787
"""

from __future__ import annotations
import asyncio
import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .models import Event, MonitoredObject, Verdict, Severity
from .scanners import Engine, sha256_of
from .behavior import BehaviorEngine, fuse
from .realtime import RealtimeMonitor
from .procscan import ProcessScanner, kill_process
from .updater import AutoUpdater
from . import feeds
from . import keystore

app = FastAPI(title="Eyil Guard Engine")

# The dashboard runs in a browser/desktop shell; allow local origins.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

engine = Engine()
behavior = BehaviorEngine()
objects: dict[int, MonitoredObject] = {}   # pid -> object

# ---------- user decisions: allowlist + quarantine ----------
from .paths import DATA
QUARANTINE_DIR = DATA / "quarantine"
ALLOWLIST_FILE = DATA / "allowlist.json"


def _obj_key(obj: MonitoredObject) -> str:
    """Stable identity for a user decision: hash if we have one, else path/name."""
    return (obj.sha256 or obj.path or obj.name).lower()


def _load_allowlist() -> dict[str, dict]:
    if ALLOWLIST_FILE.exists():
        try:
            data = json.loads(ALLOWLIST_FILE.read_text())
            if isinstance(data, list):
                return {str(key): {"key": str(key)} for key in data}
            if isinstance(data, dict):
                out = {}
                for key, value in data.items():
                    out[str(key)] = value if isinstance(value, dict) else {"key": str(key)}
                return out
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_allowlist(entries: dict[str, dict]) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    ALLOWLIST_FILE.write_text(json.dumps(entries, indent=2, sort_keys=True))


allowlist: dict[str, dict] = _load_allowlist()

# A user "allow" trusts a file's *identity* (signatures/patterns), so these are
# suppressed for allowlisted files. Dynamic *activity* (behavior/network) is never
# blanket-allowed — an allowed file that starts acting harmful re-alerts, and stays
# tracked the whole time.
_STATIC_SOURCES = {"clamav", "yara", "hashfeed"}


def _verdict_for(obj: MonitoredObject, findings: list) -> Verdict:
    """Fuse findings into a verdict, honoring an 'allow' decision for identity
    only. Behavioral/network findings always flag, even on an allowed file."""
    if obj.status == "quarantined":
        return fuse(findings)
    if _obj_key(obj) in allowlist:
        obj.status = "allowed"
        dynamic = [f for f in findings if f.source not in _STATIC_SOURCES]
        if not dynamic:
            return Verdict(severity=Severity.safe, confidence=99,
                           why="You marked this file as safe, so Eyil isn't alerting on its signature.")
        v = fuse(dynamic)
        return Verdict(severity=v.severity, confidence=v.confidence, findings=findings,
                       why=("You allowed this file earlier — but it just did something "
                            "risky, so Eyil flagged it again: " + v.why))
    obj.status = "active"
    return fuse(findings)


def _allowlist_entry(obj: MonitoredObject, key: str) -> dict:
    return {
        "key": key,
        "name": obj.name,
        "path": obj.path,
        "sha256": obj.sha256,
        "allowed_at": time.time(),
        "sources": sorted({finding.source for finding in obj.verdict.findings}),
        "rules": [finding.name for finding in obj.verdict.findings],
    }


def _collect_findings(obj: MonitoredObject) -> list:
    """Re-scan an object from scratch (file signatures + current behavior)."""
    findings = []
    if obj.path and os.path.isfile(obj.path):
        findings += engine.scan(obj.path)
    if obj.pid is not None:
        findings += behavior.evaluate(obj.pid)
    return findings


# ---------- websocket fan-out ----------
class Hub:
    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def join(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)

    def leave(self, ws: WebSocket):
        self.clients.discard(ws)

    async def broadcast(self, payload: dict):
        dead = []
        for ws in self.clients:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.leave(ws)


hub = Hub()


# ---------- real-time monitor (user-mode) + auto-updater ----------
_loop: asyncio.AbstractEventLoop | None = None
monitor: RealtimeMonitor | None = None
procscanner: ProcessScanner | None = None
updater: AutoUpdater | None = None


def _broadcast_health() -> None:
    """Push a fresh health snapshot to the dashboard (called after an update)."""
    behavior.reload_c2()          # make any freshly-pulled C2 IPs live immediately
    if _loop is not None:
        asyncio.run_coroutine_threadsafe(
            hub.broadcast({"type": "health", "health": get_health().model_dump()}),
            _loop,
        )


def _report_from_thread(obj: MonitoredObject) -> None:
    """Called from the monitor's worker thread when a changed file gets a
    non-safe verdict. Apply the allow policy, upsert, and push to the dashboard."""
    obj.verdict = _verdict_for(obj, obj.verdict.findings)
    if obj.status == "allowed" and obj.verdict.severity == Severity.safe:
        objects.pop(obj.pid, None)
        if _loop is not None:
            asyncio.run_coroutine_threadsafe(
                hub.broadcast({"type": "objects_changed"}),
                _loop,
            )
        return
    objects[obj.pid] = obj
    if _loop is not None:
        asyncio.run_coroutine_threadsafe(
            hub.broadcast({"type": "verdict", "pid": obj.pid, "name": obj.name,
                           "verdict": obj.verdict.model_dump()}),
            _loop,
        )


def _remove_from_thread(pid: int) -> None:
    """Drop an object (e.g. a process that exited) and refresh the dashboard, so the
    live inventory reflects what's actually running."""
    if objects.pop(pid, None) is None:
        return
    if _loop is not None:
        asyncio.run_coroutine_threadsafe(
            hub.broadcast({"type": "objects_changed"}), _loop)


@app.on_event("startup")
async def _start_background():
    global _loop, monitor, procscanner, updater
    _loop = asyncio.get_running_loop()
    if os.environ.get("EYIL_REALTIME", "1") != "0":
        monitor = RealtimeMonitor(engine, report=_report_from_thread)
        monitor.start()
        procscanner = ProcessScanner(engine, report=_report_from_thread,
                                     remove=_remove_from_thread,
                                     c2_provider=lambda: behavior.c2)
        procscanner.start()
    updater = AutoUpdater(engine, on_update=_broadcast_health)
    updater.start()


@app.on_event("shutdown")
async def _stop_background():
    if monitor is not None:
        monitor.stop()
    if procscanner is not None:
        procscanner.stop()
    if updater is not None:
        updater.stop()


# ---------- request models ----------
class ScanRequest(BaseModel):
    path: str


class EventsRequest(BaseModel):
    events: list[Event]


class ActionRequest(BaseModel):
    pid: int
    action: str                 # "allow" | "quarantine"


class KeyRequest(BaseModel):
    service: str                # "abuse_ch" | "malpedia"
    key: str = ""               # empty string removes the key


class AllowlistRemoveRequest(BaseModel):
    key: str


class YaraRuleRequest(BaseModel):
    rule: str
    name: str = ""
    path: str = ""          # for /yara/test — a file to test the rule against


class YaraRemoveRequest(BaseModel):
    name: str


# ---------- custom YARA rules (write-your-own) ----------
CUSTOM_YARA_DIR = DATA / "yara" / "custom"
_YARA_EXTERNALS = ("filename", "filepath", "extension", "filetype", "owner", "md5")


def _safe_rule_filename(name: str) -> str:
    base = os.path.basename((name or "").strip()) or "custom"
    base = re.sub(r"[^A-Za-z0-9_.-]", "_", base)
    if not base.lower().endswith((".yar", ".yara")):
        base += ".yar"
    return base


def _compile_yara_source(source: str):
    """Compile a YARA source with yara-x + the standard externals. Returns the
    compiled Rules. Raises on a compile error (caller reports the message)."""
    import yara_x
    comp = yara_x.Compiler()
    for ext in _YARA_EXTERNALS:
        try:
            comp.define_global(ext, "")
        except Exception:
            pass
    comp.add_source(source)
    return comp.build()


def _validate_yara(source: str) -> dict:
    try:
        import yara_x  # noqa: F401
    except ImportError:
        return {"valid": False, "error": "YARA engine (yara-x) not installed.", "rules": 0}
    try:
        _compile_yara_source(source)
    except Exception as e:
        return {"valid": False, "error": str(e), "rules": 0}
    n = len(re.findall(r"^\s*(?:private\s+|global\s+)*rule\s+\w+", source, re.M))
    return {"valid": True, "error": "", "rules": n}


# ---------- helpers ----------
def _verdict_for_path(path: str) -> Verdict:
    findings = engine.scan(path)
    return fuse(findings)


def _ensure_object(ev: Event) -> MonitoredObject:
    obj = objects.get(ev.pid)
    if obj is None:
        obj = MonitoredObject(
            id=str(uuid.uuid4())[:8],
            name=os.path.basename(ev.process) or ev.process,
            path=ev.process, pid=ev.pid, parent=ev.parent,
            signer="signed" if ev.signed else "unsigned",
        )
        objects[ev.pid] = obj
    return obj


# ---------- endpoints ----------
@app.get("/health")
def get_health():
    h = feeds.health(clam_version=engine.clam.version(),
                     hash_count=engine.hash.count)
    active = monitor is not None and monitor.active
    h.realtime_active = active
    h.realtime_mode = "user-mode (detect & react)" if active else "off"
    h.watching = monitor.dirs if monitor is not None else []
    h.yara_rule_count = engine.yara.rule_count
    return h


@app.get("/objects", response_model=list[MonitoredObject])
def get_objects():
    # threats first, then watch, then the safe live-inventory apps
    order = {"risk": 0, "watch": 1, "safe": 2}
    return sorted(objects.values(),
                  key=lambda o: order.get(getattr(o.verdict.severity, "value",
                                                   o.verdict.severity), 3))


@app.post("/scan")
def scan(req: ScanRequest):
    verdict = _verdict_for_path(req.path)
    return {
        "path": req.path,
        "sha256": sha256_of(req.path),
        "verdict": verdict,
    }


@app.post("/events")
async def ingest(req: EventsRequest):
    """Receive a batch of events (from the minifilter / Sysmon), update behavioral
    state, recompute the affected processes' verdicts, and push to the dashboard."""
    touched: set[int] = set()
    for ev in req.events:
        behavior.record(ev)
        obj = _ensure_object(ev)
        obj.logs.append({"ts": ev.ts, "op": ev.op, "path": ev.path})
        if ev.op == "CONNECT":
            obj.net.append({"target": ev.path})
        else:
            obj.ops.append({"op": ev.op, "path": ev.path})
        touched.add(ev.pid)

    for pid in touched:
        obj = objects[pid]
        # combine on-access file findings with behavioral findings
        file_findings = []
        last_file = next((o["path"] for o in reversed(obj.ops)), None)
        if last_file and os.path.exists(last_file):
            file_findings = engine.scan(last_file)
        obj.verdict = _verdict_for(obj, file_findings + behavior.evaluate(pid))
        if obj.status == "allowed" and obj.verdict.severity == Severity.safe:
            objects.pop(pid, None)
            await hub.broadcast({"type": "objects_changed"})
            continue
        await hub.broadcast({"type": "verdict", "pid": pid,
                             "name": obj.name, "verdict": obj.verdict.model_dump()})

    return {"updated": list(touched)}


@app.post("/action")
async def action(req: ActionRequest):
    """Apply a user decision to a monitored object.

    allow      -> remember the choice (persisted allowlist), stop alerting.
    quarantine -> mark it and move the file aside *if a real file exists*; if the
                  minifilter isn't active there's no live file to pull, and we say so
                  rather than pretending we blocked something.
    """
    obj = objects.get(req.pid)
    if obj is None:
        return {"ok": False, "error": f"no monitored object for pid {req.pid}"}

    act = req.action.lower()
    ts = time.time()

    if act == "allow":
        key = _obj_key(obj)
        allowlist[key] = _allowlist_entry(obj, key)
        _save_allowlist(allowlist)
        obj.verdict = _verdict_for(obj, obj.verdict.findings)   # suppress identity only
        obj.logs.append({"ts": ts, "op": "ALLOW", "path": f"user allowlisted {key}"})
        if obj.verdict.severity == Severity.safe:
            objects.pop(req.pid, None)
            result = {"ok": True, "status": "allowed", "hidden": True}
        else:
            result = {"ok": True, "status": obj.status, "hidden": False}

    elif act == "unallow":
        allowlist.pop(_obj_key(obj), None)
        _save_allowlist(allowlist)
        obj.status = "active"
        obj.verdict = _verdict_for(obj, _collect_findings(obj))   # re-check from scratch
        obj.logs.append({"ts": ts, "op": "UNALLOW", "path": "removed from allowlist — re-checked"})
        result = {"ok": True, "status": obj.status, "severity": obj.verdict.severity.value}

    elif act == "quarantine":
        obj.status = "quarantined"
        killed = kill_process(obj.pid, obj.path)     # stop it if it's running
        moved_to = None
        if obj.path and os.path.isfile(obj.path):
            try:
                QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
                dest = QUARANTINE_DIR / f"{obj.name}.{int(ts)}.quarantine"
                shutil.move(obj.path, str(dest))
                moved_to = str(dest)
                note = f"file moved to {dest}"
            except OSError as e:
                note = f"could not move file: {e}"
        else:
            note = "no file on disk to move"
        if killed:
            note = "process terminated · " + note
        obj.logs.append({"ts": ts, "op": "QUARANTINE", "path": note})
        result = {"ok": True, "status": "quarantined", "killed": killed,
                  "moved_to": moved_to, "note": note}

    else:
        return {"ok": False, "error": f"unknown action '{req.action}'"}

    await hub.broadcast({"type": "objects_changed"})
    return result


@app.post("/update")
async def update_now():
    """Force a signature + feed refresh right now (the auto-updater also does this
    on a schedule). Runs off the event loop since it does network + subprocess I/O."""
    if updater is None:
        return {"ok": False, "error": "updater not running"}
    result = await asyncio.to_thread(updater.run_once)
    return {"ok": True, "result": result, "health": get_health().model_dump()}


@app.post("/rescan")
async def rescan():
    """Sweep the watched folders on demand (a full scan of files already on disk,
    not just new writes). Runs in the background; findings stream to the dashboard."""
    if monitor is None or not monitor.available:
        return {"ok": False, "error": "real-time monitor not active"}

    async def _run():
        await asyncio.to_thread(monitor.scan_existing, None, 8000)
        _broadcast_health()

    asyncio.create_task(_run())
    return {"ok": True, "scanning": True, "dirs": monitor.dirs}


@app.get("/keys")
def get_keys():
    """Which BYOK services have a key configured (masked — never the secret)."""
    return keystore.status()


@app.get("/allowlist")
def get_allowlist():
    """User-allowed identities. These are hidden from the dashboard until removed."""
    return sorted(allowlist.values(), key=lambda item: item.get("allowed_at", 0), reverse=True)


@app.post("/allowlist/remove")
async def remove_allowlist(req: AllowlistRemoveRequest):
    """Remove an allowlisted identity so future scans can show it again."""
    removed = allowlist.pop(req.key, None)
    _save_allowlist(allowlist)
    await hub.broadcast({"type": "objects_changed"})
    return {"ok": True, "removed": removed is not None}


# ---------- custom YARA rules: write / validate / test / save / remove ----------

@app.post("/yara/validate")
def yara_validate(req: YaraRuleRequest):
    """Compile-check a YARA rule without saving it. Returns valid + rule count or
    the exact compiler error."""
    return _validate_yara(req.rule)


@app.post("/yara/test")
def yara_test(req: YaraRuleRequest):
    """Compile a rule and scan one file with it — does it match? (Nothing saved.)"""
    import yara_x
    v = _validate_yara(req.rule)
    if not v["valid"]:
        return {"ok": False, "error": v["error"]}
    if not req.path or not os.path.isfile(req.path):
        return {"ok": False, "error": "File not found — give an absolute path to a file."}
    try:
        rules = _compile_yara_source(req.rule)
        with open(req.path, "rb") as f:
            data = f.read()
        result = yara_x.Scanner(rules).scan(data)
        names = [r.identifier for r in result.matching_rules]
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "matched": bool(names), "rules": names}


@app.post("/yara/save")
async def yara_save(req: YaraRuleRequest):
    """Validate then save a custom rule to data/yara/custom/ and reload the engine."""
    v = _validate_yara(req.rule)
    if not v["valid"]:
        return {"ok": False, "error": v["error"]}
    CUSTOM_YARA_DIR.mkdir(parents=True, exist_ok=True)
    fname = _safe_rule_filename(req.name)
    (CUSTOM_YARA_DIR / fname).write_text(req.rule, encoding="utf-8")
    await asyncio.to_thread(engine.yara.reload)     # recompile (can be slow) off-loop
    _broadcast_health()
    return {"ok": True, "saved": fname, "total_rules": engine.yara.rule_count}


@app.get("/yara/custom")
def yara_custom_list():
    """List the user's own saved YARA rules."""
    out = []
    if CUSTOM_YARA_DIR.is_dir():
        for p in sorted(CUSTOM_YARA_DIR.glob("*.yar")) + sorted(CUSTOM_YARA_DIR.glob("*.yara")):
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            names = re.findall(r"^\s*(?:private\s+|global\s+)*rule\s+(\w+)", text, re.M)
            out.append({"name": p.name, "rules": names})
    return out


@app.post("/yara/custom/remove")
async def yara_custom_remove(req: YaraRemoveRequest):
    """Delete a custom rule file and reload."""
    target = CUSTOM_YARA_DIR / _safe_rule_filename(req.name)
    existed = target.exists()
    try:
        target.unlink(missing_ok=True)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    await asyncio.to_thread(engine.yara.reload)
    _broadcast_health()
    return {"ok": True, "removed": existed, "total_rules": engine.yara.rule_count}


def _apply_malpedia() -> dict:
    res = feeds.update_malpedia_yara()
    engine.yara.reload()
    res["loaded_rule_files"] = engine.yara.rule_count
    return res


@app.post("/keys")
async def set_key(req: KeyRequest):
    """Store a user-supplied key locally (never bundled) and act on it: a Malpedia
    key pulls that user's YARA rules to this machine; an abuse.ch key triggers a
    feed refresh. Returns masked status only."""
    try:
        keystore.set_key(req.service, req.key)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    result: dict = {}
    if req.service == "malpedia" and req.key:
        result = await asyncio.to_thread(_apply_malpedia)
    elif req.service == "abuse_ch" and req.key and updater is not None:
        asyncio.create_task(asyncio.to_thread(updater.run_once))
    _broadcast_health()
    return {"ok": True, "status": keystore.status(), "result": result}


@app.websocket("/stream")
async def stream(ws: WebSocket):
    await hub.join(ws)
    try:
        await ws.send_json({"type": "hello",
                            "health": get_health().model_dump()})
        while True:
            await asyncio.sleep(30)
            await ws.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        hub.leave(ws)
    except Exception:
        hub.leave(ws)


# ---------- uninstall: remove Eyil Guard's footprint, then stop ----------

class UninstallRequest(BaseModel):
    confirm: bool = False


def _user_locations():
    """Best-effort Startup folder + Desktop folder(s), incl. a OneDrive desktop."""
    home = Path(os.path.expanduser("~"))
    appdata = os.environ.get("APPDATA") or str(home / "AppData" / "Roaming")
    startup = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    desktops = [home / "Desktop"]
    one = os.environ.get("OneDrive")
    if one:
        desktops.append(Path(one) / "Desktop")
    return startup, desktops


def _uninstall_footprint() -> list[str]:
    """Delete the autostart entry, desktop shortcut and log folder. Leaves the
    project source and your data in place (and ClamAV untouched)."""
    removed: list[str] = []
    startup, desktops = _user_locations()
    targets = [startup / "EyilGuard.vbs", startup / "HavenShield.vbs"]
    for d in desktops:
        targets += [d / "Eyil Guard.lnk", d / "Haven Shield.lnk"]
    for t in targets:
        try:
            if t.exists():
                t.unlink()
                removed.append(str(t))
        except Exception:
            pass
    local = os.environ.get("LOCALAPPDATA")
    if local:
        log_dir = Path(local) / "EyilGuard"
        if log_dir.exists():
            shutil.rmtree(log_dir, ignore_errors=True)
            removed.append(str(log_dir))
    return removed


@app.post("/uninstall")
async def uninstall(req: UninstallRequest):
    """Remove Eyil Guard from this machine: autostart, desktop shortcut and logs,
    then stop the listener. Source files + your data stay (delete the project folder
    yourself for those). Local-only API and gated behind an explicit confirm."""
    if not req.confirm:
        return {"ok": False, "error": "confirmation required"}
    removed = _uninstall_footprint()
    # Stop the listener shortly after replying so the UI can show the result first.
    import threading
    threading.Timer(1.2, lambda: os._exit(0)).start()
    return {"ok": True, "removed": removed}


# ---------- serve the built dashboard (single-process product) ----------
# When the Eyil UI has been built (`npm run build` in dashboard/), the engine
# serves it directly so the whole app is one process and one window — no
# separate browser or dev server. Registered LAST so the API routes above win.
_UI_DIST = Path(__file__).resolve().parent.parent / "dashboard" / "dist"
if (_UI_DIST / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(_UI_DIST), html=True), name="ui")
