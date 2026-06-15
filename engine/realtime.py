"""User-mode real-time file monitor.

Watches the user's most-targeted folders and scans files the moment they're
written, feeding verdicts to the engine so the dashboard lights up live — with
no kernel driver and no admin rights.

HONEST SCOPE (internal notes #4): this is *detect-and-react* — it scans a file just
after it appears and then alerts / lets you quarantine it. It is NOT kernel-level
*pre-execution blocking*: it cannot stop a file from being opened or run in the
first place. True on-access blocking needs the minifilter driver
(`driver/avfilter.c`), built and signed in a Windows VM. This monitor gives real
live protection today; the driver is the upgrade to hard blocking.

Because a file-system watcher sees file changes (not which process made them),
objects reported here use a stable pseudo-PID derived from the path and a parent
of "real-time monitor". Real per-process attribution arrives with the driver or
Sysmon.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

from .models import MonitoredObject, Severity
from .scanners import Engine, sha256_of
from .behavior import fuse

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    _HAVE_WATCHDOG = True
except ImportError:                       # degrade gracefully, like the scanners
    _HAVE_WATCHDOG = False
    FileSystemEventHandler = object       # type: ignore

# Folders most worth watching by default; overridable with EYIL_WATCH_DIRS
# (a ';'-separated list of absolute paths).
DEFAULT_WATCH = ("Downloads", "Documents", "Desktop")

_EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".msi", ".js", ".vbs"}
_SCAN_MAX_BYTES = 256 * 1024 * 1024     # skip enormous files during sweeps

# Paths we never want to scan: our own files, build/churn dirs, and the AV's DB.
SKIP_FRAGMENTS = ("\\haven-shield\\", "/haven-shield/", "\\data\\clam\\", "/data/clam/",
                  "\\.git\\", "/.git/", "\\node_modules\\", "/node_modules/")


def default_watch_dirs() -> list[str]:
    env = os.environ.get("EYIL_WATCH_DIRS")
    if env:
        return [d for d in (p.strip() for p in env.split(";")) if d and os.path.isdir(d)]
    home = Path.home()
    return [str(home / name) for name in DEFAULT_WATCH if (home / name).is_dir()]


def _pseudo_pid(path: str) -> int:
    """Stable, deterministic pseudo-PID so the dashboard's PID-keyed actions
    (allow / quarantine) work for file objects. Real PIDs come with the driver."""
    h = hashlib.sha1(path.lower().encode("utf-8", "ignore")).hexdigest()
    return int(h[:8], 16) % 90000 + 10000


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor: "RealtimeMonitor"):
        self.m = monitor

    def on_created(self, event):
        if not event.is_directory:
            self.m.enqueue(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.m.enqueue(event.src_path)

    def on_moved(self, event):
        dest = getattr(event, "dest_path", None)
        if dest and not getattr(event, "is_directory", False):
            self.m.enqueue(dest)


class RealtimeMonitor:
    """Debounced, threaded file watcher that scans changed files through the engine."""

    def __init__(self, engine: Engine, report: Callable[[MonitoredObject], None],
                 dirs: Optional[list[str]] = None, debounce: float = 0.6):
        self.engine = engine
        self.report = report
        self.dirs = dirs if dirs is not None else default_watch_dirs()
        self.debounce = debounce
        self.available = _HAVE_WATCHDOG
        self.active = False
        self._observer = None
        self._pending: dict[str, float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None

    # --- producer side (watchdog thread) ---
    def enqueue(self, path: str) -> None:
        if not path:
            return
        low = path.lower()
        if any(frag in low for frag in SKIP_FRAGMENTS):
            return
        with self._lock:
            self._pending[path] = time.time()

    # --- consumer side (our worker thread) ---
    def _drain(self) -> None:
        while not self._stop.is_set():
            now = time.time()
            ready = []
            with self._lock:
                for p, t in list(self._pending.items()):
                    if now - t >= self.debounce:
                        ready.append(p)
                        self._pending.pop(p, None)
            for path in ready:
                self._scan_one(path)
            time.sleep(0.2)

    def _scan_one(self, path: str) -> None:
        try:
            if not os.path.isfile(path):
                return
            findings = self.engine.scan(path)      # clamd (instream) + hash + YARA
            verdict = fuse(findings)
            if verdict.severity == Severity.safe:
                return                              # only surface things worth showing
            ext = os.path.splitext(path)[1].lower()
            op = "EXECUTE" if ext in _EXEC_EXT else "WRITE"
            obj = MonitoredObject(
                id=str(uuid.uuid4())[:8],
                name=os.path.basename(path) or path,
                path=path,
                pid=_pseudo_pid(path),
                parent="real-time monitor",
                signer="unknown",
                sha256=sha256_of(path) or "",
                size_bytes=os.path.getsize(path),
                verdict=verdict,
                ops=[{"op": op, "path": path}],
                logs=[{"ts": time.time(), "op": op, "path": path}],
            )
            self.report(obj)
        except Exception:
            # one bad file must never take the monitor down
            pass

    # --- on-disk sweep (the live watcher only sees *new* writes) ---
    def scan_existing(self, max_age_days: float | None = 7, max_files: int = 5000) -> int:
        """Scan files already present in the watched dirs and report non-safe ones.
        Bounded by age + count so it can't run away. Returns how many were scanned."""
        cutoff = (time.time() - max_age_days * 86400) if max_age_days else None
        scanned = 0
        for d in self.dirs:
            for root, dirs, names in os.walk(d):
                dirs[:] = [x for x in dirs
                           if not any(f in (os.path.join(root, x).lower() + os.sep)
                                      for f in SKIP_FRAGMENTS)]
                # scan executables/scripts first so real threats surface fast
                names.sort(key=lambda n: 0 if os.path.splitext(n)[1].lower() in _EXEC_EXT else 1)
                for name in names:
                    if scanned >= max_files:
                        return scanned
                    p = os.path.join(root, name)
                    if any(f in p.lower() for f in SKIP_FRAGMENTS):
                        continue
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    if (cutoff and st.st_mtime < cutoff) or st.st_size > _SCAN_MAX_BYTES:
                        continue
                    self._scan_one(p)
                    scanned += 1
        return scanned

    def _initial_sweep(self) -> None:
        try:
            self.scan_existing()
        except Exception:
            pass

    # --- lifecycle ---
    def start(self) -> bool:
        if not self.available or not self.dirs:
            return False
        self._observer = Observer()
        handler = _Handler(self)
        for d in self.dirs:
            try:
                self._observer.schedule(handler, d, recursive=True)
            except Exception:
                pass
        self._observer.daemon = True
        self._observer.start()
        self._worker = threading.Thread(target=self._drain, daemon=True)
        self._worker.start()
        # sweep files already on disk (e.g. a download that arrived before we started)
        threading.Thread(target=self._initial_sweep, daemon=True).start()
        self.active = True
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=2)
            except Exception:
                pass
        self.active = False
