"""Running-process scanner.

The file monitor only sees files being *written*. This watches what's actually
*running*: it polls the process list, scans each new process's executable
(YARA + hash — fast), and checks each process's live network connections against
the C2 blocklist. A threat that's already executing shows up within seconds, with
its real PID — and can be terminated from the dashboard.

This is detect-and-kill, not kernel pre-execution blocking (that still needs the
minifilter driver). But it closes the big gap: "I ran a hacktool and nothing
happened." Now Haven sees running programs, not just files on disk.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from typing import Callable, Optional

from .models import MonitoredObject, Finding, Severity
from .behavior import fuse
from .scanners import sha256_of

try:
    import psutil
    _HAVE_PSUTIL = True
except ImportError:
    _HAVE_PSUTIL = False

# Signed OS binaries live here; skip them for the (slower) exe scan to stay fast.
# They're still network-checked, and a threat dropped into these needs admin anyway.
_SYSTEM_DIRS = ("\\windows\\", "\\program files\\", "\\program files (x86)\\")


def _connections(proc):
    try:
        return proc.net_connections(kind="inet")
    except Exception:
        try:
            return proc.connections(kind="inet")
        except Exception:
            return []


class ProcessScanner:
    def __init__(self, engine, report: Callable[[MonitoredObject], None],
                 remove: Optional[Callable[[int], None]] = None,
                 c2_provider: Optional[Callable[[], set]] = None, interval: float = 3.0):
        self.engine = engine
        self.report = report
        self.remove = remove or (lambda pid: None)
        self.c2_provider = c2_provider or (lambda: set())
        self.interval = interval
        self.available = _HAVE_PSUTIL
        self.active = False
        self._stop = threading.Event()
        self._thread = None
        self._inventory: dict[str, int] = {}       # exe(lower) -> representative pid
        self._exe_cache: dict[str, list] = {}      # exe path -> static findings

    def _exe_findings(self, exe: str) -> list:
        if not exe:
            return []
        key = exe.lower()
        if key in self._exe_cache:
            return self._exe_cache[key]
        findings: list = []
        try:
            findings += self.engine.hash.scan(exe)     # fast: sha256 lookup
            findings += self.engine.yara.scan(exe)      # fast: yara-x
        except Exception:
            pass
        self._exe_cache[key] = findings
        return findings

    def _net_findings(self, proc) -> list:
        c2 = self.c2_provider()
        if not c2:
            return []
        for conn in _connections(proc):
            ip = getattr(getattr(conn, "raddr", None), "ip", None)
            if ip and ip in c2:
                return [Finding(source="netfeed", name="known-c2-connection",
                                severity=Severity.risk,
                                detail=(f"This running program is connected to {ip} — a known "
                                        "botnet command-and-control server."))]
        return []

    def _build_obj(self, proc, verdict, exe: str, name: str) -> MonitoredObject:
        try:
            parent = psutil.Process(proc.ppid()).name()
        except Exception:
            parent = ""
        net = []
        for conn in _connections(proc):
            ra = getattr(conn, "raddr", None)
            if ra and getattr(ra, "ip", None):
                net.append({"target": f"{ra.ip}:{getattr(ra, 'port', '')}"})
        try:
            size_bytes = os.path.getsize(exe) if exe else None
        except OSError:
            size_bytes = None
        return MonitoredObject(
            id=str(uuid.uuid4())[:8],
            name=name, path=exe or name, pid=proc.info.get("pid"),
            parent=parent, signer="unknown",
            sha256=(sha256_of(exe) or "") if exe else "",
            size_bytes=size_bytes,
            verdict=verdict,
            ops=[{"op": "EXECUTE", "path": exe}] if exe else [],
            net=net,
            logs=[{"ts": time.time(), "op": "EXECUTE", "path": exe or name}],
        )

    def _poll_once(self) -> None:
        """Maintain a *live inventory* — one card per running executable. Safe user
        apps are listed (mostly green); safe system-dir noise is hidden; anything
        flagged (signature/YARA/hash or a live C2 connection) is always listed.
        Apps that exit are reaped so the dashboard reflects what's running now."""
        live_by_exe: dict[str, object] = {}
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            exe = proc.info.get("exe") or ""
            # require a real file path (skips kernel pseudo-processes like Registry)
            if not exe or ("\\" not in exe and "/" not in exe):
                continue
            k = exe.lower()
            if k not in live_by_exe:
                live_by_exe[k] = proc

        # add newly-seen executables
        for k, proc in live_by_exe.items():
            if k in self._inventory:
                continue
            exe = proc.info.get("exe") or ""
            name = proc.info.get("name") or os.path.basename(exe) or "process"
            is_system = any(d in k for d in _SYSTEM_DIRS)
            findings = list(self._net_findings(proc))
            if not is_system:
                findings += self._exe_findings(exe)
            verdict = fuse(findings)
            if verdict.severity == Severity.safe and is_system:
                continue                       # hide safe system noise
            obj = self._build_obj(proc, verdict, exe, name)
            self._inventory[k] = obj.pid
            self.report(obj)

        # reap executables that are no longer running
        for k in list(self._inventory):
            if k not in live_by_exe:
                self.remove(self._inventory.pop(k))

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll_once()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def start(self) -> bool:
        if not self.available:
            return False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.active = True
        return True

    def stop(self) -> None:
        self._stop.set()
        self.active = False


def kill_process(pid: Optional[int], expected_path: Optional[str] = None) -> bool:
    """Terminate a running process (same-user, no admin needed). Used when you
    quarantine a live threat. If expected_path is given, only kill when the
    process's exe actually matches — so a synthetic/reused PID can't take down an
    unrelated process."""
    if pid is None or not _HAVE_PSUTIL:
        return False
    try:
        p = psutil.Process(pid)
        if expected_path:
            try:
                if (p.exe() or "").lower() != expected_path.lower():
                    return False
            except Exception:
                return False
        p.terminate()
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
        return True
    except Exception:
        return False
