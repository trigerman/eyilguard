"""Automatic signature & feed updates — protection that stays current on its own.

Runs on a background thread (plus once shortly after start) and, each tick:
  1. pulls the abuse.ch hash blocklist via engine.feeds and reloads the scanner
     so new hashes are live immediately, and
  2. refreshes ClamAV signatures with freshclam if it's installed.

Honest by design (internal notes #5): engine.feeds.update() never advances its
"updated at" timestamp on a failed fetch, so a network outage shows up in the UI
as *stale* rather than a false *fresh*. freshclam likewise only bumps the DB on a
real download. We surface whatever actually happened.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Callable, Optional

from . import feeds
from . import keystore
from .scanners import Engine

DATA = Path(__file__).resolve().parent.parent / "data"
FRESHCLAM_CONF = DATA / "clam" / "freshclam.conf"

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _hidden_startupinfo():
    """Hide the console window the freshclam shim would otherwise pop up."""
    if os.name != "nt":
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return si


def _find_freshclam() -> Optional[str]:
    # Prefer the real exe over a scoop shim (the shim opens its own console window).
    for cand in (Path.home() / "scoop" / "apps" / "clamav" / "current" / "freshclam.exe",
                 Path(r"C:\Program Files\ClamAV\freshclam.exe")):
        if cand.exists():
            return str(cand)
    return shutil.which("freshclam")

DEFAULT_INTERVAL = 6 * 3600   # check every 6 hours
INITIAL_DELAY = 5             # let the server finish coming up first


class AutoUpdater:
    def __init__(self, engine: Engine,
                 on_update: Optional[Callable[[], None]] = None,
                 interval: float = DEFAULT_INTERVAL):
        self.engine = engine
        self.on_update = on_update
        self.interval = interval
        self.last_result: dict = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # --- one update cycle ---
    def run_once(self) -> dict:
        result: dict = {"hashes": None, "clamav": None, "feed_error": None}
        try:
            feeds.update()                 # honest: no timestamp bump on failure
            self.engine.hash.reload()      # make new hashes live right away
            result["hashes"] = self.engine.hash.count
        except Exception as e:             # network/parse trouble must not crash us
            result["feed_error"] = str(e)
            result["hashes"] = self.engine.hash.count
        try:
            result["c2_ips"] = feeds.update_c2()   # Feodo Tracker C2 IP blocklist
        except Exception as e:
            result["c2_error"] = str(e)
        try:
            result["threatfox"] = feeds.update_threatfox()  # IOCs (hashes + C2 IPs)
            result["urlhaus"] = feeds.update_urlhaus()      # payload hashes
            self.engine.hash.reload()                       # new hashes live now
            result["hashes"] = self.engine.hash.count
        except Exception as e:
            result["ioc_error"] = str(e)
        if keystore.get("malpedia"):
            try:
                result["malpedia"] = feeds.update_malpedia_yara()
                self.engine.yara.reload()
            except Exception as e:
                result["malpedia_error"] = str(e)
        result["clamav"] = self._run_freshclam()
        self.last_result = result
        if self.on_update:
            try:
                self.on_update()
            except Exception:
                pass
        return result

    def _run_freshclam(self) -> str:
        exe = _find_freshclam()
        if not exe:
            return "freshclam not installed (skipped)"
        cmd = [exe]
        if FRESHCLAM_CONF.exists():
            cmd.append(f"--config-file={FRESHCLAM_CONF}")
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                               creationflags=_NO_WINDOW, startupinfo=_hidden_startupinfo())
            return "ok" if p.returncode == 0 else f"exit {p.returncode}"
        except Exception as e:
            return f"error: {e}"

    # --- background loop ---
    def _loop(self) -> None:
        if self._stop.wait(INITIAL_DELAY):
            return
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self.interval)

    def start(self) -> bool:
        if os.environ.get("EYIL_AUTOUPDATE", "1") == "0":
            return False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
