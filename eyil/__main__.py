"""Launch Eyil Guard as a desktop product.

Self-sufficient launcher: it makes sure the ClamAV daemon (clamd) is running,
boots the FastAPI engine (engine.service:app) on 127.0.0.1 in a background
thread, waits until it answers, then either opens the native window (pywebview)
or stays running headless as the always-on background listener.

    python -m eyil                 # open the Eyil window (foreground app)
    python -m eyil --no-window     # run as the background listener (autostart)
    python -m eyil --background    # alias for --no-window
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8787
URL = f"http://{HOST}:{PORT}"
CLAMD_PORT = 3310

# In a PyInstaller build the bundled data (UI, clam confs) lives under sys._MEIPASS
# (the exe's _internal dir). From source it's the project root. The entry script's
# __file__ points at the exe folder, NOT _internal — so resolve frozen paths explicitly.
if getattr(sys, "frozen", False):
    ROOT = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
else:
    ROOT = Path(__file__).resolve().parent.parent
UI_DIST = ROOT / "dashboard" / "dist"
CLAM_CONF = ROOT / "data" / "clam" / "clamd.conf"
CLAM_LOG = ROOT / "data" / "clam" / "clamd.out.log"


def _ensure_streams() -> None:
    """In a windowed (no-console) frozen build, sys.stdout/stderr are None — any
    print() or logging call would then crash the app. Point them at a log file."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    try:
        log_dir = Path(base) / "EyilGuard"
        log_dir.mkdir(parents=True, exist_ok=True)
        f = open(log_dir / "eyil.log", "a", buffering=1, encoding="utf-8")
    except Exception:
        f = open(os.devnull, "w")
    if sys.stdout is None:
        sys.stdout = f
    if sys.stderr is None:
        sys.stderr = f


def _port_open(port: int, host: str = HOST) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _hidden_startupinfo():
    """A STARTUPINFO that hides any console window a child process would create.
    Belt-and-suspenders alongside CREATE_NO_WINDOW (some launchers/shims ignore it)."""
    if os.name != "nt":
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return si


def _find_clamd() -> str | None:
    # Prefer the *real* binary over a scoop shim — the shim spawns its own visible
    # console window, which is what users were seeing pop up on launch.
    for cand in (Path.home() / "scoop" / "apps" / "clamav" / "current" / "clamd.exe",
                 Path(r"C:\Program Files\ClamAV\clamd.exe")):
        if cand.exists():
            return str(cand)
    return shutil.which("clamd")


def _ensure_clamd() -> str:
    """Start clamd if it isn't already listening. Returns a short status string.
    ClamAV is optional — without it, hash + behavioral + network detection still
    work, so we degrade gracefully and just say so."""
    if _port_open(CLAMD_PORT):
        return "clamd already running"
    exe = _find_clamd()
    if not exe or not CLAM_CONF.exists():
        return "clamd not found — running without ClamAV signatures"
    try:
        # CREATE_NO_WINDOW only — do NOT combine with DETACHED_PROCESS (that pair is an
        # invalid Win32 combo and lets a console window leak through).
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        with open(CLAM_LOG, "ab") as log:
            subprocess.Popen([exe, f"--config-file={CLAM_CONF}"],
                             stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                             creationflags=flags, startupinfo=_hidden_startupinfo(),
                             close_fds=True)
    except Exception as e:
        return f"could not start clamd: {e}"
    for _ in range(60):                      # loading ~8.5M signatures takes a moment
        if _port_open(CLAMD_PORT):
            return "clamd started"
        time.sleep(1)
    return "clamd starting (still loading signatures)"


def _kill_stale_engine() -> None:
    """Single-instance: if an older Eyil engine already holds our port, stop it
    so this launch loads the *current* code instead of leaving a stale engine
    serving the old API to a fresh window."""
    try:
        import psutil
    except ImportError:
        return
    me = os.getpid()
    for c in psutil.net_connections(kind="inet"):
        try:
            if (c.laddr and c.laddr.port == PORT and c.status == "LISTEN"
                    and c.pid and c.pid != me):
                p = psutil.Process(c.pid)
                p.terminate()
                p.wait(timeout=5)
        except Exception:
            pass


def _serve() -> None:
    import uvicorn
    from engine.service import app           # import the object (frozen-friendly)
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")


def _wait_until_up(timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{URL}/health", timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


# The pywebview Window is kept module-level, NOT as an attribute on the js_api object.
# pywebview introspects the api object to build the JS bridge; a Window attribute makes
# it recurse into the native control (window.native.AccessibilityObject.Bounds...) until
# it hits "maximum recursion depth exceeded" and the window dies. Keep the api stateless.
_WINDOW = None
_WINDOW_MAXED = False


class _WindowAPI:
    """Window controls for the custom (frameless) title bar. Called from the UI as
    window.pywebview.api.<method>(). Holds no object references (see _WINDOW above)."""

    def minimize(self):
        if _WINDOW is not None:
            _WINDOW.minimize()

    def toggle_maximize(self):
        global _WINDOW_MAXED
        if _WINDOW is None:
            return False
        _WINDOW.restore() if _WINDOW_MAXED else _WINDOW.maximize()
        _WINDOW_MAXED = not _WINDOW_MAXED
        return _WINDOW_MAXED

    def close(self):
        if _WINDOW is not None:
            _WINDOW.destroy()


def main() -> int:
    ap = argparse.ArgumentParser(prog="eyil", description="Eyil Guard desktop app")
    ap.add_argument("--no-window", "--background", dest="no_window", action="store_true",
                    help="run as the headless background listener (no native window)")
    args = ap.parse_args()

    _ensure_streams()                    # safe before any print() in a windowed exe

    # Run from the project root so relative paths (engine, data, dist) resolve.
    os.chdir(ROOT)

    _kill_stale_engine()                 # take over the port -> always fresh code

    ui_built = (UI_DIST / "index.html").exists()
    if not ui_built and not args.no_window:
        print("The Eyil UI hasn't been built yet. Run the setup first:\n"
              "    powershell -ExecutionPolicy Bypass -File install.ps1\n"
              "or build it manually:  cd dashboard && npm install && npm run build",
              file=sys.stderr)
        return 2

    print(f"[eyil] {_ensure_clamd()}")

    threading.Thread(target=_serve, daemon=True).start()
    if not _wait_until_up():
        print("Engine did not start in time. Check the console for errors.", file=sys.stderr)
        return 1

    if args.no_window:
        print(f"[eyil] listener running at {URL}  (real-time protection on)")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0

    try:
        import webview  # pywebview
    except ImportError:
        print("pywebview isn't installed, so the native window can't open.\n"
              f"Install it with:  pip install pywebview\nThe engine is live at {URL}",
              file=sys.stderr)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0

    global _WINDOW
    _WINDOW = webview.create_window(
        "Eyil Guard", URL, js_api=_WindowAPI(),
        frameless=True, easy_drag=False,          # custom title bar + drag region in the UI
        width=960, height=880, min_size=(760, 640),
    )
    webview.start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
