# Eyil Guard - PyInstaller spec.  Build:  python build_exe.py   (or)  pyinstaller eyil.spec --noconfirm --clean
#
# Produces dist/Eyil/Eyil.exe — a windowed launcher that starts the engine,
# serves the bundled dashboard, and opens the native window. ClamAV (clamd) is
# NOT bundled (217 MB); the launcher starts a locally-installed clamd if present.

import os
from PyInstaller.utils.hooks import collect_submodules

hidden = (
    collect_submodules("uvicorn")
    + collect_submodules("engine")
    + collect_submodules("watchdog")
    + collect_submodules("webview")
    + ["clamd", "yara_x", "psutil", "anyio", "fastapi", "starlette", "pydantic", "pydantic_core"]
)

# The built UI + bundled YARA rules must ride along so the engine works offline.
datas = [
    ("dashboard/dist", "dashboard/dist"),
    ("engine/yara_builtin", "engine/yara_builtin"),
    ("data/clam/clamd.conf", "data/clam"),
    ("data/clam/freshclam.conf", "data/clam"),
]
# Bundle the community YARA rules (signature-base, etc.) when they've been downloaded,
# so the exe ships the full ruleset instead of just the 12 builtin rules. These are
# DRL-licensed — included as data with attribution (see README). On first run the
# frozen app seeds them into %LOCALAPPDATA%\EyilGuard\data\yara (engine/paths.py).
if os.path.isdir("data/yara"):
    datas.append(("data/yara", "data/yara"))

a = Analysis(
    ["eyil/__main__.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="Eyil",
    icon="assets/eyil.ico",   # fortress app icon (taskbar + window + file)
    console=False,            # windowed app (no console); launcher redirects stdio to a log

    disable_windowed_traceback=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="Eyil")
