"""Where Eyil keeps its data.

From source: the repo's `data/` folder — unchanged behaviour.
Frozen (a packaged `Eyil.exe`): a **writable** per-user folder under
`%LOCALAPPDATA%\\EyilGuard\\data`, seeded once from the read-only defaults bundled
inside the exe (community YARA, clam confs). This lets the installed app update its
feeds + persist your keys even when the program files themselves are read-only.

Centralising this here keeps every engine module pointed at the same place — they
all do `from .paths import DATA`.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

# When frozen, this module lives at <sys._MEIPASS>/engine/paths.pyc, so parent.parent
# is the bundle root (_internal) where the bundled `data/` defaults sit. From source
# it's the repo root, so _BUNDLED_DATA is just the repo's own data/ (no copy needed).
_BUNDLED_DATA = Path(__file__).resolve().parent.parent / "data"


def _seed(dest: Path) -> None:
    """First run only: copy the bundled defaults into the writable data dir.
    Skips anything already present, so it's cheap on every later launch."""
    try:
        if not _BUNDLED_DATA.exists() or _BUNDLED_DATA.resolve() == dest.resolve():
            return
        for child in _BUNDLED_DATA.iterdir():
            target = dest / child.name
            if target.exists():
                continue
            if child.is_dir():
                shutil.copytree(child, target, dirs_exist_ok=True)
            else:
                shutil.copy2(child, target)
    except Exception:
        pass  # detection still works against an empty data dir; never crash on seeding


def _resolve_data_dir() -> Path:
    if getattr(sys, "frozen", False):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        d = Path(base) / "EyilGuard" / "data"
        d.mkdir(parents=True, exist_ok=True)
        _seed(d)
        return d
    return _BUNDLED_DATA  # source: the repo's data/ (identical to the old behaviour)


DATA = _resolve_data_dir()
