"""Build a looping feature-tour GIF for the README from the captured screenshots.

A simple slideshow: caught-a-threat -> Simple view -> Technical view -> Settings.
Frames are scaled to one width and top-aligned on the app's lavender background so
the header stays put as the content changes. Re-run after updating screenshots:
    python tools/make_demo_gif.py
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "assets" / "screenshots"
OUT = ROOT / "assets" / "demo.gif"
BG = (237, 235, 246)      # P.bg lavender
WIDTH = 620
HOLD_MS = 1600

ORDER = ["01-dashboard", "02-simple-detail", "03-technical", "04-settings"]


def main() -> None:
    scaled = []
    for name in ORDER:
        im = Image.open(SHOTS / f"{name}.png").convert("RGB")
        h = round(im.height * WIDTH / im.width)
        scaled.append(im.resize((WIDTH, h), Image.LANCZOS))

    canvas_h = max(im.height for im in scaled)
    frames = []
    for im in scaled:
        c = Image.new("RGB", (WIDTH, canvas_h), BG)
        c.paste(im, (0, 0))                       # top-align: header stays fixed
        # quantize per-frame for a smaller, cleaner GIF
        frames.append(c.quantize(colors=128, method=Image.MEDIANCUT, dither=Image.Dither.NONE))

    frames[0].save(
        OUT, save_all=True, append_images=frames[1:],
        duration=HOLD_MS, loop=0, optimize=True, disposal=2,
    )
    print(f"wrote {OUT}  ({OUT.stat().st_size // 1024} KB, {len(frames)} frames, {WIDTH}x{canvas_h})")


if __name__ == "__main__":
    main()
