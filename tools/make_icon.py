"""Generate the Eyil Guard app icon — a white fortress on the brand indigo.

Produces a multi-size .ico for the packaged Eyil.exe and a favicon for the
dashboard. Re-run after changing the logo:  python tools/make_icon.py
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ACCENT = (123, 108, 246, 255)   # #7B6CF6
WHITE = (255, 255, 255, 255)

S = 1024  # supersample, then downscale for crisp edges


def render() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # rounded-square app tile
    m = int(S * 0.04)
    d.rounded_rectangle([m, m, S - m, S - m], radius=int(S * 0.205), fill=ACCENT)

    # crenellated keep (same merlon logic as the dashboard mascot)
    x0, x1 = int(S * 0.29), int(S * 0.71)
    y_top, y_floor, bottom = int(S * 0.37), int(S * 0.46), int(S * 0.75)
    n = 4
    seg = 2 * n - 1
    w = (x1 - x0) / seg
    pts = [(x0, bottom), (x0, y_top)]
    for s in range(seg):
        xe = x0 + (s + 1) * w
        pts.append((xe, y_top if s % 2 == 0 else y_floor))
        if s < seg - 1:
            pts.append((xe, y_top if (s + 1) % 2 == 0 else y_floor))
    pts.append((x1, bottom))
    d.polygon(pts, fill=WHITE)

    # arrow-slit windows + an arched gate, punched back out in the tile colour
    for cx in (int(S * 0.40), int(S * 0.60)):
        d.rounded_rectangle([cx - int(S * 0.013), int(S * 0.49),
                             cx + int(S * 0.013), int(S * 0.55)], radius=int(S * 0.013), fill=ACCENT)
    gw = int(S * 0.11)
    gx = S // 2 - gw // 2
    d.rounded_rectangle([gx, int(S * 0.585), gx + gw, bottom], radius=int(gw * 0.5), fill=ACCENT)
    d.rectangle([gx, int(S * 0.66), gx + gw, bottom], fill=ACCENT)

    return img.resize((256, 256), Image.LANCZOS)


def main() -> None:
    base = render()
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]

    out_ico = ROOT / "assets" / "eyil.ico"
    out_ico.parent.mkdir(parents=True, exist_ok=True)
    base.save(out_ico, format="ICO", sizes=sizes)

    favicon = ROOT / "dashboard" / "public" / "favicon.ico"
    favicon.parent.mkdir(parents=True, exist_ok=True)
    base.save(favicon, format="ICO", sizes=sizes)

    print(f"wrote {out_ico}")
    print(f"wrote {favicon}")


if __name__ == "__main__":
    main()
