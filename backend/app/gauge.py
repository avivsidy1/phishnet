"""Animated verdict + score image for the add-on card.

Gmail cards can't run code or CSS, and card text can't be enlarged, but cards show images and an
animated GIF plays when the card opens. Layout: on the left, a ring and number that count up to the
score; on the right, the verdict as the most visible element (icon + large word in its color) and the
score range it covers. The verdict is drawn from the first frame, so a client that shows only the first
frame still shows what matters. The image depends only on the score and the thresholds (no email
data), so it is public and cacheable. Drawn at 3x and downscaled for smooth edges.
Gmail stretches card images to the panel's width, hence the wide canvas.
"""

import io
import math
from functools import lru_cache

from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 560, 200  # final canvas
SCALE = 3                 # supersampling factor
RING_DIAMETER = 168       # ring on the left, vertically centered
RING = 16                 # ring thickness
FRAMES = 24               # animation frames
FRAME_MS = 40             # ~1 s total
FINAL_HOLD_MS = 60_000    # GIFs without a loop play once; the last frame stays

WHITE = (255, 255, 255)
TRACK = (232, 234, 237)
TEXT_MUTED = (95, 99, 104)
VERDICT_COLORS = {"safe": (24, 128, 56), "suspicious": (227, 116, 0), "malicious": (217, 48, 37)}
VERDICT_LABELS = {"safe": "SAFE", "suspicious": "SUSPICIOUS", "malicious": "MALICIOUS"}


def verdict_for(score: int, suspicious: int = 30, malicious: int = 70) -> str:
    return "malicious" if score >= malicious else "suspicious" if score >= suspicious else "safe"


def range_text(verdict: str, suspicious: int, malicious: int) -> str:
    if verdict == "malicious":
        return f"Score {malicious} or higher"
    if verdict == "suspicious":
        return f"Score between {suspicious} and {malicious - 1}"
    return f"Score below {suspicious}"


def _font(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.load_default(size=size * SCALE)  # Pillow's bundled scalable font


def _icon(draw: ImageDraw.ImageDraw, verdict: str, cx: float, cy: float, r: float, color) -> None:
    """Outline icons, no fill: a check mark (safe), a warning triangle with "!" (suspicious),
    a stop octagon with an X (malicious)."""
    w = round(r * 0.2)  # stroke width
    if verdict == "safe":
        draw.line([(cx - r * 0.8, cy + r * 0.02), (cx - r * 0.25, cy + r * 0.6), (cx + r * 0.85, cy - r * 0.62)],
                  fill=color, width=round(r * 0.26), joint="curve")
        for x, y in ((cx - r * 0.8, cy + r * 0.02), (cx + r * 0.85, cy - r * 0.62)):  # round line ends
            k = r * 0.13
            draw.ellipse((x - k, y - k, x + k, y + k), fill=color)
    elif verdict == "suspicious":
        top, bottom = cy - r * 1.0, cy + r * 0.85
        draw.line([(cx, top), (cx + r * 1.08, bottom), (cx - r * 1.08, bottom), (cx, top)],
                  fill=color, width=w, joint="curve")
        draw.rounded_rectangle((cx - r * 0.1, cy - r * 0.42, cx + r * 0.1, cy + r * 0.25), radius=r * 0.08, fill=color)
        draw.ellipse((cx - r * 0.12, cy + r * 0.4, cx + r * 0.12, cy + r * 0.64), fill=color)
    else:
        points = [(cx + r * math.cos(math.radians(22.5 + 45 * i)), cy + r * math.sin(math.radians(22.5 + 45 * i)))
                  for i in range(9)]
        draw.line(points, fill=color, width=w, joint="curve")
        k = r * 0.36
        draw.line([(cx - k, cy - k), (cx + k, cy + k)], fill=color, width=w)
        draw.line([(cx - k, cy + k), (cx + k, cy - k)], fill=color, width=w)


def _frame(shown: int, verdict: str, range_line: str) -> Image.Image:
    s = SCALE
    color = VERDICT_COLORS[verdict]
    image = Image.new("RGB", (WIDTH * s, HEIGHT * s), WHITE)
    draw = ImageDraw.Draw(image)

    # Ring + number (left, secondary).
    d = RING_DIAMETER * s
    left, top = 16 * s, (HEIGHT * s - d) // 2
    box = (left, top, left + d, top + d)
    draw.ellipse(box, outline=TRACK, width=RING * s)
    cx, cy = left + d / 2, top + d / 2
    if shown > 0:
        draw.arc(box, start=-90, end=-90 + 360 * shown / 100, fill=color, width=RING * s)
        r_mid = d / 2 - RING * s / 2  # Pillow draws a wide arc inward from the box edge
        for angle in (-90, -90 + 360 * shown / 100):  # round caps
            x, y = cx + r_mid * math.cos(math.radians(angle)), cy + r_mid * math.sin(math.radians(angle))
            draw.ellipse((x - RING * s / 2, y - RING * s / 2, x + RING * s / 2, y + RING * s / 2), fill=color)
    draw.text((cx, cy - 5 * s), str(shown), fill=color, font=_font(50), anchor="mm")
    draw.text((cx, cy + 32 * s), "/ 100", fill=TEXT_MUTED, font=_font(15), anchor="mm")

    # Verdict (right, primary): icon + large bold word, then the range.
    tx = left + d + 26 * s
    icon_r = 21 * s
    icon_cy = HEIGHT * s / 2 - 18 * s
    _icon(draw, verdict, tx + icon_r, icon_cy, icon_r, color)
    draw.text((tx + 2 * icon_r + 12 * s, icon_cy), VERDICT_LABELS[verdict], fill=color, font=_font(38),
              anchor="lm", stroke_width=round(1.6 * s), stroke_fill=color)  # stroke = bolder weight
    draw.text((tx + 2, icon_cy + 46 * s), range_line, fill=TEXT_MUTED, font=_font(19), anchor="lm")
    return image.resize((WIDTH, HEIGHT), Image.LANCZOS)


@lru_cache(maxsize=256)
def gauge_gif(score: int, suspicious: int = 30, malicious: int = 70) -> bytes:
    """GIF bytes for a score 0-100: ring and number count up (ease-out), verdict shown throughout."""
    if not 0 <= score <= 100:
        raise ValueError("score must be 0-100")
    verdict = verdict_for(score, suspicious, malicious)
    line = range_text(verdict, suspicious, malicious)
    steps = [round(score * (1 - (1 - i / (FRAMES - 1)) ** 3)) for i in range(FRAMES)]  # ease-out cubic
    frames = [_frame(s, verdict, line).convert("P", palette=Image.ADAPTIVE, colors=64) for s in steps]
    durations = [FRAME_MS] * (FRAMES - 1) + [FINAL_HOLD_MS]
    out = io.BytesIO()
    # No `loop` argument: no NETSCAPE loop extension, so viewers play it once and keep the last frame.
    frames[0].save(out, format="GIF", save_all=True, append_images=frames[1:], duration=durations,
                   disposal=1, optimize=False)
    return out.getvalue()
