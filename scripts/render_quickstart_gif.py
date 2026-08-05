#!/usr/bin/env python3
"""Render ``docs/evidence/images/quickstart.gif`` from a captured quickstart run.

The README's first screenful is a GIF, and a GIF is the easiest place in a
security project to lie: nobody diffs a picture. So this script exists, and so
does the transcript it draws from.

``docs/evidence/images/quickstart.ansi`` is the raw ``script(1)`` capture of an
actual ``./scripts/quickstart.sh`` run. Every line of text in the GIF appears in
that file verbatim. What this script does is *select* (scenario 3 and the
next-steps block are left out for length) and *lay out* — it does not reword,
round, or improve any output. To check that, read the .ansi and compare.

    python scripts/render_quickstart_gif.py

Requires Pillow and DejaVu Sans Mono; both are dev-only, neither is a gateway
dependency. Re-record the transcript and re-run this after any change to the
walkthrough's output, or the GIF starts quoting a version of the product that
no longer exists.
"""

from __future__ import annotations

import os
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - dev-only tool
    sys.exit("Pillow is required:  pip install Pillow")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO_ROOT, "docs", "evidence", "images", "quickstart.gif")

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SIZE = 17

BG = (13, 17, 23)
CHROME = (22, 27, 34)
FG = (201, 209, 217)
DIM = (110, 118, 129)
WHITE = (240, 246, 252)
GREEN = (63, 185, 80)
RED = (248, 81, 73)

# (text, colour, bold) segments, one list per line. Verbatim from the transcript.
LINES: list[list[tuple[str, tuple[int, int, int], bool]]] = [
    [],
    [("◐ checking prerequisites", WHITE, True)],
    [("  python3 · redis-server ✓", DIM, False)],
    [("◐ starting sandbox gateway on :8080", WHITE, True)],
    [('{"status":"live","glyph":"◐","loop":"uvloop","version":"3.0.0"}', GREEN, False)],
    [],
    [
        ("MCPIP — live company walkthrough", WHITE, True),
        ("  ◐ http://localhost:8080 · v3.0.0", DIM, False),
    ],
    [("Every line below is a real /v1/mcp round-trip through the zero-trust pipeline.", DIM, False)],
    [],
    [("Scenario 1 — Engineering agent", WHITE, True)],
    [("  tools/list → skill_company_overview, skill_data_lake, skill_engineering_roadmap,", DIM, False)],
    [("               skill_aws_s3, skill_aws_dynamodb, skill_email_send", DIM, False)],
    [("    ALLOW", GREEN, False), ("  skill_engineering_roadmap", FG, False)],
    [
        ("    DENY ", RED, False),
        ("  skill_financial_wage_sheet", FG, False),
        ("   opaque · correlation df2abd35a0854c6e80a178b8b6c930a2", DIM, False),
    ],
    [],
    [("Scenario 2 — Finance agent", WHITE, True)],
    [("  tools/list → skill_company_overview, skill_data_lake, skill_financial_wage_sheet,", DIM, False)],
    [("               skill_financial_ledger_post, skill_email_send", DIM, False)],
    [("    ALLOW", GREEN, False), ("  skill_financial_wage_sheet", FG, False)],
    [
        ("    DENY ", RED, False),
        ("  skill_engineering_roadmap", FG, False),
        ("   opaque · correlation 1090a244e8444df19e9ce433b6083195", DIM, False),
    ],
    [],
    [("✓ All decisions matched — team separation enforced at the choke point.", GREEN, True)],
    [("The finance wage sheet never appeared in Engineering's tools/list, and every", DIM, False)],
    [("cross-team call was denied opaquely. Every decision is WORM-logged.", DIM, False)],
]

CMD = "git clone https://github.com/mcpip-security/mcpip.git && cd mcpip && ./scripts/quickstart.sh"
TITLE = "mcpip — one gateway, two agents, real decisions"


def main() -> None:
    font = ImageFont.truetype(FONT_PATH, SIZE)
    bold = ImageFont.truetype(BOLD_PATH, SIZE)

    advance = font.getlength("M")
    line_h = SIZE + 7
    pad = 22
    chrome_h = 34
    cols = max(
        len(CMD) + 2,
        max((sum(len(t) for t, _, _ in line) for line in LINES), default=0),
    )
    width = int(pad * 2 + advance * cols) + 8
    height = pad * 2 + chrome_h + line_h * (len(LINES) + 1)

    def frame(typed: str, shown: int) -> Image.Image:
        im = Image.new("RGB", (width, height), BG)
        draw = ImageDraw.Draw(im)

        draw.rectangle([0, 0, width, chrome_h], fill=CHROME)
        for i, colour in enumerate(((255, 95, 87), (254, 188, 46), (40, 200, 64))):
            cx, cy = pad + i * 20, chrome_h // 2
            draw.ellipse([cx - 6, cy - 6, cx + 6, cy + 6], fill=colour)
        draw.text(
            ((width - font.getlength(TITLE)) / 2, chrome_h / 2 - SIZE / 2 - 1),
            TITLE,
            font=font,
            fill=DIM,
        )

        y = chrome_h + pad
        draw.text((pad, y), "$ ", font=bold, fill=GREEN)
        draw.text((pad + advance * 2, y), typed, font=font, fill=WHITE)
        if shown == 0:  # blinking-free block cursor, only while typing
            draw.rectangle(
                [
                    pad + advance * (2 + len(typed)),
                    y + 2,
                    pad + advance * (3 + len(typed)) - 1,
                    y + SIZE + 3,
                ],
                fill=FG,
            )
        y += line_h

        for line in LINES[:shown]:
            x = pad
            for text, colour, is_bold in line:
                draw.text((x, y), text, font=bold if is_bold else font, fill=colour)
                x += advance * len(text)
            y += line_h
        return im

    frames: list[Image.Image] = []
    delays: list[int] = []  # centiseconds

    frames.append(frame("", 0))
    delays.append(70)
    for i in range(3, len(CMD) + 1, 3):
        frames.append(frame(CMD[:i], 0))
        delays.append(2)
    frames.append(frame(CMD, 0))
    delays.append(45)

    for n in range(1, len(LINES) + 1):
        frames.append(frame(CMD, n))
        body = "".join(t for t, _, _ in LINES[n - 1])
        if not body.strip():
            delays.append(8)
        elif "ALLOW" in body or "DENY" in body:
            delays.append(38)  # the beats worth reading
        elif body.startswith("✓"):
            delays.append(60)
        else:
            delays.append(20)
    delays[-1] = 420  # hold the final screen before looping

    # One shared palette, taken from the fullest frame, so the GIF stays small
    # and does not flicker between per-frame adaptive palettes.
    palette = frames[-1].convert("P", palette=Image.ADAPTIVE, colors=32)
    quantized = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]

    quantized[0].save(
        OUT,
        save_all=True,
        append_images=quantized[1:],
        duration=[d * 10 for d in delays],
        loop=0,
        optimize=True,
        disposal=1,
    )
    print(
        f"{OUT}  {width}x{height}  {len(frames)} frames  "
        f"{sum(delays) / 100:.1f}s  {os.path.getsize(OUT) / 1024:.0f} KiB"
    )


if __name__ == "__main__":
    main()
