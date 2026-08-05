#!/usr/bin/env python3
"""Render the README/marketing terminal GIFs from captured runs.

    python scripts/render_demo_gifs.py            # all scenes
    python scripts/render_demo_gifs.py quickstart

A GIF is the easiest thing in a security repo to lie with, because nobody diffs a
picture. So every scene below names the ``script(1)`` capture it was drawn from,
and that capture is committed next to the GIF. Each line of text in the frames
appears in its capture verbatim. This script *selects* (long runs are trimmed for
length) and *lays out*; it does not reword, round, or improve any output. Read the
.ansi and compare.

Re-record and re-run after any change to what these commands print, or the README
starts quoting a version of the product that no longer exists.

Requires Pillow and DejaVu Sans Mono. Both are dev-only; neither is a gateway
dependency.
"""

from __future__ import annotations

import os
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - dev-only tool
    sys.exit("Pillow is required:  pip install Pillow")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = os.path.join(REPO_ROOT, "docs", "evidence", "images")

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
CYAN = (86, 212, 221)

Line = list[tuple[str, tuple[int, int, int], bool]]  # (text, colour, bold)


# --- scene 1: the quickstart walkthrough -------------------------------------
# Source capture: docs/evidence/images/quickstart.ansi
# Omitted for length: scenario 3, the timing line, the next-steps block.
QUICKSTART: list[Line] = [
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

# --- scene 2: deleting an audit record ---------------------------------------
# Source capture: docs/evidence/images/tamper.ansi (complete — nothing omitted).
TAMPER: list[Line] = [
    [],
    [("MCPIP — can you tell if someone deleted an audit record?", WHITE, True)],
    [("The gateway signs a Merkle root per epoch. The key is not in Redis.", DIM, False)],
    [],
    [("1. Verify the signed chain as it stands", WHITE, True)],
    [("  $ ", DIM, False), ("curl -s http://localhost:8080/v1/audit/verify", CYAN, False)],
    [('  {"intact":true,"first_bad_epoch":null}', GREEN, False)],
    [],
    [("2. Delete one sealed record — straight in Redis, bypassing the gateway", WHITE, True)],
    [("  $ ", DIM, False), ("redis-cli -p 63790 XDEL mcpip:worm:events 1785960540041-0", CYAN, False)],
    [("  (integer) 1", FG, False)],
    [],
    [("3. Ask the gateway to verify the chain again", WHITE, True)],
    [("  $ ", DIM, False), ("curl -s http://localhost:8080/v1/audit/verify", CYAN, False)],
    [('  {"intact":false,"first_bad_epoch":6}', RED, False)],
    [],
    [("✓ Caught.", GREEN, True), (" The gateway names the epoch the missing record was in.", WHITE, True)],
    [("The root is recomputed from the surviving records and compared against the one", DIM, False)],
    [("Ed25519-signed at epoch close. Re-signing a root that matches what was left behind", DIM, False)],
    [("needs the signing key, which is not in Redis — so deletion is detectable, not deniable.", DIM, False)],
]

SCENES: dict[str, dict[str, object]] = {
    "quickstart": {
        "lines": QUICKSTART,
        "cmd": "git clone https://github.com/mcpip-security/mcpip.git && cd mcpip && ./scripts/quickstart.sh",
        "title": "mcpip — one gateway, two agents, real decisions",
        "out": os.path.join(IMAGES, "quickstart.gif"),
    },
    "tamper": {
        "lines": TAMPER,
        "cmd": "./scripts/audit_tamper_demo.sh",
        "title": "mcpip — delete an audit record, watch the chain notice",
        "out": os.path.join(IMAGES, "tamper.gif"),
    },
}


def _hold(body: str) -> int:
    """Centiseconds to rest on a line once it lands — the beats worth reading."""
    if not body.strip():
        return 8
    if "intact" in body:  # the verdict lines carry the whole argument
        return 95
    if "ALLOW" in body or "DENY" in body:
        return 38
    if body.lstrip().startswith(("✓", "✕")):
        return 60
    return 20


def render(lines: list[Line], cmd: str, title: str, out: str) -> None:
    font = ImageFont.truetype(FONT_PATH, SIZE)
    bold = ImageFont.truetype(BOLD_PATH, SIZE)

    advance = font.getlength("M")
    line_h = SIZE + 7
    pad = 22
    chrome_h = 34
    cols = max(
        len(cmd) + 2,
        max((sum(len(t) for t, _, _ in line) for line in lines), default=0),
    )
    width = int(pad * 2 + advance * cols) + 8
    height = pad * 2 + chrome_h + line_h * (len(lines) + 1)

    def frame(typed: str, shown: int) -> Image.Image:
        im = Image.new("RGB", (width, height), BG)
        draw = ImageDraw.Draw(im)

        draw.rectangle([0, 0, width, chrome_h], fill=CHROME)
        for i, colour in enumerate(((255, 95, 87), (254, 188, 46), (40, 200, 64))):
            cx, cy = pad + i * 20, chrome_h // 2
            draw.ellipse([cx - 6, cy - 6, cx + 6, cy + 6], fill=colour)
        draw.text(
            ((width - font.getlength(title)) / 2, chrome_h / 2 - SIZE / 2 - 1),
            title,
            font=font,
            fill=DIM,
        )

        y = chrome_h + pad
        draw.text((pad, y), "$ ", font=bold, fill=GREEN)
        draw.text((pad + advance * 2, y), typed, font=font, fill=WHITE)
        if shown == 0:  # block cursor, only while the command is being typed
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

        for line in lines[:shown]:
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
    for i in range(3, len(cmd) + 1, 3):
        frames.append(frame(cmd[:i], 0))
        delays.append(2)
    frames.append(frame(cmd, 0))
    delays.append(45)

    for n in range(1, len(lines) + 1):
        frames.append(frame(cmd, n))
        delays.append(_hold("".join(t for t, _, _ in lines[n - 1])))
    delays[-1] = 420  # hold the final screen before looping

    # One shared palette, taken from the fullest frame, so the GIF stays small and
    # does not flicker between per-frame adaptive palettes.
    palette = frames[-1].convert("P", palette=Image.ADAPTIVE, colors=32)
    quantized = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]

    quantized[0].save(
        out,
        save_all=True,
        append_images=quantized[1:],
        duration=[d * 10 for d in delays],
        loop=0,
        optimize=True,
        disposal=1,
    )
    print(
        f"{os.path.relpath(out, REPO_ROOT)}  {width}x{height}  {len(frames)} frames  "
        f"{sum(delays) / 100:.1f}s  {os.path.getsize(out) / 1024:.0f} KiB"
    )


def main() -> None:
    wanted = sys.argv[1:] or list(SCENES)
    for name in wanted:
        scene = SCENES.get(name)
        if scene is None:
            sys.exit(f"unknown scene {name!r} — choose from: {', '.join(SCENES)}")
        render(
            scene["lines"],  # type: ignore[arg-type]
            scene["cmd"],  # type: ignore[arg-type]
            scene["title"],  # type: ignore[arg-type]
            scene["out"],  # type: ignore[arg-type]
        )


if __name__ == "__main__":
    main()
