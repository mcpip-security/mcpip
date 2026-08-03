"""
MCPIP — every documentation link must resolve.

Two failure modes, both of which shipped: a relative path to a file that does not
exist, and an intra-page `#anchor` that matches no heading. The second is the
quieter one — the browser silently scrolls to the top, so the reader lands on the
wrong content believing they are in the right place. Seven of those accumulated
in the operator runbook alone, pointing at headings that had been retitled.

This is deliberately mechanical: it does not judge whether a link is *useful*,
only that following it lands somewhere real.
"""

from __future__ import annotations

import glob
import sys
import os
import re

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Markdown files that are product documentation (not vendored or generated).
_DOCS = sorted(
    glob.glob(os.path.join(_REPO_ROOT, "docs", "**", "*.md"), recursive=True)
    + [os.path.join(_REPO_ROOT, n) for n in ("README.md", "SECURITY.md", "CHANGELOG.md")]
    + glob.glob(os.path.join(_REPO_ROOT, ".github", "*.md"))
)

_LINK = re.compile(r"\]\(([^)\s]+)\)")
_HEADING = re.compile(r"^#{1,6}\s+(.*)$", re.M)


def _slug(heading: str) -> str:
    """GitHub's anchor slug: lowercase, drop punctuation, spaces to hyphens."""
    return re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def test_every_relative_link_resolves() -> None:
    broken: list[str] = []
    for path in _DOCS:
        if not os.path.exists(path):
            continue
        base = os.path.dirname(path)
        for target in _LINK.findall(_read(path)):
            file_part = target.split("#")[0].strip()
            if not file_part or file_part.startswith(("http://", "https://", "mailto:")):
                continue
            if not os.path.exists(os.path.normpath(os.path.join(base, file_part))):
                broken.append(f"{os.path.relpath(path, _REPO_ROOT)} -> {target}")
    assert not broken, "documentation links to files that do not exist:\n  " + "\n  ".join(broken)


def test_every_intra_page_anchor_resolves() -> None:
    broken: list[str] = []
    for path in _DOCS:
        if not os.path.exists(path):
            continue
        text = _read(path)
        anchors = {_slug(h) for h in _HEADING.findall(text)}
        for target in _LINK.findall(text):
            if not target.startswith("#"):
                continue
            if target[1:] not in anchors:
                broken.append(f"{os.path.relpath(path, _REPO_ROOT)} -> {target}")
    assert not broken, (
        "documentation anchors that match no heading (these fail silently in a "
        "browser — the reader lands at the top of the page):\n  " + "\n  ".join(broken)
    )


def test_cross_file_anchors_resolve() -> None:
    """`other.md#section` must name a heading that exists in that file."""
    broken: list[str] = []
    for path in _DOCS:
        if not os.path.exists(path):
            continue
        base = os.path.dirname(path)
        for target in _LINK.findall(_read(path)):
            if "#" not in target or target.startswith(("#", "http://", "https://")):
                continue
            file_part, _, anchor = target.partition("#")
            dest = os.path.normpath(os.path.join(base, file_part))
            if not dest.endswith(".md") or not os.path.exists(dest):
                continue
            anchors = {_slug(h) for h in _HEADING.findall(_read(dest))}
            if anchor not in anchors:
                broken.append(f"{os.path.relpath(path, _REPO_ROOT)} -> {target}")
    assert not broken, "cross-file anchors that match no heading:\n  " + "\n  ".join(broken)


def test_documented_test_count_is_a_floor_that_still_holds() -> None:
    """A claimed test count must be a floor the suite still clears.

    An exact count rots the moment anyone adds a test — this session put three
    stale ones in the tree that way. Stating a floor ("1,600+") is honest, stays
    true as the suite grows, and is checkable; this asserts it has not been
    overtaken, which is the only way it can become a lie.
    """
    import subprocess

    claimed: set[int] = set()
    pattern = re.compile(r"([\d,]+)\+?\s+tests\b")
    for path in _DOCS:
        if not os.path.exists(path):
            continue
        for raw in pattern.findall(_read(path)):
            digits = raw.replace(",", "")
            if digits.isdigit() and int(digits) > 100:  # skip "3 tests" style prose
                claimed.add(int(digits))
    if not claimed:
        return  # no count claimed anywhere is a perfectly good state

    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=_REPO_ROOT, capture_output=True, text=True, timeout=300,
    ).stdout
    match = re.search(r"(\d+) tests? collected", out)
    assert match, f"could not read the collected-test count from pytest:\n{out[-500:]}"
    actual = int(match.group(1))

    overtaken = sorted(c for c in claimed if c > actual)
    assert not overtaken, (
        f"documentation claims {overtaken} tests but the suite collects {actual} — "
        "a claimed count must be a floor the suite clears, not a number it fell below"
    )
