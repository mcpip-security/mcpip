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

#: A backticked repo path, optionally with a `:line` or `:line-line` citation.
_CITATION = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_./-]*\.[A-Za-z0-9]{1,5})(?::(\d+)(?:-(\d+))?)?`")

#: Extensions we treat as "this names a file in this repository".
_SOURCE_SUFFIXES = (
    ".py", ".ts", ".tsx", ".js", ".mjs", ".json", ".yaml", ".yml",
    ".toml", ".sh", ".rs", ".md", ".txt", ".cfg", ".ini", ".png",
)

#: Backticked strings that match the path shape but name something else.
_NOT_A_PATH = frozenset({
    "mcpip.io", "claude.ai", "example.com", "package.json", "pyproject.toml",
    "requirements.txt", "tsconfig.json", "values.yaml", "Chart.yaml",
})

#: Paths the documentation names on purpose that are not in the tree, and why.
#: Every entry is a deliberate decision — add one only when the reader is told,
#: at the point of citation, that the file is not here.
_DELIBERATELY_ABSENT = {
    "audit/group_wal.py": "a future wave, labelled 'not built here' where it is cited",
    "services/extension_registry.py": "Phase 3 of the extension roadmap, not shipped",
    "release/provenance.intoto.json": "generated at release time and gitignored",
    "artifacts/BUILD_RECIPE.md": "a path inside the air-gap bundle, not the repository",
    "keys/rotation.json": "a path inside the air-gap bundle, not the repository",
}

#: A changelog describes files that were added *and removed*; naming a deleted
#: module is what it is for, so it is not checked for path existence.
_HISTORICAL = ("CHANGELOG.md",)


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


def _cited_paths() -> list[tuple[str, str, str | None, str | None]]:
    """Every backticked repo path in the docs, as (doc, path, start_line, end_line)."""
    found: list[tuple[str, str, str | None, str | None]] = []
    for path in _DOCS:
        if not os.path.exists(path):
            continue
        doc = os.path.relpath(path, _REPO_ROOT)
        for target, start, end in _CITATION.findall(_read(path)):
            if target in _NOT_A_PATH or "/" not in target:
                continue
            if not target.endswith(_SOURCE_SUFFIXES):
                continue
            found.append((doc, target, start or None, end or None))
    return found


def test_backticked_source_paths_exist() -> None:
    """A path named in backticks must name a real file.

    Prose citations are not links, so nothing else checks them — a module can be
    renamed and every document that points a reader at it keeps saying the old
    name indefinitely.
    """
    broken: list[str] = []
    for doc, target, _start, _end in _cited_paths():
        if doc in _HISTORICAL or target in _DELIBERATELY_ABSENT:
            continue
        base = os.path.dirname(os.path.join(_REPO_ROOT, doc))
        if os.path.exists(os.path.join(_REPO_ROOT, target)):
            continue
        if os.path.exists(os.path.normpath(os.path.join(base, target))):
            continue
        broken.append(f"{doc} -> `{target}`")
    assert not broken, "documentation names files that do not exist:\n  " + "\n  ".join(
        sorted(set(broken))
    )


def test_line_number_citations_are_in_range() -> None:
    """`path.py:120-130` must name lines that file actually has.

    Line numbers drift as soon as anyone edits above them, and a citation that
    has slid a few hundred lines still *looks* authoritative. This catches the
    case where it has slid off the end entirely; prefer citing a symbol name
    over a line number where you can, because that cannot drift at all.
    """
    broken: list[str] = []
    for doc, target, start, end in _cited_paths():
        if start is None:
            continue
        candidate = os.path.join(_REPO_ROOT, target)
        if not os.path.exists(candidate):
            candidate = os.path.normpath(os.path.join(os.path.dirname(os.path.join(_REPO_ROOT, doc)), target))
        if not os.path.exists(candidate):
            continue  # reported by test_backticked_source_paths_exist
        total = len(_read(candidate).splitlines())
        last = int(end or start)
        if int(start) < 1 or last > total:
            broken.append(f"{doc} -> `{target}:{start}{'-' + end if end else ''}` (file has {total} lines)")
    assert not broken, "line-number citations that point past the end of the file:\n  " + "\n  ".join(broken)


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
