#!/usr/bin/env python3
"""
◐ MCPIP — release tag guard (read-only).

A tag is the only instruction a release workflow receives. If the tag says
``sdk-py-v0.2.0`` while ``sdk/python/pyproject.toml`` still says ``0.1.0``, the
workflow does not fail — it cheerfully republishes ``0.1.0`` under a name nobody
can correlate, and PyPI refuses the *next* real ``0.1.0`` upload because the
version was already burned. The same shape of mistake on the container tag ships
an image whose label disagrees with the code inside it.

So the tag is checked against the manifest it claims, before anything is built:

    v3.0.0            ->  VERSION
    sdk-py-v0.1.0     ->  sdk/python/pyproject.toml   [project] version
    sdk-ts-v0.1.0     ->  sdk/typescript/package.json version
    desktop-v3.0.0    ->  dashboard/package.json      version

The four version lines are **deliberately independent** — the SDKs are versioned
apart from the gateway by design (see ``scripts/preflight_version_consistency.py``,
which must not force them into lockstep). This guard therefore never compares
them to each other, only each tag to its own manifest.

Read-only, stdlib-only, no network. Exit 0 = the tag matches; exit 1 = it does
not, or the tag is not a shape this repository releases.

    python scripts/check_release_tag.py v3.0.0
    python scripts/check_release_tag.py "$GITHUB_REF_NAME"
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: MAJOR.MINOR.PATCH with an optional pre-release suffix (``-rc.1``). Build
#: metadata (``+sha``) is deliberately NOT accepted: it is not part of a PyPI or
#: npm version, so a tag carrying one could never match its manifest anyway.
_SEMVER = r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?"


def _pyproject_version(rel: str) -> str:
    """Read ``[project] version`` without a TOML parser.

    The floor this repository supports includes 3.10, where ``tomllib`` does not
    exist; a regex over the one line we need keeps the guard stdlib-only on every
    interpreter it might run under.
    """
    text = (ROOT / rel).read_text(encoding="utf-8")
    match = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if match is None:
        raise ValueError(f"{rel}: no [project] version line found")
    return match.group(1)


def _json_version(rel: str) -> str:
    data = json.loads((ROOT / rel).read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str):
        raise ValueError(f"{rel}: no string 'version' key")
    return version


def _file_version(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8").strip()


#: prefix -> (human label, manifest path, reader). Order matters only for the
#: error message; matching is exact on the prefix.
TAG_KINDS: tuple[tuple[str, str, str, object], ...] = (
    ("sdk-py-v", "Python SDK", "sdk/python/pyproject.toml", _pyproject_version),
    ("sdk-ts-v", "TypeScript SDK", "sdk/typescript/package.json", _json_version),
    ("desktop-v", "operator console", "dashboard/package.json", _json_version),
    # Bare `v` is last: every other prefix also ends in `v`, so testing it first
    # would swallow `sdk-py-v0.1.0` as the gateway tag `v0.1.0`... except it would
    # not even match, because the prefix test is anchored at position 0. Kept last
    # anyway so the intent survives someone reordering this table.
    ("v", "gateway", "VERSION", _file_version),
)


def check(tag: str) -> tuple[bool, str]:
    """Return ``(ok, message)`` for a tag. Never raises for a malformed tag."""
    for prefix, label, manifest, reader in TAG_KINDS:
        if not tag.startswith(prefix):
            continue
        claimed = tag[len(prefix) :]
        if not re.fullmatch(_SEMVER, claimed):
            return False, (
                f"tag {tag!r} is not MAJOR.MINOR.PATCH after the {prefix!r} prefix "
                f"(got {claimed!r})"
            )
        try:
            actual = reader(manifest)  # type: ignore[operator]
        except (OSError, ValueError) as exc:
            return False, f"cannot read {manifest}: {exc}"
        if actual != claimed:
            return False, (
                f"tag {tag!r} claims {label} {claimed}, but {manifest} says {actual!r} — "
                f"bump the manifest and re-tag, or the release publishes {actual!r} "
                f"under a name nothing can correlate"
            )
        return True, f"{tag} matches {manifest} ({actual}) — {label}"

    known = ", ".join(f"{p}<semver>" for p, _, _, _ in TAG_KINDS)
    return False, f"tag {tag!r} is not a release tag this repository cuts; expected one of: {known}"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} <tag>", file=sys.stderr)
        return 2
    ok, message = check(argv[1])
    print(("OK   " if ok else "FAIL ") + message, file=sys.stderr if not ok else sys.stdout)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
