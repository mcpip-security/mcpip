"""
MCPIP — the desktop lockfile must name the version the desktop actually is.

``dashboard/src-tauri/Cargo.lock`` recorded ``mcpip-operator 2.1.0`` while both
``Cargo.toml`` and ``VERSION`` said ``3.0.0``. Nothing noticed for a whole minor
release: a lockfile is not read by any test, the console build does not consult
it, and it only regenerates when someone happens to run ``cargo`` — which is
exactly what surfaced it, by accident, during an audit.

The cost is not cosmetic. ``desktop-release.yml`` bundles installers from this
tree, so a stale lock is the version recorded in a shipped artifact's dependency
graph, and any provenance or SBOM taken from it describes a release that does not
exist. It is also the class of drift ``scripts/preflight_version_consistency.py``
was written to stop — this surface was simply never added to it.

Deliberately narrow: this asserts the ``mcpip-operator`` package entry alone.
Third-party pins are Cargo's business and must stay free to move.
"""

from __future__ import annotations

import os
import re

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOCK = os.path.join(_REPO_ROOT, "dashboard", "src-tauri", "Cargo.lock")
_TOML = os.path.join(_REPO_ROOT, "dashboard", "src-tauri", "Cargo.toml")
_VERSION = os.path.join(_REPO_ROOT, "VERSION")

#: The crate whose version is OURS. Everything else in the lock is upstream.
_PACKAGE = "mcpip-operator"


def _version_file() -> str:
    with open(_VERSION, encoding="utf-8") as handle:
        return handle.read().strip()


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _locked_version() -> str | None:
    """The ``version`` of the ``[[package]] name = "mcpip-operator"`` entry."""
    if not os.path.exists(_LOCK):
        pytest.skip("Cargo.lock absent — the desktop crate is not vendored in this tree")
    match = re.search(
        r'\[\[package\]\]\s*\nname\s*=\s*"' + re.escape(_PACKAGE) + r'"\s*\nversion\s*=\s*"([^"]+)"',
        _read(_LOCK),
    )
    return match.group(1) if match else None


def _manifest_version() -> str | None:
    match = re.search(r'^\s*version\s*=\s*"([^"]+)"', _read(_TOML), re.MULTILINE)
    return match.group(1) if match else None


def test_the_lockfile_names_the_desktop_crate() -> None:
    assert _locked_version() is not None, (
        f"Cargo.lock has no [[package]] entry for {_PACKAGE!r} — either the crate was "
        "renamed (update _PACKAGE here) or the lock is not for this workspace"
    )


def test_the_lockfile_matches_the_crate_manifest() -> None:
    """The drift that actually happened: lock 2.1.0, manifest 3.0.0."""
    locked, manifest = _locked_version(), _manifest_version()
    assert locked == manifest, (
        f"dashboard/src-tauri/Cargo.lock pins {_PACKAGE} {locked!r} but Cargo.toml says "
        f"{manifest!r}. Regenerate it — `cargo generate-lockfile` (or any cargo command) "
        "in dashboard/src-tauri — and commit the result."
    )


def test_the_crate_manifest_matches_the_VERSION_file() -> None:
    """VERSION is the single source of truth; the desktop is a lockstep surface."""
    manifest, version = _manifest_version(), _version_file()
    assert manifest == version, (
        f"dashboard/src-tauri/Cargo.toml says {manifest!r} but VERSION says {version!r}. "
        "The desktop console ships as part of this release and must not carry its own "
        "version line (see scripts/preflight_version_consistency.py for the other "
        "lockstep surfaces)."
    )
