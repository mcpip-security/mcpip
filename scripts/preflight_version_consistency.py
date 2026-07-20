#!/usr/bin/env python3
"""
◐ MCPIP — version-consistency preflight (read-only).

Guards the exact staleness class that produced the "app shows v2.0.0" report: a version
surface drifting out of lockstep with the ``VERSION`` file.

``VERSION`` is the single source of truth. This check asserts the **lockstep** surfaces
match it byte-for-byte:

  * chart/Chart.yaml  ->  version  AND  appVersion
  * dashboard/package.json  ->  version

and reports the **signed release provenance** surfaces (``release/manifest.json`` +
``release/integrity_manifest.json``) HONESTLY:

  * a signed manifest that LAGS ``VERSION`` is the EXPECTED owner-offline-resign state
    (RELEASE.md §0) -> a WARNING, never a hard failure (the running gateway's dynamic
    surfaces already read 3.0.0; the signed provenance reconciles only when the owner
    re-signs on the air-gapped signer).
  * a signed manifest AHEAD of ``VERSION`` is a real error -> hard failure.

Deliberately NOT checked: the SDKs (``sdk/python/pyproject.toml`` /
``sdk/typescript/package.json``) are independently versioned at 0.1.0 BY DESIGN and
reconcile via a dynamic gateway read, not a forced lockstep bump — so they are not a
stale surface and this preflight must not flag them.

Read-only, stdlib-only, no network. Exit 0 = lockstep OK (a lagging signed manifest is a
warning, still exit 0); exit 1 = a real mismatch. Run before every deploy.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_SEMVER = re.compile(r"^\d+\.\d+\.\d+")


def _read_text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8").strip()


def _semver_tuple(v: str) -> tuple[int, int, int]:
    if not _SEMVER.match(v):
        raise ValueError(f"not a strict MAJOR.MINOR.PATCH version: {v!r}")
    major, minor, patch = (v.split("-")[0].split("+")[0]).split(".")[:3]
    return (int(major), int(minor), int(patch))


def _chart_versions(rel: str) -> tuple[str, str]:
    """Parse Chart.yaml's top-level ``version`` and ``appVersion`` without a YAML dep."""
    version = app_version = None
    for line in _read_text(rel).splitlines():
        m = re.match(r"^version:\s*(\S+)\s*$", line)
        if m:
            version = m.group(1).strip().strip('"').strip("'")
        m = re.match(r"^appVersion:\s*(\S+)\s*$", line)
        if m:
            app_version = m.group(1).strip().strip('"').strip("'")
    if version is None or app_version is None:
        raise ValueError(f"{rel}: could not find version/appVersion")
    return version, app_version


def _json_version(rel: str) -> str:
    obj = json.loads(_read_text(rel))
    v = obj.get("version")
    if not isinstance(v, str):
        raise ValueError(f"{rel}: missing string .version")
    return v


def main() -> int:
    source = _read_text("VERSION")
    print(f"◐ MCPIP version-consistency preflight")
    print(f"  source of truth  VERSION = {source}")

    problems: list[str] = []
    warnings: list[str] = []

    # --- Lockstep surfaces: MUST equal VERSION. --------------------------------------
    lockstep: list[tuple[str, str]] = []
    try:
        cv, cav = _chart_versions("chart/Chart.yaml")
        lockstep.append(("chart/Chart.yaml:version", cv))
        lockstep.append(("chart/Chart.yaml:appVersion", cav))
    except (OSError, ValueError) as exc:
        problems.append(f"chart/Chart.yaml: {exc}")
    try:
        lockstep.append(("dashboard/package.json:version", _json_version("dashboard/package.json")))
    except (OSError, ValueError) as exc:
        problems.append(f"dashboard/package.json: {exc}")

    print("\n  lockstep surfaces (must equal VERSION):")
    for name, val in lockstep:
        ok = val == source
        print(f"    [{'OK ' if ok else 'BAD'}] {name} = {val}")
        if not ok:
            problems.append(f"{name} = {val} != VERSION {source}")

    # --- Signed provenance: a LAG is the honest owner-offline-resign state. -----------
    print("\n  signed provenance (lag until owner re-sign is EXPECTED, RELEASE.md §0):")
    for name, rel in (
        ("release/manifest.json", "release/manifest.json"),
        ("release/integrity_manifest.json", "release/integrity_manifest.json"),
    ):
        try:
            mv = _json_version(rel)
        except (OSError, ValueError) as exc:
            warnings.append(f"{name}: unreadable ({exc})")
            print(f"    [??] {name}: unreadable ({exc})")
            continue
        if mv == source:
            print(f"    [OK ] {name} = {mv} (reconciled — the owner has re-signed)")
        elif _semver_tuple(mv) < _semver_tuple(source):
            print(
                f"    [LAG] {name} = {mv} < VERSION {source} — expected: the signed "
                f"release re-signs OFFLINE on the owner's air-gapped key."
            )
            warnings.append(f"{name} = {mv} lags VERSION {source} (owner-offline re-sign pending)")
        else:
            print(f"    [BAD] {name} = {mv} > VERSION {source} — a signed manifest AHEAD of VERSION")
            problems.append(f"{name} = {mv} is AHEAD of VERSION {source}")

    print("\n  note: the SDKs (sdk/python, sdk/typescript) are independently versioned "
          "at 0.1.0 by design and are NOT checked here.")

    if warnings:
        print("\n⚠ warnings (not failures):")
        for w in warnings:
            print(f"    - {w}")

    if problems:
        print("\n✗ version-consistency FAILED:")
        for p in problems:
            print(f"    - {p}")
        return 1

    print("\n✓ lockstep version surfaces reconcile to VERSION.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
