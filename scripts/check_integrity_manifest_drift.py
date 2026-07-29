#!/usr/bin/env python3
"""
Integrity-manifest DRIFT check (CI change-integrity gate) — signature-free.

The committed ``release/integrity_manifest.json`` is the signed baseline that
``core/integrity.py`` re-hashes at boot; production refuses to start on any
mismatch. That signed baseline is produced by an OFFLINE owner ceremony
(``scripts/gen_integrity_manifest.py`` with the release-root private key), so
CI cannot re-sign it — but CI CAN and SHOULD catch when the *source tree drifts
away from the committed manifest*, which is exactly the "the repo as committed
is not bootable in production" failure class (a stale 2.0.0 manifest vs 3.0.0
source).

This checker recomputes the SHA-256 of the SAME normative file set the manifest
generator hashes (``scripts.gen_integrity_manifest._collect_files``) and diffs
the *file set + per-file hashes* — NOT the signature — against the committed
manifest. It reuses the generator's collection logic verbatim so the two can
never disagree about what "the shipped source set" is.

Exit codes:
  * ``0`` — no drift, OR drift detected in WARN mode (default): the drift is
    printed but the build is not failed, matching ``preflight_version_consistency``'s
    "expected owner-offline-resign lag = warn, exit 0" posture. This keeps the
    merge gate green while the 3.0.0 re-sign is still pending.
  * ``1`` — drift detected in ``--strict`` mode. Flip CI to ``--strict`` once
    the owner has re-signed the manifest at the current VERSION, so any future
    drift is a hard failure at PR time.

There is NO remediation/self-heal path in the product; the operator redeploys a
re-signed, verified image through change control.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Reuse the generator's collection + hashing so "the shipped source set" is
# defined in exactly one place and the two can never drift apart.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_integrity_manifest import (  # noqa: E402
    _REPO_ROOT,
    _collect_files,
    _read_version,
    _sha256_file,
)


def _load_manifest(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Diff the committed integrity manifest against the live source tree"
    )
    parser.add_argument(
        "--manifest",
        default=str(_REPO_ROOT / "release" / "integrity_manifest.json"),
        help="committed signed manifest to check against",
    )
    parser.add_argument(
        "--base-dir",
        default=str(_REPO_ROOT),
        help="source tree root to hash (default: repo root)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero on drift (flip on after the owner re-signs at the current VERSION)",
    )
    args = parser.parse_args()

    base_dir = Path(args.base_dir).resolve()
    manifest = _load_manifest(Path(args.manifest))

    committed: dict[str, str] = {
        str(e["path"]): str(e["sha256"]) for e in manifest.get("files", [])  # type: ignore[index,union-attr]
    }
    live: dict[str, str] = {
        path.relative_to(base_dir).as_posix(): _sha256_file(path)
        for path in _collect_files(base_dir)
    }

    committed_paths = set(committed)
    live_paths = set(live)
    added = sorted(live_paths - committed_paths)
    removed = sorted(committed_paths - live_paths)
    changed = sorted(
        p for p in (committed_paths & live_paths) if committed[p] != live[p]
    )

    manifest_version = str(manifest.get("version", "?"))
    source_version = _read_version(base_dir)
    drift = bool(added or removed or changed)

    if not drift:
        print(
            f"integrity manifest OK: {len(live)} files match "
            f"(manifest {manifest_version} == source {source_version})"
        )
        return 0

    print("=== integrity manifest DRIFT ===", file=sys.stderr)
    print(
        f"manifest version={manifest_version}  source VERSION={source_version}",
        file=sys.stderr,
    )
    for p in changed:
        print(f"  CHANGED  {p}", file=sys.stderr)
    for p in added:
        print(f"  ADDED    {p}  (in source, not in manifest)", file=sys.stderr)
    for p in removed:
        print(f"  REMOVED  {p}  (in manifest, not in source)", file=sys.stderr)
    print(
        f"drift: {len(changed)} changed, {len(added)} added, {len(removed)} removed",
        file=sys.stderr,
    )

    if args.strict:
        print(
            "FAIL (--strict): re-run the offline "
            "`scripts/gen_integrity_manifest.py` ceremony and commit the "
            "re-signed manifest at the current VERSION.",
            file=sys.stderr,
        )
        return 1

    print(
        "WARN: not failing the build (expected owner-offline-resign lag). "
        "Flip CI to --strict after the manifest is re-signed at the current VERSION.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
