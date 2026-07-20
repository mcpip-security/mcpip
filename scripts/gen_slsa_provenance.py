#!/usr/bin/env python3
"""
MCPIP SLSA provenance generator — an in-toto / SLSA v1 provenance predicate
over the artifacts the release manifest already pins.

Emits ONE in-toto Statement (``https://in-toto.io/Statement/v1``) whose
``predicateType`` is ``https://slsa.dev/provenance/v1``:

  * ``subject``  — the release artifacts (name + SHA-256 digest) taken VERBATIM
    from the signed ``release/manifest.json`` produced by ``sign_release.py``.
    The digests are the authoritative ones already computed and signed by the
    release ceremony; this generator never re-hashes or re-derives them, so the
    provenance can never disagree with the manifest.
  * ``predicate.buildDefinition`` — the ``buildType`` schema tag, the external
    parameters (version + requested artifact set), and ``resolvedDependencies``:
    the PINNED inputs (git source commit when available, ``requirements*.txt``,
    ``VERSION``) hashed from disk.
  * ``predicate.runDetails`` — the ``builder.id`` (the OWNER's build-platform
    identity — a REQUIRED argument, never fabricated), the invocation metadata,
    and the ceremony byproducts (the signed release + integrity manifests).

This tool signs NOTHING. SLSA/in-toto provenance is attested by the OWNER's
offline cosign key as a separate, deliberate step (see ``RELEASE.md`` §"cosign
attestation") — exactly like the release-root signing boundary. It never
uploads, never pulls, never mutates a running gateway.

Honest fail-closed: an absent/unreadable manifest, an empty subject set, or a
missing pinned input is a hard error — the generator refuses to emit a
half-formed or fabricated statement rather than invent a value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHUNK = 1024 * 1024

# in-toto / SLSA type URIs (v1.0).
_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

# The default buildType SCHEMA tag for the MCPIP offline release ceremony. It
# names the *shape* of this build process (the ordered ceremony in RELEASE.md),
# NOT a signing identity or an authenticity claim — the owner may override it to
# a URI they publish. The BUILDER IDENTITY (builder.id) is a separate, REQUIRED
# argument and is deliberately never defaulted.
_DEFAULT_BUILD_TYPE = "https://mcpip.dev/slsa/buildtypes/release-ceremony/v1"

# Pinned inputs hashed from disk as resolvedDependencies (materials). Each is a
# real, committed file in the source tree; a missing one fails closed.
_PINNED_INPUTS = ("requirements.txt", "requirements-dev.txt", "VERSION")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def _load_manifest(path: Path) -> dict[str, object]:
    if not path.is_file():
        _fail(f"missing release manifest: {path}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _fail(f"unreadable release manifest {path}: {exc}")
    if not isinstance(manifest, dict):
        _fail(f"malformed release manifest: {path}")
    return manifest


def _subjects_from_manifest(manifest: dict[str, object]) -> list[dict[str, object]]:
    """Project the manifest's signed artifacts to in-toto subjects (name+sha256).

    The digests are copied verbatim from the manifest — the release ceremony's
    authoritative, signed values — so provenance can never diverge from the
    signed release. An empty or malformed artifact list fails closed.
    """
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        _fail("release manifest has no artifacts to attest")
    subjects: list[dict[str, object]] = []
    for entry in artifacts:
        if not isinstance(entry, dict):
            _fail("malformed artifact entry in release manifest")
        name = entry.get("name")
        sha256 = entry.get("sha256")
        if not isinstance(name, str) or not name:
            _fail("artifact entry missing name")
        if not isinstance(sha256, str) or len(sha256) != 64:
            _fail(f"artifact {name!r} has no valid sha256 digest")
        subjects.append({"name": name, "digest": {"sha256": sha256}})
    return subjects


def _git(*args: str) -> Optional[str]:
    """Best-effort ``git`` read; None when git/repo is unavailable (honest)."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=_REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip()
    return value or None


def _source_dependency() -> Optional[dict[str, object]]:
    """The git source commit as a resolvedDependency, or None if unavailable.

    Absent git ⇒ the material is simply omitted — never a placeholder commit.
    """
    commit = _git("rev-parse", "HEAD")
    if commit is None:
        return None
    remote = _git("config", "--get", "remote.origin.url")
    dependency: dict[str, object] = {
        "name": "source",
        "digest": {"gitCommit": commit},
    }
    if remote is not None:
        dependency["uri"] = f"git+{remote}@{commit}"
    return dependency


def _pinned_dependencies(base_dir: Path) -> list[dict[str, object]]:
    deps: list[dict[str, object]] = []
    source = _source_dependency()
    if source is not None:
        deps.append(source)
    for name in _PINNED_INPUTS:
        path = base_dir / name
        if not path.is_file():
            _fail(f"missing pinned input: {path}")
        deps.append({"name": name, "digest": {"sha256": _sha256_file(path)}})
    return deps


def _byproduct(base_dir: Path, rel: str) -> Optional[dict[str, object]]:
    """A ceremony byproduct (signed manifest) as a digest reference, or None.

    A byproduct that has not been produced yet is omitted — not fabricated.
    """
    path = base_dir / rel
    if not path.is_file():
        return None
    return {"name": rel, "digest": {"sha256": _sha256_file(path)}}


def _byproducts(base_dir: Path, manifest_path: Path) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    manifest_rel = (
        manifest_path.resolve().relative_to(base_dir).as_posix()
        if manifest_path.resolve().is_relative_to(base_dir)
        else manifest_path.name
    )
    manifest_ref = _byproduct(base_dir, manifest_rel)
    if manifest_ref is not None:
        items.append(manifest_ref)
    integrity = _byproduct(base_dir, "release/integrity_manifest.json")
    if integrity is not None:
        items.append(integrity)
    return items


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".provenance-")
    try:
        os.write(fd, text.encode("utf-8"))
        os.fchmod(fd, 0o644)  # committed, public metadata — not key material.
    finally:
        os.close(fd)
    os.replace(tmp_name, path)


def build_provenance(
    manifest: dict[str, object],
    manifest_path: Path,
    *,
    builder_id: str,
    build_type: str,
    base_dir: Path,
) -> dict[str, object]:
    """Assemble the in-toto Statement wrapping the SLSA v1 provenance predicate."""
    subjects = _subjects_from_manifest(manifest)

    version = manifest.get("version")
    if not isinstance(version, str) or not version:
        _fail("release manifest has no version")
    created_at = manifest.get("created_at")
    started_on = created_at if isinstance(created_at, str) and created_at else _utc_now_iso()
    finished_on = _utc_now_iso()

    invocation_id = _git("rev-parse", "HEAD") or f"{version}@{started_on}"

    predicate: dict[str, object] = {
        "buildDefinition": {
            "buildType": build_type,
            "externalParameters": {
                "version": version,
                "artifacts": [subject["name"] for subject in subjects],
                "releaseManifest": manifest.get("schema", "mcpip-release-manifest/1"),
            },
            "internalParameters": {},
            "resolvedDependencies": _pinned_dependencies(base_dir),
        },
        "runDetails": {
            "builder": {"id": builder_id},
            "metadata": {
                "invocationId": invocation_id,
                "startedOn": started_on,
                "finishedOn": finished_on,
            },
            "byproducts": _byproducts(base_dir, manifest_path),
        },
    }

    return {
        "_type": _STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": _PREDICATE_TYPE,
        "predicate": predicate,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate an in-toto / SLSA v1 provenance statement for an MCPIP release"
    )
    parser.add_argument(
        "--manifest",
        default=str(_REPO_ROOT / "release" / "manifest.json"),
        help="signed release manifest (source of the attested subjects; default: release/manifest.json)",
    )
    parser.add_argument(
        "--builder-id",
        required=True,
        help=(
            "SLSA builder.id — the OWNER's build-platform identity URI "
            "(e.g. https://github.com/<org>/<repo>/.github/workflows/release.yml@refs/tags/v<x> "
            "or an offline-signer id). REQUIRED — never fabricated."
        ),
    )
    parser.add_argument(
        "--build-type",
        default=_DEFAULT_BUILD_TYPE,
        help=f"SLSA buildType schema tag (default: {_DEFAULT_BUILD_TYPE})",
    )
    parser.add_argument(
        "--base-dir",
        default=str(_REPO_ROOT),
        help="repo root for hashing pinned inputs + byproducts (default: repo root)",
    )
    parser.add_argument(
        "--out",
        default=str(_REPO_ROOT / "release" / "provenance.intoto.json"),
        help="output path (default: release/provenance.intoto.json)",
    )
    args = parser.parse_args()

    if not args.builder_id.strip():
        _fail("--builder-id must be a non-empty build-platform identity")

    base_dir = Path(args.base_dir).resolve()
    manifest_path = Path(args.manifest)
    manifest = _load_manifest(manifest_path)

    statement = build_provenance(
        manifest,
        manifest_path,
        builder_id=args.builder_id,
        build_type=args.build_type,
        base_dir=base_dir,
    )

    out_path = Path(args.out)
    _atomic_write_text(out_path, json.dumps(statement, indent=2) + "\n")
    subjects = statement["subject"]
    assert isinstance(subjects, list)
    print(f"SLSA provenance: {len(subjects)} subject(s) -> {out_path}")
    print(f"  buildType: {args.build_type}")
    print(f"  builder:   {args.builder_id}")
    print("  NEXT (owner, offline): cosign attest the artifacts with this predicate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
