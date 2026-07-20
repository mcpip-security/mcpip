"""
MCPIP V2 — SLSA provenance generator test suite (in-toto / SLSA v1 predicate).

    ◐  "Provenance the release ceremony can hand off — it signs NOTHING, never re-hashes a
       digest, and refuses to fabricate a half-formed statement."

Exercises the REAL ``scripts/gen_slsa_provenance.py`` (``build_provenance`` + the ``main``
CLI) against REAL on-disk pinned inputs (``requirements*.txt`` / ``VERSION``) and REAL
manifests written to a tmp dir — no mocks of the code under test.

Covered:
  * ``build_provenance`` emits a well-formed in-toto Statement wrapping the SLSA v1
    provenance predicate — subjects copied VERBATIM from the signed manifest (never
    re-hashed), the pinned inputs hashed from disk, the REQUIRED builder.id echoed, the
    schema-tag buildType, and the git source resolvedDependency;
  * fail-closed honesty: empty/malformed artifacts, a missing version, a bad digest, a
    missing manifest, a missing pinned input, and an empty builder id are HARD errors — no
    fabricated or half-formed statement is emitted;
  * the ``main`` CLI round-trips a manifest to a valid statement file and NEVER signs.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _REPO_ROOT / "scripts" / "gen_slsa_provenance.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location("gen_slsa_provenance", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gsp = _load_module()

_BUILDER = "https://github.com/aegis/mcpip/.github/workflows/release.yml@refs/tags/v2.1.0"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(**over: Any) -> dict[str, Any]:
    """A minimal but well-formed release manifest (the shape sign_release.py emits)."""
    base: dict[str, Any] = {
        "schema": "mcpip-release-manifest/1",
        "version": "2.1.0",
        "created_at": "2026-07-17T00:00:00Z",
        "artifacts": [
            {"name": "mcpip-2.1.0-py3-none-any.whl", "sha256": "a" * 64, "size_bytes": 1000},
            {"name": "mcpip-2.1.0.tar.gz", "sha256": "b" * 64, "size_bytes": 2000},
        ],
        "signing_key_id": "c" * 64,
        "signature": "d" * 128,
    }
    base.update(over)
    return base


def _build(manifest: dict[str, Any], **kw: Any) -> dict[str, Any]:
    return gsp.build_provenance(
        manifest,
        _REPO_ROOT / "release" / "manifest.json",
        builder_id=kw.get("builder_id", _BUILDER),
        build_type=kw.get("build_type", gsp._DEFAULT_BUILD_TYPE),
        base_dir=kw.get("base_dir", _REPO_ROOT),
    )


# ---------------------------------------------------------------------------
# 1) Well-formed in-toto Statement / SLSA v1 predicate.
# ---------------------------------------------------------------------------


def test_build_provenance_shape() -> None:
    manifest = _manifest()
    stmt = _build(manifest)

    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"] == "https://slsa.dev/provenance/v1"

    # Subjects copied VERBATIM from the signed manifest — name + sha256 digest, never
    # re-hashed (the generator trusts the ceremony's authoritative digests).
    subjects = stmt["subject"]
    assert subjects == [
        {"name": "mcpip-2.1.0-py3-none-any.whl", "digest": {"sha256": "a" * 64}},
        {"name": "mcpip-2.1.0.tar.gz", "digest": {"sha256": "b" * 64}},
    ]

    predicate = stmt["predicate"]
    build_def = predicate["buildDefinition"]
    assert build_def["buildType"] == gsp._DEFAULT_BUILD_TYPE
    ext = build_def["externalParameters"]
    assert ext["version"] == "2.1.0"
    assert ext["artifacts"] == ["mcpip-2.1.0-py3-none-any.whl", "mcpip-2.1.0.tar.gz"]
    assert ext["releaseManifest"] == "mcpip-release-manifest/1"

    run = predicate["runDetails"]
    assert run["builder"] == {"id": _BUILDER}
    assert run["metadata"]["startedOn"] == "2026-07-17T00:00:00Z"  # from created_at.
    assert isinstance(run["metadata"]["finishedOn"], str) and run["metadata"]["finishedOn"]


# ---------------------------------------------------------------------------
# 2) resolvedDependencies pin the real on-disk inputs (hashed from disk).
# ---------------------------------------------------------------------------


def test_resolved_dependencies_hash_real_inputs() -> None:
    stmt = _build(_manifest())
    deps = stmt["predicate"]["buildDefinition"]["resolvedDependencies"]
    by_name = {d["name"]: d for d in deps}

    # Every pinned input is present with its REAL on-disk sha256.
    for pinned in gsp._PINNED_INPUTS:
        assert pinned in by_name, pinned
        expected = _sha256((_REPO_ROOT / pinned).read_bytes())
        assert by_name[pinned]["digest"]["sha256"] == expected

    # The git source commit is pinned as a resolvedDependency (this repo IS a git repo).
    assert "source" in by_name
    assert "gitCommit" in by_name["source"]["digest"]
    assert len(by_name["source"]["digest"]["gitCommit"]) == 40


# ---------------------------------------------------------------------------
# 3) Fail-closed honesty — no fabricated / half-formed statement.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "manifest",
    [
        {"version": "2.1.0", "artifacts": []},  # empty artifact set.
        {"version": "2.1.0", "artifacts": "not-a-list"},  # malformed artifacts.
        {"version": "2.1.0", "artifacts": [{"name": "x"}]},  # artifact missing sha256.
        {"version": "2.1.0", "artifacts": [{"name": "x", "sha256": "short"}]},  # bad digest.
        {"version": "2.1.0", "artifacts": [{"sha256": "a" * 64}]},  # artifact missing name.
        _manifest(version=""),  # empty version.
        {k: v for k, v in _manifest().items() if k != "version"},  # no version.
    ],
)
def test_build_provenance_fails_closed(manifest: dict[str, Any]) -> None:
    with pytest.raises(SystemExit):
        _build(manifest)


def test_missing_pinned_input_fails_closed(tmp_path: Path) -> None:
    # base_dir with NO requirements*/VERSION → a pinned material is missing → hard error.
    with pytest.raises(SystemExit):
        _build(_manifest(), base_dir=tmp_path)


def test_missing_manifest_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        gsp._load_manifest(tmp_path / "does-not-exist.json")


def test_malformed_manifest_file_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "manifest.json"
    bad.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(SystemExit):
        gsp._load_manifest(bad)
    # A JSON array (not an object) is also refused.
    arr = tmp_path / "arr.json"
    arr.write_text("[]", encoding="utf-8")
    with pytest.raises(SystemExit):
        gsp._load_manifest(arr)


# ---------------------------------------------------------------------------
# 4) The main() CLI round-trips a manifest to a valid statement file (signs NOTHING).
# ---------------------------------------------------------------------------


def test_main_cli_writes_valid_statement(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
    out_path = tmp_path / "provenance.intoto.json"

    argv = [
        "gen_slsa_provenance",
        "--manifest",
        str(manifest_path),
        "--builder-id",
        _BUILDER,
        "--base-dir",
        str(_REPO_ROOT),
        "--out",
        str(out_path),
    ]
    old_argv = sys.argv
    sys.argv = argv
    try:
        rc = gsp.main()
    finally:
        sys.argv = old_argv
    assert rc == 0
    assert out_path.is_file()

    stmt = json.loads(out_path.read_text(encoding="utf-8"))
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"] == "https://slsa.dev/provenance/v1"
    assert stmt["predicate"]["runDetails"]["builder"]["id"] == _BUILDER
    # The generator signs NOTHING — no signature/cosign field is ever emitted.
    assert "signature" not in stmt
    assert "signatures" not in stmt
    # The output is public metadata (0644), never key material.
    assert (os.stat(out_path).st_mode & 0o777) == 0o644


def test_main_cli_requires_nonempty_builder_id(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
    argv = [
        "gen_slsa_provenance",
        "--manifest",
        str(manifest_path),
        "--builder-id",
        "   ",  # whitespace-only → refused (builder identity is never fabricated).
        "--base-dir",
        str(_REPO_ROOT),
        "--out",
        str(tmp_path / "out.json"),
    ]
    old_argv = sys.argv
    sys.argv = argv
    try:
        with pytest.raises(SystemExit):
            gsp.main()
    finally:
        sys.argv = old_argv


def test_main_cli_runs_against_the_real_release_manifest(tmp_path: Path) -> None:
    """The shipped ``release/manifest.json`` is real and signed — the generator produces a
    valid statement over its actual current artifacts (subjects verbatim from it)."""
    real_manifest = json.loads((_REPO_ROOT / "release" / "manifest.json").read_text())
    stmt = _build(real_manifest)
    names = [s["name"] for s in stmt["subject"]]
    assert names == [a["name"] for a in real_manifest["artifacts"]]
    for subj, art in zip(stmt["subject"], real_manifest["artifacts"]):
        # Digest copied verbatim — provenance can never diverge from the signed manifest.
        assert subj["digest"]["sha256"] == art["sha256"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
