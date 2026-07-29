"""
MCPIP — the release path is code, and untested code rots.

    ◐ "A build script nobody runs in CI is a build script that already broke."

``scripts/build_production_package.py`` had no test. It broke, and stayed broken
silently: it carried a rewrite pass that converted the private working tree into the
public one, every anchor of which pointed at prose the rewrite had itself already
replaced. The very first ``--check`` after publication died on
``.github/SUPPORT.md: anchor ... matched 0 lines``, and because nothing ran it, that
went unnoticed — taking ``PACKAGE_MANIFEST.json`` with it, since regenerating the
manifest is what the build does. The shipped per-file hashes could not be refreshed
by the tool that claims to produce them.

These tests hold the release path to the four guarantees its docstring advertises:

  * **allowlist, not denylist** — pinned against ``git ls-files``, so a new tracked
    file is either shipped or explicitly withheld, never silently dropped, and an
    untracked file never rides along
  * **byte-exact** — the package is a copy, so ``PACKAGE_MANIFEST.json`` describes
    this tree as well as the archive
  * **no internal reference** — a citation into withheld material stops the build
  * **determinism** — the same tree produces a byte-identical ZIP
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

_REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "scripts"))

from build_production_package import (  # noqa: E402
    GENERATED_ROOT_FILES,
    PRUNE_EXCEPTIONS,
    WITHHELD_DOCS,
    WITHHELD_EXCEPTIONS,
    WITHHELD_PATHS,
    BuildError,
    _is_pruned,
    _is_withheld,
    build,
    select_files,
    verify,
)


@pytest.fixture(scope="module")
def selected() -> list[str]:
    return select_files(_REPO)


@pytest.fixture(scope="module")
def staged(tmp_path_factory) -> tuple[pathlib.Path, list[str]]:
    """One real build, shared: staging 400+ files per test would be waste."""
    out = tmp_path_factory.mktemp("pkg")
    result = build(_REPO, out, check_only=False, keep_tree=True)
    assert result.stage is not None
    return result.stage, result.files


def _tracked() -> set[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=_REPO, capture_output=True, text=True, check=True
    )
    return set(out.stdout.split())


def _pruned_anywhere(rel: str) -> bool:
    """True if any path component would be pruned as a build artifact."""
    parts = rel.split("/")
    return any(
        _is_pruned("/".join(parts[: i + 1]), part, is_dir=(i < len(parts) - 1))
        for i, part in enumerate(parts)
    )


class TestTheBuildStillRuns:
    """The regression that motivated this file: `--check` did not complete."""

    def test_a_check_build_completes(self, selected) -> None:
        assert len(selected) > 300, "selection collapsed — the allowlist is not matching"

    def test_verification_passes_over_the_real_package(self, staged) -> None:
        """Warnings are tolerated; a BuildError is not. This raised before the fix."""
        stage, files = staged
        verify(stage, files)


class TestTheAllowlistAgreesWithTheRepository:
    """'Allowlist, not denylist' is only a guarantee if something checks it.

    The allowlist is a hand-maintained list of directories. Nothing connected it to
    what the repository actually tracks, so a new top-level directory of product code
    — ``load/``, the k6 suite behind the published throughput numbers — sat outside
    the package while the build reported success. The claim was true and the coverage
    was wrong, which is the failure mode an allowlist is supposed to prevent.
    """

    def test_every_tracked_product_file_is_selected(self, selected) -> None:
        missing = sorted(
            p
            for p in _tracked() - set(selected)
            if not _pruned_anywhere(p)
            and not _is_withheld(p)
            and p not in GENERATED_ROOT_FILES
        )
        assert not missing, (
            f"tracked files the package would silently omit: {missing} — add the "
            "directory to INCLUDE_DIRS/INCLUDE_ROOT_FILES, or name it in WITHHELD_PATHS"
        )

    def test_no_untracked_file_rides_along(self, selected) -> None:
        """The other direction: a scratch file in the tree must not become product."""
        extra = sorted(set(selected) - _tracked())
        assert not extra, f"untracked files would enter the distribution: {extra}"


class TestWhatMustNotShip:
    def test_private_key_material_is_pruned(self, staged) -> None:
        """The one prune whose failure is unrecoverable — a leaked key cannot be unshipped."""
        stage, files = staged
        keys = [
            f
            for f in files
            if f.endswith((".pem", ".key")) and not f.startswith(PRUNE_EXCEPTIONS)
        ]
        assert not keys, f"key material in the distribution: {keys}"

    def test_the_agent_context_lake_is_withheld_except_the_named_skill(self, selected) -> None:
        """The carve-out must be exactly as narrow as it claims."""
        dot_claude = [p for p in selected if p.startswith(".claude/")]
        assert dot_claude, "the load-test skill should ship"
        assert all(p.startswith(WITHHELD_EXCEPTIONS) for p in dot_claude), (
            f"material under .claude/ outside the named exception: {dot_claude}"
        )

    def test_a_citation_into_withheld_material_fails_the_build(self, tmp_path) -> None:
        """Not hypothetical: ~30 such links dangled in the first published tree.

        A reader following one lands on a 404 in a repository that is supposed to be
        self-contained, so this is a hard failure rather than a warning.
        """
        doc = tmp_path / "docs"
        doc.mkdir()
        (doc / "GUIDE.md").write_text(
            f"See [the plan](./{WITHHELD_DOCS[0]}) for details.\n", encoding="utf-8"
        )
        with pytest.raises(BuildError, match="references withheld material"):
            verify(tmp_path, ["docs/GUIDE.md"])

    def test_withheld_paths_are_still_named_in_the_output(self, staged) -> None:
        """The distribution states what it holds back rather than leaving an absence."""
        stage, _ = staged
        manifest = json.loads((stage / "PACKAGE_MANIFEST.json").read_text(encoding="utf-8"))
        assert set(manifest["excluded"]["paths"]) == set(WITHHELD_PATHS)
        assert manifest["excluded"]["documents"]


class TestTheManifestDescribesThisTree:
    def test_the_package_is_byte_exact_with_the_working_tree(self, staged) -> None:
        """Why the manifest can be trusted against a checkout.

        The build used to rewrite documentation as it copied, so a packaged file and
        its source differed and only the archive's hashes were meaningful. It copies
        now — which makes `sha256sum` against a clone a valid audit, and is the reason
        `--manifest` may hash the source directly.
        """
        stage, files = staged
        for rel in files:
            if rel in GENERATED_ROOT_FILES:
                continue
            assert (stage / rel).read_bytes() == (_REPO / rel).read_bytes(), (
                f"{rel} differs between the tree and the package"
            )

    def test_the_manifest_covers_every_file_but_itself(self, staged) -> None:
        stage, files = staged
        manifest = json.loads((stage / "PACKAGE_MANIFEST.json").read_text(encoding="utf-8"))
        listed = set(manifest["files"])
        assert listed == set(files) - set(GENERATED_ROOT_FILES)
        assert manifest["file_count"] == len(listed)

    def test_the_recorded_digests_are_correct(self, staged) -> None:
        stage, _ = staged
        manifest = json.loads((stage / "PACKAGE_MANIFEST.json").read_text(encoding="utf-8"))
        for rel, digest in manifest["files"].items():
            actual = hashlib.sha256((stage / rel).read_bytes()).hexdigest()
            assert actual == digest, f"{rel}: manifest digest does not match the packaged bytes"


class TestDeterminism:
    def test_the_same_tree_produces_a_byte_identical_archive(self, tmp_path) -> None:
        """An archive hash is only reviewable if it is reproducible.

        The manifest embeds the git commit, so this compares two builds of the same
        checkout rather than a stored constant — the property under test is that
        nothing else (traversal order, timestamps, compression) varies between runs.
        """
        digests = []
        for i in range(2):
            out = tmp_path / f"run{i}"
            out.mkdir()
            result = build(_REPO, out, check_only=False, keep_tree=False)
            assert result.archive is not None
            digests.append(hashlib.sha256(result.archive.read_bytes()).hexdigest())
        assert digests[0] == digests[1]
