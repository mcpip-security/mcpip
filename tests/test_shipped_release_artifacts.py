"""
MCPIP — the release artifacts that actually shipped, not synthetic ones.

    ◐ "`test_release_tooling.py` proves the signer and the verifier agree. It signs a
       fixture with a key it just generated. Nothing in it has ever opened
       `release/manifest.json`."

That gap is why the shipped set could drift without a red test. This file loads the
committed artifacts and holds them to what the documentation claims about them.

Two states are legitimate here and the difference matters:

  * **Lag.** `release/` sits at the last owner-signed version while `VERSION` moves
    ahead. `docs/operate/RELEASE.md` §0 documents this: the manifests are produced on
    an air-gapped signer, so they reconcile only after the owner's offline cut, and
    the honest boundary is to leave them stale rather than hand-fake a signature.
    Asserted below as a *known* condition — not tolerated silently.
  * **Breakage.** The signature does not verify, or an artifact that should be
    committed is gone. Neither is documented and neither is acceptable.

The SBOM tests are here rather than beside the generator because the finding they
encode is about a *published* file: the shipped 2.0.0 SBOM inventories a development
virtualenv and carries a maintainer's home directory inside a signed release artifact.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sys

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

_REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "scripts"))

from gen_release_keys import rotate  # noqa: E402
from sbom_finalize import find_leaks, finalize, root_component  # noqa: E402

_RELEASE = _REPO / "release"
_MANIFEST = _RELEASE / "manifest.json"
_RELEASE_KEY = _RELEASE / "keys" / "release_root_ed25519.pub.pem"

#: Build outputs are not committed (`dist/` is .gitignore'd), so the wheel and sdist
#: the manifest lists are release ASSETS: present when an operator downloads them into
#: place, absent in a bare checkout. Any other missing artifact is a real hole.
_ASSET_PREFIX = "dist/"


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


class TestTheShippedManifestIsIntact:
    def test_the_signature_verifies_with_the_shipped_public_key(self, manifest) -> None:
        """The whole chain of custody rests on this one check actually passing.

        The repository ships the release-root public key so anyone can run it. Nothing
        ran it — so a corrupted or truncated `manifest.json` would have been noticed by
        an evaluator before it was noticed here.
        """
        unsigned = {k: v for k, v in manifest.items() if k != "signature"}
        payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        public_key = load_pem_public_key(_RELEASE_KEY.read_bytes())
        try:
            public_key.verify(base64.b64decode(manifest["signature"]), payload)
        except InvalidSignature:  # pragma: no cover - the point of the test
            pytest.fail("release/manifest.json does not verify with the shipped key")

    def test_the_signing_key_id_is_the_active_release_root(self, manifest) -> None:
        rotation = json.loads((_RELEASE / "keys" / "rotation.json").read_text(encoding="utf-8"))
        active = {
            k["key_id"]
            for k in rotation["keys"]
            if k["role"] == "release-root" and k["status"] == "active"
        }
        assert manifest["signing_key_id"] in active, (
            "the manifest is signed by a key the rotation record does not list as the "
            "active release root"
        )

    def test_every_committed_artifact_hashes_correctly(self, manifest) -> None:
        for entry in manifest["artifacts"]:
            path = _REPO / entry["path"]
            if not path.exists():
                continue  # covered by the asset test below
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            assert digest == entry["sha256"], f"{entry['path']} does not match the signed digest"

    def test_anything_absent_is_a_release_asset_and_nothing_else(self, manifest) -> None:
        """`mcpip verify --base-dir .` exits 2 in a checkout. That must be explicable.

        It is: `dist/` is .gitignore'd, so the wheel and sdist are downloaded, not
        committed, and the tool fails closed on their absence — correct behaviour, and
        documented in README and OPERATIONS. A *non*-`dist/` artifact going missing has
        no such explanation and is a hole in the signed set.
        """
        unexplained = [
            entry["path"]
            for entry in manifest["artifacts"]
            if not (_REPO / entry["path"]).exists()
            and not entry["path"].startswith(_ASSET_PREFIX)
        ]
        assert not unexplained, (
            f"signed artifacts missing with no release-asset explanation: {unexplained}"
        )

    def test_the_version_lag_is_the_documented_condition(self, manifest) -> None:
        """Stale is allowed. Stale and undocumented is not.

        If `release/` ever catches up to `VERSION`, this test stops requiring the lag
        paragraph — the assertion is that the tree and the documentation agree, in
        whichever state the tree is in.
        """
        version = (_REPO / "VERSION").read_text(encoding="utf-8").strip()
        if manifest["version"] == version:
            return
        release_doc = (_REPO / "docs" / "operate" / "RELEASE.md").read_text(encoding="utf-8")
        assert "legitimately LAG" in release_doc, (
            f"release/ is at {manifest['version']} while VERSION is {version}, and "
            "docs/operate/RELEASE.md no longer explains why"
        )
        assert f"(`{manifest['version']}`)" in release_doc, (
            "RELEASE.md names a different last-signed version than the manifest carries"
        )


class TestTheSBOMGeneratorRefusesToLeak:
    """The shipped 2.0.0 SBOM is the fixture. It is not hypothetical.

    It was generated from the development virtualenv, which contained an editable
    install of the optional Rust accelerator, so it carries

        file:///Users/yuvalkatz/mcpip-genesis/rust/mcpip_fastwalk

    — a maintainer's home directory and the project's pre-publication name, inside an
    artifact listed in the signed release manifest. `scripts/build_sbom.sh` now
    inventories the runtime closure (requirements.txt as the Dockerfile resolves it),
    which removes the cause; `sbom_finalize.py` refuses the symptom, so a future
    environment change cannot quietly reintroduce it.
    """

    def test_the_finalizer_catches_the_leak_that_shipped(self) -> None:
        shipped = json.loads(
            (_RELEASE / "sbom" / "mcpip-2.0.0.cdx.json").read_text(encoding="utf-8")
        )
        leaks = find_leaks(shipped)
        assert leaks, (
            "the 2.0.0 SBOM no longer contains the known local-path leak — if it was "
            "regenerated, drop this test; if the detector stopped matching, fix it"
        )

    @pytest.mark.parametrize(
        "value",
        [
            "file:///Users/someone/project",
            "/home/builder/src/pkg",
            "/root/.cache/pip/wheels",
            "file:///C:/Users/dev/mcpip",
        ],
    )
    def test_local_paths_are_detected_wherever_they_hide(self, value: str) -> None:
        assert find_leaks({"components": [{"externalReferences": [{"url": value}]}]})

    @pytest.mark.parametrize(
        "value",
        ["pkg:pypi/fastapi@0.115.0", "https://github.com/mcpip-security/mcpip", "MIT"],
    )
    def test_legitimate_references_are_not_flagged(self, value: str) -> None:
        assert not find_leaks({"components": [{"externalReferences": [{"url": value}]}]})

    def test_the_root_component_identifies_the_release(self) -> None:
        """Without it the document says what is installed, never what it is installed for.

        No `metadata.component` means no NTIA minimum elements, and nothing for
        grype/trivy/Dependency-Track to attribute a finding to.
        """
        document = finalize({"components": []}, "9.9.9")
        component = document["metadata"]["component"]
        assert component == root_component("9.9.9")
        assert component["name"] == "mcpip"
        assert component["version"] == "9.9.9"
        assert component["purl"] == "pkg:pypi/mcpip@9.9.9"
        assert component["licenses"][0]["license"]["id"] == "BUSL-1.1"

    def test_finalizing_preserves_the_inventory(self) -> None:
        """Stamping the root must not disturb what the generator found."""
        components = [{"name": "fastapi", "version": "0.115.0"}]
        document = finalize({"components": list(components), "specVersion": "1.5"}, "3.0.0")
        assert document["components"] == components
        assert document["specVersion"] == "1.5"


class TestRotationActuallyRotates:
    """`rotation.json` is cited as the evidence for control T12. It never rotated.

    Each run of `gen_release_keys.py` wrote a fresh document with every key
    `status: active`, `supersedes: null` — so replacing a root ERASED the record of
    the key that signed every earlier release. An auditor verifying a 2.0.0 signature
    would find it checks out against a key the current manifest does not mention, with
    nothing to distinguish a properly retired root from a forged one.
    """

    _NOW = "2026-06-01T00:00:00Z"

    def test_a_first_ceremony_records_an_active_key_with_no_predecessor(self) -> None:
        keys, superseded = rotate(None, "release-root", "ed25519:aaa", "k.pub.pem", self._NOW)
        assert superseded is None
        assert keys == [
            {
                "key_id": "ed25519:aaa",
                "role": "release-root",
                "public_key_path": "k.pub.pem",
                "status": "active",
                "not_after": None,
                "supersedes": None,
            }
        ]

    def test_rotating_retires_the_predecessor_instead_of_dropping_it(self) -> None:
        first, _ = rotate(None, "release-root", "ed25519:aaa", "k.pub.pem", "2026-01-01T00:00:00Z")
        second, superseded = rotate(
            {"keys": first}, "release-root", "ed25519:bbb", "k.pub.pem", self._NOW
        )
        assert superseded == "ed25519:aaa"
        retired = [k for k in second if k["status"] == "retired"]
        active = [k for k in second if k["status"] == "active"]
        assert [k["key_id"] for k in retired] == ["ed25519:aaa"]
        assert retired[0]["not_after"] == self._NOW, "a retired key must say when"
        assert active[0]["supersedes"] == "ed25519:aaa", "the chain must be walkable"

    def test_history_survives_repeated_rotations(self) -> None:
        """Two rotations, three keys. Nothing may fall off the back."""
        keys: list[dict] = []
        for index, key_id in enumerate(("ed25519:a", "ed25519:b", "ed25519:c")):
            keys, _ = rotate({"keys": keys}, "release-root", key_id, "k.pub.pem", f"2026-0{index + 1}-01T00:00:00Z")
        assert [k["key_id"] for k in keys] == ["ed25519:a", "ed25519:b", "ed25519:c"]
        assert [k["status"] for k in keys] == ["retired", "retired", "active"]

    def test_regenerating_the_same_key_is_not_a_rotation(self) -> None:
        """Idempotence: re-running the ceremony must not retire a key in favour of itself."""
        first, _ = rotate(None, "license-root", "ed25519:aaa", "k.pub.pem", self._NOW)
        again, superseded = rotate(
            {"keys": first}, "license-root", "ed25519:aaa", "k.pub.pem", "2026-09-01T00:00:00Z"
        )
        assert superseded is None
        assert again == first

    def test_rotating_one_role_leaves_the_other_untouched(self) -> None:
        keys, _ = rotate(None, "release-root", "ed25519:rel", "r.pub.pem", self._NOW)
        keys, _ = rotate({"keys": keys}, "license-root", "ed25519:lic", "l.pub.pem", self._NOW)
        keys, superseded = rotate(
            {"keys": keys}, "release-root", "ed25519:rel2", "r.pub.pem", "2026-12-01T00:00:00Z"
        )
        assert superseded == "ed25519:rel"
        licenses = [k for k in keys if k["role"] == "license-root"]
        assert len(licenses) == 1 and licenses[0]["status"] == "active"

    def test_the_shipped_manifest_has_exactly_one_active_key_per_role(self) -> None:
        """Two active release roots would make 'which key signs a release' ambiguous."""
        rotation = json.loads((_RELEASE / "keys" / "rotation.json").read_text(encoding="utf-8"))
        for role in ("release-root", "license-root"):
            active = [
                k for k in rotation["keys"] if k["role"] == role and k["status"] == "active"
            ]
            assert len(active) == 1, f"{role}: expected one active key, found {len(active)}"
            assert (_REPO / active[0]["public_key_path"]).is_file(), (
                f"{role}: the active key's public PEM is not in the distribution"
            )
