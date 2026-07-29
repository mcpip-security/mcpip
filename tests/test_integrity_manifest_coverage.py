"""
MCPIP — a manifest that does not cover the code is not a manifest.

    ◐ "Verifying the files you listed proves nothing about the ones you didn't."

``verify_boot_integrity`` proved every manifest-LISTED file was unmodified. It said
nothing about a file the manifest omits — and an unlisted executable file is simply
unverified. So a manifest covering two thirds of the tree passed exactly like one
covering all of it, with no signal that the difference existed.

That was not hypothetical. The shipped ``release/integrity_manifest.json`` lags at
2.0.0 while ``VERSION`` is 3.0.0: it lists 51 files where 85 are in scope, leaving 34
unlisted — among them ``services/secret_vault.py``, ``services/revocation.py``,
``services/policy_engine.py`` and ``services/forensic_store.py``. Verified boot would
have reported success over a tree whose security core it never hashed.

The manifest's scope is deterministic — every ``*.py`` under
``MANIFEST_PACKAGE_DIRS`` plus ``MANIFEST_EXTRA_FILES`` — so coverage is checkable
rather than assumed, and the scope now lives in product code with the generator
importing it, so the signed set and the required set cannot drift apart.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib

os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/5")

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from core.integrity import (  # noqa: E402
    MANIFEST_EXTRA_FILES,
    MANIFEST_PACKAGE_DIRS,
    _in_scope_files,
    canonical_signed_bytes,
    sha256_stream,
    verify_boot_integrity,
)

_REPO = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def signer() -> tuple[Ed25519PrivateKey, bytes]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return key, pub


def _sign(doc: dict, key: Ed25519PrivateKey) -> dict:
    doc = {k: v for k, v in doc.items() if k != "signature"}
    doc["signature"] = base64.b64encode(key.sign(canonical_signed_bytes(doc))).decode()
    return doc


def _full_manifest(key: Ed25519PrivateKey) -> dict:
    files = [
        {"path": rel, "sha256": sha256_stream(_REPO / rel)}
        for rel in sorted(_in_scope_files(_REPO))
    ]
    return _sign({"schema": "mcpip-integrity-manifest/1", "version": "test", "files": files}, key)


def _write(tmp_path: pathlib.Path, doc: dict) -> pathlib.Path:
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return p


class TestScopeIsSharedNotDuplicated:
    """The generator and the verifier must not hold two copies of the same rule."""

    def test_generator_imports_the_scope_from_product_code(self) -> None:
        src = (_REPO / "scripts" / "gen_integrity_manifest.py").read_text(encoding="utf-8")
        assert "from core.integrity import" in src, (
            "the generator must import the scope from core.integrity; a second copy of "
            "the rule is how the signed set and the required set drift apart silently"
        )
        assert "MANIFEST_PACKAGE_DIRS" in src and "MANIFEST_EXTRA_FILES" in src

    def test_scope_covers_the_security_core(self) -> None:
        """A scope that quietly stopped covering these would defeat the whole control."""
        for pkg in ("app", "core", "auth", "audit", "bridge", "services", "obfuscator"):
            assert pkg in MANIFEST_PACKAGE_DIRS
        assert "interfaces.py" in MANIFEST_EXTRA_FILES

    def test_in_scope_discovery_finds_real_files(self) -> None:
        scope = _in_scope_files(_REPO)
        assert "services/secret_vault.py" in scope
        assert "app/main.py" in scope
        assert "interfaces.py" in scope
        assert not any("__pycache__" in p for p in scope)


class TestCoverageIsEnforced:
    def test_a_complete_manifest_boots(self, signer, tmp_path) -> None:
        key, pub = signer
        verify_boot_integrity(_write(tmp_path, _full_manifest(key)), pub, _REPO)

    def test_a_validly_signed_but_INCOMPLETE_manifest_is_refused(self, signer, tmp_path) -> None:
        """The exact shape the shipped 2.0.0 manifest has.

        The signature verifies. Every listed file hashes correctly. It simply omits
        code — and before the coverage check that booted clean, leaving the omitted
        files tamperable behind a control reporting success.
        """
        key, pub = signer
        full = _full_manifest(key)
        trimmed = dict(full)
        trimmed["files"] = [e for e in full["files"] if not e["path"].startswith("services/")]
        dropped = len(full["files"]) - len(trimmed["files"])
        assert dropped > 10, "fixture is not exercising a meaningful omission"

        with pytest.raises(RuntimeError, match="integrity verification failed"):
            verify_boot_integrity(_write(tmp_path, _sign(trimmed, key)), pub, _REPO)

    def test_omitting_even_one_file_is_refused(self, signer, tmp_path) -> None:
        """No tolerance threshold: one unverified source file is one too many."""
        key, pub = signer
        full = _full_manifest(key)
        trimmed = dict(full)
        trimmed["files"] = [e for e in full["files"] if e["path"] != "services/secret_vault.py"]
        with pytest.raises(RuntimeError, match="integrity verification failed"):
            verify_boot_integrity(_write(tmp_path, _sign(trimmed, key)), pub, _REPO)

    def test_tampering_a_listed_file_is_still_refused(self, signer, tmp_path) -> None:
        """The original guarantee must survive the new one."""
        key, pub = signer
        full = _full_manifest(key)
        for entry in full["files"]:
            if entry["path"] == "services/secret_vault.py":
                entry["sha256"] = "0" * 64
        with pytest.raises(RuntimeError, match="integrity verification failed"):
            verify_boot_integrity(_write(tmp_path, _sign(full, key)), pub, _REPO)

    def test_an_unsigned_edit_is_refused(self, signer, tmp_path) -> None:
        """Coverage must not become a way around the signature."""
        key, pub = signer
        full = _full_manifest(key)
        full["files"] = [e for e in full["files"] if not e["path"].startswith("services/")]
        # NOT re-signed — the signature no longer matches the document.
        with pytest.raises(RuntimeError, match="integrity verification failed"):
            verify_boot_integrity(_write(tmp_path, full), pub, _REPO)
