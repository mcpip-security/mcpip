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
rather than assumed. The generator holds a second, deliberate copy of that scope (it
must stay importable on a bare interpreter for the dependency-free CI drift job);
``TestScopeIsSharedNotDuplicated`` below pins the two copies to each other so the
signed set and the required set cannot drift apart silently.
"""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
import os
import pathlib
import sys

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
_GENERATOR = _REPO / "scripts" / "gen_integrity_manifest.py"


def _load_generator():
    """Import the generator the way the dependency-free CI job does — by path.

    Not ``from scripts import ...``: the point of the exercise is that this module
    loads with nothing installed, so it is loaded in isolation rather than through
    any package ``__init__`` that might pull runtime deps in behind it.
    """
    spec = importlib.util.spec_from_file_location("_gen_integrity_manifest", _GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    """Two copies of the scope exist. This class is what keeps them one rule.

    The generator cannot import ``core.integrity``: ``core/__init__.py`` pulls in
    ``core.config`` and therefore pydantic, and the change-integrity CI job installs
    no dependencies — the drift gate would die with ``ModuleNotFoundError`` before it
    could report anything, which is a worse failure than a duplicated tuple. So the
    duplication is deliberate, and these tests are the seam that makes it safe.
    """

    def test_the_generator_scope_is_IDENTICAL_to_the_verifier_scope(self) -> None:
        """Divergence fails here rather than silently signing the wrong file set.

        Signing a narrower set than the boot gate requires covered turns every release
        into a boot refusal; signing a wider one hashes files the gate never checks.
        Either way the two must be the same rule, so they are compared as values —
        order included, since both feed a sorted, reproducible manifest.
        """
        gen = _load_generator()
        assert gen._PACKAGE_DIRS == MANIFEST_PACKAGE_DIRS, (
            "scripts/gen_integrity_manifest.py::_PACKAGE_DIRS has drifted from "
            "core.integrity.MANIFEST_PACKAGE_DIRS — update both together"
        )
        assert gen._EXTRA_FILES == MANIFEST_EXTRA_FILES, (
            "scripts/gen_integrity_manifest.py::_EXTRA_FILES has drifted from "
            "core.integrity.MANIFEST_EXTRA_FILES — update both together"
        )

    def test_the_generator_stays_importable_without_runtime_dependencies(self) -> None:
        """The reason the copy exists — regress this and the CI drift gate crashes.

        Anyone 'fixing' the duplication by importing ``core.integrity`` re-breaks the
        dependency-free job, so the constraint is asserted rather than left in a
        comment for the next reader to disbelieve.

        Checked against the AST rather than the text, because the comment explaining
        the rule names ``core.integrity`` and a substring search cannot tell a warning
        from a violation. Only imports that actually EXECUTE at module load count:
        ``cryptography`` is imported lazily inside the signing helpers and under
        ``if TYPE_CHECKING``, neither of which runs when the drift job imports this.
        """
        tree = ast.parse(_GENERATOR.read_text(encoding="utf-8"))
        roots: set[str] = set()
        for node in tree.body:  # module scope only — nested imports are lazy by design
            if isinstance(node, ast.Import):
                roots.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])

        non_stdlib = sorted(r for r in roots if r not in sys.stdlib_module_names)
        assert not non_stdlib, (
            f"the generator gained eagerly-imported non-stdlib dependencies {non_stdlib}; "
            "it must load on a bare interpreter for the dependency-free "
            "change-integrity CI job (import lazily inside a function instead)"
        )

    def test_both_copies_produce_the_same_file_set(self) -> None:
        """Belt and braces: equal tuples should mean equal output, so prove it.

        The generator walks with ``rglob`` and the verifier with its own discovery;
        equal inputs are only interesting if they land on the same files.
        """
        gen = _load_generator()
        generated = {p.relative_to(_REPO).as_posix() for p in gen._collect_files(_REPO)}
        assert generated == _in_scope_files(_REPO)

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
