"""
MCPIP V2 — Core: startup integrity self-check (verified boot, fail-closed).

    ◐ "Authorize every AI action before execution."

At boot the gateway proves that every source file it is about to execute is
byte-identical to the set the release engineer signed with the OFFLINE Ed25519
release-root key. The check is READ-ONLY and terminal:

  * There is NO remediation, self-heal, or auto-update path. On any mismatch the
    process raises before a socket is ever bound and exits nonzero; the OPERATOR
    redeploys a verified immutable image through change control. (If update
    automation is ever wanted, the documented path is TUF/Sigstore — future work,
    never in-binary.)
  * The raised error is deliberately OPAQUE (``integrity verification failed`` —
    no filename, hash, or path). The specific cause is recorded ONLY on the
    structured ``mcpip.boot`` logger at CRITICAL before raising, so operators can
    diagnose from logs while nothing actionable leaks through crash loops or
    orchestrator status surfaces.

Signing rule (normative, shared with the release tooling and ``mcpip verify``):
the signed message is the manifest JSON object WITHOUT its ``signature`` key,
serialized ``json.dumps(obj, sort_keys=True, separators=(",", ":"))`` UTF-8; the
signature is a raw 64-byte Ed25519 signature over those bytes, base64-encoded.
This module implements the rule LOCALLY — it must never import ``mcpip_verify``
so the gateway stays importable without the release-tooling package.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

_OPAQUE_ERROR = "integrity verification failed"
_MANIFEST_SCHEMA = "mcpip-integrity-manifest/1"
_CHUNK_BYTES = 1024 * 1024

_log = logging.getLogger("mcpip.boot")


def _canonical_json_bytes(
    document: dict[str, Any], *, exclude: frozenset[str]
) -> bytes:
    """
    The one canonicalization rule shared by every signed/hashed JSON document here:
    drop the ``exclude`` keys, then ``json.dumps(..., sort_keys=True,
    separators=(",", ":"))`` encoded UTF-8. Keeping the sort/compact discipline in a
    single place means the signer, the ``mcpip verify`` CLI, the boot check, the
    license verifier, and the community-extension manifest digest can never drift.
    """
    trimmed = {key: value for key, value in document.items() if key not in exclude}
    return json.dumps(trimmed, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_signed_bytes(document: dict[str, Any]) -> bytes:
    """
    Return the canonical byte serialization of ``document`` for Ed25519 signing.

    Normative rule (§2 of the release spec): drop the ``signature`` key, then
    ``json.dumps(..., sort_keys=True, separators=(",", ":"))`` encoded UTF-8.
    Used identically by the offline signer, the ``mcpip verify`` CLI, this boot
    check, and the license verifier.
    """
    return _canonical_json_bytes(document, exclude=frozenset({"signature"}))


def canonical_manifest_bytes(document: dict[str, Any]) -> bytes:
    """
    Canonical bytes for a community-extension manifest's ``sha256`` self-pin.

    SAME sort/compact/UTF-8 discipline as ``canonical_signed_bytes`` but drops BOTH
    the ``sha256`` self-digest key AND the reserved ``signature`` key, so the digest
    is taken over exactly the substantive manifest fields. Reserving ``signature``
    now (even though Phase 1 does not verify a detached signature) keeps the Phase 3
    cross-org ``authorship_sig``/``approval_sig`` extension purely additive — the
    digested bytes will not shift when a signature key is later added.

    This is deliberately the integrity-manifest hash FAMILY, kept OFF the payload-lock
    path: it is NOT ``interfaces.canonical_json``, so the byte-identity contract that
    binds ``canonical_json`` / ``enforce_argument_safety`` / the PIN-hash derivation
    (and their Rust mirror) is untouched, and no gate ever recomputes a lock hash.
    """
    return _canonical_json_bytes(document, exclude=frozenset({"sha256", "signature"}))


def verify_ed25519_signature(document: dict[str, Any], public_key_pem: bytes) -> None:
    """
    Verify the embedded base64 Ed25519 ``signature`` of a signed JSON document.

    Raises ``ValueError`` on a structurally broken document/key and
    ``cryptography.exceptions.InvalidSignature`` on a cryptographic mismatch —
    callers map either to their own opaque fail-closed error.
    """
    signature_field = document.get("signature")
    if not isinstance(signature_field, str) or not signature_field:
        raise ValueError("signature field missing or not a string")
    signature = base64.b64decode(signature_field, validate=True)
    public_key = load_pem_public_key(public_key_pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    public_key.verify(signature, canonical_signed_bytes(document))


def sha256_stream(path: Path) -> str:
    """SHA-256 a file by streaming 1 MiB chunks (never loads the file whole)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fail(cause: str) -> NoReturn:
    """CRITICAL-log the specific cause, then raise the OPAQUE boot error."""
    _log.critical("startup integrity self-check failed: %s", cause)
    raise RuntimeError(_OPAQUE_ERROR)


def verify_boot_integrity(
    manifest_path: Path, public_key_pem: bytes, base_dir: Path
) -> None:
    """
    Fail-closed verified boot: prove every manifest-listed file is unmodified.

    Loads the signed integrity manifest, verifies its Ed25519 release-root
    signature over the canonical bytes, then stream-hashes every listed file
    under ``base_dir`` and compares via ``hmac.compare_digest``. Any unreadable/
    malformed manifest, bad signature, missing file, or hash mismatch raises
    ``RuntimeError("integrity verification failed")`` — the caller (the
    composition root) lets it propagate so the process exits nonzero BEFORE
    binding a socket. Read-only; there is no remediation or self-update path —
    the operator redeploys a verified image.
    """
    try:
        loaded: Any = json.loads(manifest_path.read_bytes())
    except (OSError, ValueError) as exc:
        _fail(f"manifest unreadable or malformed ({type(exc).__name__})")

    if not isinstance(loaded, dict):
        _fail("manifest is not a JSON object")
    manifest: dict[str, Any] = loaded
    if manifest.get("schema") != _MANIFEST_SCHEMA:
        _fail("unknown manifest schema")

    try:
        verify_ed25519_signature(manifest, public_key_pem)
    except Exception as exc:  # noqa: BLE001 — any signature problem is terminal.
        _fail(f"manifest signature invalid ({type(exc).__name__})")

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        _fail("manifest file list missing or empty")

    for entry in files:
        if not isinstance(entry, dict):
            _fail("manifest file entry is not an object")
        rel_path = entry.get("path")
        expected = entry.get("sha256")
        if not isinstance(rel_path, str) or not isinstance(expected, str):
            _fail("manifest file entry missing path/sha256")
        posix = PurePosixPath(rel_path)
        if posix.is_absolute() or ".." in posix.parts:
            _fail(f"manifest file entry escapes base dir: {rel_path}")
        try:
            actual = sha256_stream(base_dir / posix)
        except OSError:
            _fail(f"listed file missing or unreadable: {rel_path}")
        if not hmac.compare_digest(actual, expected.lower()):
            _fail(f"hash mismatch: {rel_path}")
