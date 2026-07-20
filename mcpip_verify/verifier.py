"""
MCPIP release verification — pure library (READ-ONLY, fail-closed).

Verifies Ed25519-signed release manifests, their SHA-256 artifact digests, and
offline air-gap bundles. This module:

  * never writes to any user path (bundle extraction goes to a private
    ``tempfile.TemporaryDirectory`` that is deleted before returning),
  * never touches the network — trust anchors on the operator-supplied public
    key (checked out-of-band against the published fingerprint),
  * never imports ``app`` or ``redis`` — the gateway is not needed to verify
    a release, and verification is independent of TLS.

Signing rule (normative, shared with the signer): the signed message is
``json.dumps(manifest_without_signature_field, sort_keys=True,
separators=(",", ":")).encode("utf-8")`` where the ``"signature"`` key is
removed from the top-level object. The signature is a raw 64-byte Ed25519
signature over those bytes, base64-encoded.

There is NO remediation path here: any mismatch raises ``VerificationError``
and callers fail closed. Operators redeploy verified artifacts through change
control — MCPIP has no runtime self-update.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "VerificationError",
    "canonical_manifest_bytes",
    "sha256_file",
    "verify_manifest_signature",
    "verify_artifacts",
    "verify_bundle",
]

_CHUNK = 1024 * 1024  # 1 MiB streaming hash chunks.


class VerificationError(Exception):
    """Any verification failure. Callers MUST treat this as fail-closed."""


def canonical_manifest_bytes(manifest: dict[str, object]) -> bytes:
    """Canonical signed bytes: the manifest minus ``signature``, canonical JSON."""
    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path) -> str:
    """Streaming SHA-256 (1 MiB chunks) of a file, lowercase hex."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _load_ed25519_public_key(public_key_pem: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:  # malformed PEM → fail closed.
        raise VerificationError("bad public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationError("bad public key type")
    return key


def verify_manifest_signature(
    manifest: dict[str, object], public_key_pem: bytes
) -> None:
    """Verify the embedded base64 Ed25519 signature over the canonical bytes."""
    signature_b64 = manifest.get("signature")
    if not isinstance(signature_b64, str) or not signature_b64:
        raise VerificationError("missing signature")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError("malformed signature") from exc
    if len(signature) != 64:
        raise VerificationError("malformed signature")
    key = _load_ed25519_public_key(public_key_pem)
    try:
        key.verify(signature, canonical_manifest_bytes(manifest))
    except InvalidSignature as exc:
        raise VerificationError("signature mismatch") from exc


def _artifact_entries(manifest: dict[str, object]) -> list[dict[str, object]]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise VerificationError("missing artifacts")
    entries: list[dict[str, object]] = []
    for entry in artifacts:
        if not isinstance(entry, dict):
            raise VerificationError("malformed artifact entry")
        entries.append(entry)
    return entries


def _check_artifact_file(entry: dict[str, object], file_path: Path) -> None:
    expected_sha = entry.get("sha256")
    expected_size = entry.get("size_bytes")
    if not isinstance(expected_sha, str) or not isinstance(expected_size, int):
        raise VerificationError("malformed artifact entry")
    if not file_path.is_file():
        raise VerificationError("artifact missing")
    if file_path.stat().st_size != expected_size:
        raise VerificationError("artifact size mismatch")
    actual = sha256_file(file_path)
    if not hmac.compare_digest(actual, expected_sha.lower()):
        raise VerificationError("artifact digest mismatch")


def verify_artifacts(manifest: dict[str, object], base_dir: Path) -> None:
    """Verify every listed artifact exists under ``base_dir`` and hash-matches."""
    for entry in _artifact_entries(manifest):
        rel = entry.get("path")
        if not isinstance(rel, str) or not rel:
            raise VerificationError("malformed artifact entry")
        _check_artifact_file(entry, base_dir / rel)


def _safe_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    """Reject path traversal, absolute paths, links, and devices — fail closed."""
    members: list[tarfile.TarInfo] = []
    for member in archive.getmembers():
        name = PurePosixPath(member.name)
        if name.is_absolute() or ".." in name.parts:
            raise VerificationError("unsafe bundle member")
        if not (member.isfile() or member.isdir()):
            raise VerificationError("unsafe bundle member type")
        members.append(member)
    return members


def _bundle_root(extract_dir: Path) -> Path:
    entries = [p for p in extract_dir.iterdir() if p.name != "__MACOSX"]
    if len(entries) != 1 or not entries[0].is_dir():
        raise VerificationError("bad bundle layout")
    return entries[0]


def _verify_sha256sums(root: Path) -> None:
    """Defense in depth: SHA256SUMS must cover every bundled file, all matching."""
    sums_path = root / "SHA256SUMS"
    if not sums_path.is_file():
        raise VerificationError("SHA256SUMS missing")
    listed: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(maxsplit=1)
        if len(parts) != 2:
            raise VerificationError("malformed SHA256SUMS")
        digest, rel = parts[0], parts[1].lstrip("*")
        listed[rel] = digest.lower()
    actual_files = sorted(
        str(p.relative_to(root).as_posix())
        for p in root.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    )
    if sorted(listed) != actual_files:
        raise VerificationError("SHA256SUMS coverage mismatch")
    for rel, digest in listed.items():
        if not hmac.compare_digest(sha256_file(root / rel), digest):
            raise VerificationError("SHA256SUMS digest mismatch")


def _verify_detached_signature(
    manifest: dict[str, object], sig_path: Path, public_key_pem: bytes
) -> None:
    if not sig_path.is_file():
        raise VerificationError("detached signature missing")
    try:
        signature = base64.b64decode(
            sig_path.read_text(encoding="utf-8").strip(), validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise VerificationError("malformed detached signature") from exc
    if len(signature) != 64:
        raise VerificationError("malformed detached signature")
    key = _load_ed25519_public_key(public_key_pem)
    try:
        key.verify(signature, canonical_manifest_bytes(manifest))
    except InvalidSignature as exc:
        raise VerificationError("detached signature mismatch") from exc


def _bundled_pubkey_matches(root: Path, public_key_pem: bytes) -> None:
    """The bundled public key must equal the operator-supplied trust anchor."""
    bundled = root / "keys" / "release_root_ed25519.pub.pem"
    if not bundled.is_file():
        raise VerificationError("bundled public key missing")
    anchor = _load_ed25519_public_key(public_key_pem)
    shipped = _load_ed25519_public_key(bundled.read_bytes())
    raw_anchor = anchor.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    raw_shipped = shipped.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if not hmac.compare_digest(raw_anchor, raw_shipped):
        raise VerificationError("bundled public key mismatch")


def load_manifest(path: Path) -> dict[str, object]:
    """Load a manifest JSON object from disk (fail-closed on any malformation)."""
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise VerificationError("unreadable manifest") from exc
    if not isinstance(loaded, dict):
        raise VerificationError("malformed manifest")
    result: dict[str, object] = {}
    for key, value in loaded.items():
        if not isinstance(key, str):
            raise VerificationError("malformed manifest")
        result[key] = value
    return result


def verify_bundle(bundle_path: Path, public_key_pem: bytes) -> None:
    """
    Verify an offline air-gap bundle with NO network:

      1. safe extraction to a private temp dir (traversal/link members rejected),
      2. bundled public key equals the supplied trust anchor,
      3. manifest signature (embedded) + detached ``manifest.sig``,
      4. every manifest artifact present (``artifacts/`` or ``sbom/``) with a
         matching SHA-256 digest and size,
      5. SHA256SUMS covers every bundled file and every digest matches.
    """
    if not bundle_path.is_file():
        raise VerificationError("bundle missing")
    with tempfile.TemporaryDirectory(prefix="mcpip-verify-") as tmp:
        extract_dir = Path(tmp)
        try:
            with tarfile.open(bundle_path, mode="r:gz") as archive:
                members = _safe_members(archive)
                archive.extractall(extract_dir, members=members)  # noqa: S202
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise VerificationError("unreadable bundle") from exc
        root = _bundle_root(extract_dir)
        _bundled_pubkey_matches(root, public_key_pem)
        manifest = load_manifest(root / "manifest.json")
        verify_manifest_signature(manifest, public_key_pem)
        _verify_detached_signature(manifest, root / "manifest.sig", public_key_pem)
        for entry in _artifact_entries(manifest):
            name = entry.get("name")
            if not isinstance(name, str) or not name or "/" in name:
                raise VerificationError("malformed artifact entry")
            candidates = [root / "artifacts" / name, root / "sbom" / name]
            located: Optional[Path] = next(
                (c for c in candidates if c.is_file()), None
            )
            if located is None:
                raise VerificationError("artifact missing from bundle")
            _check_artifact_file(entry, located)
        _verify_sha256sums(root)
