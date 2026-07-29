#!/usr/bin/env python3
"""
MCPIP integrity manifest generator — signed source set for verified boot.

Hashes (SHA-256, streamed) the normative shipped source set:

    every ``*.py`` under app/ core/ auth/ audit/ bridge/ services/ models/
    obfuscator/ mcpip_verify/  (``__pycache__`` excluded)
    plus ``interfaces.py``, ``main.py``, ``VERSION``

sorted by repo-root-relative POSIX path, and signs the manifest with the
RELEASE ROOT key using the normative canonical-JSON signing rule (the
``"signature"`` key removed, ``sort_keys=True``, ``separators=(",", ":")``).

Run as the LAST step before ``docker build`` so it hashes the final source.
At boot, ``core/integrity.py`` re-hashes every file read-only and refuses to
start on any mismatch — there is NO remediation/self-heal/self-update path;
the operator redeploys a verified image through change control.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

# ``cryptography`` is imported LAZILY inside the signing-only helpers below, so the
# pure file-set/hashing helpers (``_collect_files``/``_sha256_file``/``_read_version``)
# can be imported by a signature-free consumer (``check_integrity_manifest_drift.py``,
# run in a minimal CI job that does not install runtime deps) without pulling in
# ``cryptography``. Signing (``main``) still requires it.
if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHUNK = 1024 * 1024

# The scope lives in PRODUCT code (core/integrity.py) and is imported here, so the
# file set that gets SIGNED and the set the boot gate REQUIRES COVERED are one
# definition. Two copies of the same rule is how a coverage gap opens silently.
sys.path.insert(0, str(_REPO_ROOT))
from core.integrity import MANIFEST_EXTRA_FILES, MANIFEST_PACKAGE_DIRS  # noqa: E402

_PACKAGE_DIRS = MANIFEST_PACKAGE_DIRS
_EXTRA_FILES = MANIFEST_EXTRA_FILES


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


def _canonical_bytes(manifest: dict[str, object]) -> bytes:
    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_private_key(path: Path) -> "Ed25519PrivateKey":
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        print("private key is not Ed25519", file=sys.stderr)
        raise SystemExit(1)
    return key


def _key_id(private_key: "Ed25519PrivateKey") -> str:
    from cryptography.hazmat.primitives import serialization

    raw_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "ed25519:" + hashlib.sha256(raw_public).hexdigest()[:16]


def _collect_files(base_dir: Path) -> list[Path]:
    files: list[Path] = []
    for pkg in _PACKAGE_DIRS:
        pkg_dir = base_dir / pkg
        if not pkg_dir.is_dir():
            print(f"missing package directory: {pkg_dir}", file=sys.stderr)
            raise SystemExit(1)
        for path in pkg_dir.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            files.append(path)
    for name in _EXTRA_FILES:
        path = base_dir / name
        if not path.is_file():
            print(f"missing required file: {path}", file=sys.stderr)
            raise SystemExit(1)
        files.append(path)
    return sorted(files, key=lambda p: p.relative_to(base_dir).as_posix())


def _read_version(base_dir: Path) -> str:
    raw = (base_dir / "VERSION").read_text(encoding="utf-8").strip()
    if re.fullmatch(r"\d+\.\d+\.\d+", raw) is None:
        print("VERSION file missing or malformed", file=sys.stderr)
        raise SystemExit(1)
    return raw


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".integrity-")
    try:
        os.write(fd, text.encode("utf-8"))
        os.fchmod(fd, 0o644)  # committed, public metadata — not key material.
    finally:
        os.close(fd)
    os.replace(tmp_name, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate + sign the MCPIP boot integrity manifest"
    )
    parser.add_argument(
        "--private-key",
        default=str(_REPO_ROOT / ".keys" / "release_root_ed25519.pem"),
        help="release ROOT private key PEM (offline)",
    )
    parser.add_argument(
        "--base-dir",
        default=str(_REPO_ROOT),
        help="source tree root to hash (default: repo root)",
    )
    parser.add_argument(
        "--out",
        default=str(_REPO_ROOT / "release" / "integrity_manifest.json"),
        help="output path (default: release/integrity_manifest.json)",
    )
    args = parser.parse_args()

    base_dir = Path(args.base_dir).resolve()
    private_key = _load_private_key(Path(args.private_key))

    entries: list[dict[str, object]] = [
        {
            "path": path.relative_to(base_dir).as_posix(),
            "sha256": _sha256_file(path),
        }
        for path in _collect_files(base_dir)
    ]

    manifest: dict[str, object] = {
        "schema": "mcpip-integrity-manifest/1",
        "version": _read_version(base_dir),
        "generated_at": _utc_now_iso(),
        "files": entries,
        "signing_key_id": _key_id(private_key),
    }
    signature = private_key.sign(_canonical_bytes(manifest))
    manifest["signature"] = base64.b64encode(signature).decode("ascii")

    out_path = Path(args.out)
    _atomic_write_text(out_path, json.dumps(manifest, indent=2) + "\n")
    print(f"integrity manifest: {len(entries)} files -> {out_path}")
    print(f"  key id: {manifest['signing_key_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
