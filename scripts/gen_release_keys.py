#!/usr/bin/env python3
"""
MCPIP key ceremony — generate the two OFFLINE Ed25519 root keypairs.

Roles (three distinct keys, never conflated):
  * release root  — signs release manifests + integrity manifests,
  * license root  — signs license files,
  * audit epoch   — the EXISTING operator-supplied WORM epoch-signing key
                    (``MCPIP_WORM_SIGNING_KEY_PATH``) — untouched here.

Private keys are written 0o600 to the gitignored ``.keys/`` directory and are
NEVER committed and NEVER enter the image. Only the public keys (PEM,
SubjectPublicKeyInfo) plus ``release/keys/rotation.json`` ship.

These are DEMO/DEV keys. Production root keys are generated and kept on an
offline signer (HSM / air-gapped laptop); the signing scripts accept
``--private-key <path>`` so the same tooling runs there.

Refuses to overwrite an existing private key unless ``--force``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key_id(private_key: Ed25519PrivateKey) -> str:
    raw_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "ed25519:" + hashlib.sha256(raw_public).hexdigest()[:16]


def _write_private_pem(path: Path, private_key: Ed25519PrivateKey, force: bool) -> None:
    if path.exists() and not force:
        print(
            f"refusing to overwrite existing private key {path} (use --force)",
            file=sys.stderr,
        )
        raise SystemExit(1)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def _write_public_pem(path: Path, private_key: Ed25519PrivateKey) -> None:
    pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".rotation-")
    try:
        os.write(fd, text.encode("utf-8"))
        os.fchmod(fd, 0o644)  # committed, public metadata — not key material.
    finally:
        os.close(fd)
    os.replace(tmp_name, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate MCPIP release-root + license-root Ed25519 keypairs"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing private keys (dangerous — rotates the roots)",
    )
    parser.add_argument(
        "--keys-dir",
        default=str(_REPO_ROOT / ".keys"),
        help="gitignored directory for PRIVATE keys (default: .keys/)",
    )
    parser.add_argument(
        "--public-dir",
        default=str(_REPO_ROOT / "release" / "keys"),
        help="committed directory for PUBLIC keys (default: release/keys/)",
    )
    args = parser.parse_args()

    keys_dir = Path(args.keys_dir)
    public_dir = Path(args.public_dir)

    roles = (
        ("release-root", "release_root_ed25519"),
        ("license-root", "license_root_ed25519"),
    )
    rotation_keys: list[dict[str, object]] = []
    for role, stem in roles:
        private_key = Ed25519PrivateKey.generate()
        private_path = keys_dir / f"{stem}.pem"
        public_path = public_dir / f"{stem}.pub.pem"
        _write_private_pem(private_path, private_key, args.force)
        _write_public_pem(public_path, private_key)
        key_id = _key_id(private_key)
        rotation_keys.append(
            {
                "key_id": key_id,
                "role": role,
                "public_key_path": public_path.relative_to(_REPO_ROOT).as_posix()
                if public_path.is_relative_to(_REPO_ROOT)
                else str(public_path),
                "status": "active",
                "not_after": None,
                "supersedes": None,
            }
        )
        print(f"generated {role}: {key_id}")
        print(f"  private (gitignored, 0600): {private_path}")
        print(f"  public  (committed):        {public_path}")

    rotation = {
        "schema": "mcpip-key-rotation/1",
        "generated_at": _utc_now_iso(),
        "keys": rotation_keys,
    }
    rotation_path = public_dir / "rotation.json"
    _atomic_write_text(rotation_path, json.dumps(rotation, indent=2) + "\n")
    print(f"wrote rotation manifest: {rotation_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
