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

``rotation.json`` accumulates. Re-running this retires the outgoing key for each
role (``status: retired`` + ``not_after``) and records it in the new key's
``supersedes``, so the key that signed an earlier release stays identifiable after
it is replaced — without that history, verifying a past release means trusting a
key the manifest no longer mentions. The audit-epoch root is deliberately absent:
it is per-DEPLOYMENT (``scripts/provision_gateway_keys.py``), so its rotation
record belongs to the operator's key ceremony, not to a shipped file.

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


def rotate(
    existing: dict[str, object] | None, role: str, key_id: str, public_path: str, now: str
) -> tuple[list[dict[str, object]], str | None]:
    """Retire the previous active key for ``role`` and return the carried-forward history.

    Rotation is the whole point of a rotation manifest, and the original never did it:
    each run wrote a fresh two-entry document with ``status: active``,
    ``supersedes: null``, so rotating a root ERASED the record of the key that signed
    every previous release. That record is exactly what an auditor needs — a 2.0.0
    signature verifies against a key that, after rotation, the manifest no longer
    mentions, leaving no way to tell a retired root from a forged one.

    History is therefore carried forward: the outgoing key becomes ``retired`` with
    ``not_after`` stamped, and the incoming key names it in ``supersedes``.
    """
    history: list[dict[str, object]] = []
    superseded: str | None = None
    for entry in (existing or {}).get("keys", []) or []:  # type: ignore[union-attr]
        if not isinstance(entry, dict):
            continue
        if entry.get("role") == role and entry.get("status") == "active":
            if entry.get("key_id") == key_id:
                continue  # same key regenerated — not a rotation, no history to keep
            superseded = str(entry.get("key_id"))
            entry = {**entry, "status": "retired", "not_after": now}
        history.append(entry)
    history.append(
        {
            "key_id": key_id,
            "role": role,
            "public_key_path": public_path,
            "status": "active",
            "not_after": None,
            "supersedes": superseded,
        }
    )
    return history, superseded


def _load_existing(path: Path) -> dict[str, object] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


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
    rotation_path = public_dir / "rotation.json"
    now = _utc_now_iso()
    manifest = _load_existing(rotation_path)
    rotation_keys: list[dict[str, object]] = list(
        (manifest or {}).get("keys", []) or []  # type: ignore[arg-type]
    )
    for role, stem in roles:
        private_key = Ed25519PrivateKey.generate()
        private_path = keys_dir / f"{stem}.pem"
        public_path = public_dir / f"{stem}.pub.pem"
        _write_private_pem(private_path, private_key, args.force)
        _write_public_pem(public_path, private_key)
        key_id = _key_id(private_key)
        rotation_keys, superseded = rotate(
            {"keys": rotation_keys},
            role,
            key_id,
            public_path.relative_to(_REPO_ROOT).as_posix()
            if public_path.is_relative_to(_REPO_ROOT)
            else str(public_path),
            now,
        )
        print(f"generated {role}: {key_id}")
        if superseded:
            print(f"  supersedes (now retired):   {superseded}")
        print(f"  private (gitignored, 0600): {private_path}")
        print(f"  public  (committed):        {public_path}")

    rotation = {
        "schema": "mcpip-key-rotation/1",
        "generated_at": now,
        "keys": rotation_keys,
    }
    _atomic_write_text(rotation_path, json.dumps(rotation, indent=2) + "\n")
    print(f"wrote rotation manifest: {rotation_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
