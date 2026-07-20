#!/usr/bin/env python3
"""
MCPIP gateway key ceremony — generate the Product-side master keypairs.

Two operator-supplied Ed25519 keys the gateway needs at production boot, which the
release/license ceremony (``gen_release_keys.py``) deliberately does NOT generate:

  * WORM epoch-signing key  — the gateway signs each sealed Merkle-epoch root with
                              this. ``MCPIP_WORM_SIGNING_KEY_PATH``. Its PUBLIC half
                              lets an auditor independently re-verify the ledger
                              (``mcpip export-audit --verify --pubkey ...``).
  * IdP identity-signing key — the identity provider signs principal JWTs with the
                              PRIVATE half (held offline / in the minting host / HSM);
                              the gateway trusts only the PUBLIC half via
                              ``MCPIP_JWT_PUBLIC_KEY_PATH``. The gateway NEVER holds
                              this private key — identity sovereignty is verify-only.

Discipline (Tier-1):
  * Keys are generated IN MEMORY (CSPRNG) and the PRIVATE PEM is written 0o600 to the
    gitignored ``.keys/`` directory, atomically. It is NEVER printed, NEVER logged,
    NEVER committed, and NEVER enters the container image.
  * Only PUBLIC material + SHA-256 key-id fingerprints are printed.
  * Refuses to overwrite an existing private key unless ``--force`` (no silent
    key rotation that would orphan a signed ledger / issued tokens).

These are the mechanics; in production the private keys live on an offline signer /
KMS / HSM and only the public PEMs + the WORM key handle reach the gateway host.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _key_id(private_key: Ed25519PrivateKey) -> str:
    """A short, public, stable fingerprint (never reveals the private scalar)."""
    raw_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "ed25519:" + hashlib.sha256(raw_public).hexdigest()[:16]


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    """Write ``data`` to ``path`` atomically with exactly ``mode`` permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        raise


def _write_private(path: Path, key: Ed25519PrivateKey, *, force: bool) -> None:
    if path.exists() and not force:
        print(f"refusing to overwrite existing private key {path} (use --force)", file=sys.stderr)
        raise SystemExit(1)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _atomic_write(path, pem, mode=0o600)  # owner read/write ONLY.
    # Defence in depth: verify the on-disk mode is exactly 0600.
    actual = stat.S_IMODE(path.stat().st_mode)
    if actual != 0o600:
        raise SystemExit(f"private key {path} has mode {oct(actual)}, expected 0o600")


def _write_public(path: Path, key: Ed25519PrivateKey) -> None:
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    _atomic_write(path, pem, mode=0o644)  # public — safe to read/ship.


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MCPIP gateway key ceremony (WORM + IdP Ed25519 keypairs).")
    parser.add_argument("--keys-dir", default=str(_REPO_ROOT / ".keys"),
                        help="gitignored directory for PRIVATE keys (default: .keys/)")
    parser.add_argument("--public-dir", default=str(_REPO_ROOT / "release" / "keys"),
                        help="directory for PUBLIC keys the gateway/auditor consume")
    parser.add_argument("--force", action="store_true", help="overwrite existing private keys")
    args = parser.parse_args(argv)

    keys_dir = Path(args.keys_dir)
    public_dir = Path(args.public_dir)

    worm = Ed25519PrivateKey.generate()
    idp = Ed25519PrivateKey.generate()

    worm_priv = keys_dir / "worm_signing_ed25519.key"
    worm_pub = public_dir / "worm_signing_ed25519.pub.pem"
    idp_priv = keys_dir / "idp_signing_ed25519.key"
    idp_pub = public_dir / "idp_signing_ed25519.pub.pem"

    _write_private(worm_priv, worm, force=args.force)
    _write_public(worm_pub, worm)
    _write_private(idp_priv, idp, force=args.force)
    _write_public(idp_pub, idp)

    # Public output ONLY — no private bytes ever reach stdout/stderr/logs.
    print("MCPIP gateway key ceremony complete.\n")
    print(f"  WORM epoch-signing  {_key_id(worm)}")
    print(f"    private (0600)    {worm_priv}   -> MCPIP_WORM_SIGNING_KEY_PATH")
    print(f"    public            {worm_pub}    -> auditors (mcpip export-audit --verify --pubkey)")
    print(f"  IdP identity-signing {_key_id(idp)}")
    print(f"    private (0600)    {idp_priv}   -> the token minter (offline / KMS), NEVER the gateway")
    print(f"    public            {idp_pub}    -> MCPIP_JWT_PUBLIC_KEY_PATH")
    print("\nPrivate keys are 0600 in the gitignored keys dir. Do not commit; do not log.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
