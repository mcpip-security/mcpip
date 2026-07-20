#!/usr/bin/env python3
"""
MCPIP dev license minting — Ed25519-signed entitlement files.

Licenses gate PROCESS BOOT only — they are never consulted by the
authorization pipeline (separation of concerns: entitlement is an operator /
change-control matter, per-request authorization is the engine's). Signed by
the LICENSE ROOT key (separate from both the release root and the WORM epoch
key) with the normative canonical-JSON rule.

Default output lands under the gitignored ``.keys/`` so a dev license can
never be committed by accident. Production licenses are minted on the offline
signer and delivered to the customer out-of-band.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REPO_ROOT = Path(__file__).resolve().parent.parent

_TIERS = ("cloud", "self-hosted", "air-gapped")
_DEFAULT_ENTITLEMENTS = ("authorize", "mcp_edge", "audit_export", "metrics")


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_bytes(obj: dict[str, object]) -> bytes:
    unsigned = {k: v for k, v in obj.items() if k != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        print("private key is not Ed25519", file=sys.stderr)
        raise SystemExit(1)
    return key


def _key_id(private_key: Ed25519PrivateKey) -> str:
    raw_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "ed25519:" + hashlib.sha256(raw_public).hexdigest()[:16]


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".license-")
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp_name, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Mint a signed MCPIP dev license")
    parser.add_argument("--customer", required=True, help="customer display name")
    parser.add_argument("--tier", required=True, choices=_TIERS)
    parser.add_argument(
        "--days", type=int, default=365, help="validity window in days (default 365)"
    )
    parser.add_argument(
        "--entitlements",
        default=",".join(_DEFAULT_ENTITLEMENTS),
        help="comma-separated entitlement list",
    )
    parser.add_argument(
        "--private-key",
        default=str(_REPO_ROOT / ".keys" / "license_root_ed25519.pem"),
        help="LICENSE root private key PEM (offline)",
    )
    parser.add_argument(
        "--out",
        default=str(_REPO_ROOT / ".keys" / "dev_license.json"),
        help="output path (default: gitignored .keys/dev_license.json)",
    )
    args = parser.parse_args()

    private_key = _load_private_key(Path(args.private_key))
    now = datetime.now(timezone.utc)
    entitlements = sorted(
        {e.strip() for e in str(args.entitlements).split(",") if e.strip()}
    )
    if not entitlements:
        print("empty entitlement set", file=sys.stderr)
        raise SystemExit(1)

    license_obj: dict[str, object] = {
        "schema": "mcpip-license/1",
        "license_id": str(uuid.uuid4()),
        "customer": args.customer,
        "tier": args.tier,
        "issued_at": _iso(now),
        "expires_at": _iso(now + timedelta(days=args.days)),
        "entitlements": entitlements,
        "signing_key_id": _key_id(private_key),
    }
    signature = private_key.sign(_canonical_bytes(license_obj))
    license_obj["signature"] = base64.b64encode(signature).decode("ascii")

    out_path = Path(args.out)
    _atomic_write_text(out_path, json.dumps(license_obj, indent=2) + "\n")
    print(
        f"minted license {license_obj['license_id']} "
        f"(tier={args.tier}, expires={license_obj['expires_at']}) -> {out_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
