#!/usr/bin/env python3
"""
MCPIP release signer — SHA-256 artifact digests + Ed25519-signed manifest.

Produces ``release/manifest.json`` (embedded base64 signature) and the
detached ``release/manifest.sig`` (base64 + newline), written atomically.

Signing rule (normative, shared verbatim with both verifiers): the signed
message is ``json.dumps(manifest_without_signature_field, sort_keys=True,
separators=(",", ":")).encode("utf-8")`` where the ``"signature"`` key is
removed from the top-level object; signature = raw 64-byte Ed25519 over those
bytes, base64-encoded.

The private key NEVER leaves the offline signer — pass ``--private-key``.
Exits nonzero on any missing artifact. This tool never uploads, never pulls,
never mutates a running gateway: releases are immutable, deployment is the
operator's change-control action.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHUNK = 1024 * 1024


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


def _repo_relative(path: Path) -> str:
    resolved = path.resolve()
    if resolved.is_relative_to(_REPO_ROOT):
        return resolved.relative_to(_REPO_ROOT).as_posix()
    return path.as_posix()


def _artifact_entry(path: Path) -> dict[str, object]:
    if not path.is_file():
        print(f"missing artifact: {path}", file=sys.stderr)
        raise SystemExit(1)
    return {
        "name": path.name,
        "path": _repo_relative(path),
        "sha256": _sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _docker_image_id(image_ref: str) -> str:
    result = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".manifest-")
    try:
        os.write(fd, data)
        os.fchmod(fd, 0o644)  # committed, public metadata — not key material.
    finally:
        os.close(fd)
    os.replace(tmp_name, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign an MCPIP release")
    parser.add_argument("--version", required=True, help="release version, e.g. 2.0.0")
    parser.add_argument(
        "--private-key",
        required=True,
        help="release ROOT private key PEM (offline; e.g. .keys/release_root_ed25519.pem)",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="artifact file to hash + list (repeatable)",
    )
    parser.add_argument("--image-tar", default=None, help="docker-save image tarball")
    parser.add_argument("--image-ref", default=None, help="image ref, e.g. mcpip-gateway:2.0.0")
    parser.add_argument(
        "--image-id",
        default=None,
        help="docker image id (sha256:…); read via `docker image inspect` when omitted",
    )
    parser.add_argument(
        "--out-dir",
        default=str(_REPO_ROOT / "release"),
        help="output directory for manifest.json + manifest.sig (default: release/)",
    )
    args = parser.parse_args()

    private_key = _load_private_key(Path(args.private_key))

    artifacts: list[dict[str, object]] = [
        _artifact_entry(Path(a)) for a in args.artifact
    ]
    if args.image_tar is not None:
        if args.image_ref is None:
            print("--image-tar requires --image-ref", file=sys.stderr)
            raise SystemExit(1)
        image_id: Optional[str] = args.image_id
        if image_id is None:
            image_id = _docker_image_id(args.image_ref)
        entry = _artifact_entry(Path(args.image_tar))
        entry["image_ref"] = args.image_ref
        entry["image_id"] = image_id
        artifacts.append(entry)
    if not artifacts:
        print("no artifacts given", file=sys.stderr)
        raise SystemExit(1)

    manifest: dict[str, object] = {
        "schema": "mcpip-release-manifest/1",
        "version": args.version,
        "created_at": _utc_now_iso(),
        "artifacts": artifacts,
        "signing_key_id": _key_id(private_key),
    }
    signature = private_key.sign(_canonical_bytes(manifest))
    manifest["signature"] = base64.b64encode(signature).decode("ascii")

    out_dir = Path(args.out_dir)
    manifest_path = out_dir / "manifest.json"
    sig_path = out_dir / "manifest.sig"
    _atomic_write_bytes(
        manifest_path, (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    )
    _atomic_write_bytes(
        sig_path, base64.b64encode(signature) + b"\n"
    )
    print(f"signed release {args.version}: {len(artifacts)} artifacts")
    print(f"  manifest:  {manifest_path}")
    print(f"  signature: {sig_path}")
    print(f"  key id:    {manifest['signing_key_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
