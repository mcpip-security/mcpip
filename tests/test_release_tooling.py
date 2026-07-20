"""
Release tooling suite — sign → verify roundtrip, tamper → fail-closed exit 2,
license minting/expiry semantics. No network, no Redis: pure file + key ops.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mcpip_verify import cli
from mcpip_verify.verifier import (
    VerificationError,
    canonical_manifest_bytes,
    sha256_file,
    verify_artifacts,
    verify_manifest_signature,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


@pytest.fixture()
def keypair(tmp_path: Path) -> tuple[Path, Path]:
    """(private_pem_path, public_pem_path) — throwaway Ed25519 pair."""
    private_key = Ed25519PrivateKey.generate()
    priv = tmp_path / "root.pem"
    pub = tmp_path / "root.pub.pem"
    priv.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv, pub


def _sign_release(tmp_path: Path, priv: Path, artifact: Path) -> Path:
    """Run scripts/sign_release.py; returns the manifest path."""
    out_dir = tmp_path / "release_out"
    subprocess.run(
        [
            PYTHON,
            str(REPO_ROOT / "scripts" / "sign_release.py"),
            "--version",
            "0.0.1",
            "--private-key",
            str(priv),
            "--artifact",
            str(artifact),
            "--out-dir",
            str(out_dir),
        ],
        check=True,
        cwd=tmp_path,
        capture_output=True,
    )
    return out_dir / "manifest.json"


def test_sign_verify_roundtrip(
    tmp_path: Path, keypair: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    priv, pub = keypair
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"mcpip release payload " * 1024)

    manifest_path = _sign_release(tmp_path, priv, artifact)
    assert manifest_path.is_file()
    assert (manifest_path.parent / "manifest.sig").is_file()

    rc = cli.main(
        [
            "verify",
            "--manifest",
            str(manifest_path),
            "--pubkey",
            str(pub),
            "--base-dir",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out.strip() == "verified: mcpip 0.0.1 (1 artifacts)"
    assert captured.err == ""


def test_tampered_artifact_fails_closed_opaque(
    tmp_path: Path, keypair: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    priv, pub = keypair
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"mcpip release payload " * 1024)
    manifest_path = _sign_release(tmp_path, priv, artifact)

    # Flip ONE byte in the artifact.
    blob = bytearray(artifact.read_bytes())
    blob[100] ^= 0xFF
    artifact.write_bytes(bytes(blob))

    rc = cli.main(
        [
            "verify",
            "--manifest",
            str(manifest_path),
            "--pubkey",
            str(pub),
            "--base-dir",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    # Opaque: exactly this string, no reason/path/hash leakage.
    assert captured.err.strip() == "verification failed"
    assert captured.out == ""


def test_tampered_manifest_signature_fails(
    tmp_path: Path, keypair: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    priv, pub = keypair
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"payload")
    manifest_path = _sign_release(tmp_path, priv, artifact)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = "9.9.9"  # mutate a signed field
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    rc = cli.main(
        [
            "verify",
            "--manifest",
            str(manifest_path),
            "--pubkey",
            str(pub),
            "--base-dir",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.err.strip() == "verification failed"


def test_verifier_library_contracts(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    art = tmp_path / "a.bin"
    art.write_bytes(b"hello")
    manifest: dict[str, object] = {
        "schema": "mcpip-release-manifest/1",
        "version": "0.0.1",
        "artifacts": [
            {
                "name": "a.bin",
                "path": "a.bin",
                "sha256": sha256_file(art),
                "size_bytes": art.stat().st_size,
            }
        ],
    }
    sig = private_key.sign(canonical_manifest_bytes(manifest))
    manifest["signature"] = base64.b64encode(sig).decode("ascii")

    verify_manifest_signature(manifest, pub_pem)
    verify_artifacts(manifest, tmp_path)

    # Canonicalization is signature-field independent.
    with_sig = dict(manifest)
    without_sig = {k: v for k, v in manifest.items() if k != "signature"}
    assert canonical_manifest_bytes(with_sig) == canonical_manifest_bytes(
        dict(without_sig)
    )

    # Wrong key → VerificationError, not InvalidSignature leakage.
    other_pub = Ed25519PrivateKey.generate().public_key()
    other_pem = other_pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(VerificationError):
        verify_manifest_signature(manifest, other_pem)


def _mint_license(tmp_path: Path, priv: Path, days: int) -> Path:
    out = tmp_path / "license.json"
    subprocess.run(
        [
            PYTHON,
            str(REPO_ROOT / "scripts" / "gen_license.py"),
            "--customer",
            "Test Corp",
            "--tier",
            "air-gapped",
            "--days",
            str(days),
            "--private-key",
            str(priv),
            "--out",
            str(out),
        ],
        check=True,
        capture_output=True,
    )
    return out


def test_license_mint_and_signature(
    tmp_path: Path, keypair: tuple[Path, Path]
) -> None:
    priv, pub = keypair
    lic_path = _mint_license(tmp_path, priv, days=365)
    lic = json.loads(lic_path.read_text(encoding="utf-8"))

    assert lic["schema"] == "mcpip-license/1"
    assert lic["tier"] == "air-gapped"
    assert set(lic["entitlements"]) == {
        "authorize",
        "mcp_edge",
        "audit_export",
        "metrics",
    }
    issued = datetime.strptime(lic["issued_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    expires = datetime.strptime(lic["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    assert expires - issued == timedelta(days=365)

    # License signature verifies under the SAME normative canonical rule.
    key = serialization.load_pem_public_key(pub.read_bytes())
    assert isinstance(key, Ed25519PublicKey)
    key.verify(
        base64.b64decode(lic["signature"]),
        canonical_manifest_bytes(lic),
    )
    # ...and a mutated field breaks it (expiry/tier cannot be forged).
    forged = dict(lic)
    forged["expires_at"] = "2099-01-01T00:00:00Z"
    with pytest.raises(InvalidSignature):
        key.verify(
            base64.b64decode(lic["signature"]),
            canonical_manifest_bytes(forged),
        )


def test_license_expiry_rejected_by_gate(
    tmp_path: Path, keypair: tuple[Path, Path]
) -> None:
    """Expired license must be refused by the boot gate (core.licensing —
    Builder A's module; skipped until it lands, then enforced forever)."""
    licensing = pytest.importorskip("core.licensing")
    priv, pub = keypair
    lic_path = _mint_license(tmp_path, priv, days=1)
    future = datetime.now(timezone.utc) + timedelta(days=2)
    with pytest.raises(RuntimeError):
        licensing.load_and_verify_license(lic_path, pub.read_bytes(), now=future)
    # Valid window still loads.
    lic = licensing.load_and_verify_license(lic_path, pub.read_bytes())
    assert lic.tier == "air-gapped"
