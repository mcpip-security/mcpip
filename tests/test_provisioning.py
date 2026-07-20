"""
MCPIP — zero-trust credential provisioning: key ceremony + principal minting.

    ◐ "Master keys generated in memory, 0600, never logged; principals signed,
    scoped, and verify-only at the gateway."

Drives the real CLIs end-to-end (subprocess) and asserts:
  * the gateway key ceremony emits valid Ed25519 keypairs, PRIVATE keys 0600,
    NEVER printing private material, and refuses to overwrite without --force;
  * a minted principal JWT is ACCEPTED by the gateway's own ``TokenResolver``
    (matching iss/aud) with its capability/compartment entitlements intact;
  * every tamper — wrong audience, flipped signature, foreign IdP key, malformed
    capability UUID — fails CLOSED.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auth import StaticPEMKeyProvider, TokenError, TokenResolver

_REPO = Path(__file__).resolve().parent.parent
_PROVISION = _REPO / "scripts" / "provision_gateway_keys.py"
_MINT = _REPO / "scripts" / "mint_principal.py"

_ISS = "prod-idp.hero"
_AUD = "mcpip-gateway"
_CAP = "9c2b6f14-7a3d-4e8b-b1c0-2f5a9d3e4c71"
_COMP = "f4100000-0000-4000-8000-0000000fa1c0"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args], capture_output=True, text=True, cwd=str(_REPO)
    )


def _ceremony(tmp: Path, *, force: bool = False) -> subprocess.CompletedProcess[str]:
    argv = [str(_PROVISION), "--keys-dir", str(tmp / "keys"), "--public-dir", str(tmp / "pub")]
    if force:
        argv.append("--force")
    return _run(*argv)


def _mint(idp_key: Path, *extra: str) -> str:
    proc = _run(
        str(_MINT), "--idp-key", str(idp_key),
        "--tenant", "tenant-acme", "--agent", "agent-hero-1", "--role", "ops",
        "--issuer", _ISS, "--audience", _AUD, "--ttl", "900", *extra,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _resolver(pub_pem: bytes, *, issuer: str = _ISS, audience: str = _AUD) -> TokenResolver:
    return TokenResolver(StaticPEMKeyProvider(pub_pem), issuer=issuer, audience=audience)


# ---------------------------------------------------------------------------
# Gateway key ceremony.
# ---------------------------------------------------------------------------


def test_ceremony_emits_0600_ed25519_keypairs(tmp_path: Path) -> None:
    proc = _ceremony(tmp_path)
    assert proc.returncode == 0, proc.stderr
    worm_priv = tmp_path / "keys" / "worm_signing_ed25519.key"
    idp_priv = tmp_path / "keys" / "idp_signing_ed25519.key"
    worm_pub = tmp_path / "pub" / "worm_signing_ed25519.pub.pem"
    idp_pub = tmp_path / "pub" / "idp_signing_ed25519.pub.pem"
    for f in (worm_priv, idp_priv, worm_pub, idp_pub):
        assert f.exists(), f
    # Private keys are owner-read/write ONLY.
    assert (worm_priv.stat().st_mode & 0o777) == 0o600
    assert (idp_priv.stat().st_mode & 0o777) == 0o600
    # Both private keys are genuine Ed25519.
    for f in (worm_priv, idp_priv):
        assert isinstance(load_pem_private_key(f.read_bytes(), password=None), Ed25519PrivateKey)


def test_ceremony_never_prints_private_material(tmp_path: Path) -> None:
    proc = _ceremony(tmp_path)
    combined = proc.stdout + proc.stderr
    assert "PRIVATE KEY" not in combined  # no PEM private block ever hits stdout/stderr
    assert "ed25519:" in proc.stdout       # only public fingerprints are shown


def test_ceremony_refuses_overwrite_without_force(tmp_path: Path) -> None:
    assert _ceremony(tmp_path).returncode == 0
    again = _ceremony(tmp_path)  # no --force
    assert again.returncode != 0
    assert "refusing to overwrite" in again.stderr
    assert _ceremony(tmp_path, force=True).returncode == 0  # --force succeeds


# ---------------------------------------------------------------------------
# Principal minting → gateway verification.
# ---------------------------------------------------------------------------


def test_minted_principal_is_accepted_with_entitlements(tmp_path: Path) -> None:
    assert _ceremony(tmp_path).returncode == 0
    idp_key = tmp_path / "keys" / "idp_signing_ed25519.key"
    idp_pub = (tmp_path / "pub" / "idp_signing_ed25519.pub.pem").read_bytes()
    token = _mint(idp_key, "--capability", _CAP, "--compartment", _COMP)
    ident = _resolver(idp_pub).resolve(token)
    assert (ident.tenant_id, ident.agent_id, ident.role) == ("tenant-acme", "agent-hero-1", "ops")
    assert ident.capabilities == (_CAP,)
    assert ident.compartment == _COMP


def test_minted_token_wrong_audience_rejected(tmp_path: Path) -> None:
    assert _ceremony(tmp_path).returncode == 0
    idp_key = tmp_path / "keys" / "idp_signing_ed25519.key"
    idp_pub = (tmp_path / "pub" / "idp_signing_ed25519.pub.pem").read_bytes()
    token = _mint(idp_key)
    with pytest.raises(TokenError):
        _resolver(idp_pub, audience="some-other-gateway").resolve(token)


def test_minted_token_tampered_signature_rejected(tmp_path: Path) -> None:
    assert _ceremony(tmp_path).returncode == 0
    idp_key = tmp_path / "keys" / "idp_signing_ed25519.key"
    idp_pub = (tmp_path / "pub" / "idp_signing_ed25519.pub.pem").read_bytes()
    token = _mint(idp_key)
    head, _, sig = token.rpartition(".")
    flipped = "A" if sig[0] != "A" else "B"
    with pytest.raises(TokenError):
        _resolver(idp_pub).resolve(f"{head}.{flipped}{sig[1:]}")


def test_token_from_foreign_idp_key_rejected(tmp_path: Path) -> None:
    """A token signed by one IdP is rejected against a different IdP's public key."""
    assert _ceremony(tmp_path).returncode == 0
    other = tmp_path / "other"
    assert _ceremony(other).returncode == 0
    token = _mint(tmp_path / "keys" / "idp_signing_ed25519.key")
    foreign_pub = (other / "pub" / "idp_signing_ed25519.pub.pem").read_bytes()
    with pytest.raises(TokenError):
        _resolver(foreign_pub).resolve(token)


def test_mint_rejects_malformed_capability_uuid(tmp_path: Path) -> None:
    assert _ceremony(tmp_path).returncode == 0
    idp_key = tmp_path / "keys" / "idp_signing_ed25519.key"
    proc = _run(
        str(_MINT), "--idp-key", str(idp_key),
        "--tenant", "t", "--agent", "a", "--issuer", _ISS, "--audience", _AUD,
        "--capability", "not-a-uuid",
    )
    assert proc.returncode != 0
    assert "UUID" in proc.stderr
