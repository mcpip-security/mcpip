"""
MCPIP — opt-in principal pseudonymization (SOC2_READINESS.md #40b / Phase E; GDPR Art. 17).

    ◐ "The immutable ledger stays intact; the natural-person link becomes shreddable."

When ``MCPIP_PSEUDONYMIZE_PRINCIPALS`` is on, the delegation actors recorded to the
permanent WORM ledger (``act_sub`` / ``delegation_chain`` — RFC 8693 actors that can name
a human) are replaced with a stable keyed-HMAC pseudonym: crypto-shreddable (destroy the
key ⇒ sever linkage), deterministic (audit correlation still works), one-way, and
verify_chain-unaffected. Default OFF ⇒ raw identifiers, byte-identical to today.

Pure-function + loader tests. Sandbox is set before importing ``app.main``.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/5")

import pytest

from app.main import _load_pseudonym_key, _pseudonymize_principal
from core.config import Settings


# --- _pseudonymize_principal (pure) --------------------------------------------


def test_off_returns_raw_value() -> None:
    # key None (feature off) ⇒ the raw identifier is recorded, unchanged.
    assert _pseudonymize_principal("alice@corp.example", None) == "alice@corp.example"


def test_on_is_stable_one_way_and_distinct() -> None:
    key = b"k" * 32
    a = _pseudonymize_principal("alice@corp.example", key)
    assert a.startswith("psn_")
    assert a != "alice@corp.example"  # one-way: the raw value never appears
    assert "alice" not in a
    # Deterministic: the same subject → the same pseudonym (audit correlation works).
    assert _pseudonymize_principal("alice@corp.example", key) == a
    # Distinct subjects → distinct pseudonyms.
    assert _pseudonymize_principal("bob@corp.example", key) != a
    # Crypto-shred: a different key yields a different pseudonym (old key destroyed ⇒
    # the link can no longer be re-derived).
    assert _pseudonymize_principal("alice@corp.example", b"j" * 32) != a


# --- _load_pseudonym_key -------------------------------------------------------


def _settings(**over: object) -> Settings:
    base: dict[str, object] = {"sandbox_mode": True}
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


def test_disabled_loads_no_key() -> None:
    assert _load_pseudonym_key(_settings(pseudonymize_principals=False)) is None


def test_enabled_sandbox_autoprovisions_key() -> None:
    key = _load_pseudonym_key(_settings(sandbox_mode=True, pseudonymize_principals=True))
    assert isinstance(key, bytes) and len(key) >= 32


def test_enabled_production_without_key_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="MCPIP_PSEUDONYM_KEY_PATH"):
        _load_pseudonym_key(
            _settings(sandbox_mode=False, pseudonymize_principals=True, pseudonym_key_path=None)
        )


def test_enabled_with_short_key_file_fails_closed(tmp_path) -> None:
    p = tmp_path / "psn.key"
    p.write_bytes(b"too-short")
    os.chmod(p, 0o600)
    with pytest.raises(RuntimeError, match="at least 32"):
        _load_pseudonym_key(
            _settings(sandbox_mode=False, pseudonymize_principals=True, pseudonym_key_path=str(p))
        )


def test_enabled_with_valid_key_file_loads(tmp_path) -> None:
    p = tmp_path / "psn.key"
    p.write_bytes(b"z" * 48)
    os.chmod(p, 0o600)
    key = _load_pseudonym_key(
        _settings(sandbox_mode=False, pseudonymize_principals=True, pseudonym_key_path=str(p))
    )
    assert key == b"z" * 48
