"""
MCPIP — opt-in WORM event-body at-rest encryption (SOC 2 C1.1/SC-28).

    ◐ "Integrity stays publicly verifiable; the body needs the key."

With a content key the sensitive ``event`` payload is AES-256-GCM-wrapped BEFORE it is
stored, so the alias→target de-obfuscation map is ciphertext in Redis + AOF. The signed
Merkle leaf hashes the STORED (encrypted) record, so ``verify_chain`` is byte-for-byte
unaffected and still verifies WITHOUT the key — only reading a body needs it. Default OFF
⇒ plaintext bodies, byte-identical.

REAL end-to-end tests against the dev Redis (:63790), namespaced to db /14.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/5")

import pytest
import redis.asyncio as aioredis
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.worm_logger import (
    WormLogger,
    _decrypt_worm_event,
    _encrypt_worm_event,
)

_ENC_REDIS_URL = "redis://localhost:63790/14"
_KEY = b"K" * 32
_TARGET = "mainframe.cics.PAYR.MASTER"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


async def _fresh(**kwargs: Any) -> tuple[WormLogger, Any]:
    client: Any = aioredis.from_url(_ENC_REDIS_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    await client.flushdb()
    logger = WormLogger(
        client,
        Ed25519PrivateKey.generate(),
        path=os.path.join(os.path.dirname(__file__), ".mcpip_test_enc_worm.jsonl"),
        **kwargs,
    )
    return logger, client


def test_pure_envelope_roundtrip_and_opacity() -> None:
    event = {"decision": "allow", "tenant_id": "t", "alias": "skill_pay", "target": _TARGET}
    env = _encrypt_worm_event(event, _KEY)
    assert env.startswith("encv1:")
    assert _TARGET not in env and "skill_pay" not in env  # ciphertext, not plaintext
    assert _decrypt_worm_event(env, _KEY) == event  # round-trips with the key
    assert _decrypt_worm_event(env, None) == env  # no key ⇒ opaque envelope returned as-is
    assert _decrypt_worm_event(event, _KEY) == event  # a plaintext dict is passed through
    with pytest.raises(InvalidTag):
        _decrypt_worm_event(env, b"j" * 32)  # a wrong key cannot forge/read the body


def test_emit_encrypts_body_and_chain_still_verifies() -> None:
    async def scenario() -> None:
        logger, client = await _fresh(content_key=_KEY)
        try:
            await logger.emit(
                {"decision": "allow", "tenant_id": "acme", "alias": "skill_pay", "target": _TARGET}
            )
            entries = await client.xrange("mcpip:worm:events")
            assert entries
            _sid, fields = entries[0]
            # At rest, the body is an envelope and the real target is NOT recoverable.
            assert "encv1:" in fields["record"]
            assert _TARGET not in fields["record"]
            # Seal the epoch, then verify the chain WITHOUT the content key — integrity is
            # public; encryption is transparent to it.
            await logger.close_epoch()
            intact, bad = await logger.verify_chain()
            assert intact and bad is None
            # A reader WITH the key decrypts the operator row back to plaintext.
            row = WormLogger._project_decision_row("acme", fields, _KEY)
            assert row is not None and row["alias"] == "skill_pay"
            # A reader WITHOUT the key cannot read the body (the envelope is not a dict).
            assert WormLogger._project_decision_row("acme", fields, None) is None
        finally:
            await client.aclose()

    _run(scenario())


def test_default_off_stores_plaintext_body() -> None:
    async def scenario() -> None:
        logger, client = await _fresh()  # no content_key
        try:
            await logger.emit(
                {"decision": "allow", "tenant_id": "acme", "alias": "skill_pay", "target": _TARGET}
            )
            entries = await client.xrange("mcpip:worm:events")
            _sid, fields = entries[0]
            assert "encv1:" not in fields["record"]  # plaintext dict, byte-identical
            row = WormLogger._project_decision_row("acme", fields, None)
            assert row is not None and row["alias"] == "skill_pay"
        finally:
            await client.aclose()

    _run(scenario())


_KEY_B = b"R" * 32  # a rotated-in (successor) content key, distinct from _KEY


def test_retired_key_fallback_decrypts_after_rotation() -> None:
    """A body sealed under the retired key still reads once the active key rotates, as long
    as the retired key is RETAINED in the fallback set — the active key is tried first, then
    each fallback. Rotation without retaining the old key would leave old bodies unreadable."""
    event = {"decision": "allow", "tenant_id": "t", "alias": "skill_pay", "target": _TARGET}
    sealed_under_old = _encrypt_worm_event(event, _KEY)
    # Active key is now _KEY_B; the old _KEY is retained as a fallback.
    assert _decrypt_worm_event(sealed_under_old, _KEY_B, (_KEY,)) == event
    # Active key alone (retired key dropped) can no longer open the old body — loud, not silent.
    with pytest.raises(InvalidTag):
        _decrypt_worm_event(sealed_under_old, _KEY_B)
    # And a body sealed under the NEW active key reads under the active key directly.
    sealed_under_new = _encrypt_worm_event(event, _KEY_B)
    assert _decrypt_worm_event(sealed_under_new, _KEY_B, (_KEY,)) == event


def test_all_keys_fail_reraises_not_silent() -> None:
    """If neither the active key nor any retained fallback can open a real envelope, the
    AES-GCM error is re-raised — never a silent unreadable pass-through."""
    env = _encrypt_worm_event({"a": 1}, _KEY)
    with pytest.raises(InvalidTag):
        _decrypt_worm_event(env, b"x" * 32, (b"y" * 32, b"z" * 32))


def test_fallbacks_without_active_key_is_rejected() -> None:
    """A retired key with no active key can never SEAL — a misconfiguration, refused at
    construction (fail-closed)."""
    import redis.asyncio as _aio

    client: Any = _aio.from_url(_ENC_REDIS_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    with pytest.raises(ValueError):
        WormLogger(
            client,
            Ed25519PrivateKey.generate(),
            content_key=None,
            content_key_fallbacks=(_KEY,),
        )


def test_emit_under_rotated_key_reads_old_and_new_end_to_end() -> None:
    """End-to-end: emit under the old key, then bring up a logger with the NEW active key and
    the old key retained; both the pre-rotation and post-rotation rows project correctly and
    the chain still verifies without any content key."""
    async def scenario() -> None:
        logger_old, client = await _fresh(content_key=_KEY)
        try:
            await logger_old.emit(
                {"decision": "allow", "tenant_id": "acme", "alias": "skill_old", "target": _TARGET}
            )
            # Rotate: same Redis/stream, new active key, old key retained as a fallback.
            logger_new = WormLogger(
                client,
                logger_old._private_key,
                path=logger_old._path.as_posix(),
                content_key=_KEY_B,
                content_key_fallbacks=(_KEY,),
            )
            await logger_new.emit(
                {"decision": "allow", "tenant_id": "acme", "alias": "skill_new", "target": _TARGET}
            )
            rows = await logger_new.recent_decisions("acme", limit=10)
            aliases = {r["alias"] for r in rows}
            assert {"skill_old", "skill_new"} <= aliases  # both readable across the rotation
            await logger_new.close_epoch()
            intact, bad = await logger_new.verify_chain()
            assert intact and bad is None
        finally:
            await client.aclose()

    _run(scenario())
