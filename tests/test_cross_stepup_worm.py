"""
MCPIP V2 — CROSS suite: payload-bound PIN step-up ceremony × write-before-execute WORM.

    ◐ Auth: "A payload-bound PIN spent exactly once, or the action never runs."
    ◐ Audit: "The signed decision record is durable BEFORE the action can dispatch."

This file crosses the two halves of a high-risk action:

  * the STEP-UP CEREMONY — mint a one-time PIN, register the payload-bound lock,
    deliver the code out-of-band, then atomically SPEND it exactly once
    (``services/auth_engine.py`` ``register_lock`` / ``consume_and_execute`` over
    ``auth/pin_validator.py``'s single Redis Lua ``LOCK_CONSUME_LUA``); and
  * WRITE-BEFORE-EXECUTE — the signed WORM record for a decision is durably
    committed BEFORE the action would dispatch (``audit/worm_logger.py`` ``emit``),
    a staged ``PIN_REQUIRED`` decision is itself audited, and a failed emit is a
    DENY, never a dropped log line.

Harness style: the engine/pure level (brief style #1 — robust, fast, deterministic,
no HTTP, no network, no SDK). Each test is ``asyncio.run(_body())`` over a fresh
``AuthEngine`` / ``PinValidator`` / ``WormLogger`` and a real Redis on ``:63790``.
Auth-engine tests run on a dedicated db and mint UNIQUE uuid4 tenants/agents/aliases
per test, so they never assume an empty db and never contend on a shared rate-limit
counter or lock. WORM-chain tests run on their own flushed db so ``verify_chain`` is
deterministic (epoch 0) and a tamper case can never poison a sibling test.

Every deny test asserts the ENGINE-side concrete ``DenyReason`` (what the WORM log
would carry) AND — where a caller envelope is modeled — that the opaque
``{error, correlation_id}`` shell leaks neither the PIN/OTP nor the real target.
"""

from __future__ import annotations

import asyncio
import json
import types
import uuid
import unicodedata
from typing import Any

import pytest
import redis.asyncio as aioredis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.worm_logger import WormLogger, _EVENTS_STREAM, _redact
from auth import LockError, PinValidator, lock_payload_hash
from auth.pin_validator import _lock_key
from core.security import (
    AGENT_FACING_DENY_MESSAGE,
    GatewayDeny,
    new_correlation_id,
)
from interfaces import (
    AuthenticatorNotice,
    BaseAuthenticatorChannel,
    DenyReason,
    Identity,
    PIN_LENGTH,
    PIN_MAX_ATTEMPTS,
    PIN_TTL_SECONDS,
    RiskTier,
)
from services.auth_engine import (
    AuthEngine,
    _CONSUME_RATE_MAX,
    _STEPUP_RATE_MAX,
)
from services.authn_channel import (
    AuthenticatorDeliveryError,
    SandboxRedisAuthenticatorChannel,
)

# Dedicated dbs (see grep of the suite: /9 + /10 are unused by any other test file,
# so a flush here can never wipe a module-scoped fixture elsewhere). Auth-engine tests
# do NOT flush /9 — they mint unique ids so residue is irrelevant (honors "no clean-db
# assumption"). WORM-chain tests flush /10 for a deterministic genesis chain.
_AUTH_DB = "redis://localhost:63790/9"
_WORM_DB = "redis://localhost:63790/10"


# ---------------------------------------------------------------------------
# Harness helpers.
# ---------------------------------------------------------------------------


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _client(url: str) -> Any:
    return aioredis.from_url(url, decode_responses=True)  # type: ignore[no-untyped-call]


def _uid(prefix: str) -> str:
    """A collision-free per-test identifier (brief: unique uuid4 ids per test)."""
    return f"{prefix}-{uuid.uuid4().hex}"


def _identity(
    *,
    tenant: str | None = None,
    agent: str | None = None,
    compartment: str | None = None,
) -> Identity:
    """A sovereign Identity (as a verified JWT would resolve to). Unique by default."""
    return Identity(
        tenant_id=tenant or _uid("tenant"),
        agent_id=agent or _uid("agent"),
        role="worker",  # descriptive ONLY — authorizes nothing.
        issuer="test-idp",
        audience="mcpip",
        compartment=compartment,
    )


def _entry(alias: str) -> Any:
    """The resolved alias handle consume needs (only ``.alias`` is read)."""
    return types.SimpleNamespace(alias=alias)


def _engine(client: Any, *, deliver: bool = True) -> AuthEngine:
    """A fresh AuthEngine over a real PinValidator (+ sandbox delivery channel)."""
    channel = SandboxRedisAuthenticatorChannel(client) if deliver else None
    return AuthEngine(
        resolver=None,  # type: ignore[arg-type]  — verify_identity is unused here.
        pin=PinValidator(client),
        redis_client=client,
        channel=channel,
    )


async def _stage(
    engine: AuthEngine, identity: Identity, alias: str, arguments: dict[str, Any]
) -> tuple[str, str]:
    """Run the step-up staging half → (challenge_id, out-of-band otp)."""
    challenge_id = await engine.register_lock(
        identity, alias, arguments, RiskTier.PIN_REQUIRED
    )
    otp = await engine.peek_authenticator_otp(identity, challenge_id)
    assert otp is not None, "sandbox channel must surface the staged code out-of-band"
    return challenge_id, otp


def _wrong_pin(otp: str) -> str:
    """A well-formed 6-digit PIN GUARANTEED to differ from ``otp``."""
    return f"{(int(otp) + 1) % (10 ** PIN_LENGTH):0{PIN_LENGTH}d}"


def _opaque_envelope(correlation_id: str) -> dict[str, str]:
    """The ONLY shape a policy deny ever shows the agent (interfaces invariant #5)."""
    return {"error": AGENT_FACING_DENY_MESSAGE, "correlation_id": correlation_id}


async def _latest_event(client: Any) -> dict[str, Any] | None:
    """The inner ``event`` dict of the most-recently buffered WORM record."""
    entries: Any = await client.xrevrange(_EVENTS_STREAM, count=1)
    if not entries:
        return None
    record: Any = json.loads(entries[0][1]["record"])
    assert isinstance(record["event"], dict)
    return record["event"]


async def _event_by_id(client: Any, event_id: str) -> dict[str, Any] | None:
    """The inner ``event`` dict for a specific emit receipt's event_id."""
    entries: Any = await client.xrevrange(_EVENTS_STREAM, count=500)
    for _sid, fields in entries:
        if fields.get("event_id") == event_id:
            record: Any = json.loads(fields["record"])
            return record["event"]  # type: ignore[no-any-return]
    return None


class _RaisingChannel(BaseAuthenticatorChannel):
    """A delivery channel whose ``deliver`` always fails (out-of-band push unreachable)."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    async def deliver(self, notice: AuthenticatorNotice) -> None:
        raise self._exc


class _RecordingDispatcher:
    """Records whether the ALLOW WORM record was ALREADY durable at dispatch time."""

    def __init__(self, client: Any) -> None:
        self._client = client
        self.dispatched = False
        self.record_present_at_dispatch = False

    async def dispatch(self, event_id: str) -> None:
        entries: Any = await self._client.xrevrange(_EVENTS_STREAM, count=200)
        self.record_present_at_dispatch = any(
            fields.get("event_id") == event_id for _sid, fields in entries
        )
        self.dispatched = True


class _BrokenWorm:
    """A WORM logger whose ``emit`` fails — models a durable-buffer transport failure."""

    async def emit(self, event: dict[str, Any]) -> Any:
        raise LockError("simulated WORM buffer transport failure")


async def _gate_allow(
    worm: Any, dispatcher: _RecordingDispatcher, event: dict[str, Any]
) -> Any:
    """
    The write-before-execute funnel: durably EMIT the decision, THEN dispatch.

    A failed emit is a fail-closed DENY (GatewayDeny) — never a dropped log line and
    never a dispatch. On success, dispatch runs only AFTER the receipt is durable.
    """
    try:
        receipt = await worm.emit(event)
    except Exception as exc:  # noqa: BLE001 — a lost audit write must fail closed.
        raise GatewayDeny(DenyReason.INTERNAL, "audit emit failed") from exc
    await dispatcher.dispatch(receipt.event_id)
    return receipt


# ===========================================================================
# 1. Step-up ceremony — register → consume EXACTLY once; delivery seam.
# ===========================================================================


def test_register_then_consume_once_allows() -> None:
    """A staged payload lock is spent exactly once and ALLOWs (Lua code 1)."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-1", "cycle": "monthly"}
            challenge, otp = await _stage(engine, ident, alias, args)
            code = await engine.consume_and_execute(
                ident, _entry(alias), args, otp, challenge
            )
            assert code == 1
        finally:
            await client.aclose()

    _run(_body())


def test_second_consume_is_replay_denied_pin_not_found() -> None:
    """A second consume of a spent challenge (replay) → PIN_NOT_FOUND, fail closed."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-2"}
            challenge, otp = await _stage(engine, ident, alias, args)
            assert await engine.consume_and_execute(
                ident, _entry(alias), args, otp, challenge
            ) == 1
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), args, otp, challenge
                )
            assert exc.value.reason is DenyReason.PIN_NOT_FOUND
        finally:
            await client.aclose()

    _run(_body())


def test_challenge_id_is_uuid4_hex_not_the_otp() -> None:
    """The staged challenge_id is an opaque uuid4 hex, never the delivered code."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            challenge, otp = await _stage(engine, ident, _uid("skill"), {"a": 1})
            assert len(challenge) == 32
            uuid.UUID(challenge)  # well-formed uuid4 hex, no topology.
            assert challenge != otp
            assert len(otp) == PIN_LENGTH and otp.isdigit()
        finally:
            await client.aclose()

    _run(_body())


def test_delivered_otp_is_six_digits_and_consumes() -> None:
    """The out-of-band OTP is a PIN_LENGTH decimal code that spends its own lock."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"amount": 100}
            challenge, otp = await _stage(engine, ident, alias, args)
            assert len(otp) == PIN_LENGTH and otp.isdigit()
            assert await engine.consume_and_execute(
                ident, _entry(alias), args, otp, challenge
            ) == 1
        finally:
            await client.aclose()

    _run(_body())


def test_no_channel_fails_closed_otp_delivery_failed() -> None:
    """No configured delivery channel → OTP_DELIVERY_FAILED (no staged challenge)."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client, deliver=False)
            with pytest.raises(GatewayDeny) as exc:
                await engine.register_lock(
                    _identity(), _uid("skill"), {"a": 1}, RiskTier.PIN_REQUIRED
                )
            assert exc.value.reason is DenyReason.OTP_DELIVERY_FAILED
        finally:
            await client.aclose()

    _run(_body())


def test_no_channel_registers_no_spendable_lock() -> None:
    """A channel-less gateway stages nothing: peek is None and a guessed spend denies."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client, deliver=False)
            ident = _identity()
            with pytest.raises(GatewayDeny):
                await engine.register_lock(
                    ident, _uid("skill"), {"a": 1}, RiskTier.PIN_REQUIRED
                )
            # Nothing to peek and nothing to spend — the PIN_REQUIRED action cannot proceed.
            guessed = uuid.uuid4().hex
            assert await engine.peek_authenticator_otp(ident, guessed) is None
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry("skill_x"), {"a": 1}, "000000", guessed
                )
            assert exc.value.reason is DenyReason.PIN_NOT_FOUND
        finally:
            await client.aclose()

    _run(_body())


def test_channel_deliver_raises_is_otp_delivery_failed() -> None:
    """A channel whose ``deliver`` raises → fail-closed OTP_DELIVERY_FAILED."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = AuthEngine(
                resolver=None,  # type: ignore[arg-type]
                pin=PinValidator(client),
                redis_client=client,
                channel=_RaisingChannel(AuthenticatorDeliveryError("sink down")),
            )
            with pytest.raises(GatewayDeny) as exc:
                await engine.register_lock(
                    _identity(), _uid("skill"), {"a": 1}, RiskTier.PIN_REQUIRED
                )
            assert exc.value.reason is DenyReason.OTP_DELIVERY_FAILED
        finally:
            await client.aclose()

    _run(_body())


def test_channel_gatewaydeny_propagates_unwrapped() -> None:
    """A GatewayDeny raised by ``deliver`` propagates unchanged (not re-wrapped)."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            marker = GatewayDeny(DenyReason.OTP_DELIVERY_FAILED, "explicit channel deny")
            engine = AuthEngine(
                resolver=None,  # type: ignore[arg-type]
                pin=PinValidator(client),
                redis_client=client,
                channel=_RaisingChannel(marker),
            )
            with pytest.raises(GatewayDeny) as exc:
                await engine.register_lock(
                    _identity(), _uid("skill"), {"a": 1}, RiskTier.PIN_REQUIRED
                )
            assert exc.value is marker  # the SAME object — the except-GatewayDeny re-raise.
        finally:
            await client.aclose()

    _run(_body())


def test_peek_unknown_challenge_returns_none() -> None:
    """Peeking an out-of-band code for an unknown challenge honestly returns None."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            assert await engine.peek_authenticator_otp(
                _identity(), uuid.uuid4().hex
            ) is None
        finally:
            await client.aclose()

    _run(_body())


def test_consume_wrong_challenge_id_is_pin_not_found() -> None:
    """A correct PIN against the WRONG challenge_id → PIN_NOT_FOUND (lock keyed by id)."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-9"}
            _challenge, otp = await _stage(engine, ident, alias, args)
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), args, otp, uuid.uuid4().hex
                )
            assert exc.value.reason is DenyReason.PIN_NOT_FOUND
        finally:
            await client.aclose()

    _run(_body())


def test_consume_correct_challenge_after_stage_allows() -> None:
    """The returned challenge_id IS the lock id — presenting it spends the lock."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"k": "v"}
            challenge, otp = await _stage(engine, ident, alias, args)
            # The lock lives under the tenant-scoped key formed from the challenge id.
            assert await client.exists(_lock_key(ident.tenant_id, challenge)) == 1
            assert await engine.consume_and_execute(
                ident, _entry(alias), args, otp, challenge
            ) == 1
            assert await client.exists(_lock_key(ident.tenant_id, challenge)) == 0
        finally:
            await client.aclose()

    _run(_body())


# ===========================================================================
# 2. Payload binding — byte-identity of canonical_json register↔consume.
# ===========================================================================


def test_one_byte_argument_drift_is_payload_mismatch() -> None:
    """One byte of argument drift after staging → PAYLOAD_MISMATCH."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            challenge, otp = await _stage(engine, ident, alias, {"cycle": "monthly"})
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), {"cycle": "monthlyX"}, otp, challenge
                )
            assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
        finally:
            await client.aclose()

    _run(_body())


def test_payload_mismatch_does_not_spend_lock() -> None:
    """A payload mismatch spends no attempt — the correct payload still ALLOWs after."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"cycle": "monthly"}
            challenge, otp = await _stage(engine, ident, alias, args)
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), {"cycle": "weekly"}, otp, challenge
                )
            assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
            # Lock survived the drift — the correct payload spends it.
            assert await engine.consume_and_execute(
                ident, _entry(alias), args, otp, challenge
            ) == 1
        finally:
            await client.aclose()

    _run(_body())


def test_reordered_argument_keys_still_consume() -> None:
    """Key order is irrelevant — canonical_json sorts keys, so the lock still spends."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            challenge, otp = await _stage(
                engine, ident, alias, {"b": 2, "a": 1, "m": 3}
            )
            assert await engine.consume_and_execute(
                ident, _entry(alias), {"a": 1, "m": 3, "b": 2}, otp, challenge
            ) == 1
        finally:
            await client.aclose()

    _run(_body())


def test_nfc_equivalent_argument_value_still_consumes() -> None:
    """Canonicalization NFC-normalizes strings — a decomposed form still consumes."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            composed = unicodedata.normalize("NFC", "café")     # U+00E9
            decomposed = unicodedata.normalize("NFD", "café")   # e + U+0301
            assert composed != decomposed  # distinct byte sequences pre-canonicalization.
            challenge, otp = await _stage(engine, ident, alias, {"note": composed})
            assert await engine.consume_and_execute(
                ident, _entry(alias), {"note": decomposed}, otp, challenge
            ) == 1
        finally:
            await client.aclose()

    _run(_body())


def test_number_vs_string_drift_is_payload_mismatch() -> None:
    """A number retyped as its string form is a different payload → PAYLOAD_MISMATCH."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            challenge, otp = await _stage(engine, ident, alias, {"n": 1})
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), {"n": "1"}, otp, challenge
                )
            assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
        finally:
            await client.aclose()

    _run(_body())


def test_int_vs_float_drift_is_payload_mismatch() -> None:
    """1 and 1.0 canonicalize to distinct bytes ('1' vs '1.0') → PAYLOAD_MISMATCH."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            challenge, otp = await _stage(engine, ident, alias, {"amount": 1})
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), {"amount": 1.0}, otp, challenge
                )
            assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
        finally:
            await client.aclose()

    _run(_body())


def test_extra_argument_key_is_payload_mismatch() -> None:
    """An added argument key changes the canonical payload → PAYLOAD_MISMATCH."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            challenge, otp = await _stage(engine, ident, alias, {"a": 1})
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), {"a": 1, "b": 2}, otp, challenge
                )
            assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
        finally:
            await client.aclose()

    _run(_body())


def test_removed_argument_key_is_payload_mismatch() -> None:
    """A dropped argument key changes the canonical payload → PAYLOAD_MISMATCH."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            challenge, otp = await _stage(engine, ident, alias, {"a": 1, "b": 2})
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), {"a": 1}, otp, challenge
                )
            assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
        finally:
            await client.aclose()

    _run(_body())


def test_nested_argument_drift_is_payload_mismatch() -> None:
    """A byte of drift deep in a nested container still changes the hash → mismatch."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            challenge, otp = await _stage(
                engine, ident, alias, {"filter": {"scope": ["a", "b"]}}
            )
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), {"filter": {"scope": ["a", "c"]}}, otp, challenge
                )
            assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
        finally:
            await client.aclose()

    _run(_body())


def test_wrong_alias_at_consume_is_payload_mismatch() -> None:
    """The alias is one of the four bound fields — a different alias → PAYLOAD_MISMATCH."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-alias"}
            challenge, otp = await _stage(engine, ident, alias, args)
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(_uid("other")), args, otp, challenge
                )
            assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
        finally:
            await client.aclose()

    _run(_body())


def test_lock_payload_hash_is_key_order_independent() -> None:
    """The bound hash is a PURE function of canonical_json — key order cannot change it."""
    tenant, agent, alias = _uid("t"), _uid("a"), _uid("s")
    h1 = lock_payload_hash(tenant, agent, alias, {"x": 1, "y": 2})
    h2 = lock_payload_hash(tenant, agent, alias, {"y": 2, "x": 1})
    assert h1 == h2


def test_lock_payload_hash_changes_with_each_bound_field() -> None:
    """tenant, agent, alias, and arguments EACH bind the hash — any change diverges it."""
    tenant, agent, alias, args = _uid("t"), _uid("a"), _uid("s"), {"k": "v"}
    base = lock_payload_hash(tenant, agent, alias, args)
    assert lock_payload_hash(_uid("t"), agent, alias, args) != base
    assert lock_payload_hash(tenant, _uid("a"), alias, args) != base
    assert lock_payload_hash(tenant, agent, _uid("s"), args) != base
    assert lock_payload_hash(tenant, agent, alias, {"k": "w"}) != base


# ===========================================================================
# 3. Identity binding — a PIN for A cannot be spent by B / another tenant.
# ===========================================================================


def test_agent_b_cannot_consume_agent_a_lock_payload_mismatch() -> None:
    """A PIN issued for agent A cannot be consumed by agent B → PAYLOAD_MISMATCH."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            tenant = _uid("tenant")
            agent_a = _identity(tenant=tenant, agent=_uid("A"))
            agent_b = _identity(tenant=tenant, agent=_uid("B"))
            alias = _uid("skill")
            args = {"run_id": "PR-AB"}
            challenge, otp = await _stage(engine, agent_a, alias, args)
            # Same tenant → the lock key EXISTS, but agent_id is a bound field, so the
            # payload hash diverges: the deny is PAYLOAD_MISMATCH, not PIN_NOT_FOUND.
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    agent_b, _entry(alias), args, otp, challenge
                )
            assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
            # And A can still legitimately spend its own lock (B's attempt did not burn it).
            assert await engine.consume_and_execute(
                agent_a, _entry(alias), args, otp, challenge
            ) == 1
        finally:
            await client.aclose()

    _run(_body())


def test_tenant_b_cannot_consume_tenant_a_lock_pin_not_found() -> None:
    """A PIN staged in tenant A is invisible to tenant B → PIN_NOT_FOUND (scoped key)."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            agent = _uid("agent")
            tenant_a = _identity(tenant=_uid("A"), agent=agent)
            tenant_b = _identity(tenant=_uid("B"), agent=agent)
            alias = _uid("skill")
            args = {"run_id": "PR-XT"}
            challenge, otp = await _stage(engine, tenant_a, alias, args)
            # The lock key is tenant-scoped, so tenant B addresses a different (absent)
            # key entirely — the deny is PIN_NOT_FOUND (structural isolation).
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    tenant_b, _entry(alias), args, otp, challenge
                )
            assert exc.value.reason is DenyReason.PIN_NOT_FOUND
        finally:
            await client.aclose()

    _run(_body())


def test_lock_binds_exactly_the_four_fields_not_compartment() -> None:
    """The lock binds EXACTLY {tenant,agent,alias,arguments} — compartment is NOT a lock
    input (compartment isolation is a SEPARATE upstream gate), so a same-tenant/agent
    consume under a different compartment still spends the lock."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            tenant, agent, alias = _uid("t"), _uid("a"), _uid("s")
            staged = _identity(tenant=tenant, agent=agent, compartment=uuid.uuid4().hex)
            other_compartment = _identity(
                tenant=tenant, agent=agent, compartment=uuid.uuid4().hex
            )
            args = {"run_id": "PR-CMPT"}
            challenge, otp = await _stage(engine, staged, alias, args)
            assert await engine.consume_and_execute(
                other_compartment, _entry(alias), args, otp, challenge
            ) == 1
        finally:
            await client.aclose()

    _run(_body())


def test_lock_payload_hash_ignores_compartment() -> None:
    """``lock_payload_hash`` cannot depend on compartment — it never receives it."""
    tenant, agent, alias, args = _uid("t"), _uid("a"), _uid("s"), {"k": "v"}
    # Two calls with identical bound fields are byte-identical regardless of any
    # compartment the calling identity happens to carry.
    assert lock_payload_hash(tenant, agent, alias, args) == lock_payload_hash(
        tenant, agent, alias, args
    )


# ===========================================================================
# 4. TTL / expiry / attempt-budget lockout.
# ===========================================================================


def test_lock_ttl_is_armed_near_pin_ttl_seconds() -> None:
    """A freshly staged lock carries a bounded TTL (<= PIN_TTL_SECONDS), never eternal."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            challenge, _otp = await _stage(engine, ident, _uid("skill"), {"a": 1})
            pttl = await client.pttl(_lock_key(ident.tenant_id, challenge))
            assert 0 < pttl <= PIN_TTL_SECONDS * 1000
        finally:
            await client.aclose()

    _run(_body())


def test_expired_lock_consume_is_pin_not_found() -> None:
    """After the lock's TTL elapses, the correct PIN no longer spends → PIN_NOT_FOUND."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-TTL"}
            challenge, otp = await _stage(engine, ident, alias, args)
            # Collapse the TTL to a sliver and let it lapse (deterministic, no real wait).
            await client.pexpire(_lock_key(ident.tenant_id, challenge), 40)
            await asyncio.sleep(0.12)
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), args, otp, challenge
                )
            assert exc.value.reason is DenyReason.PIN_NOT_FOUND
        finally:
            await client.aclose()

    _run(_body())


def test_wrong_pin_is_pin_mismatch() -> None:
    """A wrong PIN over the correct payload → PIN_MISMATCH (distinct from mismatch/absent)."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-WP"}
            challenge, otp = await _stage(engine, ident, alias, args)
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), args, _wrong_pin(otp), challenge
                )
            assert exc.value.reason is DenyReason.PIN_MISMATCH
        finally:
            await client.aclose()

    _run(_body())


def test_four_wrong_pins_lock_survives_correct_still_allows() -> None:
    """Below the attempt budget the lock survives — the correct PIN still ALLOWs."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-4WRONG"}
            challenge, otp = await _stage(engine, ident, alias, args)
            bad = _wrong_pin(otp)
            for _ in range(PIN_MAX_ATTEMPTS - 1):  # 4 wrong attempts.
                with pytest.raises(GatewayDeny) as exc:
                    await engine.consume_and_execute(
                        ident, _entry(alias), args, bad, challenge
                    )
                assert exc.value.reason is DenyReason.PIN_MISMATCH
            assert await engine.consume_and_execute(
                ident, _entry(alias), args, otp, challenge
            ) == 1
        finally:
            await client.aclose()

    _run(_body())


def test_five_wrong_pins_self_destruct_then_pin_not_found() -> None:
    """At PIN_MAX_ATTEMPTS wrong PINs the lock self-destructs → later spend PIN_NOT_FOUND."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-5WRONG"}
            challenge, otp = await _stage(engine, ident, alias, args)
            bad = _wrong_pin(otp)
            for _ in range(PIN_MAX_ATTEMPTS):  # 5th wrong attempt deletes the lock.
                with pytest.raises(GatewayDeny) as exc:
                    await engine.consume_and_execute(
                        ident, _entry(alias), args, bad, challenge
                    )
                assert exc.value.reason is DenyReason.PIN_MISMATCH
            assert await client.exists(_lock_key(ident.tenant_id, challenge)) == 0
            with pytest.raises(GatewayDeny) as exc2:
                await engine.consume_and_execute(
                    ident, _entry(alias), args, otp, challenge
                )
            assert exc2.value.reason is DenyReason.PIN_NOT_FOUND
        finally:
            await client.aclose()

    _run(_body())


def test_wrong_payload_never_spends_a_pin_attempt() -> None:
    """Payload is compared BEFORE the PIN — many wrong-payload tries burn no attempts."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-PBP"}
            challenge, otp = await _stage(engine, ident, alias, args)
            for i in range(PIN_MAX_ATTEMPTS + 3):  # well past the wrong-PIN budget.
                with pytest.raises(GatewayDeny) as exc:
                    await engine.consume_and_execute(
                        ident, _entry(alias), {"run_id": f"drift-{i}"}, otp, challenge
                    )
                assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
            # No attempt was spent, so the correct payload+PIN still ALLOWs.
            assert await engine.consume_and_execute(
                ident, _entry(alias), args, otp, challenge
            ) == 1
        finally:
            await client.aclose()

    _run(_body())


# ===========================================================================
# 5. Rate limits — cheap pre-throttle guards on BOTH scrypt paths.
# ===========================================================================


def test_stepup_staging_rate_limited_before_mint() -> None:
    """Over the staging window an identity fails closed RATE_LIMITED before minting."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            # Exhaust the fixed window with the cheap pre-check only (no scrypt spent).
            for _ in range(_STEPUP_RATE_MAX):
                await engine._enforce_stepup_rate(ident)  # type: ignore[attr-defined]
            with pytest.raises(GatewayDeny) as exc:
                await engine.register_lock(
                    ident, _uid("skill"), {"a": 1}, RiskTier.PIN_REQUIRED
                )
            assert exc.value.reason is DenyReason.RATE_LIMITED
        finally:
            await client.aclose()

    _run(_body())


def test_consume_completion_rate_limited_and_lock_untouched() -> None:
    """A completion flood is refused RATE_LIMITED with O(1) work — the lock is NOT spent."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-CRATE"}
            challenge, otp = await _stage(engine, ident, alias, args)
            for _ in range(_CONSUME_RATE_MAX):
                await engine._enforce_consume_rate(ident)  # type: ignore[attr-defined]
            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), args, otp, challenge
                )
            assert exc.value.reason is DenyReason.RATE_LIMITED
            # The throttle precedes the atomic Lua, so the lock was never reached/spent.
            assert await client.exists(_lock_key(ident.tenant_id, challenge)) == 1
        finally:
            await client.aclose()

    _run(_body())


def test_stage_and_consume_use_distinct_rate_namespaces() -> None:
    """A normal stage→consume pair never self-contends: the two counters are distinct."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-NS"}
            challenge, otp = await _stage(engine, ident, alias, args)
            assert await engine.consume_and_execute(
                ident, _entry(alias), args, otp, challenge
            ) == 1
            stepup_key = f"mcpip:stepup:rate:{ident.tenant_id}:{ident.agent_id}"
            consume_key = f"mcpip:consume:rate:{ident.tenant_id}:{ident.agent_id}"
            # One stage + one consume → each counter reads exactly 1 (they do not share).
            assert await client.get(stepup_key) == "1"
            assert await client.get(consume_key) == "1"
        finally:
            await client.aclose()

    _run(_body())


# ===========================================================================
# 6. Concurrency — no double-spend of a single lock.
# ===========================================================================


def test_two_concurrent_consumers_exactly_one_wins() -> None:
    """Two callers racing on ONE lock → exactly one ALLOW, the other PIN_NOT_FOUND."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-RACE2"}
            challenge, otp = await _stage(engine, ident, alias, args)
            results = await asyncio.gather(
                *[
                    engine.consume_and_execute(ident, _entry(alias), args, otp, challenge)
                    for _ in range(2)
                ],
                return_exceptions=True,
            )
            wins = [r for r in results if r == 1]
            denies = [r for r in results if isinstance(r, GatewayDeny)]
            assert len(wins) == 1, results
            assert len(denies) == 1
            assert denies[0].reason is DenyReason.PIN_NOT_FOUND
        finally:
            await client.aclose()

    _run(_body())


def test_ten_concurrent_consumers_exactly_one_wins() -> None:
    """A 10-way concurrent consume of ONE lock → exactly one ALLOW, nine denied."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-RACE10"}
            challenge, otp = await _stage(engine, ident, alias, args)
            results = await asyncio.gather(
                *[
                    engine.consume_and_execute(ident, _entry(alias), args, otp, challenge)
                    for _ in range(10)
                ],
                return_exceptions=True,
            )
            assert sum(1 for r in results if r == 1) == 1, results
            denies = [r for r in results if isinstance(r, GatewayDeny)]
            assert len(denies) == 9
            assert all(d.reason is DenyReason.PIN_NOT_FOUND for d in denies)
        finally:
            await client.aclose()

    _run(_body())


# ===========================================================================
# 7. Write-before-execute — WORM record durable BEFORE dispatch.
# ===========================================================================


async def _fresh_worm(client: Any) -> WormLogger:
    """A WormLogger on a freshly-flushed db (deterministic genesis chain, no anchor)."""
    await client.flushdb()
    return WormLogger(
        client,
        Ed25519PrivateKey.generate(),
        path="/tmp/_cross_stepup_worm.jsonl",
        mode="epoch",
        anchor=None,
    )


def test_allow_record_is_durable_before_dispatch() -> None:
    """The ALLOW WORM record is already durable in the buffer at dispatch time."""

    async def _body() -> None:
        client = _client(_WORM_DB)
        try:
            worm = await _fresh_worm(client)
            dispatcher = _RecordingDispatcher(client)
            cid = new_correlation_id()
            receipt = await _gate_allow(
                worm,
                dispatcher,
                {"decision": "allow", "alias": _uid("skill"), "correlation_id": cid},
            )
            assert receipt.seq >= 1
            assert dispatcher.dispatched is True
            assert dispatcher.record_present_at_dispatch is True
        finally:
            await client.aclose()

    _run(_body())


def test_failed_worm_emit_denies_and_never_dispatches() -> None:
    """A failed durable emit is a fail-closed DENY — the action never dispatches."""

    async def _body() -> None:
        client = _client(_WORM_DB)
        try:
            dispatcher = _RecordingDispatcher(client)
            with pytest.raises(GatewayDeny) as exc:
                await _gate_allow(
                    _BrokenWorm(),
                    dispatcher,
                    {"decision": "allow", "alias": _uid("skill")},
                )
            assert exc.value.reason is DenyReason.INTERNAL
            assert dispatcher.dispatched is False  # no dropped log line, no dispatch.
        finally:
            await client.aclose()

    _run(_body())


def test_staged_pin_required_decision_is_audited() -> None:
    """The staged (PIN_REQUIRED) decision is itself written to the WORM buffer."""

    async def _body() -> None:
        client = _client(_WORM_DB)
        try:
            worm = await _fresh_worm(client)
            cid = new_correlation_id()
            await worm.emit(
                {
                    "decision": "deny",
                    "deny_reason": DenyReason.PIN_REQUIRED.value,
                    "alias": _uid("skill"),
                    "risk_tier": RiskTier.PIN_REQUIRED.value,
                    "correlation_id": cid,
                }
            )
            event = await _latest_event(client)
            assert event is not None
            assert event["deny_reason"] == "pin_required"
            assert event["correlation_id"] == cid
        finally:
            await client.aclose()

    _run(_body())


def test_staged_then_consumed_worm_records_in_order() -> None:
    """The staged→consumed transition emits pin_required THEN allow, in seq order."""

    async def _body() -> None:
        client = _client(_WORM_DB)
        try:
            worm = await _fresh_worm(client)
            alias = _uid("skill")
            cid = new_correlation_id()
            staged = await worm.emit(
                {"decision": "deny", "deny_reason": "pin_required",
                 "alias": alias, "correlation_id": cid}
            )
            allowed = await worm.emit(
                {"decision": "allow", "alias": alias, "correlation_id": cid}
            )
            assert staged.seq < allowed.seq  # write-order preserved on the durable buffer.
            stage_ev = await _event_by_id(client, staged.event_id)
            allow_ev = await _event_by_id(client, allowed.event_id)
            assert stage_ev is not None and stage_ev["deny_reason"] == "pin_required"
            assert allow_ev is not None and allow_ev["decision"] == "allow"
        finally:
            await client.aclose()

    _run(_body())


def test_worm_record_carries_reason_while_envelope_is_opaque() -> None:
    """The concrete deny reason lives ONLY in the WORM record — the caller sees opacity."""

    async def _body() -> None:
        client = _client(_WORM_DB)
        try:
            worm = await _fresh_worm(client)
            cid = new_correlation_id()
            await worm.emit(
                {"decision": "deny", "deny_reason": DenyReason.PIN_NOT_FOUND.value,
                 "alias": _uid("skill"), "correlation_id": cid}
            )
            event = await _latest_event(client)
            assert event is not None and event["deny_reason"] == "pin_not_found"
            # The agent-facing envelope carries the generic message + id, nothing more.
            envelope = _opaque_envelope(cid)
            assert set(envelope) == {"error", "correlation_id"}
            assert envelope["error"] == AGENT_FACING_DENY_MESSAGE
            assert "pin_not_found" not in json.dumps(envelope)
        finally:
            await client.aclose()

    _run(_body())


def test_audited_ceremony_seals_into_intact_signed_chain() -> None:
    """Staged + consumed records seal into a signed epoch that verify_chain accepts."""

    async def _body() -> None:
        client = _client(_WORM_DB)
        try:
            worm = await _fresh_worm(client)
            alias = _uid("skill")
            await worm.emit({"decision": "deny", "deny_reason": "pin_required", "alias": alias})
            await worm.emit({"decision": "allow", "alias": alias})
            header = await worm.close_epoch()
            assert header is not None and header.epoch == 0 and header.leaf_count == 2
            intact, first_bad = await worm.verify_chain()
            assert intact is True and first_bad is None
        finally:
            await client.aclose()

    _run(_body())


def test_tampering_the_sealed_ceremony_record_is_detected() -> None:
    """Erasing the sealed decision content reads as TAMPER (verify_chain fails closed)."""

    async def _body() -> None:
        client = _client(_WORM_DB)
        try:
            worm = await _fresh_worm(client)
            await worm.emit({"decision": "allow", "alias": _uid("skill")})
            header = await worm.close_epoch()
            assert header is not None and header.epoch == 0
            intact, _ = await worm.verify_chain()
            assert intact is True
            # A Redis-write attacker erases the epoch's decision content; the signed
            # header/root/counters are left untouched (the "looks like trimming" attack).
            entries: Any = await client.xrange(_EVENTS_STREAM, min="-", max="+")
            for sid, _fields in entries:
                await client.xdel(_EVENTS_STREAM, sid)
            intact2, first_bad2 = await worm.verify_chain()
            assert intact2 is False and first_bad2 == 0
        finally:
            await client.aclose()

    _run(_body())


def test_pin_and_otp_are_redacted_before_persistence() -> None:
    """PIN/OTP-shaped fields are scrubbed by the WORM redaction pass before any write."""
    otp = "424242"
    redacted = _redact(
        {
            "pin": otp,
            "otp": otp,
            "aws_secret_access_key": "AKIAsecret",
            "alias": "skill_payroll_run",
            "decision": "allow",
        }
    )
    assert redacted["pin"] == "[REDACTED]"
    assert redacted["otp"] == "[REDACTED]"
    assert redacted["aws_secret_access_key"] == "[REDACTED]"
    assert redacted["alias"] == "skill_payroll_run"  # non-secret survives.
    assert otp not in json.dumps(redacted)


def test_opaque_envelope_and_challenge_never_leak_otp_or_target() -> None:
    """Neither the 202-staging body nor the deny envelope leaks the OTP or real target."""

    async def _body() -> None:
        client = _client(_AUTH_DB)
        try:
            engine = _engine(client)
            ident = _identity()
            alias = _uid("skill")
            challenge, otp = await _stage(engine, ident, alias, {"a": 1})
            real_target = "cloud://payroll.internal/run"  # the hidden downstream.

            # The 202-equivalent staging body carries the opaque challenge id ONLY.
            staged_body = {"challenge_id": challenge}
            assert "otp" not in staged_body and "pin" not in staged_body
            assert otp not in staged_body.values()
            assert real_target not in json.dumps(staged_body)

            # The eventual deny envelope carries the generic message + correlation id ONLY.
            envelope = _opaque_envelope(new_correlation_id())
            assert otp not in envelope.values()
            assert real_target not in json.dumps(envelope)
        finally:
            await client.aclose()

    _run(_body())


# ===========================================================================
# 8. Full cross ceremony — real stage/consume × ordered, leak-free WORM.
# ===========================================================================


def test_full_ceremony_stage_consume_emits_ordered_records_no_leak() -> None:
    """A real stage→consume writes pin_required then allow, in order, leaking no OTP."""

    async def _body() -> None:
        auth = _client(_AUTH_DB)
        worm_c = _client(_WORM_DB)
        try:
            engine = _engine(auth)
            worm = await _fresh_worm(worm_c)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-E2E", "cycle": "monthly"}
            cid = new_correlation_id()

            # Stage (audited BEFORE the challenge is usable) …
            challenge, otp = await _stage(engine, ident, alias, args)
            staged = await worm.emit(
                {"decision": "deny", "deny_reason": "pin_required",
                 "alias": alias, "correlation_id": cid}
            )
            # … then spend exactly once, audited (ALLOW) BEFORE any dispatch.
            assert await engine.consume_and_execute(
                ident, _entry(alias), args, otp, challenge
            ) == 1
            allowed = await worm.emit(
                {"decision": "allow", "alias": alias, "correlation_id": cid}
            )

            assert staged.seq < allowed.seq
            header = await worm.close_epoch()
            assert header is not None
            intact, first_bad = await worm.verify_chain()
            assert intact is True and first_bad is None
            # The raw one-time code never rode either persisted record.
            dump: Any = await worm_c.xrange(_EVENTS_STREAM, min="-", max="+")
            blob = "".join(fields.get("record", "") for _sid, fields in dump)
            assert otp not in blob
        finally:
            await auth.aclose()
            await worm_c.aclose()

    _run(_body())


def test_replay_after_ceremony_denies_and_worm_logs_pin_not_found() -> None:
    """After a completed ceremony, a replay denies and the WORM logs pin_not_found."""

    async def _body() -> None:
        auth = _client(_AUTH_DB)
        worm_c = _client(_WORM_DB)
        try:
            engine = _engine(auth)
            worm = await _fresh_worm(worm_c)
            ident = _identity()
            alias = _uid("skill")
            args = {"run_id": "PR-REPLAY"}
            challenge, otp = await _stage(engine, ident, alias, args)
            assert await engine.consume_and_execute(
                ident, _entry(alias), args, otp, challenge
            ) == 1

            with pytest.raises(GatewayDeny) as exc:
                await engine.consume_and_execute(
                    ident, _entry(alias), args, otp, challenge
                )
            assert exc.value.reason is DenyReason.PIN_NOT_FOUND
            # The concrete reason is what the durable audit trail records.
            cid = new_correlation_id()
            await worm.emit(
                {"decision": "deny", "deny_reason": exc.value.reason.value,
                 "alias": alias, "correlation_id": cid}
            )
            event = await _latest_event(worm_c)
            assert event is not None and event["deny_reason"] == "pin_not_found"
            assert "pin_not_found" not in json.dumps(_opaque_envelope(cid))
        finally:
            await auth.aclose()
            await worm_c.aclose()

    _run(_body())
