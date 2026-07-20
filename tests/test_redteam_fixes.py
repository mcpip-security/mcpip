"""
Red-team regression suite — one focused test per CONFIRMED finding fixed in this pass.

Each test targets the SPECIFIC weakness and asserts the invariant the fix restores, so it
fails against the pre-fix code and passes after. Findings validated elsewhere:
  * pin-lock-parity Rust category check — ``tests/test_fastwalk_differential.py`` (the
    differential gate; the new ``_FORMAT_MARKS`` corpus diverges on the unfixed walker).
  * /metrics deny_reason oracle — ``tests/test_release_hooks.py`` (asserts the concrete
    reason is absent from the exposition).

Covered here (direct component tests against the real Redis on :63790, no mocks of the
unit under test):
  * worm-audit/whole-epoch-event-deletion-undetected
  * worm-audit/close-epoch-crash-dup-header
  * obfuscation-canary/skill-gate-reopens-compartment-existence-timing-oracle
  * new-features-composition/overlay-additive-only-split-brain-repoint
  * dos-resource/scrypt-consume-unthrottled
"""

from __future__ import annotations

import os

# Namespaced sandbox env before importing app.main (settings are lru_cached at first
# import; in a single ``pytest tests/`` run an earlier module may already have frozen the
# db — the _resolve_alias test below spies on component methods and is db-agnostic).
_TEST_REDIS_URL = "redis://localhost:63790/12"
os.environ.setdefault("MCPIP_REDIS_URL", _TEST_REDIS_URL)
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_redteam_worm.jsonl"),
)

import asyncio
import types
from typing import Any

import pytest
import redis.asyncio as aioredis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.worm_logger import (
    WormLogger,
    _CURSOR_KEY,
    _EPOCHS_STREAM,
    _EPOCH_HEAD_KEY,
    _EPOCH_INDEX_KEY,
    _EPOCH_LAST_SEQ_KEY,
    _EPOCH_LEAVES_KEY,
    _EPOCH_NUM_KEY,
    _EPOCH_STREAMID_KEY,
    _EVENTLOC_KEY,
    _EVENTS_STREAM,
)
from core.security import GatewayDeny
from interfaces import DenyReason, Identity
from services.auth_engine import AuthEngine, _CONSUME_RATE_MAX
from services.catalog_overlay import CatalogOverlayStore

_WORM_DB_URL = "redis://localhost:63790/14"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


async def _fresh_worm() -> tuple[Any, WormLogger, str]:
    """A WormLogger on a dedicated, freshly-flushed db with NO anchor (counters-only)."""
    client: Any = aioredis.from_url(_WORM_DB_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    await client.flushdb()
    key = Ed25519PrivateKey.generate()
    logger = WormLogger(client, key, path="/tmp/_redteam_worm.jsonl", mode="epoch", anchor=None)
    return client, logger, _WORM_DB_URL


# ---------------------------------------------------------------------------
# worm-audit/whole-epoch-event-deletion-undetected
# ---------------------------------------------------------------------------
def test_whole_epoch_event_deletion_within_hot_window_is_tamper() -> None:
    """Deleting EVERY event of a hot epoch must read as TAMPER, not a legitimate trim.

    Pre-fix, ``_verify_header_fields`` treated ``present == []`` as "trimmed" for ANY
    epoch and verified signature-only, so wiping all of a recent epoch's decision content
    left ``verify_chain`` reporting intact. The fix ties full-presence to the retention
    low-watermark: an epoch above it must have ALL its events buffered.
    """

    async def _body() -> None:
        client, logger, _ = await _fresh_worm()
        try:
            for i in range(4):
                await logger.emit({"decision": "allow", "alias": f"skill_{i}", "seq_probe": i})
            header = await logger.close_epoch()
            assert header is not None and header.epoch == 0
            intact, first_bad = await logger.verify_chain()
            assert intact and first_bad is None, "fresh sealed chain must verify intact"

            # Delete EVERY event of epoch 0 from the durable buffer (a Redis-write attacker
            # erasing recent decision content). The signed header/root/counters are left
            # UNTOUCHED — exactly the "looks like retention trimming" attack.
            entries: Any = await client.xrange(_EVENTS_STREAM, min="-", max="+")
            for sid, _fields in entries:
                await client.xdel(_EVENTS_STREAM, sid)
            assert await client.xlen(_EVENTS_STREAM) == 0

            intact2, first_bad2 = await logger.verify_chain()
            assert not intact2, "whole-epoch event deletion inside the hot window must be tamper"
            assert first_bad2 == 0
        finally:
            await client.aclose()

    _run(_body())


# ---------------------------------------------------------------------------
# worm-audit/close-epoch-crash-dup-header
# ---------------------------------------------------------------------------
def test_close_epoch_commit_is_atomic_and_dedup_guarded() -> None:
    """Re-close is idempotent and a duplicate epoch header can never be appended.

    The commit (header XADD + all four linkage counters + indexes) is one atomic Lua
    script with an anti-dup guard. A normal re-close reads an empty tail and appends
    nothing; a stray re-commit of an already-committed epoch is refused by the guard. The
    companion assertion documents the threat: a RAW injected duplicate header (the state
    the old non-atomic close could leave after a crash) wedges verify_chain — which is
    exactly what the atomic commit + guard now prevent.
    """

    async def _body() -> None:
        client, logger, _ = await _fresh_worm()
        try:
            for i in range(3):
                await logger.emit({"decision": "allow", "alias": f"skill_{i}"})
            h0 = await logger.close_epoch()
            assert h0 is not None and h0.epoch == 0
            assert await client.xlen(_EPOCHS_STREAM) == 1
            intact, _ = await logger.verify_chain()
            assert intact

            # (1) Normal re-close: the cursor already advanced, so the tail is empty and
            # NO new (or duplicate) header is produced. Idempotent across a restart.
            assert await logger.close_epoch() is None
            assert await client.xlen(_EPOCHS_STREAM) == 1
            intact, _ = await logger.verify_chain()
            assert intact

            # (2) Anti-dup guard: a re-commit for the ALREADY-committed epoch 0 (epoch <=
            # the committed epoch:num) appends NO second header — the guard returns the
            # stored streamid instead of XADD-ing. Args model the smallest valid commit
            # (X=0 XADD tokens, E=0 eventloc tokens) for epoch 0.
            keys = [
                _EPOCHS_STREAM,
                _EPOCH_INDEX_KEY,
                _EPOCH_STREAMID_KEY,
                _EVENTLOC_KEY,
                _EPOCH_LEAVES_KEY,
                _EPOCH_NUM_KEY,
                _EPOCH_HEAD_KEY,
                _EPOCH_LAST_SEQ_KEY,
                _CURSOR_KEY,
            ]
            await logger._close_commit_script(  # type: ignore[attr-defined]
                keys=keys,
                args=["0", "{}", "[]", "deadbeef", "3", "0-0", "0", "0"],
            )
            assert await client.xlen(_EPOCHS_STREAM) == 1, "guard must refuse a duplicate header"
            intact, _ = await logger.verify_chain()
            assert intact, "chain stays intact — no duplicate epoch-0 header exists"

            # (3) Threat documentation: a RAW duplicate epoch-0 header (bypassing the guard,
            # as the old crash bug produced) DOES wedge verify — proving the guard/atomicity
            # is load-bearing.
            dup = dict((await client.xrange(_EPOCHS_STREAM, min="-", max="+"))[0][1])
            dup["timestamp_ns"] = str(int(dup["timestamp_ns"]) + 1)  # fresh ts => diff hash.
            await client.xadd(_EPOCHS_STREAM, dup)
            intact_after, _ = await logger.verify_chain()
            assert not intact_after, "a duplicate trailing epoch header must read as tamper"
        finally:
            await client.aclose()

    _run(_body())


# ---------------------------------------------------------------------------
# new-features-composition/overlay-additive-only-split-brain-repoint
# ---------------------------------------------------------------------------
def test_catalog_overlay_add_is_atomic_additive_only() -> None:
    """``add`` never repoints an existing overlay alias — a second add is refused, not overwritten.

    Pre-fix ``add`` used a blind ``HSET`` (last-write-wins) and returned nothing, so a
    second admin register / community approval racing on another worker (whose stale
    in-memory ``has_alias`` said "absent") could silently repoint the alias to an attacker
    target. The fix makes ``add`` an atomic ``HSETNX`` returning whether it created the
    field; a second add returns False and leaves the ORIGINAL target intact.
    """

    async def _body() -> None:
        client: Any = aioredis.from_url("redis://localhost:63790/15", decode_responses=True)  # type: ignore[no-untyped-call]
        await client.flushdb()
        try:
            store = CatalogOverlayStore(client)
            tenant = "tenant-acme"
            alias = "skill_new_overlay"
            honest = {"target": "cloud://honest", "transport": "cloud_rest"}
            attacker = {"target": "cloud://attacker", "transport": "cloud_rest"}

            assert await store.exists(tenant, alias) is False
            created = await store.add(tenant, alias, honest)
            assert created is True, "first add creates the field"
            assert await store.exists(tenant, alias) is True

            # A concurrent second worker's blind add MUST NOT repoint.
            recreated = await store.add(tenant, alias, attacker)
            assert recreated is False, "an already-present alias is an additive-only refusal"
            stored = await store.get(tenant, alias)
            assert stored == honest, "the original target is preserved — never repointed"
        finally:
            await client.aclose()

    _run(_body())


# ---------------------------------------------------------------------------
# obfuscation-canary/skill-gate-reopens-compartment-existence-timing-oracle
# ---------------------------------------------------------------------------
def test_resolve_miss_pays_same_round_trips_as_compartment_denied() -> None:
    """An unknown-alias denial spends the SAME Redis round trips as a resolve-then-denied one.

    The resolve-succeeds-then-denied path spends TWO round trips before denying: the
    step-4a′ ``skill_gate.is_disabled`` SISMEMBER and the compartment gate's
    ``grants.has_active_grant`` GET. Pre-fix the resolve-MISS decoy paid only the grant
    GET, so ``is_disabled`` reintroduced a one-round-trip existence oracle. The fix adds a
    decoy ``is_disabled`` to the miss path so both denial families pay is_disabled + grant.
    """

    async def _body() -> None:
        import app.main as app_main

        skill_calls = {"n": 0}
        grant_calls = {"n": 0}
        real_is_disabled = app_main._components.skill_gate.is_disabled
        real_has_grant = app_main._components.grants.has_active_grant

        # Pure counting stubs (do NOT touch the app's redis client — it is bound to the
        # app-startup event loop, not this asyncio.run loop, so calling through would be
        # cross-loop-fragile in a full-suite run). We assert only the round-trip COUNT
        # parity, which is exactly the timing-oracle property under test.
        async def _spy_is_disabled(tenant_id: str, alias: str) -> bool:
            skill_calls["n"] += 1
            return False

        async def _spy_has_grant(tenant_id: str, agent_id: str, compartment: str) -> bool:
            grant_calls["n"] += 1
            return False

        app_main._components.skill_gate.is_disabled = _spy_is_disabled  # type: ignore[method-assign]
        app_main._components.grants.has_active_grant = _spy_has_grant  # type: ignore[method-assign]
        try:
            identity = Identity(
                tenant_id="tenant-acme", agent_id="agent-x", role="worker",
                issuer="test-idp", audience="mcpip",
            )
            with pytest.raises(Exception):
                await app_main._resolve_alias(identity, "skill_definitely_unknown_xyz")
            # The miss path pays EXACTLY the two decoy round trips the denied path pays:
            # one is_disabled SISMEMBER + one has_active_grant GET.
            assert skill_calls["n"] == 1, "resolve-miss must pay the decoy is_disabled SISMEMBER"
            assert grant_calls["n"] == 1, "resolve-miss must still pay the decoy grant GET"
        finally:
            app_main._components.skill_gate.is_disabled = real_is_disabled  # type: ignore[method-assign]
            app_main._components.grants.has_active_grant = real_has_grant  # type: ignore[method-assign]

    _run(_body())


# ---------------------------------------------------------------------------
# dos-resource/scrypt-consume-unthrottled
# ---------------------------------------------------------------------------
class _FakePin:
    """Records whether the memory-hard consume (scrypt) was reached."""

    def __init__(self) -> None:
        self.consume_calls = 0

    async def register(self, *a: Any, **k: Any) -> str:  # pragma: no cover - unused here.
        return "lock"

    async def consume(self, *a: Any, **k: Any) -> int:
        self.consume_calls += 1
        return 1


def test_consume_path_is_rate_limited_before_scrypt() -> None:
    """A PIN-completion flood is throttled with O(1) work BEFORE any scrypt derivation.

    Pre-fix, ``consume_and_execute`` went straight into ``PinValidator.consume``, which
    derives the memory-hard scrypt PIN hash BEFORE the atomic Lua even checks the challenge
    exists — an unthrottled CPU/RAM amplifier. The fix adds a per-identity consume-side
    fixed-window throttle ahead of the derivation; once the window is exhausted, completion
    fails closed with RATE_LIMITED and NEVER reaches ``consume`` (scrypt).
    """

    async def _body() -> None:
        client: Any = aioredis.from_url("redis://localhost:63790/13", decode_responses=True)  # type: ignore[no-untyped-call]
        await client.flushdb()
        try:
            fake = _FakePin()
            engine = AuthEngine(resolver=None, pin=fake, redis_client=client, channel=None)  # type: ignore[arg-type]
            identity = Identity(
                tenant_id="tenant-acme", agent_id="agent-flood", role="worker",
                issuer="test-idp", audience="mcpip",
            )
            entry = types.SimpleNamespace(alias="skill_x")

            # Exhaust the consume window with the cheap pre-check ONLY (no scrypt): the
            # throttle must trip at count > _CONSUME_RATE_MAX.
            for _ in range(_CONSUME_RATE_MAX):
                await engine._enforce_consume_rate(identity)  # type: ignore[attr-defined]
            with pytest.raises(GatewayDeny) as exc:
                await engine._enforce_consume_rate(identity)  # type: ignore[attr-defined]
            assert exc.value.reason is DenyReason.RATE_LIMITED

            # Now a real completion attempt from this flooded identity must fail closed
            # WITHOUT reaching scrypt (fake.consume never called).
            with pytest.raises(GatewayDeny) as exc2:
                await engine.consume_and_execute(
                    identity, entry, {"a": 1}, "000000", "challenge-x"  # type: ignore[arg-type]
                )
            assert exc2.value.reason is DenyReason.RATE_LIMITED
            assert fake.consume_calls == 0, "throttle must precede the memory-hard consume/scrypt"
        finally:
            await client.aclose()

    _run(_body())
