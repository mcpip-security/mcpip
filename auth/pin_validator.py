"""
MCPIP V2 — Auth: canonical payload lock (TOCTOU-proof PIN).

    ◐ Auth: "A payload-bound PIN that's spent exactly once, or the action never runs."

A high-risk action is gated by a 6-digit PIN that is cryptographically bound to the
SHA-256 of the CANONICAL JSON of exactly four fields — tenant_id, agent_id, alias,
arguments. One byte of drift between authorization and execution changes the hash and
the action is denied.

Consumption is EXACTLY-ONCE and atomic: a single Redis Lua EVAL performs
fetch → compare payload → compare PIN → delete, entirely server-side. Python does
ZERO check-then-act on lock state (no TOCTOU window). We never store the raw PIN;
what we store is a scrypt-derived digest SALTED by (tenant_id, lock_id,
payload_hash) — never a plain unsalted SHA-256 of a 6-digit value. The salt makes
each lock's digest unique (no precomputation/rainbow reuse) and scrypt's memory-hard
cost turns the 10^6-keyspace offline brute force from instant into expensive, even
for someone who scrapes the full Redis record. The derivation is byte-identical at
register and consume, so exactly-once + payload-binding are preserved. The PIN-hash
comparison is constant-time (a no-early-exit XOR-fold over both hex digests), so it
never leaks the stored digest through timing.

Return codes from the script (mapped to DenyReason by the gateway):
    1  → OK       (consumed + deleted)
   -1  → NOT_FOUND
   -2  → PIN_MISMATCH   (attempt counted; lock self-destructs at PIN_MAX_ATTEMPTS)
   -3  → PAYLOAD_MISMATCH (no attempt spent; a correct-payload retry survives)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Final

import redis.asyncio as redis
from redis.exceptions import RedisError

from interfaces import (
    PIN_LENGTH,
    PIN_MAX_ATTEMPTS,
    PIN_TTL_SECONDS,
    canonical_json,
    sha256_hex,
)

# Exact decimal-PIN shape: exactly PIN_LENGTH digits, nothing else.
_PIN_RE = re.compile(rf"^\d{{{PIN_LENGTH}}}$")

# scrypt cost parameters for the salted PIN derivation. n=2**14 gives a memory-hard
# ~16 MiB work factor per guess (128 * r * n bytes); dklen=32 yields a 64-char hex
# digest — identical width to the previous SHA-256, so the Lua constant-time compare
# (which asserts a fixed 64-char length) is unchanged. maxmem is set with headroom so
# OpenSSL does not reject the allocation.
_SCRYPT_N: Final[int] = 2 ** 14
_SCRYPT_R: Final[int] = 8
_SCRYPT_P: Final[int] = 1
_SCRYPT_DKLEN: Final[int] = 32
_SCRYPT_MAXMEM: Final[int] = 64 * 1024 * 1024

# DEDICATED, BOUNDED scrypt pool. Each derivation is memory-hard (~16 MiB, tens of ms);
# an authenticated attacker who spams PIN staging/consume could otherwise pin every
# worker of the shared default ``asyncio.to_thread`` executor (<=32) AND flood ~1 GiB of
# transient RAM, starving every other off-loop task (finding: scrypt CPU+memory DoS
# amplifier). Confining scrypt to its OWN small pool HARD-CAPS concurrent derivations —
# bounding peak scrypt RAM to ~``_SCRYPT_MAX_CONCURRENCY * 16 MiB`` and leaving the
# default executor free for unrelated I/O — while the cost/salt/output are byte-identical,
# so exactly-once + payload binding + brute-force resistance are all preserved. Excess
# derivations QUEUE on this pool rather than being refused, so correctness never depends
# on the cap.
_SCRYPT_MAX_CONCURRENCY: Final[int] = max(1, min(4, (os.cpu_count() or 1)))
_SCRYPT_EXECUTOR: Final[ThreadPoolExecutor] = ThreadPoolExecutor(
    max_workers=_SCRYPT_MAX_CONCURRENCY, thread_name_prefix="mcpip-scrypt"
)


async def _derive_pin_hash_bounded(
    pin: str, tenant_id: str, lock_id: str, payload_hash: str
) -> str:
    """Run the memory-hard derivation on the dedicated bounded scrypt pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _SCRYPT_EXECUTOR, _derive_pin_hash, pin, tenant_id, lock_id, payload_hash
    )


def _derive_pin_hash(
    pin: str, tenant_id: str, lock_id: str, payload_hash: str
) -> str:
    """
    Derive the stored/compared PIN digest, salted by the lock's own identity.

    The salt binds the digest to (tenant_id, lock_id, payload_hash): the same PIN
    yields a different digest for every lock, defeating precomputation, and scrypt's
    memory-hard cost defeats the instant offline brute force of the 10^6 PIN
    keyspace. ``register`` and ``consume`` call this IDENTICALLY, so the atomic
    exactly-once compare and the payload binding are preserved byte-for-byte.
    """
    salt = canonical_json(
        {"tenant_id": tenant_id, "lock_id": lock_id, "payload_hash": payload_hash}
    )
    derived = hashlib.scrypt(
        pin.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=_SCRYPT_MAXMEM,
    )
    return derived.hex()


# ---------------------------------------------------------------------------
# §2.4  EXACT Lua script (verbatim). Registered once, executed via EVALSHA.
# ---------------------------------------------------------------------------
#
# Payload is compared BEFORE the PIN on purpose: a tampered payload is rejected
# (-3) without spending a PIN attempt or destroying the lock, so a legitimate
# correct-payload retry still works; a wrong PIN (-2) increments attempts and, at
# the threshold, deletes the lock — killing brute force well inside the 300 s TTL.
LOCK_CONSUME_LUA: str = """local raw = redis.call('GET', KEYS[1])
if not raw then
  return -1
end
local rec = cjson.decode(raw)
if rec.payload ~= ARGV[2] then
  return -3
end
-- Constant-time PIN-hash comparison (invariant #1): secrets.compare_digest is
-- unavailable server-side, so we XOR-fold every byte of the two 64-char hex
-- hashes into a single difference accumulator with NO early exit. The compare
-- time is independent of where (or whether) the hashes diverge, so a stored
-- pin_hash cannot be reconstructed byte-by-byte via response timing. The length
-- guard branches only on hash length (fixed 64, not secret). The 5-attempt
-- lockout remains the primary brute-force control.
local stored = rec.pin
local presented = ARGV[1]
local diff = 0
if #stored ~= #presented then
  diff = 1
else
  for i = 1, #stored do
    diff = bit.bor(diff, bit.bxor(string.byte(stored, i), string.byte(presented, i)))
  end
end
if diff ~= 0 then
  rec.attempts = (rec.attempts or 0) + 1
  if rec.attempts >= tonumber(ARGV[3]) then
    redis.call('DEL', KEYS[1])
  else
    local pttl = redis.call('PTTL', KEYS[1])
    if pttl and pttl > 0 then
      redis.call('SET', KEYS[1], cjson.encode(rec), 'PX', pttl)
    else
      redis.call('SET', KEYS[1], cjson.encode(rec))
    end
  end
  return -2
end
redis.call('DEL', KEYS[1])
return 1
"""


class LockError(Exception):
    """Raised when the lock cannot be created (collision / transport failure)."""


def lock_payload_hash(
    tenant_id: str, agent_id: str, alias: str, arguments: dict[str, Any]
) -> str:
    """
    Compute the payload hash bound to a PIN (§2.1).

    Hashes the canonical JSON of the four-field object. ``register`` and
    ``consume`` call this identically, so any drift in any field yields a
    different hash → PAYLOAD_MISMATCH.
    """
    return sha256_hex(
        canonical_json(
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "alias": alias,
                "arguments": arguments,
            }
        )
    )


def _lock_key(tenant_id: str, lock_id: str) -> str:
    """Tenant-scoped Redis key so one tenant can never touch another's lock."""
    return f"mcpip:pinlock:{tenant_id}:{lock_id}"


class PinValidator:
    """Registers and atomically consumes canonical payload locks."""

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client
        # Cache the script; the client uploads it once and prefers EVALSHA.
        self._consume_script = redis_client.register_script(LOCK_CONSUME_LUA)

    async def register(
        self,
        tenant_id: str,
        agent_id: str,
        alias: str,
        arguments: dict[str, Any],
        pin: str,
    ) -> str:
        """
        Create a payload lock and return its ``lock_id``.

        Stores only a scrypt-derived PIN digest (salted by tenant_id/lock_id/
        payload_hash) and the payload hash — never the raw PIN. Uses ``SET NX EX``
        so a (astronomically unlikely) lock_id collision fails closed rather than
        clobbering an existing lock.

        Raises ``ValueError`` on a malformed PIN, ``LockError`` on NX failure or
        any Redis transport error.
        """
        if not _PIN_RE.match(pin):
            raise ValueError("pin must be exactly 6 decimal digits")

        payload_hash = lock_payload_hash(tenant_id, agent_id, alias, arguments)
        # lock_id is generated FIRST because it salts the PIN derivation below.
        lock_id = uuid.uuid4().hex
        # scrypt is CPU-bound and memory-hard (~16 MiB, tens of ms). Run it on the
        # DEDICATED BOUNDED pool so the event loop is not blocked AND a burst of staging
        # cannot pin the shared executor or flood RAM (see _SCRYPT_EXECUTOR). OpenSSL
        # scrypt releases the GIL, so threads give real parallelism; the cost/salt/output
        # are unchanged, so exactly-once + payload binding + brute-force cost are preserved.
        pin_hash = await _derive_pin_hash_bounded(
            pin, tenant_id, lock_id, payload_hash
        )

        record = json.dumps(
            {
                "pin": pin_hash,
                "payload": payload_hash,
                "alias": alias,
                "agent_id": agent_id,
                "attempts": 0,
                "created_ns": time.time_ns(),
            },
            separators=(",", ":"),
        )

        key = _lock_key(tenant_id, lock_id)
        try:
            created = await self._redis.set(
                key, record, nx=True, ex=PIN_TTL_SECONDS
            )
        except RedisError as exc:
            raise LockError("lock transport failure during register") from exc

        if not created:
            # NX said the key already existed — treat as fail-closed.
            raise LockError("lock id collision during register")

        return lock_id

    async def consume(
        self,
        tenant_id: str,
        lock_id: str,
        agent_id: str,
        alias: str,
        arguments: dict[str, Any],
        pin: str,
    ) -> int:
        """
        Atomically consume a payload lock; return the raw Lua code (1/-1/-2/-3).

        Recomputes the payload hash and the salted scrypt PIN digest from the
        values presented at execution time and hands them to the single EVAL. The
        derivation is identical to ``register`` (salted by tenant_id/lock_id/
        payload_hash), so a correct PIN over the correct payload reproduces the
        stored digest exactly. The raw PIN is never stored or logged. A transport
        failure is surfaced as ``LockError`` so the gateway can deny with LOCK_ERROR.
        """
        payload_hash = lock_payload_hash(tenant_id, agent_id, alias, arguments)
        # Offload the memory-hard scrypt derivation to the DEDICATED BOUNDED pool (see
        # register): keeps the loop responsive and caps concurrent scrypt under load. The
        # derivation is byte-identical to register, so exactly-once binding is preserved.
        pin_hash = await _derive_pin_hash_bounded(
            pin, tenant_id, lock_id, payload_hash
        )
        key = _lock_key(tenant_id, lock_id)

        try:
            # keys/args map to KEYS[1] and ARGV[1..3] exactly per §2.3.
            result = await self._consume_script(
                keys=[key],
                args=[pin_hash, payload_hash, str(PIN_MAX_ATTEMPTS)],
            )
        except RedisError as exc:
            raise LockError("lock transport failure during consume") from exc

        # redis returns the Lua integer as an int (decode_responses does not
        # affect integer replies); normalize defensively.
        return int(result)


__all__ = [
    "LOCK_CONSUME_LUA",
    "LockError",
    "lock_payload_hash",
    "PinValidator",
]
