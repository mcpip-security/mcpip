"""
MCPIP V2 — Service: QuarantineStore (canary-tripwire agent freeze).

    ◐ "A tripped canary is an alarm the attacker never hears."

When an agent invokes a canary alias (a decoy skill seeded into its catalog —
see ``obfuscator.tenant_catalog.CANARY_ALIASES``), the pipeline records a
CANARY_TRIPPED deny to WORM and freezes the agent here. While the quarantine
key lives, EVERY subsequent request from that (tenant, agent) is denied
AGENT_QUARANTINED immediately after identity verification — the compromised
agent cannot pivot from the decoy to a real skill.

Both sides stay opaque: the tripping request and every quarantined request
receive the same generic ``MCPIPDenied`` + correlation id as any other deny,
so the attacker learns nothing; the concrete reasons live only in the WORM log
where the operator alerts on them.

Fail-closed discipline (mirrors ``GrantStore``):
  * ``is_quarantined`` runs on the hot path for every request; a Redis
    transport failure raises ``LockError`` so the single funnel denies
    LOCK_ERROR rather than skipping the gate.
  * ``quarantine`` (the mark) is best-effort: it runs while a CANARY_TRIPPED
    deny is already in flight, and a Redis outage must not replace that deny
    with a crash — the deny itself never depends on the mark landing.
"""

from __future__ import annotations

import json
import time
from typing import Any

import redis.asyncio as redis
from redis.exceptions import RedisError

from auth import LockError
from interfaces import MAX_QUARANTINE_ROSTER, QUARANTINE_TTL_SECONDS


def _glob_escape(text: str) -> str:
    """
    Escape Redis ``MATCH`` glob metacharacters (``* ? [ ] \\``) so ``text`` matches
    LITERALLY. The roster scan interpolates the (JWT-verified) tenant id into a MATCH
    pattern; escaping means a tenant id that happens to contain a wildcard can never
    widen the scan into another tenant's key namespace.
    """
    out: list[str] = []
    for ch in text:
        if ch in "*?[]\\":
            out.append("\\")
        out.append(ch)
    return "".join(out)


class QuarantineStore:
    """Redis-backed (tenant, agent) freeze list — TTL-bounded, fail-closed reads."""

    def __init__(
        self,
        redis_client: "redis.Redis",
        *,
        ttl_seconds: int = QUARANTINE_TTL_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl_seconds

    @staticmethod
    def _key(tenant_id: str, agent_id: str) -> str:
        return f"mcpip:quarantine:{tenant_id}:{agent_id}"

    async def quarantine(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        correlation_id: str,
        tripped_alias: str,
    ) -> None:
        """
        Freeze the agent for ``ttl_seconds`` (best-effort — see module docstring).

        The stored payload is operator forensics only (which alias tripped, when,
        under which correlation id); enforcement needs nothing but key presence.
        """
        payload = json.dumps(
            {
                "tripped_alias": tripped_alias,
                "correlation_id": correlation_id,
                "quarantined_at_ns": time.time_ns(),
            },
            separators=(",", ":"),
        )
        try:
            await self._redis.set(
                self._key(tenant_id, agent_id), payload, ex=self._ttl
            )
        except RedisError:
            # The CANARY_TRIPPED deny is already in flight; losing the mark under a
            # Redis outage degrades persistence of the freeze, never the deny.
            pass

    async def is_quarantined(self, tenant_id: str, agent_id: str) -> bool:
        """
        True iff an unexpired quarantine mark exists (Redis ``EX`` is the clock).

        Fail-closed: a transport failure raises ``LockError`` (mapped to a
        LOCK_ERROR deny by the funnel) — an unreadable freeze list never lets a
        possibly-quarantined agent through.
        """
        try:
            raw: Any = await self._redis.get(self._key(tenant_id, agent_id))
        except RedisError as exc:
            raise LockError("quarantine transport failure") from exc
        return raw is not None

    async def list_quarantined(
        self, tenant_id: str, *, limit: int = MAX_QUARANTINE_ROSTER
    ) -> list[tuple[str, int]]:
        """
        Return ``(agent_id, ttl_seconds)`` for every agent currently frozen in
        ``tenant_id`` — the operator's roster view, bounded to ``limit`` rows.

        Uses non-blocking ``SCAN`` over the tenant-scoped key prefix (glob-escaped, so
        the tenant id is matched literally — see ``_glob_escape``) and reads each
        mark's remaining TTL; Redis ``EX`` is the clock, so the TTL is authoritative.
        A mark that expires between the SCAN and the TTL read is skipped (``-2``).
        Fail-soft (mirrors ``RevocationStore.list_revoked``): a transport error yields
        ``[]`` rather than raising — this backs a read-only admin listing, never an
        authorization decision; enforcement stays the fail-closed ``is_quarantined``.
        """
        prefix = self._key(tenant_id, "")
        found: list[tuple[str, int]] = []
        try:
            async for key in self._redis.scan_iter(match=_glob_escape(prefix) + "*"):
                text = key.decode() if isinstance(key, bytes) else str(key)
                ttl: Any = await self._redis.ttl(text)
                remaining = int(ttl)
                if remaining == -2:
                    continue  # vanished between SCAN and TTL — no longer frozen.
                # -1 (no expiry) cannot arise from ``quarantine`` (it always sets EX);
                # pass it through verbatim rather than hide a frozen principal.
                found.append((text[len(prefix):], remaining))
                if len(found) >= limit:
                    break
        except RedisError:
            return []
        return found


__all__ = ["QuarantineStore"]
