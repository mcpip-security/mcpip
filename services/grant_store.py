"""
MCPIP V2 — Service: GrantStore (UUID capability-based delegated compartment grants).

    ◐ "AI Reasons. MCPIP Authorizes. Systems Execute."

A GRANT delegates access to a compartment to a subject agent for a bounded time. It
is issued ONLY as the result of an authorization-gated EXECUTE mandate (the
``skill_compartment_grant`` governance alias) whose caller holds the
``CAP_COMPARTMENT_GRANT`` capability UUID — never because of any role string.

Grants live in Redis (stateless nodes; Redis is the single sync-state store), keyed
tenant+compartment+subject and stored with ``EX=ttl`` so Redis auto-expiry IS the
"active, unexpired" test — there is no manual clock in the hot path. Reads are
fail-closed: a missing or malformed record yields "no grant".
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from auth import LockError
from services.grant_cache import NegativeGrantCache
from services.relation_store import RelationTupleStore


@dataclass(frozen=True)
class GrantRecord:
    """An issued, time-bounded compartment grant (the value stored in Redis)."""

    grant_id: str            # uuid4 hex
    tenant_id: str
    subject_agent_id: str
    compartment_uuid: str
    issued_by: str           # authorizing principal's agent_id
    capability_used: str     # CAP_COMPARTMENT_GRANT
    issued_at_ns: int
    expires_at_ns: int
    correlation_id: str      # correlation id of the authorizing EXECUTE action


class GrantStore:
    """Issues, queries, and revokes delegated compartment grants in Redis."""

    def __init__(
        self,
        redis_client: "redis.Redis",
        cache: Optional[NegativeGrantCache] = None,
        relations: Optional[RelationTupleStore] = None,
    ) -> None:
        self._redis = redis_client
        # Per-worker negative cache of the ABSENT outcome only. Constructed here when
        # not supplied so every construction (including the demo) is cache-backed; the
        # gateway wires one explicitly per worker so it can be rebuilt on a client swap.
        self._cache = cache if cache is not None else NegativeGrantCache()
        # OPTIONAL best-effort ReBAC projection (Zanzibar-style relation tuples backing the
        # operator Knowledge-Graph). ADDITIVE and downstream of the authoritative grant:
        # ``issue`` projects a member tuple ONLY after the grant ``.set()`` succeeds and
        # ``revoke`` best-effort removes it AFTER the authoritative delete; both swallow
        # every error and NEVER raise into the grant path. ``None`` ⇒ no projection, so
        # ``GrantStore`` behaves exactly as it did before the layer existed.
        self._relations = relations

    async def issue(
        self,
        *,
        tenant_id: str,
        subject_agent_id: str,
        compartment_uuid: str,
        issued_by: str,
        capability_used: str,
        correlation_id: str,
        ttl_seconds: int,
    ) -> GrantRecord:
        """
        Persist a grant with ``EX=ttl_seconds`` and return the record.

        Fail-closed: any Redis transport error raises ``LockError`` so the pipeline
        denies (LOCK_ERROR) rather than reporting a grant that was not durably stored.
        """
        now = time.time_ns()
        record = GrantRecord(
            grant_id=uuid.uuid4().hex,
            tenant_id=tenant_id,
            subject_agent_id=subject_agent_id,
            compartment_uuid=compartment_uuid,
            issued_by=issued_by,
            capability_used=capability_used,
            issued_at_ns=now,
            expires_at_ns=now + ttl_seconds * 1_000_000_000,
            correlation_id=correlation_id,
        )
        key = self._key(tenant_id, compartment_uuid, subject_agent_id)
        payload = json.dumps(asdict(record), separators=(",", ":"))
        try:
            await self._redis.set(key, payload, ex=ttl_seconds)
        except RedisError as exc:
            raise LockError("grant transport failure during issue") from exc
        # Drop any stale ABSENT marker for the just-issued grant so this worker sees it
        # immediately (shortens the <=ttl_s newly-issued staleness window to zero here).
        self._cache.invalidate(key)
        # ADDITIVE, best-effort ReBAC projection — STRICTLY downstream of the authoritative
        # grant above (fires only because ``.set()`` already succeeded). It NEVER raises
        # (swallows RedisError internally), so ``has_active_grant`` / the payload lock / the
        # WORM emit are untouched and a projection outage degrades only the Knowledge-Graph.
        # No new WORM record: this grant action was already WORM-ALLOW-emitted before
        # dispatch and the tuple is a projection of that already-logged event.
        if self._relations is not None:
            await self._relations.project_member(
                tenant_id=tenant_id,
                compartment_uuid=compartment_uuid,
                subject_agent_id=subject_agent_id,
                grant_id=record.grant_id,
                issued_by=issued_by,
                correlation_id=correlation_id,
                issued_at_ns=record.issued_at_ns,
                ttl_seconds=ttl_seconds,
            )
        return record

    async def has_active_grant(
        self, tenant_id: str, subject_agent_id: str, compartment_uuid: str
    ) -> bool:
        """
        True iff an active (unexpired) grant exists. Read-only; fail-closed.

        A missing key (None) or a malformed record → False. Redis auto-expiry means a
        present key IS an unexpired grant, so no clock comparison is needed here.

        Negative-cache fast path (see ``NegativeGrantCache``): a fresh ABSENT marker
        short-circuits to False WITHOUT a Redis round trip. A PRESENT/allow result is
        NEVER cached — True is always produced by the live GET below — so a revoke (DEL)
        or TTL-expiry is observed on the very next call: a revoked grant is never served
        stale. The cache only ever turns a would-be ALLOW into a (fail-safe) DENY.

        Both the timing-decoy caller (``app.main._TIMING_DECOY_COMPARTMENT``) and the
        real compartment-denied path route through the SAME cache, so warm they are
        cache-served identically and cold they each do exactly one live GET — the
        cross-compartment existence oracle stays closed exactly as intended; the decoy
        key is deliberately NOT special-cased out of the cache.
        """
        key = self._key(tenant_id, compartment_uuid, subject_agent_id)
        # Fast deny path: a fresh absent-marker means "no grant" without touching Redis.
        if self._cache.get_absent(key):
            return False
        try:
            raw: Any = await self._redis.get(key)
        except RedisError:
            # Transport error is a transient miss — NOT a confirmed absence; do not cache.
            return False
        if raw is None:
            self._cache.mark_absent(key)
            return False
        try:
            record = json.loads(raw)
        except (ValueError, TypeError):
            self._cache.mark_absent(key)
            return False
        if isinstance(record, dict) and record.get("compartment_uuid") == compartment_uuid:
            # PRESENT — return from the live read; NEVER cache the allow outcome.
            return True
        self._cache.mark_absent(key)
        return False

    async def get_grant(
        self, tenant_id: str, subject_agent_id: str, compartment_uuid: str
    ) -> Optional[GrantRecord]:
        """Return the active GrantRecord, or None if absent/expired/malformed."""
        key = self._key(tenant_id, compartment_uuid, subject_agent_id)
        try:
            raw: Any = await self._redis.get(key)
        except RedisError:
            return None
        if raw is None:
            return None
        try:
            record = json.loads(raw)
            if not isinstance(record, dict):
                return None
            return GrantRecord(**record)
        except (ValueError, TypeError):
            return None

    async def revoke(
        self, tenant_id: str, subject_agent_id: str, compartment_uuid: str
    ) -> bool:
        """Delete a grant. Returns True iff a key was removed. Fail-closed on error."""
        key = self._key(tenant_id, compartment_uuid, subject_agent_id)
        try:
            removed: Any = await self._redis.delete(key)
        except RedisError as exc:
            raise LockError("grant transport failure during revoke") from exc
        # Drop any absent-marker so a subsequent re-issue is seen immediately, and never
        # leave a stale marker that contradicts the just-mutated key on this worker.
        self._cache.invalidate(key)
        # ADDITIVE, best-effort ReBAC projection remove — AFTER the authoritative delete
        # above. NEVER raises; even a dropped remove self-heals at the tuple's EX TTL (it
        # mirrors the grant TTL), so the projection can never outlive its grant.
        if self._relations is not None:
            await self._relations.remove_member(
                tenant_id=tenant_id,
                compartment_uuid=compartment_uuid,
                subject_agent_id=subject_agent_id,
            )
        return int(removed) > 0

    @staticmethod
    def _key(tenant_id: str, compartment_uuid: str, subject_agent_id: str) -> str:
        """Tenant+compartment+subject scoped key — never cross-tenant."""
        return f"mcpip:grant:{tenant_id}:{compartment_uuid}:{subject_agent_id}"


__all__ = ["GrantStore", "GrantRecord"]
