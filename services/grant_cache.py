"""
MCPIP V2 — Service: NegativeGrantCache (per-worker, bounded, TTL negative cache).

    ◐ "Authorize every AI action before execution."

A read-side accelerator for the ONLY read-heavy, mutate-rarely, security-critical
Redis lookup in the gateway: the compartment grant/entitlement check
(``GrantStore.has_active_grant``, key ``mcpip:grant:{tenant}:{compartment}:{subject}``).

DECISIVE CONSTRAINT (verified against the installed venv): redis-py 5.3.1's ASYNC
client does not support client-side caching — ``cache``/``cache_config`` are
constructor params of the SYNC ``redis.Redis`` only; ``redis.asyncio.Redis`` exposes
``protocol`` but no cache hooks. The gateway is 100% ``redis.asyncio``. So server-
assisted RESP3 client-side caching cannot be enabled on the async client at all. This
module is the specified fallback: a per-worker, in-process, bounded, TTL cache.

CRITICAL SECURITY PROPERTY — a revoked/expired grant is NEVER served stale to
``authorize``. This cache memoizes ONLY the "no active grant" (ABSENT) outcome:

  * A cached ABSENT can only ever turn a would-be ALLOW into a DENY — fail-SAFE
    (availability, never authorization). It can never manufacture an ALLOW.
  * A PRESENT/ALLOW decision is NEVER cached: ``GrantStore.has_active_grant`` returns
    True only from a fresh authoritative Redis read. So a revoke (DEL) or TTL-expiry is
    observed on the very next lookup — immediate, hard freshness on the security-
    critical direction. This is the strongest form of the spec's "recheck-on-allow"
    guarantee: the cache never returns ALLOW, so there is nothing to recheck.

Staleness is bounded to ``ttl_s`` and applies ONLY to newly-*issued* grants (the cache
may still say ABSENT for <= ttl_s → a legitimate caller is briefly denied and retries);
``GrantStore.issue`` additionally calls ``invalidate`` on the issuing worker to shorten
even that window. Default ``ttl_s = 1.0`` is the conservative bounded-staleness cap.

The cache is per-worker (a plain in-process dict): the event loop is single-threaded
per worker, so all mutations here run without a lock. It never crosses process/node
boundaries — correctness never depends on fleet-wide coherence because the ALLOW path
is always authoritative.
"""

from __future__ import annotations

import time
from collections import OrderedDict


class NegativeGrantCache:
    """
    Bounded, TTL, LRU in-process cache of the ABSENT ("no active grant") outcome only.

    An entry maps a grant-key string to the monotonic timestamp it was inserted. An
    entry older than ``ttl_s`` is treated as a miss (and lazily dropped). At ``max_size``
    the least-recently-used entry is evicted. Only ever caches ABSENT — never PRESENT.
    """

    def __init__(self, ttl_s: float = 1.0, max_size: int = 100_000) -> None:
        self._ttl_s = ttl_s
        self._max_size = max_size
        # grant-key -> monotonic insert timestamp; ordered for O(1) LRU eviction.
        self._entries: "OrderedDict[str, float]" = OrderedDict()

    def get_absent(self, key: str) -> bool:
        """True iff a FRESH (now - ts <= ttl_s) absent-marker exists for ``key``."""
        ts = self._entries.get(key)
        if ts is None:
            return False
        if time.monotonic() - ts > self._ttl_s:
            # Stale marker — drop it and report a miss so the caller does a live read.
            del self._entries[key]
            return False
        self._entries.move_to_end(key)  # LRU touch.
        return True

    def mark_absent(self, key: str) -> None:
        """Record ``key`` as ABSENT as of now, evicting the LRU entry past max_size."""
        self._entries[key] = time.monotonic()
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_size:
            self._entries.popitem(last=False)

    def invalidate(self, key: str) -> None:
        """Drop any absent-marker for ``key`` (called on issue/revoke of that grant)."""
        self._entries.pop(key, None)

    def clear(self) -> None:
        """Drop every marker (used when the cache must not outlive a client swap)."""
        self._entries.clear()


__all__ = ["NegativeGrantCache"]
