"""
MCPIP V2 — Service: RelationTupleStore (Zanzibar-style ReBAC relation-tuple PROJECTION).

    ◐ "AI Reasons. MCPIP Authorizes. Systems Execute."

STRICTLY ADDITIVE to the authoritative grant model. This layer is a best-effort,
Redis-auto-expiring PROJECTION of committed compartment grants — NOT a second source of
truth and NOT a weakening of any gate. ``GrantStore.issue`` / ``has_active_grant`` /
``revoke``, the payload lock, and the WORM ledger are byte-for-byte unchanged; the tuple
is written only AFTER the authoritative grant ``.set()`` succeeds and swallows every
Redis error, so a projection outage degrades only the operator Knowledge-Graph, never a
decision.

Vocabulary is drawn from primitives MCPIP already models:

  * ``object``   = ``compartment_uuid``   (the need-to-know blast radius)
  * ``relation`` = ``member``              (the subject holds a live delegated grant into
                                            the compartment); a read-time-derived
                                            ``grantor`` edge is projected from the same
                                            tuple's stored ``issued_by``.
  * ``subject``  = ``agent_id``

Tuple form (tenant-scoped, one tuple per grant — 1:1 with the grant key)::

    mcpip:rel:{tenant}:{object}#{relation}@{subject}

The tuple is written with ``EX=ttl`` MIRRORING the grant, so the projection self-heals to
match grant expiry with zero extra clock: even a dropped best-effort remove on revoke can
never let the projection outlive its grant by more than the grant's own remaining TTL.

Boundaries (opacity intact): a tuple carries compartment UUIDs + agent ids + non-secret
grant metadata — the SAME operator-facing identifiers already rendered in the console
directory — NEVER the hidden alias→target mapping, a secret, or a PIN/OTP. The read
surface is admin-only (``CAP_DIRECTORY_ADMIN``) and never crosses the agent boundary; the
agent still sees only ``MCPIPDenied`` + a ``correlation_id``.

Parity: ``_key`` is plain f-string interpolation of already-validated tenant/compartment/
agent strings — it shares NOTHING with ``canonical_json`` / ``enforce_argument_safety`` /
the scrypt PIN-hash and recomputes no lock hash.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from core.metrics import RELATION_PROJECTION
from interfaces import (
    MAX_RELATION_DEPTH,
    MAX_RELATION_FANOUT,
    MAX_RELATION_ROSTER,
    RELATION_KEY_PREFIX,
)
from services.quarantine import _glob_escape

# The single stored relation in v1. ``grantor`` is DERIVED at read time from a member
# tuple's ``issued_by`` — it is NOT a separately stored tuple (so exactly one tuple per
# grant, and no orphaned shared tuple whose TTL would skew from any individual grant).
MEMBER_RELATION = "member"
GRANTOR_RELATION = "grantor"


@dataclass(frozen=True)
class RelationEdge:
    """One projected relation edge for the operator Knowledge-Graph.

    ``subject`` has ``relation`` to ``object_uuid``. ``grant_id`` / ``correlation_id`` /
    ``issued_at_ns`` are the projected non-secret grant metadata (``None`` when derived or
    when the tuple value was unreadable); no secret, target, or alias mapping is ever here.
    """

    object_uuid: str
    relation: str
    subject: str
    grant_id: Optional[str] = None
    correlation_id: Optional[str] = None
    issued_at_ns: Optional[int] = None


class RelationTupleStore:
    """Best-effort projection of committed grants into Zanzibar-style relation tuples.

    Injected OPTIONALLY into ``GrantStore``: when wired, ``GrantStore.issue`` projects a
    member tuple after the authoritative grant lands and ``GrantStore.revoke`` best-effort
    removes it after the authoritative delete. When ``None`` (not wired) ``GrantStore``
    behaves exactly as today.
    """

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _key(tenant_id: str, object_uuid: str, relation: str, subject: str) -> str:
        """Tenant-scoped Zanzibar tuple key — the ONLY place the format is written.

        ``mcpip:rel:{tenant}:{object}#{relation}@{subject}``. Plain interpolation of
        already-validated ids (shares no code with the payload lock).
        """
        return f"{RELATION_KEY_PREFIX}:{tenant_id}:{object_uuid}#{relation}@{subject}"

    async def project_member(
        self,
        *,
        tenant_id: str,
        compartment_uuid: str,
        subject_agent_id: str,
        grant_id: str,
        issued_by: str,
        correlation_id: str,
        issued_at_ns: int,
        ttl_seconds: int,
    ) -> None:
        """Project (best-effort) the member tuple for a just-committed grant.

        Fires ONLY after ``GrantStore``'s authoritative ``.set()`` succeeded. Written with
        the SAME ``EX=ttl_seconds`` as the grant so it auto-expires in lockstep. Swallows
        any ``RedisError`` (metric only) and NEVER raises into the grant path — a
        projection outage degrades only the Knowledge-Graph, never a decision.

        The value carries only non-secret projection metadata (grant id, grantor, the
        already-WORM-logged correlation id, issue time) — no alias target, no secret.
        """
        key = self._key(tenant_id, compartment_uuid, MEMBER_RELATION, subject_agent_id)
        value = json.dumps(
            {
                "grant_id": grant_id,
                "issued_by": issued_by,
                "correlation_id": correlation_id,
                "issued_at_ns": issued_at_ns,
            },
            separators=(",", ":"),
        )
        try:
            await self._redis.set(key, value, ex=ttl_seconds)
        except RedisError:
            RELATION_PROJECTION.labels("project_error").inc()
            return
        RELATION_PROJECTION.labels("projected").inc()

    async def remove_member(
        self,
        *,
        tenant_id: str,
        compartment_uuid: str,
        subject_agent_id: str,
    ) -> None:
        """Best-effort remove the member tuple after an authoritative grant revoke.

        Fires ONLY after ``GrantStore``'s authoritative delete. Swallows ``RedisError``
        (metric only) and NEVER raises — even a dropped remove self-heals at ``EX`` TTL, so
        the projection can never outlive its grant by more than the grant's remaining TTL.
        """
        key = self._key(tenant_id, compartment_uuid, MEMBER_RELATION, subject_agent_id)
        try:
            await self._redis.delete(key)
        except RedisError:
            RELATION_PROJECTION.labels("project_error").inc()
            return
        RELATION_PROJECTION.labels("removed").inc()

    def _parse_key(self, tenant_id: str, key: str) -> Optional[tuple[str, str, str]]:
        """Parse ``mcpip:rel:{tenant}:{object}#{relation}@{subject}`` → (object, relation, subject).

        ``None`` on any shape mismatch. ``object`` (a UUID) never contains ``#`` and
        ``relation`` (``member``) never contains ``@``, so splitting on the FIRST ``#`` and
        then the FIRST ``@`` is unambiguous even if a ``subject`` id itself contains ``@``
        or ``#`` (the subject is always the trailing segment).
        """
        prefix = f"{RELATION_KEY_PREFIX}:{tenant_id}:"
        if not key.startswith(prefix):
            return None
        remainder = key[len(prefix):]
        if "#" not in remainder:
            return None
        object_uuid, rest = remainder.split("#", 1)
        if "@" not in rest:
            return None
        relation, subject = rest.split("@", 1)
        if not object_uuid or not relation or not subject:
            return None
        return object_uuid, relation, subject

    async def list_relations(
        self,
        tenant_id: str,
        *,
        subject: Optional[str] = None,
        relation: Optional[str] = None,
        object_uuid: Optional[str] = None,
        limit: int = MAX_RELATION_ROSTER,
    ) -> list[RelationEdge]:
        """Return the projected relation edges for ``tenant_id`` (the operator roster).

        Each stored member tuple projects TWO edges: a ``member`` edge (subject → object)
        and a read-time-derived ``grantor`` edge (``issued_by`` → object). Optional
        ``subject`` / ``relation`` / ``object_uuid`` filters narrow the emitted edges.

        Fail-soft (mirrors ``QuarantineStore.list_quarantined`` /
        ``RevocationStore.list_revoked``): a transport error yields ``[]`` rather than
        raising — this backs a read-only admin LISTING, never an authorization decision.
        Bounded to ``limit`` emitted edges; the SCAN is glob-escaped on the tenant id so a
        wildcard-bearing tenant id can never widen it into another tenant's namespace.
        """
        scan_prefix = f"{RELATION_KEY_PREFIX}:{tenant_id}:"
        edges: list[RelationEdge] = []
        try:
            async for raw_key in self._redis.scan_iter(
                match=_glob_escape(scan_prefix) + "*"
            ):
                key = raw_key.decode() if isinstance(raw_key, bytes) else str(raw_key)
                parsed = self._parse_key(tenant_id, key)
                if parsed is None:
                    continue
                obj, rel, subj = parsed
                if rel != MEMBER_RELATION:
                    # v1 only ever WRITES member tuples; ignore anything else defensively.
                    continue
                grant_id, issued_by, corr, issued_at = await self._read_metadata(key)
                # Member edge: subject → compartment.
                for edge in self._project_edges(obj, subj, grant_id, issued_by, corr, issued_at):
                    if subject is not None and edge.subject != subject:
                        continue
                    if relation is not None and edge.relation != relation:
                        continue
                    if object_uuid is not None and edge.object_uuid != object_uuid:
                        continue
                    edges.append(edge)
                    if len(edges) >= limit:
                        return edges
        except RedisError:
            return []
        return edges

    async def _read_metadata(
        self, key: str
    ) -> tuple[Optional[str], Optional[str], Optional[str], Optional[int]]:
        """Read a tuple's projected metadata (grant_id, issued_by, correlation_id, issued_at_ns).

        All ``None`` on a miss/transport/malformed value — the member edge is still known
        from the key alone, so an unreadable value under-reports metadata, never the edge.
        """
        try:
            raw: Any = await self._redis.get(key)
        except RedisError:
            return None, None, None, None
        if raw is None:
            return None, None, None, None
        try:
            value = json.loads(raw)
        except (ValueError, TypeError):
            return None, None, None, None
        if not isinstance(value, dict):
            return None, None, None, None
        grant_id = value.get("grant_id")
        issued_by = value.get("issued_by")
        corr = value.get("correlation_id")
        issued_at = value.get("issued_at_ns")
        return (
            grant_id if isinstance(grant_id, str) else None,
            issued_by if isinstance(issued_by, str) else None,
            corr if isinstance(corr, str) else None,
            issued_at if isinstance(issued_at, int) else None,
        )

    @staticmethod
    def _project_edges(
        object_uuid: str,
        subject: str,
        grant_id: Optional[str],
        issued_by: Optional[str],
        correlation_id: Optional[str],
        issued_at_ns: Optional[int],
    ) -> list[RelationEdge]:
        """Project the member edge + the derived grantor edge from one member tuple."""
        out = [
            RelationEdge(
                object_uuid=object_uuid,
                relation=MEMBER_RELATION,
                subject=subject,
                grant_id=grant_id,
                correlation_id=correlation_id,
                issued_at_ns=issued_at_ns,
            )
        ]
        # Derived grantor edge: the authorizing principal → the same compartment. Only when
        # the value was readable AND the grantor differs from the subject (a self-issue
        # would otherwise duplicate the member edge). Metadata is intentionally omitted on
        # the derived edge — it is a projection, not a first-class stored tuple.
        if issued_by is not None and issued_by != subject:
            out.append(
                RelationEdge(
                    object_uuid=object_uuid,
                    relation=GRANTOR_RELATION,
                    subject=issued_by,
                )
            )
        return out

    async def check(
        self,
        *,
        tenant_id: str,
        subject: str,
        relation: str,
        object_uuid: str,
    ) -> bool:
        """Bounded transitive-closure membership check — READ/VISUALIZATION ONLY.

        Answers "does ``subject`` have ``relation`` to ``object_uuid`` (possibly
        transitively)?" over the member-tuple graph. It is NOT consulted by the
        authorization pipeline in v1 — the capability-UUID + grant gates remain the SOLE
        authority. Documented rule: IF ever promoted to the hot path it stays deny-only /
        additive (it can only ADD a deny, never rescue an otherwise-denied call).

        The walk is a hop- and fanout-capped BFS over the object graph, bounded by
        ``MAX_RELATION_DEPTH`` (hops) and ``MAX_RELATION_FANOUT`` (total tuples visited).
        In v1 the graph is DIRECT (compartment#member@agent), so the answer is the first,
        O(1) key-existence probe; the bounded expansion is the STRUCTURAL guard for a
        future wave that adds group/role nesting (object-to-object rewrites), so the walk
        can NEVER become an unbounded CPU/timing walk. Every failure axis — an unknown
        relation, either cap hit, or a Redis transport error — returns ``False``
        (fail-closed deny), never raises, never walks further.
        """
        if relation != MEMBER_RELATION:
            # v1 projects/traverses only 'member'; grantor is a derived visualization edge,
            # not a traversable relation. Fail-closed on anything else.
            return False
        try:
            # Direct edge (the entire v1 graph): a present key IS an unexpired membership.
            if await self._redis.exists(
                self._key(tenant_id, object_uuid, MEMBER_RELATION, subject)
            ):
                return True
            # Bounded transitive walk for future nesting. Expands the frontier of objects
            # reachable via stored member-of-object tuples, collecting member subjects at
            # each hop. In v1 subjects are agent ids (never compartment objects), so the
            # first expansion terminates — but the caps hold structurally regardless.
            frontier = [object_uuid]
            seen_objects = {object_uuid}
            visited = 0
            for _hop in range(MAX_RELATION_DEPTH):
                if not frontier:
                    break
                next_frontier: list[str] = []
                for obj in frontier:
                    obj_prefix = f"{RELATION_KEY_PREFIX}:{tenant_id}:{obj}#{MEMBER_RELATION}@"
                    async for raw_key in self._redis.scan_iter(
                        match=_glob_escape(obj_prefix) + "*"
                    ):
                        visited += 1
                        if visited > MAX_RELATION_FANOUT:
                            return False  # fanout cap: fail-closed, never walk further.
                        key = (
                            raw_key.decode()
                            if isinstance(raw_key, bytes)
                            else str(raw_key)
                        )
                        parsed = self._parse_key(tenant_id, key)
                        if parsed is None:
                            continue
                        _obj, _rel, member_subject = parsed
                        if member_subject == subject:
                            return True
                        if member_subject not in seen_objects:
                            seen_objects.add(member_subject)
                            next_frontier.append(member_subject)
                frontier = next_frontier
        except RedisError:
            return False  # transport error: fail-closed deny, never a silent pass.
        return False


__all__ = ["RelationTupleStore", "RelationEdge", "MEMBER_RELATION", "GRANTOR_RELATION"]
