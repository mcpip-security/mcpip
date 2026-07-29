"""
MCPIP V2 — ReBAC relation-tuple PROJECTION test suite (Zanzibar-style, additive).

    ◐  "A projection of committed grants — never a second source of authority.
       A relation tuple alone never authorizes what the grant gate would deny."

Two layers, both against REAL code and REAL Redis (:63790) — no mocks of the code under
test:

  * STORE level (dedicated db ``/11``, driven with ``asyncio.run`` like the WORM tamper
    probe): the REAL ``GrantStore`` wired with the REAL ``RelationTupleStore`` — a grant
    ``issue`` projects the member tuple (1:1 with the grant key, ``EX`` mirroring the grant
    TTL), ``revoke`` removes it, TTL auto-expiry removes it, and the bounded transitive
    ``check`` returns correct membership AND refuses to exceed the depth / fanout caps
    (fail-closed, never an unbounded walk). Crucially: the authoritative
    ``has_active_grant`` / payload lock are byte-for-byte unchanged by the projection.

  * ENDPOINT level (shared sandbox db ``/5`` + ``TestClient``, same env as
    ``tests/test_authorize_api.py`` so one ``_components`` graph is shared): the read
    surface ``GET /v1/admin/directory/relations`` is ``CAP_DIRECTORY_ADMIN``-gated,
    tenant-scoped, honest-empty, opaque on a malformed filter — and, the load-bearing
    invariant, a projected relation tuple NEVER authorizes an action the grant gate denies.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MUST match tests/test_authorize_api.py so the shared _components graph agrees on the
# Redis db + sandbox flag regardless of import order.
_TEST_REDIS_URL = "redis://localhost:63790/5"
_STORE_REDIS_URL = "redis://localhost:63790/11"  # isolated: store-level probes only.
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import asyncio
import json
import time
import uuid
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
import redis.asyncio as aioredis
from fastapi.testclient import TestClient
from httpx import Response

from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import (
    CAP_DIRECTORY_ADMIN,
    MAX_RELATION_DEPTH,
    MAX_RELATION_FANOUT,
    RELATION_KEY_PREFIX,
)
from services.grant_cache import NegativeGrantCache
from services.grant_store import GrantStore
from services.relation_store import MEMBER_RELATION, RelationTupleStore

from app.main import _components, app
from main import _DemoIdP

_AEGIS = "aegis-dynamics"
_FALCON_ALIAS = "skill_airframe_telemetry"
_EVENTS_STREAM = "mcpip:worm:events"


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def idp() -> _DemoIdP:
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Store-level harness (real GrantStore + real RelationTupleStore, real Redis /11).
# ---------------------------------------------------------------------------


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


async def _fresh_store() -> tuple[Any, GrantStore, RelationTupleStore]:
    """A GrantStore wired with a RelationTupleStore against a flushed dedicated db."""
    redis_client: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
        _STORE_REDIS_URL, decode_responses=True
    )
    await redis_client.flushdb()
    relations = RelationTupleStore(redis_client)
    grants = GrantStore(redis_client, cache=NegativeGrantCache(), relations=relations)
    return redis_client, grants, relations


def _rel_key(tenant: str, compartment: str, subject: str) -> str:
    return f"{RELATION_KEY_PREFIX}:{tenant}:{compartment}#{MEMBER_RELATION}@{subject}"


# ---------------------------------------------------------------------------
# 1) A grant issue writes the member relation tuple (1:1, EX mirrors the grant).
# ---------------------------------------------------------------------------


def test_issue_projects_member_tuple() -> None:
    async def scenario() -> None:
        redis_client, grants, _relations = await _fresh_store()
        try:
            tenant, subject, comp = "tenant-r1", "agent-r1", uuid.uuid4().hex
            record = await grants.issue(
                tenant_id=tenant,
                subject_agent_id=subject,
                compartment_uuid=comp,
                issued_by="agent-grantor-1",
                capability_used="cap-x",
                correlation_id="corr-abc",
                ttl_seconds=300,
            )
            # The authoritative grant is unchanged and active.
            assert await grants.has_active_grant(tenant, subject, comp) is True

            # Exactly one projected tuple, 1:1 with the grant, carrying only non-secret
            # projection metadata (grant id / grantor / correlation / issue time).
            key = _rel_key(tenant, comp, subject)
            raw = await redis_client.get(key)
            assert raw is not None, "issue must project a member tuple"
            value = json.loads(raw)
            assert value["grant_id"] == record.grant_id
            assert value["issued_by"] == "agent-grantor-1"
            assert value["correlation_id"] == "corr-abc"
            assert value["issued_at_ns"] == record.issued_at_ns
            # No secret / target / alias mapping ever lands in the tuple value.
            assert set(value.keys()) == {
                "grant_id",
                "issued_by",
                "correlation_id",
                "issued_at_ns",
            }

            # EX mirrors the grant: the tuple TTL tracks the grant key TTL (self-heals to
            # match grant expiry with zero extra clock).
            rel_ttl = await redis_client.ttl(key)
            grant_ttl = await redis_client.ttl(f"mcpip:grant:{tenant}:{comp}:{subject}")
            assert 0 < rel_ttl <= 300
            assert abs(rel_ttl - grant_ttl) <= 1
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# 2) Revoke removes the tuple; the authoritative grant delete is unchanged.
# ---------------------------------------------------------------------------


def test_revoke_removes_tuple() -> None:
    async def scenario() -> None:
        redis_client, grants, _relations = await _fresh_store()
        try:
            tenant, subject, comp = "tenant-r2", "agent-r2", uuid.uuid4().hex
            await grants.issue(
                tenant_id=tenant,
                subject_agent_id=subject,
                compartment_uuid=comp,
                issued_by="agent-grantor-2",
                capability_used="cap-x",
                correlation_id="corr-2",
                ttl_seconds=300,
            )
            key = _rel_key(tenant, comp, subject)
            assert await redis_client.exists(key) == 1

            removed = await grants.revoke(tenant, subject, comp)
            assert removed is True
            assert await grants.has_active_grant(tenant, subject, comp) is False
            # The projection is removed after the authoritative delete.
            assert await redis_client.exists(key) == 0
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# 3) TTL auto-expiry removes the tuple in lockstep with the grant.
# ---------------------------------------------------------------------------


def test_ttl_expiry_removes_tuple() -> None:
    async def scenario() -> None:
        redis_client, grants, _relations = await _fresh_store()
        try:
            tenant, subject, comp = "tenant-r3", "agent-r3", uuid.uuid4().hex
            await grants.issue(
                tenant_id=tenant,
                subject_agent_id=subject,
                compartment_uuid=comp,
                issued_by="agent-grantor-3",
                capability_used="cap-x",
                correlation_id="corr-3",
                ttl_seconds=1,
            )
            key = _rel_key(tenant, comp, subject)
            grant_key = f"mcpip:grant:{tenant}:{comp}:{subject}"
            assert await redis_client.exists(key) == 1
            time.sleep(1.4)  # let both the grant and the mirrored tuple auto-expire.
            assert await redis_client.exists(grant_key) == 0, "grant should auto-expire"
            assert await redis_client.exists(key) == 0, "tuple must expire with the grant"
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# 4) Bounded closure: correct DIRECT membership; grantor is not traversable.
# ---------------------------------------------------------------------------


def test_check_direct_membership() -> None:
    async def scenario() -> None:
        redis_client, grants, relations = await _fresh_store()
        try:
            tenant, subject, comp = "tenant-r4", "agent-r4", uuid.uuid4().hex
            await grants.issue(
                tenant_id=tenant,
                subject_agent_id=subject,
                compartment_uuid=comp,
                issued_by="agent-grantor-4",
                capability_used="cap-x",
                correlation_id="corr-4",
                ttl_seconds=300,
            )
            assert (
                await relations.check(
                    tenant_id=tenant, subject=subject, relation="member", object_uuid=comp
                )
                is True
            )
            # A different subject / compartment is not a member.
            assert (
                await relations.check(
                    tenant_id=tenant, subject="agent-other", relation="member", object_uuid=comp
                )
                is False
            )
            assert (
                await relations.check(
                    tenant_id=tenant, subject=subject, relation="member", object_uuid=uuid.uuid4().hex
                )
                is False
            )
            # 'grantor' is a derived DISPLAY edge — never traversable; fail-closed.
            assert (
                await relations.check(
                    tenant_id=tenant, subject=subject, relation="grantor", object_uuid=comp
                )
                is False
            )
            # A cross-tenant probe never sees the tuple.
            assert (
                await relations.check(
                    tenant_id="tenant-elsewhere", subject=subject, relation="member", object_uuid=comp
                )
                is False
            )
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# 5) The closure REFUSES to exceed the depth cap — same graph, one hop deeper flips
#    True→False, so the False is purely the cap (a reachable path), never absence.
# ---------------------------------------------------------------------------


async def _write_member_tuple(redis_client: Any, tenant: str, obj: str, subject: str) -> None:
    await redis_client.set(_rel_key(tenant, obj, subject), json.dumps({"grant_id": "x"}))


def test_check_depth_cap_is_fail_closed() -> None:
    async def scenario() -> None:
        redis_client, _grants, relations = await _fresh_store()
        try:
            tenant = "tenant-depth"
            # Build a chain o0 -member-> o1 -member-> ... where each member_subject is the
            # NEXT object id (object-to-object nesting the cap guards for the future).
            def chain(prefix: str, depth: int) -> tuple[str, str]:
                nodes = [f"{prefix}-{i}" for i in range(depth + 1)]
                return nodes[0], nodes[-1]

            # Reachable at EXACTLY MAX_RELATION_DEPTH hops → within the cap → True.
            root_ok, target_ok = chain("ok", MAX_RELATION_DEPTH)
            nodes_ok = [f"ok-{i}" for i in range(MAX_RELATION_DEPTH + 1)]
            for i in range(MAX_RELATION_DEPTH):
                await _write_member_tuple(redis_client, tenant, nodes_ok[i], nodes_ok[i + 1])
            assert (
                await relations.check(
                    tenant_id=tenant, subject=target_ok, relation="member", object_uuid=root_ok
                )
                is True
            ), "a target reachable within MAX_RELATION_DEPTH hops must resolve"

            # Same shape, ONE hop deeper (MAX_RELATION_DEPTH + 1) → exceeds the cap → the
            # walk stops and returns False despite a real path existing (fail-closed).
            root_deep, target_deep = chain("deep", MAX_RELATION_DEPTH + 1)
            nodes_deep = [f"deep-{i}" for i in range(MAX_RELATION_DEPTH + 2)]
            for i in range(MAX_RELATION_DEPTH + 1):
                await _write_member_tuple(redis_client, tenant, nodes_deep[i], nodes_deep[i + 1])
            assert (
                await relations.check(
                    tenant_id=tenant, subject=target_deep, relation="member", object_uuid=root_deep
                )
                is False
            ), "a target one hop past the depth cap must fail closed, not walk further"
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# 6) The closure REFUSES to exceed the fanout cap — a wide (not deep) tuple set can't
#    blow up the walk. Same s0->TARGET child; only the sibling COUNT changes the result.
# ---------------------------------------------------------------------------


def test_check_fanout_cap_is_fail_closed() -> None:
    async def scenario() -> None:
        redis_client, _grants, relations = await _fresh_store()
        try:
            tenant = "tenant-fanout"
            target = "agent-fanout-target"

            async def build(hub: str, siblings: int) -> None:
                # `siblings` member tuples under `hub`; sibling s0 has a child edge to the
                # target one hop deeper. A correct UNBOUNDED walk finds the target at hop 2.
                pipe = redis_client.pipeline()
                for i in range(siblings):
                    pipe.set(_rel_key(tenant, hub, f"{hub}-s{i}"), json.dumps({"grant_id": "x"}))
                pipe.set(_rel_key(tenant, f"{hub}-s0", target), json.dumps({"grant_id": "x"}))
                await pipe.execute()

            # Small hub (well under the fanout cap): the walk expands s0 and finds target.
            await build("hub-small", siblings=5)
            assert (
                await relations.check(
                    tenant_id=tenant, subject=target, relation="member", object_uuid="hub-small"
                )
                is True
            ), "under the fanout cap the target one hop deeper is reachable"

            # Wide hub (> MAX_RELATION_FANOUT siblings): the first hop alone exhausts the
            # visit budget, so the walk bails BEFORE expanding s0 → fail-closed False even
            # though the identical deeper path exists.
            await build("hub-wide", siblings=MAX_RELATION_FANOUT + 1)
            assert (
                await relations.check(
                    tenant_id=tenant, subject=target, relation="member", object_uuid="hub-wide"
                )
                is False
            ), "past the fanout cap the walk must stop and fail closed"
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# 7) list_relations projects a member edge + a derived grantor edge; filters narrow.
# ---------------------------------------------------------------------------


def test_list_relations_projects_member_and_grantor_edges() -> None:
    async def scenario() -> None:
        redis_client, grants, relations = await _fresh_store()
        try:
            tenant, subject, comp = "tenant-r7", "agent-r7", uuid.uuid4().hex
            await grants.issue(
                tenant_id=tenant,
                subject_agent_id=subject,
                compartment_uuid=comp,
                issued_by="agent-grantor-7",
                capability_used="cap-x",
                correlation_id="corr-7",
                ttl_seconds=300,
            )
            edges = await relations.list_relations(tenant)
            by_rel = {(e.relation, e.subject): e for e in edges}
            # Member edge: subject -> compartment, carrying the grant metadata.
            member = by_rel[(MEMBER_RELATION, subject)]
            assert member.object_uuid == comp
            assert member.correlation_id == "corr-7"
            # Derived grantor edge: the issuing principal -> the same compartment.
            grantor = by_rel[("grantor", "agent-grantor-7")]
            assert grantor.object_uuid == comp

            # A subject filter narrows to just that subject's edges.
            only_grantor = await relations.list_relations(tenant, subject="agent-grantor-7")
            assert {e.relation for e in only_grantor} == {"grantor"}
            # An object filter narrows to that compartment.
            in_comp = await relations.list_relations(tenant, object_uuid=comp)
            assert all(e.object_uuid == comp for e in in_comp)
            # A cross-tenant listing is honestly empty (tenant-scoped SCAN).
            assert await relations.list_relations("tenant-nobody") == []
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# 8) relations=None ⇒ GrantStore behaves EXACTLY as before (no projection, no raise).
# ---------------------------------------------------------------------------


def test_grantstore_without_relations_is_unchanged() -> None:
    async def scenario() -> None:
        redis_client: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
            _STORE_REDIS_URL, decode_responses=True
        )
        await redis_client.flushdb()
        try:
            grants = GrantStore(redis_client, cache=NegativeGrantCache())  # no relations.
            tenant, subject, comp = "tenant-r8", "agent-r8", uuid.uuid4().hex
            await grants.issue(
                tenant_id=tenant,
                subject_agent_id=subject,
                compartment_uuid=comp,
                issued_by="g",
                capability_used="cap-x",
                correlation_id="corr-8",
                ttl_seconds=300,
            )
            assert await grants.has_active_grant(tenant, subject, comp) is True
            # No projection keys were written at all.
            keys = [k async for k in redis_client.scan_iter(match=f"{RELATION_KEY_PREFIX}:*")]
            assert keys == []
            assert await grants.revoke(tenant, subject, comp) is True
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# Endpoint level: GET /v1/admin/directory/relations.
# ---------------------------------------------------------------------------


def _admin(idp: _DemoIdP, tenant_id: str) -> str:
    return idp.mint(
        tenant_id=tenant_id, agent_id="agent-dir-admin", capabilities=[CAP_DIRECTORY_ADMIN]
    )


def _bh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed_app_tuple(
    tenant: str, compartment: str, subject: str, *, issued_by: str = "agent-seed-grantor"
) -> None:
    """Seed one member tuple directly into the app's sandbox db (the exact format
    ``project_member`` writes — verified byte-for-byte by the store-level tests above)."""
    w: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        w.set(
            _rel_key(tenant, compartment, subject),
            json.dumps(
                {
                    "grant_id": "seed-grant",
                    "issued_by": issued_by,
                    "correlation_id": "seed-corr",
                    "issued_at_ns": 123,
                },
                separators=(",", ":"),
            ),
        )
    finally:
        w.close()


def _relations_get(client: TestClient, token: str, **params: str) -> Response:
    return client.get("/v1/admin/directory/relations", headers=_bh(token), params=params)


def test_relations_read_requires_directory_admin(client: TestClient, idp: _DemoIdP) -> None:
    tenant = f"tenant-rel-{uuid.uuid4().hex[:8]}"
    # No bearer → opaque 403.
    assert client.get("/v1/admin/directory/relations").status_code == 403
    # A plain (no-capability) token → opaque 403 with the generic envelope only.
    plain = idp.mint(tenant_id=tenant, agent_id="agent-plain")
    denied = _relations_get(client, plain)
    assert denied.status_code == 403
    assert set(denied.json().keys()) == {"error", "correlation_id"}
    assert denied.json()["error"] == AGENT_FACING_DENY_MESSAGE
    # The proper admin token → 200.
    assert _relations_get(client, _admin(idp, tenant)).status_code == 200


def test_relations_read_is_tenant_scoped_and_honest_empty(
    client: TestClient, idp: _DemoIdP
) -> None:
    tenant_a = f"tenant-rel-a-{uuid.uuid4().hex[:8]}"
    tenant_b = f"tenant-rel-b-{uuid.uuid4().hex[:8]}"
    comp = uuid.uuid4().hex
    _seed_app_tuple(tenant_a, comp, "agent-in-a")

    # Tenant A's admin sees the edge.
    a_rows = _relations_get(client, _admin(idp, tenant_a)).json()["relations"]
    assert any(r["subject"] == "agent-in-a" and r["object"] == comp for r in a_rows)

    # Tenant B's admin sees an HONEST EMPTY roster — never tenant A's tuple.
    b_resp = _relations_get(client, _admin(idp, tenant_b))
    assert b_resp.status_code == 200
    assert b_resp.json() == {"relations": []}


def test_relations_read_filters_and_bounded_check(client: TestClient, idp: _DemoIdP) -> None:
    tenant = f"tenant-rel-{uuid.uuid4().hex[:8]}"
    comp = uuid.uuid4().hex
    subject = "agent-member-x"
    _seed_app_tuple(tenant, comp, subject, issued_by="agent-grantor-x")
    admin = _admin(idp, tenant)

    # A full (subject, relation=member, object) triple surfaces the bounded closure check.
    hit = _relations_get(
        client, admin, subject=subject, relation=MEMBER_RELATION, object=comp
    ).json()
    assert hit["allowed"] is True
    assert any(r["subject"] == subject and r["relation"] == MEMBER_RELATION for r in hit["relations"])

    # A subject with no tuple → allowed False (the check is fail-closed).
    miss = _relations_get(
        client, admin, subject="agent-nobody", relation=MEMBER_RELATION, object=comp
    ).json()
    assert miss["allowed"] is False

    # A malformed filter (over-length / newline) is an OPAQUE deny, never a hint or 5xx.
    assert _relations_get(client, admin, subject="a" * 300).status_code == 403
    assert _relations_get(client, admin, relation="mem\nber").status_code == 403


def test_relation_tuple_alone_never_authorizes(client: TestClient, idp: _DemoIdP) -> None:
    """THE load-bearing invariant: the projection is not an authorization source. A member
    tuple placed for an agent into the FALCON compartment does NOT let a bare, ungranted
    token reach the FALCON alias — the grant gate still denies COMPARTMENT_DENIED."""
    from obfuscator.tenant_catalog import FALCON

    agent_id = f"agent-rebac-mole-{uuid.uuid4().hex[:8]}"
    # Seed a relation tuple asserting membership — with NO real grant behind it.
    _seed_app_tuple(_AEGIS, FALCON, agent_id)

    # A bare token (no compartment claim, no delegated grant) attempts the FALCON alias.
    token = idp.mint(tenant_id=_AEGIS, agent_id=agent_id)
    resp = client.post(
        "/v1/authorize",
        json={
            "source_format": "openai_tool_call",
            "tool_call": {
                "id": "call_test",
                "type": "function",
                "function": {"name": _FALCON_ALIAS, "arguments": json.dumps({})},
            },
            "jwt": token,
        },
    )
    # Still denied — the capability-UUID + grant gates remain the SOLE authority.
    assert resp.status_code == 403, resp.text
    assert set(resp.json().keys()) == {"error", "correlation_id"}
    assert _last_deny_reason() == "compartment_denied"


def _last_deny_reason() -> Optional[str]:
    """The concrete deny reason of the most recent WORM decision (audit-only)."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=50)
    finally:
        reader.close()
    for _sid, fields in entries:
        try:
            event = json.loads(fields["record"])["event"]
        except (ValueError, KeyError, TypeError):
            continue
        if event.get("decision") == "deny" and event.get("deny_reason"):
            return str(event["deny_reason"])
    return None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
