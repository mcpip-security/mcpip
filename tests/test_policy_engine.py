"""
MCPIP V2 — G3: deny-only policy overlay (velocity cap + amount ceiling) tests.

    ◐  "A policy can only ever say no. It never mints identity, never repoints a skill,
       never rescues a call an earlier gate refused."

Exercises the REAL policy engine (``services/policy_engine.py``) two ways:

  * ENGINE-LEVEL, against a real Redis (db ``/14``, isolated) with the real
    ``VelocityAmountPolicyEngine`` + ``PolicyDocStore`` + real velocity Lua: the
    velocity cap denies the (N+1)th action in the window and allows again after expiry;
    the amount ceiling denies over / allows under / refuses a non-numeric amount /
    no-ops an absent field; the pure amount check runs BEFORE the state-mutating
    velocity INCR; a missing document is the honest no-limits ``continue``; a Redis
    transport error or a malformed stored document fails CLOSED to a deny; and the
    strict write-time ``validate`` rejects every malformed rule shape.

  * PIPELINE-LEVEL, through Starlette's ``TestClient`` (sandbox, db ``/5``, the same
    shared ``_components`` graph the API suite uses): a POLICY_DENIED is opaque on the
    agent wire (only ``{error, correlation_id}``; the concrete reason lands in WORM
    only); the amount ceiling denies at PIN staging while an under-ceiling call falls
    THROUGH to the risk gate (proving ``continue`` never becomes an allow — deny-only);
    a PIN COMPLETION is NOT double-counted against velocity; and with NO document the
    gate imposes no limits.

Real config only — every policy document is written through the real
``PUT /v1/admin/policy`` admin surface or the real ``PolicyDocStore``; nothing is mocked
or fabricated.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- MUST match tests/test_authorize_api.py (db + sandbox flag). ---------------------
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import asyncio
import json
import time
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
import redis.asyncio as aioredis
from fastapi.testclient import TestClient
from httpx import Response

from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import (
    CAP_DIRECTORY_ADMIN,
    DenyReason,
    Identity,
    MAX_POLICY_RULES,
    PolicyContext,
    PolicyDecision,
    RiskTier,
)
from services.policy_engine import (
    POLICY_SCHEMA,
    PolicyDocStore,
    PolicyDocumentError,
    PolicyError,
    VelocityAmountPolicyEngine,
)

from app.main import _components, app
from main import _DemoIdP

_AUTO_ALIAS = "skill_spend_summary"       # tenant-acme AUTO.
_AUTO_ALIAS_2 = "skill_customer_lookup"   # tenant-acme AUTO (2nd, for isolation).
_WIRE_ALIAS = "skill_wire_transfer"       # tenant-acme PIN_REQUIRED (carries 'amount').
_PIN_ALIAS = "skill_payroll_run"          # tenant-acme PIN_REQUIRED.
_FALCON_ALIAS = "skill_falcon_telemetry"  # aegis-dynamics compartmented.
_EVENTS_STREAM = "mcpip:worm:events"
_CORR_HEADER = "x-mcpip-correlation-id"
_ENGINE_REDIS_URL = "redis://localhost:63790/14"  # isolated engine-level db.


# ---------------------------------------------------------------------------
# Fixtures / helpers.
# ---------------------------------------------------------------------------


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


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


@pytest.fixture(autouse=True)
def _clear_policy_state() -> Iterator[None]:
    """Drop every policy doc + velocity counter (both dbs) before each test so a stored
    document / fixed-window counter never leaks across tests."""
    for url in (_TEST_REDIS_URL, _ENGINE_REDIS_URL):
        r: Any = redis_sync.Redis.from_url(url, decode_responses=True)
        try:
            for key in r.scan_iter(match="mcpip:policy:*"):
                r.delete(key)
        finally:
            r.close()
    yield


async def _fresh_engine() -> tuple[VelocityAmountPolicyEngine, PolicyDocStore, Any]:
    redis_client: Any = aioredis.from_url(_ENGINE_REDIS_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    store = PolicyDocStore(redis_client)
    engine = VelocityAmountPolicyEngine(redis_client, store)
    return engine, store, redis_client


def _velocity_doc(alias: str, max_actions: int, window_seconds: int) -> dict[str, Any]:
    return {
        "schema": POLICY_SCHEMA,
        "rules": [
            {
                "kind": "velocity",
                "scope": "alias",
                "scope_value": alias,
                "max_actions": max_actions,
                "window_seconds": window_seconds,
            }
        ],
    }


def _amount_doc(alias: str, field: str, max_amount: str) -> dict[str, Any]:
    return {
        "schema": POLICY_SCHEMA,
        "rules": [
            {
                "kind": "amount",
                "scope": "alias",
                "scope_value": alias,
                "amount_field": field,
                "max_amount": max_amount,
            }
        ],
    }


def _ctx(
    identity: Identity,
    alias: str,
    *,
    risk_tier: RiskTier = RiskTier.AUTO,
    transport_class: str = "cloud_rest",
    arguments: Optional[dict[str, Any]] = None,
) -> PolicyContext:
    return PolicyContext(
        identity=identity,
        alias=alias,
        transport_class=transport_class,
        risk_tier=risk_tier,
        arguments=arguments or {},
    )


def _identity(idp: _DemoIdP, agent_id: str, tenant_id: str = "tenant-acme") -> Identity:
    return _components.auth.verify_identity(
        idp.mint(tenant_id=tenant_id, agent_id=agent_id)
    )


# ---- pipeline helpers -------------------------------------------------------


def _openai_call(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "call_test",
        "type": "function",
        "function": {"name": alias, "arguments": json.dumps(arguments)},
    }


def _post(
    client: TestClient,
    *,
    alias: str,
    arguments: dict[str, Any],
    token: Optional[str] = None,
    pin: Optional[str] = None,
    challenge_id: Optional[str] = None,
) -> Response:
    body: dict[str, Any] = {
        "source_format": "openai_tool_call",
        "tool_call": _openai_call(alias, arguments),
    }
    if token is not None:
        body["jwt"] = token
    if pin is not None:
        body["pin"] = pin
    if challenge_id is not None:
        body["challenge_id"] = challenge_id
    return client.post("/v1/authorize", json=body)


def _put_policy(client: TestClient, admin_token: str, document: dict[str, Any]) -> Response:
    return client.put(
        "/v1/admin/policy",
        json=document,
        headers={"Authorization": f"Bearer {admin_token}"},
    )


def _last_deny_reason() -> Optional[str]:
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=1)
    finally:
        reader.close()
    if not entries:
        return None
    _sid, fields = entries[0]
    reason = json.loads(fields["record"])["event"].get("deny_reason")
    return reason if isinstance(reason, str) else None


def _assert_opaque_denial(resp: Response) -> None:
    assert resp.status_code == 403, resp.text
    data = resp.json()
    assert set(data.keys()) == {"error", "correlation_id"}, data
    assert data["error"] == AGENT_FACING_DENY_MESSAGE
    assert resp.headers.get(_CORR_HEADER) == data["correlation_id"]


def _admin_token(idp: _DemoIdP) -> str:
    return idp.mint(
        tenant_id="tenant-acme",
        agent_id="agent-policy-admin",
        capabilities=[CAP_DIRECTORY_ADMIN],
    )


def _authenticator_otp(client: TestClient, challenge_id: str, token: str) -> str:
    resp = client.get(
        f"/v1/authenticator/{challenge_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    return str(resp.json()["otp"])


# ===========================================================================
# ENGINE-LEVEL — velocity cap.
# ===========================================================================


def test_no_policy_configured_continues(idp: _DemoIdP) -> None:
    async def scenario() -> None:
        engine, _store, redis_client = await _fresh_engine()
        try:
            identity = _identity(idp, "agent-nopolicy")
            decision = await engine.evaluate(_ctx(identity, _AUTO_ALIAS))
            # No document at all → opt-in honest no-limits (never a fabricated rule).
            assert decision.outcome == "continue"
        finally:
            await redis_client.aclose()

    _run(scenario())


def test_velocity_cap_denies_after_limit(idp: _DemoIdP) -> None:
    async def scenario() -> None:
        engine, store, redis_client = await _fresh_engine()
        try:
            identity = _identity(idp, "agent-vel")
            await store.put(
                identity.tenant_id,
                PolicyDocStore.validate(_velocity_doc(_AUTO_ALIAS, 2, 3600)),
            )
            ctx = _ctx(identity, _AUTO_ALIAS)
            # First two calls in the window are under the cap.
            assert (await engine.evaluate(ctx)).outcome == "continue"
            assert (await engine.evaluate(ctx)).outcome == "continue"
            # The third trips the fixed-window cap.
            third = await engine.evaluate(ctx)
            assert third.outcome == "deny"
            assert "velocity" in third.detail.lower()
            # A DIFFERENT alias is a distinct scope — unaffected by the tripped counter.
            assert (
                await engine.evaluate(_ctx(identity, _AUTO_ALIAS_2))
            ).outcome == "continue"
        finally:
            await redis_client.aclose()

    _run(scenario())


def test_velocity_window_expiry_allows_again(idp: _DemoIdP) -> None:
    async def scenario() -> None:
        engine, store, redis_client = await _fresh_engine()
        try:
            identity = _identity(idp, "agent-velexpiry")
            await store.put(
                identity.tenant_id,
                PolicyDocStore.validate(_velocity_doc(_AUTO_ALIAS, 1, 1)),
            )
            ctx = _ctx(identity, _AUTO_ALIAS)
            assert (await engine.evaluate(ctx)).outcome == "continue"
            assert (await engine.evaluate(ctx)).outcome == "deny"  # 2nd in window.
            # Let the 1s fixed window lapse; the counter EXPIREs and the cap resets.
            time.sleep(1.2)
            assert (await engine.evaluate(ctx)).outcome == "continue"
        finally:
            await redis_client.aclose()

    _run(scenario())


# ===========================================================================
# ENGINE-LEVEL — amount ceiling.
# ===========================================================================


def test_amount_ceiling_over_under_and_boundary(idp: _DemoIdP) -> None:
    async def scenario() -> None:
        engine, store, redis_client = await _fresh_engine()
        try:
            identity = _identity(idp, "agent-amount")
            await store.put(
                identity.tenant_id,
                PolicyDocStore.validate(_amount_doc(_WIRE_ALIAS, "amount", "1000")),
            )

            async def _e(args: dict[str, Any]) -> PolicyDecision:
                return await engine.evaluate(
                    _ctx(
                        identity, _WIRE_ALIAS,
                        risk_tier=RiskTier.PIN_REQUIRED, arguments=args,
                    )
                )

            # Under / at the ceiling → continue (equal is NOT over).
            assert (await _e({"amount": 500})).outcome == "continue"
            assert (await _e({"amount": 1000})).outcome == "continue"
            # Over the ceiling → deny (int and float, no drift).
            assert (await _e({"amount": 1000.01})).outcome == "deny"
            assert (await _e({"amount": 5000})).outcome == "deny"
            # A string amount is the evasion — fail CLOSED, never coerce.
            nonnum = await _e({"amount": "5000"})
            assert nonnum.outcome == "deny" and "non-numeric" in nonnum.detail.lower()
            # bool is a subclass of int — excluded, denied as non-numeric.
            assert (await _e({"amount": True})).outcome == "deny"
            # A non-finite amount (NaN/±Infinity — json.loads accepts bare NaN/Infinity)
            # constructs a Decimal without error, but the `> ceiling` comparison would
            # raise; it MUST fail CLOSED to a deny here, not throw out of the checker.
            nan_dec = await _e({"amount": float("nan")})
            assert nan_dec.outcome == "deny" and "finite" in nan_dec.detail.lower()
            assert (await _e({"amount": float("inf")})).outcome == "deny"
            assert (await _e({"amount": float("-inf")})).outcome == "deny"
            # An ABSENT named field is a no-op (schema-unknown → never guess).
            assert (await _e({"to": "acct-1"})).outcome == "continue"
        finally:
            await redis_client.aclose()

    _run(scenario())


def test_amount_checked_before_velocity_incr(idp: _DemoIdP) -> None:
    async def scenario() -> None:
        engine, store, redis_client = await _fresh_engine()
        try:
            identity = _identity(idp, "agent-order")
            # Same alias carries BOTH an amount ceiling and a max-1 velocity cap.
            doc = {
                "schema": POLICY_SCHEMA,
                "rules": [
                    {
                        "kind": "amount", "scope": "alias", "scope_value": _WIRE_ALIAS,
                        "amount_field": "amount", "max_amount": "1000",
                    },
                    {
                        "kind": "velocity", "scope": "alias", "scope_value": _WIRE_ALIAS,
                        "max_actions": 1, "window_seconds": 3600,
                    },
                ],
            }
            await store.put(identity.tenant_id, PolicyDocStore.validate(doc))
            vel_key = f"mcpip:policy:vel:{identity.tenant_id}:alias:{_WIRE_ALIAS}"

            def over() -> PolicyContext:
                return _ctx(
                    identity, _WIRE_ALIAS,
                    risk_tier=RiskTier.PIN_REQUIRED, arguments={"amount": 9000},
                )

            def under() -> PolicyContext:
                return _ctx(
                    identity, _WIRE_ALIAS,
                    risk_tier=RiskTier.PIN_REQUIRED, arguments={"amount": 10},
                )

            # An over-ceiling request denies on AMOUNT and must NOT consume velocity
            # budget — the pure ceiling check precedes the state-mutating INCR.
            assert (await engine.evaluate(over())).outcome == "deny"
            assert await redis_client.get(vel_key) is None  # no INCR happened.

            # An under-ceiling request passes the ceiling and consumes one velocity slot.
            assert (await engine.evaluate(under())).outcome == "continue"
            assert await redis_client.get(vel_key) == "1"
            # The next under-ceiling request trips the (now-exhausted) velocity cap.
            assert (await engine.evaluate(under())).outcome == "deny"
        finally:
            await redis_client.aclose()

    _run(scenario())


# ===========================================================================
# ENGINE-LEVEL — fail-closed (missing / malformed doc / transport error).
# ===========================================================================


def test_malformed_stored_document_fails_closed(idp: _DemoIdP) -> None:
    async def scenario() -> None:
        engine, store, redis_client = await _fresh_engine()
        try:
            identity = _identity(idp, "agent-malformed")
            key = f"mcpip:policy:doc:{identity.tenant_id}"
            # A stored doc that is valid JSON but not a valid ruleset (direct tamper).
            await redis_client.set(key, json.dumps({"schema": "wrong", "rules": []}))
            decision = await engine.evaluate(_ctx(identity, _AUTO_ALIAS))
            assert decision.outcome == "deny"
            assert "unavailable" in decision.detail.lower()
            # Non-JSON garbage at rest → also fail closed (never silently continue).
            await redis_client.set(key, ")(*&not-json")
            assert (await engine.evaluate(_ctx(identity, _AUTO_ALIAS))).outcome == "deny"
            # And the fail-closed read raises the internal PolicyError for the engine.
            with pytest.raises(PolicyError):
                await store.load(identity.tenant_id)
        finally:
            await redis_client.aclose()

    _run(scenario())


def test_redis_transport_error_fails_closed(idp: _DemoIdP) -> None:
    async def scenario() -> None:
        # Point the engine at a dead endpoint so the real Redis GET raises RedisError.
        dead: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
            "redis://localhost:1/0",
            socket_connect_timeout=0.2,
            socket_timeout=0.2,
        )
        engine = VelocityAmountPolicyEngine(dead, PolicyDocStore(dead))
        try:
            identity = _identity(idp, "agent-deadredis")
            decision = await engine.evaluate(_ctx(identity, _AUTO_ALIAS))
            # A transport error is fail-closed POLICY_DENIED, never a silent allow.
            assert decision.outcome == "deny"
        finally:
            await dead.aclose()

    _run(scenario())


# ===========================================================================
# ENGINE-LEVEL — strict write-time validation & deny-only decision shape.
# ===========================================================================


def test_validate_rejects_malformed_documents() -> None:
    good = PolicyDocStore.validate(_velocity_doc(_AUTO_ALIAS, 3, 60))
    assert good["schema"] == POLICY_SCHEMA and len(good["rules"]) == 1

    bad_docs: list[Any] = [
        "not-a-dict",
        {"rules": []},                                  # missing schema.
        {"schema": "mcpip-policy/2", "rules": []},      # unknown schema.
        {"schema": POLICY_SCHEMA, "rules": [           # unknown kind.
            {"kind": "quota", "scope": "alias", "scope_value": "x"}]},
        {"schema": POLICY_SCHEMA, "rules": [           # velocity missing fields.
            {"kind": "velocity", "scope": "alias", "scope_value": "x"}]},
        {"schema": POLICY_SCHEMA, "rules": [           # amount missing fields.
            {"kind": "amount", "scope": "alias", "scope_value": "x"}]},
        {"schema": POLICY_SCHEMA, "rules": [           # amount carrying velocity fields.
            {"kind": "amount", "scope": "alias", "scope_value": "x",
             "amount_field": "a", "max_amount": "1", "max_actions": 5}]},
        {"schema": POLICY_SCHEMA, "rules": [           # invalid scope.
            {"kind": "velocity", "scope": "role", "scope_value": "x",
             "max_actions": 1, "window_seconds": 60}]},
        {"schema": POLICY_SCHEMA, "rules": [           # non-decimal max_amount.
            {"kind": "amount", "scope": "alias", "scope_value": "x",
             "amount_field": "a", "max_amount": "abc"}]},
        {"schema": POLICY_SCHEMA, "rules": [           # too many rules.
            {"kind": "velocity", "scope": "alias", "scope_value": str(i),
             "max_actions": 1, "window_seconds": 60}
            for i in range(MAX_POLICY_RULES + 1)]},
    ]
    for doc in bad_docs:
        with pytest.raises(PolicyDocumentError):
            PolicyDocStore.validate(doc)


def test_policy_decision_is_structurally_deny_only() -> None:
    # There is deliberately no allow/override outcome — only continue | deny.
    assert PolicyDecision(outcome="continue").outcome == "continue"
    assert PolicyDecision(outcome="deny", detail="x").outcome == "deny"
    with pytest.raises(Exception):
        PolicyDecision(outcome="allow")  # type: ignore[arg-type]
    # PolicyContext is frozen — a provider cannot mutate the intent/target it sees.
    ctx = PolicyContext(
        identity=_components.auth.verify_identity(_frozen_probe_token()),
        alias="a", transport_class="cloud_rest",
        risk_tier=RiskTier.AUTO, arguments={},
    )
    with pytest.raises(Exception):
        ctx.alias = "other"  # type: ignore[misc]


def _frozen_probe_token() -> str:
    demo = _components.demo_idp
    assert demo is not None
    return demo.mint(tenant_id="tenant-acme", agent_id="agent-frozen-probe")


# ===========================================================================
# PIPELINE-LEVEL — opacity, deny-only, exactly-once, no-policy.
# ===========================================================================


def test_pipeline_velocity_denied_is_opaque(client: TestClient, idp: _DemoIdP) -> None:
    admin = _admin_token(idp)
    assert _put_policy(client, admin, _velocity_doc(_AUTO_ALIAS, 1, 3600)).status_code == 200

    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-vel-wire")
    # First AUTO call under the cap → allow.
    first = _post(client, alias=_AUTO_ALIAS, arguments={"period": "q1"}, token=agent)
    assert first.status_code == 200, first.text
    # Second within the window → POLICY_DENIED, but the agent sees only the opaque
    # envelope; the concrete reason lands in WORM ONLY.
    second = _post(client, alias=_AUTO_ALIAS, arguments={"period": "q2"}, token=agent)
    _assert_opaque_denial(second)
    assert _last_deny_reason() == DenyReason.POLICY_DENIED.value


def test_pipeline_amount_over_denies_under_falls_through(
    client: TestClient, idp: _DemoIdP
) -> None:
    admin = _admin_token(idp)
    assert _put_policy(client, admin, _amount_doc(_WIRE_ALIAS, "amount", "1000")).status_code == 200

    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-amt-wire")
    # Over the ceiling → POLICY_DENIED at the staging pass (BEFORE the PIN is minted).
    over = _post(client, alias=_WIRE_ALIAS, arguments={"amount": 5000, "to": "x"}, token=agent)
    _assert_opaque_denial(over)
    assert _last_deny_reason() == DenyReason.POLICY_DENIED.value

    # Under the ceiling → policy CONTINUEs and falls through to the risk gate, which
    # stages a PIN (202). Proof that deny-only 'continue' is NOT an allow — the policy
    # can never rescue a PIN_REQUIRED action into a 200.
    under = _post(client, alias=_WIRE_ALIAS, arguments={"amount": 500, "to": "x"}, token=agent)
    assert under.status_code == 202, under.text
    assert "challenge_id" in under.json()


def test_pipeline_pin_completion_not_double_counted(
    client: TestClient, idp: _DemoIdP
) -> None:
    admin = _admin_token(idp)
    # max_actions=1 on a PIN_REQUIRED alias: exactly one STAGING is allowed per window.
    assert _put_policy(client, admin, _velocity_doc(_PIN_ALIAS, 1, 3600)).status_code == 200

    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-once")
    args = {"run": "2026-07", "amount": 10}

    # Staging #1 counts one velocity slot → 202.
    staged = _post(client, alias=_PIN_ALIAS, arguments=args, token=agent)
    assert staged.status_code == 202, staged.text
    challenge_id = staged.json()["challenge_id"]
    otp = _authenticator_otp(client, challenge_id, agent)

    # COMPLETION (pin + challenge) is the PIN-completion pass → the policy gate is
    # SKIPPED, so it does NOT consume a second velocity slot. The action completes.
    done = _post(
        client, alias=_PIN_ALIAS, arguments=args, token=agent,
        pin=otp, challenge_id=challenge_id,
    )
    assert done.status_code == 200, done.text
    assert done.json()["decision"] == "allow"

    # A brand-new STAGING would be the 2nd counted action in the window → POLICY_DENIED.
    # (If completion had been counted, the count would already be >1; either way the
    # invariant we assert is that staging is counted and completion is not.)
    restage = _post(client, alias=_PIN_ALIAS, arguments=args, token=agent)
    _assert_opaque_denial(restage)
    assert _last_deny_reason() == DenyReason.POLICY_DENIED.value


def test_pipeline_no_policy_imposes_no_limits(client: TestClient, idp: _DemoIdP) -> None:
    # The autouse fixture cleared every policy doc → honest no-limits state.
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-unlimited")
    for i in range(4):
        resp = _post(
            client, alias=_AUTO_ALIAS_2, arguments={"id": f"c-{i}"}, token=agent
        )
        assert resp.status_code == 200, resp.text


def test_pipeline_policy_cannot_rescue_prior_deny(client: TestClient, idp: _DemoIdP) -> None:
    # Even with a permissive (empty-rules) policy stored, an entitlement deny that
    # precedes the policy gate still denies — the overlay is deny-only, never a rescue.
    admin = _admin_token(idp)
    assert _put_policy(
        client, admin, {"schema": POLICY_SCHEMA, "rules": []}
    ).status_code == 200

    # An acme agent reaching an aegis-only alias is denied at the entitlement layer,
    # upstream of the policy gate — the (empty) policy neither runs a rescue nor flips it.
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-norescue")
    resp = _post(client, alias=_FALCON_ALIAS, arguments={"sensor": "s1"}, token=agent)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() != DenyReason.POLICY_DENIED.value


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
