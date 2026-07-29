"""
MCPIP V2 — Forensic payload capture + retrieval test suite.

    ◐  "The agent wire stays opaque. The investigator's reconstruction is a
       separate, capability-gated, audited surface an agent can never reach."

Exercises the forensic side-channel end to end through Starlette's ``TestClient`` (so the
FastAPI lifespan — Redis rebind + epoch daemon — and every request run on one loop, as
production would). The environment is the SAME namespaced sandbox Redis / sandbox flag as
``tests/test_authorize_api.py`` (db ``/5``) so the two suites share one ``_components``
graph regardless of import order and never disagree on the store or the WORM stream.

Red-team targets covered here:
  * capture round-trips the already-normalized arguments (allow + staged-deny + deny);
  * secrets (password/api_key/jwt) are NEVER captured — redacted in the record AND absent
    from the ciphertext-at-rest blob;
  * retrieval REQUIRES CAP_FORENSIC_READ — a plain / directory-admin-only / no-bearer
    token is opaque-denied (capability confusion closed);
  * every retrieval emits exactly one WORM ``forensic_read`` (actor + subject) BEFORE
    disclosure, and does NOT re-embed the payload;
  * the agent wire is byte-unchanged and never references the store;
  * flag-off (store None) captures NOTHING and 404s;
  * a capture failure never blocks or flips the authorize decision;
  * cross-tenant read is an indistinguishable miss; malformed correlation ids 404 (no 5xx).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- MUST match tests/test_authorize_api.py so a shared _components graph agrees on the
#     Redis db + sandbox flag no matter which suite imports app.main first. ------------
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import json
import time
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from interfaces import CAP_DIRECTORY_ADMIN, CAP_FORENSIC_READ
from core.security import AGENT_FACING_DENY_MESSAGE

from app.main import _components, app
from main import _DemoIdP

_AUTO_ALIAS = "skill_spend_summary"       # tenant-acme AUTO, un-compartmented → allow.
_PIN_ALIAS = "skill_payroll_run"          # tenant-acme PIN_REQUIRED → staged-deny.
_FALCON_ALIAS = "skill_airframe_telemetry"  # aegis-dynamics compartmented → deny w/o entitlement.
_EVENTS_STREAM = "mcpip:worm:events"
_CORR_HEADER = "x-mcpip-correlation-id"


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
# Helpers.
# ---------------------------------------------------------------------------


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


def _corr_of(resp: Response) -> str:
    """The correlation id of a response (allow body, deny body, or the echoed header)."""
    data: Any = resp.json()
    if isinstance(data, dict) and isinstance(data.get("correlation_id"), str):
        return data["correlation_id"]
    header = resp.headers.get(_CORR_HEADER)
    assert header is not None, resp.text
    return header


def _forensic_get(client: TestClient, correlation_id: str, token: str) -> Response:
    return client.get(
        f"/v1/admin/forensic/{correlation_id}",
        headers={"Authorization": f"Bearer {token}"},
    )


def _wait_forensic(
    client: TestClient, correlation_id: str, token: str, *, tries: int = 60
) -> Response:
    """
    Poll the retrieval route until the fire-and-forget capture lands (or give up).

    Capture is dispatched as a background task on the portal loop; ``time.sleep`` yields
    to that loop thread so the encrypted write completes deterministically before the
    next poll. Returns the last response (200 on hit, 404 if never captured).
    """
    resp = _forensic_get(client, correlation_id, token)
    for _ in range(tries):
        if resp.status_code == 200:
            return resp
        time.sleep(0.05)
        resp = _forensic_get(client, correlation_id, token)
    return resp


def _forensic_read_events(subject_correlation_id: str) -> list[dict[str, Any]]:
    """All buffered WORM ``forensic_read`` events for a given subject correlation id."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=500)
    finally:
        reader.close()
    out: list[dict[str, Any]] = []
    for _sid, fields in entries:
        try:
            event = json.loads(fields["record"])["event"]
        except (ValueError, KeyError, TypeError):
            continue
        if (
            event.get("admin_action") == "forensic_read"
            and event.get("subject_correlation_id") == subject_correlation_id
        ):
            out.append(event)
    return out


def _raw_forensic_blob(tenant_id: str, correlation_id: str) -> Optional[str]:
    """The raw at-rest value of one forensic Redis key (should be b64 ciphertext)."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        return reader.get(f"mcpip:forensic:{tenant_id}:{correlation_id}")
    finally:
        reader.close()


def _forensic_token(idp: _DemoIdP, tenant_id: str = "tenant-acme") -> str:
    """A JWT holding CAP_FORENSIC_READ in ``tenant_id`` (the investigator)."""
    return idp.mint(
        tenant_id=tenant_id,
        agent_id="agent-forensic-investigator",
        capabilities=[CAP_FORENSIC_READ],
    )


# ---------------------------------------------------------------------------
# 1) Capture round-trips the normalized query (ALLOW terminal).
# ---------------------------------------------------------------------------


def test_capture_roundtrips_allow_query(client: TestClient, idp: _DemoIdP) -> None:
    assert _components.forensic is not None, "sandbox default should have capture ON"
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-alpha")
    args = {"period": "2026-Q2", "note": "quarterly", "nested": {"k": "v"}}
    resp = _post(client, alias=_AUTO_ALIAS, arguments=args, token=agent)
    assert resp.status_code == 200, resp.text
    corr = _corr_of(resp)

    inv = _forensic_token(idp)
    hit = _wait_forensic(client, corr, inv)
    assert hit.status_code == 200, hit.text
    body = hit.json()
    assert body["found"] is True
    rec = body["forensic"]
    # The reconstructed QUERY the agent sent.
    assert rec["alias"] == _AUTO_ALIAS
    assert rec["arguments"] == args
    assert rec["tenant_id"] == "tenant-acme"
    assert rec["agent_id"] == "agent-alpha"
    assert rec["decision"] == "allow"
    assert rec["source_format"] == "openai_tool_call"
    # Hidden topology never appears in the reconstruction.
    assert "target" not in rec
    assert "payload_hash" not in rec


# ---------------------------------------------------------------------------
# 2) Secrets are NEVER captured (redacted in the record AND in the ciphertext).
# ---------------------------------------------------------------------------


def test_secrets_never_captured(client: TestClient, idp: _DemoIdP) -> None:
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-secretcarrier")
    secret_val = "hunter2-super-secret"
    api_val = "sk-live-DEADBEEF"
    args = {
        "password": secret_val,
        "api_key": api_val,
        "aws_secret_access_key": "AKIA-SECRET",
        "note": "this stays visible",
    }
    resp = _post(client, alias=_AUTO_ALIAS, arguments=args, token=agent)
    assert resp.status_code == 200, resp.text
    corr = _corr_of(resp)

    inv = _forensic_token(idp)
    hit = _wait_forensic(client, corr, inv)
    assert hit.status_code == 200, hit.text
    rec_args = hit.json()["forensic"]["arguments"]
    # Secret-shaped keys scrubbed via the reused WORM _redact discipline.
    assert rec_args["password"] == "[REDACTED]"
    assert rec_args["api_key"] == "[REDACTED]"
    assert rec_args["aws_secret_access_key"] == "[REDACTED]"
    # Non-secret argument survives (an investigator still gets the real query shape).
    assert rec_args["note"] == "this stays visible"

    # Encryption at rest: the raw Redis blob is ciphertext — the secret VALUE and the
    # agent's JWT never appear in plaintext at rest.
    blob = _raw_forensic_blob("tenant-acme", corr)
    assert blob is not None
    assert secret_val not in blob
    assert api_val not in blob
    assert agent[:24] not in blob  # a slice of the JWT never lands in the capture.


# ---------------------------------------------------------------------------
# 3) Retrieval requires CAP_FORENSIC_READ (capability confusion closed).
# ---------------------------------------------------------------------------


def test_retrieval_requires_forensic_capability(client: TestClient, idp: _DemoIdP) -> None:
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-forcap")
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=agent)
    corr = _corr_of(resp)
    inv = _forensic_token(idp)
    _wait_forensic(client, corr, inv)  # ensure it IS captured first.

    # A plain agent token → opaque 403 (no capability).
    plain = idp.mint(tenant_id="tenant-acme", agent_id="agent-plain")
    denied = _forensic_get(client, corr, plain)
    assert denied.status_code == 403
    assert set(denied.json().keys()) == {"error", "correlation_id"}
    assert denied.json()["error"] == AGENT_FACING_DENY_MESSAGE

    # A DIRECTORY-ADMIN-only token does NOT confer forensic read (distinct capability).
    admin = idp.mint(
        tenant_id="tenant-acme",
        agent_id="agent-diradmin",
        capabilities=[CAP_DIRECTORY_ADMIN],
    )
    assert _forensic_get(client, corr, admin).status_code == 403

    # No bearer at all → 403.
    assert client.get(f"/v1/admin/forensic/{corr}").status_code == 403

    # The proper investigator token → 200.
    assert _forensic_get(client, corr, inv).status_code == 200


# ---------------------------------------------------------------------------
# 4) Every retrieval emits a WORM forensic_read BEFORE disclosure.
# ---------------------------------------------------------------------------


def test_retrieval_emits_worm_forensic_read(client: TestClient, idp: _DemoIdP) -> None:
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-audited")
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "audit"}, token=agent)
    corr = _corr_of(resp)
    inv = _forensic_token(idp)
    hit = _wait_forensic(client, corr, inv)
    assert hit.status_code == 200

    events = _forensic_read_events(corr)
    assert len(events) >= 1
    ev = events[0]
    assert ev["actor_agent_id"] == "agent-forensic-investigator"
    assert ev["subject_correlation_id"] == corr
    assert ev["found"] is True
    assert ev["tenant_id"] == "tenant-acme"
    # The reconstructed payload is NOT re-embedded in the audit record.
    assert "arguments" not in ev
    assert "forensic" not in ev

    # A MISS is also audited (audit-before-disclosure holds even when not found).
    missing = "deadbeef" * 4  # well-formed but never captured.
    miss = _forensic_get(client, missing, inv)
    assert miss.status_code == 404
    miss_events = _forensic_read_events(missing)
    assert len(miss_events) >= 1
    assert miss_events[0]["found"] is False


# ---------------------------------------------------------------------------
# 5) The agent wire never exposes the store.
# ---------------------------------------------------------------------------


def test_agent_wire_unchanged_and_opaque(client: TestClient, idp: _DemoIdP) -> None:
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-wire")
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "wire"}, token=agent)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # The allow receipt exposes only its documented fields — no forensic leakage.
    for banned in ("forensic", "target", "arguments", "payload_hash"):
        assert banned not in body
    # No response header advertises the capture store.
    joined = " ".join(resp.headers.keys()).lower()
    assert "forensic" not in joined

    # An agent token (no forensic cap) cannot reach the retrieval route at all.
    corr = _corr_of(resp)
    assert _forensic_get(client, corr, agent).status_code == 403


# ---------------------------------------------------------------------------
# 6) Staged-deny (PIN) and compartment-deny terminals are captured too.
# ---------------------------------------------------------------------------


def test_capture_staged_and_denied_terminals(client: TestClient, idp: _DemoIdP) -> None:
    inv = _forensic_token(idp)

    # PIN_REQUIRED with no pin → 202 staged-deny; the query is still captured.
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-staged")
    staged = _post(client, alias=_PIN_ALIAS, arguments={"amount": 42}, token=agent)
    assert staged.status_code == 202, staged.text
    staged_corr = _corr_of(staged)
    hit = _wait_forensic(client, staged_corr, inv)
    assert hit.status_code == 200
    srec = hit.json()["forensic"]
    assert srec["alias"] == _PIN_ALIAS
    assert srec["arguments"] == {"amount": 42}
    assert srec["decision"] == "deny"
    assert srec["deny_reason"] == "pin_required"

    # A compartment-denied request (aegis alias, unentitled acme agent) → 403; the
    # attempted query is captured for the investigator (identity + intent are known).
    denier = idp.mint(tenant_id="aegis-dynamics", agent_id="agent-nocompartment")
    denied = _post(client, alias=_FALCON_ALIAS, arguments={"sensor": "sat-1"}, token=denier)
    assert denied.status_code == 403
    dcorr = _corr_of(denied)
    inv_aegis = _forensic_token(idp, tenant_id="aegis-dynamics")
    dhit = _wait_forensic(client, dcorr, inv_aegis)
    assert dhit.status_code == 200
    drec = dhit.json()["forensic"]
    assert drec["alias"] == _FALCON_ALIAS
    assert drec["arguments"] == {"sensor": "sat-1"}
    assert drec["decision"] == "deny"


# ---------------------------------------------------------------------------
# 7) Cross-tenant read is an indistinguishable miss.
# ---------------------------------------------------------------------------


def test_cross_tenant_read_is_a_miss(client: TestClient, idp: _DemoIdP) -> None:
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-xt")
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "xt"}, token=agent)
    corr = _corr_of(resp)
    inv_acme = _forensic_token(idp, tenant_id="tenant-acme")
    assert _wait_forensic(client, corr, inv_acme).status_code == 200  # owner sees it.

    # An investigator in ANOTHER tenant requesting the SAME correlation id → 404, with no
    # exists-elsewhere oracle (key namespace + AAD both bind the caller's tenant).
    inv_other = _forensic_token(idp, tenant_id="tenant-globex")
    other = _forensic_get(client, corr, inv_other)
    assert other.status_code == 404


# ---------------------------------------------------------------------------
# 8) Malformed correlation ids 404 (no 5xx) — injection is validated pre-Redis.
# ---------------------------------------------------------------------------


def test_malformed_correlation_id_is_opaque_404(client: TestClient, idp: _DemoIdP) -> None:
    inv = _forensic_token(idp)
    for bad in ("with%20space", "..", "glob*star", "a" * 200):
        resp = _forensic_get(client, bad, inv)
        assert resp.status_code == 404, (bad, resp.status_code)
    # A path-traversal / newline segment cannot widen the key or 5xx.
    resp = client.get(
        "/v1/admin/forensic/mcpip:vault:tenant-acme",
        headers={"Authorization": f"Bearer {inv}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 9) Flag-off → nothing captured (store None during capture → honest miss).
# ---------------------------------------------------------------------------


def test_flag_off_captures_nothing(client: TestClient, idp: _DemoIdP) -> None:
    real_store = _components.forensic
    assert real_store is not None
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-flagoff")
    inv = _forensic_token(idp)

    # Simulate capture OFF for the duration of one authorize (the capture hook no-ops).
    _components.forensic = None
    try:
        resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "dark"}, token=agent)
        assert resp.status_code == 200, resp.text
        corr = _corr_of(resp)
        # With the feature off the endpoint 404s regardless.
        assert _forensic_get(client, corr, inv).status_code == 404
    finally:
        _components.forensic = real_store

    # Restore the feature and confirm nothing was captured while it was off.
    time.sleep(0.1)
    assert _forensic_get(client, corr, inv).status_code == 404


# ---------------------------------------------------------------------------
# 10) A capture failure never blocks or flips the authorize decision.
# ---------------------------------------------------------------------------


def test_capture_failure_never_blocks_authorize(client: TestClient, idp: _DemoIdP) -> None:
    store = _components.forensic
    assert store is not None
    agent = idp.mint(tenant_id="tenant-acme", agent_id="agent-failopen")

    async def _boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("simulated capture outage (bad key / Redis down)")

    original = store.capture
    store.capture = _boom  # type: ignore[method-assign]
    try:
        resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "boom"}, token=agent)
        # The ALLOW is unaffected — capture runs AFTER the decision + WORM emit and is
        # fully exception-swallowed, so a capture outage neither blocks nor flips it.
        assert resp.status_code == 200, resp.text
        assert resp.json()["decision"] == "allow"
        corr = _corr_of(resp)
        # Let the (raising) background task run; the loop stays healthy.
        time.sleep(0.1)
    finally:
        store.capture = original  # type: ignore[method-assign]

    # Nothing was persisted for the failed capture; retrieval is an honest miss.
    inv = _forensic_token(idp)
    assert _forensic_get(client, corr, inv).status_code == 404
    # And the gateway still authorizes normally after the outage.
    ok = _post(client, alias=_AUTO_ALIAS, arguments={"period": "recovered"}, token=agent)
    assert ok.status_code == 200, ok.text


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
