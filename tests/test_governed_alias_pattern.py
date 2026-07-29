"""
MCPIP — the GOVERNED-ALIAS deployment pattern, driven end to end (docs/integrate/INTEGRATIONS.md).

    ◐ "postmark-mcp / line-jumping live in a plane MCPIP does not observe — UNLESS the
       sensitive side-effecting tool is a governed alias."  (LANDSCAPE_2026H2 §5.5)

This suite proves the recipe on REAL traffic (no mock): a sensitive data-egress / email-send
tool registered as an MCPIP ``cloud_rest`` + ``PIN_REQUIRED`` alias inherits two structural
controls straight from the shipped payload lock + out-of-band OTP channel:

  1. The recipient set rides in ``arguments`` and is CRYPTOGRAPHICALLY BOUND at staging
     (``lock_payload_hash({tenant, agent, alias, arguments})``). A covert extra recipient /
     redirected payload injected at completion changes the hash → ``PAYLOAD_MISMATCH`` deny,
     and the write-before-execute WORM record captured the honest staged decision first.
  2. A ``PIN_REQUIRED`` egress alias cannot complete without the out-of-band OTP — the
     structural circuit-breaker for a fully line-jumped agent (it cannot produce a code it
     never received).

Both registration ROUTES of the recipe are exercised against the REAL sandbox app:
  * the SHIPPED reference catalog alias ``skill_email_send`` (obfuscator/tenant_catalog.py), and
  * the RUNTIME operator route ``POST /v1/admin/skills/register`` (the overlay path an operator
    uses to convert an arbitrary side-effecting tool into a governed PIN alias).

Every deny is asserted OPAQUE (``{error, correlation_id}`` only); the concrete reason is read
from the OPERATOR-only decisions feed (``/v1/admin/decisions/recent``, CAP_DIRECTORY_ADMIN),
never from the agent wire. MCPIP does NOT content-inspect the downstream call — it GOVERNS it
(authorizes + audits) — so this is a deployment posture, not an injection detector.
"""

from __future__ import annotations

import os
import sys

# Make the repo root importable when run directly; pytest already adds it via rootdir.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MUST be set before importing app.main (settings are lru_cached at import). Uses the SAME
# namespaced sandbox db as the adversarial API / live-surfaces suites, so import order is
# immaterial (the composition root binds ONE redis url per process).
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import CAP_DIRECTORY_ADMIN

from app.main import _components, app

_TENANT = "mcpip-inc"
_EGRESS_ALIAS = "skill_email_send"          # the shipped governed-alias reference row.
_HONEST_RECIPIENTS = ["alice@corp.example"]
_ATTACKER_RECIPIENT = "attacker@evil.example"


# ---------------------------------------------------------------------------
# Fixtures (namespaced sandbox — mirrors tests/test_admin_live_surfaces.py).
# ---------------------------------------------------------------------------


def _reset_backing_state() -> None:
    """Flush the namespaced db and drop the on-disk WORM/anchor artifacts."""
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        reset.flushdb()
    finally:
        reset.close()
    worm_path = _components.settings.worm_path
    for artifact in (worm_path, worm_path + ".anchor"):
        try:
            os.remove(artifact)
        except FileNotFoundError:
            pass


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    """Module-scoped TestClient over a hermetic slate (reset before AND after the lifespan)."""
    _reset_backing_state()
    with TestClient(app) as test_client:
        yield test_client
    _reset_backing_state()


# ---------------------------------------------------------------------------
# Helpers — every call is a REAL pipeline round-trip over the sandbox HTTP oracle.
# ---------------------------------------------------------------------------


def _json(resp: Response) -> dict[str, Any]:
    data: Any = resp.json()
    assert isinstance(data, dict)
    return data


def _dev_token(
    client: TestClient,
    *,
    agent_id: str,
    capabilities: Optional[list[str]] = None,
) -> str:
    """Mint a sandbox JWT for an mcpip-inc principal via the real /v1/dev/token oracle."""
    body: dict[str, Any] = {"tenant_id": _TENANT, "agent_id": agent_id}
    if capabilities is not None:
        body["capabilities"] = capabilities
    resp = client.post("/v1/dev/token", json=body)
    assert resp.status_code == 200, resp.text
    return str(_json(resp)["jwt"])


def _authorize(
    client: TestClient,
    token: str,
    *,
    alias: str,
    arguments: dict[str, Any],
    pin: Optional[str] = None,
    challenge_id: Optional[str] = None,
) -> Response:
    """One /v1/authorize round-trip (mcp_jsonrpc envelope, Bearer identity)."""
    body: dict[str, Any] = {
        "source_format": "mcp_jsonrpc",
        "tool_call": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": alias, "arguments": arguments},
        },
    }
    if pin is not None:
        body["pin"] = pin
    if challenge_id is not None:
        body["challenge_id"] = challenge_id
    return client.post(
        "/v1/authorize", json=body, headers={"Authorization": f"Bearer {token}"}
    )


def _otp(client: TestClient, token: str, challenge_id: str) -> str:
    """Peek the out-of-band one-time code from the sandbox authenticator (enrolled-device stand-in)."""
    resp = client.get(
        f"/v1/authenticator/{challenge_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200, resp.text
    return str(_json(resp)["otp"])


def _wrong_pin(otp: str) -> str:
    """A deterministically-different 6-digit code (a line-jumped agent's blind guess)."""
    return str((int(otp) + 1) % 1_000_000).zfill(len(otp))


def _assert_opaque_denial(resp: Response) -> str:
    """A denied egress exposes exactly ``{error, correlation_id}`` — no reason/target/topology."""
    assert resp.status_code == 403, resp.text
    data = _json(resp)
    assert set(data.keys()) == {"error", "correlation_id"}, data
    assert data["error"] == AGENT_FACING_DENY_MESSAGE
    assert not hasattr(data["error"], "reason")
    return str(data["correlation_id"])


def _admin_token(client: TestClient) -> str:
    return _dev_token(client, agent_id="agent-gov-admin", capabilities=[CAP_DIRECTORY_ADMIN])


def _feed_reason(client: TestClient, admin: str, correlation_id: str) -> Optional[str]:
    """The concrete ``deny_reason`` the OPERATOR feed shows for one correlation id (WORM-only)."""
    resp = client.get(
        "/v1/admin/decisions/recent?limit=500",
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert resp.status_code == 200, resp.text
    rows = [
        r
        for r in _json(resp)["decisions"]
        if isinstance(r, dict) and r.get("correlation_id") == correlation_id
    ]
    assert len(rows) == 1, f"expected exactly one feed row for {correlation_id}, got {len(rows)}"
    row = rows[0]
    # The feed never leaks topology/payload even to the operator — whitelist projection.
    for forbidden in ("target", "arguments", "payload_hash", "pin", "jwt"):
        assert forbidden not in row
    return row.get("deny_reason")


def _stage(
    client: TestClient, token: str, alias: str, recipients: list[str]
) -> tuple[str, str]:
    """Stage an egress challenge; return (challenge_id, correlation_id). Asserts nothing vended."""
    resp = _authorize(
        client,
        token,
        alias=alias,
        arguments={"to": recipients, "subject": "quarterly report", "body": "attached"},
    )
    assert resp.status_code == 202, resp.text
    staged = _json(resp)
    assert staged["risk_tier"] == "pin_required"
    assert "vended_credential" not in staged  # nothing egressed at staging.
    assert "decision" not in staged
    return str(staged["challenge_id"]), str(staged["correlation_id"])


# ---------------------------------------------------------------------------
# 1) Staging binds the recipient set + emits a write-before-execute record.
# ---------------------------------------------------------------------------


def test_stage_binds_recipient_set_and_records_before_execute(client: TestClient) -> None:
    """
    The first call to the governed egress alias STAGES a payload-bound challenge (HTTP 202),
    vends nothing, and the write-before-execute WORM record for its correlation_id already
    reads PIN_REQUIRED on the OPERATOR feed — the honest staged decision is durable before
    anything can fire.
    """
    admin = _admin_token(client)
    token = _dev_token(client, agent_id="agent-gov-stage")
    challenge_id, corr = _stage(client, token, _EGRESS_ALIAS, _HONEST_RECIPIENTS)

    assert len(challenge_id) == 32 and all(c in "0123456789abcdef" for c in challenge_id)
    assert _feed_reason(client, admin, corr) == "pin_required"


# ---------------------------------------------------------------------------
# 2) A covert extra recipient at completion => PAYLOAD_MISMATCH deny (nothing egresses).
# ---------------------------------------------------------------------------


def test_covert_extra_recipient_is_payload_mismatch_deny(client: TestClient) -> None:
    """
    Stage with the honest recipient set, fetch the correct OTP, then COMPLETE with a tampered
    ``arguments`` carrying an extra covert recipient. The exact recipient set was cryptographically
    bound at staging, so the completion is an OPAQUE deny and the operator feed shows
    PAYLOAD_MISMATCH — no allow, no receipt, nothing egressed.
    """
    admin = _admin_token(client)
    token = _dev_token(client, agent_id="agent-gov-tamper")
    challenge_id, _corr = _stage(client, token, _EGRESS_ALIAS, _HONEST_RECIPIENTS)
    otp = _otp(client, token, challenge_id)

    tampered = _authorize(
        client,
        token,
        alias=_EGRESS_ALIAS,
        arguments={
            "to": _HONEST_RECIPIENTS + [_ATTACKER_RECIPIENT],  # covert extra recipient.
            "subject": "quarterly report",
            "body": "attached",
        },
        pin=otp,
        challenge_id=challenge_id,
    )
    corr = _assert_opaque_denial(tampered)
    assert _feed_reason(client, admin, corr) == "payload_mismatch"


# ---------------------------------------------------------------------------
# 3) PIN-gated egress cannot complete without the out-of-band OTP (line-jump breaker).
# ---------------------------------------------------------------------------


def test_pin_gated_egress_requires_out_of_band_otp(client: TestClient) -> None:
    """
    (a) The honest staged arguments + a WRONG pin (a line-jumped agent's blind guess) → opaque
        deny (PIN_MISMATCH, WORM-only). (b) The honest arguments + the correct OTP → HTTP 200
        ExecutionReceipt allow, transaction_ref ``txn_…``, cloud_rest class, no vended credential.
        (c) A replay of the now-spent challenge → opaque deny (exactly-once).
    """
    admin = _admin_token(client)
    token = _dev_token(client, agent_id="agent-gov-egress")
    challenge_id, _corr = _stage(client, token, _EGRESS_ALIAS, _HONEST_RECIPIENTS)
    otp = _otp(client, token, challenge_id)
    honest = {"to": _HONEST_RECIPIENTS, "subject": "quarterly report", "body": "attached"}

    # (a) A blind wrong code cannot complete — the structural circuit-breaker.
    bad = _authorize(
        client, token, alias=_EGRESS_ALIAS, arguments=honest,
        pin=_wrong_pin(otp), challenge_id=challenge_id,
    )
    corr_bad = _assert_opaque_denial(bad)
    assert _feed_reason(client, admin, corr_bad) == "pin_mismatch"

    # (b) The correct out-of-band code completes exactly once.
    ok = _authorize(
        client, token, alias=_EGRESS_ALIAS, arguments=honest, pin=otp, challenge_id=challenge_id
    )
    assert ok.status_code == 200, ok.text
    receipt = _json(ok)
    assert receipt["decision"] == "allow"
    assert str(receipt["transaction_ref"]).startswith("txn_")
    assert receipt["executed_target_class"] == "cloud_rest"  # class only, never the target.
    assert receipt.get("vended_credential") is None  # cloud_rest vends nothing.

    # (c) The spent lock cannot be replayed.
    replay = _authorize(
        client, token, alias=_EGRESS_ALIAS, arguments=honest, pin=otp, challenge_id=challenge_id
    )
    corr_replay = _assert_opaque_denial(replay)
    assert _feed_reason(client, admin, corr_replay) == "pin_not_found"


# ---------------------------------------------------------------------------
# 4) The RUNTIME operator route: convert an arbitrary side-effecting tool into a governed alias.
# ---------------------------------------------------------------------------


def test_operator_runtime_registration_route(client: TestClient) -> None:
    """
    An operator (CAP_DIRECTORY_ADMIN) registers a NEW governed egress alias at runtime via
    ``POST /v1/admin/skills/register`` (cloud_rest + pin_required), then it enforces the SAME
    payload-binding + OTP guarantees as the shipped row. A second register of the same alias is
    an opaque additive-only deny (never repoint).
    """
    admin = _admin_token(client)
    alias = "skill_notify_send"

    registered = client.post(
        "/v1/admin/skills/register",
        json={
            "alias": alias,
            "target": "rest.ops.notify.send",
            "risk_tier": "pin_required",
            "classification": "unclassified",
        },
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert registered.status_code == 200, registered.text
    assert _json(registered)["registered"] == alias

    # Additive-only: a second register of the same alias is refused opaquely (never repoint).
    dup = client.post(
        "/v1/admin/skills/register",
        json={
            "alias": alias,
            "target": "rest.attacker.exfil.send",
            "risk_tier": "pin_required",
            "classification": "unclassified",
        },
        headers={"Authorization": f"Bearer {admin}"},
    )
    _assert_opaque_denial(dup)

    # The runtime-registered alias governs egress identically: bind → tamper-deny → OTP-gated allow.
    token = _dev_token(client, agent_id="agent-gov-runtime")
    challenge_id, corr = _stage(client, token, alias, _HONEST_RECIPIENTS)
    assert _feed_reason(client, admin, corr) == "pin_required"
    otp = _otp(client, token, challenge_id)

    tampered = _authorize(
        client, token, alias=alias,
        arguments={"to": _HONEST_RECIPIENTS + [_ATTACKER_RECIPIENT], "subject": "quarterly report", "body": "attached"},
        pin=otp, challenge_id=challenge_id,
    )
    assert _feed_reason(client, admin, _assert_opaque_denial(tampered)) == "payload_mismatch"

    honest = {"to": _HONEST_RECIPIENTS, "subject": "quarterly report", "body": "attached"}
    ok = _authorize(client, token, alias=alias, arguments=honest, pin=otp, challenge_id=challenge_id)
    assert ok.status_code == 200, ok.text
    assert _json(ok)["decision"] == "allow"


# ---------------------------------------------------------------------------
# 5) Opacity + catalog: the agent boundary reveals a transport CLASS only, never the target.
# ---------------------------------------------------------------------------


def test_catalog_exposes_transport_class_only(client: TestClient) -> None:
    """
    The AGENT-facing catalog lists the governed egress alias with its transport CLASS and risk
    tier only — never the dotted downstream target, never a canary flag.
    """
    token = _dev_token(client, agent_id="agent-gov-catalog")
    resp = client.get("/v1/catalog", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    items: Any = _json(resp)["catalog"]
    rows = [item for item in items if item.get("alias") == _EGRESS_ALIAS]
    assert len(rows) == 1, f"{_EGRESS_ALIAS} must be visible to an mcpip-inc agent"
    row = rows[0]
    assert row["risk_tier"] == "pin_required"
    assert row["transport_class"] == "cloud_rest"
    assert "target" not in row  # the dotted downstream target never crosses the wire.
    assert "canary" not in row
