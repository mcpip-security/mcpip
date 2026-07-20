"""
MCPIP V2 — WORM attestation endpoint test suite (read-only, signed, portable).

    ◐  "A portable, externally-checkable snapshot of the audit chain — it mints no key,
       signs nothing new, and never runs on the emit hot path."

Drives ``GET /v1/audit/attestation`` through ``TestClient`` against the same namespaced
sandbox Redis / sandbox flag as ``tests/test_authorize_api.py`` (db ``/5``), so the FastAPI
lifespan (Redis rebind + epoch daemon) and every request run on one loop, as production
would. All assertions are against the REAL ``WormLogger.attestation`` output — no mocks of
the code under test.

Covered:
  * JWT-gated: no bearer / a malformed token → opaque ``403`` (generic envelope only);
  * the returned ``signing_key_id`` is the WORM epoch key's REAL public fingerprint
    (matches ``WormLogger.signing_key_id()``) and is STABLE across calls — no key is minted;
  * after activity + an epoch close the attestation surfaces the real SEALED epoch head
    (epoch / end_seq / merkle_root / epoch_hash / signature) plus a fresh ``verify_chain``
    result (``intact`` True, ``first_bad_epoch`` None) and the anchor low-watermark;
  * an engine/transport failure is an OPAQUE ``403`` (never leaks internals);
  * the agent-facing opacity boundary is untouched — no target/payload/secret appears.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import json
import re
from typing import Any, Iterator

import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import CAP_DIRECTORY_ADMIN

from app.main import _components, app
from main import _DemoIdP

_AUTO_ALIAS = "skill_spend_summary"
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX128 = re.compile(r"\A[0-9a-f]{128}\Z")


@pytest.fixture(scope="module")
def idp() -> _DemoIdP:
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    # Reset the FULL WORM state for a consistent clean slate: the in-Redis epoch chain AND
    # its out-of-tamper-domain anchor file are two halves of one state — flushing only Redis
    # (as the sibling shared-db suites do) leaves the persistent anchor watermark ahead of a
    # freshly-empty chain, which reads as a (false) rollback. Resetting both keeps the chain
    # and its low-watermark consistent so a fresh close verifies intact. Safe across suites:
    # this module collects last, after the other intact-asserting suite has already run.
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    worm_path = os.environ["MCPIP_WORM_PATH"]
    for stale in (worm_path, worm_path + ".anchor"):
        try:
            os.remove(stale)
        except FileNotFoundError:
            pass
    with TestClient(app) as test_client:
        yield test_client


def _bh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _admin(idp: _DemoIdP) -> str:
    """A JWT holding CAP_DIRECTORY_ADMIN — the attestation commits to the GLOBAL WORM head,
    so the endpoint is admin-gated (not readable by a plain agent JWT in production)."""
    return idp.mint(capabilities=[CAP_DIRECTORY_ADMIN])


def _attest(client: TestClient, token: str) -> Response:
    return client.get("/v1/audit/attestation", headers=_bh(token))


def _authorize(client: TestClient, token: str, args: dict[str, Any]) -> Response:
    return client.post(
        "/v1/authorize",
        json={
            "source_format": "openai_tool_call",
            "tool_call": {
                "id": "call_test",
                "type": "function",
                "function": {"name": _AUTO_ALIAS, "arguments": json.dumps(args)},
            },
            "jwt": token,
        },
    )


# ---------------------------------------------------------------------------
# 1) JWT-gated: no bearer / malformed token → opaque 403.
# ---------------------------------------------------------------------------


def test_attestation_requires_jwt(client: TestClient, idp: _DemoIdP) -> None:
    no_bearer = client.get("/v1/audit/attestation")
    assert no_bearer.status_code == 403
    assert set(no_bearer.json().keys()) == {"error", "correlation_id"}
    assert no_bearer.json()["error"] == AGENT_FACING_DENY_MESSAGE

    bad = _attest(client, "not-a-real-jwt")
    assert bad.status_code == 403
    assert set(bad.json().keys()) == {"error", "correlation_id"}

    # A VALID but plain agent JWT (no CAP_DIRECTORY_ADMIN) is denied too: the attestation
    # commits to the GLOBAL cross-tenant WORM head, so it is admin-gated, opaquely.
    plain = _attest(client, idp.mint())
    assert plain.status_code == 403
    assert plain.json()["error"] == AGENT_FACING_DENY_MESSAGE


# ---------------------------------------------------------------------------
# 2) signing_key_id is the REAL public fingerprint, stable, and mints no key.
# ---------------------------------------------------------------------------


def test_signing_key_id_is_real_and_stable(client: TestClient, idp: _DemoIdP) -> None:
    token = _admin(idp)
    first = _attest(client, token)
    assert first.status_code == 200, first.text
    kid = first.json()["signing_key_id"]
    # A domain-separated SHA-256 of the WORM public key — 64 lowercase hex, non-secret.
    assert _HEX64.match(kid), kid
    # It is the WORM epoch key's ACTUAL fingerprint (pure, local, no key minted).
    assert kid == _components.worm.signing_key_id()
    # Stable across calls — an attestation never rotates/mints a key.
    second = _attest(client, token)
    assert second.json()["signing_key_id"] == kid


# ---------------------------------------------------------------------------
# 3) After activity + an epoch close, the attestation surfaces the real sealed head.
# ---------------------------------------------------------------------------


def test_attestation_reflects_sealed_epoch(client: TestClient, idp: _DemoIdP) -> None:
    token = _admin(idp)
    # Generate a real WORM decision, then force an epoch close (sandbox /v1/audit/verify).
    assert _authorize(client, token, {"period": "attest"}).status_code == 200
    verify = client.get("/v1/audit/verify", headers=_bh(token))
    assert verify.status_code == 200, verify.text
    assert verify.json()["intact"] is True

    att = _attest(client, token)
    assert att.status_code == 200, att.text
    body = att.json()

    # The attestation's fresh verify result MIRRORS the authoritative /v1/audit/verify
    # surface (same chain, same verdict) — an order-independent contract check.
    assert body["intact"] == verify.json()["intact"]
    assert body["first_bad_epoch"] == verify.json()["first_bad_epoch"]

    # The whole documented shape is present.
    assert set(body.keys()) == {
        "epoch",
        "end_seq",
        "merkle_root",
        "epoch_hash",
        "signature",
        "signing_key_id",
        "intact",
        "first_bad_epoch",
        "anchor_epoch",
        "anchor_epoch_hash",
    }
    # A sealed epoch head is now present and well-formed (Ed25519-signed at close).
    assert isinstance(body["epoch"], int) and body["epoch"] >= 0
    assert isinstance(body["end_seq"], int) and body["end_seq"] >= 1
    assert _HEX64.match(body["merkle_root"]), body["merkle_root"]
    assert _HEX64.match(body["epoch_hash"]), body["epoch_hash"]
    assert _HEX128.match(body["signature"]), body["signature"]
    # A fresh verify_chain result — the honest chain is intact.
    assert body["intact"] is True
    assert body["first_bad_epoch"] is None


# ---------------------------------------------------------------------------
# 4) The attestation head matches the authoritative inclusion-proof head (not fabricated).
# ---------------------------------------------------------------------------


def test_attestation_head_matches_inclusion_proof(client: TestClient, idp: _DemoIdP) -> None:
    token = _admin(idp)
    assert _authorize(client, token, {"period": "match"}).status_code == 200
    event_id = _last_event_id()
    assert event_id is not None
    # Force a close so the event is sealed, then read BOTH surfaces back to back.
    assert client.get("/v1/audit/verify", headers=_bh(token)).status_code == 200

    proof = client.get(f"/v1/audit/proof/{event_id}", headers=_bh(token))
    assert proof.status_code == 200, proof.text
    proof_body = proof.json()

    att = _attest(client, token).json()
    # The attestation reports a head at least as new as the event's sealed epoch, and when
    # it IS that epoch the signed commitments are byte-identical to the proof's — i.e. the
    # attestation surfaces the REAL signed head, never a fabricated one.
    assert att["epoch"] >= proof_body["epoch"]
    if att["epoch"] == proof_body["epoch"]:
        assert att["epoch_hash"] == proof_body["epoch_hash"]
        assert att["signature"] == proof_body["signature"]
        assert att["merkle_root"] == proof_body["merkle_root"]


# ---------------------------------------------------------------------------
# 5) An engine/transport failure is an OPAQUE 403 (never leaks internals).
# ---------------------------------------------------------------------------


def test_attestation_engine_failure_is_opaque(client: TestClient, idp: _DemoIdP) -> None:
    token = _admin(idp)

    async def _boom() -> Any:
        raise RuntimeError("simulated WORM/Redis outage")

    original = _components.worm.attestation
    _components.worm.attestation = _boom  # type: ignore[method-assign]
    try:
        resp = _attest(client, token)
        assert resp.status_code == 403
        # Opaque: only the generic envelope, no engine detail / stack / topology.
        assert set(resp.json().keys()) == {"error", "correlation_id"}
        assert resp.json()["error"] == AGENT_FACING_DENY_MESSAGE
    finally:
        _components.worm.attestation = original  # type: ignore[method-assign]

    # The endpoint recovers once the engine is healthy again.
    assert _attest(client, token).status_code == 200


# ---------------------------------------------------------------------------
# 6) No target / payload / secret ever crosses the wire.
# ---------------------------------------------------------------------------


def test_attestation_exposes_no_secret_or_topology(client: TestClient, idp: _DemoIdP) -> None:
    token = _admin(idp)
    assert _authorize(client, token, {"period": "opaque"}).status_code == 200
    assert client.get("/v1/audit/verify", headers=_bh(token)).status_code == 200
    body = _attest(client, token).json()
    for banned in ("target", "arguments", "payload_hash", "pin", "otp", "jwt", "signing_key"):
        assert banned not in body
    # Nothing in the serialized attestation reveals a hidden target or an alias mapping.
    blob = json.dumps(body).lower()
    assert "mainframe" not in blob
    assert "cics" not in blob


def _last_event_id() -> Any:
    """The WORM ``event_id`` of the most recent buffered decision (audit-only read)."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange("mcpip:worm:events", count=1)
    finally:
        reader.close()
    if not entries:
        return None
    _sid, fields = entries[0]
    return fields.get("event_id")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
