"""
MCPIP V2 — compliance-evidence bundle test suite (X1).

    ◐  "Evidence, not a certificate. Export what the gateway has ALREADY signed — never
       fabricate a certification, a customer, or an auditor sign-off."

Two layers:
  * UNIT (Redis-free): the pure ``build_evidence_bundle`` over a synthesized sealed / empty
    ``WormAttestation`` — 1:1 field serialization, honest ``sealed``/``empty_state_note``, the
    control-mapping "provides-evidence-for" phrasing + per-framework ``certification_note``, and
    a no-fabrication grep over the serialized bundle for forbidden certification-CLAIM substrings.
  * LIVE (TestClient, sandbox Redis :63790, mirrors ``tests/test_worm_attestation.py``): the
    ``GET /v1/admin/compliance/evidence`` surface — admin-gated + opaque deny, real sealed WORM
    state after an epoch close, honest empty state before the first seal, production-availability,
    and the agent-facing opacity boundary (no target/payload/secret).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Share the API-suite Redis db (/5) + WORM path convention. ``app.main._components`` is a
# process-global bound at first import — when this module runs alongside the other live API
# suites, that binding is whichever suite imported ``app.main`` first, NOT necessarily this
# module's env. So the fixture below resets the app's REAL Redis + WORM files derived from
# ``_components.settings`` rather than a guessed db, making the empty-state test correct
# regardless of collection order.
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

from audit.worm_logger import WormAttestation
from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import CAP_DIRECTORY_ADMIN
from services.compliance_evidence import (
    BUNDLE_DISCLAIMER,
    CONTROL_MAPPING,
    build_evidence_bundle,
)

_AUTO_ALIAS = "skill_spend_summary"
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX128 = re.compile(r"\A[0-9a-f]{128}\Z")

# Certification-CLAIM phrasings that must NEVER appear anywhere in the serialized bundle.
_FORBIDDEN_CLAIM_SUBSTRINGS = (
    "soc 2 certified",
    "soc2 certified",
    "fedramp authorized",
    "fedramp authorization granted",
    "audit passed",
    "control passed",
    "certified compliant",
    "attestation of compliance",
    "auditor sign-off",
    "auditor signed off",
    "we are certified",
    "is certified",
)


def _sealed_attestation() -> WormAttestation:
    return WormAttestation(
        epoch=7,
        end_seq=42,
        merkle_root="a" * 64,
        epoch_hash="b" * 64,
        signature="c" * 128,
        signing_key_id="d" * 64,
        intact=True,
        first_bad_epoch=None,
        anchor_epoch=7,
        anchor_epoch_hash="b" * 64,
    )


def _empty_attestation() -> WormAttestation:
    return WormAttestation(
        epoch=None,
        end_seq=None,
        merkle_root=None,
        epoch_hash=None,
        signature=None,
        signing_key_id="e" * 64,
        intact=True,
        first_bad_epoch=None,
        anchor_epoch=None,
        anchor_epoch_hash=None,
    )


# ---------------------------------------------------------------------------
# UNIT (Redis-free) — the pure assembler.
# ---------------------------------------------------------------------------


def test_build_sealed_bundle_serializes_state_1to1() -> None:
    att = _sealed_attestation()
    prov = {"version": "2.0.0", "signing_key_id": "f" * 64, "verified": True}
    bundle = build_evidence_bundle(
        attestation=att,
        gateway_version="2.0.0",
        release_provenance=prov,
        generated_at="2026-07-17T00:00:00+00:00",
    )

    assert bundle["sealed"] is True
    assert "empty_state_note" not in bundle
    assert bundle["generated_at"] == "2026-07-17T00:00:00+00:00"
    assert bundle["gateway_version"] == "2.0.0"
    assert bundle["release_provenance"] == {
        "version": "2.0.0",
        "signing_key_id": "f" * 64,
        "verified": True,
    }

    # Attestation fields serialized 1:1.
    a = bundle["attestation"]
    assert a["epoch"] == att.epoch
    assert a["end_seq"] == att.end_seq
    assert a["merkle_root"] == att.merkle_root
    assert a["epoch_hash"] == att.epoch_hash
    assert a["signature"] == att.signature
    assert a["signing_key_id"] == att.signing_key_id
    assert a["intact"] == att.intact
    assert a["first_bad_epoch"] == att.first_bad_epoch
    assert a["anchor_epoch"] == att.anchor_epoch
    assert a["anchor_epoch_hash"] == att.anchor_epoch_hash

    assert bundle["disclaimer"] == BUNDLE_DISCLAIMER
    assert bundle["control_mapping"]  # non-empty


def test_control_mapping_uses_evidence_phrasing_and_certification_notes() -> None:
    frameworks = {block["framework"] for block in CONTROL_MAPPING}
    # Every required framework is encoded.
    for required in (
        "EU AI Act",
        "SEC 17a-4 / FINRA 4511",
        "DORA",
        "NIST SP 800-53 rev. 5",
        "SOC 2",
        "ISO/IEC 42001",
    ):
        assert required in frameworks, required

    for block in CONTROL_MAPPING:
        # Every framework block carries the certification != evidence note.
        note = block["certification_note"].lower()
        assert "external third-party process" in note
        assert "cannot produce" in note
        assert block["clauses"]
        for clause in block["clauses"]:
            # Never "certified/authorized/passed" — always "provides-evidence-for".
            assert clause["coverage"] == "provides-evidence-for"
            for key in ("clause", "mechanism", "mcpip_evidence", "code_pointer"):
                assert isinstance(clause[key], str) and clause[key]


def test_empty_state_is_honest() -> None:
    att = _empty_attestation()
    bundle = build_evidence_bundle(
        attestation=att,
        gateway_version="2.0.0",
        release_provenance={"version": None, "signing_key_id": None, "verified": None},
        generated_at="2026-07-17T00:00:00+00:00",
    )
    assert bundle["sealed"] is False
    assert "empty_state_note" in bundle
    assert "empty" in bundle["empty_state_note"].lower()
    a = bundle["attestation"]
    # Epoch fields honestly None, but a REAL verdict + key id remain populated.
    assert a["epoch"] is None
    assert a["end_seq"] is None
    assert a["merkle_root"] is None
    assert a["epoch_hash"] is None
    assert a["signature"] is None
    assert a["intact"] is True
    assert a["signing_key_id"] == "e" * 64


def _claim_blob(bundle: dict[str, Any]) -> str:
    """
    Serialize ONLY the claim-bearing parts of the bundle (the attestation state, the
    control-mapping clauses, the release provenance) — with the honesty ``disclaimer`` and each
    framework's ``certification_note`` stripped. Those two are the DELIBERATE negation zone (they
    enumerate what the bundle is NOT: "no auditor sign-off", "not a certification"), so grepping
    them for claim phrasings would flag the very hedge that keeps the bundle honest. Fabrication
    risk lives in the substantive claim area, which is what this returns.
    """
    import copy as _copy

    scrub = _copy.deepcopy(bundle)
    scrub.pop("disclaimer", None)
    for block in scrub.get("control_mapping", []):
        block.pop("certification_note", None)
    return json.dumps(scrub).lower()


def test_no_fabricated_certification_claim_in_claim_area() -> None:
    # Both a sealed and an empty bundle: the substantive claim area must be free of certification
    # CLAIMS, while the disclaimer/notes honestly restate evidence != certification.
    for att in (_sealed_attestation(), _empty_attestation()):
        bundle = build_evidence_bundle(
            attestation=att,
            gateway_version="2.0.0",
            release_provenance={"version": "2.0.0", "signing_key_id": "f" * 64, "verified": True},
            generated_at="2026-07-17T00:00:00+00:00",
        )
        blob = _claim_blob(bundle)
        for banned in _FORBIDDEN_CLAIM_SUBSTRINGS:
            assert banned not in blob, banned
        # The clauses use "provides-evidence-for" phrasing, never "certified/passed".
        assert "provides-evidence-for" in blob
        # The disclaimer DOES honestly restate evidence != certification.
        assert "not a certification" in bundle["disclaimer"].lower()


def _all_keys(obj: Any) -> set[str]:
    """Every dict key appearing anywhere in a nested JSON-ish structure, lowercased."""
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k.lower())
            out |= _all_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _all_keys(v)
    return out


def test_bundle_carries_no_secret_shaped_key() -> None:
    att = _sealed_attestation()
    bundle = build_evidence_bundle(
        attestation=att,
        gateway_version="2.0.0",
        release_provenance={"version": "2.0.0", "signing_key_id": "f" * 64, "verified": True},
        generated_at="2026-07-17T00:00:00+00:00",
    )
    # No secret-SHAPED key anywhere in the structure ("pin"/"otp" as a KEY, not as the
    # substring inside "mcpip"/"one-time PIN" prose which is legitimate mapping text).
    keys = _all_keys(bundle)
    for banned in ("pin", "otp", "payload_hash", "vended_credential", "session_token", "secret_access_key", "target"):
        assert banned not in keys, banned


def test_returned_bundle_cannot_mutate_source_mapping() -> None:
    att = _sealed_attestation()
    bundle = build_evidence_bundle(
        attestation=att,
        gateway_version="2.0.0",
        release_provenance={"version": None, "signing_key_id": None, "verified": None},
        generated_at="2026-07-17T00:00:00+00:00",
    )
    bundle["control_mapping"][0]["framework"] = "MUTATED"
    bundle["control_mapping"][0]["clauses"].clear()
    # The module-level source is untouched (deep-copied on build).
    assert CONTROL_MAPPING[0]["framework"] != "MUTATED"
    assert CONTROL_MAPPING[0]["clauses"]


# ---------------------------------------------------------------------------
# LIVE (TestClient, sandbox Redis) — the endpoint.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def _live() -> Iterator[tuple[TestClient, Any]]:
    # Import inside the fixture so the unit tests above stay Redis-free at collection time.
    from app.main import _components, app
    from main import _DemoIdP

    # Reset the app's ACTUAL Redis + WORM state (both halves of one chain — flushing only Redis
    # leaves the persistent anchor watermark ahead of an empty chain, reading as a false
    # rollback). Derive them from the live settings so we reset whatever db/path the global
    # ``_components`` is really bound to, not a guessed one. Safe here: this module collects
    # after the other API suites and before ``test_worm_attestation`` (which resets again).
    reset: Any = redis_sync.Redis.from_url(_components.settings.redis_url, decode_responses=True)
    reset.flushdb()
    reset.close()
    worm_path = _components.settings.worm_path
    for stale in (worm_path, worm_path + ".anchor"):
        try:
            os.remove(stale)
        except FileNotFoundError:
            pass

    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    with TestClient(app) as client:
        yield client, demo


def _bh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _admin_token(idp: Any) -> str:
    return idp.mint(capabilities=[CAP_DIRECTORY_ADMIN])


def _evidence(client: TestClient, token: str) -> Response:
    return client.get("/v1/admin/compliance/evidence", headers=_bh(token))


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


def test_live_admin_gate_is_opaque(_live: tuple[TestClient, Any]) -> None:
    client, idp = _live

    no_bearer = client.get("/v1/admin/compliance/evidence")
    assert no_bearer.status_code == 403
    assert set(no_bearer.json().keys()) == {"error", "correlation_id"}
    assert no_bearer.json()["error"] == AGENT_FACING_DENY_MESSAGE

    bad = _evidence(client, "not-a-real-jwt")
    assert bad.status_code == 403
    assert set(bad.json().keys()) == {"error", "correlation_id"}

    # Valid but plain agent JWT (no CAP_DIRECTORY_ADMIN) is denied, opaquely.
    plain = _evidence(client, idp.mint())
    assert plain.status_code == 403
    assert plain.json()["error"] == AGENT_FACING_DENY_MESSAGE


def test_live_empty_state_before_any_seal(_live: tuple[TestClient, Any]) -> None:
    client, idp = _live
    body = _evidence(client, _admin_token(idp)).json()
    # Fresh namespaced db + flushed anchor: nothing sealed yet.
    assert body["sealed"] is False
    assert body["attestation"]["epoch"] is None
    assert body["attestation"]["end_seq"] is None
    assert "empty_state_note" in body
    # A REAL signing_key_id + verdict are still present.
    assert _HEX64.match(body["attestation"]["signing_key_id"])
    assert body["attestation"]["intact"] is True


def test_live_sealed_bundle_from_real_worm_state(_live: tuple[TestClient, Any]) -> None:
    client, idp = _live
    token = _admin_token(idp)
    # Real WORM decision, then force an epoch close (sandbox /v1/audit/verify).
    assert _authorize(client, token, {"period": "evidence"}).status_code == 200
    verify = client.get("/v1/audit/verify", headers=_bh(token))
    assert verify.status_code == 200, verify.text
    assert verify.json()["intact"] is True

    body = _evidence(client, token).json()
    assert body["sealed"] is True
    a = body["attestation"]
    assert isinstance(a["epoch"], int) and a["epoch"] >= 0
    assert isinstance(a["end_seq"], int) and a["end_seq"] >= 1
    assert _HEX64.match(a["merkle_root"])
    assert _HEX64.match(a["epoch_hash"])
    assert _HEX128.match(a["signature"])
    assert a["intact"] is True
    assert a["first_bad_epoch"] is None

    # The bundle's attestation equals the authoritative attestation endpoint (same engine call).
    direct = client.get("/v1/audit/attestation", headers=_bh(token)).json()
    assert a["signing_key_id"] == direct["signing_key_id"]
    assert a["intact"] == direct["intact"]
    assert a["first_bad_epoch"] == direct["first_bad_epoch"]

    # Top-level shape.
    assert set(body.keys()) >= {
        "generated_at",
        "gateway_version",
        "release_provenance",
        "sealed",
        "attestation",
        "control_mapping",
        "disclaimer",
    }
    assert body["control_mapping"]
    assert "not a certification" in body["disclaimer"].lower()


def test_live_opacity_no_secret_or_topology(_live: tuple[TestClient, Any]) -> None:
    client, idp = _live
    token = _admin_token(idp)
    assert _authorize(client, token, {"period": "opaque"}).status_code == 200
    assert client.get("/v1/audit/verify", headers=_bh(token)).status_code == 200
    body = _evidence(client, token).json()

    # No secret/target/payload key at the top level.
    for banned in ("target", "arguments", "payload_hash", "pin", "otp", "jwt", "vended_credential"):
        assert banned not in body

    blob = json.dumps(body).lower()
    # No hidden target / alias mapping leaks.
    assert "mainframe" not in blob
    assert "cics" not in blob
    # No fabricated certification claim in the substantive claim area on the live wire either.
    claim_blob = _claim_blob(body)
    for banned in _FORBIDDEN_CLAIM_SUBSTRINGS:
        assert banned not in claim_blob, banned


def test_live_engine_failure_is_opaque(_live: tuple[TestClient, Any]) -> None:
    from app.main import _components

    client, idp = _live
    token = _admin_token(idp)

    async def _boom() -> Any:
        raise RuntimeError("simulated WORM/Redis outage")

    original = _components.worm.attestation
    _components.worm.attestation = _boom  # type: ignore[method-assign]
    try:
        resp = _evidence(client, token)
        assert resp.status_code == 403
        assert set(resp.json().keys()) == {"error", "correlation_id"}
        assert resp.json()["error"] == AGENT_FACING_DENY_MESSAGE
    finally:
        _components.worm.attestation = original  # type: ignore[method-assign]

    assert _evidence(client, token).status_code == 200


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
