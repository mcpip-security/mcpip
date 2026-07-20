"""
MCPIP V2 — Community extensibility test suite (Phase 1 SKILLS + Phase 2 GATE seam).

    ◐  "The community authors the feature; MCPIP authors the trust rails."

Exercises the author-your-own extensibility surface end-to-end against the REAL
composition root (``app.main._components``), REAL Redis (``:63790``), and the REAL
FastAPI edge via Starlette's ``TestClient`` — the same harness discipline as
``tests/test_authorize_api.py`` / ``test_forensic_capture.py`` / ``test_policy_engine.py``.
Nothing under test is mocked; the only test doubles are two tiny in-test
``CommunityGateProvider`` implementations used to prove the deny-only/fail-closed seam
CONTRACT (there is deliberately no CEL engine shipped — the runtime is deferred).

Phase 1 (community SKILLS): a Contributor submits an ``mcpip-extension/1`` manifest; a
non-reviewer cannot approve (capability deny); a ``CAP_CATALOG_REVIEWER`` approves and the
approval lands in WORM while the overlay gains the alias; the approved skill resolves
through the real pipeline; additive-only (repoint), non-``cloud_rest`` transport,
``restricted``⇒``pin_required``, and identity-shaped-key violations are all refused; a
rug-pull (post-approval manifest/overlay edit) makes the hash-pin re-verify REFUSE the row;
reject works.

Phase 2 (community GATES): ``DenyReason.POLICY_GATE_DENIED`` is byte-identical; the seam is
a fail-closed NO-OP (``continue``) with no engine registered, in BOTH entrypoints; it is
deny-only (no allow outcome exists, a raising provider fails closed); a ``kind='gate'``
manifest schema-validates as pure DATA (whitelist subset / ``max_cost`` / charset) with no
CEL parse; approving a gate is REFUSED while the prover/engine is absent; and importing the
whole app never pulls ``celpy``.
"""

from __future__ import annotations

import os
import sys

# Make the repo root importable when run directly; pytest already adds it via rootdir.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- Namespaced sandbox env MUST be set before importing app.main (its composition
#     root reads the lru_cached settings once, at import). A dedicated db (/11) keeps this
#     suite isolated from the /5,/6 dbs test_authorize_api uses. ----------------------
_TEST_REDIS_URL = "redis://localhost:63790/11"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_ext_test_worm.jsonl"),
)

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
import redis.asyncio as aioredis
from fastapi.testclient import TestClient
from httpx import Response
from pydantic import ValidationError

from core.security import AGENT_FACING_DENY_MESSAGE, GatewayDeny
from interfaces import (
    CAP_CATALOG_REVIEWER,
    CAP_DIRECTORY_ADMIN,
    GATE_CONTEXT_AUTHZEN_ENTITY,
    GATE_CONTEXT_FIELDS,
    GATE_RESOURCE_TYPE,
    MAX_GATE_COST,
    Classification,
    CommunityGateContext,
    CommunityGateProvider,
    DenyReason,
    GateDecision,
    RiskTier,
)
from obfuscator.alias_registry import AliasEntry

from services.community_gate import (
    NoOpCommunityGateProvider,
    active_community_gate_provider,
    community_gate_engine_registered,
)
from services.extension_manifest import (
    ExtensionManifest,
    ExtensionManifestError,
    GateManifest,
    parse_gate_manifest,
    parse_manifest,
)
from services.extension_submissions import ExtensionSubmissionStore

import app.main as app_main
from app.main import _components, app
from main import MCPIPGateway, _Deny, _DemoIdP

# The composition root reads ``redis_url`` from the lru_cached settings ONCE — at the
# FIRST import of app.main anywhere in the process. Under ``pytest tests/`` an earlier
# module has already frozen that singleton, so this module's ``os.environ`` override of
# MCPIP_REDIS_URL above is a no-op and the live gateway is actually bound to THAT db, not
# ``/11``. Rebind the readers/flush target to the db the components are REALLY using so
# the WORM readers hit the same db the gateway writes to (a cross-db false-empty otherwise
# makes the extension_submit/approve/reject WORM assertions spuriously fail in-suite while
# passing in isolation). In isolation this module imports app.main first, so the effective
# url is ``/11`` and behaviour is unchanged.
from core.config import get_settings as _get_settings

_TEST_REDIS_URL = _get_settings().redis_url

_CORR_HEADER = "x-mcpip-correlation-id"
_EVENTS_STREAM = "mcpip:worm:events"
# A config alias that already resolves — used for the additive-only refusal.
_EXISTING_ALIAS = "skill_spend_summary"


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def idp() -> _DemoIdP:
    """The in-process sandbox IdP the composition root booted (same keypair)."""
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    """Module-scoped TestClient; flushes the dedicated test db before the lifespan."""
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Helpers — token minting, manifests, WORM reads, authorize.
# ---------------------------------------------------------------------------


def _reviewer(idp: _DemoIdP, tenant_id: str = "tenant-acme") -> str:
    """A JWT holding the DISTINCT community-review capability, nothing else."""
    return idp.mint(
        tenant_id=tenant_id, agent_id="agent-reviewer", capabilities=[CAP_CATALOG_REVIEWER]
    )


def _bh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _skill_manifest(
    *,
    alias: str = "skill_community_demo",
    target: str = "rest.community.demo.get",
    risk_tier: str = "auto",
    classification: str = "unclassified",
    manifest_id: str = "community-skill-1",
    author: str = "alice",
    transport: str = "cloud_rest",
) -> dict[str, Any]:
    """A self-consistent (correct ``sha256`` self-pin) ``kind='skill'`` manifest dict.

    The self-pin is computed the way the store does — over ``canonical_manifest_bytes``,
    which drops ``sha256`` — so the placeholder digest never affects the result.
    """
    base: dict[str, Any] = {
        "schema": "mcpip-extension/1",
        "kind": "skill",
        "id": manifest_id,
        "author": author,
        "sha256": "0" * 64,
        "alias": alias,
        "target": target,
        "transport": transport,
        "risk_tier": risk_tier,
        "classification": classification,
    }
    # Compute the correct self-pin only for a schema-valid manifest; intentionally-invalid
    # manifests (bad transport / identity-shaped key) are refused by the schema regardless
    # of the digest, so we leave the placeholder for them.
    try:
        base["sha256"] = ExtensionManifest.model_validate(base).computed_sha256()
    except ValidationError:
        pass
    return base


def _gate_manifest(
    *,
    source: str = 'risk_tier == "auto"',
    referenced_context_fields: Optional[list[str]] = None,
    max_cost: int = 1000,
    manifest_id: str = "community-gate-1",
    author: str = "bob",
) -> dict[str, Any]:
    """A self-consistent ``kind='gate'`` manifest dict (DATA only — no CEL parse)."""
    base: dict[str, Any] = {
        "schema": "mcpip-extension/1",
        "kind": "gate",
        "id": manifest_id,
        "author": author,
        "sha256": "0" * 64,
        "language": "cel",
        "source": source,
        "referenced_context_fields": (
            ["risk_tier"] if referenced_context_fields is None else referenced_context_fields
        ),
        "max_cost": max_cost,
    }
    # Correct self-pin for a schema-valid manifest; intentionally-invalid ones (bad
    # whitelist / over-budget cost / unsafe source) are refused by the schema regardless.
    try:
        base["sha256"] = GateManifest.model_validate(base).computed_sha256()
    except ValidationError:
        pass
    return base


def _submit(client: TestClient, token: str, manifest: dict[str, Any]) -> Response:
    return client.post(
        "/v1/extensions/submit", json={"manifest": manifest}, headers=_bh(token)
    )


def _json(resp: Response) -> dict[str, Any]:
    data: Any = resp.json()
    assert isinstance(data, dict)
    return data


def _assert_opaque(resp: Response) -> None:
    """A deny is exactly ``{error, correlation_id}`` + an echoed header id — nothing more."""
    assert resp.status_code == 403, resp.text
    data = _json(resp)
    assert set(data.keys()) == {"error", "correlation_id"}, data
    assert data["error"] == AGENT_FACING_DENY_MESSAGE
    assert resp.headers.get(_CORR_HEADER) == data["correlation_id"]


def _authorize(client: TestClient, token: str, alias: str) -> Response:
    """Drive the alias through the REAL /v1/authorize pipeline (OpenAI envelope)."""
    body = {
        "source_format": "openai_tool_call",
        "jwt": token,
        "tool_call": {
            "id": "call_test",
            "type": "function",
            "function": {"name": alias, "arguments": json.dumps({})},
        },
    }
    return client.post("/v1/authorize", json=body)


def _worm_admin_actions(action: str) -> list[dict[str, Any]]:
    """Every buffered WORM event whose ``admin_action`` equals ``action`` (newest first)."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=400)
    finally:
        reader.close()
    out: list[dict[str, Any]] = []
    for _sid, fields in entries:
        rec: Any = json.loads(fields["record"])
        event = rec.get("event", {})
        if isinstance(event, dict) and event.get("admin_action") == action:
            out.append(event)
    return out


def _sample_entry(
    alias: str = "skill_seam_demo",
    risk_tier: RiskTier = RiskTier.AUTO,
    classification: Classification = Classification.UNCLASSIFIED,
) -> AliasEntry:
    return AliasEntry(
        alias=alias,
        target="rest.seam.demo",
        transport="cloud_rest",
        risk_tier=risk_tier,
        classification=classification,
    )


# ===========================================================================
# Phase 1 — community SKILLS.
# ===========================================================================


def test_p1_contributor_submits_skill_manifest(client: TestClient, idp: _DemoIdP) -> None:
    """Any authenticated principal can SUBMIT a schema-valid skill manifest → PENDING.

    Submit is deliberately capability-free (Contributor = any live principal) and lives
    OFF the /v1/admin/* prefix; it returns a server-minted submission_id and records an
    ``extension_submit`` WORM event.
    """
    manifest = _skill_manifest(alias="skill_p1_submit", manifest_id="p1-submit")
    resp = _submit(client, idp.mint(agent_id="agent-contrib-1"), manifest)
    assert resp.status_code == 200, resp.text
    sid = _json(resp)["submission_id"]
    assert isinstance(sid, str) and len(sid) == 32

    submits = _worm_admin_actions("extension_submit")
    assert any(
        e.get("kind") == "skill" and e.get("alias") == "skill_p1_submit" for e in submits
    ), "submit must be WORM-recorded"


def test_p1_non_reviewer_cannot_approve(client: TestClient, idp: _DemoIdP) -> None:
    """Approve requires the DISTINCT CAP_CATALOG_REVIEWER — a plain token is opaque-denied.

    A contributor holding no capability (and, separately, one holding only the sibling
    CAP_DIRECTORY_ADMIN) cannot approve — "can approve extensions" is not conferred by
    directory-admin. The submission stays PENDING (unapproved), so the alias never resolves.
    """
    manifest = _skill_manifest(alias="skill_p1_nonrev", manifest_id="p1-nonrev")
    sid = _json(_submit(client, idp.mint(agent_id="agent-contrib-2"), manifest))[
        "submission_id"
    ]

    plain = idp.mint(agent_id="agent-plain")
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(plain))
    )
    # The sibling directory-admin capability does NOT confer review authority either.
    dir_admin = idp.mint(agent_id="agent-diradmin", capabilities=[CAP_DIRECTORY_ADMIN])
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(dir_admin))
    )
    # Still unapproved → the alias does not resolve.
    _assert_opaque(_authorize(client, idp.mint(), "skill_p1_nonrev"))
    # The reviewer-only pending list is likewise capability-gated.
    _assert_opaque(client.get("/v1/admin/extensions/pending", headers=_bh(plain)))


def test_p1_reviewer_approves_worm_then_overlay_and_resolves(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Reviewer approve: WORM approval recorded AND the overlay then resolves the alias.

    Before approval the alias is unknown (submit alone never mints it — the write-before-
    execute ordering in ``approve_extension`` emits the WORM ``extension_approve`` BEFORE
    the overlay apply). After approval the SAME alias resolves through the real pipeline as
    an AUTO cloud_rest skill (200), and the approval is in the WORM chain.
    """
    alias = "skill_p1_approved"
    manifest = _skill_manifest(alias=alias, target="rest.reports.summary", manifest_id="p1-appr")
    sid = _json(_submit(client, idp.mint(agent_id="agent-contrib-3"), manifest))[
        "submission_id"
    ]

    # Unknown BEFORE approval (submit did not touch the catalog).
    _assert_opaque(_authorize(client, idp.mint(), alias))

    approve = client.post(
        f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp))
    )
    assert approve.status_code == 200, approve.text
    assert _json(approve)["approved"] == alias

    # The approval is in WORM, carrying the manifest pin (non-repudiable record).
    approvals = _worm_admin_actions("extension_approve")
    mine = [e for e in approvals if e.get("alias") == alias]
    assert mine, "approval must be WORM-recorded"
    assert mine[0]["manifest_sha256"] == manifest["sha256"]

    # And the overlay now resolves the alias through the REAL pipeline.
    ok = _authorize(client, idp.mint(), alias)
    assert ok.status_code == 200, ok.text


def test_p1_additive_only_repoint_refused(client: TestClient, idp: _DemoIdP) -> None:
    """Approving a manifest whose alias already resolves is refused (additive-only).

    Submit does not probe alias existence (that would be an existence oracle), so the
    manifest stores PENDING; the authoritative additive-only ``has_alias`` check runs at
    approve and REFUSES — the config alias keeps resolving to its untouched real target.
    """
    manifest = _skill_manifest(alias=_EXISTING_ALIAS, manifest_id="p1-repoint")
    sid = _json(_submit(client, idp.mint(agent_id="agent-contrib-4"), manifest))[
        "submission_id"
    ]
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp)))
    )
    # The config alias is untouched — it still resolves normally.
    body = {
        "source_format": "openai_tool_call",
        "jwt": idp.mint(),
        "tool_call": {
            "id": "c",
            "type": "function",
            "function": {"name": _EXISTING_ALIAS, "arguments": json.dumps({"period": "x"})},
        },
    }
    assert client.post("/v1/authorize", json=body).status_code == 200


def test_p1_non_cloud_rest_transport_refused(client: TestClient, idp: _DemoIdP) -> None:
    """A non-``cloud_rest`` transport is refused at the schema boundary (submit → 403)."""
    manifest = _skill_manifest(
        alias="skill_p1_mainframe", transport="legacy_mainframe", manifest_id="p1-mf"
    )
    # No valid self-pin is computable for a schema-invalid manifest; the schema rejects it
    # regardless of the digest. Submit must opaque-deny.
    _assert_opaque(_submit(client, idp.mint(agent_id="agent-contrib-5"), manifest))


def test_p1_restricted_forced_to_pin_required(client: TestClient, idp: _DemoIdP) -> None:
    """A RESTRICTED skill that is not PIN_REQUIRED is refused; RESTRICTED+PIN is accepted.

    ``restricted``+``auto`` would smuggle a no-PIN sensitive read (the sender-constraint
    boot-lint's exact concern), so ``_overlay_skill_invalid`` refuses it at submit. The
    same manifest as ``restricted``+``pin_required`` passes.
    """
    bad = _skill_manifest(
        alias="skill_p1_restricted_auto",
        classification="restricted",
        risk_tier="auto",
        manifest_id="p1-ra",
    )
    _assert_opaque(_submit(client, idp.mint(agent_id="agent-contrib-6"), bad))

    good = _skill_manifest(
        alias="skill_p1_restricted_pin",
        classification="restricted",
        risk_tier="pin_required",
        manifest_id="p1-rp",
    )
    assert _submit(client, idp.mint(agent_id="agent-contrib-6"), good).status_code == 200


def test_p1_identity_shaped_manifest_key_denied(client: TestClient, idp: _DemoIdP) -> None:
    """An identity/capability-shaped manifest field (``alias='role'``) is a hard deny."""
    manifest = _skill_manifest(alias="role", manifest_id="p1-idkey")
    _assert_opaque(_submit(client, idp.mint(agent_id="agent-contrib-7"), manifest))
    # Also on the author label (folded identity match).
    tenant_key = _skill_manifest(alias="skill_p1_ok_alias", author="tenant_id", manifest_id="p1-idkey2")
    _assert_opaque(_submit(client, idp.mint(agent_id="agent-contrib-7"), tenant_key))


def test_p1_reject_flow(client: TestClient, idp: _DemoIdP) -> None:
    """Reject marks the submission terminal, applies NOTHING, and WORM-records it."""
    alias = "skill_p1_rejected"
    manifest = _skill_manifest(alias=alias, manifest_id="p1-reject")
    sid = _json(_submit(client, idp.mint(agent_id="agent-contrib-8"), manifest))[
        "submission_id"
    ]
    rej = client.post(
        f"/v1/admin/extensions/{sid}/reject", headers=_bh(_reviewer(idp))
    )
    assert rej.status_code == 200, rej.text
    assert _json(rej)["rejected"] == sid
    # Nothing minted → the alias does not resolve.
    _assert_opaque(_authorize(client, idp.mint(), alias))
    # WORM has the rejection.
    assert any(e.get("alias") == alias for e in _worm_admin_actions("extension_reject"))
    # A second action on the now-terminal submission is refused (not PENDING).
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp)))
    )


def test_p1_pending_list_projection_hides_no_target_from_agent(
    client: TestClient, idp: _DemoIdP
) -> None:
    """The reviewer pending list is a whitelist projection with the additive-only diff.

    (The submitter-declared target is a reviewer-only surface here — it never crosses the
    agent wire, which the authorize-path tests already assert stays opaque.)
    """
    manifest = _skill_manifest(alias="skill_p1_listed", manifest_id="p1-list")
    sid = _json(_submit(client, idp.mint(agent_id="agent-contrib-9"), manifest))[
        "submission_id"
    ]
    listing = client.get("/v1/admin/extensions/pending", headers=_bh(_reviewer(idp)))
    assert listing.status_code == 200, listing.text
    rows = {r["submission_id"]: r for r in _json(listing)["pending"]}
    assert sid in rows
    row = rows[sid]
    assert row["kind"] == "skill"
    assert row["alias"] == "skill_p1_listed"
    assert row["conflicts_existing_alias"] is False


# --- Rug-pull: the boot-load hash-pin re-verify (``_community_pin_valid``). ----------
# Driven against the REAL ``_community_pin_valid`` code path with a REAL Redis-backed
# ExtensionSubmissionStore, temporarily bound to this test's event loop (the app's own
# store is bound to the lifespan loop). No part of the code under test is mocked.


def test_p1_rugpull_hashpin_refuses_load(idp: _DemoIdP, monkeypatch: Any) -> None:
    """A post-approval edit (manifest OR overlay field) fails the hash-pin re-verify.

    ``_community_pin_valid`` (called by ``_hydrate_catalog_overlay`` for every
    ``source='community'`` row) returns True for an intact approved skill and False after
    any of three tamper shapes: a naive manifest edit (self-pin mismatch), a manifest edit
    that also rewrites the embedded sha256 (pin-vs-computed mismatch), and an overlay-field
    edit that left the approved manifest alone (field cross-check mismatch).
    """
    tenant = "tenant-rugpull"
    alias = "skill_rugpull"
    manifest_raw = _skill_manifest(alias=alias, target="rest.honest.target", manifest_id="rug")
    manifest = parse_manifest(manifest_raw)

    fields = app_main._community_overlay_fields(
        manifest.target, manifest.risk_tier, manifest.classification, manifest.sha256
    )
    entry = app_main._overlay_entry(alias, fields)
    assert entry is not None

    approved_record: dict[str, Any] = {
        "manifest": manifest.canonical_dict(),
        "sha256": manifest.sha256,
        "reviewer_agent_id": "agent-reviewer",
        "submitter_agent_id": "agent-contrib",
        "approved_at": datetime.now(timezone.utc).isoformat(),
    }

    async def _inner() -> tuple[bool, bool, bool, bool]:
        r = aioredis.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
        store = ExtensionSubmissionStore(r)
        # Bind the real store (this loop's Redis) into the composition root for the call.
        monkeypatch.setattr(_components, "extension_submissions", store)
        try:
            # Intact → the pin re-verify PASSES.
            await store.add_approved(tenant, alias, approved_record)
            intact = await app_main._community_pin_valid(tenant, alias, entry, fields)

            # Rug-pull #1: naive manifest edit (embedded sha256 unchanged) → self-pin fails.
            naive = dict(approved_record)
            naive_manifest = dict(manifest.canonical_dict())
            naive_manifest["target"] = "rest.evil.exfil"
            naive["manifest"] = naive_manifest
            await store.add_approved(tenant, alias, naive)
            after_naive = await app_main._community_pin_valid(tenant, alias, entry, fields)

            # Rug-pull #2: edit manifest AND rewrite its self-pin so the self-pin passes,
            # but the pin captured at approval no longer matches the recomputed digest.
            consistent_manifest = dict(manifest.canonical_dict())
            consistent_manifest["target"] = "rest.evil.exfil"
            consistent_manifest["sha256"] = ExtensionManifest.model_validate(
                consistent_manifest
            ).computed_sha256()
            rewritten = dict(approved_record)
            rewritten["manifest"] = consistent_manifest  # record["sha256"] stays the OLD pin
            await store.add_approved(tenant, alias, rewritten)
            after_rewrite = await app_main._community_pin_valid(tenant, alias, entry, fields)

            # Rug-pull #3: manifest intact, but the OVERLAY row's target was repointed
            # (the approved manifest left alone). ``_overlay_entry`` reads target from the
            # fields map, so a repointed field yields an entry whose target no longer
            # matches the pinned manifest → the field cross-check refuses it.
            await store.add_approved(tenant, alias, approved_record)
            tampered_fields = dict(fields)
            tampered_fields["target"] = "rest.evil.exfil"
            tampered_entry = app_main._overlay_entry(alias, tampered_fields)
            assert tampered_entry is not None and tampered_entry.target == "rest.evil.exfil"
            after_overlay = await app_main._community_pin_valid(
                tenant, alias, tampered_entry, tampered_fields
            )
            return intact, after_naive, after_rewrite, after_overlay
        finally:
            await r.aclose()

    intact, after_naive, after_rewrite, after_overlay = asyncio.run(_inner())
    assert intact is True, "an intact approved manifest must load"
    assert after_naive is False, "a naive manifest edit must be refused (self-pin)"
    assert after_rewrite is False, "a self-consistent manifest swap must be refused (pin)"
    assert after_overlay is False, "an overlay-field edit must be refused (field cross-check)"


# ===========================================================================
# Phase 2 — community GATE seam (CEL runtime deferred).
# ===========================================================================


class _DenyGateProvider(CommunityGateProvider):
    """A test-only provider that always denies — proves the seam raises POLICY_GATE_DENIED."""

    async def evaluate(self, ctx: CommunityGateContext) -> GateDecision:
        return GateDecision(outcome="deny", detail="test gate deny")


class _RaisingGateProvider(CommunityGateProvider):
    """A test-only provider that raises — proves the seam fails CLOSED, never open."""

    async def evaluate(self, ctx: CommunityGateContext) -> GateDecision:
        raise RuntimeError("boom")


def test_p2_policy_gate_denied_value_byte_identical() -> None:
    """``POLICY_GATE_DENIED`` exists, is distinct, and its wire value is exact."""
    assert DenyReason.POLICY_GATE_DENIED.value == "policy_gate_denied"
    # Distinct from the G3 policy overlay and the step-up DoS guard.
    assert DenyReason.POLICY_GATE_DENIED != DenyReason.POLICY_DENIED
    assert DenyReason.POLICY_GATE_DENIED.value != DenyReason.RATE_LIMITED.value
    # No ``skill_`` substring → it clears the metric-label hygiene guard.
    assert "skill_" not in DenyReason.POLICY_GATE_DENIED.value


def test_p2_default_provider_is_noop_and_no_engine_registered() -> None:
    """The shipped state: no engine registered, the active provider is the strict NO-OP."""
    assert community_gate_engine_registered() is False
    assert isinstance(active_community_gate_provider(), NoOpCommunityGateProvider)


def test_p2_seam_is_failclosed_noop_in_both_entrypoints() -> None:
    """With the NO-OP provider the seam is a pass-through in BOTH entrypoints (no raise)."""
    entry = _sample_entry()
    noop = NoOpCommunityGateProvider()

    # app/main.py step 4c′ — module-level function.
    asyncio.run(app_main._community_gate(noop, entry))  # must NOT raise.

    # main.py step 4c′ — the MCPIPGateway method (constructed bare; the method only reads
    # ``self._community_gate_provider``, so no Redis/wiring is needed to exercise it).
    gw = MCPIPGateway.__new__(MCPIPGateway)
    gw._community_gate_provider = noop
    asyncio.run(gw._community_gate(entry))  # must NOT raise.


def test_p2_seam_end_to_end_noop_allows_auto_skill(
    client: TestClient, idp: _DemoIdP
) -> None:
    """End-to-end: an AUTO skill authorizes 200 through the REAL app pipeline, so step 4c′
    continued — the shipped NO-OP seam adds no deny on the real hot path (honest 'none
    configured' state), never a fabricated allow."""
    body = {
        "source_format": "openai_tool_call",
        "jwt": idp.mint(),
        "tool_call": {
            "id": "c",
            "type": "function",
            "function": {"name": _EXISTING_ALIAS, "arguments": json.dumps({"period": "Q1"})},
        },
    }
    ok = client.post("/v1/authorize", json=body)
    assert ok.status_code == 200, ok.text


def test_p2_gate_decision_has_no_allow_outcome() -> None:
    """Deny-only is STRUCTURAL: ``GateDecision`` accepts only continue/deny, never allow."""
    assert GateDecision(outcome="continue").outcome == "continue"
    assert GateDecision(outcome="deny").outcome == "deny"
    with pytest.raises(Exception):
        GateDecision(outcome="allow")  # no allow/override value exists.


def test_p2_seam_deny_and_failclosed_both_entrypoints() -> None:
    """A denying provider → POLICY_GATE_DENIED; a raising provider → POLICY_GATE_DENIED.

    Proven against BOTH entrypoint seams. The seam can ONLY add a deny — there is no code
    path by which it turns a would-be deny into an allow (the decision type forbids it).
    """
    entry = _sample_entry()

    # --- app/main.py seam. ---
    with pytest.raises(GatewayDeny) as ai_deny:
        asyncio.run(app_main._community_gate(_DenyGateProvider(), entry))
    assert ai_deny.value.reason is DenyReason.POLICY_GATE_DENIED
    with pytest.raises(GatewayDeny) as ai_raise:
        asyncio.run(app_main._community_gate(_RaisingGateProvider(), entry))
    assert ai_raise.value.reason is DenyReason.POLICY_GATE_DENIED

    # --- main.py seam. ---
    gw = MCPIPGateway.__new__(MCPIPGateway)
    gw._community_gate_provider = _DenyGateProvider()
    with pytest.raises(_Deny) as m_deny:
        asyncio.run(gw._community_gate(entry))
    assert m_deny.value.reason is DenyReason.POLICY_GATE_DENIED

    gw._community_gate_provider = _RaisingGateProvider()
    with pytest.raises(_Deny) as m_raise:
        asyncio.run(gw._community_gate(entry))
    assert m_raise.value.reason is DenyReason.POLICY_GATE_DENIED


def test_p2_gate_context_is_topology_free() -> None:
    """``CommunityGateContext`` carries EXACTLY the whitelist — no target/secret/args field."""
    ctx = CommunityGateContext(
        alias="skill_x",
        transport_class="cloud_rest",
        risk_tier=RiskTier.AUTO,
        classification=Classification.UNCLASSIFIED,
    )
    assert set(ctx.model_dump().keys()) == GATE_CONTEXT_FIELDS
    # A ``target`` (or any non-whitelisted field) is rejected (extra='forbid').
    with pytest.raises(Exception):
        CommunityGateContext(
            alias="x",
            transport_class="cloud_rest",
            risk_tier=RiskTier.AUTO,
            classification=Classification.UNCLASSIFIED,
            target="rest.secret.internal",
        )


def test_p2_gate_context_authzen_mapping_matches_whitelist() -> None:
    """The SARC alignment mapping tracks the whitelist EXACTLY and is resource-only.

    ``set(GATE_CONTEXT_AUTHZEN_ENTITY) == GATE_CONTEXT_FIELDS`` (no drift), and EVERY
    value is a ``resource.*`` slot — proving the AuthZEN ``subject`` (identity) and
    ``action`` (arguments) contribute NOTHING to the gate context.
    """
    assert set(GATE_CONTEXT_AUTHZEN_ENTITY.keys()) == GATE_CONTEXT_FIELDS
    for field, slot in GATE_CONTEXT_AUTHZEN_ENTITY.items():
        assert slot.startswith("resource"), (field, slot)
        assert not slot.startswith("subject") and not slot.startswith("action")
    # ``alias`` is the resource id; the other three are coarse resource properties.
    assert GATE_CONTEXT_AUTHZEN_ENTITY["alias"] == "resource.id"
    assert all(
        GATE_CONTEXT_AUTHZEN_ENTITY[f].startswith("resource.properties.")
        for f in GATE_CONTEXT_FIELDS - {"alias"}
    )
    # The mapping is frozen (MappingProxyType) — a caller cannot widen it in place.
    with pytest.raises(TypeError):
        GATE_CONTEXT_AUTHZEN_ENTITY["subject"] = "subject.id"  # type: ignore[index]


def test_p2_gate_context_authzen_projection_is_whitelist_only() -> None:
    """``as_authzen_resource()`` is a whitelist-only, JSON-safe SARC ``resource`` view.

    ``id == alias``, ``type == GATE_RESOURCE_TYPE``, ``properties`` keyset ==
    ``GATE_CONTEXT_FIELDS - {'alias'}``, values are the enum ``.value`` strings, and NO
    target/secret/subject/action/arguments key appears anywhere in the projection.
    """
    ctx = CommunityGateContext(
        alias="skill_email_send",
        transport_class="cloud_rest",
        risk_tier=RiskTier.AUTO,
        classification=Classification.UNCLASSIFIED,
    )
    res = ctx.as_authzen_resource()
    assert res["id"] == "skill_email_send"
    assert res["type"] == GATE_RESOURCE_TYPE == "mcpip.skill"
    assert set(res["properties"].keys()) == GATE_CONTEXT_FIELDS - {"alias"}
    assert res["properties"]["risk_tier"] == "auto"
    assert res["properties"]["transport_class"] == "cloud_rest"
    assert res["properties"]["classification"] == "unclassified"

    # No topology/identity/argument key anywhere in the (shallow) projection tree.
    forbidden = {"target", "secret", "subject", "action", "arguments"}
    flat = set(res.keys()) | set(res["properties"].keys())
    assert flat.isdisjoint(forbidden)

    # Every value is JSON-safe (str, from the ``str, Enum`` .value) — a COAZ engine can
    # serialize the projection without an enum-encoding hook.
    import json

    json.dumps(res)  # would raise if a bare Enum leaked instead of its .value.


def test_p2_authzen_alignment_pulls_no_celpy() -> None:
    """The AuthZEN-shape alignment adds NO CEL dependency.

    Building a context and projecting it must not import ``celpy`` — the alignment is pure
    stdlib (``types.MappingProxyType`` + a dict projection), NOT a policy-DSL runtime.
    """
    import interfaces  # noqa: F401 — already imported; asserts alignment lives here.

    ctx = CommunityGateContext(
        alias="skill_x",
        transport_class="cloud_rest",
        risk_tier=RiskTier.AUTO,
        classification=Classification.UNCLASSIFIED,
    )
    ctx.as_authzen_resource()
    assert "celpy" not in sys.modules


def test_p2_gate_manifest_schema_validates_as_data() -> None:
    """A gate manifest is validated as pure DATA (no CEL parse): whitelist / cost / charset."""
    # Happy path — schema-valid, self-pin holds.
    gate = parse_gate_manifest(_gate_manifest())
    assert gate.kind == "gate" and gate.language == "cel"
    assert gate.referenced_context_fields == ["risk_tier"]

    # referenced_context_fields must be a SUBSET of the whitelist — ``target`` is refused.
    with pytest.raises(ExtensionManifestError):
        parse_gate_manifest(_gate_manifest(referenced_context_fields=["target"]))

    # max_cost is bounded by MAX_GATE_COST.
    with pytest.raises(ExtensionManifestError):
        parse_gate_manifest(_gate_manifest(max_cost=MAX_GATE_COST + 1))

    # A control/bidi char in the reviewer-read ``source`` is a charset reject (poisoning
    # countermeasure) — proves ``source`` is charset-scrubbed, NOT CEL-parsed.
    with pytest.raises(ExtensionManifestError):
        parse_gate_manifest(_gate_manifest(source='risk_tier ==‮ "auto"'))


def test_p2_gate_submit_stores_but_approval_refused(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A gate manifest submits + schema-validates + stores PENDING, but approval REFUSES.

    No static prover/engine is registered, so a gate can never be approved (no
    approve-without-proof). The reviewer pending list marks it ``approvable=False``.
    """
    gate = _gate_manifest(manifest_id="p2-gate-submit")
    resp = _submit(client, idp.mint(agent_id="agent-gate-author"), gate)
    assert resp.status_code == 200, resp.text
    sid = _json(resp)["submission_id"]

    # WORM recorded a gate submission (kind='gate').
    assert any(e.get("kind") == "gate" for e in _worm_admin_actions("extension_submit"))

    # The reviewer sees it, honestly flagged as not-yet-approvable.
    listing = client.get("/v1/admin/extensions/pending", headers=_bh(_reviewer(idp)))
    rows = {r["submission_id"]: r for r in _json(listing)["pending"]}
    assert sid in rows and rows[sid]["kind"] == "gate"
    assert rows[sid]["approvable"] is False

    # Approval is refused fail-closed (no prover) — opaque deny, engine still absent.
    assert community_gate_engine_registered() is False
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp)))
    )


def test_p2_app_import_does_not_require_celpy() -> None:
    """Importing the whole app never pulls ``celpy`` (the deferred native CEL runtime).

    ``app.main`` (hence the community-gate seam + manifest schema) is imported at the top of
    this module; assert the CEL runtime is absent from ``sys.modules`` and that importing the
    gate modules directly does not pull it either — no module hard-imports it.
    """
    assert "celpy" not in sys.modules
    import importlib

    importlib.import_module("services.community_gate")
    importlib.import_module("services.extension_manifest")
    assert "celpy" not in sys.modules, "no module may hard-import celpy"


if __name__ == "__main__":  # pragma: no cover - direct-run convenience.
    sys.exit(pytest.main([__file__, "-v"]))
