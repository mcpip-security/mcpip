"""
MCPIP V2 — CROSS test suite: SKILL / registry-overlay lifecycle × the authorize hot path.

    ◐ "The obfuscator catalog is immutable config; the overlay is what an operator (or an
       approved contributor) may ADD. Every add / disable / deregister must take effect on
       the very next authorize — the hot path is the state, not a cache of it."

Angle (per the cross-test brief): the operator-registered overlay + the community-approved
overlay are the ONLY runtime-mutable governors of what an agent may call, and they change the
``/v1/authorize`` decision the instant they change. These tests drive the REAL composition
root (``app.main._components``), REAL Redis (``:63790``), and the REAL FastAPI edge via
Starlette's ``TestClient`` — the exact harness discipline of ``tests/test_authorize_api.py``
and ``tests/test_community_extensions.py``. Nothing under test is mocked.

Scenarios (each a distinct cross of lifecycle × absence × isolation × attacker):
  * register overlay skill → appears in ``/v1/catalog`` + MCP ``tools/list`` + authorize
    ALLOWs; disable → authorize DENYs ``alias_disabled`` immediately (hot path reflects the
    kill-switch); re-enable → ALLOW again; deregister → gone from catalog/tools-list + denied.
  * additive-only: a duplicate/shadowing register is refused (never a repoint).
  * risk-tier / classification gating: a ``pin_required`` overlay stages a 202 the ``auto``
    one skips; a ``restricted`` overlay MUST be ``pin_required`` or registration is refused.
  * per-tenant isolation: tenant A's overlay alias is CROSS_TENANT-denied + invisible for B;
    a disable in A never leaks to B's like-named alias.
  * community skills inherit EVERYTHING (submit→approve→resolve, reject, additive-only, the
    kill-switch, deregister, tenant isolation, reviewer-gating).
  * canary/decoy alias → trips the tripwire + quarantines the agent (assert the quarantine
    roster + the WORM ``canary_tripped``), while real overlay aliases are unaffected.
  * overlay persistence across a fresh store instance (a reload); the community manifest
    hash-pin re-verify (rug-pull governance) passes intact and refuses a repoint.

Ground rules honored: UNIQUE uuid4 ids per test (tenants / agents / aliases); never assume an
empty db; deterministic; no real network / SMTP / socket. Every deny asserts BOTH the opaque
``{error, correlation_id}`` envelope to the caller AND the concrete reason in the WORM buffer.
"""

from __future__ import annotations

import os
import sys

# Make the repo root importable when run directly; pytest already adds it via rootdir.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- Namespaced sandbox env MUST be set before importing app.main (its composition root
#     reads the lru_cached settings ONCE, at the first import of app.main in the process).
#     Under ``pytest tests/`` an earlier module has already frozen that singleton, so these
#     ``setdefault``s are no-ops in-suite and we rebind the readers to the EFFECTIVE db below;
#     in isolation this module imports app.main first, so /3 is the live db. ----------------
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/3")
os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_cross_skills_worm.jsonl"),
)

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
import redis.asyncio as aioredis
from fastapi.testclient import TestClient
from httpx import Response

from core.config import get_settings as _get_settings
from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import (
    CAP_CATALOG_REVIEWER,
    CAP_DIRECTORY_ADMIN,
    Classification,
    DenyReason,
    RiskTier,
)
from obfuscator.alias_registry import AliasEntry
from services.catalog_overlay import CatalogOverlayStore, MAX_OVERLAY_ENTRIES
from services.extension_manifest import ExtensionManifest
from services.extension_submissions import ExtensionSubmissionStore

import app.main as app_main
from app.main import _components, app
from main import _DemoIdP

# Rebind readers/flush target to the db the LIVE components actually use (see the preamble):
# in-suite an earlier module froze the singleton, so this is that module's db, not /3.
_TEST_REDIS_URL = _get_settings().redis_url

_EVENTS_STREAM = "mcpip:worm:events"
_CORR_HEADER = "x-mcpip-correlation-id"

# Config (immutable) reference rows exercised for the "config is untouchable" assertions.
_CONFIG_AUTO = "skill_spend_summary"
_CANARY_ALIAS = "skill_export_all_credentials"  # a seeded AUTO-tier deception tripwire.
_EXISTING_CONFIG_ALIAS = "skill_payroll_run"  # a config PIN row used for the shadow refusal.


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
    """Module-scoped TestClient; flushes the dedicated test db before the lifespan.

    The flush keeps the persisted overlay small across repeat runs (Redis is durable at
    :63790) so ``MAX_OVERLAY_ENTRIES`` is never approached; every test still mints UNIQUE
    ids and never asserts on global counts, per the brief.
    """
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Helpers — unique ids, tokens, envelopes, WORM reads.
# ---------------------------------------------------------------------------


def _uid() -> str:
    return uuid.uuid4().hex


def _alias() -> str:
    return f"skill_x_{_uid()}"


def _tenant() -> str:
    return f"tenant-{_uid()}"


def _bh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _admin(idp: _DemoIdP, tenant_id: str = "tenant-acme") -> str:
    """A JWT holding CAP_DIRECTORY_ADMIN in ``tenant_id`` (the operator overlay authority)."""
    return idp.mint(
        tenant_id=tenant_id, agent_id=f"agent-admin-{_uid()}", capabilities=[CAP_DIRECTORY_ADMIN]
    )


def _reviewer(idp: _DemoIdP, tenant_id: str = "tenant-acme") -> str:
    """A JWT holding the DISTINCT community-review capability, nothing else."""
    return idp.mint(
        tenant_id=tenant_id, agent_id=f"agent-reviewer-{_uid()}", capabilities=[CAP_CATALOG_REVIEWER]
    )


def _plain(idp: _DemoIdP, tenant_id: str = "tenant-acme") -> str:
    return idp.mint(tenant_id=tenant_id, agent_id=f"agent-{_uid()}")


def _register(
    client: TestClient,
    admin_token: str,
    alias: str,
    *,
    target: str = "rest.overlay.demo.get",
    risk_tier: str = "auto",
    classification: str = "unclassified",
) -> Response:
    """Drive ``POST /v1/admin/skills/register`` (operator overlay add)."""
    return client.post(
        "/v1/admin/skills/register",
        json={
            "alias": alias,
            "target": target,
            "risk_tier": risk_tier,
            "classification": classification,
        },
        headers=_bh(admin_token),
    )


def _authorize(
    client: TestClient,
    token: str,
    alias: str,
    arguments: Optional[dict[str, Any]] = None,
    *,
    pin: Optional[str] = None,
    challenge_id: Optional[str] = None,
) -> Response:
    """Drive the alias through the REAL /v1/authorize pipeline (OpenAI envelope)."""
    body: dict[str, Any] = {
        "source_format": "openai_tool_call",
        "jwt": token,
        "tool_call": {
            "id": "call_cross",
            "type": "function",
            "function": {"name": alias, "arguments": json.dumps(arguments or {})},
        },
    }
    if pin is not None:
        body["pin"] = pin
    if challenge_id is not None:
        body["challenge_id"] = challenge_id
    return client.post("/v1/authorize", json=body)


def _stage_and_otp(
    client: TestClient, token: str, alias: str, arguments: dict[str, Any]
) -> tuple[str, str]:
    """Stage a PIN_REQUIRED action → (challenge_id, otp) fetched out-of-band (sandbox)."""
    staged = _authorize(client, token, alias, arguments)
    assert staged.status_code == 202, staged.text
    challenge_id = str(_json(staged)["challenge_id"])
    otp_resp = client.get(f"/v1/authenticator/{challenge_id}", headers=_bh(token))
    assert otp_resp.status_code == 200, otp_resp.text
    return challenge_id, str(_json(otp_resp)["otp"])


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


def _recent_events(count: int = 300) -> list[dict[str, Any]]:
    """Every buffered WORM ``event`` sub-dict, newest first."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=count)
    finally:
        reader.close()
    out: list[dict[str, Any]] = []
    for _sid, fields in entries:
        rec: Any = json.loads(fields["record"])
        event = rec.get("event", {})
        if isinstance(event, dict):
            out.append(event)
    return out


def _deny_reason_for_alias(alias: str) -> Optional[str]:
    """The concrete ``deny_reason`` of the newest WORM DENY for ``alias`` (opaque-vs-logged)."""
    for event in _recent_events():
        if event.get("decision") == "deny" and event.get("alias") == alias:
            reason = event.get("deny_reason")
            return reason if isinstance(reason, str) else None
    return None


def _last_deny_reason() -> Optional[str]:
    """The most-recently buffered WORM event's concrete ``deny_reason`` (tail)."""
    events = _recent_events(count=1)
    if not events:
        return None
    reason = events[0].get("deny_reason")
    return reason if isinstance(reason, str) else None


def _worm_admin_actions(action: str) -> list[dict[str, Any]]:
    """Every buffered WORM event whose ``admin_action`` equals ``action`` (newest first)."""
    return [e for e in _recent_events() if e.get("admin_action") == action]


def _catalog_names(client: TestClient, token: str) -> set[str]:
    resp = client.get("/v1/catalog", headers=_bh(token))
    assert resp.status_code == 200, resp.text
    return {str(item["alias"]) for item in _json(resp)["catalog"]}


def _catalog_items(client: TestClient, token: str) -> list[dict[str, Any]]:
    resp = client.get("/v1/catalog", headers=_bh(token))
    assert resp.status_code == 200, resp.text
    return list(_json(resp)["catalog"])


def _tools_list_names(client: TestClient, token: str) -> set[str]:
    resp = client.post(
        "/v1/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers=_bh(token),
    )
    assert resp.status_code == 200, resp.text
    result = _json(resp)["result"]
    return {str(t["name"]) for t in result["tools"]}


def _skill_manifest(
    *,
    alias: str,
    target: str = "rest.community.demo.get",
    risk_tier: str = "auto",
    classification: str = "unclassified",
    manifest_id: Optional[str] = None,
    author: str = "author-alice",
    transport: str = "cloud_rest",
) -> dict[str, Any]:
    """A self-consistent (correct ``sha256`` self-pin) ``kind='skill'`` manifest dict.

    The self-pin is computed the way the store does — over ``canonical_manifest_bytes`` which
    drops ``sha256`` — so the placeholder digest never affects a schema-valid result. For an
    intentionally schema-invalid manifest (bad transport / identity-shaped alias) the schema
    refuses it regardless of the digest, so the placeholder is left in place.
    """
    base: dict[str, Any] = {
        "schema": "mcpip-extension/1",
        "kind": "skill",
        "id": manifest_id or f"ext-{_uid()}",
        "author": author,
        "sha256": "0" * 64,
        "alias": alias,
        "target": target,
        "transport": transport,
        "risk_tier": risk_tier,
        "classification": classification,
    }
    try:
        base["sha256"] = ExtensionManifest.model_validate(base).computed_sha256()
    except Exception:  # noqa: BLE001 — schema-invalid manifests keep the placeholder digest.
        pass
    return base


def _submit(client: TestClient, token: str, manifest: dict[str, Any]) -> Response:
    return client.post("/v1/extensions/submit", json={"manifest": manifest}, headers=_bh(token))


def _submit_and_id(client: TestClient, token: str, manifest: dict[str, Any]) -> str:
    resp = _submit(client, token, manifest)
    assert resp.status_code == 200, resp.text
    return str(_json(resp)["submission_id"])


# ===========================================================================
# A — operator overlay: register → catalog/tools-list/authorize → disable → deregister.
# ===========================================================================


def test_register_appears_in_catalog_and_authorizes(client: TestClient, idp: _DemoIdP) -> None:
    """A freshly-registered overlay skill resolves on the NEXT authorize AND lists in catalog.

    The overlay add is registered live on this worker, so the hot path reflects the new alias
    with no restart — an AUTO cloud_rest overlay skill authorizes 200 through the real pipeline.
    """
    alias = _alias()
    assert _register(client, _admin(idp), alias).status_code == 200
    assert alias in _catalog_names(client, _plain(idp))
    ok = _authorize(client, _plain(idp), alias, {"q": "1"})
    assert ok.status_code == 200, ok.text
    assert _json(ok)["decision"] == "allow"


def test_registered_auto_returns_coarse_transport_class(client: TestClient, idp: _DemoIdP) -> None:
    """An overlay ALLOW surfaces only the coarse transport CLASS, never the dotted target."""
    alias = _alias()
    assert _register(client, _admin(idp), alias, target="rest.hidden.topology.v1").status_code == 200
    ok = _authorize(client, _plain(idp), alias)
    assert ok.status_code == 200, ok.text
    data = _json(ok)
    assert data["executed_target_class"] == "cloud_rest"
    assert "." not in data["executed_target_class"]  # class, not target (invariant #4).
    assert "rest.hidden.topology.v1" not in ok.text


def test_registered_skill_visible_in_tools_list(client: TestClient, idp: _DemoIdP) -> None:
    """The overlay skill appears in the MCP ``tools/list`` projection (same visibility)."""
    alias = _alias()
    assert _register(client, _admin(idp), alias).status_code == 200
    assert alias in _tools_list_names(client, _plain(idp))


def test_disable_denies_immediately_with_worm_reason(client: TestClient, idp: _DemoIdP) -> None:
    """Disable takes effect on the very next authorize: opaque deny to the caller, and the
    concrete ``alias_disabled`` reason in the WORM buffer only (opaque-vs-logged split)."""
    alias = _alias()
    admin = _admin(idp)
    assert _register(client, admin, alias).status_code == 200
    # Baseline: ALLOWs before the kill-switch.
    assert _authorize(client, _plain(idp), alias).status_code == 200

    dis = client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin))
    assert dis.status_code == 200 and _json(dis)["disabled"] == alias
    denied = _authorize(client, _plain(idp), alias)
    _assert_opaque(denied)
    assert _deny_reason_for_alias(alias) == DenyReason.SKILL_DISABLED.value == "alias_disabled"


def test_disable_then_enable_restores_hot_path(client: TestClient, idp: _DemoIdP) -> None:
    """disable → DENY, re-enable → ALLOW again: the hot path is the live state, both ways."""
    alias = _alias()
    admin = _admin(idp)
    assert _register(client, admin, alias).status_code == 200
    client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin))
    _assert_opaque(_authorize(client, _plain(idp), alias))

    en = client.post(f"/v1/admin/skills/{alias}/enable", headers=_bh(admin))
    assert en.status_code == 200 and _json(en) == {"enabled": alias, "removed": True}
    restored = _authorize(client, _plain(idp), alias)
    assert restored.status_code == 200, restored.text


def test_disable_is_idempotent(client: TestClient, idp: _DemoIdP) -> None:
    """Disabling an already-disabled alias is a safe no-op (still denied, still 200 on the op)."""
    alias = _alias()
    admin = _admin(idp)
    assert _register(client, admin, alias).status_code == 200
    first = client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin))
    second = client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin))
    assert first.status_code == 200 and second.status_code == 200
    assert _json(second)["disabled"] == alias
    _assert_opaque(_authorize(client, _plain(idp), alias))
    assert _deny_reason_for_alias(alias) == "alias_disabled"


def test_enable_when_not_disabled_is_noop(client: TestClient, idp: _DemoIdP) -> None:
    """Enabling an alias that was never disabled reports ``removed: False`` and still ALLOWs."""
    alias = _alias()
    admin = _admin(idp)
    assert _register(client, admin, alias).status_code == 200
    en = client.post(f"/v1/admin/skills/{alias}/enable", headers=_bh(admin))
    assert en.status_code == 200 and _json(en)["removed"] is False
    assert _authorize(client, _plain(idp), alias).status_code == 200


def test_deregister_removes_from_catalog_and_denies_unknown(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Deregister drops the alias from the registry: gone from catalog, ``unknown_alias`` on
    authorize (a full removal, distinct from the reversible disable kill-switch)."""
    alias = _alias()
    admin = _admin(idp)
    assert _register(client, admin, alias).status_code == 200
    assert alias in _catalog_names(client, _plain(idp))

    dr = client.post(f"/v1/admin/skills/{alias}/deregister", headers=_bh(admin))
    assert dr.status_code == 200 and _json(dr) == {"deregistered": alias, "removed": True}
    assert alias not in _catalog_names(client, _plain(idp))
    denied = _authorize(client, _plain(idp), alias)
    _assert_opaque(denied)
    assert _deny_reason_for_alias(alias) == "unknown_alias"


def test_deregister_removes_from_tools_list(client: TestClient, idp: _DemoIdP) -> None:
    """A deregistered overlay skill also disappears from the MCP ``tools/list`` projection."""
    alias = _alias()
    admin = _admin(idp)
    assert _register(client, admin, alias).status_code == 200
    assert alias in _tools_list_names(client, _plain(idp))
    assert client.post(f"/v1/admin/skills/{alias}/deregister", headers=_bh(admin)).status_code == 200
    assert alias not in _tools_list_names(client, _plain(idp))


def test_deregister_config_alias_is_noop_and_config_still_resolves(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Config aliases are immutable: a deregister of one is a no-op success and it keeps
    resolving — the overlay can only ever remove what it itself added."""
    admin = _admin(idp)
    dr = client.post(f"/v1/admin/skills/{_CONFIG_AUTO}/deregister", headers=_bh(admin))
    assert dr.status_code == 200 and _json(dr) == {"deregistered": _CONFIG_AUTO, "removed": False}
    # The config alias is untouched — it still authorizes.
    ok = _authorize(client, _plain(idp), _CONFIG_AUTO, {"period": "Q1"})
    assert ok.status_code == 200, ok.text


def test_deregister_is_idempotent(client: TestClient, idp: _DemoIdP) -> None:
    """Deregistering twice: the first removes (``removed: True``), the second is a no-op
    (``removed: False``) — a double-delete never errors or leaks a reason."""
    alias = _alias()
    admin = _admin(idp)
    assert _register(client, admin, alias).status_code == 200
    first = client.post(f"/v1/admin/skills/{alias}/deregister", headers=_bh(admin))
    second = client.post(f"/v1/admin/skills/{alias}/deregister", headers=_bh(admin))
    assert _json(first)["removed"] is True
    assert second.status_code == 200 and _json(second)["removed"] is False


def test_register_records_skill_register_in_worm(client: TestClient, idp: _DemoIdP) -> None:
    """Every overlay add is a WORM ``skill_register`` admin_action (non-repudiable operator log)."""
    alias = _alias()
    assert _register(client, _admin(idp), alias).status_code == 200
    assert any(e.get("alias") == alias for e in _worm_admin_actions("skill_register"))


# ===========================================================================
# A2 — additive-only + charset/identity guards inherited by overlay skills.
# ===========================================================================


def test_register_duplicate_overlay_refused(client: TestClient, idp: _DemoIdP) -> None:
    """Additive-only: registering an alias that is already an overlay entry is refused
    (opaque), and the ORIGINAL binding is never repointed — the first target keeps resolving."""
    alias = _alias()
    admin = _admin(idp)
    assert _register(client, admin, alias, target="rest.first.target").status_code == 200
    dup = _register(client, admin, alias, target="rest.attacker.exfil")
    _assert_opaque(dup)
    # The alias still resolves (to its original, un-repointed binding).
    assert _authorize(client, _plain(idp), alias).status_code == 200


def test_register_cannot_shadow_config_alias(client: TestClient, idp: _DemoIdP) -> None:
    """Additive-only: an overlay can never SHADOW a config alias — registering onto a
    config PIN row is refused, and that row keeps its original (PIN-gated) behavior."""
    admin = _admin(idp)
    shadow = _register(client, admin, _EXISTING_CONFIG_ALIAS, target="rest.attacker.exfil")
    _assert_opaque(shadow)
    # The config PIN alias still behaves as itself — a no-pin call stages (202), not ALLOW.
    staged = _authorize(client, _plain(idp), _EXISTING_CONFIG_ALIAS, {"run_id": "PR-1"})
    assert staged.status_code == 202, staged.text


def test_register_invalid_risk_tier_refused(client: TestClient, idp: _DemoIdP) -> None:
    """A risk tier outside the overlay allow-set is an opaque deny (never a silent coerce)."""
    _assert_opaque(_register(client, _admin(idp), _alias(), risk_tier="critical"))


def test_register_requires_directory_admin(client: TestClient, idp: _DemoIdP) -> None:
    """Register is CAP_DIRECTORY_ADMIN-gated: a plain principal is opaque-denied and the
    alias never comes into being (a subsequent authorize is ``unknown_alias``)."""
    alias = _alias()
    _assert_opaque(_register(client, _plain(idp), alias))
    denied = _authorize(client, _plain(idp), alias)
    _assert_opaque(denied)
    assert _deny_reason_for_alias(alias) == "unknown_alias"


def test_registered_skill_still_enforces_identity_injection(
    client: TestClient, idp: _DemoIdP
) -> None:
    """An overlay skill is NOT a lower-trust lane: an identity-shaped argument key on it is
    the same hard deny (``identity_injection``) as on any config alias."""
    alias = _alias()
    assert _register(client, _admin(idp), alias).status_code == 200
    denied = _authorize(client, _plain(idp), alias, {"tenant_id": "evil"})
    _assert_opaque(denied)
    # The identity hard-deny fires during bridge parse, BEFORE ``ctx['alias']`` is set, so
    # the deny event carries no alias — read the tail reason (this authorize is the last emit).
    assert _last_deny_reason() == "identity_injection"


# ===========================================================================
# A3 — risk-tier / classification gating: the higher-risk alias needs the extra control.
# ===========================================================================


def test_pin_required_overlay_stages_while_auto_does_not(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Risk-tier gating on runtime-registered skills: a ``pin_required`` overlay stages a 202
    step-up (``pin_required`` in WORM) that the like-shaped ``auto`` overlay skips (200)."""
    admin = _admin(idp)
    auto_alias, pin_alias = _alias(), _alias()
    assert _register(client, admin, auto_alias, risk_tier="auto").status_code == 200
    assert _register(client, admin, pin_alias, risk_tier="pin_required").status_code == 200

    assert _authorize(client, _plain(idp), auto_alias).status_code == 200
    staged = _authorize(client, _plain(idp), pin_alias, {"n": "1"})
    assert staged.status_code == 202, staged.text
    assert "otp" not in _json(staged) and "pin" not in _json(staged)
    assert _deny_reason_for_alias(pin_alias) == "pin_required"


def test_pin_required_overlay_completes_with_oob_otp(client: TestClient, idp: _DemoIdP) -> None:
    """A runtime-registered PIN skill completes ONLY with the out-of-band OTP — the full
    stage→fetch→consume payload-lock round trip works on an overlay alias exactly as config."""
    admin = _admin(idp)
    alias = _alias()
    assert _register(client, admin, alias, risk_tier="pin_required").status_code == 200
    token = _plain(idp)
    args = {"amount": "10", "cycle": "monthly"}
    challenge_id, otp = _stage_and_otp(client, token, alias, args)
    done = _authorize(client, token, alias, args, pin=otp, challenge_id=challenge_id)
    assert done.status_code == 200, done.text
    assert _json(done)["decision"] == "allow"


def test_restricted_overlay_must_be_pin_required(client: TestClient, idp: _DemoIdP) -> None:
    """Classification gating (sender-constraint boot-lint parity): a RESTRICTED overlay skill
    that is not PIN_REQUIRED is refused (a no-PIN sensitive read); RESTRICTED+PIN is accepted."""
    admin = _admin(idp)
    bad = _register(
        client, admin, _alias(), risk_tier="auto", classification="restricted"
    )
    _assert_opaque(bad)
    good_alias = _alias()
    good = _register(
        client, admin, good_alias, risk_tier="pin_required", classification="restricted"
    )
    assert good.status_code == 200, good.text
    # And it is PIN-gated on the hot path (stages, never a silent AUTO allow).
    assert _authorize(client, _plain(idp), good_alias, {"n": "1"}).status_code == 202


# ===========================================================================
# B — per-tenant isolation of the overlay.
# ===========================================================================


def test_overlay_skill_is_cross_tenant_denied_for_another_tenant(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Tenant A's overlay alias is invisible to tenant B: B's authorize is a CROSS_TENANT
    deny (known-but-not-yours) — the overlay is tenant-keyed, no leakage across the boundary."""
    tenant_a, tenant_b = _tenant(), _tenant()
    alias = _alias()
    assert _register(client, _admin(idp, tenant_a), alias).status_code == 200
    denied = _authorize(client, _plain(idp, tenant_b), alias)
    _assert_opaque(denied)
    assert _deny_reason_for_alias(alias) == "cross_tenant"


def test_overlay_skill_absent_from_other_tenant_catalog(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Tenant A's overlay alias never appears in tenant B's catalog projection."""
    tenant_a, tenant_b = _tenant(), _tenant()
    alias = _alias()
    assert _register(client, _admin(idp, tenant_a), alias).status_code == 200
    assert alias in _catalog_names(client, _plain(idp, tenant_a))
    assert alias not in _catalog_names(client, _plain(idp, tenant_b))


def test_disable_is_isolated_per_tenant(client: TestClient, idp: _DemoIdP) -> None:
    """The kill-switch is tenant-scoped: the SAME alias name registered in A and B, disabled
    only in A, denies in A but keeps ALLOWing in B — a disable never leaks across tenants."""
    tenant_a, tenant_b = _tenant(), _tenant()
    admin_a, admin_b = _admin(idp, tenant_a), _admin(idp, tenant_b)
    alias = _alias()
    assert _register(client, admin_a, alias, target="rest.a.target").status_code == 200
    assert _register(client, admin_b, alias, target="rest.b.target").status_code == 200

    assert client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin_a)).status_code == 200
    denied_a = _authorize(client, _plain(idp, tenant_a), alias)
    _assert_opaque(denied_a)
    assert _deny_reason_for_alias(alias) == "alias_disabled"
    # Tenant B's like-named alias is unaffected.
    assert _authorize(client, _plain(idp, tenant_b), alias).status_code == 200


def test_deregister_is_isolated_per_tenant(client: TestClient, idp: _DemoIdP) -> None:
    """Deregistering an alias in tenant A leaves tenant B's like-named alias fully resolvable."""
    tenant_a, tenant_b = _tenant(), _tenant()
    admin_a, admin_b = _admin(idp, tenant_a), _admin(idp, tenant_b)
    alias = _alias()
    assert _register(client, admin_a, alias, target="rest.a.target").status_code == 200
    assert _register(client, admin_b, alias, target="rest.b.target").status_code == 200
    assert client.post(f"/v1/admin/skills/{alias}/deregister", headers=_bh(admin_a)).status_code == 200
    # A no longer resolves it; B still does.
    _assert_opaque(_authorize(client, _plain(idp, tenant_a), alias))
    assert _authorize(client, _plain(idp, tenant_b), alias).status_code == 200


# ===========================================================================
# C — community skills inherit the whole overlay lifecycle (submit → approve → …).
# ===========================================================================


def test_community_submit_pending_then_approve_resolves(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A submitted community skill is unknown until a reviewer approves; approval mints it
    onto the SAME overlay path and it resolves through the real pipeline (200)."""
    tenant = _tenant()
    alias = _alias()
    sid = _submit_and_id(client, _plain(idp, tenant), _skill_manifest(alias=alias))
    # Unknown before approval (submit never touches the catalog).
    _assert_opaque(_authorize(client, _plain(idp, tenant), alias))

    approve = client.post(
        f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp, tenant))
    )
    assert approve.status_code == 200 and _json(approve)["approved"] == alias
    ok = _authorize(client, _plain(idp, tenant), alias)
    assert ok.status_code == 200, ok.text


def test_community_approve_worm_before_overlay(client: TestClient, idp: _DemoIdP) -> None:
    """The approval is WORM-recorded (write-before-execute) carrying the manifest pin, and the
    alias then resolves — the durable approve record precedes the live mint."""
    tenant = _tenant()
    alias = _alias()
    manifest = _skill_manifest(alias=alias)
    sid = _submit_and_id(client, _plain(idp, tenant), manifest)
    approve = client.post(
        f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp, tenant))
    )
    assert approve.status_code == 200, approve.text
    mine = [
        e
        for e in _worm_admin_actions("extension_approve")
        if e.get("alias") == alias and e.get("tenant_id") == tenant
    ]
    assert mine and mine[0]["manifest_sha256"] == manifest["sha256"]


def test_community_skill_obeys_kill_switch(client: TestClient, idp: _DemoIdP) -> None:
    """A community-minted skill is a first-class overlay: the operator kill-switch disables
    it (``alias_disabled``) and re-enable restores it — same hot-path governance as an
    operator-registered skill."""
    tenant = _tenant()
    alias = _alias()
    sid = _submit_and_id(client, _plain(idp, tenant), _skill_manifest(alias=alias))
    admin = _admin(idp, tenant)
    assert client.post(
        f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp, tenant))
    ).status_code == 200
    assert _authorize(client, _plain(idp, tenant), alias).status_code == 200

    assert client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin)).status_code == 200
    _assert_opaque(_authorize(client, _plain(idp, tenant), alias))
    assert _deny_reason_for_alias(alias) == "alias_disabled"
    assert client.post(f"/v1/admin/skills/{alias}/enable", headers=_bh(admin)).status_code == 200
    assert _authorize(client, _plain(idp, tenant), alias).status_code == 200


def test_community_skill_is_deregisterable(client: TestClient, idp: _DemoIdP) -> None:
    """A community-approved overlay skill can be deregistered like any operator overlay,
    after which it is gone from the catalog and denied ``unknown_alias``."""
    tenant = _tenant()
    alias = _alias()
    sid = _submit_and_id(client, _plain(idp, tenant), _skill_manifest(alias=alias))
    admin = _admin(idp, tenant)
    assert client.post(
        f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp, tenant))
    ).status_code == 200
    assert alias in _catalog_names(client, _plain(idp, tenant))

    assert client.post(f"/v1/admin/skills/{alias}/deregister", headers=_bh(admin)).status_code == 200
    assert alias not in _catalog_names(client, _plain(idp, tenant))
    denied = _authorize(client, _plain(idp, tenant), alias)
    _assert_opaque(denied)
    assert _deny_reason_for_alias(alias) == "unknown_alias"


def test_community_reject_mints_nothing(client: TestClient, idp: _DemoIdP) -> None:
    """Reject is terminal, applies NOTHING (the alias never resolves), and is WORM-recorded."""
    tenant = _tenant()
    alias = _alias()
    sid = _submit_and_id(client, _plain(idp, tenant), _skill_manifest(alias=alias))
    rej = client.post(
        f"/v1/admin/extensions/{sid}/reject", headers=_bh(_reviewer(idp, tenant))
    )
    assert rej.status_code == 200 and _json(rej)["rejected"] == sid
    _assert_opaque(_authorize(client, _plain(idp, tenant), alias))
    assert any(
        e.get("alias") == alias and e.get("tenant_id") == tenant
        for e in _worm_admin_actions("extension_reject")
    )


def test_community_additive_only_repoint_refused(client: TestClient, idp: _DemoIdP) -> None:
    """A community approval that would REPOINT an existing overlay alias is refused — the
    authoritative additive-only ``has_alias`` runs at approve, so the first binding stands."""
    tenant = _tenant()
    alias = _alias()
    admin = _admin(idp, tenant)
    # Operator registers the alias first.
    assert _register(client, admin, alias, target="rest.first.target").status_code == 200
    # A community submission for the SAME alias stores PENDING (submit is oracle-free) …
    sid = _submit_and_id(
        client, _plain(idp, tenant), _skill_manifest(alias=alias, target="rest.attacker.exfil")
    )
    # … but approve REFUSES it (additive-only), and the original binding keeps resolving.
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp, tenant)))
    )
    assert _authorize(client, _plain(idp, tenant), alias).status_code == 200


def test_community_non_cloud_rest_transport_refused_at_submit(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A non-``cloud_rest`` transport is refused at the schema boundary (submit → opaque 403),
    so the community path can never mint onto a privileged transport."""
    manifest = _skill_manifest(alias=_alias(), transport="legacy_mainframe")
    _assert_opaque(_submit(client, _plain(idp, _tenant()), manifest))


def test_community_restricted_gating(client: TestClient, idp: _DemoIdP) -> None:
    """Community skills inherit the classification gate: ``restricted``+``auto`` is refused at
    submit, ``restricted``+``pin_required`` is accepted (the same rule operator overlays obey)."""
    tenant = _tenant()
    bad = _skill_manifest(alias=_alias(), classification="restricted", risk_tier="auto")
    _assert_opaque(_submit(client, _plain(idp, tenant), bad))
    good = _skill_manifest(
        alias=_alias(), classification="restricted", risk_tier="pin_required"
    )
    assert _submit(client, _plain(idp, tenant), good).status_code == 200


def test_community_identity_shaped_alias_denied(client: TestClient, idp: _DemoIdP) -> None:
    """An identity-shaped manifest alias (``role``) is a hard deny at submit — the manifest
    identity-fold mirrors the argument identity-injection guard."""
    manifest = _skill_manifest(alias="role")
    _assert_opaque(_submit(client, _plain(idp, _tenant()), manifest))


def test_community_non_reviewer_cannot_approve(client: TestClient, idp: _DemoIdP) -> None:
    """Approve needs the DISTINCT CAP_CATALOG_REVIEWER: neither a plain principal nor the
    sibling CAP_DIRECTORY_ADMIN can approve; the submission stays pending (alias unresolved)."""
    tenant = _tenant()
    alias = _alias()
    sid = _submit_and_id(client, _plain(idp, tenant), _skill_manifest(alias=alias))
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(_plain(idp, tenant)))
    )
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(_admin(idp, tenant)))
    )
    _assert_opaque(_authorize(client, _plain(idp, tenant), alias))


def test_community_second_action_on_terminal_submission_refused(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A submission is single-shot: after approval the same id cannot be approved again
    (not PENDING) — no double-mint from one submission."""
    tenant = _tenant()
    alias = _alias()
    sid = _submit_and_id(client, _plain(idp, tenant), _skill_manifest(alias=alias))
    reviewer = _reviewer(idp, tenant)
    assert client.post(
        f"/v1/admin/extensions/{sid}/approve", headers=_bh(reviewer)
    ).status_code == 200
    _assert_opaque(client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(reviewer)))


def test_community_pin_required_skill_stages(client: TestClient, idp: _DemoIdP) -> None:
    """Risk-tier gating flows through the community path: an approved ``pin_required`` skill
    stages a 202 (never a silent AUTO allow)."""
    tenant = _tenant()
    alias = _alias()
    sid = _submit_and_id(
        client, _plain(idp, tenant), _skill_manifest(alias=alias, risk_tier="pin_required")
    )
    assert client.post(
        f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp, tenant))
    ).status_code == 200
    staged = _authorize(client, _plain(idp, tenant), alias, {"n": "1"})
    assert staged.status_code == 202, staged.text
    assert _deny_reason_for_alias(alias) == "pin_required"


def test_community_submission_is_tenant_isolated(client: TestClient, idp: _DemoIdP) -> None:
    """Submissions are JWT-tenant-keyed: tenant B's reviewer cannot even see (let alone
    approve) tenant A's submission id — cross-tenant approve is structurally impossible."""
    tenant_a, tenant_b = _tenant(), _tenant()
    alias = _alias()
    sid = _submit_and_id(client, _plain(idp, tenant_a), _skill_manifest(alias=alias))
    # B's reviewer approving A's sid → the record is absent in B's tenant → opaque deny.
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp, tenant_b)))
    )
    # A's reviewer still sees it PENDING.
    listing = client.get("/v1/admin/extensions/pending", headers=_bh(_reviewer(idp, tenant_a)))
    assert listing.status_code == 200
    assert sid in {r["submission_id"] for r in _json(listing)["pending"]}
    # Nothing was minted for A either (never approved).
    _assert_opaque(_authorize(client, _plain(idp, tenant_a), alias))


# ===========================================================================
# D — canary / decoy tripwire vs. real overlay aliases.
# ===========================================================================


def test_canary_trips_quarantines_and_spares_siblings(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Selecting a decoy alias trips ``canary_tripped`` + quarantines the agent (asserted via
    the admin roster AND WORM); its next otherwise-valid call denies ``agent_quarantined``,
    while a sibling agent of the same tenant is unaffected — blast radius is exactly one."""
    agent_id = f"agent-canary-{_uid()}"
    token = idp.mint(tenant_id="tenant-acme", agent_id=agent_id)

    # 1) Trip the decoy (AUTO-tier, so it fires with no step-up).
    tripped = _authorize(client, token, _CANARY_ALIAS, {"scope": "all"})
    _assert_opaque(tripped)
    assert _deny_reason_for_alias(_CANARY_ALIAS) == "canary_tripped"

    # 2) The agent is now frozen: its next valid AUTO call denies agent_quarantined …
    frozen = _authorize(client, token, _CONFIG_AUTO, {"period": "Q1"})
    _assert_opaque(frozen)
    assert _last_deny_reason() == "agent_quarantined"

    # … and the freeze is visible on the operator quarantine roster.
    roster = client.get("/v1/admin/quarantine", headers=_bh(_admin(idp, "tenant-acme")))
    assert roster.status_code == 200, roster.text
    assert agent_id in {r["agent_id"] for r in _json(roster)["quarantined"]}

    # 3) A sibling agent authorizes normally.
    sibling = idp.mint(tenant_id="tenant-acme", agent_id=f"agent-sibling-{_uid()}")
    assert _authorize(client, sibling, _CONFIG_AUTO, {"period": "Q1"}).status_code == 200


def test_canary_flag_never_leaks_in_catalog(client: TestClient, idp: _DemoIdP) -> None:
    """The decoy is visible BAIT in the catalog, but the ``canary`` tripwire flag and the real
    target never cross the agent boundary (invariant #4) — the deception stays opaque."""
    items = _catalog_items(client, idp.mint(tenant_id="tenant-acme", agent_id=f"a-{_uid()}"))
    names = {str(i["alias"]) for i in items}
    assert _CANARY_ALIAS in names  # bait is visible …
    for item in items:
        assert "canary" not in item  # … but the tripwire flag never leaks …
        assert "target" not in item  # … and neither does the real target.


def test_real_overlay_skill_unaffected_by_decoy_trip(client: TestClient, idp: _DemoIdP) -> None:
    """A tripped decoy quarantines only the tripping agent: a real overlay skill in the same
    tenant keeps resolving for an untainted agent — decoys never disable real skills."""
    admin = _admin(idp, "tenant-acme")
    alias = _alias()
    assert _register(client, admin, alias).status_code == 200

    tripper = idp.mint(tenant_id="tenant-acme", agent_id=f"agent-trip-{_uid()}")
    _assert_opaque(_authorize(client, tripper, _CANARY_ALIAS, {"scope": "all"}))
    # A DIFFERENT agent still authorizes the real overlay skill.
    clean = idp.mint(tenant_id="tenant-acme", agent_id=f"agent-clean-{_uid()}")
    assert _authorize(client, clean, alias).status_code == 200


# ===========================================================================
# E — overlay persistence (reload) + community manifest hash-pin (rug-pull governance).
#
# Engine-level, mirroring tests/test_community_extensions.py's rug-pull test: a fresh
# Redis client + store on THIS test's event loop (the app's own store is bound to the
# lifespan loop), unique tenants/aliases, no flush (isolation via unique ids). No mocks.
# ===========================================================================


def test_overlay_store_persists_across_a_fresh_instance() -> None:
    """The overlay lives in Redis, not process memory: a SECOND store instance (a stand-in for
    a restarted worker) reads back exactly what the first wrote — this is what lets
    ``_hydrate_catalog_overlay`` reload operator skills across a reboot."""
    tenant = _tenant()
    alias = _alias()
    fields = app_main._overlay_fields("rest.persist.target", "auto", "unclassified")

    async def _body() -> None:
        w = aioredis.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
        r = aioredis.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
        try:
            assert await CatalogOverlayStore(w).add(tenant, alias, fields) is True
            # A completely separate store instance sees the persisted row.
            reloaded = await CatalogOverlayStore(r).get(tenant, alias)
            assert reloaded is not None
            assert reloaded["target"] == "rest.persist.target"
            assert reloaded["transport"] == "cloud_rest"
            # And the hydrator's reconstruction yields a live AliasEntry.
            entry = app_main._overlay_entry(alias, reloaded)
            assert isinstance(entry, AliasEntry)
            assert entry.target == "rest.persist.target"
            assert entry.risk_tier is RiskTier.AUTO
            # Cleanup this test's unique row.
            assert await CatalogOverlayStore(w).remove(tenant, alias) is True
            assert await CatalogOverlayStore(r).get(tenant, alias) is None
        finally:
            await w.aclose()
            await r.aclose()

    asyncio.run(_body())


def test_overlay_store_add_is_additive_only_hsetnx() -> None:
    """The store's ``add`` is an atomic HSETNX: the first create wins, a second add for the
    same alias returns False and NEVER overwrites the stored fields — the additive-only
    guarantee is decided by Redis, not a per-worker in-memory check."""
    tenant = _tenant()
    alias = _alias()
    original = app_main._overlay_fields("rest.original.target", "auto", "unclassified")
    repoint = app_main._overlay_fields("rest.attacker.exfil", "auto", "unclassified")

    async def _body() -> None:
        r = aioredis.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
        store = CatalogOverlayStore(r)
        try:
            assert await store.add(tenant, alias, original) is True
            assert await store.exists(tenant, alias) is True
            # Second add (a repoint attempt) is refused and the row is untouched.
            assert await store.add(tenant, alias, repoint) is False
            stored = await store.get(tenant, alias)
            assert stored is not None and stored["target"] == "rest.original.target"
            await store.remove(tenant, alias)
        finally:
            await r.aclose()

    asyncio.run(_body())


def test_community_pin_reverify_passes_intact_refuses_repoint(monkeypatch: Any) -> None:
    """The boot-load rug-pull re-verify (``_community_pin_valid``) is the hash-pin governance a
    community overlay row rides through on every reload: an INTACT approved manifest re-verifies
    True, but a repointed overlay ``target`` (manifest left alone) is refused False — a
    de-synced overlay field can never silently reload a repointed skill."""
    from services.extension_manifest import parse_manifest

    tenant = _tenant()
    alias = _alias()
    manifest = parse_manifest(_skill_manifest(alias=alias, target="rest.honest.target"))
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

    async def _body() -> tuple[bool, bool, bool]:
        r = aioredis.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
        store = ExtensionSubmissionStore(r)
        monkeypatch.setattr(_components, "extension_submissions", store)
        try:
            # No approved record yet → fail-closed (re-review required).
            missing = await app_main._community_pin_valid(tenant, alias, entry, fields)
            # Intact approved manifest → the pin re-verify PASSES.
            await store.add_approved(tenant, alias, approved_record)
            intact = await app_main._community_pin_valid(tenant, alias, entry, fields)
            # Repoint the OVERLAY row's target only (approved manifest untouched) → the field
            # cross-check refuses it.
            tampered_fields = dict(fields)
            tampered_fields["target"] = "rest.evil.exfil"
            tampered_entry = app_main._overlay_entry(alias, tampered_fields)
            assert tampered_entry is not None and tampered_entry.target == "rest.evil.exfil"
            after = await app_main._community_pin_valid(
                tenant, alias, tampered_entry, tampered_fields
            )
            return missing, intact, after
        finally:
            await r.aclose()

    missing, intact, after = asyncio.run(_body())
    assert missing is False, "an absent approved record must fail closed"
    assert intact is True, "an intact approved manifest must re-verify"
    assert after is False, "a repointed overlay field must be refused (field cross-check)"


# ===========================================================================
# F — pure governance-predicate unit tests (deterministic, no Redis, no network).
# ===========================================================================


def test_overlay_skill_invalid_accepts_valid_shapes() -> None:
    """The single-source-of-truth validity predicate ACCEPTS the two legal shapes."""
    assert app_main._overlay_skill_invalid("skill_ok", "rest.t", "auto", "unclassified") is False
    assert (
        app_main._overlay_skill_invalid("skill_ok", "rest.t", "pin_required", "restricted")
        is False
    )


def test_overlay_skill_invalid_refuses_restricted_auto() -> None:
    """RESTRICTED without PIN_REQUIRED is INVALID (the no-PIN sensitive-read the boot-lint
    rejects) — the runtime overlay parity guard."""
    assert (
        app_main._overlay_skill_invalid("skill_ok", "rest.t", "auto", "restricted") is True
    )


def test_overlay_skill_invalid_refuses_bad_enums_and_target() -> None:
    """Bad risk/classification, a newline or over-length target, and an empty alias are all
    INVALID — the coarse shape guard the register/approve handlers share."""
    assert app_main._overlay_skill_invalid("skill_ok", "rest.t", "critical", "unclassified") is True
    assert app_main._overlay_skill_invalid("skill_ok", "rest.t", "auto", "secret") is True
    assert app_main._overlay_skill_invalid("skill_ok", "rest\n.t", "auto", "unclassified") is True
    assert app_main._overlay_skill_invalid("skill_ok", "x" * 513, "auto", "unclassified") is True
    assert app_main._overlay_skill_invalid("", "rest.t", "auto", "unclassified") is True


def test_overlay_entry_reconstruction_and_none_cases() -> None:
    """``_overlay_entry`` rebuilds a cloud_rest AliasEntry from stored fields and returns None
    for a non-cloud_rest transport or a malformed risk tier (the hydrator's fail-closed skip)."""
    good = app_main._overlay_fields("rest.t", "pin_required", "restricted")
    entry = app_main._overlay_entry("skill_ok", good)
    assert isinstance(entry, AliasEntry)
    assert entry.transport == "cloud_rest"
    assert entry.risk_tier is RiskTier.PIN_REQUIRED
    assert entry.classification is Classification.RESTRICTED
    # A privileged transport can never be reconstructed from an overlay row.
    bad_transport = dict(good)
    bad_transport["transport"] = "legacy_mainframe"
    assert app_main._overlay_entry("skill_ok", bad_transport) is None
    # A malformed risk enum is None (fail-closed), never a coerced default.
    bad_risk = dict(good)
    bad_risk["risk_tier"] = "critical"
    assert app_main._overlay_entry("skill_ok", bad_risk) is None


def test_overlay_field_maps_have_expected_shape() -> None:
    """``_overlay_fields`` forces cloud_rest + stamps a timestamp; the community variant adds the
    ``source='community'`` discriminator + the manifest pin (both inert to the auth pipeline)."""
    op = app_main._overlay_fields("rest.t", "auto", "unclassified")
    assert op["transport"] == "cloud_rest"
    assert op["target"] == "rest.t" and op["risk_tier"] == "auto"
    assert "registered_at" in op and "source" not in op

    comm = app_main._community_overlay_fields("rest.t", "auto", "unclassified", "a" * 64)
    assert comm["source"] == app_main._OVERLAY_SOURCE_COMMUNITY == "community"
    assert comm["manifest_sha256"] == "a" * 64
    assert comm["transport"] == "cloud_rest"


def test_skill_disabled_deny_reason_wire_value() -> None:
    """The kill-switch deny reason's wire value is exact and clears the metric-label hygiene
    guard (no ``skill_`` substring that a canary/alias oracle could scrape off /metrics)."""
    assert DenyReason.SKILL_DISABLED.value == "alias_disabled"
    assert "skill_" not in DenyReason.SKILL_DISABLED.value
    assert MAX_OVERLAY_ENTRIES > 0  # the overlay is bounded (metadata, not bulk).


if __name__ == "__main__":  # pragma: no cover — direct-run convenience.
    sys.exit(pytest.main([__file__, "-v"]))
