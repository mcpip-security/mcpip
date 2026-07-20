"""
MCPIP V2 — Registry-sourced skill governance test suite (X3, Phase 3a).

    ◐  "The open MCP Registry is preview + unsigned. MCPIP governs a registry-sourced
       server.json by PROJECTING it into the hardened Phase-1 overlay + a reviewer-pinned
       verified-publisher allow-list — no live fetch, no new trust root."

Exercises the registry-server extension surface end-to-end against the REAL composition
root (``app.main._components``), REAL Redis (``:63790``), and the REAL FastAPI edge via
Starlette's ``TestClient`` — the same discipline as ``tests/test_community_extensions.py``.
Nothing under test is mocked; the only test double is a rug-pull driver that re-binds the
REAL Redis-backed stores onto the test event loop to exercise ``_community_pin_valid``.

Covered: the happy path (submit → allow-list the publisher → approve → the overlay resolves
the alias through the REAL pipeline); the verified-publisher fail-closed gate; additive-only
(repoint) refusal; privileged-transport impossibility (local/stdio-only server.json refused);
restricted+auto refusal; identity-shaped hard-deny; the sha256 self-pin + rug-pull (manifest/
overlay edit AND publisher de-list) boot re-verify; provenance recorded-not-trusted; opacity;
the CAP_CATALOG_REVIEWER-gated allow-list admin surface with emit-before-mutate WORM; and the
backward-compat / no-celpy guarantees.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Dedicated db (/13) keeps this suite isolated from the other API suites.
_TEST_REDIS_URL = "redis://localhost:63790/13"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_reg_test_worm.jsonl"),
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

from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import (
    CAP_CATALOG_REVIEWER,
    CAP_DIRECTORY_ADMIN,
    MAX_VERIFIED_PUBLISHERS,
)
from services.extension_manifest import (
    RegistryServerManifest,
    parse_registry_manifest,
    ExtensionManifestError,
    publisher_namespace,
)
from services.extension_submissions import ExtensionSubmissionStore
from services.registry_publishers import (
    PUBLISHERS_SCHEMA,
    PublisherAllowList,
    PublisherAllowListError,
    PublisherStoreError,
    VerifiedPublisherStore,
)

import app.main as app_main
from app.main import _components, app

from core.config import get_settings as _get_settings

_TEST_REDIS_URL = _get_settings().redis_url

_CORR_HEADER = "x-mcpip-correlation-id"
_EVENTS_STREAM = "mcpip:worm:events"
_EXISTING_ALIAS = "skill_spend_summary"


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def idp() -> Any:
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


def _reviewer(idp: Any, tenant_id: str = "tenant-acme") -> str:
    return idp.mint(
        tenant_id=tenant_id, agent_id="agent-reviewer", capabilities=[CAP_CATALOG_REVIEWER]
    )


def _bh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _server_json(
    *,
    name: str = "io.github.acme/weather",
    description: str = "Weather MCP server",
    version: str = "1.2.0",
    url: str = "https://mcp.acme.example/mcp",
    remote_type: str = "streamable-http",
    with_remote: bool = True,
    extra_packages: bool = False,
    meta: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "name": name,
        "description": description,
        "version": version,
        "_meta": (
            {"io.modelcontextprotocol.registry/official": {"id": "srv-abc", "published_at": "2026-01-01T00:00:00Z"}}
            if meta is None
            else meta
        ),
        "remotes": [],
    }
    if with_remote:
        doc["remotes"] = [{"type": remote_type, "url": url}]
    if extra_packages:
        # A real registry doc often carries local packages too — tolerated (extra='allow'),
        # never a target source.
        doc["packages"] = [{"registryType": "npm", "identifier": "@acme/weather"}]
        doc["status"] = "active"
    return doc


def _registry_manifest(
    *,
    alias: str = "skill_reg_weather",
    risk_tier: str = "auto",
    classification: str = "unclassified",
    manifest_id: str = "reg-1",
    author: str = "carol",
    server: Optional[dict[str, Any]] = None,
    fix_pin: bool = True,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema": "mcpip-extension/1",
        "kind": "registry_server",
        "id": manifest_id,
        "author": author,
        "sha256": "0" * 64,
        "alias": alias,
        "risk_tier": risk_tier,
        "classification": classification,
        "server": _server_json() if server is None else server,
    }
    if fix_pin:
        try:
            base["sha256"] = RegistryServerManifest.model_validate(base).computed_sha256()
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
    assert resp.status_code == 403, resp.text
    data = _json(resp)
    assert set(data.keys()) == {"error", "correlation_id"}, data
    assert data["error"] == AGENT_FACING_DENY_MESSAGE
    assert resp.headers.get(_CORR_HEADER) == data["correlation_id"]


def _authorize(client: TestClient, token: str, alias: str) -> Response:
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
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=600)
    finally:
        reader.close()
    out: list[dict[str, Any]] = []
    for _sid, fields in entries:
        rec: Any = json.loads(fields["record"])
        event = rec.get("event", {})
        if isinstance(event, dict) and event.get("admin_action") == action:
            out.append(event)
    return out


def _set_publishers(client: TestClient, idp: Any, namespaces: list[str]) -> Response:
    return client.put(
        "/v1/admin/extensions/publishers",
        json={"schema": PUBLISHERS_SCHEMA, "namespaces": namespaces},
        headers=_bh(_reviewer(idp)),
    )


# ===========================================================================
# Manifest schema / projection unit tests.
# ===========================================================================


def test_manifest_projects_cloud_rest_and_derives_target() -> None:
    """The manifest projects to cloud_rest + derives its target from the single remote."""
    m = parse_registry_manifest(_registry_manifest())
    assert m.transport == "cloud_rest"
    assert m.target == "https://mcp.acme.example/mcp"
    assert m.publisher == "io.github.acme"
    assert m.alias == "skill_reg_weather"
    assert publisher_namespace(m.server.name) == "io.github.acme"
    # Provenance is exposed but is an untrusted recorded field.
    assert m.provenance() is not None


def test_local_only_server_json_refused_no_remote_target() -> None:
    """A server.json with only local packages / no remote https transport is REFUSED.

    A local/stdio MCP server can never become a governed cloud_rest alias — the projection
    can never emit a non-cloud_rest transport, so parse refuses at the source.
    """
    with pytest.raises(ExtensionManifestError):
        parse_registry_manifest(
            _registry_manifest(server=_server_json(with_remote=False, extra_packages=True))
        )
    # A non-https remote is likewise refused (must be https).
    with pytest.raises(ExtensionManifestError):
        parse_registry_manifest(
            _registry_manifest(server=_server_json(url="http://mcp.acme.example/mcp"))
        )
    # A stdio/local remote type is refused (only sse/streamable-http qualify).
    with pytest.raises(ExtensionManifestError):
        parse_registry_manifest(
            _registry_manifest(server=_server_json(remote_type="stdio"))
        )


def test_sha256_self_pin_mismatch_refused_at_parse() -> None:
    """A manifest whose declared sha256 disagrees with its content is refused at parse."""
    bad = _registry_manifest(fix_pin=False)
    bad["sha256"] = "a" * 64  # valid hex, wrong digest.
    with pytest.raises(ExtensionManifestError):
        parse_registry_manifest(bad)


def test_identity_shaped_fields_refused() -> None:
    """Identity-shaped alias OR a folded-identity server namespace is a hard deny at parse."""
    with pytest.raises(ExtensionManifestError):
        parse_registry_manifest(_registry_manifest(alias="role"))
    # A server name whose namespace folds to a forbidden identity key.
    with pytest.raises(ExtensionManifestError):
        parse_registry_manifest(
            _registry_manifest(server=_server_json(name="role/weather"))
        )


def test_meta_provenance_charset_scrubbed_and_bounded() -> None:
    """The ``_meta`` provenance envelope is recorded to WORM + shown to the reviewer, so —
    like every other human-readable manifest field — an unsafe string (bidi/format mark) in a
    ``_meta`` key or value, and an oversized ``_meta``, are refused at parse. Closes the one
    surface that previously escaped the reject_unsafe_string + size discipline."""
    from interfaces import MAX_REGISTRY_META_BYTES

    # A bidi/format mark hidden in a _meta VALUE (U+200E LEFT-TO-RIGHT MARK).
    with pytest.raises(ExtensionManifestError):
        parse_registry_manifest(
            _registry_manifest(server=_server_json(meta={"prov": {"id": "srv‎abc"}}))
        )
    # A bidi/format mark hidden in a nested _meta KEY.
    with pytest.raises(ExtensionManifestError):
        parse_registry_manifest(
            _registry_manifest(server=_server_json(meta={"pro‎v": {"id": "srv"}}))
        )
    # An oversized _meta envelope (a giant provenance blob smuggled toward the audit log).
    with pytest.raises(ExtensionManifestError):
        parse_registry_manifest(
            _registry_manifest(
                server=_server_json(meta={"blob": "x" * (MAX_REGISTRY_META_BYTES + 1)})
            )
        )
    # A clean, in-bounds _meta still parses (no regression to the happy path).
    parse_registry_manifest(
        _registry_manifest(server=_server_json(meta={"official": {"id": "srv-ok"}}))
    )


# ===========================================================================
# Verified-publisher allow-list model + store.
# ===========================================================================


def test_publisher_allowlist_validate_rejects_bad_shapes() -> None:
    """Strict validation: schema tag, over-cap, identity-shaped, and duplicate namespaces."""
    ok = VerifiedPublisherStore.validate(
        {"schema": PUBLISHERS_SCHEMA, "namespaces": ["io.github.acme", "com.example"]}
    )
    assert ok["namespaces"] == ["io.github.acme", "com.example"]
    with pytest.raises(PublisherAllowListError):
        VerifiedPublisherStore.validate({"schema": "wrong", "namespaces": []})
    with pytest.raises(PublisherAllowListError):
        VerifiedPublisherStore.validate(
            {"schema": PUBLISHERS_SCHEMA, "namespaces": ["role"]}
        )
    with pytest.raises(PublisherAllowListError):
        VerifiedPublisherStore.validate(
            {"schema": PUBLISHERS_SCHEMA, "namespaces": ["dup", "dup"]}
        )
    with pytest.raises(PublisherAllowListError):
        VerifiedPublisherStore.validate(
            {
                "schema": PUBLISHERS_SCHEMA,
                "namespaces": [f"ns{i}" for i in range(MAX_VERIFIED_PUBLISHERS + 1)],
            }
        )


def test_publisher_store_load_fail_closed_on_absent() -> None:
    """``load`` (approve/boot read) raises on an ABSENT doc — fail-closed, not empty pass."""

    async def _inner() -> tuple[bool, bool]:
        r = aioredis.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
        store = VerifiedPublisherStore(r)
        try:
            await r.delete(VerifiedPublisherStore._key("tenant-absent"))
            absent_raises = False
            try:
                await store.load("tenant-absent")
            except PublisherStoreError:
                absent_raises = True
            # is_verified over an absent doc is False (fail-closed).
            not_verified = await store.is_verified("tenant-absent", "io.github.acme")
            return absent_raises, not_verified
        finally:
            await r.aclose()

    absent_raises, not_verified = asyncio.run(_inner())
    assert absent_raises is True
    assert not_verified is False


# ===========================================================================
# End-to-end flow through the REAL app.
# ===========================================================================


def test_happy_path_submit_allowlist_approve_resolves(
    client: TestClient, idp: Any
) -> None:
    """Submit → allow-list the publisher → approve → the overlay resolves the alias.

    Submit lands PENDING with a WORM ``extension_submit(kind='registry_server')``; approval
    (after the publisher namespace is allow-listed) emits WORM ``extension_approve`` BEFORE
    apply and the minted skill resolves through the REAL /v1/authorize pipeline.
    """
    alias = "skill_reg_happy"
    server = _server_json(name="io.github.acme/happy", url="https://mcp.acme.example/happy")
    manifest = _registry_manifest(alias=alias, manifest_id="reg-happy", server=server)

    sid = _json(_submit(client, idp.mint(agent_id="agent-contrib-r1"), manifest))[
        "submission_id"
    ]
    submits = _worm_admin_actions("extension_submit")
    assert any(
        e.get("kind") == "registry_server" and e.get("alias") == alias for e in submits
    )

    # Unknown before approval.
    _assert_opaque(_authorize(client, idp.mint(), alias))

    # Approve WITHOUT allow-listing the publisher → fail-closed refuse.
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp)))
    )
    assert not any(
        e.get("alias") == alias for e in _worm_admin_actions("extension_approve")
    ), "no approve WORM before the publisher is verified"

    # Allow-list the publisher namespace, then approve succeeds.
    assert _set_publishers(client, idp, ["io.github.acme"]).status_code == 200
    approve = client.post(
        f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp))
    )
    assert approve.status_code == 200, approve.text
    assert _json(approve)["approved"] == alias

    approvals = [e for e in _worm_admin_actions("extension_approve") if e.get("alias") == alias]
    assert approvals, "approval must be WORM-recorded"
    assert approvals[0]["kind"] == "registry_server"
    assert approvals[0]["publisher_namespace"] == "io.github.acme"
    assert approvals[0]["manifest_sha256"] == manifest["sha256"]
    # Provenance is RECORDED in the approve record (recorded-not-trusted).
    assert approvals[0].get("server_provenance") is not None

    # The overlay now resolves the alias through the REAL pipeline.
    ok = _authorize(client, idp.mint(), alias)
    assert ok.status_code == 200, ok.text
    # OPACITY: the target URL never crosses the agent wire.
    assert "https://mcp.acme.example/happy" not in ok.text


def test_provenance_recorded_not_trusted(client: TestClient, idp: Any) -> None:
    """A forged/absent server provenance does NOT change the verdict — it rides the allow-list.

    The verdict is identical to the happy path when the publisher is allow-listed, regardless
    of what (if anything) the untrusted ``_meta`` provenance claims.
    """
    alias = "skill_reg_forged_prov"
    server = _server_json(
        name="io.github.acme/forged",
        url="https://mcp.acme.example/forged",
        meta={"io.modelcontextprotocol.registry/official": {"id": "TOTALLY-FORGED", "is_latest": True}},
    )
    manifest = _registry_manifest(alias=alias, manifest_id="reg-forged", server=server)
    sid = _json(_submit(client, idp.mint(agent_id="agent-contrib-r2"), manifest))[
        "submission_id"
    ]
    assert _set_publishers(client, idp, ["io.github.acme"]).status_code == 200
    approve = client.post(
        f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp))
    )
    assert approve.status_code == 200, approve.text
    # Verdict is ALLOW purely because the publisher is allow-listed; forged provenance is inert.
    assert _authorize(client, idp.mint(), alias).status_code == 200


def test_additive_only_repoint_refused(client: TestClient, idp: Any) -> None:
    """A registry submission whose derived alias already resolves is refused at approve."""
    server = _server_json(name="io.github.acme/repoint")
    manifest = _registry_manifest(
        alias=_EXISTING_ALIAS, manifest_id="reg-repoint", server=server
    )
    sid = _json(_submit(client, idp.mint(agent_id="agent-contrib-r3"), manifest))[
        "submission_id"
    ]
    assert _set_publishers(client, idp, ["io.github.acme"]).status_code == 200
    _assert_opaque(
        client.post(f"/v1/admin/extensions/{sid}/approve", headers=_bh(_reviewer(idp)))
    )
    # The config alias is untouched.
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


def test_privileged_transport_refused_at_submit(client: TestClient, idp: Any) -> None:
    """A local/stdio-only server.json (no remote https) is refused at submit (403)."""
    manifest = _registry_manifest(
        alias="skill_reg_local",
        manifest_id="reg-local",
        server=_server_json(with_remote=False, extra_packages=True),
    )
    _assert_opaque(_submit(client, idp.mint(agent_id="agent-contrib-r4"), manifest))


def test_restricted_auto_refused(client: TestClient, idp: Any) -> None:
    """``restricted``+``auto`` fails ``_overlay_skill_invalid`` at submit (and approve)."""
    manifest = _registry_manifest(
        alias="skill_reg_restricted_auto",
        classification="restricted",
        risk_tier="auto",
        manifest_id="reg-ra",
        server=_server_json(name="io.github.acme/restricted"),
    )
    _assert_opaque(_submit(client, idp.mint(agent_id="agent-contrib-r5"), manifest))
    # restricted+pin_required is accepted at submit.
    good = _registry_manifest(
        alias="skill_reg_restricted_pin",
        classification="restricted",
        risk_tier="pin_required",
        manifest_id="reg-rp",
        server=_server_json(name="io.github.acme/restricted2"),
    )
    assert _submit(client, idp.mint(agent_id="agent-contrib-r5"), good).status_code == 200


def test_identity_shaped_manifest_refused_at_submit(client: TestClient, idp: Any) -> None:
    """An identity-shaped alias / server namespace is refused at submit (403)."""
    _assert_opaque(
        _submit(
            client,
            idp.mint(agent_id="agent-contrib-r6"),
            _registry_manifest(alias="role", manifest_id="reg-idkey"),
        )
    )
    _assert_opaque(
        _submit(
            client,
            idp.mint(agent_id="agent-contrib-r6"),
            _registry_manifest(
                alias="skill_reg_okalias",
                manifest_id="reg-idkey2",
                server=_server_json(name="tenant_id/weather"),
            ),
        )
    )


def test_pending_list_projection_and_verified_flag(client: TestClient, idp: Any) -> None:
    """The reviewer pending list projects registry rows with the live ``verified`` flag."""
    alias = "skill_reg_listed"
    server = _server_json(name="io.github.listco/listed", url="https://mcp.listco.example/x")
    manifest = _registry_manifest(alias=alias, manifest_id="reg-list", server=server)
    sid = _json(_submit(client, idp.mint(agent_id="agent-contrib-r7"), manifest))[
        "submission_id"
    ]
    # Not yet allow-listed → verified False.
    listing = client.get("/v1/admin/extensions/pending", headers=_bh(_reviewer(idp)))
    rows = {r["submission_id"]: r for r in _json(listing)["pending"]}
    assert sid in rows
    row = rows[sid]
    assert row["kind"] == "registry_server"
    assert row["alias"] == alias
    assert row["publisher_namespace"] == "io.github.listco"
    assert row["transport"] == "cloud_rest"
    assert row["target"] == "https://mcp.listco.example/x"  # reviewer-only surface.
    assert row["verified"] is False
    assert row["conflicts_existing_alias"] is False

    # Allow-list it → verified flips True.
    assert _set_publishers(client, idp, ["io.github.acme", "io.github.listco"]).status_code == 200
    listing2 = client.get("/v1/admin/extensions/pending", headers=_bh(_reviewer(idp)))
    rows2 = {r["submission_id"]: r for r in _json(listing2)["pending"]}
    assert rows2[sid]["verified"] is True


def test_publishers_admin_surface_gating_and_worm(client: TestClient, idp: Any) -> None:
    """GET/PUT publishers require CAP_CATALOG_REVIEWER; PUT emits WORM before the write."""
    plain = idp.mint(agent_id="agent-plain")
    dir_admin = idp.mint(agent_id="agent-diradmin", capabilities=[CAP_DIRECTORY_ADMIN])
    _assert_opaque(client.get("/v1/admin/extensions/publishers", headers=_bh(plain)))
    _assert_opaque(client.get("/v1/admin/extensions/publishers", headers=_bh(dir_admin)))
    _assert_opaque(
        client.put(
            "/v1/admin/extensions/publishers",
            json={"schema": PUBLISHERS_SCHEMA, "namespaces": ["io.github.acme"]},
            headers=_bh(plain),
        )
    )
    # A malformed doc is an opaque deny (over-cap / identity-shaped).
    _assert_opaque(
        client.put(
            "/v1/admin/extensions/publishers",
            json={"schema": PUBLISHERS_SCHEMA, "namespaces": ["role"]},
            headers=_bh(_reviewer(idp)),
        )
    )
    # A valid PUT succeeds and is WORM-recorded (emit-before-mutate).
    assert _set_publishers(client, idp, ["io.github.putco"]).status_code == 200
    puts = _worm_admin_actions("registry_publishers_put")
    assert puts and puts[0]["publisher_count"] >= 1
    got = _json(
        client.get("/v1/admin/extensions/publishers", headers=_bh(_reviewer(idp)))
    )["publishers"]
    assert "io.github.putco" in got["namespaces"]


# ---------------------------------------------------------------------------
# Rug-pull: the boot-load hash-pin + publisher re-verify (``_community_pin_valid``).
# ---------------------------------------------------------------------------


def test_rugpull_and_publisher_delist_refuse_boot_load(idp: Any, monkeypatch: Any) -> None:
    """Boot re-verify refuses a tampered registry row AND a de-listed publisher.

    ``_community_pin_valid`` (kind-aware) returns True for an intact approved registry row
    whose publisher is still allow-listed, and False after (a) a manifest edit, (b) an
    overlay-field repoint, and (c) the publisher being de-listed (fail-closed trust rail).
    """
    tenant = "tenant-reg-rug"
    alias = "skill_reg_rug"
    server = _server_json(name="io.github.acme/rug", url="https://mcp.acme.example/rug")
    manifest = parse_registry_manifest(
        _registry_manifest(alias=alias, manifest_id="reg-rug", server=server)
    )
    fields = app_main._community_overlay_fields(
        manifest.target, manifest.risk_tier, manifest.classification, manifest.sha256
    )
    entry = app_main._overlay_entry(alias, fields)
    assert entry is not None

    approved_record: dict[str, Any] = {
        "manifest": manifest.canonical_dict(),
        "sha256": manifest.sha256,
        "publisher_namespace": manifest.publisher,
        "reviewer_agent_id": "agent-reviewer",
        "submitter_agent_id": "agent-contrib",
        "approved_at": datetime.now(timezone.utc).isoformat(),
    }

    async def _inner() -> tuple[bool, bool, bool, bool]:
        r = aioredis.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
        sub_store = ExtensionSubmissionStore(r)
        pub_store = VerifiedPublisherStore(r)
        monkeypatch.setattr(_components, "extension_submissions", sub_store)
        monkeypatch.setattr(_components, "registry_publishers", pub_store)
        try:
            # Publisher allow-listed + intact record → the re-verify PASSES.
            await pub_store.put(
                tenant,
                VerifiedPublisherStore.validate(
                    {"schema": PUBLISHERS_SCHEMA, "namespaces": [manifest.publisher]}
                ),
            )
            await sub_store.add_approved(tenant, alias, approved_record)
            intact = await app_main._community_pin_valid(tenant, alias, entry, fields)

            # Rug-pull #1: naive manifest edit (embedded sha256 unchanged) → self-pin fails.
            naive = dict(approved_record)
            naive_manifest = dict(manifest.canonical_dict())
            naive_server = dict(naive_manifest["server"])
            naive_server["remotes"] = [
                {"type": "streamable-http", "url": "https://mcp.evil.example/exfil"}
            ]
            naive_manifest["server"] = naive_server
            naive["manifest"] = naive_manifest
            await sub_store.add_approved(tenant, alias, naive)
            after_naive = await app_main._community_pin_valid(tenant, alias, entry, fields)

            # Rug-pull #2: the OVERLAY row's target was repointed (approved manifest intact).
            await sub_store.add_approved(tenant, alias, approved_record)
            tampered_fields = dict(fields)
            tampered_fields["target"] = "https://mcp.evil.example/exfil"
            tampered_entry = app_main._overlay_entry(alias, tampered_fields)
            assert tampered_entry is not None
            after_overlay = await app_main._community_pin_valid(
                tenant, alias, tampered_entry, tampered_fields
            )

            # De-list the publisher (record + overlay intact) → boot re-verify refuses.
            await sub_store.add_approved(tenant, alias, approved_record)
            await pub_store.put(
                tenant,
                VerifiedPublisherStore.validate(
                    {"schema": PUBLISHERS_SCHEMA, "namespaces": ["io.github.other"]}
                ),
            )
            after_delist = await app_main._community_pin_valid(tenant, alias, entry, fields)
            return intact, after_naive, after_overlay, after_delist
        finally:
            await r.aclose()

    intact, after_naive, after_overlay, after_delist = asyncio.run(_inner())
    assert intact is True, "an intact allow-listed registry row must load"
    assert after_naive is False, "a manifest edit must be refused (self-pin)"
    assert after_overlay is False, "an overlay-field repoint must be refused (cross-check)"
    assert after_delist is False, "a de-listed publisher must fail the boot re-verify"


def test_app_import_does_not_require_celpy() -> None:
    """Importing the app + registry modules never pulls the deferred CEL runtime."""
    assert "celpy" not in sys.modules
    import importlib

    importlib.import_module("services.registry_publishers")
    importlib.import_module("services.extension_manifest")
    assert "celpy" not in sys.modules


if __name__ == "__main__":  # pragma: no cover - direct-run convenience.
    sys.exit(pytest.main([__file__, "-v"]))
