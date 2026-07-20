"""
MCPIP V2 — mcpip-sdk (Python) contract suite against the REAL in-process gateway.

    ◐  "One SDK, the same choke point."

Drives the shipped ``sdk/python`` client (``mcpip_sdk``) end to end through
``httpx.ASGITransport(app=app.main.app)`` — no sockets, no mocks, the actual
FastAPI app with its lifespan (Redis rebind + epoch daemon) running on one
dedicated event loop, exactly as ``TestClient`` would run it. A tiny sync
adapter (:class:`_LoopASGITransport`) bridges the SDK's synchronous httpx
client onto that loop so every request the SDK issues executes against the
same loop the lifespan bound Redis to.

Covers the mission surface: happy authorize, opaque deny (``MCPIPDenied``
carries a correlation id and nothing else), the full PIN ceremony (stage →
sandbox authenticator OTP → complete → replay-deny), catalog, the JSON-RPC
``/v1/mcp`` edge, admin register+disable roundtrip, vault put/list/delete,
the live decisions feed (correlating the agent's opaque deny with the
operator's concrete reason), the canary/quarantine rosters, and the audit
verify + per-event inclusion-proof pair.

Mirrors ``test_authorize_api``'s namespaced sandbox env (same Redis db /5 on
:63790, same WORM path) so import order across suites is immaterial; the
backing state is reset before the lifespan boots and again after teardown.
"""

from __future__ import annotations

import os
import sys

# Make the repo root AND the SDK's src layout importable when this file runs
# directly or under pytest — the SDK is a separate distribution (sdk/python),
# deliberately not installed into the gateway's environment.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "sdk", "python", "src"))

# --- Namespaced sandbox environment MUST be set before importing app.main, whose
#     composition root reads the (lru_cached) settings once, at import. --------------
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import asyncio
import json
from typing import Any, Iterator

import httpx
import pytest
import redis as redis_sync

from interfaces import CAP_DIRECTORY_ADMIN, QUARANTINE_TTL_SECONDS

from app.main import _components, app

from mcpip_sdk import (
    AGENT_FACING_DENY_MESSAGE,
    Allowed,
    DeploymentStats,
    MCPIPAdminClient,
    OperatorUser,
    OperatorUserPage,
    MCPIPDenied,
    SandboxClient,
    Staged,
)

# Aliases from the tenant-acme sandbox catalog (same rows as the API suite).
_AUTO_ALIAS = "skill_spend_summary"
_PIN_ALIAS = "skill_payroll_run"
_CANARY_ALIAS = "skill_export_all_credentials"  # a seeded deception tripwire row.
_BASE_URL = "http://gateway.sdk.test"  # arbitrary — ASGITransport never resolves it.
_ADMIN_ID = "agent-sdk-admin"


# ---------------------------------------------------------------------------
# In-process gateway plumbing: one loop, one lifespan, one ASGI transport.
# ---------------------------------------------------------------------------


class _LoopASGITransport(httpx.BaseTransport):
    """
    Sync httpx transport that dispatches through ``httpx.ASGITransport`` on ONE
    dedicated event loop — the loop the app lifespan ran on, so the handlers'
    Redis clients are bound consistently. The async response body is fully
    materialized before re-wrapping, so the SDK's sync client consumes it
    exactly like a socket response.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop, asgi_app: Any) -> None:
        self._loop = loop
        self._asgi = httpx.ASGITransport(app=asgi_app)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        async def _dispatch() -> tuple[int, list[tuple[bytes, bytes]], bytes]:
            response = await self._asgi.handle_async_request(request)
            body = await response.aread()
            return response.status_code, list(response.headers.raw), body

        status, headers, body = self._loop.run_until_complete(_dispatch())
        return httpx.Response(status_code=status, headers=headers, content=body)


def _reset_backing_state() -> None:
    """Flush the namespaced db and drop the on-disk WORM/anchor artifacts, so a
    fresh chain never disagrees with a stale anchor witness (and vice versa)."""
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
def gateway() -> Iterator[httpx.BaseTransport]:
    """The REAL gateway app behind an in-process transport, lifespan running."""
    _reset_backing_state()
    loop = asyncio.new_event_loop()
    lifespan = app.router.lifespan_context(app)
    loop.run_until_complete(lifespan.__aenter__())
    try:
        yield _LoopASGITransport(loop, app)
    finally:
        loop.run_until_complete(lifespan.__aexit__(None, None, None))
        loop.close()
        _reset_backing_state()


@pytest.fixture(scope="module")
def agent(gateway: httpx.BaseTransport) -> Iterator[SandboxClient]:
    """An agent client whose token provider proactively re-mints dev tokens."""
    with SandboxClient(base_url=_BASE_URL, transport=gateway) as client:
        client.set_token(lambda: client.dev_token())  # default demo principal.
        yield client


@pytest.fixture(scope="module")
def admin(gateway: httpx.BaseTransport) -> Iterator[MCPIPAdminClient]:
    """A control-plane client holding CAP_DIRECTORY_ADMIN via a callable provider."""
    with SandboxClient(base_url=_BASE_URL, transport=gateway) as minter:
        with MCPIPAdminClient(
            base_url=_BASE_URL,
            token=lambda: minter.dev_token(
                agent_id=_ADMIN_ID, capabilities=[CAP_DIRECTORY_ADMIN]
            ),
            transport=gateway,
        ) as client:
            yield client


# ---------------------------------------------------------------------------
# Agent surface.
# ---------------------------------------------------------------------------


def test_health_and_ready(agent: SandboxClient) -> None:
    """Liveness and readiness parse into typed models; Redis is up for the suite."""
    health = agent.health()
    assert health.status == "live"
    assert health.version  # the VERSION file value, whatever it currently is.
    readiness = agent.ready()
    assert readiness.ready is True
    assert readiness.redis == "up"


def test_authorize_happy_path(agent: SandboxClient) -> None:
    """An AUTO alias authorizes to an Allowed receipt; the class is a transport
    CLASS, never a target (zero topology leakage holds through the SDK)."""
    outcome = agent.authorize(
        _AUTO_ALIAS, {"period": "2026-Q2"}, source_format="openai_tool_call"
    )
    assert isinstance(outcome, Allowed)
    assert outcome.decision == "allow"
    assert outcome.status == "committed"
    assert outcome.transaction_ref.startswith("txn_")
    assert outcome.executed_target_class == "cloud_rest"
    assert "." not in outcome.executed_target_class
    assert outcome.correlation_id
    assert outcome.worm_sequence >= 1
    assert outcome.vended_credential is None  # cloud_iam only.


def test_denial_is_opaque(agent: SandboxClient) -> None:
    """A deny raises MCPIPDenied carrying ONLY the correlation id — the SDK
    surfaces exactly what crossed the wire, no reason, structurally."""
    with pytest.raises(MCPIPDenied) as excinfo:
        agent.authorize("skill_sdk_does_not_exist", {})
    denied = excinfo.value
    assert denied.correlation_id
    assert denied.http_status == 403
    assert str(denied) == AGENT_FACING_DENY_MESSAGE
    # Opacity is structural: the exception has no reason-shaped attribute at all.
    assert not hasattr(denied, "deny_reason")
    assert not hasattr(denied, "reason")


def test_pin_ceremony_stage_otp_complete(agent: SandboxClient) -> None:
    """The full step-up: 202 Staged → sandbox authenticator OTP → complete →
    Allowed; replaying the spent challenge is an opaque deny."""
    staged = agent.authorize(_PIN_ALIAS, {"run_id": "SDK-1", "cycle": "monthly"})
    assert isinstance(staged, Staged)
    assert staged.risk_tier == "pin_required"
    assert staged.challenge_id
    assert staged.action_required
    assert staged.expires_in == 300  # the protocol's fixed lock TTL.

    otp = agent.authenticator_code(staged.challenge_id)
    assert len(otp) == 6 and otp.isdigit()

    receipt = agent.complete(staged, otp)
    assert receipt.decision == "allow"
    assert receipt.transaction_ref.startswith("txn_")

    # The lock is one-time: a replay of the SPENT challenge is an opaque deny.
    with pytest.raises(MCPIPDenied) as excinfo:
        agent.complete(staged, otp)
    assert excinfo.value.correlation_id


def test_catalog_lists_entitled_metadata(agent: SandboxClient) -> None:
    """The catalog returns typed metadata rows for entitled aliases — including
    the canary bait (visible by design; its tripwire flag never crosses)."""
    items = agent.catalog()
    by_alias = {item.alias: item for item in items}
    assert _AUTO_ALIAS in by_alias
    assert by_alias[_AUTO_ALIAS].risk_tier == "auto"
    assert by_alias[_PIN_ALIAS].risk_tier == "pin_required"
    assert _CANARY_ALIAS in by_alias  # bait is enumerable, indistinguishable.
    for item in items:
        assert item.transport_class  # coarse class only — never a dotted target.
        assert "." not in item.transport_class


def test_mcp_jsonrpc_edge(agent: SandboxClient) -> None:
    """mcp_call speaks real JSON-RPC 2.0: initialize (no auth), notification
    (202/None), tools/list, tools/call receipt, and the -32000 opaque deny."""
    init = agent.mcp_call("initialize")
    assert isinstance(init, dict)
    assert init["protocolVersion"] == "2025-06-18"
    assert init["serverInfo"]["name"] == "mcpip"

    assert agent.mcp_call("notifications/initialized") is None

    listing = agent.mcp_call("tools/list")
    names = {tool["name"] for tool in listing["tools"]}
    assert _AUTO_ALIAS in names

    result = agent.mcp_call(
        "tools/call", {"name": _AUTO_ALIAS, "arguments": {"period": "mcp"}}
    )
    assert result["isError"] is False
    receipt = json.loads(result["content"][0]["text"])
    assert receipt["decision"] == "allow"

    # A deny on this edge is HTTP 200 + JSON-RPC -32000 — same typed exception.
    with pytest.raises(MCPIPDenied) as excinfo:
        agent.mcp_call("tools/call", {"name": "skill_sdk_missing", "arguments": {}})
    assert excinfo.value.correlation_id


def test_version_and_license(agent: SandboxClient) -> None:
    """JWT-gated version/license reads parse into typed views (sandbox truths:
    redeploy-only updates, unlicensed)."""
    version = agent.version()
    assert version.running
    assert version.update_policy == "redeploy"
    assert version.channel == "sandbox"
    license_info = agent.license()
    assert license_info.licensed is False
    assert license_info.customer is None  # nothing fabricated when unlicensed.


# ---------------------------------------------------------------------------
# Admin surface.
# ---------------------------------------------------------------------------


def test_admin_register_disable_roundtrip(
    agent: SandboxClient, admin: MCPIPAdminClient
) -> None:
    """register → authorizable → disable → opaque deny → enable → deregister,
    all through the SDK against the real overlay + kill-switch stores."""
    alias = "skill_sdk_suite_probe"

    with pytest.raises(MCPIPDenied):
        agent.authorize(alias, {})  # unknown before registration.

    assert admin.skills_register(alias, "rest.sdk.suite.probe") == alias
    outcome = agent.authorize(alias, {})
    assert isinstance(outcome, Allowed)
    assert alias in [entry.alias for entry in admin.skills_registered()]

    assert admin.skills_disable(alias) == alias
    with pytest.raises(MCPIPDenied):
        agent.authorize(alias, {})
    assert alias in admin.skills_disabled()

    assert admin.skills_enable(alias) is True
    assert isinstance(agent.authorize(alias, {}), Allowed)

    assert admin.skills_deregister(alias) is True
    with pytest.raises(MCPIPDenied):
        agent.authorize(alias, {})
    assert alias not in [entry.alias for entry in admin.skills_registered()]


def test_vault_secret_lifecycle(admin: MCPIPAdminClient) -> None:
    """put → list → delete; the vault answers metadata + fingerprint only (the
    typed model cannot even represent a value — write-only by construction)."""
    listing = admin.vault_secrets_list()
    assert listing.vault_enabled is True  # sandbox auto-provisions a dev key.

    secret = admin.vault_secrets_put(
        "sdk-broker-aws",
        "aws",
        {"access_key_id": "AKIA_SDK_TEST", "secret_access_key": "sdk-secret-value"},
        description="SDK suite broker credential",
    )
    assert secret.secret_id == "sdk-broker-aws"
    assert secret.vendor == "aws"
    assert len(secret.fingerprint) == 12  # keyed tag, not the material.
    assert secret.fingerprint != "sdk-secret-value"

    ids = [s.secret_id for s in admin.vault_secrets_list().secrets]
    assert "sdk-broker-aws" in ids

    assert admin.vault_secrets_delete("sdk-broker-aws") is True
    assert "sdk-broker-aws" not in [
        s.secret_id for s in admin.vault_secrets_list().secrets
    ]


def test_decisions_feed_correlates_opaque_denials(
    agent: SandboxClient, admin: MCPIPAdminClient
) -> None:
    """The operator feed carries the concrete reason for the very deny the
    agent saw opaquely — joined by correlation id, with audit handles."""
    allowed = agent.authorize(_AUTO_ALIAS, {"period": "feed"})
    assert isinstance(allowed, Allowed)
    with pytest.raises(MCPIPDenied) as excinfo:
        agent.authorize("skill_sdk_feed_missing", {})
    denied_corr = excinfo.value.correlation_id

    rows = admin.decisions_recent(limit=200)
    assert rows, "the feed must surface this module's real traffic"
    by_corr = {row.correlation_id: row for row in rows}

    allow_row = by_corr[allowed.correlation_id]
    assert allow_row.decision == "allow"
    assert allow_row.alias == _AUTO_ALIAS
    assert allow_row.deny_reason is None
    assert allow_row.source_format == "raw_mcp"  # the SDK's default envelope.
    assert allow_row.tenant_id == "tenant-acme"
    assert allow_row.worm_sequence >= 1
    assert allow_row.event_id  # the /v1/audit/proof handle.

    deny_row = by_corr[denied_corr]
    assert deny_row.decision == "deny"
    assert deny_row.deny_reason == "unknown_alias"  # operator sees the reason…
    assert deny_row.transaction_ref is None  # …and no transaction ever existed.


def test_admin_stats_is_real_and_honest(
    agent: SandboxClient, admin: MCPIPAdminClient
) -> None:
    """``MCPIPAdminClient.stats()`` returns the caller's OWN tenant's REAL live
    numbers — a governed-agent cardinality + real decision totals + honest license
    and opt-in-telemetry posture. Never a fabricated client/number/"connected"
    state: this sandbox is air-gapped (the beacon is structurally disabled)."""
    allowed = agent.authorize(_AUTO_ALIAS, {"period": "stats"})
    assert isinstance(allowed, Allowed)

    stats = admin.stats()
    assert isinstance(stats, DeploymentStats)
    # Real aggregates: this module's traffic has flowed, so the counts are non-trivial
    # and the value metric (a HyperLogLog cardinality) has seen at least this agent.
    assert stats.version
    assert stats.governed_agent_identity_count >= 1
    assert stats.decisions.allow >= 1
    # Honest license posture — the sandbox boots unlicensed, never a fabricated tier.
    assert stats.license.licensed is False
    # Honest telemetry: a sandbox/air-gapped deployment NEVER phones home.
    assert stats.telemetry.status == "air-gap"
    assert stats.telemetry.air_gapped is True
    assert stats.telemetry.enabled is False
    assert stats.telemetry.last_sent is None


def test_admin_stats_requires_directory_admin(
    gateway: httpx.BaseTransport, agent: SandboxClient
) -> None:
    """The local live-stats read is CAP_DIRECTORY_ADMIN-gated — a plain principal
    token is the SAME opaque deny as everywhere else."""
    plain = MCPIPAdminClient(
        base_url=_BASE_URL, token=lambda: agent.dev_token(), transport=gateway
    )
    with pytest.raises(MCPIPDenied):
        plain.stats()


def test_operator_users_lifecycle(admin: MCPIPAdminClient) -> None:
    """The SDK mirrors the operator/team roster surface end-to-end: invite → list →
    update → remove, all through the REAL ``/v1/admin/users`` endpoints (WORM-audited
    server-side). The invite returns a real one-time reference token; the ``role`` is a
    management label. Additive-only — a duplicate invite is the opaque deny."""
    email = "sdk-teammate@example.com"
    invite = admin.users_invite(email, role="admin")
    assert invite.user.email == email
    assert invite.user.role == "admin"
    assert invite.user.status == "invited"
    assert isinstance(invite.invite_token, str) and len(invite.invite_token) > 20

    page = admin.users_list()
    assert isinstance(page, OperatorUserPage)
    assert any(u.email == email for u in page.users)
    assert page.count >= 1

    # Additive-only: re-inviting the same email is the SAME opaque deny (no repoint).
    with pytest.raises(MCPIPDenied):
        admin.users_invite(email)

    updated = admin.users_update(email, status="active")
    assert isinstance(updated, OperatorUser)
    assert updated.status == "active"

    assert admin.users_remove(email) is True
    assert admin.users_remove(email) is False  # idempotent


def test_operator_users_require_directory_admin(
    gateway: httpx.BaseTransport, agent: SandboxClient
) -> None:
    """The roster surface is CAP_DIRECTORY_ADMIN-gated — a plain principal is the same
    opaque deny on every verb."""
    plain = MCPIPAdminClient(
        base_url=_BASE_URL, token=lambda: agent.dev_token(), transport=gateway
    )
    with pytest.raises(MCPIPDenied):
        plain.users_list()
    with pytest.raises(MCPIPDenied):
        plain.users_invite("nope@example.com")


def test_canary_and_quarantine_rosters(
    gateway: httpx.BaseTransport, admin: MCPIPAdminClient
) -> None:
    """Tripping a decoy freezes the caller; both NEW rosters surface it: the
    canary list (admin-only reveal) and the TTL-bounded quarantine roster."""
    with SandboxClient(base_url=_BASE_URL, transport=gateway) as tripper:
        tripper.set_token(lambda: tripper.dev_token(agent_id="agent-sdk-canary"))
        with pytest.raises(MCPIPDenied) as tripped:
            tripper.authorize(_CANARY_ALIAS, {"scope": "all"})
        assert tripped.value.correlation_id
        # The same agent is now frozen: a benign AUTO skill denies opaquely too.
        with pytest.raises(MCPIPDenied):
            tripper.authorize(_AUTO_ALIAS, {"period": "post-trip"})

    roster = admin.quarantine()
    frozen = {entry.agent_id: entry for entry in roster}
    assert "agent-sdk-canary" in frozen
    assert 0 < frozen["agent-sdk-canary"].ttl_seconds <= QUARANTINE_TTL_SECONDS

    canaries = admin.canaries()
    assert _CANARY_ALIAS in [c.alias for c in canaries]
    for canary in canaries:
        assert canary.risk_tier in {"auto", "pin_required"}
        assert canary.classification


def test_audit_verify_and_inclusion_proof(
    agent: SandboxClient, admin: MCPIPAdminClient
) -> None:
    """SandboxClient audit surface: chain verify seals an epoch, then the feed's
    event_id resolves to a real Merkle inclusion proof for an SDK-driven call."""
    receipt = agent.authorize(_AUTO_ALIAS, {"period": "audit"})
    assert isinstance(receipt, Allowed)

    verify = agent.audit_verify()  # forces the epoch close (seals the event).
    assert verify.intact is True
    assert verify.first_bad_epoch is None

    rows = admin.decisions_recent(limit=200)
    row = next(r for r in rows if r.correlation_id == receipt.correlation_id)
    assert row.event_id is not None

    proof = agent.audit_proof(row.event_id)
    assert proof.event_id == row.event_id
    assert proof.merkle_root and proof.signature
    assert proof.proof is not None  # the (side, digest) path — possibly empty
    # for a single-leaf epoch, but always present and verifiable server-side.


# ---------------------------------------------------------------------------
# Compliance evidence (X1) + registry-governance publishers (X3) — the new
# operator surfaces, exercised through the REAL gateway (evidence, never a cert).
# ---------------------------------------------------------------------------


def test_compliance_evidence_bundle_is_real_and_honest(
    agent: SandboxClient, admin: MCPIPAdminClient
) -> None:
    """The bundle is assembled from REAL signed WORM state and NEVER asserts a
    certification: it carries the disclaimer, framework certification_notes, and
    'provides-evidence-for' clauses only — no cert/customer/pass field exists."""
    agent.authorize(_AUTO_ALIAS, {"period": "compliance"})
    agent.audit_verify()  # seal an epoch so the bundle binds a real header.

    bundle = admin.compliance_evidence()
    # Real signed commitments from the running gateway — a sealed epoch header
    # under the WORM key's public signing_key_id, with a fresh intact verdict.
    assert bundle.attestation.signing_key_id
    assert bundle.attestation.intact is True
    assert bundle.sealed is True and bundle.attestation.epoch is not None
    assert bundle.gateway_version
    assert bundle.control_mapping  # the static mapping is present.
    # EVIDENCE, NEVER a CERTIFICATION.
    assert "not a certification" in bundle.disclaimer.lower()
    frameworks = {f.framework for f in bundle.control_mapping}
    assert {"SOC 2", "DORA", "EU AI Act"} <= frameworks
    for fw in bundle.control_mapping:
        assert fw.certification_note
        for clause in fw.clauses:
            assert clause.coverage == "provides-evidence-for"


def test_compliance_evidence_requires_directory_admin(
    agent: SandboxClient, gateway: httpx.BaseTransport
) -> None:
    """A plain agent token cannot read the bundle — it commits to the GLOBAL WORM
    head, so directory-admin is required (opaque deny otherwise)."""
    plain = MCPIPAdminClient(
        base_url=_BASE_URL, token=lambda: agent.dev_token(), transport=gateway
    )
    with plain:
        with pytest.raises(MCPIPDenied):
            plain.compliance_evidence()


def test_verified_publishers_roundtrip(
    agent: SandboxClient, gateway: httpx.BaseTransport
) -> None:
    """The reviewer allow-list round-trips through the REAL endpoint; an honest
    empty document is returned before anything is pinned."""
    from interfaces import CAP_CATALOG_REVIEWER

    reviewer = MCPIPAdminClient(
        base_url=_BASE_URL,
        token=lambda: agent.dev_token(
            agent_id="agent-sdk-reviewer", capabilities=[CAP_CATALOG_REVIEWER]
        ),
        transport=gateway,
    )
    with reviewer:
        reviewer.verified_publishers_put(["io.github.acme", "com.example.tools"])
        listed = reviewer.verified_publishers_get()
        assert listed.schema == "mcpip-registry-publishers/1"
        assert set(listed.namespaces) == {"io.github.acme", "com.example.tools"}
        # Replace (not merge): a new set overwrites the old one.
        reviewer.verified_publishers_put(["io.github.acme"])
        assert reviewer.verified_publishers_get().namespaces == ("io.github.acme",)
