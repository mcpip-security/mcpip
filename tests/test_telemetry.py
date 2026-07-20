"""
MCPIP V2 — opt-in VENDOR telemetry: aggregate stats store + best-effort beacon.

    ◐ "Count the deployment, never the agent."

Covers the two cleanly-separated pieces of ``services/telemetry.py`` plus the local
``GET /v1/admin/stats`` read, all against the REAL sandbox gateway / a dedicated Redis db:

  * STORE level (dedicated db ``/12``, driven with ``asyncio.run``): the governed-agent
    HLL CARDINALITY counts distinct agents WITHOUT exposing ids; decision totals; the
    deployment-wide UNION aggregate; and the swallow-only best-effort discipline (a broken
    Redis never raises out of ``record_*``).
  * BEACON level: the CLOSED eight-field payload (no tenant/agent/alias/target/secret ever
    appears), a random once-generated persisted install-id, the hermetic
    (``trust_env=False`` + ``proxy=None`` + no-redirects) IP-pinned client, the fail-closed
    SSRF refusal of a loopback URL, the fail-closed half-config boot error, and the
    disabled/sandbox/air-gap "no beacon, no install identity" states.
  * APP level (sandbox ``/5`` — mirrors the adversarial API suite): ``/v1/admin/stats``
    returns the caller's OWN tenant's REAL counts + honest license/telemetry states, is
    ``CAP_DIRECTORY_ADMIN``-gated + opaque, and is tenant-scoped.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MUST match tests/test_authorize_api.py so the shared _components graph agrees on the
# Redis db + sandbox flag regardless of import order.
_TEST_REDIS_URL = "redis://localhost:63790/5"
_STORE_REDIS_URL = "redis://localhost:63790/12"  # isolated: store-level probes only.
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
import redis.asyncio as aioredis
from fastapi.testclient import TestClient
from httpx import Response

from core.metrics import TELEMETRY
from core.security import AGENT_FACING_DENY_MESSAGE
from core.version import get_version
from interfaces import CAP_DIRECTORY_ADMIN, CAP_FORENSIC_READ
from services.telemetry import (
    BEACON_PAYLOAD_FIELDS,
    TelemetryBeacon,
    TelemetryStats,
)

import app.main as appmain
from app.main import _build_telemetry_beacon, _components, app
from core.config import Settings
from main import _DemoIdP

_TENANT = "tenant-acme"
_AUTO_ALIAS = "skill_spend_summary"          # tenant-acme AUTO row.
_PIN_ALIAS = "skill_wire_transfer"           # tenant-acme PIN_REQUIRED (cloud_rest) row.


# ---------------------------------------------------------------------------
# asyncio.run harness (store level, isolated db /12).
# ---------------------------------------------------------------------------


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


async def _fresh_stats() -> tuple[Any, TelemetryStats]:
    """A TelemetryStats over a flushed dedicated db."""
    redis_client: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
        _STORE_REDIS_URL, decode_responses=True
    )
    await redis_client.flushdb()
    return redis_client, TelemetryStats(redis_client)


class _BrokenRedis:
    """A Redis stand-in whose every op raises — proves record_* swallows fail-closed."""

    async def pfadd(self, *_a: Any, **_k: Any) -> int:
        raise ConnectionError("redis is down")

    async def incr(self, *_a: Any, **_k: Any) -> int:
        raise ConnectionError("redis is down")


def _metric(event: str) -> float:
    """Current value of mcpip_telemetry_total{event=...} (0.0 if never touched)."""
    value = TELEMETRY.labels(event)._value.get()
    return float(value)


# ---------------------------------------------------------------------------
# 1) Cardinality counts distinct agents WITHOUT exposing the ids.
# ---------------------------------------------------------------------------


def test_cardinality_counts_distinct_agents_not_calls() -> None:
    """
    record_agent the SAME id N times and M distinct ids → PFCOUNT ≈ M (not N, not N*M),
    and the HLL key holds NO readable member set — only the aggregate integer is retrievable.
    """
    async def scenario() -> None:
        redis_client, stats = await _fresh_stats()
        try:
            # 50 records of the SAME agent, then 9 more distinct agents (10 distinct total).
            for _ in range(50):
                await stats.record_agent(_TENANT, "agent-repeat")
            for i in range(9):
                await stats.record_agent(_TENANT, f"agent-{i}")

            count, _decisions = await stats.read_tenant(_TENANT)
            # HLL is approximate but exact for such a tiny set.
            assert count == 10, count

            # The key is a Redis STRING (HLL registers), NOT a set: a set read raises
            # WRONGTYPE, and the raw registers never contain a plaintext agent id (the raw
            # HLL bytes are not even valid UTF-8 — read via a non-decoding client).
            key = TelemetryStats._agents_key(_TENANT)
            assert (await redis_client.type(key)) == "string"
            with pytest.raises(redis_sync.exceptions.ResponseError):
                await redis_client.smembers(key)
            raw_client: Any = redis_sync.Redis.from_url(_STORE_REDIS_URL, decode_responses=False)
            try:
                raw = raw_client.get(key)
            finally:
                raw_client.close()
            assert b"agent-repeat" not in raw
            assert b"agent-0" not in raw
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# 2) Decision totals + honest empty state.
# ---------------------------------------------------------------------------


def test_record_decision_and_read_tenant_totals() -> None:
    """record_decision INCRs the closed-enum counters; a fresh tenant reads honest zeros."""
    async def scenario() -> None:
        redis_client, stats = await _fresh_stats()
        try:
            for _ in range(3):
                await stats.record_decision(_TENANT, "allow")
            await stats.record_decision(_TENANT, "deny")
            await stats.record_decision(_TENANT, "staged")
            await stats.record_decision(_TENANT, "staged")
            # An out-of-vocabulary outcome is a no-op (never mints a stray key segment).
            await stats.record_decision(_TENANT, "bogus")

            count, decisions = await stats.read_tenant(_TENANT)
            assert decisions == {"allow": 3, "deny": 1, "staged": 2}
            assert count == 0  # no agents recorded here.

            # A fresh tenant is honest zeros — never a fabricated number.
            fresh_count, fresh_dec = await stats.read_tenant("tenant-never-seen")
            assert fresh_count == 0
            assert fresh_dec == {"allow": 0, "deny": 0, "staged": 0}
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# 3) Deployment-wide aggregate: UNION cardinality + summed decisions.
# ---------------------------------------------------------------------------


def test_aggregate_union_cardinality_and_summed_decisions() -> None:
    """aggregate() unions the per-tenant HLLs and sums the per-tenant decision counters."""
    async def scenario() -> None:
        redis_client, stats = await _fresh_stats()
        try:
            # tenant A: agents {a1,a2,shared}; tenant B: {b1,shared}. Union = 4 distinct.
            for aid in ("a1", "a2", "shared"):
                await stats.record_agent("tenant-A", aid)
            for aid in ("b1", "shared"):
                await stats.record_agent("tenant-B", aid)
            await stats.record_decision("tenant-A", "allow")
            await stats.record_decision("tenant-A", "allow")
            await stats.record_decision("tenant-B", "deny")
            await stats.record_decision("tenant-B", "staged")

            count, decisions = await stats.aggregate()
            assert count == 4, count  # UNION cardinality, not 3+2=5.
            assert decisions == {"allow": 2, "deny": 1, "staged": 1}
        finally:
            await redis_client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# 4) record_* is swallow-only (a broken Redis can NEVER fail a decision).
# ---------------------------------------------------------------------------


def test_record_is_swallow_only_on_broken_redis() -> None:
    """A broken Redis makes record_agent/record_decision raise NOTHING; a metric bumps."""
    async def scenario() -> None:
        stats = TelemetryStats(_BrokenRedis())
        before = _metric("record_error")
        # Neither raises despite the backing store throwing on every op.
        await stats.record_agent(_TENANT, "agent-x")
        await stats.record_decision(_TENANT, "allow")
        after = _metric("record_error")
        assert after >= before + 2

    _run(scenario())


# ---------------------------------------------------------------------------
# 5) Beacon payload is a CLOSED set — no tenant/agent/alias/target/secret.
# ---------------------------------------------------------------------------


class _StubStats:
    """A stats stand-in returning canned aggregate numbers for the beacon payload test."""

    async def aggregate(self) -> tuple[int, dict[str, int]]:
        return 7, {"allow": 3, "deny": 2, "staged": 1}


def _stub_beacon(
    *,
    url: str = "https://receiver.example.com/telemetry",
    license_obj: Optional[Any] = None,
) -> TelemetryBeacon:
    return TelemetryBeacon(
        stats_getter=lambda: _StubStats(),  # type: ignore[arg-type,return-value]
        url=url,
        interval_s=3600.0,
        install_id="1234567890abcdef",
        secret=b"x" * 32,
        license_getter=lambda: license_obj,
    )


def test_beacon_payload_is_closed_eight_field_set() -> None:
    """
    The serialized beacon body's key set is EXACTLY the eight allowed fields, decisions'
    keys are EXACTLY {allow,deny,staged}, and NO seeded tenant/agent/alias string appears.
    """
    lic = SimpleNamespace(tier="self-hosted", license_id="lic-abc-123")
    beacon = _stub_beacon(license_obj=lic)

    payload = _run(beacon.assemble_payload())
    assert set(payload.keys()) == BEACON_PAYLOAD_FIELDS
    assert set(payload.keys()) == {
        "install_id", "license_tier", "license_id", "version",
        "governed_agent_identity_count", "decisions", "uptime_seconds", "sent_at",
    }
    assert set(payload["decisions"].keys()) == {"allow", "deny", "staged"}
    assert payload["governed_agent_identity_count"] == 7
    assert payload["decisions"] == {"allow": 3, "deny": 2, "staged": 1}
    assert payload["license_tier"] == "self-hosted"
    assert payload["license_id"] == "lic-abc-123"
    assert payload["version"] == get_version()

    # The serialized body carries ONLY aggregate integers + coarse license/version fields —
    # scan the bytes for any request-identifying string and assert absent.
    body = TelemetryBeacon._serialize(payload).decode("utf-8")
    for forbidden in (
        _TENANT, "tenant-A", "agent-repeat", "agent-0", _AUTO_ALIAS, _PIN_ALIAS,
        "target", "correlation", "arguments", "payload_hash", "pin", "jwt", "secret",
    ):
        assert forbidden not in body, forbidden
    # Signature/timestamp ride only as HEADERS, never in the body.
    assert "signature" not in body.lower()


def test_beacon_payload_unlicensed_state_is_honest() -> None:
    """No license → tier 'unlicensed' + license_id None (never a fabricated tier)."""
    beacon = _stub_beacon(license_obj=None)
    payload = _run(beacon.assemble_payload())
    assert payload["license_tier"] == "unlicensed"
    assert payload["license_id"] is None


# ---------------------------------------------------------------------------
# 6) Install identity: random, once-generated, persisted, 0600, not derived.
# ---------------------------------------------------------------------------


def test_install_identity_persist_random_and_0600(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The install-id + secret are minted ONCE at 0600, a second call reads the SAME id, and
    the id is a random hex token (NOT derived from tenant/host/customer/license).
    """
    id_path = tmp_path / ".keys" / "mcpip_install_id"
    secret_path = tmp_path / ".keys" / "mcpip_telemetry_secret"
    monkeypatch.setattr(appmain, "_INSTALL_ID_PATH", id_path)
    monkeypatch.setattr(appmain, "_TELEMETRY_SECRET_PATH", secret_path)

    install_id, secret = appmain._load_or_create_install_identity()
    assert id_path.exists() and secret_path.exists()
    # 0600 on both files.
    assert (id_path.stat().st_mode & 0o777) == 0o600
    assert (secret_path.stat().st_mode & 0o777) == 0o600
    # A random 16-byte hex token; a 32-byte secret.
    assert len(install_id) == 32 and all(c in "0123456789abcdef" for c in install_id)
    assert len(secret) == 32
    # Not derived from any identity: it equals none of the tenant/host/customer strings.
    for identity_like in (_TENANT, "aegis-dynamics", os.uname().nodename):
        assert install_id != identity_like

    # A second construction reads the SAME persisted id + secret (created once).
    again_id, again_secret = appmain._load_or_create_install_identity()
    assert again_id == install_id
    assert again_secret == secret


# ---------------------------------------------------------------------------
# 7) Hermetic + SSRF-guarded outbound client.
# ---------------------------------------------------------------------------


class _FakeResponse:
    status_code = 200

    async def aiter_raw(self) -> Any:
        yield b"ok"

    async def aclose(self) -> None:
        return None


class _FakeClient:
    captured: dict[str, Any] = {}

    def __init__(self, **kwargs: Any) -> None:
        _FakeClient.captured = dict(kwargs)

    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *_a: Any) -> bool:
        return False

    def build_request(self, *_a: Any, **_k: Any) -> object:
        return object()

    async def send(self, _request: Any, stream: bool = False) -> _FakeResponse:
        return _FakeResponse()


def test_beacon_client_is_hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    The beacon AsyncClient is built with trust_env=False + proxy=None + follow_redirects=
    False (no ambient HTTPS_PROXY/SSL_CERT_FILE reroute/MITM), and a 2xx bumps 'sent'.
    """
    monkeypatch.setattr("services.telemetry.httpx.AsyncClient", _FakeClient)
    beacon = _stub_beacon()
    # Bypass DNS/SSRF for THIS test (guarded separately below) with a fixed public IP.
    async def _fixed_ip() -> str:
        return "203.0.113.10"
    monkeypatch.setattr(beacon, "_resolve_and_validate", _fixed_ip)

    before = _metric("sent")
    _run(beacon.send_once())
    assert _FakeClient.captured["trust_env"] is False
    assert _FakeClient.captured["proxy"] is None
    assert _FakeClient.captured["follow_redirects"] is False
    assert _FakeClient.captured["verify"] is True
    assert _metric("sent") >= before + 1
    assert beacon.last_result == "ok"


def test_beacon_refuses_non_https_url() -> None:
    """A non-https telemetry URL is refused at construction (fail-closed)."""
    with pytest.raises(ValueError, match="https"):
        _stub_beacon(url="http://receiver.example.com/telemetry")


def test_beacon_refuses_loopback_url_drops_to_send_error() -> None:
    """
    A URL resolving to a loopback/metadata IP is refused by the reused SSRF guard and the
    send drops to send_error — it NEVER dials the internal address, NEVER raises.
    """
    beacon = _stub_beacon(url="https://127.0.0.1/telemetry")
    before = _metric("send_error")
    _run(beacon.send_once())  # must not raise.
    assert _metric("send_error") >= before + 1
    assert beacon.last_result == "error"


def test_beacon_send_failure_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A raising stats_getter (or any assembly failure) is swallowed to send_error."""
    def _boom() -> TelemetryStats:
        raise RuntimeError("aggregate blew up")

    beacon = TelemetryBeacon(
        stats_getter=_boom,
        url="https://receiver.example.com/telemetry",
        interval_s=3600.0,
        install_id="deadbeef",
        secret=b"y" * 32,
        license_getter=lambda: None,
    )
    before = _metric("send_error")
    _run(beacon.send_once())  # must not raise.
    assert _metric("send_error") >= before + 1


# ---------------------------------------------------------------------------
# 8) Composition: half-config fails boot; disabled/sandbox mints no beacon.
# ---------------------------------------------------------------------------


def test_build_beacon_disabled_returns_none() -> None:
    """Flag OFF (the default) → no beacon (unchanged behavior)."""
    assert _build_telemetry_beacon(Settings(), _components) is None


def test_build_beacon_half_config_fails_boot() -> None:
    """Flag ON with no URL is a fail-closed BOOT error (mirrors the authn-webhook refusal)."""
    with pytest.raises(RuntimeError, match="MCPIP_TELEMETRY_URL"):
        _build_telemetry_beacon(Settings(telemetry_enabled=True), _components)


def test_build_beacon_sandbox_air_gap_mints_no_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Sandbox with the flag ON never phones home AND never mints an install identity (air-gap
    wins): no beacon is built and no install-id/secret file is created.
    """
    id_path = tmp_path / ".keys" / "mcpip_install_id"
    secret_path = tmp_path / ".keys" / "mcpip_telemetry_secret"
    monkeypatch.setattr(appmain, "_INSTALL_ID_PATH", id_path)
    monkeypatch.setattr(appmain, "_TELEMETRY_SECRET_PATH", secret_path)

    beacon = _build_telemetry_beacon(
        Settings(
            telemetry_enabled=True,
            telemetry_url="https://receiver.example.com/telemetry",
            sandbox_mode=True,
        ),
        _components,
    )
    assert beacon is None
    # The load-bearing air-gap guarantee: NO telemetry identity was ever minted.
    assert not id_path.exists()
    assert not secret_path.exists()


# ---------------------------------------------------------------------------
# APP level — GET /v1/admin/stats over the real sandbox gateway.
# ---------------------------------------------------------------------------


def _reset_backing_state() -> None:
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
def idp() -> _DemoIdP:
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    _reset_backing_state()
    with TestClient(app) as test_client:
        yield test_client
    _reset_backing_state()


def _openai_call(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "call_test",
        "type": "function",
        "function": {"name": alias, "arguments": json.dumps(arguments)},
    }


def _post(client: TestClient, *, alias: str, arguments: dict[str, Any], token: str) -> Response:
    body = {"source_format": "openai_tool_call", "tool_call": _openai_call(alias, arguments), "jwt": token}
    return client.post("/v1/authorize", json=body)


def _json(resp: Response) -> dict[str, Any]:
    data: Any = resp.json()
    assert isinstance(data, dict)
    return data


def _admin_headers(idp: _DemoIdP, tenant_id: str = _TENANT) -> dict[str, str]:
    token = idp.mint(tenant_id=tenant_id, agent_id="agent-stats-admin", capabilities=[CAP_DIRECTORY_ADMIN])
    return {"Authorization": f"Bearer {token}"}


def test_admin_stats_reports_real_counts_and_honest_states(
    client: TestClient, idp: _DemoIdP
) -> None:
    """
    After driving allow / deny / staged for the tenant, GET /v1/admin/stats returns the
    tenant's REAL cardinality + decision totals + honest license/telemetry states + version.
    """
    # allow (AUTO), deny (unknown alias), staged (PIN_REQUIRED, no pin → 202).
    allow = _post(client, alias=_AUTO_ALIAS, arguments={"period": "m"}, token=idp.mint(agent_id="agent-a"))
    assert allow.status_code == 200, allow.text
    denied = _post(client, alias="skill_nope", arguments={}, token=idp.mint(agent_id="agent-b"))
    assert denied.status_code == 403
    staged = _post(client, alias=_PIN_ALIAS, arguments={"amount": "5"}, token=idp.mint(agent_id="agent-c"))
    assert staged.status_code == 202, staged.text

    resp = client.get("/v1/admin/stats", headers=_admin_headers(idp))
    assert resp.status_code == 200, resp.text
    data = _json(resp)

    assert data["version"] == get_version()
    # Three distinct agents authenticated for this tenant → cardinality >= 3.
    assert data["governed_agent_identity_count"] >= 3
    dec = data["decisions"]
    assert dec["allow"] >= 1 and dec["deny"] >= 1 and dec["staged"] >= 1
    # Honest license state: a license-less sandbox boot is {"licensed": false}, never faked.
    assert data["license"] == {"licensed": False}
    # Honest telemetry state: sandbox is structurally air-gapped (no beacon).
    assert data["telemetry"]["status"] == "air-gap"
    assert data["telemetry"]["last_result"] == "never"
    # No tenant/agent/alias/target ever crosses this admin boundary.
    blob = json.dumps(data)
    for forbidden in ("agent-a", "agent-b", "agent-c", _AUTO_ALIAS, _PIN_ALIAS, "target"):
        assert forbidden not in blob, forbidden


def test_admin_stats_is_admin_gated_and_opaque(client: TestClient, idp: _DemoIdP) -> None:
    """No token / a non-admin capability both get the opaque 403 — never the numbers."""
    # No bearer at all.
    no_tok = client.get("/v1/admin/stats")
    assert no_tok.status_code == 403
    assert set(_json(no_tok).keys()) == {"error", "correlation_id"}
    assert _json(no_tok)["error"] == AGENT_FACING_DENY_MESSAGE

    # A token holding a DIFFERENT capability (forensic-read) is not a directory admin.
    forensic_tok = idp.mint(agent_id="agent-forensic", capabilities=[CAP_FORENSIC_READ])
    non_admin = client.get("/v1/admin/stats", headers={"Authorization": f"Bearer {forensic_tok}"})
    assert non_admin.status_code == 403
    assert set(_json(non_admin).keys()) == {"error", "correlation_id"}


def test_admin_stats_is_tenant_scoped(client: TestClient, idp: _DemoIdP) -> None:
    """Tenant B's admin sees its OWN (fresh) numbers, never tenant A's activity."""
    # Drive activity for tenant-acme (A).
    ok = _post(client, alias=_AUTO_ALIAS, arguments={"period": "iso"}, token=idp.mint(agent_id="agent-iso"))
    assert ok.status_code == 200, ok.text

    # A brand-new tenant B admin: its own stats are honest zeros (A's counts never leak).
    b_headers = _admin_headers(idp, tenant_id="tenant-bravo-fresh")
    resp = client.get("/v1/admin/stats", headers=b_headers)
    assert resp.status_code == 200, resp.text
    data = _json(resp)
    # Only tenant B's own admin agent authenticated under B → cardinality is its own count,
    # and B has driven no allow/deny/staged decisions of its own.
    assert data["decisions"] == {"allow": 0, "deny": 0, "staged": 0}
