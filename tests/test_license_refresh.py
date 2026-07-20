"""
MCPIP V2 — opt-in, off-hot-path license REFRESH (T2 "pull control").

    ◐ "The entitlement may be pulled — but only the vendor's OWN root can grant it."

Covers ``core/licensing.py`` (the extracted ``verify_license_bytes`` / ``is_newer_license``
+ the byte-identical boot gate) and ``services/license_refresh.py`` (``LicenseRefresher``):

  * VERIFY: a valid newer signed candidate swaps ATOMICALLY; a forged / unsigned /
    WRONG-ROOT / expired / not-newer candidate is REFUSED and the last-good license is
    RETAINED (proving no new trust root, no widening, no fail-open to unlicensed).
  * NEVER-FAIL-OPEN: transport / non-2xx / SSRF-blocked / oversized / malformed candidate
    each RETAINS the license (never None) with the correct closed-enum metric.
  * HERMETIC + SSRF-guarded: the refresh client is trust_env=False + proxy=None +
    follow_redirects=False, and a loopback/metadata URL is refused before any dial.
  * SEPARABILITY + PRIVACY: without a beacon provider the body is a MINIMAL identity subset
    of the closed field set (no tenant/agent/alias/target); with a provider it rides the
    beacon payload.
  * COMPOSITION: absent URL → no refresher (today's air-gapped behavior, byte-identical);
    a licensed build wires getter/setter that atomically swap ``Components.license``.
  * BOOT GATE UNCHANGED: ``load_and_verify_license`` still fail-closed byte-identical.
  * OFF-HOT-PATH: an authorize succeeds normally while the refresher raises on every attempt.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MUST match tests/test_authorize_api.py so the shared _components graph agrees on the
# Redis db + sandbox flag regardless of import order.
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from httpx import Response

from core.integrity import canonical_signed_bytes
from core.licensing import (
    License,
    LicenseError,
    is_newer_license,
    load_and_verify_license,
    verify_license_bytes,
)
from core.metrics import LICENSE_REFRESH
from core.version import get_version
from interfaces import CAP_DIRECTORY_ADMIN, MAX_LICENSE_DOC_BYTES
from services.license_refresh import LicenseRefresher, LicenseRefreshError

import app.main as appmain
from app.main import _build_license_refresher, _components, app
from core.config import Settings
from main import _DemoIdP


# ---------------------------------------------------------------------------
# Signed-license helpers (mirror tests/test_release_hooks.py).
# ---------------------------------------------------------------------------


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _pub_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _sign(document: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    unsigned = {k: v for k, v in document.items() if k != "signature"}
    signature = private_key.sign(canonical_signed_bytes(unsigned))
    signed = dict(unsigned)
    signed["signature"] = base64.b64encode(signature).decode("ascii")
    return signed


def _license_doc(
    *,
    license_id: str = "6a2f1f7e-0000-4000-8000-000000000042",
    tier: str = "self-hosted",
    issued_delta_days: float = -1.0,
    valid_days: float = 30.0,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    issued = now + timedelta(days=issued_delta_days)
    expires = issued + timedelta(days=valid_days)
    return {
        "schema": "mcpip-license/1",
        "license_id": license_id,
        "customer": "aegis-dynamics",
        "tier": tier,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "entitlements": ["core", "cloud_iam"],
    }


def _signed_bytes(doc: dict[str, Any], key: Ed25519PrivateKey) -> bytes:
    return json.dumps(_sign(doc, key)).encode("utf-8")


class _Box:
    """A tiny mutable license holder standing in for ``Components.license``."""

    def __init__(self, lic: Optional[License]) -> None:
        self.lic = lic

    def get(self) -> Optional[License]:
        return self.lic

    def set(self, lic: License) -> None:
        self.lic = lic


def _metric(event: str) -> float:
    """Current value of mcpip_license_refresh_total{event=...} (0.0 if never touched)."""
    return float(LICENSE_REFRESH.labels(event)._value.get())


def _refresher(
    *,
    box: _Box,
    pub_pem: bytes,
    url: str = "https://license.example.com/pull",
    payload_provider: Any = None,
) -> LicenseRefresher:
    return LicenseRefresher(
        url=url,
        public_key_pem=pub_pem,
        current_getter=box.get,
        license_setter=box.set,
        interval_s=3600.0,
        payload_provider=payload_provider,
    )


def _patch_fetch(refresher: LicenseRefresher, raw: bytes) -> None:
    """Bypass the network: make ``_fetch`` return canned candidate bytes."""

    async def _fake_fetch(_body: bytes) -> bytes:
        return raw

    refresher._fetch = _fake_fetch  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# 1) verify_license_bytes + is_newer_license (the extracted validator + ordering).
# ---------------------------------------------------------------------------


def test_verify_license_bytes_accepts_valid_and_matches_boot() -> None:
    key = Ed25519PrivateKey.generate()
    raw = _signed_bytes(_license_doc(), key)
    lic = verify_license_bytes(raw, _pub_pem(key))
    assert lic.tier == "self-hosted"
    assert lic.license_id == "6a2f1f7e-0000-4000-8000-000000000042"


@pytest.mark.parametrize("tamper", ["expired", "future", "bad_tier", "bad_schema"])
def test_verify_license_bytes_rejects_bad_docs(tamper: str) -> None:
    key = Ed25519PrivateKey.generate()
    if tamper == "expired":
        doc = _license_doc(issued_delta_days=-40.0, valid_days=1.0)
    elif tamper == "future":
        doc = _license_doc(issued_delta_days=5.0)
    elif tamper == "bad_tier":
        doc = _license_doc(tier="enterprise-unlimited")
    else:
        doc = _license_doc()
        doc["schema"] = "mcpip-license/2"
    raw = _signed_bytes(doc, key)
    with pytest.raises(LicenseError):
        verify_license_bytes(raw, _pub_pem(key))


def test_verify_license_bytes_rejects_wrong_root() -> None:
    """A perfectly-signed license under a DIFFERENT key is refused — no new trust root."""
    signer = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    raw = _signed_bytes(_license_doc(), signer)
    with pytest.raises(LicenseError):
        verify_license_bytes(raw, _pub_pem(other))


def test_verify_license_bytes_rejects_malformed_json() -> None:
    key = Ed25519PrivateKey.generate()
    with pytest.raises(LicenseError):
        verify_license_bytes(b"{not json", _pub_pem(key))


def test_is_newer_license_strict_ordering() -> None:
    key = Ed25519PrivateKey.generate()
    older = verify_license_bytes(_signed_bytes(_license_doc(issued_delta_days=-2.0), key), _pub_pem(key))
    newer = verify_license_bytes(_signed_bytes(_license_doc(issued_delta_days=-1.0), key), _pub_pem(key))
    assert is_newer_license(newer, older) is True
    assert is_newer_license(older, newer) is False
    assert is_newer_license(older, older) is False  # equal is NOT newer.


# ---------------------------------------------------------------------------
# 2) Boot gate unchanged — load_and_verify_license still fail-closed byte-identical.
# ---------------------------------------------------------------------------


def test_boot_gate_valid_roundtrip(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    lic_path = tmp_path / "license.json"
    lic_path.write_bytes(_signed_bytes(_license_doc(), key))
    lic = load_and_verify_license(lic_path, _pub_pem(key))
    assert lic.tier == "self-hosted"


def test_boot_gate_forged_is_opaque_runtimeerror(tmp_path: Path) -> None:
    """The boot gate still raises the OPAQUE RuntimeError (never LicenseError) on a forgery."""
    signer = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    lic_path = tmp_path / "license.json"
    lic_path.write_bytes(_signed_bytes(_license_doc(), signer))
    with pytest.raises(RuntimeError, match="license verification failed"):
        load_and_verify_license(lic_path, _pub_pem(other))


def test_boot_gate_unreadable_is_opaque(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    with pytest.raises(RuntimeError, match="license verification failed"):
        load_and_verify_license(tmp_path / "missing.json", _pub_pem(key))


# ---------------------------------------------------------------------------
# 3) refresh_once — atomic swap ONLY on a valid, strictly-newer candidate.
# ---------------------------------------------------------------------------


def test_refresh_swaps_valid_newer_candidate() -> None:
    """A genuine RENEWAL — the SAME license_id + customer, only newer — swaps in."""
    key = Ed25519PrivateKey.generate()
    box = _Box(
        verify_license_bytes(
            _signed_bytes(_license_doc(issued_delta_days=-5.0, license_id="lic-acme"), key),
            _pub_pem(key),
        )
    )
    refresher = _refresher(box=box, pub_pem=_pub_pem(key))
    newer = _license_doc(issued_delta_days=-1.0, license_id="lic-acme")  # same id+customer, newer.
    _patch_fetch(refresher, _signed_bytes(newer, key))

    before = _metric("refreshed")
    _run(refresher.refresh_once())
    assert box.lic is not None and box.lic.license_id == "lic-acme"
    assert box.lic.customer == "aegis-dynamics"
    assert box.lic.issued_at.isoformat() == newer["issued_at"]  # the newer doc swapped in
    assert _metric("refreshed") == before + 1
    assert refresher.last_refreshed_at is not None


@pytest.mark.parametrize("mutate", [{"license_id": "lic-OTHER"}, {"customer": "globex"}])
def test_refresh_refuses_cross_identity_and_retains(mutate: dict[str, str]) -> None:
    """LICENSE + TENANT SEPARATION: a newer, validly-signed license for a DIFFERENT
    customer or license_id must NEVER swap in — the single root signs all customers, so
    without an identity binding a refresh could silently re-attest this deployment under
    the wrong customer + a widened tier. The last-good license is retained."""
    key = Ed25519PrivateKey.generate()
    current = verify_license_bytes(
        _signed_bytes(_license_doc(issued_delta_days=-3.0, license_id="lic-keep"), key),
        _pub_pem(key),
    )
    box = _Box(current)
    refresher = _refresher(box=box, pub_pem=_pub_pem(key))
    doc = _license_doc(issued_delta_days=-1.0, license_id="lic-keep")  # newer than current...
    doc.update(mutate)  # ...but a DIFFERENT customer or license_id.
    _patch_fetch(refresher, _signed_bytes(doc, key))

    before = _metric("identity_mismatch")
    _run(refresher.refresh_once())
    assert box.lic is current  # retained — never widened, never bricked.
    assert box.lic.license_id == "lic-keep" and box.lic.customer == "aegis-dynamics"
    assert _metric("identity_mismatch") == before + 1
    assert refresher.last_refreshed_at is None


@pytest.mark.parametrize(
    "kind,metric",
    [
        ("forged", "verify_failed"),
        ("wrong_root", "verify_failed"),
        ("expired", "verify_failed"),
        ("malformed", "verify_failed"),
        ("not_newer", "not_newer"),
        ("same", "not_newer"),
    ],
)
def test_refresh_refuses_and_retains(kind: str, metric: str) -> None:
    key = Ed25519PrivateKey.generate()
    current = verify_license_bytes(_signed_bytes(_license_doc(issued_delta_days=-3.0, license_id="lic-keep"), key), _pub_pem(key))
    box = _Box(current)
    refresher = _refresher(box=box, pub_pem=_pub_pem(key))

    if kind == "forged":
        raw = _signed_bytes(_license_doc(issued_delta_days=-1.0), key)
        raw = raw.replace(b'"self-hosted"', b'"cloud"')  # break the signature by mutating a signed field.
    elif kind == "wrong_root":
        other = Ed25519PrivateKey.generate()
        raw = _signed_bytes(_license_doc(issued_delta_days=-1.0), other)
    elif kind == "expired":
        raw = _signed_bytes(_license_doc(issued_delta_days=-40.0, valid_days=1.0), key)
    elif kind == "malformed":
        raw = b"{ not a license"
    elif kind == "not_newer":
        raw = _signed_bytes(_license_doc(issued_delta_days=-10.0, license_id="lic-older"), key)
    else:  # same issued_at → not strictly newer.
        raw = _signed_bytes(
            {**_license_doc(license_id="lic-same"), "issued_at": current.issued_at.isoformat()},
            key,
        )
    _patch_fetch(refresher, raw)

    before = _metric(metric)
    _run(refresher.refresh_once())  # must not raise.
    assert box.lic is current  # SAME object — the last-good license is retained.
    assert _metric(metric) == before + 1


# ---------------------------------------------------------------------------
# 4) Never-fail-open on transport failure — retained + transport_error, never None.
# ---------------------------------------------------------------------------


def test_refresh_transport_failure_retains() -> None:
    key = Ed25519PrivateKey.generate()
    current = verify_license_bytes(_signed_bytes(_license_doc(), key), _pub_pem(key))
    box = _Box(current)
    refresher = _refresher(box=box, pub_pem=_pub_pem(key))

    async def _boom(_body: bytes) -> bytes:
        raise LicenseRefreshError("kaboom")

    refresher._fetch = _boom  # type: ignore[method-assign]
    before = _metric("transport_error")
    _run(refresher.refresh_once())  # must not raise.
    assert box.lic is current  # retained, never None.
    assert _metric("transport_error") == before + 1


def test_refresh_ssrf_loopback_refused_retains() -> None:
    """A refresh URL resolving to loopback is refused by the reused SSRF guard; retained."""
    key = Ed25519PrivateKey.generate()
    current = verify_license_bytes(_signed_bytes(_license_doc(), key), _pub_pem(key))
    box = _Box(current)
    refresher = _refresher(box=box, pub_pem=_pub_pem(key), url="https://127.0.0.1/pull")
    before = _metric("transport_error")
    _run(refresher.refresh_once())  # must not raise, must not dial.
    assert box.lic is current
    assert _metric("transport_error") == before + 1


# ---------------------------------------------------------------------------
# 5) Hermetic + SSRF-guarded outbound client (mirrors the beacon/jwks discipline).
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status_code = status
        self._body = body

    async def aiter_raw(self) -> Any:
        yield self._body

    async def aclose(self) -> None:
        return None


class _FakeClient:
    captured: dict[str, Any] = {}
    response = _FakeResponse(200, b"{}")

    def __init__(self, **kwargs: Any) -> None:
        _FakeClient.captured = dict(kwargs)

    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *_a: Any) -> bool:
        return False

    def build_request(self, *_a: Any, **_k: Any) -> object:
        return object()

    async def send(self, _request: Any, stream: bool = False) -> _FakeResponse:
        return _FakeClient.response


def test_refresh_client_is_hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    key = Ed25519PrivateKey.generate()
    candidate_doc = _license_doc(issued_delta_days=-1.0)  # same id+customer as boot, newer.
    candidate = _signed_bytes(candidate_doc, key)
    _FakeClient.response = _FakeResponse(200, candidate)
    monkeypatch.setattr("services.license_refresh.httpx.AsyncClient", _FakeClient)

    box = _Box(verify_license_bytes(_signed_bytes(_license_doc(issued_delta_days=-5.0), key), _pub_pem(key)))
    refresher = _refresher(box=box, pub_pem=_pub_pem(key))

    async def _fixed_ip() -> str:
        return "203.0.113.10"

    monkeypatch.setattr(refresher, "_resolve_and_validate", _fixed_ip)

    _run(refresher.refresh_once())
    assert _FakeClient.captured["trust_env"] is False
    assert _FakeClient.captured["proxy"] is None
    assert _FakeClient.captured["follow_redirects"] is False
    assert _FakeClient.captured["verify"] is True
    # And the swap happened (end-to-end through the fetch path) — a same-identity renewal.
    assert box.lic is not None and box.lic.issued_at.isoformat() == candidate_doc["issued_at"]


def test_refresh_non_2xx_retains(monkeypatch: pytest.MonkeyPatch) -> None:
    key = Ed25519PrivateKey.generate()
    _FakeClient.response = _FakeResponse(503, b"nope")
    monkeypatch.setattr("services.license_refresh.httpx.AsyncClient", _FakeClient)
    current = verify_license_bytes(_signed_bytes(_license_doc(), key), _pub_pem(key))
    box = _Box(current)
    refresher = _refresher(box=box, pub_pem=_pub_pem(key))

    async def _fixed_ip() -> str:
        return "203.0.113.10"

    monkeypatch.setattr(refresher, "_resolve_and_validate", _fixed_ip)
    before = _metric("transport_error")
    _run(refresher.refresh_once())
    assert box.lic is current
    assert _metric("transport_error") == before + 1


def test_refresh_oversized_body_retains(monkeypatch: pytest.MonkeyPatch) -> None:
    key = Ed25519PrivateKey.generate()
    _FakeClient.response = _FakeResponse(200, b"x" * (MAX_LICENSE_DOC_BYTES + 1))
    monkeypatch.setattr("services.license_refresh.httpx.AsyncClient", _FakeClient)
    current = verify_license_bytes(_signed_bytes(_license_doc(), key), _pub_pem(key))
    box = _Box(current)
    refresher = _refresher(box=box, pub_pem=_pub_pem(key))

    async def _fixed_ip() -> str:
        return "203.0.113.10"

    monkeypatch.setattr(refresher, "_resolve_and_validate", _fixed_ip)
    before = _metric("transport_error")
    _run(refresher.refresh_once())
    assert box.lic is current
    assert _metric("transport_error") == before + 1


def test_refresh_non_https_refused_at_construction() -> None:
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="https"):
        _refresher(box=_Box(None), pub_pem=_pub_pem(key), url="http://license.example.com/pull")


# ---------------------------------------------------------------------------
# 6) Separability + privacy — the request body is the closed field set only.
# ---------------------------------------------------------------------------


def test_minimal_body_when_no_provider_is_closed_subset() -> None:
    key = Ed25519PrivateKey.generate()
    current = verify_license_bytes(_signed_bytes(_license_doc(license_id="lic-cur"), key), _pub_pem(key))
    refresher = _refresher(box=_Box(current), pub_pem=_pub_pem(key))
    body = _run(refresher._build_body())
    parsed = json.loads(body)
    # A strict SUBSET of the closed beacon field set — no install-id minted, no counts.
    assert set(parsed.keys()) == {"license_id", "version"}
    assert parsed["license_id"] == "lic-cur"
    assert parsed["version"] == get_version()
    # NEVER any tenant/agent/alias/target/argument/secret.
    text = body.decode("utf-8")
    for forbidden in ("tenant", "agent", "alias", "target", "argument", "secret", "correlation"):
        assert forbidden not in text, forbidden


def test_provider_body_rides_when_wired() -> None:
    """With a beacon payload provider the refresh body IS the closed beacon payload."""
    key = Ed25519PrivateKey.generate()

    async def _provider() -> dict[str, Any]:
        return {
            "install_id": "abc123",
            "license_tier": "self-hosted",
            "license_id": "lic-x",
            "version": get_version(),
            "governed_agent_identity_count": 4,
            "decisions": {"allow": 1, "deny": 2, "staged": 3},
            "uptime_seconds": 7,
            "sent_at": "2026-07-17T00:00:00+00:00",
        }

    refresher = _refresher(box=_Box(None), pub_pem=_pub_pem(key), payload_provider=_provider)
    parsed = json.loads(_run(refresher._build_body()))
    assert parsed["install_id"] == "abc123"
    assert parsed["governed_agent_identity_count"] == 4
    assert "tenant" not in json.dumps(parsed)


# ---------------------------------------------------------------------------
# 7) Composition — absent URL builds nothing; a licensed build wires the swap.
# ---------------------------------------------------------------------------


def test_build_refresher_absent_url_returns_none() -> None:
    """No refresh URL → no refresher (today's air-gapped/offline behavior, byte-identical)."""
    assert _build_license_refresher(Settings(), _components) is None


def test_build_refresher_url_without_license_returns_none() -> None:
    """URL set but a license-less sandbox boot → refresh absent (never invents entitlement)."""
    # _components booted in sandbox without a license.
    assert _components.license is None
    settings = Settings(license_refresh_url="https://license.example.com/pull")
    assert _build_license_refresher(settings, _components) is None


def test_build_refresher_wires_atomic_swap(tmp_path: Path) -> None:
    """
    A licensed build returns a refresher whose setter atomically swaps Components.license and
    whose getter reflects the live value — proving getter/setter close over the live graph.
    """
    from types import SimpleNamespace

    key = Ed25519PrivateKey.generate()
    pub_path = tmp_path / "license_root.pub.pem"
    pub_path.write_bytes(_pub_pem(key))
    boot_lic = verify_license_bytes(_signed_bytes(_license_doc(issued_delta_days=-5.0, license_id="lic-boot"), key), _pub_pem(key))

    fake_components = SimpleNamespace(license=boot_lic, telemetry=None)
    settings = Settings(
        license_refresh_url="https://license.example.com/pull",
        license_public_key_path=str(pub_path),
    )
    refresher = _build_license_refresher(settings, fake_components)  # type: ignore[arg-type]
    assert refresher is not None

    # The getter reflects the live license; the setter mutates the SAME components object.
    newer = _license_doc(issued_delta_days=-1.0, license_id="lic-boot")  # same id+customer, newer.
    _patch_fetch(refresher, _signed_bytes(newer, key))
    _run(refresher.refresh_once())
    assert fake_components.license.license_id == "lic-boot"
    assert fake_components.license.issued_at.isoformat() == newer["issued_at"]


# ---------------------------------------------------------------------------
# 8) Off-hot-path proof — an authorize succeeds while the refresher raises.
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
    assert demo is not None
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    _reset_backing_state()
    with TestClient(app) as test_client:
        yield test_client
    _reset_backing_state()


def test_authorize_unaffected_by_a_raising_refresher(
    client: TestClient, idp: _DemoIdP, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The license is NEVER consulted per-request, so even a refresher that raises on every
    attempt cannot block/flip a decision. Drive a real AUTO allow with a raising refresher
    installed and assert the decision is unaffected AND the license reference is untouched.
    """
    key = Ed25519PrivateKey.generate()
    box = _Box(None)  # start unlicensed, like the sandbox boot.
    refresher = _refresher(box=box, pub_pem=_pub_pem(key))

    async def _always_raise(_body: bytes) -> bytes:
        raise LicenseRefreshError("boom")

    refresher._fetch = _always_raise  # type: ignore[method-assign]
    monkeypatch.setattr(_components, "license_refresher", refresher, raising=False)
    license_before = _components.license

    token = idp.mint(agent_id="agent-off-path")
    body = {
        "source_format": "openai_tool_call",
        "tool_call": {
            "id": "call_x",
            "type": "function",
            "function": {"name": "skill_spend_summary", "arguments": json.dumps({"period": "m"})},
        },
        "jwt": token,
    }
    resp: Response = client.post("/v1/authorize", json=body)
    assert resp.status_code == 200, resp.text
    # The refresh outcome could not perturb the decision, and the license is unchanged.
    _run(refresher.refresh_once())  # raises internally, swallowed to a metric.
    assert _components.license is license_before


def test_license_view_stays_unlicensed_and_exact_in_sandbox(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A license-less sandbox boot's /v1/license is EXACTLY {'licensed': False} — additive
    refresh fields never appear in the unlicensed branch."""
    resp = client.get("/v1/license", headers={"Authorization": f"Bearer {idp.mint()}"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"licensed": False}
