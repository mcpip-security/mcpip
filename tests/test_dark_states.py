"""
MCPIP GA — dark-feature HONEST-STATE sweep.

    ◐ "A disabled feature says why, not nothing."

Covers the additive ``features`` posture block on ``GET /v1/admin/stats`` and the
sibling status helpers next to ``_telemetry_status()``. The principle mirrors the
finished telemetry reference model: every state is derived from REAL signals
(settings + the composition-root resolution), never a fabricated "connected" beacon,
and the posture is coarse + deployment-wide — NOT a per-correlation-id oracle.

  * UNIT level: ``_forensic_status`` distinguishes the three real off reasons
    (production fail-safe default / explicit opt-out / flag-on-but-no-key ABSENT) plus
    the live-enabled state, and ``_external_pdp_status`` its off/staged/enforcing
    tri-state — with NO url/key/path/target/tenant ever in the payload.
  * APP level (sandbox ``/5`` — mirrors the adversarial API suite): the real
    ``/v1/admin/stats`` carries the ``features`` block honestly (sandbox defaults
    forensic capture ON, external PDP off), stays ``CAP_DIRECTORY_ADMIN``-gated +
    opaque, and leaks no secret; and MCP ``initialize`` LIVE-advertises the MRT
    step-up capability (the console reads this, never a static string).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MUST match tests/test_authorize_api.py / test_telemetry.py so the shared _components
# graph agrees on the Redis db + sandbox flag regardless of import order.
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import json
from types import SimpleNamespace
from typing import Any, Iterator

import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import CAP_DIRECTORY_ADMIN, CAP_FORENSIC_READ

from app.main import (
    _components,
    _external_pdp_status,
    _features_status,
    _forensic_status,
    app,
)
from main import _DemoIdP

_TENANT = "tenant-acme"

# A sentinel URL that must NEVER appear in any posture payload (posture is url-free).
_SECRET_PDP_URL = "https://pdp.internal.example/decision-secret-path"
_SECRET_KEY_PATH = "/etc/mcpip/forensic-secret.key"


# ---------------------------------------------------------------------------
# UNIT — the status helpers, exercised by swapping the composition-root signals.
# ---------------------------------------------------------------------------


def _set_settings(monkeypatch: pytest.MonkeyPatch, **over: Any) -> None:
    """Swap _components.settings for a duck-typed stand-in carrying only the fields the
    status helpers read — so a unit case can drive any (flag, url, sandbox) combination
    without a full boot."""
    base: dict[str, Any] = {
        "sandbox_mode": True,
        "forensic_capture": None,
        "forensic_key_path": None,
        "external_pdp_enabled": False,
        "external_pdp_url": None,
    }
    base.update(over)
    monkeypatch.setattr(_components, "settings", SimpleNamespace(**base))


def test_forensic_status_production_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset flag in production is the fail-safe OFF — honestly labelled, not silent."""
    _set_settings(monkeypatch, sandbox_mode=False, forensic_capture=None)
    monkeypatch.setattr(_components, "forensic", None)
    status = _forensic_status()
    assert status["status"] == "disabled"
    assert status["reason"] == "production-default"
    # The detail names the 404-is-not-an-error truth and the enable recipe.
    assert "404" in status["detail"]
    assert "MCPIP_FORENSIC_CAPTURE=true" in status["detail"]


def test_forensic_status_explicit_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit MCPIP_FORENSIC_CAPTURE=false is distinguished from the default off."""
    _set_settings(monkeypatch, sandbox_mode=False, forensic_capture=False)
    monkeypatch.setattr(_components, "forensic", None)
    status = _forensic_status()
    assert status["status"] == "disabled"
    assert status["reason"] == "explicit-opt-out"


def test_forensic_status_flag_on_no_key_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flag ON but no key resolved (store is None) is the fail-closed ABSENT state —
    never a plaintext fallback, never reported as enabled."""
    _set_settings(
        monkeypatch, sandbox_mode=False, forensic_capture=True, forensic_key_path=None
    )
    monkeypatch.setattr(_components, "forensic", None)
    status = _forensic_status()
    assert status["status"] == "absent"
    assert status["reason"] == "flag-on-no-key"


def test_forensic_status_enabled_when_store_built(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flag effectively on AND a built store (a resolved key) reads as live."""
    _set_settings(monkeypatch, sandbox_mode=True, forensic_capture=None)
    monkeypatch.setattr(_components, "forensic", object())
    status = _forensic_status()
    assert status["status"] == "enabled"
    assert "reason" not in status  # enabled carries no off-reason


def test_forensic_status_never_leaks_key_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Posture is coarse — the configured key PATH never rides the payload."""
    _set_settings(
        monkeypatch,
        sandbox_mode=False,
        forensic_capture=True,
        forensic_key_path=_SECRET_KEY_PATH,
    )
    monkeypatch.setattr(_components, "forensic", object())
    assert _SECRET_KEY_PATH not in json.dumps(_forensic_status())


def test_external_pdp_status_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither flag nor url set — the shipped no-op seam."""
    _set_settings(monkeypatch, external_pdp_enabled=False, external_pdp_url=None)
    status = _external_pdp_status()
    assert status["status"] == "off"


def test_external_pdp_status_staged(monkeypatch: pytest.MonkeyPatch) -> None:
    """URL set with the flag OFF is the legitimate staged-but-disabled state."""
    _set_settings(
        monkeypatch, external_pdp_enabled=False, external_pdp_url=_SECRET_PDP_URL
    )
    status = _external_pdp_status()
    assert status["status"] == "staged"
    # The url is NEVER exposed — posture only.
    assert _SECRET_PDP_URL not in json.dumps(status)


def test_external_pdp_status_enforcing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both set — the deny-only, monotonic, fail-closed enforcing consult."""
    _set_settings(
        monkeypatch, external_pdp_enabled=True, external_pdp_url=_SECRET_PDP_URL
    )
    status = _external_pdp_status()
    assert status["status"] == "enforcing"
    assert "deny" in status["detail"].lower()
    assert _SECRET_PDP_URL not in json.dumps(status)


def test_features_status_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    """The features block carries exactly the two new posture keys (telemetry stays
    top-level; MRT is read live from initialize, not here)."""
    _set_settings(monkeypatch, sandbox_mode=True)
    monkeypatch.setattr(_components, "forensic", object())
    feats = _features_status()
    assert set(feats.keys()) == {"forensic_capture", "external_pdp"}


# ---------------------------------------------------------------------------
# APP — GET /v1/admin/stats features block + MCP initialize MRT advertisement.
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


def _json(resp: Response) -> dict[str, Any]:
    data: Any = resp.json()
    assert isinstance(data, dict)
    return data


def _admin_headers(idp: _DemoIdP, tenant_id: str = _TENANT) -> dict[str, str]:
    token = idp.mint(
        tenant_id=tenant_id,
        agent_id="agent-darkstates-admin",
        capabilities=[CAP_DIRECTORY_ADMIN],
    )
    return {"Authorization": f"Bearer {token}"}


def test_admin_stats_carries_honest_features_block(
    client: TestClient, idp: _DemoIdP
) -> None:
    """The real sandbox gateway reports the features posture: forensic capture is
    default-ON in sandbox (enabled), external PDP is off; telemetry stays top-level."""
    resp = client.get("/v1/admin/stats", headers=_admin_headers(idp))
    assert resp.status_code == 200, resp.text
    data = _json(resp)

    feats = data["features"]
    assert feats["forensic_capture"]["status"] == "enabled"
    assert feats["external_pdp"]["status"] == "off"
    # Every posture entry is self-describing (a human detail), never bare.
    assert feats["forensic_capture"]["detail"]
    assert feats["external_pdp"]["detail"]
    # Telemetry is NOT folded into features — it stays a top-level back-compat key.
    assert "features" not in data["telemetry"]
    assert data["telemetry"]["status"] == "air-gap"


def test_admin_stats_features_is_admin_gated_and_leaks_nothing(
    client: TestClient, idp: _DemoIdP
) -> None:
    """The posture surface inherits the stats boundary: admin-gated + opaque, and it
    never carries a target/secret/url."""
    # A non-admin capability is not a directory admin — opaque 403, no features.
    forensic_tok = idp.mint(agent_id="agent-fr", capabilities=[CAP_FORENSIC_READ])
    denied = client.get(
        "/v1/admin/stats", headers={"Authorization": f"Bearer {forensic_tok}"}
    )
    assert denied.status_code == 403
    assert set(_json(denied).keys()) == {"error", "correlation_id"}
    assert _json(denied)["error"] == AGENT_FACING_DENY_MESSAGE

    data = _json(client.get("/v1/admin/stats", headers=_admin_headers(idp)))
    blob = json.dumps(data["features"])
    for forbidden in ("target", "install_id", "http://", "https://", "/etc/", ".key"):
        assert forbidden not in blob, forbidden


def test_mcp_initialize_live_advertises_mrt_step_up(client: TestClient) -> None:
    """MCP ``initialize`` advertises the step-up capability in its REAL reply — the
    console reads THIS live rather than asserting a static string."""
    resp = client.post(
        "/v1/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert resp.status_code == 200, resp.text
    result = _json(resp)["result"]
    step_up = result["capabilities"]["experimental"]["mcpipStepUp"]
    assert step_up == {"mode": "mrt"}
