"""
MCPIP V2 — live operator-console surfaces: decisions-feed proofs + tripwire rosters.

    ◐ "A tripped canary is an alarm the attacker never hears — but the operator does."

Covers the three lean console surfaces end to end against the REAL gateway app:

  * ``GET /v1/admin/decisions/recent`` — every row now carries the WORM ``event_id``
    (the handle ``/v1/audit/proof/{event_id}`` accepts) and ``worm_sequence``, while the
    projection stays a strict whitelist (target / payload / challenge id never appear).
  * A REAL per-event inclusion-proof round trip: take an ``event_id`` off the feed,
    seal the epoch, fetch the proof, and verify the Merkle path locally.
  * ``GET /v1/admin/quarantine`` — the canary-tripwire freeze roster (agent + remaining
    TTL), tenant-scoped, clearing when the Redis ``EX`` clock fires.
  * ``GET /v1/admin/canaries`` — the decoy-alias roster for the admin's own tenant,
    while the AGENT-facing ``/v1/catalog`` keeps hiding the ``canary`` flag.

All three are ``CAP_DIRECTORY_ADMIN``-gated and opaque-deny like every sibling admin
read. Self-contained: mirrors ``test_authorize_api``'s namespaced-sandbox env so
importing the composition root is safe, and drives the real FastAPI app via
``TestClient`` so the lifespan (Redis rebind + epoch daemon) runs exactly as
production would.
"""

from __future__ import annotations

import os
import sys

# Make the repo root importable when this file is run directly; pytest already adds
# it via rootdir.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MUST be set before importing app.main (settings are lru_cached at import). Uses the
# SAME namespaced sandbox db as the adversarial API suite, so import order is immaterial.
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import json
import time
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from audit import merkle
from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import CAP_DIRECTORY_ADMIN, QUARANTINE_TTL_SECONDS
from obfuscator.tenant_catalog import CANARY_ALIASES

from app.main import _components, app
from main import _DemoIdP

_TENANT = "tenant-acme"
_AUTO_ALIAS = "skill_spend_summary"                    # tenant-acme AUTO config row.
_CANARY_ALIAS = "skill_export_all_credentials"         # a seeded deception tripwire row.
_EVENTS_STREAM = "mcpip:worm:events"

# The EXACT whitelist a feed row may carry — the 12 event-side fields plus the two
# stream-side audit handles (event_id / worm_sequence) this surface deliberately adds.
_FEED_KEYS = {
    "correlation_id", "agent_id", "alias", "decision", "deny_reason", "transport",
    "risk_tier", "classification", "source_format", "transaction_ref",
    "session_id",  # session attribution (None for pre-session tokens)
    "delegation_id",  # the grant a narrowed call operated under (None otherwise)
    "tenant_id", "event_id", "worm_sequence", "timestamp_ns",
}
# Fields that must NEVER surface (topology, payload, step-up, secrets).
_FORBIDDEN_FEED_KEYS = ("target", "arguments", "payload_hash", "challenge_id", "pin", "jwt")


# ---------------------------------------------------------------------------
# Fixtures (namespaced sandbox — mirrors the adversarial API suite).
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
def idp() -> _DemoIdP:
    """The in-process sandbox IdP the composition root booted (same keypair)."""
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    """
    Module-scoped TestClient over a hermetic slate — reset BEFORE the lifespan (a stale
    on-disk anchor would disagree with the flushed Redis chain) AND AFTER it: this
    module sorts before the adversarial API suite, whose own fixture flushes only
    Redis, so an anchor witness surviving from THIS module's sealed epochs would
    (correctly) flag that module's fresh chain as a rollback.
    """
    _reset_backing_state()
    with TestClient(app) as test_client:
        yield test_client
    _reset_backing_state()


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _openai_call(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Wrap arguments in an OpenAI ``tool_call`` envelope (bridge deep-validates)."""
    return {
        "id": "call_test",
        "type": "function",
        "function": {"name": alias, "arguments": json.dumps(arguments)},
    }


def _post(
    client: TestClient,
    *,
    alias: str,
    arguments: dict[str, Any],
    token: str,
) -> Response:
    """POST ``/v1/authorize`` with an OpenAI envelope and a body JWT."""
    body: dict[str, Any] = {
        "source_format": "openai_tool_call",
        "tool_call": _openai_call(alias, arguments),
        "jwt": token,
    }
    resp: Response = client.post("/v1/authorize", json=body)
    return resp


def _json(resp: Response) -> dict[str, Any]:
    """Typed view of a JSON response body."""
    data: Any = resp.json()
    assert isinstance(data, dict)
    return data


def _assert_opaque_denial(resp: Response) -> None:
    """A denied surface exposes exactly ``{error, correlation_id}`` — nothing else."""
    assert resp.status_code == 403, resp.text
    data = _json(resp)
    assert set(data.keys()) == {"error", "correlation_id"}, data
    assert data["error"] == AGENT_FACING_DENY_MESSAGE


def _last_deny_reason() -> Optional[str]:
    """Read the most-recently buffered WORM event's concrete ``deny_reason``."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=1)
    finally:
        reader.close()
    if not entries:
        return None
    _sid, fields = entries[0]
    record: Any = json.loads(fields["record"])
    reason = record["event"].get("deny_reason")
    return reason if isinstance(reason, str) else None


def _admin(idp: _DemoIdP, tenant_id: str = _TENANT) -> dict[str, str]:
    """Authorization header for a CAP_DIRECTORY_ADMIN principal in ``tenant_id``."""
    token = idp.mint(
        tenant_id=tenant_id,
        agent_id="agent-live-admin",
        capabilities=[CAP_DIRECTORY_ADMIN],
    )
    return {"Authorization": f"Bearer {token}"}


def _feed(client: TestClient, headers: dict[str, str]) -> list[dict[str, Any]]:
    """Fetch the recent-decisions feed (newest first) for the admin's tenant."""
    resp = client.get("/v1/admin/decisions/recent?limit=200", headers=headers)
    assert resp.status_code == 200, resp.text
    decisions: Any = _json(resp)["decisions"]
    assert isinstance(decisions, list)
    return [row for row in decisions if isinstance(row, dict)]


def _feed_row(client: TestClient, headers: dict[str, str], correlation_id: str) -> dict[str, Any]:
    """The feed row for one specific decision, located by its correlation id."""
    rows = [r for r in _feed(client, headers) if r.get("correlation_id") == correlation_id]
    assert len(rows) == 1, f"expected exactly one feed row for {correlation_id}"
    return rows[0]


def _query(
    client: TestClient, headers: dict[str, str], **params: Any
) -> dict[str, Any]:
    """One page of the date-ranged decision-history query (``GET /v1/admin/decisions``)."""
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    url = "/v1/admin/decisions" + (f"?{qs}" if qs else "")
    resp = client.get(url, headers=headers)
    assert resp.status_code == 200, resp.text
    data = _json(resp)
    assert isinstance(data["decisions"], list)
    return data


def _query_all(
    client: TestClient, headers: dict[str, str], **params: Any
) -> list[dict[str, Any]]:
    """Follow ``next_cursor`` to the end, returning every matching row (newest first)."""
    out: list[dict[str, Any]] = []
    cursor: Optional[str] = None
    for _ in range(1000):  # safety bound; the test stream is tiny.
        page = dict(params)
        if cursor is not None:
            page["cursor"] = cursor
        data = _query(client, headers, **page)
        out.extend(row for row in data["decisions"] if isinstance(row, dict))
        cursor = data["next_cursor"]
        if cursor is None:
            break
    return out


def _stream_id_for(correlation_id: str) -> tuple[str, int]:
    """The raw ``_EVENTS_STREAM`` id (and its millisecond part) for one decision."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=5000)
    finally:
        reader.close()
    for sid, fields in entries:
        record: Any = json.loads(fields["record"])
        if record.get("event", {}).get("correlation_id") == correlation_id:
            return str(sid), int(str(sid).split("-")[0])
    raise AssertionError(f"no stream entry for {correlation_id}")


# ---------------------------------------------------------------------------
# Decisions feed: event_id + worm_sequence, whitelist intact.
# ---------------------------------------------------------------------------


def test_feed_rows_carry_event_id_and_worm_sequence(client: TestClient, idp: _DemoIdP) -> None:
    """
    Every feed row carries the WORM ``event_id`` (a 32-hex uuid4 handle) and a positive
    ``worm_sequence`` — and NOTHING beyond the whitelist: the real target, the argument
    payload, and any step-up challenge id still never appear.
    """
    hdr = _admin(idp)

    # Drive one REAL allow and one REAL deny; key both by their correlation ids.
    ok = _post(client, alias=_AUTO_ALIAS, arguments={"period": "feed"}, token=idp.mint())
    assert ok.status_code == 200, ok.text
    allow_corr = str(_json(ok)["correlation_id"])
    denied = _post(client, alias="skill_no_such_thing", arguments={}, token=idp.mint())
    _assert_opaque_denial(denied)
    deny_corr = str(_json(denied)["correlation_id"])

    allow_row = _feed_row(client, hdr, allow_corr)
    deny_row = _feed_row(client, hdr, deny_corr)
    assert allow_row["decision"] == "allow" and allow_row["alias"] == _AUTO_ALIAS
    assert deny_row["decision"] == "deny" and deny_row["deny_reason"] == "unknown_alias"

    for row in (allow_row, deny_row):
        # Exact projection shape: the whitelist keys, always all present.
        assert set(row.keys()) == _FEED_KEYS, row
        for forbidden in _FORBIDDEN_FEED_KEYS:
            assert forbidden not in row
        # event_id is the emit-time uuid4 hex handle — 32 lowercase hex chars.
        event_id = str(row["event_id"])
        assert len(event_id) == 32 and all(c in "0123456789abcdef" for c in event_id)
        assert isinstance(row["worm_sequence"], int) and row["worm_sequence"] >= 1
        assert row["tenant_id"] == _TENANT

    # The two decisions are distinct events with distinct handles.
    assert allow_row["event_id"] != deny_row["event_id"]
    assert allow_row["worm_sequence"] != deny_row["worm_sequence"]


def test_feed_event_id_drives_real_inclusion_proof(client: TestClient, idp: _DemoIdP) -> None:
    """
    The console's per-row verify flow, end to end: take an ``event_id`` straight off
    the feed, seal the epoch, fetch ``/v1/audit/proof/{event_id}``, and verify the
    O(log n) Merkle path locally against the signed root — for the SAME decision.
    """
    hdr = _admin(idp)
    token = idp.mint()

    ok = _post(client, alias=_AUTO_ALIAS, arguments={"period": "proof-rt"}, token=token)
    assert ok.status_code == 200, ok.text
    corr = str(_json(ok)["correlation_id"])
    row = _feed_row(client, hdr, corr)
    event_id = str(row["event_id"])

    # Force an epoch close so the event is sealed under a signed root (sandbox).
    verify = client.get("/v1/audit/verify", headers={"Authorization": f"Bearer {token}"})
    assert verify.status_code == 200 and _json(verify)["intact"] is True

    # The proof surface is CAP_DIRECTORY_ADMIN-gated + tenant-scoped; use the admin
    # header (same tenant as the event), not the plain agent token that emitted it.
    proof_resp = client.get(f"/v1/audit/proof/{event_id}", headers=hdr)
    assert proof_resp.status_code == 200, proof_resp.text
    proof = _json(proof_resp)
    assert proof["event_id"] == event_id

    # Recompute the leaf from the sealed record and verify the Merkle path locally.
    path: list[tuple[str, str]] = [(str(s), str(h)) for s, h in proof["proof"]]
    included = merkle.verify_inclusion(
        merkle.leaf_digest(str(proof["record"]).encode("utf-8")),
        path,
        bytes.fromhex(str(proof["merkle_root"])),
    )
    assert included is True

    # The sealed record IS the decision the feed row projected.
    sealed: Any = json.loads(str(proof["record"]))
    assert sealed["event_id"] == event_id
    assert sealed["event"]["correlation_id"] == corr


# ---------------------------------------------------------------------------
# Decision HISTORY query: date-ranged, multi-filtered, cursor-paged (at scale).
# The same tenant-scoped whitelist projection as the live tail — just walkable.
# ---------------------------------------------------------------------------


def test_decisions_query_filters_and_paginates(client: TestClient, idp: _DemoIdP) -> None:
    """
    ``GET /v1/admin/decisions`` filters by whitelist facet and pages by cursor. A burst of
    known allows + denies is filtered by ``decision`` / ``alias``, and a ``limit=1`` cursor
    walk collects the IDENTICAL set as one big page — no duplicate, no gap.
    """
    hdr = _admin(idp)
    token = idp.mint()

    allow_corrs: list[str] = []
    for i in range(3):
        r = _post(client, alias=_AUTO_ALIAS, arguments={"period": f"q{i}"}, token=token)
        assert r.status_code == 200, r.text
        allow_corrs.append(str(_json(r)["correlation_id"]))
    deny_corrs: list[str] = []
    for _ in range(2):
        r = _post(client, alias="skill_absent_query", arguments={}, token=token)
        _assert_opaque_denial(r)
        deny_corrs.append(str(_json(r)["correlation_id"]))

    # Facet: decision=deny returns ONLY denies, and includes the two we just drove.
    denies = _query_all(client, hdr, decision="deny", limit=200)
    assert denies and all(row["decision"] == "deny" for row in denies)
    assert set(deny_corrs) <= {row["correlation_id"] for row in denies}

    # Facet: alias + decision=allow returns only our allows on that alias.
    allows = _query_all(client, hdr, alias=_AUTO_ALIAS, decision="allow", limit=200)
    assert allows and all(
        row["decision"] == "allow" and row["alias"] == _AUTO_ALIAS for row in allows
    )
    assert set(allow_corrs) <= {row["correlation_id"] for row in allows}

    # Cursor pagination (limit=1) collects the SAME filtered set — no dup, no gap.
    paged = _query_all(client, hdr, alias=_AUTO_ALIAS, decision="allow", limit=1)
    paged_seqs = [row["worm_sequence"] for row in paged]
    assert len(paged_seqs) == len(set(paged_seqs)), "cursor pages must not overlap"
    assert {row["worm_sequence"] for row in allows} == set(paged_seqs), "no page gap"
    # Newest-first ordering holds across the whole walk.
    assert paged_seqs == sorted(paged_seqs, reverse=True)


def test_decisions_query_is_tenant_scoped(client: TestClient, idp: _DemoIdP) -> None:
    """A decision in tenant-acme is queryable by acme's admin and INVISIBLE to globex's —
    the query rides the same per-tenant projection the live feed does."""
    acme = _admin(idp, _TENANT)
    globex = _admin(idp, "tenant-globex")
    token = idp.mint(tenant_id=_TENANT, agent_id="agent-scope-query")

    r = _post(client, alias=_AUTO_ALIAS, arguments={"period": "scope"}, token=token)
    assert r.status_code == 200, r.text
    corr = str(_json(r)["correlation_id"])

    acme_rows = _query_all(client, acme, limit=200)
    assert any(row["correlation_id"] == corr for row in acme_rows)
    assert all(row["tenant_id"] == _TENANT for row in acme_rows)

    globex_rows = _query_all(client, globex, limit=200)
    assert all(row["correlation_id"] != corr for row in globex_rows)
    assert all(row["tenant_id"] == "tenant-globex" for row in globex_rows)


def test_decisions_query_whitelist_and_requires_admin(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Every history row is the exact whitelist projection (no target/payload/secret), and
    the surface is CAP_DIRECTORY_ADMIN-gated + opaque-deny like every sibling admin read."""
    hdr = _admin(idp)
    r = _post(client, alias=_AUTO_ALIAS, arguments={"period": "wl"}, token=idp.mint())
    assert r.status_code == 200, r.text

    rows = _query_all(client, hdr, limit=50)
    assert rows, "expected at least one decision row"
    for row in rows:
        assert set(row.keys()) == _FEED_KEYS, row
        for forbidden in _FORBIDDEN_FEED_KEYS:
            assert forbidden not in row

    no_cap = idp.mint(tenant_id=_TENANT, agent_id="agent-nocap-query")
    _assert_opaque_denial(
        client.get("/v1/admin/decisions", headers={"Authorization": f"Bearer {no_cap}"})
    )
    assert client.get("/v1/admin/decisions").status_code == 403


def test_decisions_query_respects_time_window(client: TestClient, idp: _DemoIdP) -> None:
    """``from_ms``/``to_ms`` bound the walk by the decision's own stream-id millisecond:
    an upper bound below it excludes it; a lower bound at/below includes it; a lower bound
    above excludes it."""
    hdr = _admin(idp)
    r = _post(client, alias=_AUTO_ALIAS, arguments={"period": "window"}, token=idp.mint())
    assert r.status_code == 200, r.text
    corr = str(_json(r)["correlation_id"])
    _sid, ms = _stream_id_for(corr)

    def _present(**params: Any) -> bool:
        rows = _query_all(client, hdr, limit=200, **params)
        return any(row["correlation_id"] == corr for row in rows)

    assert not _present(to_ms=ms - 1), "upper bound below the decision must exclude it"
    assert _present(from_ms=ms), "lower bound at the decision must include it"
    assert not _present(from_ms=ms + 1), "lower bound above the decision must exclude it"


# ---------------------------------------------------------------------------
# Quarantine roster: freeze appears after a trip, is tenant-scoped, and expires.
# ---------------------------------------------------------------------------


def test_quarantine_roster_shows_tripped_agent_then_expires(
    client: TestClient, idp: _DemoIdP
) -> None:
    """
    Tripping a canary lands the agent on the admin's quarantine roster with the
    remaining freeze TTL; another tenant's admin never sees it; and when the Redis
    ``EX`` clock fires the roster clears and the agent authorizes again.
    """
    hdr = _admin(idp)
    agent_id = "agent-live-canary-trip"
    token = idp.mint(tenant_id=_TENANT, agent_id=agent_id)

    # Empty (for this agent) before the trip.
    before = _json(client.get("/v1/admin/quarantine", headers=hdr))["quarantined"]
    assert all(row["agent_id"] != agent_id for row in before)

    # Trip the decoy — opaque to the agent, concrete reason in WORM.
    tripped = _post(client, alias=_CANARY_ALIAS, arguments={"scope": "all"}, token=token)
    _assert_opaque_denial(tripped)
    assert _last_deny_reason() == "canary_tripped"

    # The roster now carries the frozen agent with a live, bounded countdown.
    roster = _json(client.get("/v1/admin/quarantine", headers=hdr))["quarantined"]
    rows = [row for row in roster if row["agent_id"] == agent_id]
    assert len(rows) == 1, roster
    ttl = rows[0]["ttl_seconds"]
    assert isinstance(ttl, int) and 0 < ttl <= QUARANTINE_TTL_SECONDS
    assert set(rows[0].keys()) == {"agent_id", "ttl_seconds"}

    # Tenant-scoped: another tenant's admin sees an empty roster, not this freeze.
    other = _json(client.get("/v1/admin/quarantine", headers=_admin(idp, "tenant-globex")))
    assert all(row["agent_id"] != agent_id for row in other["quarantined"])

    # Collapse the freeze TTL to 1ms — Redis EX is the quarantine clock, so this IS
    # expiry, just without waiting the operator-scale QUARANTINE_TTL_SECONDS.
    expire: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        assert expire.pexpire(f"mcpip:quarantine:{_TENANT}:{agent_id}", 1) == 1
    finally:
        expire.close()
    time.sleep(0.05)

    # Roster clears, and the agent is genuinely unfrozen end to end.
    after = _json(client.get("/v1/admin/quarantine", headers=hdr))["quarantined"]
    assert all(row["agent_id"] != agent_id for row in after)
    restored = _post(client, alias=_AUTO_ALIAS, arguments={"period": "thawed"}, token=token)
    assert restored.status_code == 200, restored.text


def test_quarantine_roster_requires_admin_cap(client: TestClient, idp: _DemoIdP) -> None:
    """The quarantine roster is capability-gated — no cap / no bearer → opaque 403."""
    no_cap = idp.mint(tenant_id=_TENANT, agent_id="agent-nocap-quarantine")
    _assert_opaque_denial(
        client.get("/v1/admin/quarantine", headers={"Authorization": f"Bearer {no_cap}"})
    )
    assert client.get("/v1/admin/quarantine").status_code == 403


# ---------------------------------------------------------------------------
# Canary roster: operator-only reveal; the agent boundary keeps hiding the flag.
# ---------------------------------------------------------------------------


def test_canary_roster_lists_seeded_decoys_for_own_tenant(
    client: TestClient, idp: _DemoIdP
) -> None:
    """
    The admin roster reveals exactly the seeded decoy rows (alias + risk/classification
    metadata, never a target), and a tenant seeded WITHOUT canaries reads honest-empty.
    """
    resp = client.get("/v1/admin/canaries", headers=_admin(idp))
    assert resp.status_code == 200, resp.text
    canaries: Any = _json(resp)["canaries"]
    assert isinstance(canaries, list)
    assert {row["alias"] for row in canaries} == {e.alias for e in CANARY_ALIASES}
    for row in canaries:
        assert set(row.keys()) == {"alias", "risk_tier", "classification"}
        assert row["risk_tier"] == "auto"  # bait fires on first touch — no step-up.
        assert "target" not in row  # the tripwire sink label never surfaces.

    # mcpip-inc is deliberately canary-free (operator opt-in control) — honest empty.
    clean = client.get("/v1/admin/canaries", headers=_admin(idp, "mcpip-inc"))
    assert clean.status_code == 200 and _json(clean)["canaries"] == []


def test_canary_roster_requires_admin_cap(client: TestClient, idp: _DemoIdP) -> None:
    """The canary roster is capability-gated — a plain agent token is opaque-denied."""
    no_cap = idp.mint(tenant_id=_TENANT, agent_id="agent-nocap-canaries")
    _assert_opaque_denial(
        client.get("/v1/admin/canaries", headers={"Authorization": f"Bearer {no_cap}"})
    )
    assert client.get("/v1/admin/canaries").status_code == 403


def test_agent_catalog_still_hides_canary_flag(client: TestClient, idp: _DemoIdP) -> None:
    """
    The AGENT-facing catalog is untouched by the operator reveal: decoys stay listed
    as ordinary bait, and neither the ``canary`` flag nor any target ever crosses.
    """
    token = idp.mint(tenant_id=_TENANT, agent_id="agent-live-catalog")
    resp = client.get("/v1/catalog", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    items: Any = _json(resp)["catalog"]
    names = {str(item["alias"]) for item in items}
    assert _CANARY_ALIAS in names  # bait is visible …
    for item in items:
        assert "canary" not in item  # … but the tripwire flag never leaks,
        assert "target" not in item  # and topology never surfaces.
