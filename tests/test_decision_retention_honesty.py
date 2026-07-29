"""
MCPIP — the decision history must never report ignorance as absence.

    ◐ "'Nothing happened' and 'I no longer know' are opposite answers."

Decision rows are trimmed out of the hot buffer once their epoch falls outside
``WORM_HOT_EPOCHS``; the signed Merkle roots survive, the per-decision rows do not.
That trim is correct and deliberate — the buffer has to stay bounded.

What was NOT correct is what the query said afterwards. A range older than the buffer
returned ``{"decisions": [], "exhausted": True}`` — byte-identical to a range in which
genuinely nothing happened. An operator asking "what did this agent do last Tuesday?"
was told "nothing", confidently, when the truth was "those rows aged out".

For an audit product that is the worst class of wrong: not a missing feature, but a
confident false negative in the exact surface people rely on to prove what happened.
These tests pin the honest behaviour — the query now reports its horizon, so an empty
page can always be read correctly.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Namespaced sandbox env MUST be set before importing app.main — its composition root
# reads the lru_cached settings once, at import.
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/2")
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_retention_honesty_worm.jsonl"),
)

import asyncio

import pytest
import redis.asyncio as redis_async
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.worm_logger import WormLogger

from audit.worm_logger import _stream_id_ms


# ---------------------------------------------------------------------------
# The stream-id helper — the horizon comparison is only as good as this.
# ---------------------------------------------------------------------------


def test_stream_id_ms_parses_a_plain_id() -> None:
    assert _stream_id_ms("1737000000000-0") == 1737000000000


def test_stream_id_ms_tolerates_the_exclusive_cursor_prefix() -> None:
    """Resume cursors arrive as ``(<sid>``. If the prefix broke parsing we would silently
    treat every paged query as having an unknown horizon — the bug would come straight
    back on exactly the queries that page."""
    assert _stream_id_ms("(1737000000000-4") == 1737000000000


def test_stream_id_ms_returns_none_for_sentinels() -> None:
    """``-``/``+`` are unbounded. An unbounded window can never 'precede retention', so
    the horizon must read as UNKNOWN rather than as some numeric bound."""
    assert _stream_id_ms("+") is None
    assert _stream_id_ms("-") is None


def test_stream_id_ms_returns_none_for_garbage() -> None:
    """Unparseable input yields None so the caller reports an unknown horizon. Guessing
    here would reintroduce the exact over-confidence this whole change removes."""
    assert _stream_id_ms("") is None
    assert _stream_id_ms("not-an-id") is None


# ---------------------------------------------------------------------------
# The query contract — every return path carries the horizon.
#
# SELF-CONTAINED: this builds its OWN ledger on its own Redis db inside one event
# loop, rather than reusing the app's pooled client. That client is bound to whichever
# loop first touched it, so borrowing it across `asyncio.run` boundaries fails on a
# closed transport when another module ran first — a harness artifact that would make
# this gate flaky, and a flaky gate on an honesty property is worse than none.
# Emitting real events also means the retention floor genuinely exists, so the
# regression assertion actually FIRES instead of skipping.
# ---------------------------------------------------------------------------

_RETENTION_REDIS_URL = "redis://localhost:63790/13"


def test_query_never_reports_ignorance_as_absence(tmp_path) -> None:  # type: ignore[no-untyped-def]
    async def _probe() -> dict[str, dict[str, object]]:
        client = redis_async.Redis.from_url(_RETENTION_REDIS_URL, decode_responses=True)
        await client.flushdb()
        try:
            worm = WormLogger(
                client,
                Ed25519PrivateKey.generate(),
                path=str(tmp_path / "retention_worm.jsonl"),
            )
            # A real decision, so the ledger has a genuine retention floor to compare to.
            await worm.emit(
                {
                    "decision": "allow",
                    "alias": "skill_spend_summary",
                    "agent_id": "agent-retention-probe",
                    "correlation_id": "corr-retention-probe",
                    "tenant_id": "tenant-live",
                }
            )
            await worm.close_epoch()
            return {
                # An INVALID filter matches nothing because it is invalid. Blaming
                # retention would send an operator chasing a problem that does not exist.
                "bad_filter": await worm.query_decisions(
                    "tenant-live", filters={"not_a_real_field": frozenset({"x"})}
                ),
                # Unbounded spans all retained history, so emptiness is genuine absence.
                # Flagging it would cry wolf and train operators to ignore the real flag.
                "unbounded": await worm.query_decisions("tenant-absent", limit=1),
                # THE REGRESSION CASE: a window in 1970, older than anything we hold.
                "ancient": await worm.query_decisions(
                    "tenant-live", start_id="1-0", end_id="1000-0", limit=10
                ),
            }
        finally:
            await client.aclose()

    got = asyncio.run(_probe())

    # Both keys ride EVERY path — a field that is sometimes absent is a field consumers
    # learn to ignore.
    for name, result in got.items():
        assert "retention_floor_ms" in result, name
        assert "window_precedes_retention" in result, name
        assert result["decisions"] == [], name

    assert got["bad_filter"]["exhausted"] is True
    assert got["bad_filter"]["window_precedes_retention"] is False
    assert got["bad_filter"]["retention_floor_ms"] is None

    assert got["unbounded"]["window_precedes_retention"] is False

    floor = got["ancient"]["retention_floor_ms"]
    assert isinstance(floor, int) and floor > 1000, (
        "the probe emitted a real event, so a retention floor MUST exist — without it "
        "this gate would silently skip and stop guarding anything"
    )
    assert got["ancient"]["window_precedes_retention"] is True, (
        "a window older than the retention floor reported plain emptiness — an operator "
        "would read 'nothing happened' where the truth is 'those rows aged out'"
    )
