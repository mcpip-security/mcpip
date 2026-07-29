"""
MCPIP — the SOC 2 report may understate a period. It may never overstate one.

    ◐ "A control report that quietly rounds 'what I could read' up to 'what happened'
       is worse than no report: it launders an unknown into an assertion."

`scripts/soc2_report.py` aggregates decision history for an audit period. Two ways it
could claim more coverage than it has, both real, both fixed here:

  * **Exhaustion was the DEFAULT.** ``coverage["terminated"]`` started at
    ``"exhausted"`` and only an error moved it. So any other termination — a page
    omitting ``next_cursor``, an empty batch mid-walk, an older gateway that never
    sends ``exhausted`` — inherited it, and the report printed "every record the
    durable buffer holds for this window is included" over a walk nothing had
    attested. Completeness is now asserted (``exhausted: true``) or it is
    ``cursor_lost``.

  * **Retention was ignored.** The event buffer is TRIMMED. Walking what remains to
    exhaustion says nothing about records evicted before the walk began, so a period
    starting before the oldest retained row is partially covered no matter how cleanly
    the paging ended. The gateway already returns ``retention_floor_ms`` — computed
    precisely to turn an empty page from "nothing happened" into "nothing I still
    hold" — and the report discarded it.

These tests drive ``fetch_history`` against a fake gateway, so each termination path is
exercised as the walker actually sees it.
"""

from __future__ import annotations

import pathlib
import sys
from typing import Any

import pytest

_REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "scripts"))

import soc2_report  # noqa: E402


def _row(index: int) -> dict[str, Any]:
    return {"decision": "allow", "worm_sequence": index}


class _Gateway:
    """Serves canned pages in order; records the params it was asked for."""

    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def __call__(self, base: str, path: str, token: str, params: dict[str, Any]) -> dict:
        self.calls.append(dict(params))
        return self.pages[min(len(self.calls) - 1, len(self.pages) - 1)]


@pytest.fixture
def serve(monkeypatch):
    def _install(pages: list[dict[str, Any]]) -> _Gateway:
        gateway = _Gateway(pages)
        monkeypatch.setattr(soc2_report, "_get", gateway)
        return gateway

    return _install


class TestCompletenessIsAssertedNotAssumed:
    def test_the_gateway_saying_exhausted_is_what_makes_it_exhausted(self, serve) -> None:
        serve([{"decisions": [_row(1)], "scanned": 1, "exhausted": True, "next_cursor": None}])
        rows, coverage = soc2_report.fetch_history("http://gw", "t", 0, 1)
        assert coverage["terminated"] == "exhausted"
        assert len(rows) == 1

    def test_a_missing_cursor_alone_does_NOT_mean_exhausted(self, serve) -> None:
        """The regression. This page proves nothing about the rest of the range.

        Before the fix it terminated as `exhausted` and the report stated the window
        was fully covered.
        """
        serve([{"decisions": [_row(1)], "scanned": 1, "next_cursor": None}])
        _, coverage = soc2_report.fetch_history("http://gw", "t", 0, 1)
        assert coverage["terminated"] == "cursor_lost"

    def test_an_empty_batch_mid_walk_does_not_mean_exhausted(self, serve) -> None:
        serve([{"decisions": [], "scanned": 0, "next_cursor": "1-0"}])
        _, coverage = soc2_report.fetch_history("http://gw", "t", 0, 1)
        assert coverage["terminated"] == "cursor_lost"

    def test_a_gateway_that_never_sends_the_field_is_indeterminate(self, serve) -> None:
        """An older gateway, or a proxy that drops an unknown key. Silence is not consent."""
        serve([{"decisions": [_row(1)], "scanned": 1, "next_cursor": ""}])
        _, coverage = soc2_report.fetch_history("http://gw", "t", 0, 1)
        assert coverage["terminated"] != "exhausted"

    def test_a_read_error_is_reported_as_an_error(self, serve) -> None:
        serve([{"__error__": "HTTP 403", "__path__": "/v1/admin/decisions"}])
        rows, coverage = soc2_report.fetch_history("http://gw", "t", 0, 1)
        assert coverage["terminated"] == "error"
        assert coverage["error"] and rows == []

    def test_the_page_cap_is_reported_as_truncation(self, serve, monkeypatch) -> None:
        monkeypatch.setattr(soc2_report, "MAX_PAGES", 3)
        serve([{"decisions": [_row(1)], "scanned": 1, "next_cursor": "1-0"}])
        _, coverage = soc2_report.fetch_history("http://gw", "t", 0, 1)
        assert coverage["terminated"] == "page_cap"
        assert coverage["pages"] == 3

    def test_paging_walks_until_the_gateway_asserts_the_end(self, serve) -> None:
        gateway = serve(
            [
                {"decisions": [_row(1)], "scanned": 1, "next_cursor": "9-0"},
                {"decisions": [_row(2)], "scanned": 1, "next_cursor": "8-0"},
                {"decisions": [_row(3)], "scanned": 1, "exhausted": True, "next_cursor": None},
            ]
        )
        rows, coverage = soc2_report.fetch_history("http://gw", "t", 0, 1)
        assert coverage["terminated"] == "exhausted"
        assert [r["worm_sequence"] for r in rows] == [1, 2, 3]
        assert coverage["scanned"] == 3
        assert gateway.calls[1]["cursor"] == "9-0", "the cursor must be threaded through"


class TestTheRetentionHorizonIsCarriedOut:
    """The completeness question paging cannot answer."""

    def test_the_floor_is_captured_from_the_pages(self, serve) -> None:
        serve(
            [
                {
                    "decisions": [_row(1)],
                    "scanned": 1,
                    "exhausted": True,
                    "next_cursor": None,
                    "retention_floor_ms": 1_700_000_000_000,
                }
            ]
        )
        _, coverage = soc2_report.fetch_history("http://gw", "t", 0, 1)
        assert coverage["retention_floor_ms"] == 1_700_000_000_000

    def test_an_absent_floor_stays_unknown_rather_than_zero(self, serve) -> None:
        """A confident zero would read as 'retained since the epoch' — the opposite."""
        serve([{"decisions": [], "scanned": 0, "exhausted": True, "next_cursor": None}])
        _, coverage = soc2_report.fetch_history("http://gw", "t", 0, 1)
        assert coverage["retention_floor_ms"] is None


class TestTheRenderedReportSaysWhatTheWalkFound:
    """Coverage must be legible in the artifact, not just in the data structure."""

    @staticmethod
    def _render(terminated: str, floor: object, from_ms: int = 1_700_000_000_000) -> str:
        report = {
            "generated_at": "2026-07-29T00:00:00Z",
            "gateway": "http://gw",
            "window": {
                "from_ms": from_ms,
                "to_ms": from_ms + 86_400_000,
                "from_iso": soc2_report._iso_ms(from_ms),
                "to_iso": soc2_report._iso_ms(from_ms + 86_400_000),
            },
            "tenant": "t",
            "version": "3.0.0",
            "license_tier": None,
            "license_id": None,
            "coverage": {
                "terminated": terminated,
                "pages": 1,
                "scanned": 1,
                "error": "denied" if terminated == "error" else None,
                "retention_floor_ms": floor,
            },
            "aggregate": soc2_report.aggregate([]),
            "attestation": None,
        }
        return soc2_report.render(report)

    def test_an_indeterminate_walk_is_labelled_a_lower_bound(self) -> None:
        text = self._render("cursor_lost", 1_600_000_000_000)
        assert "Indeterminate" in text and "LOWER BOUND" in text

    def test_a_trimmed_period_is_labelled_partially_retained(self) -> None:
        """The horizon sits AFTER the period start: the early window is gone."""
        text = self._render("exhausted", 1_700_000_000_000 + 3_600_000)
        assert "Partially retained" in text
        assert "signed epoch chain" in text

    def test_a_fully_retained_period_says_so_without_hedging(self) -> None:
        text = self._render("exhausted", 1_700_000_000_000 - 3_600_000)
        assert "no part of this window was trimmed" in text
        assert "Partially retained" not in text

    def test_an_unknown_horizon_is_never_silently_treated_as_covered(self) -> None:
        text = self._render("exhausted", None)
        assert "Unknown" in text
        assert "lower bound" in text
