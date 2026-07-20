"""
MCPIP audit export — read-only WORM extraction + independent Merkle re-check.

``mcpip export-audit`` streams the durable WORM event buffer
(``mcpip:worm:events``) and the sealed epoch headers
(``HGETALL mcpip:worm:epoch:index``) out of Redis into a JSONL file:

  * one JSON line per event:
    ``{"seq", "event_id", "timestamp_ns", "record", "leaf_hash", "stream_id"}``
  * followed by one JSON line per sealed epoch header (as stored — contains
    ``epoch``, ``start_seq``, ``end_seq``, ``merkle_root``, ``epoch_hash`` …).

Strictly READ-ONLY: only ``XRANGE`` and ``HGETALL`` are issued — nothing is
written to Redis, no locks are taken, no gateway state is touched. Events are
already redacted at write time; export adds no secrets.

``--verify`` recomputes each exported epoch's Merkle root from the exported
records via ``audit.merkle`` (leaf hashes are recomputed from the canonical
record bytes, then cross-checked against the stored ``leaf_hash``). Epochs
whose events were compacted out of the hot buffer are skipped (their roots
remain provable via the signed epoch chain + anchors, not this export).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, cast

from audit.merkle import leaf_digest, merkle_root

_EVENTS_STREAM = "mcpip:worm:events"
_EPOCH_INDEX_KEY = "mcpip:worm:epoch:index"
_PAGE = 1000

__all__ = ["ExportResult", "export_audit"]


@dataclass(frozen=True)
class ExportResult:
    """Outcome of an export (+ optional independent verification)."""

    events: int
    epochs: int
    verified_epochs: int
    skipped_epochs: int
    first_bad_epoch: Optional[int]

    @property
    def intact(self) -> bool:
        return self.first_bad_epoch is None


def _fetch_events(client: Any) -> list[dict[str, object]]:
    """Page XRANGE in blocks of _PAGE (read-only) into export-line dicts."""
    lines: list[dict[str, object]] = []
    lower = "-"
    while True:
        page = cast(
            "list[tuple[str, dict[str, str]]]",
            client.xrange(_EVENTS_STREAM, min=lower, max="+", count=_PAGE),
        )
        if not page:
            break
        for stream_id, fields in page:
            lines.append(
                {
                    "seq": int(fields["seq"]),
                    "event_id": fields["event_id"],
                    "timestamp_ns": int(fields["timestamp_ns"]),
                    "record": fields["record"],
                    "leaf_hash": fields["leaf_hash"],
                    "stream_id": stream_id,
                }
            )
        lower = "(" + page[-1][0]  # exclusive resume cursor.
        if len(page) < _PAGE:
            break
    return lines


def _fetch_epoch_headers(client: Any) -> list[dict[str, object]]:
    raw = cast("dict[str, str]", client.hgetall(_EPOCH_INDEX_KEY))
    headers: list[dict[str, object]] = []
    for num in sorted(raw, key=int):
        parsed = json.loads(raw[num])
        if isinstance(parsed, dict):
            headers.append(cast("dict[str, object]", parsed))
    return headers


def _verify_epochs(
    events: list[dict[str, object]], headers: list[dict[str, object]]
) -> tuple[int, int, Optional[int]]:
    """Recompute each epoch's Merkle root from exported records. Independent —
    no WormLogger state is instantiated; just ``audit.merkle`` over bytes."""
    by_seq: dict[int, dict[str, object]] = {
        cast(int, ev["seq"]): ev for ev in events
    }
    verified = 0
    skipped = 0
    first_bad: Optional[int] = None
    for header in headers:
        epoch_num = int(cast("int | str", header["epoch"]))
        start = int(cast("int | str", header["start_seq"]))
        end = int(cast("int | str", header["end_seq"]))
        span = [by_seq.get(seq) for seq in range(start, end + 1)]
        if any(ev is None for ev in span):
            skipped += 1  # compacted out of the hot buffer — not provable here.
            continue
        leaves: list[bytes] = []
        ok = True
        for ev in span:
            assert ev is not None
            leaf = leaf_digest(str(ev["record"]).encode("utf-8"))
            if leaf.hex() != str(ev["leaf_hash"]):
                ok = False  # stored leaf hash lies about the record.
                break
            leaves.append(leaf)
        if not ok or merkle_root(leaves).hex() != str(header["merkle_root"]):
            first_bad = epoch_num
            break
        verified += 1
    return verified, skipped, first_bad


def export_audit(redis_url: str, out_path: Path, verify: bool) -> ExportResult:
    """Export the WORM stream + epoch headers to JSONL; optionally re-verify."""
    import redis  # local import: `mcpip verify` never touches redis.

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    try:
        events = _fetch_events(client)
        headers = _fetch_epoch_headers(client)
    finally:
        client.close()

    with out_path.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev, separators=(",", ":"), sort_keys=True) + "\n")
        for header in headers:
            fh.write(
                json.dumps(header, separators=(",", ":"), sort_keys=True) + "\n"
            )

    verified = 0
    skipped = 0
    first_bad: Optional[int] = None
    if verify:
        verified, skipped, first_bad = _verify_epochs(events, headers)
    return ExportResult(
        events=len(events),
        epochs=len(headers),
        verified_epochs=verified,
        skipped_epochs=skipped,
        first_bad_epoch=first_bad,
    )
