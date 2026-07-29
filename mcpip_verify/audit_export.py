"""
MCPIP audit export — read-only WORM extraction + independent chain verification.

``mcpip export-audit`` streams the durable WORM event buffer
(``mcpip:worm:events``) and the sealed epoch headers
(``HGETALL mcpip:worm:epoch:index``) out of Redis into a JSONL file:

  * one JSON line per event:
    ``{"seq", "event_id", "timestamp_ns", "record", "leaf_hash", "stream_id"}``
  * followed by one JSON line per sealed epoch header (as stored — contains
    ``epoch``, ``start_seq``, ``end_seq``, ``merkle_root``, ``epoch_hash`` …).

Strictly READ-ONLY: only ``XRANGE``/``HGETALL``/``GET`` are issued — nothing is
written to Redis, no locks are taken, no gateway state is touched. Events are
already redacted at write time; export adds no secrets.

``--verify`` re-runs the SAME five per-epoch checks the gateway's own
``WormLogger.verify_chain`` runs, offline and from the exported bytes, plus the
out-of-tamper-domain anchor watermark:

  1. **prev_epoch_hash linkage** — every epoch chains to its predecessor's
     ``epoch_hash`` (genesis, or a validly-signed super-checkpoint on a compacted
     chain), with strictly monotonic epoch numbers and contiguous ``seq``
     coverage, so a dropped, duplicated or reordered epoch is caught.
  2. **Merkle root** — recomputed via ``audit.merkle`` from the exported records
     (each leaf is also cross-checked against the stored ``leaf_hash``).
  3. **epoch_hash** — recomputed over EVERY persisted header field.
  4. **Ed25519 epoch signature** — verified against the operator-supplied WORM
     public key (``--pubkey``, the ``worm_signing_ed25519.pub.pem`` half of the
     key ceremony).
  5. **anchor low-watermark** — the fsync'd, out-of-tamper-domain anchor file
     (``--anchor-path``, defaulting beside ``MCPIP_WORM_PATH``) is enforced as a
     MONOTONIC watermark: a chain that stops SHORT of the highest validly-signed
     witnessed epoch is a rollback / tail-truncation, and a different
     ``epoch_hash`` at that epoch is a substitution. Both FAIL.

Fail-closed: a missing/unusable public key, an unparseable header, a missing
signature, a present-but-unverifiable super-checkpoint, or a partially-deleted
epoch is a FAILURE — never a silent pass. Epochs whose events were legitimately
retention-trimmed out of the hot buffer are verified SIGNATURE-ONLY against their
signed root (the retained tamper-evidence anchor) and are counted and NAMED
separately in the verdict, never folded into the "verified" count.

Deliberate scope note (honesty over false confidence): this tool takes no epoch
lock — that is what keeps it production-safe — so it cannot distinguish a
whole-epoch event deletion INSIDE the hot retention window from a trim that the
close daemon performed while the export was streaming. Epochs at/below the
retention watermark are therefore accepted signature-only; only the gateway's own
``verify_chain`` (which holds the epoch lock and reads the authoritative counter)
makes that distinction. Everything above the watermark demands FULL event
presence here, and a PARTIAL epoch is tamper at any depth.

The canonicalization rules below (epoch-hash core, super-checkpoint message,
anchor message) are implemented LOCALLY and mirror the producer in
``audit/worm_logger.py`` / ``audit/anchor.py`` byte-for-byte — the same
independent-verifier discipline ``core/integrity.py`` uses. Drift is mechanically
guarded by ``tests/test_audit_export_verify.py``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from audit.merkle import (
    _DOMAIN_EPOCH,
    _GENESIS_EPOCH_HASH,
    leaf_digest,
    merkle_root,
)
from audit.worm_logger import WORM_HOT_EPOCHS
from interfaces import canonical_json, constant_time_equals, sha256_hex
from mcpip_verify.verifier import VerificationError

_EVENTS_STREAM = "mcpip:worm:events"
_EPOCH_INDEX_KEY = "mcpip:worm:epoch:index"
_EPOCH_NUM_KEY = "mcpip:worm:epoch:num"
_SUPERCP_KEY = "mcpip:worm:supercp"
_PAGE = 1000

# Domain-separated bytes the super-checkpoint / anchor signatures commit to. Mirrors
# ``audit.worm_logger._DOMAIN_SUPERCP`` and ``audit.anchor._anchor_message``.
_DOMAIN_SUPERCP = b"MCPIP:WORM:SUPERCP:v1\x03"
_DOMAIN_ANCHOR = b"MCPIP:WORM:ANCHOR:v1\x00"

# Names of the checks the verdict reports — an operator must be able to read the
# output and know EXACTLY what was proven (and what was not).
CHECK_LINKAGE = "prev_epoch_hash linkage"
CHECK_MERKLE = "Merkle roots"
CHECK_EPOCH_HASH = "epoch_hash recomputation"
CHECK_SIGNATURE = "Ed25519 epoch signatures"
CHECK_ANCHOR = "anchor low-watermark"

# Every per-epoch check runs unconditionally once --verify is on; the anchor is the
# only one that can be absent (no anchor file), and its absence is NAMED, not hidden.
_EPOCH_CHECKS: tuple[str, ...] = (
    CHECK_LINKAGE,
    CHECK_MERKLE,
    CHECK_EPOCH_HASH,
    CHECK_SIGNATURE,
)

__all__ = [
    "ExportResult",
    "export_audit",
    "resolve_anchor_path",
    "CHECK_ANCHOR",
    "CHECK_EPOCH_HASH",
    "CHECK_LINKAGE",
    "CHECK_MERKLE",
    "CHECK_SIGNATURE",
]


@dataclass(frozen=True)
class ExportResult:
    """Outcome of an export (+ optional independent verification)."""

    events: int
    epochs: int
    verified_epochs: int
    # Epochs whose events are legitimately trimmed out of the hot buffer: verified
    # signature-only against their signed root, NEVER counted as fully verified.
    signature_only_epochs: int
    first_bad_epoch: Optional[int]
    # Which check failed (None when intact) — the operator triage signal
    # OPERATIONS.md promises: a signature failure is forgery/mutation, an anchor
    # failure is rollback/truncation.
    failed_check: Optional[str] = None
    # Checks actually performed / deliberately not performed, so the success line
    # can never imply a proof that was never computed.
    checks_performed: tuple[str, ...] = ()
    checks_not_performed: tuple[str, ...] = ()
    # Highest validly-signed epoch witnessed by the out-of-domain anchor (None when
    # no anchor file / no valid line was found).
    anchor_epoch: Optional[int] = None

    @property
    def intact(self) -> bool:
        return self.failed_check is None


@dataclass
class _Chain:
    """The read-only snapshot the verifier works from (nothing is instantiated)."""

    events: list[dict[str, object]] = field(default_factory=list)
    headers: list[dict[str, object]] = field(default_factory=list)
    supercp_raw: Optional[str] = None
    epoch_num_counter: int = -1
    anchor_head: Optional[tuple[int, str]] = None


class _Failure(Exception):
    """One verification failure: the named check + the epoch it broke at."""

    def __init__(self, check: str, epoch: Optional[int]) -> None:
        super().__init__(check)
        self.check = check
        self.epoch = epoch


# ---------------------------------------------------------------------------
# Canonicalization mirrors (byte-identical to the producer — see module docstring).
# ---------------------------------------------------------------------------


def _header_core(
    epoch: int,
    start_seq: int,
    end_seq: int,
    leaf_count: int,
    timestamp_ns: int,
    merkle_root_hex: str,
    prev_epoch_hash: str,
    first_stream_id: str,
    last_stream_id: str,
) -> dict[str, Any]:
    """The header fields the epoch_hash (and thus the signature) commit to."""
    return {
        "epoch": epoch,
        "start_seq": start_seq,
        "end_seq": end_seq,
        "leaf_count": leaf_count,
        "timestamp_ns": timestamp_ns,
        "merkle_root": merkle_root_hex,
        "prev_epoch_hash": prev_epoch_hash,
        "first_stream_id": first_stream_id,
        "last_stream_id": last_stream_id,
    }


def _supercp_message(epoch: int, epoch_hash: str, end_seq: int) -> bytes:
    """Canonical, domain-separated bytes the super-checkpoint signature commits to."""
    return _DOMAIN_SUPERCP + canonical_json(
        {"epoch": epoch, "epoch_hash": epoch_hash, "end_seq": end_seq}
    )


def _anchor_message(epoch: int, epoch_hash: str) -> bytes:
    """Canonical, domain-separated bytes the anchor signature commits to."""
    return _DOMAIN_ANCHOR + canonical_json({"epoch": epoch, "epoch_hash": epoch_hash})


# ---------------------------------------------------------------------------
# Read-only acquisition.
# ---------------------------------------------------------------------------


def resolve_anchor_path(explicit: Optional[str]) -> Path:
    """
    Where the out-of-tamper-domain anchor file lives, resolved exactly like the
    gateway resolves it (``app/main.py``): an explicit path wins, else
    ``MCPIP_WORM_ANCHOR_PATH``, else ``<MCPIP_WORM_PATH>.anchor``.
    """
    if explicit:
        return Path(explicit)
    configured = os.environ.get("MCPIP_WORM_ANCHOR_PATH")
    if configured:
        return Path(configured)
    return Path(os.environ.get("MCPIP_WORM_PATH", "./mcpip_worm.jsonl") + ".anchor")


def _load_public_key(public_key_pem: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:  # malformed PEM → fail closed.
        raise VerificationError("bad WORM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationError("bad WORM public key type")
    return key


def _read_anchor_head(
    path: Path, public_key: Ed25519PublicKey
) -> tuple[bool, Optional[tuple[int, str]]]:
    """
    Highest validly-signed ``(epoch, epoch_hash)`` witnessed by the anchor file.

    Mirrors ``AnchorStore._read_head``: a line that is malformed or whose Ed25519
    signature does not verify is IGNORED rather than fatal — an attacker who can
    append garbage must not be able to break (or lower) the watermark, and the
    maximum over the surviving validly-signed lines is exactly the low-watermark
    the gateway enforces. Returns ``(file_present, head)``.
    """
    if not path.exists():
        return False, None
    best: Optional[tuple[int, str]] = None
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            stripped = raw.strip()
            if not stripped:
                continue
            parsed = _parse_verified_anchor_line(stripped, public_key)
            if parsed is None:
                continue
            if best is None or parsed[0] > best[0]:
                best = parsed
    return True, best


def _parse_verified_anchor_line(
    line: str, public_key: Ed25519PublicKey
) -> Optional[tuple[int, str]]:
    try:
        record: Any = json.loads(line)
        if not isinstance(record, dict):
            return None
        epoch = record.get("epoch")
        epoch_hash = record.get("epoch_hash")
        signature = record.get("sig")
        if (
            not isinstance(epoch, int)
            or isinstance(epoch, bool)
            or not isinstance(epoch_hash, str)
            or not isinstance(signature, str)
        ):
            return None
        public_key.verify(
            bytes.fromhex(signature), _anchor_message(epoch, epoch_hash)
        )
    except (ValueError, TypeError, InvalidSignature):
        return None
    return epoch, epoch_hash


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


def _snapshot(client: Any) -> _Chain:
    """
    Read the chain in the ONE order that cannot manufacture a false tamper while
    the close daemon runs (this tool takes no lock, by design):

      * epoch HEADERS first, then EVENTS — an event is always XADD'd before the
        header that seals it, so events read afterwards are a superset of what any
        read header references (the ordering ``verify_chain`` uses under its lock);
      * the SUPER-CHECKPOINT after the headers — compaction writes the checkpoint
        BEFORE trimming the subsumed headers, so this order can only ever yield
        "checkpoint present + subsumed headers still there", which is skipped
        cleanly, never "headers already trimmed + no checkpoint" (a false gap);
      * the epoch counter LAST, and only ever to WIDEN the retention tolerance.
    """
    chain = _Chain()
    chain.headers = _fetch_epoch_headers(client)
    supercp = client.get(_SUPERCP_KEY)
    chain.supercp_raw = None if supercp is None else str(supercp)
    chain.events = _fetch_events(client)
    counter = client.get(_EPOCH_NUM_KEY)
    chain.epoch_num_counter = -1 if counter is None else int(counter)
    return chain


# ---------------------------------------------------------------------------
# Verification (pure — operates on the exported snapshot, instantiates no logger).
# ---------------------------------------------------------------------------


def _verify_super_checkpoint(
    raw: Optional[str], public_key: Ed25519PublicKey
) -> Optional[tuple[int, str, int]]:
    """
    The signed compaction anchor, or None when the chain was never compacted.

    Mirrors ``WormLogger._read_super_checkpoint``: present-but-unverifiable is
    TAMPER at the compaction anchor (fail closed), never a silent fall back to a
    genesis replay.
    """
    if raw is None:
        return None
    try:
        data: Any = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("super-checkpoint is not an object")
        epoch = int(data["epoch"])
        epoch_hash = str(data["epoch_hash"])
        end_seq = int(data["end_seq"])
        signature = str(data["signature"])
        public_key.verify(
            bytes.fromhex(signature), _supercp_message(epoch, epoch_hash, end_seq)
        )
    except (KeyError, ValueError, TypeError, InvalidSignature) as exc:
        raise _Failure(CHECK_SIGNATURE, 0) from exc
    return epoch, epoch_hash, end_seq


def _verify_header(
    header: dict[str, object],
    *,
    public_key: Ed25519PublicKey,
    expected_prev: str,
    expected_epoch: int,
    expected_start: int,
    by_seq: dict[int, dict[str, object]],
    trim_watermark: int,
) -> tuple[int, int, str, bool]:
    """
    Run checks 1–5 on ONE exported epoch header.

    Returns ``(epoch, end_seq, epoch_hash, signature_only)``; raises ``_Failure``
    naming the broken check otherwise. Deliberately the same order and the same
    tamper definition as ``WormLogger._verify_header_fields`` so the offline tool
    and the gateway can never disagree about what "intact" means.
    """
    try:
        epoch = int(cast("int | str", header["epoch"]))
        start_seq = int(cast("int | str", header["start_seq"]))
        end_seq = int(cast("int | str", header["end_seq"]))
        leaf_count = int(cast("int | str", header["leaf_count"]))
        timestamp_ns = int(cast("int | str", header["timestamp_ns"]))
        merkle_root_field = str(header["merkle_root"])
        prev_epoch_hash = str(header["prev_epoch_hash"])
        epoch_hash_field = str(header["epoch_hash"])
        signature = str(header["signature"])
        first_stream_id = str(header["first_stream_id"])
        last_stream_id = str(header["last_stream_id"])
    except (KeyError, ValueError, TypeError) as exc:
        # An unparseable/incomplete header is tamper, never a skip.
        raise _Failure(CHECK_EPOCH_HASH, expected_epoch) from exc

    # 1) Root-chain linkage + monotonic numbering + contiguous seq coverage. A
    #    dropped, duplicated or reordered epoch fails here even though every
    #    surviving Ed25519 signature still verifies.
    if not constant_time_equals(prev_epoch_hash, expected_prev):
        # Reported at the EXPECTED position (like verify_chain's ``next_epoch``): a
        # missing epoch breaks the link at the hole, not at the header that follows it.
        raise _Failure(CHECK_LINKAGE, expected_epoch)
    if epoch != expected_epoch or start_seq != expected_start:
        raise _Failure(CHECK_LINKAGE, expected_epoch)

    # 2) Merkle root over the exported records (leaf hashes recomputed, then
    #    cross-checked against the stored leaf_hash). A trimmed epoch has NO events
    #    and is verified signature-only; a PARTIAL epoch is tamper at any depth.
    span = end_seq - start_seq + 1
    present = [by_seq[s] for s in range(start_seq, end_seq + 1) if s in by_seq]
    signature_only = False
    if len(present) == leaf_count and span == leaf_count:
        leaves: list[bytes] = []
        for event in present:
            leaf = leaf_digest(str(event["record"]).encode("utf-8"))
            if not constant_time_equals(leaf.hex(), str(event["leaf_hash"])):
                raise _Failure(CHECK_MERKLE, epoch)  # stored leaf lies about the record.
            leaves.append(leaf)
        if not constant_time_equals(merkle_root(leaves).hex(), merkle_root_field):
            raise _Failure(CHECK_MERKLE, epoch)
    elif len(present) != 0 or epoch > trim_watermark:
        # Some (but not all) of a sealed epoch's events are missing/mutated, or an
        # epoch above the retention watermark has none at all.
        raise _Failure(CHECK_MERKLE, epoch)
    else:
        signature_only = True

    # 3) Recompute the epoch hash over EVERY persisted header field (including the
    #    signed stream-id range), then 4) verify the single Ed25519 signature over it.
    core = _header_core(
        epoch, start_seq, end_seq, leaf_count, timestamp_ns,
        merkle_root_field, prev_epoch_hash, first_stream_id, last_stream_id,
    )
    if not constant_time_equals(
        sha256_hex(_DOMAIN_EPOCH + canonical_json(core)), epoch_hash_field
    ):
        raise _Failure(CHECK_EPOCH_HASH, epoch)
    try:
        public_key.verify(bytes.fromhex(signature), bytes.fromhex(epoch_hash_field))
    except (InvalidSignature, ValueError) as exc:
        raise _Failure(CHECK_SIGNATURE, epoch) from exc
    return epoch, end_seq, epoch_hash_field, signature_only


def _verify_chain(chain: _Chain, public_key: Ed25519PublicKey) -> tuple[int, int]:
    """
    Replay the exported chain end to end; return ``(verified, signature_only)``.

    Raises ``_Failure`` naming the first broken check. Mirrors
    ``WormLogger._verify_epoch`` minus the in-tamper-domain counter cross-check
    (the counters share the tamper domain with the headers they would defend — the
    out-of-domain anchor below is the load-bearing rollback witness, and reading
    the counters without the epoch lock would only add false positives).
    """
    by_seq: dict[int, dict[str, object]] = {
        cast(int, ev["seq"]): ev for ev in chain.events
    }
    supercp = _verify_super_checkpoint(chain.supercp_raw, public_key)

    if supercp is None:
        cp_epoch = -1
        expected_prev = _GENESIS_EPOCH_HASH
        expected_start = 1  # INCR-based seq starts at 1.
        next_epoch = 0
        last_epoch_seen = -1
        anchor_witnessed: Optional[str] = None
    else:
        cp_epoch, cp_hash, cp_end_seq = supercp
        expected_prev = cp_hash
        expected_start = cp_end_seq + 1
        next_epoch = cp_epoch + 1
        last_epoch_seen = cp_epoch
        anchor_witnessed = (
            cp_hash
            if chain.anchor_head is not None and chain.anchor_head[0] == cp_epoch
            else None
        )

    # Highest epoch whose events may LEGITIMATELY have been retention-trimmed. Taken
    # from the exported headers OR the (untrusted) epoch counter, whichever is
    # higher: the counter can only ever WIDEN the tolerance, so a rewritten counter
    # buys an attacker nothing beyond the signature-only verification every trimmed
    # epoch already gets — while an honest chain whose daemon trimmed mid-export is
    # never reported as tampered.
    sealed_epochs = [
        int(cast("int | str", h["epoch"])) for h in chain.headers if "epoch" in h
    ]
    highest = max([*sealed_epochs, chain.epoch_num_counter, cp_epoch], default=-1)
    trim_watermark = highest - WORM_HOT_EPOCHS

    verified = 0
    signature_only = 0
    for header in chain.headers:
        if supercp is not None:
            # Headers subsumed by the signed checkpoint (a crash mid-compaction can
            # leave them behind) are already committed by it — skipping is sound.
            try:
                if int(cast("int | str", header["epoch"])) <= cp_epoch:
                    continue
            except (KeyError, ValueError, TypeError) as exc:
                raise _Failure(CHECK_EPOCH_HASH, next_epoch) from exc
        epoch, end_seq, epoch_hash, sig_only = _verify_header(
            header,
            public_key=public_key,
            expected_prev=expected_prev,
            expected_epoch=next_epoch,
            expected_start=expected_start,
            by_seq=by_seq,
            trim_watermark=trim_watermark,
        )
        expected_prev = epoch_hash
        expected_start = end_seq + 1
        last_epoch_seen = epoch
        if chain.anchor_head is not None and epoch == chain.anchor_head[0]:
            anchor_witnessed = epoch_hash
        next_epoch += 1
        if sig_only:
            signature_only += 1
        else:
            verified += 1

    # Out-of-tamper-domain anchor cross-check, as a MONOTONIC LOW-WATERMARK: the
    # surviving chain must reach AT LEAST the witnessed epoch carrying the identical
    # epoch_hash. Stopping SHORT is a rollback / truncation; a DIFFERENT hash at the
    # witnessed epoch is a substitution. A chain AHEAD of the anchor is legitimate —
    # the anchor is appended after the header, so it can lag by the newest epoch(s).
    if chain.anchor_head is not None:
        exp_epoch, exp_hash = chain.anchor_head
        if exp_epoch > last_epoch_seen:
            raise _Failure(CHECK_ANCHOR, exp_epoch)
        if exp_epoch > cp_epoch and (
            anchor_witnessed is None
            or not constant_time_equals(anchor_witnessed, exp_hash)
        ):
            raise _Failure(CHECK_ANCHOR, exp_epoch if exp_epoch >= 0 else 0)
    return verified, signature_only


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def export_audit(
    redis_url: str,
    out_path: Path,
    verify: bool,
    *,
    public_key_pem: Optional[bytes] = None,
    anchor_path: Optional[str] = None,
    require_anchor: bool = False,
) -> ExportResult:
    """
    Export the WORM stream + epoch headers to JSONL; optionally re-verify.

    ``verify`` REQUIRES ``public_key_pem`` (the WORM epoch key's public half): the
    epoch signatures are the whole point of the check, and a verdict computed
    without them would be a lie. ``require_anchor`` additionally makes a missing
    out-of-domain anchor file fatal, for continuous production checks that must
    never silently lose their rollback witness.
    """
    if verify and public_key_pem is None:
        raise VerificationError("verification requires the WORM public key")

    import redis  # local import: `mcpip verify` never touches redis.

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    public_key = _load_public_key(public_key_pem) if public_key_pem is not None else None

    # The anchor is read BEFORE the Redis snapshot on purpose: the gateway appends
    # the anchor line AFTER the in-Redis header is durable, so reading it first can
    # only leave the chain AHEAD of the watermark (legitimate), never behind it (a
    # false rollback).
    resolved_anchor = resolve_anchor_path(anchor_path)
    anchor_present = False
    anchor_head: Optional[tuple[int, str]] = None
    if verify and public_key is not None:
        anchor_present, anchor_head = _read_anchor_head(resolved_anchor, public_key)

    try:
        chain = _snapshot(client)
    finally:
        client.close()
    chain.anchor_head = anchor_head

    with out_path.open("w", encoding="utf-8") as fh:
        for ev in chain.events:
            fh.write(json.dumps(ev, separators=(",", ":"), sort_keys=True) + "\n")
        for header in chain.headers:
            fh.write(
                json.dumps(header, separators=(",", ":"), sort_keys=True) + "\n"
            )

    if not verify or public_key is None:
        return ExportResult(
            events=len(chain.events),
            epochs=len(chain.headers),
            verified_epochs=0,
            signature_only_epochs=0,
            first_bad_epoch=None,
        )

    performed = list(_EPOCH_CHECKS)
    not_performed: list[str] = []
    if anchor_head is not None:
        performed.append(CHECK_ANCHOR)
    else:
        why = (
            f"no validly-signed line in {resolved_anchor}"
            if anchor_present
            else f"no anchor file at {resolved_anchor}"
        )
        not_performed.append(f"{CHECK_ANCHOR} ({why})")

    if require_anchor and anchor_head is None:
        # The operator demanded the out-of-domain witness; without it a rollback
        # that also rewrote Redis would be invisible. Fail closed.
        return ExportResult(
            events=len(chain.events),
            epochs=len(chain.headers),
            verified_epochs=0,
            signature_only_epochs=0,
            first_bad_epoch=None,
            failed_check=f"{CHECK_ANCHOR} (required, but no signed watermark found)",
            checks_performed=tuple(performed),
            checks_not_performed=tuple(not_performed),
        )

    try:
        verified, signature_only = _verify_chain(chain, public_key)
    except _Failure as failure:
        return ExportResult(
            events=len(chain.events),
            epochs=len(chain.headers),
            verified_epochs=0,
            signature_only_epochs=0,
            first_bad_epoch=failure.epoch,
            failed_check=failure.check,
            checks_performed=tuple(performed),
            checks_not_performed=tuple(not_performed),
            anchor_epoch=anchor_head[0] if anchor_head is not None else None,
        )
    return ExportResult(
        events=len(chain.events),
        epochs=len(chain.headers),
        verified_epochs=verified,
        signature_only_epochs=signature_only,
        first_bad_epoch=None,
        failed_check=None,
        checks_performed=tuple(performed),
        checks_not_performed=tuple(not_performed),
        anchor_epoch=anchor_head[0] if anchor_head is not None else None,
    )
