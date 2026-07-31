"""
MCPIP V2 — Audit: hybrid Merkle-epoch WORM (durable buffer → signed epoch roots).

    ◐ Audit: "Per-epoch Merkle root, root-chained and Ed25519-signed — O(log n) proofs."

The default ``mode="epoch"`` model replaces the per-event Ed25519 straight hash chain
with a HYBRID that scales signing from once-per-event to once-per-epoch while keeping
tamper-evidence total:

  (a) DURABLE BUFFER (write-before-execute). ``emit`` appends each redacted event to a
      crash-safe Redis Stream (``mcpip:worm:events``) BEFORE the caller authorizes the
      action, allocating the monotonic sequence number and doing the XADD inside ONE
      atomic Lua script (no separate INCR → no gap can ever open between the counter
      and the buffer, even across a crash). Production requires Redis AOF
      ``appendfsync always`` so the script is fsync-durable before it returns — every
      authorized decision's event is durable before any effect (fail-closed preserved).
      ``assert_persistence_posture`` enforces that at boot.
  (b) EPOCHS. ``close_epoch`` (a ~1s background daemon, or an explicit call for the
      demo/tests) reads only the UNSEALED tail after a stored stream cursor (O(epoch),
      never O(lifetime)), builds a Merkle tree over that epoch's events, chains the new
      epoch's Merkle root to the previous epoch's ``epoch_hash``, and Ed25519-SIGNS the
      new root — ONE signature per epoch, not per event. The leaf hashing + tree build run
      OFF the event loop (``asyncio.to_thread``) and a single close seals at most
      ``WORM_MAX_EPOCH_LEAVES`` leaves (the daemon drains any remainder in bounded chunks),
      so one close is O(cap) and never stalls in-flight authorize calls. After sealing it
      TRIMS events older than a retention window out of the hot buffer (the signed roots
      remain the durable tamper-evidence anchor), so Redis memory stays bounded.
  (b2) CHECKPOINT-COMPACTION. ``compact`` (periodically via ``maybe_compact``) folds every
      sealed epoch older than the newest ``WORM_CHECKPOINT_EPOCHS`` into ONE Ed25519-signed
      SUPER-CHECKPOINT committing to ``(epoch, epoch_hash, end_seq)``, then trims those
      epochs' headers/index/streamid and rotates the out-of-domain anchor file — bounding
      the otherwise-O(lifetime) header/stream/anchor growth AND the default full-verify cost
      to O(epochs since the last checkpoint). Fail-closed (pre-verifies before signing) and
      crash-safe (checkpoint written before headers are trimmed; ``verify_chain`` skips any
      still-present subsumed header, so a mid-compaction crash never yields a false tamper).
  (c) INCLUSION PROOFS. ``inclusion_proof`` returns a Merkle path from any
      still-buffered event to its signed epoch root. Proof VERIFICATION is O(log n)
      (recompute the root from the sibling path). Proof GENERATION reads the epoch's
      leaf-digest vector — a compact 32-byte-per-leaf list persisted at close (ONE
      HGET, no re-reading full event records and no re-hashing the epoch) — plus the
      single target event fetched directly by its stored stream id, then derives the
      O(log n) sibling path in memory. It never scans the whole epoch.

``verify_chain`` detects ANY tamper: a mutated event fails its epoch's recomputed
Merkle root; a mutated/removed/reordered/forged epoch header fails the signed
root-chain (linkage, recomputed ``epoch_hash``, or the Ed25519 signature); and —
critically — TAIL TRUNCATION / ROLLBACK (deleting the newest signed epoch(s) and their
events, even when the plaintext in-Redis linkage counters are ALSO rewritten back to a
prior still-valid epoch) is caught by an ``AnchorStore`` (``audit/anchor.py``): each
epoch close mirrors the signed head to an Ed25519-signed, fsync'd, append-only file
OUTSIDE the Redis tamper domain, and ``verify_chain`` enforces it as a monotonic
low-watermark — the surviving chain must reach at least the durably-witnessed epoch with
the identical ``epoch_hash``. The in-Redis counters remain a first-line cross-check for a
truncation that forgets to rewrite them, and a caller may still pass an explicit
``expected_head`` checkpoint. It returns ``(intact, first_bad_epoch)``.

CRASH-SAFETY ARGUMENT. An action is authorized only after ``emit`` returns, and
``emit`` returns only after its atomic INCR+XADD Lua script is durable on the
``appendfsync always`` stream — so no authorized decision's event can be lost
(write-before-execute) and the counter can never advance without a matching buffered
event (no seq gap). A crash between ``emit`` and the next epoch close loses only the
not-yet-signed root: on restart the daemon re-reads the unsealed tail from the durable
stream and closes the epoch deterministically (the Merkle root is a pure function of
the ordered leaves, so re-close is idempotent). Coverage is contiguous seq ranges, so
there is no inter-epoch gap even across crashes.

The legacy per-event chain remains available behind ``mode="per_event"`` for
migration (JSONL file, straight Ed25519 hash chain), but ``mode="epoch"`` is DEFAULT.

Secrets (raw PIN, raw JWT, tokens, passwords) are stripped by a recursive redaction
pass before anything is written, in BOTH modes.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Optional, cast

import redis.asyncio as redis
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from redis.exceptions import RedisError

from audit.anchor import AnchorStore
from audit.merkle import (
    _DOMAIN_EPOCH,
    _GENESIS_EPOCH_HASH,
    inclusion_proof as merkle_inclusion_proof,
    leaf_digest,
    merkle_root,
)
from interfaces import canonical_json, constant_time_equals, sha256_hex

# Atomic compare-and-delete release (standard Redlock release).
_RELEASE_LUA: str = (
    "if redis.call('GET', KEYS[1]) == ARGV[1] then "
    "return redis.call('DEL', KEYS[1]) else return 0 end"
)

# Atomic emit: allocate the monotonic seq AND append the event in ONE server-side
# script, so the counter can never advance without a matching buffered event (closes
# the INCR-then-XADD gap that could otherwise wedge epoch sealing forever). Returns
# ``{seq, stream_id}``. Hashing/signing stay in Python — the script only orders + stores.
_EMIT_LUA: str = (
    "local seq = redis.call('INCR', KEYS[1]) "
    "local sid = redis.call('XADD', KEYS[2], '*', "
    "'event_id', ARGV[1], 'seq', tostring(seq), 'timestamp_ns', ARGV[2], "
    "'record', ARGV[3], 'leaf_hash', ARGV[4]) "
    "return {seq, sid}"
)

# Atomic epoch-close COMMIT: append the signed header AND advance every linkage counter
# (epoch:num / :head / :last_seq / cursor) plus the header/streamid/eventloc/leaves indexes
# in ONE server-side script, so a crash mid-close either commits the WHOLE close or NONE of
# it. Without this atomicity a crash AFTER the header XADD but BEFORE the counter/cursor
# advance left a signed header on the epochs stream while the cursor still pointed at the
# unsealed tail: on restart close_epoch re-read the SAME tail and appended a SECOND header
# for the same epoch number (with a fresh timestamp_ns → different epoch_hash), permanently
# wedging verify_chain into a false-tamper it could never clear (non-idempotent re-close).
# With the commit atomic, a restart either finds the cursor already advanced (tail empty →
# close returns None, no dup) or finds it not advanced (re-seals the identical tail once).
# An additional anti-dup guard refuses to append a header for an epoch <= the already
# committed epoch:num (returns the stored streamid), so even a stray double-invocation
# cannot duplicate a header. Eventloc pairs are HSET in a loop (never `unpack`) so a large
# epoch can never hit Lua's argument-unpack ceiling.
#
# KEYS: 1 epochs-stream, 2 epoch-index, 3 epoch-streamid, 4 eventloc, 5 epoch-leaves,
#       6 epoch:num, 7 epoch:head, 8 epoch:last_seq, 9 cursor.
# ARGV: 1 epoch_num, 2 header_json, 3 leaves_json, 4 epoch_hash(head), 5 end_seq(last_seq),
#       6 last_stream_id(cursor), 7 X=count of XADD field/value tokens,
#       8..7+X XADD field,value,..., (8+X) E=count of eventloc field/value tokens,
#       (9+X)..(8+X+E) eventloc field,value,...
_CLOSE_COMMIT_LUA: str = (
    "local cur = tonumber(redis.call('GET', KEYS[6]) or '-1') "
    "local target = tonumber(ARGV[1]) "
    "if cur >= target then "
    "  return redis.call('HGET', KEYS[3], ARGV[1]) "
    "end "
    "local X = tonumber(ARGV[7]) "
    "local xf = {} "
    "for i = 1, X do xf[i] = ARGV[7 + i] end "
    "local sid = redis.call('XADD', KEYS[1], '*', unpack(xf)) "
    "redis.call('HSET', KEYS[2], ARGV[1], ARGV[2]) "
    "redis.call('HSET', KEYS[3], ARGV[1], sid) "
    "local ebase = 8 + X "
    "local E = tonumber(ARGV[ebase]) "
    "for i = 1, E, 2 do "
    "  redis.call('HSET', KEYS[4], ARGV[ebase + i], ARGV[ebase + i + 1]) "
    "end "
    "redis.call('HSET', KEYS[5], ARGV[1], ARGV[3]) "
    "redis.call('SET', KEYS[6], ARGV[1]) "
    "redis.call('SET', KEYS[7], ARGV[4]) "
    "redis.call('SET', KEYS[8], ARGV[5]) "
    "redis.call('SET', KEYS[9], ARGV[6]) "
    "return sid"
)

# --- Epoch-model Redis keys. ------------------------------------------------------
_SEQ_KEY = "mcpip:worm:seq"                    # INCR — monotonic event seq (from 1).
_EVENTS_STREAM = "mcpip:worm:events"           # durable event buffer (AOF fsync).
_EPOCHS_STREAM = "mcpip:worm:epochs"           # signed epoch headers (trimmed by compact).
_EVENTLOC_KEY = "mcpip:worm:eventloc"          # event_id -> "{epoch}|{index}|{stream_id}".
_EPOCH_NUM_KEY = "mcpip:worm:epoch:num"        # last closed epoch number.
_EPOCH_HEAD_KEY = "mcpip:worm:epoch:head"      # last epoch_hash (root-chain head).
_EPOCH_LAST_SEQ_KEY = "mcpip:worm:epoch:last_seq"  # last closed seq (coverage HWM).
_EPOCH_LOCK_KEY = "mcpip:worm:epoch:lock"      # serialize concurrent closes/verify.
_CURSOR_KEY = "mcpip:worm:cursor"              # last-sealed stream id (close cursor).
_EPOCH_INDEX_KEY = "mcpip:worm:epoch:index"    # epoch_num -> header JSON (O(1) proofs).
_EPOCH_LEAVES_KEY = "mcpip:worm:epoch:leaves"  # epoch_num -> JSON list of leaf-digest hex.
_EPOCH_STREAMID_KEY = "mcpip:worm:epoch:streamid"  # epoch_num -> epochs-stream entry id.
_SUPERCP_KEY = "mcpip:worm:supercp"            # signed super-checkpoint (ONE key, O(1)).

# Domain-separated bytes the super-checkpoint signature commits to. Distinct from the
# per-epoch and anchor domains so a checkpoint signature can never be replayed as an
# epoch or anchor signature.
_DOMAIN_SUPERCP: bytes = b"MCPIP:WORM:SUPERCP:v1\x03"

# Domain-separated bytes the WORM epoch key's public FINGERPRINT is derived over. This is
# an identifier (a hash of the PUBLIC key), never a secret and never a signature — it lets
# an external attestation verifier bind a returned epoch signature to a known WORM key.
_DOMAIN_KEYID: bytes = b"MCPIP:WORM:KEYID:v1\x04"

# --- Legacy per-event-mode Redis keys (migration). --------------------------------
_LAST_HASH_KEY = "mcpip:worm:last_hash"
_LOCK_KEY = "mcpip:worm:lock"
_GENESIS = "GENESIS"

# Every key the epoch/per-event model touches — the demo/tests reset exactly these.
ALL_WORM_KEYS: tuple[str, ...] = (
    _SEQ_KEY,
    _EVENTS_STREAM,
    _EPOCHS_STREAM,
    _EVENTLOC_KEY,
    _EPOCH_NUM_KEY,
    _EPOCH_HEAD_KEY,
    _EPOCH_LAST_SEQ_KEY,
    _EPOCH_LOCK_KEY,
    _CURSOR_KEY,
    _EPOCH_INDEX_KEY,
    _EPOCH_LEAVES_KEY,
    _EPOCH_STREAMID_KEY,
    _SUPERCP_KEY,
    _LAST_HASH_KEY,
    _LOCK_KEY,
)

# Bounded scan for the operator recent-decisions feed: read at most this many newest
# buffered events per call, then filter to the caller's tenant (a live-display tail, not
# the authoritative audit record — that stays the signed epoch chain).
_RECENT_DECISIONS_SCAN: int = 2000

# Operator decision-HISTORY query (date-ranged, multi-filtered, cursor-paged over the same
# tenant-scoped whitelist projection). These are internal READ-TUNING knobs, not request
# bounds (the caller-facing page cap MAX_DECISIONS_PAGE lives in interfaces.py): how deep
# the reverse walk goes to FILL one filtered page before yielding a resume cursor. Bounding
# _DECISIONS_QUERY_SCAN makes a single call O(budget) even when a tenant is sparse in a busy
# multi-tenant stream — the console keeps paging via the returned cursor.
_DECISIONS_QUERY_SCAN: int = 20000  # Max raw stream entries examined per query() call.
_DECISIONS_QUERY_BATCH: int = 500   # xrevrange COUNT per reverse-walk round.

# The strict WHITELIST projection shared by the live-tail feed (recent_decisions) and the
# date-ranged history query (query_decisions) — kept in ONE place so the two operator reads
# can never drift. Every key here is topology-free and secret-free (no target, no payload,
# no pin/otp); worm_sequence + event_id are the deliberate whitelist extensions the invariant
# documents. Adding a key here MUST be confirmed non-topology/non-secret before exposure.
_DECISION_SAFE_KEYS: tuple[str, ...] = (
    "correlation_id",
    "agent_id",
    "alias",
    "decision",
    "deny_reason",
    "transport",
    "risk_tier",
    "classification",
    "source_format",
    "transaction_ref",
    # Session identity of the caller — confirmed non-topology/non-secret: a UUID the
    # verified token asserted about ITSELF (which session of an agent acted). Names no
    # target, no payload, no pin/otp, and no other tenant's anything.
    "session_id",
)

# The alert projection for the off-hot-path deny-response playbook (``scan_alerts``) — a
# SUBSET of the operator whitelist above, deployment-wide (any tenant, since the operator
# runs the whole gateway). STILL strictly topology-free and secret-free: no target, no
# payload, no pin/otp. Adding a key here MUST be confirmed non-topology/non-secret before it
# can ride an external alert (Slack/email) or seed an automated response.
_ALERT_SAFE_KEYS: tuple[str, ...] = (
    "tenant_id",
    "agent_id",
    "alias",
    "decision",
    "deny_reason",
    "correlation_id",
)

# Background epoch-close cadence.
EPOCH_INTERVAL_S: float = 1.0

# Retention window: keep this many most-recent sealed epochs' events in the HOT buffer;
# trim older ones (their signed Merkle roots remain the durable tamper-evidence anchor).
# Bounds Redis memory to O(events in the last WORM_HOT_EPOCHS epochs) instead of O(all
# events ever). Chosen generously so the demo (a single epoch) and the API suite are
# never trimmed, yet a long-lived process cannot grow the buffer without bound.
WORM_HOT_EPOCHS: int = 32

# Per-close leaf cap: the Merkle build over an epoch is O(leaf count), so an unbounded
# unsealed tail (a daemon stall, a burst, or a forced close over a large backlog) would
# make one close's CPU work — and the loop time even when offloaded to a thread —
# proportional to the backlog. Sealing at most this many leaves per close makes every
# close O(cap)-bounded; the epoch daemon immediately closes again to drain the rest in
# bounded chunks. Chosen far above any single ~1s epoch's real leaf count so the demo
# and API suite always seal in one epoch.
WORM_MAX_EPOCH_LEAVES: int = 4096

# Checkpoint-compaction window: keep at least this many most-recent sealed epochs' signed
# HEADERS (plus their streamid/index) live in Redis; ``compact`` folds every older
# sealed-and-verified epoch into ONE Ed25519-signed super-checkpoint and trims their
# headers, so header/stream storage AND full-verify replay cost stay bounded to
# O(epochs since the last checkpoint) instead of O(lifetime). Well above the demo (1
# epoch) and the API suite so compaction never auto-fires there.
WORM_CHECKPOINT_EPOCHS: int = 128

# Keys whose values must NEVER reach the log, matched case-insensitively at every
# nesting level.
_REDACT_KEYS: frozenset[str] = frozenset(
    # Defence-in-depth: cloud_iam vended-credential fields are never placed in the audit
    # ctx to begin with (dispatch runs after the ALLOW record), but if any secret-bearing
    # key ever reaches this path it is scrubbed before persistence.
    {
        "pin",
        # The out-of-band step-up one-time code. By design the AuthenticatorNotice is
        # never merged into the audit ctx or the 202 response, but the field name now
        # exists (services/authn_channel.py), so redacting it here guarantees a stray
        # copy could never persist — same discipline as pin/jwt/token.
        "otp",
        "jwt",
        "token",
        "authorization",
        "password",
        "secret",
        "secret_access_key",
        "session_token",
        "access_token",
        "access_key_id",
        "_credential",
        # Vault broker-credential envelope + its common vendor value keys. The vault
        # endpoints never place these in the audit ctx (only metadata + fingerprint),
        # but redact them here so an accidental future inclusion still cannot persist.
        "material",
        "client_secret",
        "api_key",
        "private_key",
        "connection_string",
    }
)


def _is_secret_key(key: str) -> bool:
    """
    True if ``key`` names a secret-bearing field. Matches a token in ``_REDACT_KEYS`` as
    the WHOLE key or a separator-delimited SUFFIX (``-`` normalized to ``_``), so a
    vendor-prefixed variant — ``aws_secret_access_key``, ``gcp_private_key``,
    ``x-api-key`` — still redacts, WITHOUT over-redacting a benign field that merely
    contains a token substring. Critically, the operator-visible identifier ``secret_id``
    (emitted by the vault admin actions) does NOT match: it neither equals nor ends with
    ``_secret`` (or any other token), so the audit keeps the non-secret id while the
    actual credential material is scrubbed.
    """
    folded = key.casefold().replace("-", "_")
    return any(folded == token or folded.endswith("_" + token) for token in _REDACT_KEYS)


def _redact(obj: Any) -> Any:
    """Recursively replace sensitive keys' values with ``"[REDACTED]"`` before write."""
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for key, value in obj.items():
            if isinstance(key, str) and _is_secret_key(key):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = _redact(value)
        return cleaned
    if isinstance(obj, list):
        return [_redact(item) for item in obj]
    return obj


# ---------------------------------------------------------------------------
# Boot-time durability posture check (write-before-execute is only real if the
# buffer XADD is fsync-durable before authorize returns).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PersistencePosture:
    """The Redis persistence configuration relevant to WORM durability."""

    appendonly: str
    appendfsync: str
    # ``noeviction`` is Redis's default (while ``maxmemory=0``), so it defaults here
    # too — an operator who sets ``maxmemory`` with an eviction policy could otherwise
    # silently evict WORM buffer / replay-lock keys, which the durability contract
    # (and deploy/.env.production.example / GETTING_STARTED) forbid.
    maxmemory_policy: str = "noeviction"

    @property
    def is_durable(self) -> bool:
        """True iff AOF is fsync-per-write AND WORM/replay keys can never be evicted."""
        return (
            self.appendonly.lower() == "yes"
            and self.appendfsync.lower() == "always"
            and self.maxmemory_policy.lower() == "noeviction"
        )


async def read_persistence_posture(
    redis_client: "redis.Redis",
) -> PersistencePosture:
    """Read the running Redis's durability posture (AOF + eviction policy)."""
    ao: Any = await redis_client.config_get("appendonly")
    af: Any = await redis_client.config_get("appendfsync")
    mm: Any = await redis_client.config_get("maxmemory-policy")
    return PersistencePosture(
        appendonly=str(ao.get("appendonly", "no")) if isinstance(ao, dict) else "no",
        appendfsync=(
            str(af.get("appendfsync", "everysec")) if isinstance(af, dict) else "everysec"
        ),
        maxmemory_policy=(
            str(mm.get("maxmemory-policy", "noeviction")) if isinstance(mm, dict) else "noeviction"
        ),
    )


async def assert_persistence_posture(
    redis_client: "redis.Redis", *, require: bool
) -> PersistencePosture:
    """
    Verify the buffer's durability posture at boot.

    ``require=True`` (production / non-sandbox): refuse to boot unless AOF is enabled
    with ``appendfsync always`` — otherwise ``emit`` returns after only an in-memory
    write and a crash could lose an already-authorized action's audit event, violating
    write-before-execute. ``require=False`` (sandbox): log a loud advisory instead of
    failing, so the runnable demo/test still works against a throwaway Redis.
    """
    posture = await read_persistence_posture(redis_client)
    if posture.is_durable:
        return posture
    message = (
        "MCPIP WORM-DURABILITY: Redis persistence is "
        f"appendonly={posture.appendonly} appendfsync={posture.appendfsync} "
        f"maxmemory-policy={posture.maxmemory_policy}; "
        "write-before-execute requires appendonly=yes appendfsync=always and "
        "maxmemory-policy=noeviction so the audit buffer XADD is fsync-durable "
        "before /v1/authorize returns allow and WORM/replay keys are never evicted."
    )
    if require:
        raise RuntimeError(message)
    print(f"{message} (sandbox: continuing without durable AOF)", file=sys.stderr,
          flush=True)
    return posture


# ---------------------------------------------------------------------------
# Return / view models.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WormReceipt:
    """The append receipt returned by ``emit`` (callers may ignore it)."""

    seq: int
    event_id: str
    stream_id: str
    leaf_hash: str  # hex


@dataclass(frozen=True)
class EpochHeader:
    """A closed, signed epoch's header (the unit of the root chain)."""

    epoch: int
    start_seq: int
    end_seq: int
    leaf_count: int
    timestamp_ns: int
    merkle_root: str
    prev_epoch_hash: str
    epoch_hash: str
    signature: str
    first_stream_id: str
    last_stream_id: str


@dataclass(frozen=True)
class InclusionProof:
    """An O(log n) Merkle path from one event to its signed epoch root."""

    event_id: str
    epoch: int
    index: int
    record: str
    proof: list[tuple[str, str]]
    merkle_root: str
    epoch_hash: str
    signature: str


@dataclass(frozen=True)
class ProofScope:
    """
    The MEASURED window in which a per-event inclusion proof can actually be produced.

    A per-event proof is not a property of the ledger's whole lifetime. ``inclusion_proof``
    can only answer for an event whose epoch is BOTH sealed and still retained, because the
    two inputs it needs are written at close and dropped at trim:

      * the ``eventloc`` entry and the epoch's leaf-digest vector are written by the
        close-commit script — so an event in the CURRENT, still-open epoch has neither, and
      * ``_trim_retention`` deletes both (and XTRIMs the event out of the buffer) once its
        epoch falls more than ``WORM_HOT_EPOCHS`` behind the head.

    Outside that window the durable non-repudiation evidence is the signed epoch root chain
    (and, after compaction, the super-checkpoint): it commits to an epoch and its sequence
    RANGE, which is a different — and weaker — claim than a proof binding one event's exact
    bytes to a signed root. Compliance evidence has to state which of the two it is offering,
    so this reports the boundary as measured numbers rather than as prose.

    Every field is read-only and derived from live state; nothing here is a configured
    aspiration. ``proof_bearing_events`` is the exact population, not an estimate.
    """

    # Retention depth in sealed epochs (the configured bound the window is derived from).
    hot_epochs: int
    # Inclusive epoch range whose events can still yield a per-event proof (None = none can).
    oldest_proof_epoch: Optional[int]
    newest_proof_epoch: Optional[int]
    # Inclusive WORM sequence range covered by that epoch range (None when empty).
    first_proof_seq: Optional[int]
    last_proof_seq: Optional[int]
    # Exact count of events that can be proven individually right now.
    proof_bearing_events: int
    # Events durably emitted but not yet sealed into an epoch: recorded and covered by the
    # write-before-execute guarantee, but NOT yet individually provable.
    unsealed_events: int
    # Highest seq ever sealed. Events at or below it that fall outside the epoch range above
    # have aged out of per-event provability; the signed chain still covers them.
    sealed_through_seq: Optional[int]


@dataclass(frozen=True)
class WormAttestation:
    """
    A portable, signed snapshot of the CURRENT audit state (read-only).

    Every signed field was Ed25519-signed by the WORM epoch key at epoch close (the epoch
    header) or anchor append (the low-watermark) — producing an attestation MINTS NO KEY
    and SIGNS NOTHING NEW. ``signing_key_id`` is a public, non-secret fingerprint of the
    WORM public key so an external verifier can bind the epoch ``signature`` to a key it
    already trusts. No hidden target, payload, PIN/OTP, or other secret appears here — the
    same signed commitments ``/v1/audit/proof`` already surfaces, plus the ``/v1/audit/
    verify`` result and the anchor head. The epoch fields are ``None`` before the first
    epoch has been sealed (an honest empty state, never a fabricated header).
    """

    # Latest SEALED epoch header (None when no epoch has closed yet).
    epoch: Optional[int]
    end_seq: Optional[int]
    merkle_root: Optional[str]
    epoch_hash: Optional[str]
    signature: Optional[str]
    # Public fingerprint of the WORM Ed25519 epoch key (always present).
    signing_key_id: str
    # Fresh ``verify_chain`` result over the whole signed chain.
    intact: bool
    first_bad_epoch: Optional[int]
    # Out-of-tamper-domain anchor low-watermark (None when no anchor is configured or
    # nothing has been witnessed yet).
    anchor_epoch: Optional[int]
    anchor_epoch_hash: Optional[str]


# The header fields that the epoch_hash (and thus the signature) commit to. EVERY
# persisted header field is signed — including the stream-id range (first_stream_id /
# last_stream_id) that indexes the epoch's events in the buffer. Signing the stream-id
# range makes those fields tamper-evident too: mutating either one changes the
# recomputed epoch_hash, which then fails both the stored-hash compare and the Ed25519
# signature (they are not re-signable without the private key). A header field left OUT
# of this core would be silently mutable, so nothing persisted may be omitted here.
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


class _SuperCheckpointInvalid(Exception):
    """A super-checkpoint key is present but malformed or its signature does not verify.

    Distinct from "absent" (a fresh, never-compacted chain): a present-but-unverifiable
    super-checkpoint is TAMPER at the compaction anchor and verify must fail closed, not
    silently fall back to a genesis replay.
    """


def _supercp_message(epoch: int, epoch_hash: str, end_seq: int) -> bytes:
    """Canonical, domain-separated bytes the super-checkpoint signature commits to."""
    return _DOMAIN_SUPERCP + canonical_json(
        {"epoch": epoch, "epoch_hash": epoch_hash, "end_seq": end_seq}
    )


def _hash_epoch_leaves(records: list[str]) -> tuple[list[bytes], bytes]:
    """
    Pure CPU work: domain-separated leaf digests + the Merkle root over them.

    Factored out so ``close_epoch`` can run it OFF the serving event loop via
    ``asyncio.to_thread`` — the O(leaf count) hashing/tree build no longer blocks
    in-flight ``/v1/authorize`` calls while an epoch seals.
    """
    leaves = [leaf_digest(rec.encode("utf-8")) for rec in records]
    return leaves, merkle_root(leaves)


# ---------------------------------------------------------------------------
# Opt-in at-rest CONFIDENTIALITY for the WORM event body (SOC 2 C1.1).
#
# The chain is INTEGRITY-protected (Merkle/Ed25519) but the event body — the resolved
# real target, the alias, and identifiers — is otherwise cleartext in Redis + AOF. With a
# ``content_key`` the SENSITIVE ``event`` payload is wrapped in an AES-256-GCM envelope
# BEFORE it enters ``record_core``; the leaf still hashes the whole ``record_core`` (now
# containing the envelope string), so ``verify_chain`` — which hashes the STORED bytes —
# is byte-for-byte UNAFFECTED and remains verifiable WITHOUT the key. The signed
# commitments (event_id / timestamp / merkle root / epoch signature) stay in cleartext, so
# an auditor can still prove chain integrity offline; only READING the body needs the key.
# Destroy the key ⇒ the bodies are crypto-shredded while the integrity proof survives.
# Default OFF (``content_key is None``) ⇒ the body is the plaintext dict, byte-identical.
_WORM_ENC_PREFIX = "encv1:"
_WORM_ENC_AAD = b"mcpip-worm-event/1"  # domain separation; positional binding is the Merkle chain.


def _encrypt_worm_event(event: dict[str, Any], key: bytes) -> str:
    """Wrap the event payload in a self-describing AES-256-GCM envelope (base64)."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, canonical_json(event), _WORM_ENC_AAD)
    return _WORM_ENC_PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def _decrypt_worm_event(
    value: Any, key: Optional[bytes], fallbacks: tuple[bytes, ...] = ()
) -> Any:
    """Inverse of ``_encrypt_worm_event`` — a NO-OP on a plaintext dict (off/legacy).

    Returns the decrypted event dict for an ``encv1:`` envelope when a usable key is
    present; a plaintext dict is passed through unchanged; and if the value is an envelope
    but no key is available the opaque envelope string is returned as-is (integrity is
    intact and verifiable, the body simply cannot be read — the intended confidentiality
    boundary).

    ``fallbacks`` are RETIRED content keys retained across a key rotation. The active
    ``key`` seals every new event and is tried first; each fallback is then tried in turn,
    so a body sealed under a superseded key stays readable after the active key rotates
    (newest key seals; any retained key can read). If the value IS an envelope and no
    supplied key can open it, the AES-GCM error is re-raised — a loud signal that the
    sealing key was neither retained nor supplied, never a silent unreadable pass-through.
    """
    if not isinstance(value, str) or not value.startswith(_WORM_ENC_PREFIX):
        return value
    candidates = tuple(k for k in (key, *fallbacks) if k is not None)
    if not candidates:
        return value
    blob = base64.b64decode(value[len(_WORM_ENC_PREFIX):])
    nonce, ct = blob[:12], blob[12:]
    for candidate in candidates:
        try:
            return json.loads(AESGCM(candidate).decrypt(nonce, ct, _WORM_ENC_AAD))
        except InvalidTag:  # wrong key for THIS envelope — try the next retained key
            continue
    raise InvalidTag(
        "no content key (active or retained) could decrypt the WORM event body"
    )


def _stream_id_ms(stream_id: str) -> Optional[int]:
    """Millisecond component of a Redis stream id, tolerating the ``(`` exclusive prefix.

    Returns None for a sentinel (``-``/``+``) or anything unparseable — callers then treat
    the horizon as unknown rather than guessing, which is the whole point of the field.
    """
    raw = stream_id[1:] if stream_id.startswith("(") else stream_id
    head = raw.split("-", 1)[0]
    try:
        return int(head)
    except (TypeError, ValueError):
        return None


class WormLogger:
    """Append-only, tamper-evident audit sink (hybrid Merkle-epoch by default)."""

    def __init__(
        self,
        redis_client: "redis.Redis",
        private_key: Ed25519PrivateKey,
        *,
        path: Optional[str] = None,
        mode: str = "epoch",
        anchor: Optional[AnchorStore] = None,
        wait_replicas: int = 0,
        wait_timeout_ms: int = 2000,
        content_key: Optional[bytes] = None,
        content_key_fallbacks: tuple[bytes, ...] = (),
    ) -> None:
        if mode not in ("epoch", "per_event"):
            raise ValueError("mode must be 'epoch' or 'per_event'")
        if wait_replicas < 0:
            raise ValueError("wait_replicas must be >= 0")
        if wait_timeout_ms <= 0:
            raise ValueError("wait_timeout_ms must be > 0")
        if content_key_fallbacks and content_key is None:
            # A retired key with no active key can never SEAL — a misconfiguration.
            raise ValueError("content_key_fallbacks require an active content_key")
        self._redis = redis_client
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()
        self._mode = mode
        resolved_path: str = path if path else os.environ.get(
            "MCPIP_WORM_PATH", "./mcpip_worm.jsonl"
        )
        self._path = Path(resolved_path)
        # Out-of-tamper-domain signed head anchor. When configured, every epoch close
        # mirrors the new signed head to durable local storage the Redis attacker cannot
        # rewrite, and verify_chain consults it as a monotonic low-watermark so a
        # tail-truncation / rollback that ALSO rewrites the in-Redis counters is caught
        # (finding: anchorless verify + counters in the tamper domain).
        self._anchor = anchor
        # Opt-in synchronous-replication quorum (SOC 2 A1.2): with
        # ``wait_replicas`` > 0, every emit additionally requires that many Redis
        # replicas acknowledge the write (WAIT) BEFORE the authorize proceeds — the
        # write-before-execute durability contract extended across a replica, so a
        # master loss + replica promotion can never drop an acked audit record. 0 (the
        # default) issues no WAIT at all: byte-identical single-node behavior. Scope is
        # deliberately the EVENT EMIT only — the one correctness-critical write. Epoch
        # headers are crash-recoverable (a re-close re-seals the identical tail), and
        # every other Redis datum (payload locks, grants, counters) fails CLOSED when
        # lost, so extending WAIT to them would buy latency, not safety.
        self._wait_replicas = wait_replicas
        self._wait_timeout_ms = wait_timeout_ms
        # Opt-in at-rest confidentiality for the event body (SOC 2 C1.1). None
        # (default) ⇒ the body is the plaintext dict, byte-identical to today. Set ⇒ the
        # ``event`` payload is AES-256-GCM-wrapped before it enters ``record_core``, so the
        # Merkle leaf (over the whole record) and verify_chain are UNAFFECTED and the chain
        # stays verifiable without the key; only reading the body needs it. Rotation:
        # ``content_key`` always seals; ``content_key_fallbacks`` are RETIRED keys retained
        # so bodies sealed under a superseded key stay readable on the operator reads (the
        # active key is tried first, then each fallback). Empty ⇒ single-key behavior.
        self._content_key = content_key
        self._content_key_fallbacks = content_key_fallbacks
        self._release_script = redis_client.register_script(_RELEASE_LUA)
        self._emit_script = redis_client.register_script(_EMIT_LUA)
        self._close_commit_script = redis_client.register_script(_CLOSE_COMMIT_LUA)
        self._epoch_task: Optional[asyncio.Task[None]] = None

    # ------------------------------------------------------------------ emit

    async def emit(self, event: dict[str, Any]) -> WormReceipt:
        """
        Durably append one redacted event to the buffer; return its receipt.

        Epoch mode: compute the domain-separated leaf hash over the canonical record
        bytes ONCE (safe-win reuse), then allocate the seq and XADD atomically in one
        Lua script — the counter never advances without a matching buffered event, so no
        gap can ever wedge sealing. Per-event mode: the legacy signed JSONL chain append.
        """
        redacted = _redact(event)
        if self._mode == "per_event":
            return await self._emit_per_event(redacted)

        event_id = uuid.uuid4().hex
        ts = time.time_ns()
        # The signed leaf commits to event_id + timestamp + payload. The seq is a
        # stream-side ordering/coverage datum (allocated atomically with the XADD), so it
        # is NOT part of the hashed record — that lets the seq be assigned server-side.
        record_core = {
            "event_id": event_id,
            "timestamp_ns": ts,
            # Opt-in at-rest confidentiality: the sensitive payload is wrapped in a
            # self-describing AES-GCM envelope when a content key is set. The leaf below
            # commits to record_core AS STORED (envelope string), so verify_chain is
            # unaffected. None ⇒ the plaintext dict, byte-identical.
            "event": (
                _encrypt_worm_event(redacted, self._content_key)
                if self._content_key is not None
                else redacted
            ),
        }
        canonical = canonical_json(record_core)           # computed ONCE.
        leaf_hash = leaf_digest(canonical).hex()          # domain-separated leaf.
        raw: Any = await self._emit_script(
            keys=[_SEQ_KEY, _EVENTS_STREAM],
            args=[event_id, str(ts), canonical.decode("utf-8"), leaf_hash],
        )
        seq = int(raw[0])
        stream_id = str(raw[1])
        await self._enforce_replica_quorum()
        return WormReceipt(
            seq=seq, event_id=event_id, stream_id=stream_id, leaf_hash=leaf_hash
        )

    async def _enforce_replica_quorum(self) -> None:
        """
        Enforce the opt-in synchronous-replication quorum on an emitted event.

        No-op when ``wait_replicas`` is 0 (the default). Otherwise issue a Redis
        ``WAIT`` and FAIL CLOSED (raise) unless at least that many replicas have
        acknowledged the just-committed write within the timeout — the emit then
        counts as NOT durable, the receipt is never returned, and the authorize
        denies rather than proceed on an audit record a failover could lose. The
        raise surfaces as the same opaque deny any emit failure produces.
        """
        if self._wait_replicas <= 0:
            return
        acked_raw: Any = await self._redis.execute_command(
            "WAIT", self._wait_replicas, self._wait_timeout_ms
        )
        acked = int(acked_raw)
        if acked < self._wait_replicas:
            raise RuntimeError(
                "WORM replica quorum not met: "
                f"{acked}/{self._wait_replicas} replicas acknowledged within "
                f"{self._wait_timeout_ms}ms — refusing to treat the emit as durable"
            )

    # ------------------------------------------------------------------ epochs

    def start_epoch_daemon(self) -> "asyncio.Task[None]":
        """Launch the ~1s background epoch closer (idempotent)."""
        if self._epoch_task is None or self._epoch_task.done():
            self._epoch_task = asyncio.create_task(self._epoch_loop())
        return self._epoch_task

    async def stop_epoch_daemon(self) -> None:
        """Cancel + await the daemon for a clean shutdown."""
        task = self._epoch_task
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        self._epoch_task = None

    async def _epoch_loop(self) -> None:
        """Close an epoch every ``EPOCH_INTERVAL_S``; never crash on transient error."""
        try:
            while True:
                try:
                    header = await self.close_epoch()
                    # Drain a backlog promptly: a close that hit the per-close leaf cap
                    # very likely left more buffered events, so seal the next bounded
                    # chunk immediately instead of waiting a whole interval — each close
                    # stays O(cap) AND proof latency stays bounded under bursts.
                    if header is not None and header.leaf_count >= WORM_MAX_EPOCH_LEAVES:
                        continue
                    # Periodic checkpoint-compaction folds fully-verified old epochs into
                    # ONE signed super-checkpoint and trims their headers, bounding steady
                    # -state Redis/header storage and full-verify cost. A cheap no-op until
                    # the chain is > WORM_CHECKPOINT_EPOCHS long.
                    await self.maybe_compact()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 — advisory; keep the loop alive.
                    print(
                        f"MCPIP WORM-EPOCH-CLOSE-ERROR {type(exc).__name__}",
                        file=sys.stderr,
                        flush=True,
                    )
                await asyncio.sleep(EPOCH_INTERVAL_S)
        except asyncio.CancelledError:
            return

    async def close_epoch(self) -> Optional[EpochHeader]:
        """
        Force-close the pending epoch NOW; None if there are no pending events.

        Deterministic (used directly by the demo/tests). Runs under a short Redis lock
        so concurrent nodes never double-close. Reads ONLY the unsealed tail after the
        stored stream cursor (O(epoch size), never O(lifetime)), seals every buffered
        event in strict stream/seq order (atomic emit guarantees the tail is a gapless
        seq run, so sealing never wedges), signs the root, indexes the header, and trims
        events that have fallen out of the retention window.
        """
        async with self._epoch_lock():
            last_seq = int(await self._redis.get(_EPOCH_LAST_SEQ_KEY) or 0)
            cursor = await self._redis.get(_CURSOR_KEY)

            # Read only the unsealed tail (everything strictly after the cursor).
            if cursor:
                entries: Any = await self._redis.xrange(
                    _EVENTS_STREAM, min="(" + str(cursor), max="+"
                )
            else:
                entries = await self._redis.xrange(_EVENTS_STREAM)

            pending: list[tuple[int, str, str, str]] = []  # (seq, record, eid, sid)
            for sid, fields in entries:
                seq = int(fields["seq"])
                if seq > last_seq:
                    pending.append(
                        (seq, str(fields["record"]), str(fields["event_id"]), str(sid))
                    )
            pending.sort(key=lambda p: p[0])
            if not pending:
                return None

            # Bound this close to at most WORM_MAX_EPOCH_LEAVES leaves — seal a PREFIX of
            # the (contiguous) tail so one close's Merkle build stays O(cap) regardless of
            # backlog; the cursor advances only to the last SEALED event, so the daemon
            # drains the remainder in bounded chunks on the next tick(s).
            if len(pending) > WORM_MAX_EPOCH_LEAVES:
                pending = pending[:WORM_MAX_EPOCH_LEAVES]

            # Hash the leaves + build the Merkle root OFF the event loop so the O(leaf
            # count) CPU work does not stall in-flight authorize calls (the Redis epoch
            # lock is still held — this only frees the loop, never the cross-node lock).
            records = [rec for _s, rec, _e, _sid in pending]
            leaves, root = await asyncio.to_thread(_hash_epoch_leaves, records)
            start_seq = pending[0][0]
            end_seq = pending[-1][0]
            leaf_count = len(pending)
            first_stream_id = pending[0][3]
            last_stream_id = pending[-1][3]
            if end_seq - start_seq + 1 != leaf_count:
                # Should be impossible with atomic emit; surface loudly but still SEAL
                # (never wedge) so later events keep getting sealed — the gap is left
                # visible for verify_chain to flag rather than silently halting sealing.
                print(
                    "MCPIP WORM-SEQ-GAP "
                    f"start={start_seq} end={end_seq} count={leaf_count} "
                    "(non-contiguous tail sealed; verify_chain will flag the gap)",
                    file=sys.stderr,
                    flush=True,
                )
            prev = await self._redis.get(_EPOCH_HEAD_KEY) or _GENESIS_EPOCH_HASH
            epoch_num = int(await self._redis.get(_EPOCH_NUM_KEY) or -1) + 1
            ts = time.time_ns()

            core = _header_core(
                epoch_num, start_seq, end_seq, leaf_count, ts, root.hex(), prev,
                first_stream_id, last_stream_id,
            )
            epoch_hash = sha256_hex(_DOMAIN_EPOCH + canonical_json(core))
            signature = self._private_key.sign(bytes.fromhex(epoch_hash)).hex()

            persisted: dict[str, str] = {
                "epoch": str(epoch_num),
                "start_seq": str(start_seq),
                "end_seq": str(end_seq),
                "leaf_count": str(leaf_count),
                "timestamp_ns": str(ts),
                "merkle_root": root.hex(),
                "prev_epoch_hash": prev,
                "epoch_hash": epoch_hash,
                "signature": signature,
                "first_stream_id": first_stream_id,
                "last_stream_id": last_stream_id,
            }
            # Index each event to its (epoch, index, stream_id). The stream_id lets
            # ``inclusion_proof`` fetch ONE target event by id instead of scanning the epoch.
            loc_map = {
                eid: f"{epoch_num}|{idx}|{sid}"
                for idx, (_s, _r, eid, sid) in enumerate(pending)
            }

            # ATOMIC COMMIT — append the signed header, write the index/streamid/eventloc/
            # leaves entries, and advance ALL FOUR linkage counters (epoch:num / :head /
            # :last_seq / cursor) in ONE server-side script. This makes epoch-close crash-
            # atomic: a crash can no longer leave a header on the stream while the cursor
            # still points at the unsealed tail, so a restart can never re-seal the SAME
            # tail into a duplicate header for the same epoch (which would freshly stamp
            # timestamp_ns → a different epoch_hash → permanent false-tamper). The script's
            # anti-dup guard also refuses to append a header for an epoch <= the committed
            # epoch:num. The header/leaf JSON is byte-identical to before (same dict, same
            # separators), so proof/verify inputs are unchanged.
            header_json = json.dumps(persisted, separators=(",", ":"))
            leaves_json = json.dumps(
                [lf.hex() for lf in leaves], separators=(",", ":")
            )
            xfields: list[str] = []
            for field_name, field_value in persisted.items():
                xfields.append(field_name)
                xfields.append(field_value)
            eventloc_flat: list[str] = []
            for eid, loc in loc_map.items():
                eventloc_flat.append(eid)
                eventloc_flat.append(loc)
            await cast(
                "Awaitable[Any]",
                self._close_commit_script(
                    keys=[
                        _EPOCHS_STREAM,
                        _EPOCH_INDEX_KEY,
                        _EPOCH_STREAMID_KEY,
                        _EVENTLOC_KEY,
                        _EPOCH_LEAVES_KEY,
                        _EPOCH_NUM_KEY,
                        _EPOCH_HEAD_KEY,
                        _EPOCH_LAST_SEQ_KEY,
                        _CURSOR_KEY,
                    ],
                    args=[
                        str(epoch_num),
                        header_json,
                        leaves_json,
                        epoch_hash,
                        str(end_seq),
                        last_stream_id,
                        str(len(xfields)),
                        *xfields,
                        str(len(eventloc_flat)),
                        *eventloc_flat,
                    ],
                ),
            )

            # Mirror the new signed head OUTSIDE the Redis tamper domain (append + fsync)
            # AFTER the in-Redis header is durable. A crash between the two only leaves
            # the anchor lagging the newest epoch (verify tolerates chain-ahead-of-anchor);
            # it can never fabricate a rollback verify would accept.
            if self._anchor is not None:
                await self._anchor.record(epoch_num, epoch_hash)

            await self._trim_retention(epoch_num)

            return EpochHeader(
                epoch=epoch_num,
                start_seq=start_seq,
                end_seq=end_seq,
                leaf_count=leaf_count,
                timestamp_ns=ts,
                merkle_root=root.hex(),
                prev_epoch_hash=prev,
                epoch_hash=epoch_hash,
                signature=signature,
                first_stream_id=first_stream_id,
                last_stream_id=last_stream_id,
            )

    async def _trim_retention(self, epoch_num: int) -> None:
        """
        Trim events (and their eventloc index) for the epoch that just fell out of the
        retention window, keeping the hot buffer bounded.

        The signed epoch root chain (never trimmed) remains the durable tamper-evidence
        anchor for the trimmed events; verify_chain switches those epochs to
        signature-only. Only ONE epoch falls out per close, so this is O(epoch size).
        """
        fell_out = epoch_num - WORM_HOT_EPOCHS
        if fell_out < 0:
            return
        header = await self._read_epoch_header(fell_out)
        if header is None:
            return
        # HDEL this epoch's eventloc entries, then XTRIM the buffer up to the start of
        # the OLDEST STILL-RETAINED epoch (fell_out + 1).
        segment: Any = await self._redis.xrange(
            _EVENTS_STREAM,
            min=header.first_stream_id,
            max=header.last_stream_id,
        )
        event_ids = [str(fields["event_id"]) for _sid, fields in segment]
        if event_ids:
            await cast(
                "Awaitable[int]", self._redis.hdel(_EVENTLOC_KEY, *event_ids)
            )
        # Drop this epoch's stored leaf-digest vector too (its events are leaving the
        # hot buffer; the signed root chain remains the durable tamper-evidence anchor).
        await cast(
            "Awaitable[int]", self._redis.hdel(_EPOCH_LEAVES_KEY, str(fell_out))
        )
        keep_from = await self._read_epoch_header(fell_out + 1)
        if keep_from is not None:
            await self._redis.xtrim(
                _EVENTS_STREAM, minid=keep_from.first_stream_id, approximate=False
            )

    # ------------------------------------------------------------------ compaction

    async def maybe_compact(self) -> Optional[tuple[int, str, int]]:
        """
        Compact if the chain has grown a full stride past the last checkpoint.

        A cheap no-op (one GET + one super-checkpoint read) until the chain exceeds
        ``WORM_CHECKPOINT_EPOCHS``; then it folds in strides of ``WORM_HOT_EPOCHS`` so a
        full verify runs at most once per stride, never per close.
        """
        return await self.compact(
            keep_epochs=WORM_CHECKPOINT_EPOCHS, min_stride=WORM_HOT_EPOCHS
        )

    async def compact(
        self, *, keep_epochs: int = WORM_CHECKPOINT_EPOCHS, min_stride: int = 1
    ) -> Optional[tuple[int, str, int]]:
        """
        Fold every sealed epoch at or below ``last_epoch - keep_epochs`` into ONE
        Ed25519-signed super-checkpoint and trim their headers/index/streamid + rotate the
        out-of-domain anchor. Returns the new ``(epoch, epoch_hash, end_seq)`` or ``None``
        when there is nothing new to compact.

        FAIL-CLOSED: only checkpoints a prefix that FULLY verifies right now — it never
        signs an already-tampered prefix (a forged prefix would fail the pre-verify and
        compaction refuses). Because every ``epoch_hash`` transitively commits to
        ``prev_epoch_hash`` back to genesis, a signed checkpoint at epoch ``E`` is a sound
        stand-in for replaying epochs ``0..E``: a later ``verify_chain`` re-anchors on it
        and validates only ``E+1..head``.

        CRASH-SAFETY: the super-checkpoint key is written BEFORE the old headers are
        trimmed. A crash in between leaves the checkpoint plus still-present subsumed
        headers (epoch <= E), which ``verify`` SKIPS (they are subsumed by the signed
        checkpoint), so no false tamper — and the next ``compact`` re-trims them
        idempotently (it removes every header with epoch <= the new target). Runs under
        the epoch lock so it never races the close daemon.
        """
        async with self._epoch_lock():
            num = int(await self._redis.get(_EPOCH_NUM_KEY) or -1)
            if num < 0:
                return None
            target = num - keep_epochs
            if target < 0:
                return None
            try:
                existing = await self._read_super_checkpoint()
            except _SuperCheckpointInvalid:
                # Refuse to compact over a tampered checkpoint; verify_chain reports it.
                return None
            floor = existing[0] if existing is not None else -1
            if target <= floor or target - floor < min_stride:
                return None
            # Fail-closed: only checkpoint a prefix that verifies intact right now.
            intact, _bad = await self._verify_epoch(None)
            if not intact:
                # Declining to compact over a non-intact prefix is correct — but do NOT
                # do it silently: surface it to stderr so a tamper that stalls compaction
                # is visible even before the off-hot-path integrity monitor's next
                # verify_chain pass (which raises mcpip_audit_integrity_total{tamper_detected}
                # + a CRITICAL mcpip.audit log).
                print(
                    "MCPIP AUDIT: compaction declined — the epoch prefix is NOT intact "
                    f"(first_bad_epoch={_bad}); investigate possible tamper",
                    file=sys.stderr,
                    flush=True,
                )
                return None
            header = await self._read_epoch_header(target)
            if header is None:
                return None
            signature = self._private_key.sign(
                _supercp_message(target, header.epoch_hash, header.end_seq)
            ).hex()
            payload = json.dumps(
                {
                    "epoch": target,
                    "epoch_hash": header.epoch_hash,
                    "end_seq": header.end_seq,
                    "signature": signature,
                },
                separators=(",", ":"),
            )
            await self._redis.set(_SUPERCP_KEY, payload)
            await self._trim_compacted_headers(target)
            if self._anchor is not None:
                # Drop out-of-domain witness lines below the checkpoint epoch (the signed
                # super-checkpoint subsumes them), keeping the anchor file bounded too.
                await self._anchor.compact(target)
            return (target, header.epoch_hash, header.end_seq)

    async def _trim_compacted_headers(self, target: int) -> None:
        """
        Remove every signed epoch header (and its index/streamid/leaves) with
        ``epoch <= target`` — they are folded into the signed super-checkpoint. Scans the
        (compaction-bounded) epochs stream, so it is self-healing after a mid-compaction
        crash left subsumed headers behind.
        """
        headers: Any = await self._redis.xrange(_EPOCHS_STREAM)
        del_sids: list[Any] = []
        del_epochs: list[str] = []
        for sid, fields in headers:
            try:
                epoch = int(fields["epoch"])
            except (KeyError, ValueError, TypeError):
                continue
            if epoch <= target:
                del_sids.append(sid)
                del_epochs.append(str(epoch))
        if del_sids:
            await cast("Awaitable[int]", self._redis.xdel(_EPOCHS_STREAM, *del_sids))
        if del_epochs:
            await cast(
                "Awaitable[int]", self._redis.hdel(_EPOCH_INDEX_KEY, *del_epochs)
            )
            await cast(
                "Awaitable[int]", self._redis.hdel(_EPOCH_STREAMID_KEY, *del_epochs)
            )
            await cast(
                "Awaitable[int]", self._redis.hdel(_EPOCH_LEAVES_KEY, *del_epochs)
            )

    async def _read_super_checkpoint(self) -> Optional[tuple[int, str, int]]:
        """
        Return the verified super-checkpoint ``(epoch, epoch_hash, end_seq)`` or ``None``
        if none is set. Raises ``_SuperCheckpointInvalid`` if the key is present but
        malformed or its Ed25519 signature does not verify (fail-closed tamper).
        """
        raw: Any = await self._redis.get(_SUPERCP_KEY)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise _SuperCheckpointInvalid()
            epoch = int(data["epoch"])
            epoch_hash = str(data["epoch_hash"])
            end_seq = int(data["end_seq"])
            signature = str(data["signature"])
            self._public_key.verify(
                bytes.fromhex(signature),
                _supercp_message(epoch, epoch_hash, end_seq),
            )
        except (KeyError, ValueError, TypeError, InvalidSignature) as exc:
            raise _SuperCheckpointInvalid() from exc
        return (epoch, epoch_hash, end_seq)

    async def inclusion_proof(self, event_id: str) -> Optional[InclusionProof]:
        """
        Return the inclusion proof for ``event_id``, or None if it is not in a
        sealed-and-retained epoch.

        Cost: proof VERIFICATION is O(log n) (recompute the root from the sibling path).
        GENERATION reads the epoch's precomputed leaf-digest vector (a compact list
        persisted at close, one HGET — no re-reading full event records, no re-hashing
        the epoch) plus ONE target event fetched directly by its stored stream id, then
        derives the O(log n) Merkle path in memory. The signed ``merkle_root`` /
        ``epoch_hash`` / ``signature`` come from the O(1) header index.

        Looks up ``epoch|index|stream_id`` via the event-location hash, reads that
        epoch's signed header + stored leaf-digest vector by number, fetches the single
        target record by stream id, and produces the Merkle path plus the signed anchors.
        """
        loc: Any = await cast(
            "Awaitable[Any]", self._redis.hget(_EVENTLOC_KEY, event_id)
        )
        if loc is None:
            return None
        parts = str(loc).split("|")
        if len(parts) != 3:
            return None
        try:
            epoch = int(parts[0])
            index = int(parts[1])
        except (ValueError, TypeError):
            return None
        stream_id = parts[2]

        header = await self._read_epoch_header(epoch)
        if header is None:
            return None
        raw_leaves: Any = await cast(
            "Awaitable[Any]", self._redis.hget(_EPOCH_LEAVES_KEY, str(epoch))
        )
        if raw_leaves is None:
            return None
        try:
            leaf_hexes = json.loads(raw_leaves)
        except (ValueError, TypeError):
            return None
        if not isinstance(leaf_hexes, list) or len(leaf_hexes) != header.leaf_count:
            return None
        if index < 0 or index >= len(leaf_hexes):
            return None
        try:
            leaves = [bytes.fromhex(str(h)) for h in leaf_hexes]
        except ValueError:
            return None

        # Fetch ONLY the target event's record by its stream id (O(1)), never the epoch.
        entries: Any = await self._redis.xrange(
            _EVENTS_STREAM, min=stream_id, max=stream_id
        )
        if not entries:
            return None
        record = str(entries[0][1]["record"])

        proof = merkle_inclusion_proof(leaves, index)
        return InclusionProof(
            event_id=event_id,
            epoch=epoch,
            index=index,
            record=record,
            proof=proof,
            merkle_root=header.merkle_root,
            epoch_hash=header.epoch_hash,
            signature=header.signature,
        )

    async def list_event_ids(self) -> list[str]:
        """Every still-buffered event's ``event_id`` in append (stream) order."""
        out: list[str] = []
        entries: Any = await self._redis.xrange(_EVENTS_STREAM)
        for _sid, fields in entries:
            out.append(str(fields["event_id"]))
        return out

    async def recent_decisions(
        self, tenant_id: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        """
        Operator-visibility feed: the most recent AUTHORIZE decisions (allow/deny) for
        ONE tenant, newest first — the real-time decision stream the console renders.

        Reads the durable event buffer (NO new hot-path write) and returns a strict
        WHITELIST projection: alias, decision, deny_reason, transport class, risk tier,
        classification, correlation id, plus the stream's seq + timestamp — and, as a
        DELIBERATE extension for per-event audit verification, the WORM ``event_id``
        (the random uuid4 handle minted by ``emit`` — exactly what
        ``/v1/audit/proof/{event_id}`` accepts, carrying no topology, payload, or
        secret) alongside ``worm_sequence``. The real target, the argument payload, the
        challenge id, and any secret are NEVER included (they exist only inside the
        sealed record, gated behind topology hygiene). Tenant-scoped by the caller's
        own tenant. Bounded scan; best-effort (returns ``[]`` on transport error). This
        is a bounded RECENT tail for live display — not the authoritative audit record,
        which stays the signed epoch chain (verify via ``verify_chain`` /
        ``export-audit``).
        """
        try:
            entries: Any = await self._redis.xrevrange(
                _EVENTS_STREAM, count=_RECENT_DECISIONS_SCAN
            )
        except RedisError:
            return []
        out: list[dict[str, Any]] = []
        for _sid, fields in entries:
            row = self._project_decision_row(
                tenant_id, fields, self._content_key, self._content_key_fallbacks
            )
            if row is None:
                continue
            out.append(row)
            if len(out) >= limit:
                break
        return out

    @staticmethod
    def _project_decision_row(
        tenant_id: str,
        fields: dict[str, Any],
        content_key: Optional[bytes] = None,
        content_key_fallbacks: tuple[bytes, ...] = (),
    ) -> Optional[dict[str, Any]]:
        """
        Project ONE raw ``_EVENTS_STREAM`` entry to the operator-safe whitelist row, or
        ``None`` if the entry is unparseable, not this tenant's, or not an allow/deny
        AUTHORIZE decision. Shared by ``recent_decisions`` (live tail) and
        ``query_decisions`` (date-ranged history) so the two operator reads project the
        IDENTICAL topology-free/secret-free field set — the whitelist can never drift.
        """
        try:
            record = json.loads(fields["record"])
            event = _decrypt_worm_event(
                record.get("event"), content_key, content_key_fallbacks
            )
        except (ValueError, TypeError, KeyError):
            return None
        if not isinstance(event, dict):
            return None
        if event.get("tenant_id") != tenant_id or event.get("decision") not in (
            "allow",
            "deny",
        ):
            return None
        row: dict[str, Any] = {k: event.get(k) for k in _DECISION_SAFE_KEYS}
        row["tenant_id"] = tenant_id
        try:
            # Stream-side data (not from the event payload): the emit-time uuid4
            # event_id keys /v1/audit/proof/{event_id}; seq is the WORM height.
            row["event_id"] = str(fields["event_id"])
            row["worm_sequence"] = int(fields["seq"])
            row["timestamp_ns"] = int(record.get("timestamp_ns", 0))
        except (ValueError, TypeError, KeyError):
            return None
        return row

    async def query_decisions(
        self,
        tenant_id: str,
        *,
        start_id: str = "-",
        end_id: str = "+",
        limit: int = 100,
        filters: Optional[dict[str, frozenset[str]]] = None,
        scan_budget: int = _DECISIONS_QUERY_SCAN,
    ) -> dict[str, Any]:
        """
        Operator decision-HISTORY query: date-ranged, multi-filtered, cursor-paged over the
        SAME tenant-scoped whitelist projection ``recent_decisions`` serves — it exposes
        NOTHING the live feed doesn't (no target, no payload, no secret; just the operator's
        own WORM decision tail, walkable by time). Newest-first.

        Range + resume ride the Redis stream id (``<ms>-<seq>``): ``start_id``/``end_id`` are
        inclusive time bounds (bare ``<ms>`` auto-completes to the whole millisecond), and a
        resume cursor is passed as ``end_id="(<sid>"`` (exclusive) so pages never overlap or
        gap. Because the stream is GLOBAL (all tenants) and this filters to one, a page of
        ``limit`` matches may require examining more raw entries; the reverse walk is bounded
        by ``scan_budget`` (``_DECISIONS_QUERY_SCAN``) per call and yields ``next_cursor`` so
        the caller keeps paging. ``filters`` maps a whitelist field → allowed string values
        (AND across fields, OR within) — only ``_DECISION_SAFE_KEYS`` are honored; an unknown
        field yields zero matches (fail-closed, never a silent full scan).

        Returns ``{"decisions": [...], "next_cursor": str|None, "scanned": int,
        "exhausted": bool, "retention_floor_ms": int|None,
        "window_precedes_retention": bool}``.

        **The retention fields exist so an empty result can never lie.** Events are trimmed
        out of the hot buffer once their epoch falls outside ``WORM_HOT_EPOCHS``; their
        signed Merkle roots remain, but the per-decision rows do not. Without a horizon a
        caller cannot distinguish "nothing happened in this window" from "this window is
        older than anything I still hold" — and for an audit product those two answers are
        opposites. ``retention_floor_ms`` is the timestamp of the OLDEST row still present
        (``None`` when the buffer is empty); ``window_precedes_retention`` is True when the
        requested range ends before that floor, i.e. the emptiness is ignorance, not absence.

        ``next_cursor`` is ``None`` only when the time range is fully
        walked; otherwise it is the last raw stream id examined (re-pass as
        ``end_id="(<cursor>"``). Best-effort: a transport error ends the walk with whatever
        matched so far. Bounded scan, tenant-scoped, read-only — NOT the authoritative record
        (that stays the signed epoch chain).
        """
        active = {
            field: allowed
            for field, allowed in (filters or {}).items()
            if allowed  # an empty value-set means "no constraint", so drop it
        }
        # An unknown filter field can never match a whitelist projection → zero rows, never
        # a silent unfiltered scan (fail-closed).
        if any(field not in _DECISION_SAFE_KEYS for field in active):
            return {
                "decisions": [],
                "next_cursor": None,
                "scanned": 0,
                "exhausted": True,
                # An unknown filter field matched nothing because it is INVALID, not
                # because history is short — never blame retention for a caller error.
                "retention_floor_ms": None,
                "window_precedes_retention": False,
            }

        rows: list[dict[str, Any]] = []
        scanned = 0
        cursor_max = end_id
        last_sid: Optional[str] = None
        exhausted = False
        while len(rows) < limit and scanned < scan_budget:
            batch = min(_DECISIONS_QUERY_BATCH, scan_budget - scanned)
            try:
                entries: Any = await self._redis.xrevrange(
                    _EVENTS_STREAM, max=cursor_max, min=start_id, count=batch
                )
            except RedisError:
                break
            if not entries:
                exhausted = True
                break
            page_filled = False
            for sid, fields in entries:
                scanned += 1
                last_sid = str(sid)
                row = self._project_decision_row(
                    tenant_id, fields, self._content_key, self._content_key_fallbacks
                )
                if row is None:
                    continue
                if not all(
                    str(row.get(field)) in allowed for field, allowed in active.items()
                ):
                    continue
                rows.append(row)
                if len(rows) >= limit:
                    page_filled = True
                    break
            if page_filled:
                # Stopped MID-batch because the page is full; older entries may remain
                # beyond last_sid, so the range is NOT exhausted — resume from last_sid.
                break
            # The whole batch was consumed. A short read (fewer than requested) means the
            # [start_id, cursor_max] range is genuinely drained — only then is it exhausted.
            if len(entries) < batch:
                exhausted = True
                break
            # Resume strictly BEFORE the last raw entry examined (exclusive), so the next
            # round never re-sees it regardless of how many rows matched this round.
            cursor_max = f"({last_sid}"
        next_cursor = None if exhausted else last_sid
        # The retention horizon — read ONCE per query, from the oldest row still in the
        # stream. This is what turns an empty page from an assertion ("nothing happened")
        # into an honest one ("nothing I still hold"). Best-effort by design: if the probe
        # fails we report an UNKNOWN horizon rather than a confident zero, because the
        # failure mode we are removing is precisely over-confidence about absence.
        retention_floor_ms: Optional[int] = None
        try:
            oldest = await self._redis.xrange(_EVENTS_STREAM, count=1)
            if oldest:
                retention_floor_ms = int(str(oldest[0][0]).split("-", 1)[0])
        except Exception:  # noqa: BLE001 - horizon is advisory; never fail a read for it
            retention_floor_ms = None

        # True only when we KNOW the window closes before the oldest row we hold. An
        # unbounded ("+") end or an unknown floor stays False — we never claim ignorance
        # we cannot demonstrate.
        window_precedes_retention = False
        if retention_floor_ms is not None and not rows and end_id not in ("+", "-"):
            end_ms = _stream_id_ms(end_id)
            if end_ms is not None and end_ms < retention_floor_ms:
                window_precedes_retention = True

        return {
            "decisions": rows,
            "next_cursor": next_cursor,
            "scanned": scanned,
            "exhausted": exhausted,
            "retention_floor_ms": retention_floor_ms,
            "window_precedes_retention": window_precedes_retention,
        }

    async def stream_tail_id(self) -> str:
        """
        The newest ``_EVENTS_STREAM`` id — the deny-response playbook's boot cursor.
        Anchoring there means a restart only ever responds to events NEWER than boot, so
        the automation never re-fires on the whole audit history after a redeploy. ``"0"``
        when the buffer is empty (or on transport error — fail-safe: respond only forward).
        """
        try:
            entries: Any = await self._redis.xrevrange(_EVENTS_STREAM, count=1)
        except RedisError:
            return "0"
        return str(entries[0][0]) if entries else "0"

    async def scan_alerts(
        self,
        since_id: str,
        reasons: frozenset[str],
        *,
        limit: int,
        scan: int,
    ) -> dict[str, Any]:
        """
        Forward-scan the durable WORM buffer for NEW alert-worthy deny events since
        ``since_id`` — the read behind the opt-in deny-response playbook. DEPLOYMENT-WIDE
        (any tenant, the operator runs the whole gateway) but STILL a strict topology-free/
        secret-free projection: only ``_ALERT_SAFE_KEYS`` (tenant/agent/alias/decision/
        deny_reason/correlation) plus the stream-side ``worm_sequence`` — the real target,
        the payload, and every secret NEVER leave the box through this read. Matches only
        ``deny`` events whose ``deny_reason`` is in the closed ``reasons`` set.

        Reads the durable buffer (NO hot-path write, structurally off the decision path),
        bounded by ``scan`` raw entries per call and ``limit`` alerts returned. Returns
        ``{"alerts": [...], "cursor": <last stream id examined>}`` — the caller persists the
        cursor and resumes at ``(cursor`` (exclusive). Best-effort: a transport error
        returns no alerts and leaves the cursor unmoved (retried next poll).
        """
        try:
            entries: Any = await self._redis.xrange(
                _EVENTS_STREAM, min=f"({since_id}", max="+", count=scan
            )
        except RedisError:
            # Fail-safe: no alerts, cursor unmoved (retried next poll). The caller counts
            # this to the closed-enum ``scan_error`` metric — the WORM layer itself stays
            # free of the response-playbook metrics dependency.
            return {"alerts": [], "cursor": since_id, "error": True}
        alerts: list[dict[str, Any]] = []
        cursor = since_id
        for sid, fields in entries:
            cursor = str(sid)
            try:
                record = json.loads(fields["record"])
                event = _decrypt_worm_event(
                    record.get("event"), self._content_key, self._content_key_fallbacks
                )
            except (ValueError, TypeError, KeyError):
                continue
            if not isinstance(event, dict) or event.get("decision") != "deny":
                continue
            if event.get("deny_reason") not in reasons:
                continue
            row: dict[str, Any] = {k: event.get(k) for k in _ALERT_SAFE_KEYS}
            try:
                row["worm_sequence"] = int(fields["seq"])
                row["timestamp_ns"] = int(record.get("timestamp_ns", 0))
            except (ValueError, TypeError, KeyError):
                continue
            alerts.append(row)
            if len(alerts) >= limit:
                break
        return {"alerts": alerts, "cursor": cursor}

    # ------------------------------------------------------------------ verify

    async def verify_chain(
        self,
        expected_head: Optional[tuple[int, str]] = None,
        *,
        checkpoint: Optional[tuple[int, str]] = None,
    ) -> tuple[bool, Optional[int]]:
        """
        Verify the audit structure; return ``(intact, first_bad)``.

        Epoch mode: under the epoch lock (a consistent snapshot vs. the background
        daemon) re-read every signed epoch header in order and, for each epoch, check
        root-chain linkage, contiguous seq coverage, the recomputed Merkle root over the
        buffered leaves (for epochs still in the hot buffer; trimmed epochs are verified
        signature-only against their signed root — the retained tamper-evidence anchor),
        the recomputed ``epoch_hash``, and the Ed25519 signature.

        THEN cross-check for TAIL TRUNCATION / ROLLBACK on two independent anchors:
        (1) the durable in-Redis counters (``_EPOCH_NUM_KEY`` / ``_EPOCH_LAST_SEQ_KEY`` /
        ``_EPOCH_HEAD_KEY``) catch a truncation that forgets to rewrite them; (2) the
        out-of-tamper-domain signed ``AnchorStore`` head — resolved automatically when a
        store is configured, or overridden by an explicit ``expected_head``
        ``(epoch, epoch_hash)`` operator checkpoint — is enforced as a MONOTONIC
        LOW-WATERMARK: the surviving chain must reach AT LEAST the witnessed epoch with the
        identical ``epoch_hash`` (a chain that stops short is a rollback; a different hash
        at the witnessed epoch is a substitution; a chain merely AHEAD of a lagging anchor
        is intact). This closes the case where the attacker ALSO rewrites the in-Redis
        counters back to a prior signed epoch. Any failure at epoch ``n`` → ``(False, n)``;
        a whole-store erasure witnessed by an anchor is reported at position 0. Per-event
        mode falls back to the legacy JSONL straight-chain verifier.

        INCREMENTAL VERIFY (``checkpoint=(epoch, epoch_hash)``): a caller that already
        FULLY verified the chain up to ``(epoch, epoch_hash)`` (via ``latest_checkpoint``
        after an intact full verify) may re-verify only the NEWER epochs. Cost — and the
        epoch-close-daemon freeze while the lock is held — then scale with the number of
        epochs since the checkpoint, not the whole service lifetime. This is sound
        because every ``epoch_hash`` commits to ``prev_epoch_hash`` (the prefix is
        transitively bound), so re-anchoring on the trusted checkpoint hash and verifying
        the suffix links + signatures forward is equivalent to a full replay of the
        prefix. The checkpoint is re-anchored by confirming the header still stored at
        ``epoch`` carries the identical ``epoch_hash``; if it does not (or the counters
        rolled back below it) that is itself tamper. The default (``checkpoint=None``)
        remains a full replay — but when a signed SUPER-CHECKPOINT is present (written by
        ``compact``) the replay RE-ANCHORS on it and validates only ``epoch > checkpoint``,
        so even the default verify is bounded to O(epochs since the last compaction). A
        present-but-unverifiable super-checkpoint is itself tamper (fail closed).
        """
        if self._mode == "per_event":
            return self._verify_per_event()

        async with self._epoch_lock():
            if checkpoint is not None:
                return await self._verify_epoch_incremental(expected_head, checkpoint)
            return await self._verify_epoch(expected_head)

    async def latest_checkpoint(self) -> Optional[tuple[int, str]]:
        """
        Return ``(last_epoch, last_epoch_hash)`` — a trusted checkpoint to pass to a
        later ``verify_chain(checkpoint=...)`` so it re-verifies only newer epochs.

        Call ONLY after a full ``verify_chain()`` returned intact: the returned pair is
        trusted purely on the strength of that prior full verification. ``None`` when no
        epoch has been sealed yet.
        """
        async with self._epoch_lock():
            num = int(await self._redis.get(_EPOCH_NUM_KEY) or -1)
            if num < 0:
                return None
            head = str(await self._redis.get(_EPOCH_HEAD_KEY) or _GENESIS_EPOCH_HASH)
            return (num, head)

    def signing_key_id(self) -> str:
        """
        Deterministic PUBLIC fingerprint of the WORM Ed25519 epoch key.

        A domain-separated SHA-256 of the raw public key bytes — an identifier only, never
        secret material and never a signature. Lets an attestation verifier bind a returned
        epoch signature to a WORM public key it already holds. Pure/local: no Redis, no
        signing, no hot-path touch.
        """
        raw = self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return sha256_hex(_DOMAIN_KEYID + raw)

    async def _latest_epoch_header(self) -> Optional[EpochHeader]:
        """The most-recently SEALED epoch header, or None when none has closed yet."""
        num = int(await self._redis.get(_EPOCH_NUM_KEY) or -1)
        if num < 0:
            return None
        return await self._read_epoch_header(num)

    async def attestation(self) -> WormAttestation:
        """
        Build a portable, signed attestation of the CURRENT audit state — READ-ONLY.

        Returns the latest SEALED epoch header (already Ed25519-signed at close), a FRESH
        ``verify_chain`` result (intact + first-bad-epoch), and the out-of-tamper-domain
        anchor low-watermark, tagged with the WORM epoch key's public ``signing_key_id`` so
        an external verifier can bind the header signature to a known key. It mints no key,
        signs nothing new, and does NOT close an epoch (that is a write) — it only reads the
        already-sealed chain, so it never runs on, blocks, or perturbs the emit hot path.
        ``verify_chain`` takes the epoch lock (freezing only the background close daemon,
        never ``emit``); a header read that skews by one just-closed epoch is harmless —
        each returned field is independently signature-verifiable.

        Per-event (legacy migration) mode has no epoch headers or anchor: the epoch fields
        and anchor watermark come back ``None`` and only ``verify_chain`` + the key id are
        meaningful (the epoch model is the attested one).
        """
        key_id = self.signing_key_id()
        intact, first_bad = await self.verify_chain()
        header = await self._latest_epoch_header()
        anchor = await self._anchor.head() if self._anchor is not None else None
        return WormAttestation(
            epoch=header.epoch if header is not None else None,
            end_seq=header.end_seq if header is not None else None,
            merkle_root=header.merkle_root if header is not None else None,
            epoch_hash=header.epoch_hash if header is not None else None,
            signature=header.signature if header is not None else None,
            signing_key_id=key_id,
            intact=intact,
            first_bad_epoch=first_bad,
            anchor_epoch=anchor[0] if anchor is not None else None,
            anchor_epoch_hash=anchor[1] if anchor is not None else None,
        )

    async def proof_scope(self) -> ProofScope:
        """
        Measure the window in which a per-event inclusion proof can be produced — READ-ONLY.

        Reads only bounded, O(1)-or-O(hot epochs) keys: the eventloc population (one HLEN),
        the retained leaf-digest epochs (one HKEYS over at most ``WORM_HOT_EPOCHS`` fields),
        the sealed-coverage high-water mark, and the two boundary headers. It mints nothing,
        seals nothing, and never runs on or blocks the emit hot path.

        The numbers are deliberately derived from what is PRESENT rather than from
        ``head - WORM_HOT_EPOCHS``: after a restart, a partial trim, or an operator's manual
        intervention the arithmetic answer and the real answer can differ, and an evidence
        bundle must report the one an auditor could reproduce by asking for the proofs.

        NOT A SNAPSHOT — and the bundle must not be read as if it were. These keys are read
        sequentially, without a lock (deliberately: the epoch lock belongs to the close
        daemon, and a compliance read has no business contending for it). A close or a trim
        landing mid-read can therefore mix a population counted before it with an epoch
        range counted after. The skew is bounded by one epoch in either direction and is
        self-correcting on the next call, which is why it is acceptable here: every field is
        a monitoring quantity, none is a signed commitment, and no decision is made from
        them. What it must never become is an input to an integrity verdict — ``verify_chain``
        takes the lock precisely because IT is that verdict, and this is not.

        Per-event (legacy migration) mode has no epochs and no Merkle proofs at all: every
        window field comes back ``None``/zero, which is the honest answer for that mode
        rather than an empty-looking epoch window.
        """
        if self._mode == "per_event":
            return ProofScope(
                hot_epochs=WORM_HOT_EPOCHS,
                oldest_proof_epoch=None,
                newest_proof_epoch=None,
                first_proof_seq=None,
                last_proof_seq=None,
                proof_bearing_events=0,
                unsealed_events=0,
                sealed_through_seq=None,
            )

        # Population: eventloc holds exactly one entry per individually provable event —
        # written at close, deleted at trim — so its cardinality IS the population.
        raw_pop: Any = await cast("Awaitable[Any]", self._redis.hlen(_EVENTLOC_KEY))
        proof_bearing = int(raw_pop or 0)

        # Period: the epochs whose leaf-digest vectors survive. Bounded by WORM_HOT_EPOCHS,
        # so reading the field names is cheap and exact.
        raw_epochs: Any = await cast(
            "Awaitable[Any]", self._redis.hkeys(_EPOCH_LEAVES_KEY)
        )
        retained: list[int] = []
        for field in raw_epochs or []:
            try:
                retained.append(int(str(field)))
            except (TypeError, ValueError):
                continue

        sealed_through: Optional[int] = None
        raw_sealed: Any = await cast(
            "Awaitable[Any]", self._redis.get(_EPOCH_LAST_SEQ_KEY)
        )
        if raw_sealed is not None:
            try:
                sealed_through = int(str(raw_sealed))
            except (TypeError, ValueError):
                sealed_through = None

        # Unsealed tail: emitted (so already durable and write-before-execute covered) but
        # not yet in a signed epoch. Never negative — a close racing this read can only make
        # the sealed mark newer than the seq snapshot.
        raw_seq: Any = await cast("Awaitable[Any]", self._redis.get(_SEQ_KEY))
        try:
            head_seq = int(str(raw_seq)) if raw_seq is not None else 0
        except (TypeError, ValueError):
            head_seq = 0
        unsealed = max(0, head_seq - (sealed_through or 0))

        if not retained:
            return ProofScope(
                hot_epochs=WORM_HOT_EPOCHS,
                oldest_proof_epoch=None,
                newest_proof_epoch=None,
                first_proof_seq=None,
                last_proof_seq=None,
                proof_bearing_events=proof_bearing,
                unsealed_events=unsealed,
                sealed_through_seq=sealed_through,
            )

        oldest, newest = min(retained), max(retained)
        first_header = await self._read_epoch_header(oldest)
        last_header = await self._read_epoch_header(newest)
        return ProofScope(
            hot_epochs=WORM_HOT_EPOCHS,
            oldest_proof_epoch=oldest,
            newest_proof_epoch=newest,
            first_proof_seq=first_header.start_seq if first_header else None,
            last_proof_seq=last_header.end_seq if last_header else None,
            proof_bearing_events=proof_bearing,
            unsealed_events=unsealed,
            sealed_through_seq=sealed_through,
        )

    async def _verify_epoch(
        self, expected_head: Optional[tuple[int, str]]
    ) -> tuple[bool, Optional[int]]:
        # Resolve the out-of-tamper-domain anchor (unless an explicit checkpoint was
        # supplied by the caller). Read under the epoch lock so the daemon cannot append
        # a new head between this read and the header snapshot below.
        if expected_head is None and self._anchor is not None:
            expected_head = await self._anchor.head()

        # Load the signed super-checkpoint (compaction anchor). Absent → this is a
        # never-compacted chain and verification replays from genesis exactly as before.
        # Present-but-unverifiable → TAMPER at the compaction anchor (fail closed). When
        # present it re-anchors the replay: because every epoch_hash transitively commits
        # to prev_epoch_hash back to genesis, a validly-signed checkpoint at epoch C is a
        # sound stand-in for replaying epochs 0..C, so only C+1..head need replaying.
        try:
            supercp = await self._read_super_checkpoint()
        except _SuperCheckpointInvalid:
            return False, 0

        # Read the epoch headers FIRST, then the events buffer — never the reverse. An
        # event is always XADD'd to the buffer BEFORE the epoch header that seals it, so
        # snapshotting events after headers guarantees every seq a header references is
        # already present (eliminating a torn-read false tamper). The lock additionally
        # freezes the daemon so the counters read below match this header snapshot.
        headers: Any = await self._redis.xrange(_EPOCHS_STREAM)
        all_events = await self._all_event_records()  # dict seq -> record_str.

        # Durable monotonic counters — the tail-truncation anchors.
        k_num = int(await self._redis.get(_EPOCH_NUM_KEY) or -1)
        k_last_seq = int(await self._redis.get(_EPOCH_LAST_SEQ_KEY) or 0)
        k_head = str(await self._redis.get(_EPOCH_HEAD_KEY) or _GENESIS_EPOCH_HASH)
        # Highest epoch whose events may legitimately be retention-trimmed. Any epoch above
        # it is inside the hot window, so its events MUST still be buffered — total absence
        # is whole-epoch event deletion (tamper), not a trim. (``_trim_retention`` trims
        # exactly ``epoch - WORM_HOT_EPOCHS`` per close.)
        trim_low_watermark = k_num - WORM_HOT_EPOCHS

        if supercp is None:
            cp_epoch = -1
            expected_prev = _GENESIS_EPOCH_HASH
            expected_start = 1  # INCR-based seq starts at 1.
            next_epoch = 0
            last_epoch_seen = -1
            covered_end_seq = 0
            computed_head = _GENESIS_EPOCH_HASH
            anchor_witnessed: Optional[str] = None
        else:
            cp_epoch, cp_hash, cp_end_seq = supercp
            expected_prev = cp_hash
            expected_start = cp_end_seq + 1
            next_epoch = cp_epoch + 1
            last_epoch_seen = cp_epoch
            covered_end_seq = cp_end_seq
            computed_head = cp_hash
            anchor_witnessed = (
                cp_hash
                if expected_head is not None and expected_head[0] == cp_epoch
                else None
            )

        surviving = 0  # headers actually replayed (epoch > cp_epoch).
        for _sid, fields in headers:
            if supercp is not None:
                # Skip headers subsumed by the signed checkpoint — a crash mid-compaction
                # (checkpoint written, old headers not yet trimmed) leaves these behind;
                # they are already committed by the checkpoint, so ignoring them is sound
                # and avoids a false tamper.
                try:
                    hepoch = int(fields["epoch"])
                except (KeyError, ValueError, TypeError):
                    return False, next_epoch
                if hepoch <= cp_epoch:
                    continue
            checked = self._verify_header_fields(
                fields,
                expected_prev=expected_prev,
                expected_epoch=next_epoch,
                expected_start=expected_start,
                all_events=all_events,
                trim_low_watermark=trim_low_watermark,
            )
            if checked is None:
                return False, next_epoch
            epoch, end_seq, epoch_hash_field = checked
            expected_prev = epoch_hash_field
            expected_start = end_seq + 1
            last_epoch_seen = epoch
            covered_end_seq = end_seq
            computed_head = epoch_hash_field
            if expected_head is not None and epoch == expected_head[0]:
                anchor_witnessed = epoch_hash_field
            next_epoch += 1
            surviving += 1

        # --- Tail-truncation / rollback detection. ----------------------------------
        # Two independent anchors: (1) the durable in-Redis counters catch a truncation
        # that FORGETS to rewrite them; (2) an out-of-tamper-domain signed anchor (when
        # configured) catches the full attack where the counters are ALSO rewritten,
        # because it lives on storage the Redis attacker cannot reach.
        if supercp is None and surviving == 0:
            # No checkpoint and no headers replayed. Intact ONLY if BOTH the counters
            # agree nothing was ever sealed (k_num == -1) AND no external anchor witnessed
            # a sealed epoch. If either says an epoch existed but no header survives, the
            # entire header chain was erased — TAMPER (the "delete ALL epoch headers"
            # attack; buffered events may still be present). Events with no header while
            # k_num == -1 and no anchor are a legitimate not-yet-closed tail, not flagged.
            if k_num != -1 or k_last_seq != 0:
                return False, 0
            if expected_head is not None:
                return False, 0
            return True, None

        # A position to report for a tail failure — the last replayed epoch (or the
        # checkpoint epoch when everything sealed was already compacted).
        fail_pos = last_epoch_seen if last_epoch_seen >= 0 else 0
        # (1) In-tamper-domain counter cross-check (stale-counter truncation).
        if last_epoch_seen != k_num:
            return False, fail_pos
        if covered_end_seq != k_last_seq:
            return False, fail_pos
        if not constant_time_equals(computed_head, k_head):
            return False, fail_pos
        # (2) Out-of-tamper-domain anchor cross-check, as a MONOTONIC LOW-WATERMARK. The
        # surviving chain must reach AT LEAST the witnessed epoch with the identical
        # epoch_hash: a chain that stops SHORT of the witnessed head is a rollback /
        # truncation; a DIFFERENT hash at the witnessed epoch is a substitution. A chain
        # AHEAD of the anchor is legitimate — the anchor is appended after the header, so
        # a crash can leave it lagging by the newest not-yet-witnessed epoch(s). A witnessed
        # epoch AT/BELOW the signed checkpoint is already satisfied (the checkpoint reaches
        # it); only a witnessed epoch in the replayed suffix must be matched explicitly.
        if expected_head is not None:
            exp_epoch, exp_hash = expected_head
            if exp_epoch > last_epoch_seen:
                return False, fail_pos
            if exp_epoch > cp_epoch and (
                anchor_witnessed is None
                or not constant_time_equals(anchor_witnessed, exp_hash)
            ):
                return False, exp_epoch if exp_epoch >= 0 else 0

        return True, None

    def _verify_header_fields(
        self,
        fields: Any,
        *,
        expected_prev: str,
        expected_epoch: int,
        expected_start: int,
        all_events: dict[int, str],
        trim_low_watermark: int,
    ) -> Optional[tuple[int, int, str]]:
        """
        Verify one signed epoch header's per-epoch checks (1–5) against the running
        chain state. Returns ``(epoch, end_seq, epoch_hash)`` if the header is intact, or
        ``None`` on ANY tamper. Shared verbatim by the full and incremental verifiers so
        the two paths can never diverge in what counts as tamper.

        ``trim_low_watermark`` (= ``k_num - WORM_HOT_EPOCHS``) is the highest epoch whose
        events may LEGITIMATELY have been retention-trimmed. Any epoch STRICTLY ABOVE it is
        still inside the hot window, so its events MUST be fully present in the buffer —
        their TOTAL absence is whole-epoch event deletion, not trimming, and is flagged as
        tamper (closing the "delete every event of a hot epoch reads as trimmed" hole).
        """
        try:
            epoch = int(fields["epoch"])
            start_seq = int(fields["start_seq"])
            end_seq = int(fields["end_seq"])
            leaf_count = int(fields["leaf_count"])
            timestamp_ns = int(fields["timestamp_ns"])
            merkle_root_field = str(fields["merkle_root"])
            prev_epoch_hash = str(fields["prev_epoch_hash"])
            epoch_hash_field = str(fields["epoch_hash"])
            signature = str(fields["signature"])
            first_stream_id_field = str(fields["first_stream_id"])
            last_stream_id_field = str(fields["last_stream_id"])

            # 1) Root-chain linkage.
            if not constant_time_equals(prev_epoch_hash, expected_prev):
                return None
            # 2) Monotonic epoch numbering + contiguous seq coverage.
            if epoch != expected_epoch or start_seq != expected_start:
                return None
            # 3) Merkle root: recompute from buffered leaves when the epoch is still in
            #    the hot buffer; a trimmed epoch (no events present) is verified
            #    signature-only against its signed root. A PARTIAL presence is tamper.
            span = end_seq - start_seq + 1
            present = [
                all_events[s]
                for s in range(start_seq, end_seq + 1)
                if s in all_events
            ]
            if len(present) == leaf_count and span == leaf_count:
                leaves = [leaf_digest(rec.encode("utf-8")) for rec in present]
                if not constant_time_equals(
                    merkle_root(leaves).hex(), merkle_root_field
                ):
                    return None
            elif len(present) != 0:
                # Some (but not all) of a sealed epoch's events are missing/mutated.
                return None
            elif epoch > trim_low_watermark:
                # ZERO events present for an epoch that is STILL inside the retention (hot)
                # window — it should NOT have been trimmed, so this is whole-epoch event
                # deletion, indistinguishable-until-now from a legitimate retention trim.
                # (An epoch AT/BELOW the low-watermark with no events is genuinely trimmed
                # and is correctly verified signature-only via checks 4–5 below.)
                return None
            # 4) Recompute + compare the epoch hash (over EVERY persisted header field,
            #    incl. the signed stream-id range). A mutated first/last stream id
            #    therefore fails here (and the signature below) too.
            core = _header_core(
                epoch, start_seq, end_seq, leaf_count, timestamp_ns,
                merkle_root_field, prev_epoch_hash,
                first_stream_id_field, last_stream_id_field,
            )
            recomputed = sha256_hex(_DOMAIN_EPOCH + canonical_json(core))
            if not constant_time_equals(recomputed, epoch_hash_field):
                return None
            # 5) Verify the single Ed25519 signature over the epoch hash.
            self._public_key.verify(
                bytes.fromhex(signature), bytes.fromhex(epoch_hash_field)
            )
        except (KeyError, ValueError, TypeError, InvalidSignature):
            return None
        return epoch, end_seq, epoch_hash_field

    async def _verify_epoch_incremental(
        self, expected_head: Optional[tuple[int, str]], checkpoint: tuple[int, str]
    ) -> tuple[bool, Optional[int]]:
        """
        Re-verify ONLY the epochs newer than a trusted ``checkpoint`` (epoch, epoch_hash).

        Same tamper domain and per-epoch checks as the full verifier — it reads the
        signed epochs stream, just the SUFFIX after the checkpoint's stored stream id —
        so every mutation the full verifier catches in the suffix is caught here. The
        trusted prefix is re-anchored (the header still stored at the checkpoint epoch
        must carry the identical epoch_hash, and the counters must not have rolled back
        below it); its crypto is not replayed, which is sound because each epoch_hash
        commits to prev_epoch_hash.
        """
        cp_epoch, cp_hash = checkpoint
        if cp_epoch < 0:
            # Nothing genuinely trusted — fall back to a full replay.
            return await self._verify_epoch(expected_head)
        # If a signed super-checkpoint subsumes the caller's trusted checkpoint, defer to
        # the checkpoint-anchored full verify: it is STRONGER (the super-checkpoint is
        # Ed25519-signed, not trusted purely on faith) and scans only epochs after the
        # super-checkpoint — a subset of the requested suffix — so it is at least as cheap.
        # This also avoids a false rollback when the caller's checkpoint header was trimmed
        # by a compaction after the checkpoint was taken.
        try:
            supercp = await self._read_super_checkpoint()
        except _SuperCheckpointInvalid:
            return False, cp_epoch
        if supercp is not None and supercp[0] >= cp_epoch:
            return await self._verify_epoch(expected_head)
        if expected_head is None and self._anchor is not None:
            expected_head = await self._anchor.head()

        cp_sid_raw: Any = await cast(
            "Awaitable[Any]", self._redis.hget(_EPOCH_STREAMID_KEY, str(cp_epoch))
        )
        if cp_sid_raw is None:
            # The trusted checkpoint epoch's header is gone → rollback / truncation.
            return False, cp_epoch
        cp_sid = str(cp_sid_raw)

        all_events = await self._all_event_records()
        k_num = int(await self._redis.get(_EPOCH_NUM_KEY) or -1)
        k_last_seq = int(await self._redis.get(_EPOCH_LAST_SEQ_KEY) or 0)
        k_head = str(await self._redis.get(_EPOCH_HEAD_KEY) or _GENESIS_EPOCH_HASH)
        # Retention low-watermark (see _verify_epoch): epochs above it are hot and their
        # events must be fully present; total absence is whole-epoch event deletion.
        trim_low_watermark = k_num - WORM_HOT_EPOCHS
        if k_num < cp_epoch:
            return False, cp_epoch

        # Re-anchor on the checkpoint: the header still at cp_sid must be epoch cp_epoch
        # with the trusted hash (else a rollback / substitution below the checkpoint).
        cp_entries: Any = await self._redis.xrange(
            _EPOCHS_STREAM, min=cp_sid, max=cp_sid
        )
        if not cp_entries:
            return False, cp_epoch
        _cpsid, cp_fields = cp_entries[0]
        try:
            if int(cp_fields["epoch"]) != cp_epoch:
                return False, cp_epoch
            cp_end_seq = int(cp_fields["end_seq"])
            cp_header_hash = str(cp_fields["epoch_hash"])
        except (KeyError, ValueError, TypeError):
            return False, cp_epoch
        if not constant_time_equals(cp_header_hash, cp_hash):
            return False, cp_epoch

        # Read ONLY the suffix headers (strictly after the checkpoint's stream id).
        suffix: Any = await self._redis.xrange(
            _EPOCHS_STREAM, min="(" + cp_sid, max="+"
        )

        expected_prev = cp_hash
        expected_start = cp_end_seq + 1
        last_epoch_seen = cp_epoch
        covered_end_seq = cp_end_seq
        computed_head = cp_hash
        anchor_witnessed: Optional[str] = None
        if expected_head is not None and expected_head[0] == cp_epoch:
            anchor_witnessed = cp_hash

        next_epoch = cp_epoch + 1
        for _sid, fields in suffix:
            checked = self._verify_header_fields(
                fields,
                expected_prev=expected_prev,
                expected_epoch=next_epoch,
                expected_start=expected_start,
                all_events=all_events,
                trim_low_watermark=trim_low_watermark,
            )
            if checked is None:
                return False, next_epoch
            epoch, end_seq, epoch_hash_field = checked
            expected_prev = epoch_hash_field
            expected_start = end_seq + 1
            last_epoch_seen = epoch
            covered_end_seq = end_seq
            computed_head = epoch_hash_field
            if expected_head is not None and epoch == expected_head[0]:
                anchor_witnessed = epoch_hash_field
            next_epoch += 1

        # Counter cross-check (identical to the full verifier's tail check).
        if last_epoch_seen != k_num:
            return False, last_epoch_seen
        if covered_end_seq != k_last_seq:
            return False, last_epoch_seen
        if not constant_time_equals(computed_head, k_head):
            return False, last_epoch_seen
        # Anchor low-watermark. A witnessed epoch AT/BELOW the trusted checkpoint is
        # already satisfied (the surviving chain reaches cp_epoch >= it); only a
        # witnessed epoch in the re-scanned suffix must be matched explicitly.
        if expected_head is not None:
            exp_epoch, exp_hash = expected_head
            if exp_epoch > last_epoch_seen:
                return False, last_epoch_seen
            if exp_epoch > cp_epoch and (
                anchor_witnessed is None
                or not constant_time_equals(anchor_witnessed, exp_hash)
            ):
                return False, exp_epoch
        return True, None

    # ------------------------------------------------------------------ helpers

    async def _all_event_records(self) -> dict[int, str]:
        """seq -> canonical record string, read once from the durable buffer."""
        out: dict[int, str] = {}
        entries: Any = await self._redis.xrange(_EVENTS_STREAM)
        for _sid, fields in entries:
            out[int(fields["seq"])] = str(fields["record"])
        return out

    async def _read_epoch_header(self, epoch: int) -> Optional[EpochHeader]:
        """Read one epoch header by number from the O(1) header index."""
        raw: Any = await cast(
            "Awaitable[Any]", self._redis.hget(_EPOCH_INDEX_KEY, str(epoch))
        )
        if raw is None:
            return None
        try:
            fields = json.loads(raw)
            if not isinstance(fields, dict):
                return None
            return EpochHeader(
                epoch=int(fields["epoch"]),
                start_seq=int(fields["start_seq"]),
                end_seq=int(fields["end_seq"]),
                leaf_count=int(fields["leaf_count"]),
                timestamp_ns=int(fields["timestamp_ns"]),
                merkle_root=str(fields["merkle_root"]),
                prev_epoch_hash=str(fields["prev_epoch_hash"]),
                epoch_hash=str(fields["epoch_hash"]),
                signature=str(fields["signature"]),
                first_stream_id=str(fields["first_stream_id"]),
                last_stream_id=str(fields["last_stream_id"]),
            )
        except (KeyError, ValueError, TypeError):
            return None

    def _epoch_lock(self) -> "_RedisAppendLock":
        """Redis lock guarding epoch close/verify so nodes never double-close."""
        return _RedisAppendLock(self._redis, _EPOCH_LOCK_KEY, self._release_script)

    def _append_lock(self) -> "_RedisAppendLock":
        """Redis lock guarding legacy per-event append ordering."""
        return _RedisAppendLock(self._redis, _LOCK_KEY, self._release_script)

    # ------------------------------------------------------------------ per-event

    async def _emit_per_event(self, redacted: dict[str, Any]) -> WormReceipt:
        """Legacy migration mode — signed straight hash chain appended to JSONL."""
        async with self._append_lock():
            raw_seq = await self._redis.get(_SEQ_KEY)
            sequence = 0 if raw_seq is None else int(raw_seq) + 1
            prev_hash = await self._redis.get(_LAST_HASH_KEY) or _GENESIS
            timestamp_ns = time.time_ns()
            core = {
                "sequence": sequence,
                "timestamp_ns": timestamp_ns,
                "prev_hash": prev_hash,
                "event": (
                    _encrypt_worm_event(redacted, self._content_key)
                    if self._content_key is not None
                    else redacted
                ),
            }
            record_hash = sha256_hex(canonical_json(core))
            signature = self._private_key.sign(bytes.fromhex(record_hash)).hex()
            record = {**core, "record_hash": record_hash, "signature": signature}
            line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            await self._redis.set(_SEQ_KEY, str(sequence))
            await self._redis.set(_LAST_HASH_KEY, record_hash)
            await self._enforce_replica_quorum()
        return WormReceipt(
            seq=sequence, event_id="", stream_id="", leaf_hash=record_hash
        )

    def _verify_per_event(self) -> tuple[bool, Optional[int]]:
        """Legacy JSONL straight-chain verifier (per-event migration mode)."""
        if not self._path.exists():
            return True, None
        expected_prev = _GENESIS
        with self._path.open("r", encoding="utf-8") as handle:
            for expected_seq, raw_line in enumerate(handle):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError:
                    return False, expected_seq
                try:
                    if not isinstance(record, dict):
                        return False, expected_seq
                    sequence = record.get("sequence")
                    timestamp_ns = record.get("timestamp_ns")
                    prev_hash = record.get("prev_hash")
                    event = record.get("event")
                    record_hash = record.get("record_hash")
                    signature = record.get("signature")
                    if not isinstance(sequence, int) or isinstance(sequence, bool):
                        return False, expected_seq
                    if not isinstance(timestamp_ns, int) or isinstance(timestamp_ns, bool):
                        return False, expected_seq
                    if not isinstance(prev_hash, str):
                        return False, expected_seq
                    if not isinstance(record_hash, str):
                        return False, expected_seq
                    if not isinstance(signature, str):
                        return False, expected_seq
                    if sequence != expected_seq:
                        return False, expected_seq
                    if not constant_time_equals(prev_hash, expected_prev):
                        return False, expected_seq
                    core = {
                        "sequence": sequence,
                        "timestamp_ns": timestamp_ns,
                        "prev_hash": prev_hash,
                        "event": event,
                    }
                    recomputed = sha256_hex(canonical_json(core))
                    if not constant_time_equals(recomputed, record_hash):
                        return False, expected_seq
                    self._public_key.verify(
                        bytes.fromhex(signature), bytes.fromhex(record_hash)
                    )
                except (KeyError, ValueError, TypeError, InvalidSignature):
                    return False, expected_seq
                expected_prev = record_hash
        return True, None


class _RedisAppendLock:
    """Minimal async spin-lock over Redis ``SET NX PX`` with a short TTL."""

    def __init__(
        self, redis_client: "redis.Redis", key: str, release_script: Any
    ) -> None:
        self._redis = redis_client
        self._key = key
        self._release_script = release_script
        self._ttl_ms = 5000
        self._token = os.urandom(16).hex()
        self._acquired_ns = 0

    async def __aenter__(self) -> "_RedisAppendLock":
        deadline = time.monotonic() + 10.0
        while True:
            acquired = await self._redis.set(
                self._key, self._token, nx=True, px=self._ttl_ms
            )
            if acquired:
                self._acquired_ns = time.monotonic_ns()
                return self
            if time.monotonic() > deadline:
                raise TimeoutError("could not acquire WORM append lock")
            await asyncio.sleep(0.01)

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        held_ms = (time.monotonic_ns() - self._acquired_ns) / 1_000_000
        if held_ms >= self._ttl_ms:
            print(
                "MCPIP WORM-LOCK-OVERRUN "
                f"key={self._key} held_ms={held_ms:.1f} ttl_ms={self._ttl_ms} "
                "(append exceeded lock TTL; CAS release prevents cross-holder delete)",
                file=sys.stderr,
                flush=True,
            )
        try:
            await self._release_script(keys=[self._key], args=[self._token])
        except RedisError:
            pass


__all__ = [
    "WormLogger",
    "WormReceipt",
    "EpochHeader",
    "InclusionProof",
    "ProofScope",
    "PersistencePosture",
    "read_persistence_posture",
    "assert_persistence_posture",
    "ALL_WORM_KEYS",
    "WORM_HOT_EPOCHS",
    "WORM_MAX_EPOCH_LEAVES",
    "WORM_CHECKPOINT_EPOCHS",
]
