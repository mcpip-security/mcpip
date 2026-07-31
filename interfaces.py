"""
MCPIP V2 — Shared primitives, ingress/egress models, enums, ABCs, exceptions.

    ◐  MCPIP — The Authorization Layer for Autonomous AI
       "Authorize every AI action before execution."
       AI Reasons. MCPIP Authorizes. Systems Execute.

This module is the single source of truth for:

  * Hard limits (§0.1)               — max chain hops, arg depth, sizes, PIN policy.
  * String safety (§0.2)             — reject_unsafe_string(): control/bidi/zero-width guard.
  * Canonical JSON (§0.3)            — deterministic, NFC-normalized, sorted, byte-exact.
  * Timing-safe comparison helpers   — thin wrappers over secrets.compare_digest.
  * Ingress Pydantic v2 models       — strict + extra="forbid", recursively.
  * The transport ABC + result model.
  * MCPIPDenied                      — the ONLY exception that ever reaches the agent.

Every ingress model uses ``model_config = ConfigDict(extra="forbid", strict=True)``
and repeats that on every nested model — deep schema rigidity is non-negotiable.

The public API of this module is re-exported by nothing (it *is* the root module);
every package imports the primitives it needs directly from here.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import unicodedata
import uuid
from abc import ABC, abstractmethod
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Literal, Mapping, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

# ---------------------------------------------------------------------------
# §0.1  HARD LIMITS — single source of truth, imported everywhere.
# ---------------------------------------------------------------------------

MAX_CHAIN_HOPS: Final[int] = 16          # SwarmTrace.hops length ceiling.
MAX_ARG_DEPTH: Final[int] = 8            # Nested container depth of arguments.
MAX_ARG_KEYS: Final[int] = 64           # Keys per object.
MAX_ARG_ARRAY: Final[int] = 256         # Elements per array.
MAX_STRING_LEN: Final[int] = 4096       # Per string field (post-NFC).
MAX_CANONICAL_BYTES: Final[int] = 16384  # 16 KiB, canonical-encoded arguments payload.
PIN_TTL_SECONDS: Final[int] = 300       # Payload-lock TTL.
PIN_MAX_ATTEMPTS: Final[int] = 5        # Wrong-PIN lockout threshold.
PIN_LENGTH: Final[int] = 6              # Decimal digits.
MAX_QUARANTINE_ROSTER: Final[int] = 1000  # Rows per admin quarantine-roster read (SCAN bound).

# --- JWT temporal validation: bounded clock-skew tolerance. ------------------------
# PyJWT defaults to leeway=0, which demands the gateway's clock agree with the issuing
# IdP to the SECOND. In practice they never do — a one-second drift rejects every
# otherwise-valid token, and the failure is total and undiagnosable from the agent side
# (it sees only an opaque deny). That is an outage caused by NTP, not by policy.
#
# The tolerance is symmetric because BOTH drift directions break a valid token: a
# gateway clock running fast sees `exp` as already passed; one running slow sees
# `iat`/`nbf` as still in the future. RFC 7519 §4.1.4 explicitly sanctions "some small
# leeway, usually no more than a few minutes".
#
# THE TRADE, stated plainly: this also extends an EXPIRED token's usable life by up to
# this many seconds. That is the cost of the fix and the reason the value is small and
# fixed here rather than made configurable — an operator must not be able to widen it
# into a real replay window, and a hard limit belongs in exactly one file.
JWT_CLOCK_SKEW_LEEWAY_SECONDS: Final[int] = 60

# --- Proof-of-possession freshness (auth/pop.py) ------------------------------------
#
# The PoP proof has its OWN time window, deliberately separate from the identity leeway
# above, because the two answer different questions. The identity leeway is symmetric —
# it forgives drift in both directions on a token someone else issued. A PoP proof is
# minted by the caller for THIS request, so its window is intentionally ASYMMETRIC:
# generous backwards (a proof may be up to MAX_AGE old, covering network and retry time)
# and tight forwards (a future-dated proof is either a badly-set clock or an attempt to
# mint proofs valid beyond the replay guard's TTL).
#
# They live here, next to the leeway, because a hard limit belongs in exactly one file —
# and because someone tuning one of these must SEE the other and decide deliberately
# whether it moves too. The replay guard's TTL is derived as MAX_AGE + SKEW so a proof
# can never fall out of the single-use record while still being temporally acceptable.
POP_MAX_AGE_SECONDS: Final[int] = 120
POP_CLOCK_SKEW_SECONDS: Final[int] = 30

# --- Per-user authenticator enrollment (RFC 6238 TOTP) hard limits. -----------------
# Standard authenticator-app parameters (Google Authenticator / 1Password / Authy all
# default to SHA-1 / 6 digits / 30 s — deviating breaks real apps, so these are pinned
# here as the single source of truth for mint, verify, and the provisioning URI).
TOTP_DIGITS: Final[int] = 6              # Code length (decimal digits).
TOTP_PERIOD_S: Final[int] = 30           # RFC 6238 timestep.
TOTP_DRIFT_STEPS: Final[int] = 1         # Accepted clock drift: ±1 step (90 s window).
MAX_TOTP_ATTEMPTS: Final[int] = 5        # Failed verifications per window → lockout.
TOTP_ATTEMPT_WINDOW_S: Final[int] = 300  # Fixed lockout window (matches PIN lock TTL).
MAX_AUTHENTICATOR_ROSTER: Final[int] = 1000  # Rows per admin enrollment-roster read.
MAX_DELEGATION_CHAIN: Final[int] = 8    # RFC 8693 nested `act` delegation depth ceiling (WORM-only
                                        # chain projection). A human->...->agent nesting deeper than
                                        # this is not a real pattern; the bound caps work at MAX+1
                                        # iterations, defeating a claim-stuffing / deeply-nested token.

# --- A2A task-envelope connector (7th SOURCE_FORMAT) hard limits. -------------------
# The A2A parser normalizes ONE representative A2A Task envelope carrying EXACTLY one
# DataPart skill invocation into the same NormalizedIntent every other dialect produces.
# One invocation per request (mirrors Gemini's bare-single-part and the JSON-RPC
# one-call discipline): a Task message's ``parts`` array is bounded to this many entries,
# so >1 part (or 0) fails the strict ingress model → SCHEMA_VIOLATION. It is a PARSER
# bound only — it never touches canonical_json / enforce_argument_safety / the payload
# lock. Hard limits live ONLY here.
MAX_A2A_PARTS: Final[int] = 1
# Byte ceiling on the A2A message ``metadata`` envelope (canonical-JSON serialized). The
# envelope's declared actor/delegation metadata + task/context/message IDs are recorded
# to WORM as RECORDED-NOT-TRUSTED correlation provenance (never authorization, never the
# agent wire), so — exactly like X3's MAX_REGISTRY_META_BYTES for registry ``_meta`` — the
# whole envelope is size-bounded so an untrusted A2A document cannot smuggle unbounded
# provenance into the audit log. It is NEVER merged into ``arguments`` and NEVER enters
# the payload-lock hash.
MAX_A2A_META_BYTES: Final[int] = 4096

# --- Community-extension (author-your-own skill) submission hard limit. ------------
# Ceiling on the PENDING submissions one tenant may hold at once. A Contributor is any
# authenticated principal, so the submit surface is broadly reachable; this bound stops
# a flood of un-reviewed manifests from bloating the pending set (and Redis) while a
# reviewer works through the queue. A full set fails the next submit CLOSED (an opaque
# deny) — never silently evicts a legitimate pending review. Well above any realistic
# in-flight review queue for a single tenant. Applied skills stay bounded by the
# existing MAX_OVERLAY_ENTRIES ceiling once approved.
MAX_PENDING_SUBMISSIONS: Final[int] = 256

# --- Skill permission-model DISPLAY metadata (advisory only). -----------------------
# A skill may carry a structured access mode ("read"/"write") and a human service label
# (e.g. "AWS DynamoDB") — the Cloudflare-API-token-style permission model the console
# renders. Both are ADVISORY DISPLAY metadata: the authorize/PIN/WORM enforcement path
# NEVER consults them (enforcement stays alias/risk_tier/compartment/required_capability/
# canary/require_sender_constraint). The closed mode set and the label length ceiling
# live here — hard limits live ONLY in this module.
SKILL_ACCESS_MODES: Final[tuple[str, ...]] = ("read", "write")
MAX_SERVICE_LABEL_LEN: Final[int] = 64

# --- Registry-sourced skill governance (X3) hard limits. ---------------------------
# A registry submission wraps an MCP-Registry ``server.json`` as a community extension
# (``kind='registry_server'``) that mints through the SAME hardened overlay path. These
# three bounds are the ONLY new hard limits it introduces; they live here (single source
# of truth), never in the service modules.
#
# Ceiling on the VERIFIED-PUBLISHER allow-list a tenant reviewer may pin. The allow-list
# is a bounded set of publisher NAMESPACES (reverse-DNS prefixes) consulted OFF the auth
# hot path (only at approve + boot). Well above any realistic set of trusted publishers a
# single tenant governs; an over-cap PUT fails closed (opaque deny).
MAX_VERIFIED_PUBLISHERS: Final[int] = 256
# Per-namespace length ceiling (a reverse-DNS prefix like ``io.github.owner``). Bounds a
# single allow-list entry and the parsed publisher namespace of a submitted server.json.
MAX_PUBLISHER_NAMESPACE_LEN: Final[int] = 256
# Ceiling on ``remotes[]`` entries in an embedded server.json. The registry manifest
# derives its cloud_rest target from the single qualifying remote-HTTP https entry; this
# bounds the list the parser walks so a stuffed remotes array can never be an amplifier.
MAX_REGISTRY_REMOTES: Final[int] = 16
# Byte ceiling on a server.json ``_meta`` provenance envelope (canonical-JSON serialized).
# ``_meta`` is RECORDED to WORM and shown to the reviewer, never trusted for authorization;
# every string in it is ``reject_unsafe_string``-scrubbed and the whole envelope is bounded
# here so an untrusted registry document cannot smuggle unbounded provenance into the audit
# log (mirrors the charset+size discipline every other human-readable manifest field pays).
MAX_REGISTRY_META_BYTES: Final[int] = 4096

# --- Deny-only policy overlay (velocity + amount ceiling) hard limits. -------------
# Maximum rules a single tenant policy document may carry. The engine walks the rule
# list once per policy eval, so a bound keeps that hot-path scan cheap and refuses an
# operator (or a direct-Redis tamper) from stashing an unbounded document. Well above
# any realistic velocity/amount rule set for a tenant.
MAX_POLICY_RULES: Final[int] = 64
# Ceiling on ONE tenant policy document's JSON-encoded size, well under the 256 KiB
# pre-auth body cap so a runaway policy payload can never bloat Redis. Rules are small
# (a scope name + a couple of numbers), so this is generous.
MAX_POLICY_DOC_BYTES: Final[int] = 16384

# --- ReBAC relation-tuple layer (Zanzibar-style PROJECTION of committed grants). ---
# STRICTLY ADDITIVE to the authoritative grant model: the tuple layer is a best-effort,
# Redis-auto-expiring projection of committed compartment grants that backs an
# operator-only, capability-gated relation READ for the console Knowledge-Graph. It is a
# projection, NOT a weakening — GrantStore.issue/has_active_grant/revoke, the payload
# lock, and WORM are byte-for-byte unchanged. All three caps live here (hard limits in
# ONE place) and every one is fail-closed: hitting a closure cap returns a DENY, past the
# roster cap the read fail-softs.
#
# The transitive-closure check(subject, relation, object) is a hop-and-fanout-capped BFS
# over member tuples, capped by the two limits below so it can NEVER be an unbounded walk.
# In v1 the tuple set is DIRECT (depth 1: compartment#member@agent), so closure is
# trivially shallow — the caps are STRUCTURAL, enforced for future nesting (groups/roles,
# object-to-object rewrites) so the walk shape can never become a CPU/timing oracle.
MAX_RELATION_DEPTH: Final[int] = 4        # Transitive-closure hop ceiling. Closure follows
#   subject-set rewrites at most this many hops; hitting it returns False (fail-closed
#   deny), never a deeper walk. v1 tuples are direct (depth 1) — this is the future-nesting
#   guard, so closure can never become an unbounded walk.
MAX_RELATION_FANOUT: Final[int] = 1000    # Total tuples a single closure walk may expand
#   (BFS visit bound across all hops). A second, independent ceiling on total work so a
#   WIDE (not just deep) tuple set still can't blow up the walk; exceeding it fails closed.
MAX_RELATION_ROSTER: Final[int] = 1000    # Rows per admin relation-listing SCAN read
#   (GET /v1/admin/directory/relations). Mirrors MAX_QUARANTINE_ROSTER — bounds the
#   operator read; fail-soft ([]) past the cap, since it backs a listing, never a decision.

# Key namespace (Zanzibar tuple, tenant-scoped) — mirrors the mcpip:grant:/mcpip:quarantine:
# convention:  mcpip:rel:{tenant}:{object}#{relation}@{subject}
# e.g.  mcpip:rel:aegis-dynamics:{FALCON_uuid}#member@agent-aegis-2
# The RelationTupleStore._key helper is the ONLY place it is formatted. It shares NOTHING
# with canonical_json / enforce_argument_safety / the scrypt PIN-hash — plain f-string
# interpolation of already-validated tenant/compartment/agent strings, no lock hash.
RELATION_KEY_PREFIX: Final[str] = "mcpip:rel"

# --- Community-gate (author-your-own CEL gate — Phase 2 seam) hard limit. -----------
# Ceiling on a gate manifest's declared ``max_cost`` — the STATIC CEL evaluation-cost
# estimate an approved gate must provably stay under. A gate whose statically-proven cost
# exceeds this budget is refused at approval; because CEL is non-Turing-complete it is
# statically analyzable, so the bound is PROVABLE (not hoped-for), which — together with a
# hard eval timeout in the deferred engine — keeps a community gate from ever becoming a
# CPU/timing oracle on the hot path. Mirrors the Kubernetes ValidatingAdmissionPolicy
# per-expression CEL cost budget. It is validated as pure DATA at submit/approve
# (``max_cost <= MAX_GATE_COST``); the actual cost PROVER needs the DEFERRED CEL runtime
# (docs/integrate/EXTENSIBILITY.md §8), so no gate can be APPROVED until an engine is registered
# (no approve-without-proof). Kept here because hard limits live in ONE place.
MAX_GATE_COST: Final[int] = 1_000_000

# --- Forensic payload capture (OPTIONAL, admin/investigator side-channel). --------
# How long an encrypted forensic capture lives in Redis before it expires (SETEX).
# Bounded so captures never grow unboundedly and a stale correlation_id is an honest
# miss; an operator/investigator acts on it well within this window, and no agent-side
# path can extend it. One hour mirrors the quarantine freeze window.
FORENSIC_TTL_SECONDS: Final[int] = 3600
# Ceiling on ONE forensic capture's canonical plaintext snapshot (alias + already-
# bounded arguments + non-secret identity context). Sized above MAX_CANONICAL_BYTES —
# arguments are already capped at MAX_CANONICAL_BYTES at ingress — so a legitimate full
# snapshot (alias, identity, decision context wrapped around those arguments) still fits
# while a pathological blob is dropped (capture is best-effort, never a hard failure).
MAX_FORENSIC_PAYLOAD_BYTES: Final[int] = MAX_CANONICAL_BYTES + 4096

# --- Out-of-band authenticator webhook (step-up OTP delivery) hard limits. --------
# Ceiling on how many bytes of a webhook receiver's response body are read back. The
# response is a delivery ACK only — its content is never used, so we cap the read so a
# hostile/misbehaving sink cannot stream an unbounded body into the gateway. Kept small:
# a 2xx status is the whole contract.
MAX_AUTHN_WEBHOOK_RESPONSE_BYTES: Final[int] = 4096
# Bounds on the operator-configured webhook timeout (Settings.authn_webhook_timeout_s).
# A per-request wall-clock ceiling on connect+read; clamped so a misconfiguration can
# neither hang a staging request indefinitely nor set a sub-100ms value that always
# fails closed. The Settings default (5s) sits inside this band.
MIN_AUTHN_WEBHOOK_TIMEOUT_S: Final[float] = 0.5
MAX_AUTHN_WEBHOOK_TIMEOUT_S: Final[float] = 30.0

# --- JWKS refresh (off-hot-path verification-key-set rotation) hard limits. --------
# Ceiling on how many keys a fetched JWKS document may carry. A rotating IdP / workload-
# identity STS keeps only a small overlap window of active signing keys (typically 2-3;
# the old key stays published across the rotation window), so this bound is generous while
# refusing a pathological or hostile document from expanding the by-kid map without limit.
# A doc over this cap fails the refresh CLOSED — the CURRENT (already-validated, non-empty)
# key set is retained unchanged, never emptied. It is enforced by JWKSRefresher at refresh
# time; the JWKSKeyProvider construction remains the authoritative per-key validator.
MAX_JWKS_KEYS: Final[int] = 32
# Ceiling on the fetched JWKS response BODY read back over the network. A bounded read so a
# hostile / misbehaving JWKS endpoint cannot stream an unbounded body into the gateway. Sized
# to comfortably hold MAX_JWKS_KEYS public keys (even RSA-4096 JWKs) yet stay well under the
# 256 KiB pre-auth body cap; a body exceeding it fails the refresh closed (current set kept).
MAX_JWKS_DOC_BYTES: Final[int] = 65536

# --- Opt-in vendor telemetry beacon (OFF the hot path, fail-open) hard limits. -----
# Bounds on the operator-configured beacon interval (Settings.telemetry_interval_s),
# clamped at beacon construction. A per-beacon wall-clock cadence: floored so a
# misconfiguration cannot turn the best-effort beacon into a self-inflicted DoS on the
# vendor receiver (or the local Redis aggregate scan), and ceilinged so an absurd value
# still heartbeats within a day. The Settings default (3600s = 1h) sits inside this band.
MIN_TELEMETRY_INTERVAL_S: Final[float] = 60.0
MAX_TELEMETRY_INTERVAL_S: Final[float] = 86400.0
# Ceiling on how many bytes of the beacon receiver's response (ACK) are read back. The
# response is never used — a 2xx is the whole contract — so the read is bounded so a
# hostile/misbehaving receiver cannot stream an unbounded body into the gateway.
MAX_TELEMETRY_RESPONSE_BYTES: Final[int] = 4096
# Ceiling on how many tenant-prefixed telemetry keys the deployment-wide aggregate SCAN
# collects before stopping. The aggregate is off the hot path (only the beacon / the
# admin stats read touch it) and fail-soft, but the scan must stay bounded so a Redis with
# a pathological number of tenant partitions cannot make one aggregate pass unbounded.
MAX_TELEMETRY_TENANTS: Final[int] = 10000

# --- Deny-response playbook (opt-in deterministic automation loop) hard limits. ----
# The playbook tails the durable WORM buffer for high-signal deny events and, per a
# deterministic policy, responds off the hot path: freeze the offending agent (quarantine)
# and alert operators. Every cadence/scan/fan-out bound lives here; the reason allow-set is
# a CLOSED enum. None of this runs on the decision path — a response can never block/flip an
# authorization (it reads already-committed records and acts asynchronously).
MIN_RESPONSE_INTERVAL_S: Final[float] = 15.0      # Fastest poll — near-real-time, bounded.
MAX_RESPONSE_INTERVAL_S: Final[float] = 3600.0    # Slowest poll (1h).
MAX_RESPONSE_ACTIONS_PER_TICK: Final[int] = 50    # Responses dispatched per poll (anti-storm).
MAX_RESPONSE_SCAN: Final[int] = 2000              # Raw WORM entries examined per poll.
MAX_RESPONSE_RECIPIENTS: Final[int] = 20          # Email recipients honored from the config.
MAX_RESPONSE_ACK_BYTES: Final[int] = 4096         # Bytes of a Slack webhook ACK read back.
RESPONSE_BURST_WINDOW_S: Final[int] = 300         # Sliding window for the per-agent deny count.
RESPONSE_COOLDOWN_S: Final[int] = 3600            # Act at most once per (tenant,agent,reason).
# The CLOSED allow-set of deny reasons the playbook MAY act on (a subset is activated by
# config). Every member is a real ``DenyReason`` value; the operator can never widen beyond
# this set. ``canary_tripped`` is the single unambiguous intrusion signal; the rest are
# probe-shaped denials that warrant a response only in a burst.
RESPONSE_TRIGGER_REASONS: Final[frozenset[str]] = frozenset(
    {
        "canary_tripped",
        "identity_injection",
        "cross_tenant",
        "compartment_denied",
        "payload_mismatch",
        "pin_mismatch",
        "sender_constraint_required",
        "unknown_alias",
    }
)
# Reasons that justify a response on a SINGLE occurrence (no burst threshold): a tripped
# decoy is unambiguous. Everything else needs ``response_burst_threshold`` hits in-window.
RESPONSE_SINGLE_SHOT_REASONS: Final[frozenset[str]] = frozenset({"canary_tripped"})

# --- Operator-user roster (admin-managed team, email-keyed) hard limits. -----------
# The console operator/team roster is a per-tenant, email-keyed record set the admin
# manages (invite / role / status / remove). It is a MANAGEMENT surface only — the
# ``role`` label authorizes NOTHING (the role-claim invariant holds); identity + authz
# still come exclusively from a verified JWT + capabilities. These bound the roster so
# it stays scannable at scale and an over-cap invite fails closed (opaque deny).
MAX_OPERATOR_USERS: Final[int] = 100000  # Roster cardinality ceiling per tenant.
MAX_OPERATOR_EMAIL_LEN: Final[int] = 254  # RFC 5321 max email length.
MAX_OPERATOR_PAGE: Final[int] = 200  # Rows per admin roster-listing page (cursor read).

# --- Operator decision-history query (activity-at-scale) hard limit. ----------------
# ``GET /v1/admin/decisions`` is the operator's date-ranged, multi-filtered, cursor-paged
# view over the SAME tenant-scoped WHITELIST projection the live ``/recent`` feed serves
# (alias/decision/deny_reason/transport class/risk/classification/correlation/ts + the
# whitelisted worm_sequence + event_id) — it exposes NOTHING new, just pages the operator's
# own WORM decision tail. This bounds one page; a caller-supplied ``limit`` above it clamps
# down (never up). The internal per-call scan budget/batch (how deep the reverse walk goes
# to FILL a filtered page) are read-tuning knobs beside ``_RECENT_DECISIONS_SCAN`` in
# ``audit/worm_logger.py``, not request bounds.
MAX_DECISIONS_PAGE: Final[int] = 200  # Rows per admin decision-history page (cursor read).

# --- Opt-in license REFRESH (off the hot path, fail-open) hard limit. --------------
# Ceiling on how many bytes of a candidate license document the off-hot-path refresh
# reads back over the network before refusing (fail-closed: the last-good license is
# retained, never emptied). A license is a small signed JSON entitlement doc, so this
# bound is generous while refusing a hostile / misbehaving receiver from streaming an
# unbounded body into the gateway. Enforced by LicenseRefresher at fetch time; the
# license-root Ed25519 verification (verify_license_bytes) remains authoritative for
# content. Sized to match the JWKS document cap (a comparable small signed doc).
MAX_LICENSE_DOC_BYTES: Final[int] = 65536

# The one and only generic message that ever crosses the agent boundary.
AGENT_FACING_DENY_MESSAGE: Final[str] = "MCPIP: request denied by policy."


# ---------------------------------------------------------------------------
# §0.2  FORBIDDEN CODEPOINTS — reject_unsafe_string().
# ---------------------------------------------------------------------------
#
# We build an explicit frozenset of *individually enumerated* forbidden zero-width
# codepoints, plus range predicates for the control and bidi bands. Ranges are kept
# as (lo, hi) inclusive tuples so the scan stays branch-cheap and auditable.

# Zero-width / invisible characters that could smuggle instructions past a human
# reviewer or a naive tokenizer.
_ZERO_WIDTH: Final[frozenset[int]] = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
        0x00AD,  # SOFT HYPHEN
    }
)

# Inclusive ranges of forbidden codepoints. Order does not matter; we scan all.
_FORBIDDEN_RANGES: Final[tuple[tuple[int, int], ...]] = (
    (0x0000, 0x001F),  # C0 controls (includes TAB, LF, CR — rejected in ingress args).
    (0x007F, 0x009F),  # DEL + C1 controls.
    (0x202A, 0x202E),  # Bidi embeddings / overrides (LRE..RLO).
    (0x2066, 0x2069),  # Bidi isolates (LRI..PDI).
)


# Unicode general categories that are never legitimate in an ingress string: control
# (Cc — also covered by the C0/C1 ranges), FORMAT marks (Cf — bidi marks U+200E/200F,
# Arabic letter mark U+061C, and every other invisible directional/format char), and the
# line/paragraph separators (Zl/Zp — U+2028/U+2029). Catching these by CATEGORY (not a
# hand-maintained list) closes the whole class in one place — including the bidi marks
# that slip past NFKC folding and would otherwise let an identity-shaped key like
# "role‎" evade the hard-deny identity filter.
_FORBIDDEN_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _is_forbidden_codepoint(cp: int) -> bool:
    """Return True if the Unicode code point ``cp`` is in a forbidden band."""
    if cp in _ZERO_WIDTH:
        return True
    for lo, hi in _FORBIDDEN_RANGES:
        if lo <= cp <= hi:
            return True
    # U+0020 (plain space) is category Zs and is allowed; Zl/Zp/Cc/Cf are not.
    if unicodedata.category(chr(cp)) in _FORBIDDEN_CATEGORIES:
        return True
    return False


def reject_unsafe_string(s: str, field: str) -> str:
    """
    Normalize and validate an ingress string (§0.2).

    Processing order is fixed and load-bearing:

      1. NFC-normalize (canonical composition) so equivalent sequences collapse
         to one representation *before* any scanning or length check.
      2. Scan every code point; raise ``ValueError`` on the first forbidden one.
      3. Enforce the post-NFC length ceiling.

    Returns the NFC form (callers should store/hash the returned value, not the
    original, so downstream canonicalization is idempotent).

    PRINTABLE-ASCII FAST PATH. Step 2 is skipped — never weakened — when the NFC form is
    entirely printable ASCII, which is the overwhelming majority of real ingress. The skip
    is sound because that band is provably disjoint from every forbidden set: ``_ZERO_WIDTH``
    starts at U+00AD; the C0 range ends at U+001F and the DEL/C1 range starts at U+007F, so
    U+0020..U+007E falls between them; the bidi bands are far above; and no printable-ASCII
    codepoint carries category Cc/Cf/Zl/Zp (ASCII's only Cc are U+0000..U+001F and U+007F,
    which ``str.isprintable`` already excludes, and ASCII contains no Cf/Zl/Zp at all).
    ``str.isascii()``/``str.isprintable()`` are C-level scans, so this replaces a
    per-character Python call to ``unicodedata.category`` with two linear passes — the cost
    that dominated the guard on ASCII payloads.

    This is the SAME argument the Rust accelerator already relies on to decide pure ASCII
    in-process instead of deferring (``rust/mcpip_fastwalk/src/lib.rs``,
    ``reject_unsafe_string``). Both sides must keep agreeing: the returned NFC string, the
    accept/reject decision, and the exact ``ValueError`` message are all unchanged by this
    path, which is what ``tests/test_string_guard_differential.py`` proves exhaustively over
    every codepoint rather than by sampling.

    Raises:
        ValueError: on any control/bidi/zero-width character, or over-length.
                    Upstream maps this to SCHEMA_VIOLATION / ILLEGAL_CHARACTER.
    """
    nfc = unicodedata.normalize("NFC", s)
    if not (nfc.isascii() and nfc.isprintable()):
        for ch in nfc:
            if _is_forbidden_codepoint(ord(ch)):
                raise ValueError(
                    f"illegal character U+{ord(ch):04X} in field '{field}'"
                )
    if len(nfc) > MAX_STRING_LEN:
        raise ValueError(
            f"field '{field}' exceeds MAX_STRING_LEN ({len(nfc)} > {MAX_STRING_LEN})"
        )
    return nfc


# ---------------------------------------------------------------------------
# §0.3  CANONICAL JSON — byte-exact contract shared by lock hashing and WORM.
# ---------------------------------------------------------------------------


def _nfc(obj: Any) -> Any:
    """
    Recursively rebuild ``obj`` with every string (dict keys AND values) NFC-normalized.

    Only JSON-native types are permitted; anything else is a fail-closed TypeError.
    bool must be checked before int (bool is a subclass of int in Python).
    """
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        # NaN/Inf are rejected later by json.dumps(allow_nan=False); pass through here.
        return obj
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        rebuilt: dict[str, Any] = {}
        for key, value in obj.items():
            if not isinstance(key, str):
                raise TypeError(
                    f"canonical_json: object key must be str, got {type(key).__name__}"
                )
            rebuilt[unicodedata.normalize("NFC", key)] = _nfc(value)
        return rebuilt
    if isinstance(obj, list):
        return [_nfc(item) for item in obj]
    # Tuples, sets, bytes, custom objects, etc. — reject fail-closed.
    raise TypeError(f"canonical_json: unsupported type {type(obj).__name__}")


def canonical_json(obj: Any) -> bytes:
    """
    Produce deterministic bytes for hashing/signing (§0.3).

    Contract (must match byte-for-byte across lock hashing and the WORM log):
      1. Recursively NFC-normalize every str (keys and values).
      2. Reject NaN/Inf (allow_nan=False).
      3. Sort object keys lexicographically by Unicode code point.
      4. separators=(",", ":")  — no whitespace.
      5. ensure_ascii=False, then encode UTF-8.

    Any non-JSON-native type -> TypeError (fail-closed) via ``_nfc``.

    Dispatch: when the opt-in Rust fast-walker is enabled (``MCPIP_FAST_WALKER=1``)
    this delegates to the byte-identical Rust encoder via ``bridge.fastwalk`` — the
    SAME canonicalizer is therefore used at register AND consume (the flag is read once
    per process). The import is lazy/inside the function, mirroring the existing lazy
    import at ``_validate_arguments``, to avoid a circular load (bridge imports
    interfaces). Pure-Python (``_canonical_json_py``) is the default and the fallback.
    """
    from bridge import fastwalk

    if fastwalk.FAST_ENABLED:
        return fastwalk.canonical_json(obj)
    return _canonical_json_py(obj)


def _canonical_json_py(obj: Any) -> bytes:
    """Pure-Python canonical JSON — the source-of-truth implementation (§0.3).

    This is the default path and the fallback the Rust shim defers to; it must never
    call back through the ``canonical_json`` dispatcher (that would recurse).
    """
    normalized = _nfc(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """SHA-256 of ``data`` as lowercase hex."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# §0.4  TIMING SAFETY — every secret/hash/token comparison funnels through here.
# ---------------------------------------------------------------------------


def constant_time_equals(a: str, b: str) -> bool:
    """
    Timing-safe string equality via ``secrets.compare_digest``.

    Use for every comparison of a token, hash, PIN-hash, signature-hex, or secret.
    ``compare_digest`` on ``str`` requires both operands be ASCII; our inputs are
    always hex digests or ASCII tokens, satisfying that constraint.
    """
    return secrets.compare_digest(a, b)


# ---------------------------------------------------------------------------
# §1.1  ENUMS
# ---------------------------------------------------------------------------


class SourceFormat(str, Enum):
    """Provider dialects the Bridge accepts."""

    OPENAI_TOOL_CALL = "openai_tool_call"        # unchanged
    ANTHROPIC_TOOL_USE = "anthropic_tool_use"    # unchanged
    RAW_MCP = "raw_mcp"                          # unchanged (legacy canonical shape)
    GEMINI_FUNCTION_CALL = "gemini_function_call"
    BEDROCK_TOOL_USE = "bedrock_tool_use"
    MCP_JSONRPC = "mcp_jsonrpc"                  # JSON-RPC 2.0 tools/call
    A2A_TASK = "a2a_task"                        # A2A Task envelope (single DataPart invocation)


class RiskTier(str, Enum):
    """Per-alias execution risk gate."""

    AUTO = "auto"
    PIN_REQUIRED = "pin_required"


class Decision(str, Enum):
    """Terminal gateway verdict."""

    ALLOW = "allow"
    DENY = "deny"


class Classification(str, Enum):
    """
    Data-sensitivity classification carried by a compartmented alias.

    Display/annotation only — it never gates an authorization decision (that is the
    capability/compartment entitlement's job). It rides in the catalog so an operator
    dashboard can render the sensitivity of an MCP a team is allowed to see.
    """

    UNCLASSIFIED = "unclassified"
    RESTRICTED = "restricted"
    CLASSIFIED = "classified"


class DenyReason(str, Enum):
    """
    Internal-only deny taxonomy. These strings appear in the WORM audit log and
    in docs, but NEVER cross the agent boundary (the agent sees only a correlation id).
    """

    IDENTITY_INJECTION = "identity_injection"
    UNKNOWN_FORMAT = "unknown_format"
    UNKNOWN_VENDOR = "unknown_vendor"
    SCHEMA_VIOLATION = "schema_violation"
    DEPTH_EXCEEDED = "depth_exceeded"
    SIZE_EXCEEDED = "size_exceeded"
    ILLEGAL_CHARACTER = "illegal_character"
    UNKNOWN_ALIAS = "unknown_alias"
    CROSS_TENANT = "cross_tenant"
    JWT_INVALID = "jwt_invalid"
    JWT_CLAIMS_MISSING = "jwt_claims_missing"
    PIN_REQUIRED = "pin_required"
    PIN_NOT_FOUND = "pin_not_found"
    PIN_MISMATCH = "pin_mismatch"
    PAYLOAD_MISMATCH = "payload_mismatch"
    LOCK_ERROR = "lock_error"
    TRANSPORT_ERROR = "transport_error"
    RATE_LIMITED = "rate_limited"
    INTERNAL = "internal"
    # --- Compartmented team-MCP separation (UUID capability/entitlement model). ---
    COMPARTMENT_DENIED = "compartment_denied"
    CAPABILITY_DENIED = "capability_denied"
    # --- Sender-constraint (proof-of-possession) demanded by the RESOURCE. --------
    # An alias flagged ``require_sender_constraint`` demands a key-proven token; a
    # bare bearer JWT (no ``cnf``) reaching such an alias is denied with this reason
    # (distinct from JWT_INVALID so the WORM trail separates "no proof presented for
    # a resource that requires one" from "a proof was presented but failed").
    SENDER_CONSTRAINT_REQUIRED = "sender_constraint_required"
    # --- Deception tripwire (canary aliases). ---------------------------------
    CANARY_TRIPPED = "canary_tripped"
    AGENT_QUARANTINED = "agent_quarantined"
    # --- Operator kill-switch (admin-issued principal revocation). -------------
    # An admin holding ``CAP_DIRECTORY_ADMIN`` revoked this principal (agent_id);
    # the hot path then denies EVERY request from it, fail-closed, until an admin
    # reactivates it. Deliberately DISTINCT from ``AGENT_QUARANTINED`` (the
    # automatic canary-tripwire freeze) so the WORM trail separates an operator's
    # revocation from a tripwire. This is a DENY-only control — it never mints
    # identity, so it does not touch IdP sovereignty.
    PRINCIPAL_REVOKED = "principal_revoked"
    # --- Operator skill kill-switch (admin-disabled alias). --------------------
    # An admin holding ``CAP_DIRECTORY_ADMIN`` disabled this alias for the tenant;
    # every invocation is denied until it is re-enabled. Enforced AFTER alias
    # resolution (and after the canary tripwire) but BEFORE the entitlement gates —
    # a disabled skill is off for everyone, regardless of capability. It never
    # edits the alias→target mapping; it only DENIES, so the obfuscation layer is
    # untouched. Value is ``alias_disabled`` (not ``skill_*``) so it can never trip
    # the ``skill_``-substring metric-label hygiene guard.
    SKILL_DISABLED = "alias_disabled"
    # --- Out-of-band authenticator delivery (step-up OTP push). ----------------
    # The payload-bound one-time code was minted and its lock registered, but the
    # out-of-band authenticator channel could NOT deliver it (production with no
    # channel configured, or a configured channel whose ``deliver`` raised). This is
    # fail-closed: register_lock raises so NO 202/challenge_id is ever produced —
    # the PIN_REQUIRED action cannot complete, honestly, rather than staging a
    # challenge no authenticator can ever answer. Deliberately DISTINCT from a generic
    # ``LOCK_ERROR`` so the WORM trail separates "authenticator delivery failed /
    # unconfigured" from a Redis lock-transport failure. It stays WORM-only; the agent
    # sees only the opaque ``MCPIPDenied``. Delivery is DOWNSTREAM of the lock — this
    # never touches how the OTP is derived or bound.
    OTP_DELIVERY_FAILED = "otp_delivery_failed"
    # --- Deny-only policy overlay (velocity cap + amount ceiling). -------------
    # The stateless policy engine (services/policy_engine.py) denied this action —
    # either a fixed-window velocity cap was exceeded, an amount-ceiling rule was
    # violated, a named amount field was present but non-numeric (refused rather than
    # coerced), OR the policy evaluation itself failed closed (Redis unavailable, a
    # malformed stored policy document, or a raising provider). The concrete cause
    # ('velocity exceeded' vs 'amount exceeds ceiling' vs 'policy evaluation
    # unavailable') rides ONLY in the WORM ``detail`` string — it is NEVER a metric
    # label. Deliberately DISTINCT from ``RATE_LIMITED`` (the step-up scrypt-amplifier
    # DoS guard emitted by a different subsystem) so overloading that metric/alert
    # cannot happen: every policy-subsystem failure stays attributable to the policy
    # gate. The gate is DENY-ONLY — it can only ADD this deny; it never allows what an
    # earlier gate denied, never mints identity, never mutates the intent or target. It
    # stays WORM-only; the agent sees only the opaque ``MCPIPDenied``.
    POLICY_DENIED = "policy_denied"
    # --- Deny-only COMMUNITY-GATE overlay (author-your-own CEL gate — Phase 2). --
    # A community-authored declarative gate (services/community_gate.py, pipeline step
    # 4c′) denied this action — OR the gate seam itself failed closed (a registered gate
    # engine raised / timed out / tripped its static cost bound). Deliberately DISTINCT
    # from ``POLICY_DENIED`` (the G3 operator velocity/amount overlay) so the WORM/metric
    # trail never conflates an operator rate rule with a community gate, and DISTINCT from
    # ``RATE_LIMITED`` (the step-up scrypt-amplifier DoS guard). Deny-only + monotonic by
    # construction: the seam can ONLY add this deny — it never allows what an earlier gate
    # denied, never mints identity, never mutates the intent or target. When NO community
    # gate engine is registered the seam is a strict fail-closed NO-OP (the default
    # provider always continues — there are genuinely no community gates enforced, the
    # honest 'none configured' state), so this reason surfaces only once a real engine is
    # wired in and denies (or errors). The concrete gate id / cause rides ONLY in the WORM
    # ``detail`` string — NEVER a metric label; the value has NO ``skill_`` substring so it
    # clears the metric-label hygiene guard. It stays WORM-only; the agent sees only the
    # opaque ``MCPIPDenied``.
    POLICY_GATE_DENIED = "policy_gate_denied"


class DenyFamily(str, Enum):
    """
    OPERATOR-FACING triage grouping over :class:`DenyReason` — a coarse, closed set
    that answers "what do I do next?", not "what exactly happened".

    A 29-member taxonomy is right for the WORM record (an auditor needs the precise
    cause) and wrong for a console (an operator scanning an incident needs to sort by
    the ACTION each deny implies). This enum is that second view, and nothing more:

      * It is a strict COARSENING of ``DenyReason`` — every family is derivable from
        the reason alone, carries strictly LESS information, and is therefore safe
        anywhere the reason itself is already safe. It is never persisted, never a
        WORM field, and never widens an existing projection.
      * It NEVER crosses the agent boundary. The agent still sees only ``MCPIPDenied``
        + a correlation id; grouping denials for an operator does not un-hide them for
        the caller.
      * It is DERIVED, never stored, so it cannot drift from the reason it summarizes.

    Families are ordered by operator urgency, most urgent first.
    """

    #: We believe the caller is hostile — investigate now.
    TRIPWIRE = "tripwire"
    #: The caller is who they say, but is not allowed to do this. Grant, or don't.
    NOT_PERMITTED = "not_permitted"
    #: Identity itself failed — an IdP / token problem, not an authorization one.
    IDENTITY = "identity"
    #: A human must approve (or the approval channel failed). Someone has to act.
    NEEDS_HUMAN = "needs_human"
    #: The request was never well-formed. Fix the calling integration.
    MALFORMED = "malformed"
    #: The alias is unknown or switched off. A catalog problem, not a caller problem.
    CATALOG = "catalog"
    #: OUR failure, not the caller's — page someone. Never blame the agent for these.
    INFRASTRUCTURE = "infrastructure"


#: Total ``DenyReason`` → ``DenyFamily`` map. EXHAUSTIVE BY CONTRACT: adding a
#: ``DenyReason`` without adding it here fails ``test_deny_family_is_total`` — so a new
#: reason can never silently land in a console bucket that misrepresents what an
#: operator should do about it. Keep the grouping keyed on the OPERATOR'S NEXT ACTION;
#: when a reason could arguably sit in two families, choose the one whose remediation
#: is correct, because that is what the family is for.
DENY_FAMILY: Final[Mapping[DenyReason, DenyFamily]] = MappingProxyType({
    # Deception tripwires + the freeze they trigger. Highest urgency: a canary is only
    # ever touched by something enumerating the estate.
    DenyReason.CANARY_TRIPPED: DenyFamily.TRIPWIRE,
    DenyReason.AGENT_QUARANTINED: DenyFamily.TRIPWIRE,
    # Identity verified; authority absent. The operator decides whether to grant.
    DenyReason.CROSS_TENANT: DenyFamily.NOT_PERMITTED,
    DenyReason.COMPARTMENT_DENIED: DenyFamily.NOT_PERMITTED,
    DenyReason.CAPABILITY_DENIED: DenyFamily.NOT_PERMITTED,
    DenyReason.POLICY_DENIED: DenyFamily.NOT_PERMITTED,
    DenyReason.POLICY_GATE_DENIED: DenyFamily.NOT_PERMITTED,
    # The claim of identity failed. Remediation lives in the IdP or the token minting,
    # never in MCPIP's grants — so this must NOT read as "not permitted".
    DenyReason.JWT_INVALID: DenyFamily.IDENTITY,
    DenyReason.JWT_CLAIMS_MISSING: DenyFamily.IDENTITY,
    DenyReason.SENDER_CONSTRAINT_REQUIRED: DenyFamily.IDENTITY,
    DenyReason.PRINCIPAL_REVOKED: DenyFamily.IDENTITY,
    # IDENTITY_INJECTION is an attempt to ASSERT identity through arguments. It is a
    # malformed-input rejection mechanically, but the operator's next move is an
    # identity investigation, so it groups with identity.
    DenyReason.IDENTITY_INJECTION: DenyFamily.IDENTITY,
    # A person has to approve — or the channel that would ask them broke.
    DenyReason.PIN_REQUIRED: DenyFamily.NEEDS_HUMAN,
    DenyReason.PIN_NOT_FOUND: DenyFamily.NEEDS_HUMAN,
    DenyReason.PIN_MISMATCH: DenyFamily.NEEDS_HUMAN,
    DenyReason.PAYLOAD_MISMATCH: DenyFamily.NEEDS_HUMAN,
    DenyReason.OTP_DELIVERY_FAILED: DenyFamily.NEEDS_HUMAN,
    # The request never parsed / never passed the safety walker. Fix the integration.
    DenyReason.UNKNOWN_FORMAT: DenyFamily.MALFORMED,
    DenyReason.UNKNOWN_VENDOR: DenyFamily.MALFORMED,
    DenyReason.SCHEMA_VIOLATION: DenyFamily.MALFORMED,
    DenyReason.DEPTH_EXCEEDED: DenyFamily.MALFORMED,
    DenyReason.SIZE_EXCEEDED: DenyFamily.MALFORMED,
    DenyReason.ILLEGAL_CHARACTER: DenyFamily.MALFORMED,
    # The alias does not exist here, or an operator switched it off.
    DenyReason.UNKNOWN_ALIAS: DenyFamily.CATALOG,
    DenyReason.SKILL_DISABLED: DenyFamily.CATALOG,
    # Ours. An operator must never spend time debugging a caller for these.
    DenyReason.LOCK_ERROR: DenyFamily.INFRASTRUCTURE,
    DenyReason.TRANSPORT_ERROR: DenyFamily.INFRASTRUCTURE,
    DenyReason.RATE_LIMITED: DenyFamily.INFRASTRUCTURE,
    DenyReason.INTERNAL: DenyFamily.INFRASTRUCTURE,
})


def deny_family(reason: DenyReason | str) -> DenyFamily | None:
    """
    Coarsen a ``DenyReason`` (enum or its wire string) to its operator triage family.

    Returns ``None`` for a string that is not a known reason — callers render an
    unknown reason ungrouped rather than guessing a family, because a WRONG family is
    worse than no family: it tells an operator to take the wrong next action.
    """
    if isinstance(reason, DenyReason):
        return DENY_FAMILY.get(reason)
    try:
        return DENY_FAMILY.get(DenyReason(reason))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# §1.1b  CAPABILITY / COMPARTMENT CONSTANTS — UUID-identified authorization.
# ---------------------------------------------------------------------------
#
# Authorization is NEVER gated on the coarse ``role`` string. A principal may
# perform a privileged action IFF it holds the required capability UUID (carried in
# the JWT ``capabilities`` claim and/or a Redis-held entitlement/grant). These are
# fixed, well-known capability ids so every layer references the same value.

CAP_COMPARTMENT_GRANT: Final[str] = "9c2b6f14-7a3d-4e8b-b1c0-2f5a9d3e4c71"
CAP_COMPARTMENT_REVOKE: Final[str] = "3e7d1a95-6c4b-42f0-8a9e-1b2c3d4e5f60"
# Directory administration: revoke / reactivate a principal (the operator
# kill-switch) — and, later, persist the operator directory. Gates the
# ``/v1/admin/principals/*`` endpoints. A DENY-only authority: holding it lets an
# operator BLOCK a principal's requests, never mint one, so IdP sovereignty stands.
CAP_DIRECTORY_ADMIN: Final[str] = "b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20"
# Forensic payload read: retrieve the RECONSTRUCTED query (alias + normalized arguments
# + non-secret identity context) an agent sent for a given correlation_id, from the
# encrypted forensic capture store. Gates the SOLE ``GET /v1/admin/forensic/{id}``
# retrieval route. Deliberately DISTINCT from ``CAP_DIRECTORY_ADMIN``: holding
# directory-admin does NOT confer raw-payload read — forensic read is a separately-
# grantable, higher-sensitivity INVESTIGATOR authority (least privilege). No agent
# token ever carries it, so a reconstructed payload is structurally unreachable from
# the agent boundary. Like every capability it is matched constant-time and the ``role``
# claim still authorizes nothing. Minted once (a fresh uuid4) and frozen.
CAP_FORENSIC_READ: Final[str] = "d5f0c9a2-4b71-4e6a-9c83-1a7f2e6b4d90"
# Community-extension review: APPROVE (or reject) a Contributor-submitted extension
# manifest — the reviewer half of the author-your-own-skill workflow. Gates the
# ``GET /v1/admin/extensions/pending`` + ``POST /v1/admin/extensions/{id}/{approve,reject}``
# reviewer surface. Deliberately DISTINCT from ``CAP_DIRECTORY_ADMIN`` and
# ``CAP_FORENSIC_READ``: "can approve community extensions" is separable from "can
# revoke a principal" (directory-admin) and from "can read raw forensic payloads"
# (forensic-read). Holding either of those does NOT confer it — least privilege — and,
# like every capability, it is matched constant-time while the ``role`` claim still
# authorizes nothing. Minted once (a fresh uuid4) and frozen.
CAP_CATALOG_REVIEWER: Final[str] = "7a1f9c34-2e58-4b6d-9f01-3c7a5e2b8d46"

# Namespace for deriving per-compartment, SCOPED grant capabilities (see
# ``grant_capability_for``). Fixed so the derivation is stable across processes.
_CAP_GRANT_NAMESPACE: Final[uuid.UUID] = uuid.UUID(CAP_COMPARTMENT_GRANT)


def grant_capability_for(compartment_uuid: str) -> str:
    """
    Deterministic per-compartment grant-issuing capability UUID (RFC-4122 v5).

    The coarse ``CAP_COMPARTMENT_GRANT`` only marks a principal as a grant-issuing
    authority — it gates *use* of the ``skill_compartment_grant`` governance alias.
    Authority to actually issue a grant is COMPARTMENT-SCOPED: to grant compartment
    ``X`` the issuer must additionally hold ``grant_capability_for(X)``. Holding the
    scoped capability for compartment ``X`` can NEVER authorize issuing a grant for a
    different compartment ``Y`` (``Y != X``), which closes the cross-compartment
    delegation escape (a FALCON delegator cannot mint AEGIS access). Derived via
    uuid5 over the fixed grant namespace so it is stable, collision-free, and a
    well-formed UUID string that passes the JWT ``capabilities`` claim validator.

    ``compartment_uuid`` MUST already be a well-formed UUID string (callers pass the
    strict-validated grant-mandate ``compartment`` arg); it is validated here too so a
    malformed input fails closed rather than deriving a bogus capability.
    """
    uuid.UUID(compartment_uuid)  # fail-closed on a non-UUID compartment id.
    return str(uuid.uuid5(_CAP_GRANT_NAMESPACE, compartment_uuid))


MAX_CAPABILITIES: Final[int] = 32          # oversized list → fail-closed JWT_INVALID.
MAX_GRANT_TTL_SECONDS: Final[int] = 86400  # 24h ceiling on a delegated grant.
MIN_GRANT_TTL_SECONDS: Final[int] = 60     # floor — no sub-minute delegation.
DEFAULT_GRANT_TTL_SECONDS: Final[int] = 3600

# How long a canary-tripped agent stays frozen (every request denied
# AGENT_QUARANTINED). Long enough for an operator to act on the WORM alert;
# bounded so a false trip self-heals without a manual Redis intervention.
QUARANTINE_TTL_SECONDS: Final[int] = 3600


# ---------------------------------------------------------------------------
# §1.2  SwarmTrace / Hop — provenance of a multi-agent call chain.
# ---------------------------------------------------------------------------


class Hop(BaseModel):
    """One link in an agent delegation chain."""

    model_config = ConfigDict(extra="forbid", strict=True)

    hop_index: int = Field(ge=0, lt=MAX_CHAIN_HOPS)
    agent_id: str = Field(min_length=1, max_length=256)
    parent_agent_id: Optional[str] = Field(default=None, max_length=256)
    purpose: str = Field(min_length=1, max_length=MAX_STRING_LEN)

    @field_validator("agent_id", "purpose", mode="after")
    @classmethod
    def _clean_required_strings(cls, v: str) -> str:
        # agent_id and purpose are always present; scrub control/bidi/zero-width.
        return reject_unsafe_string(v, "hop")

    @field_validator("parent_agent_id", mode="after")
    @classmethod
    def _clean_optional_parent(cls, v: Optional[str]) -> Optional[str]:
        # None is legal (root hop); scrub only when present.
        if v is None:
            return None
        return reject_unsafe_string(v, "parent_agent_id")


class SwarmTrace(BaseModel):
    """An ordered, integrity-checked chain of hops. hop[0] is the root."""

    model_config = ConfigDict(extra="forbid", strict=True)

    trace_id: str
    hops: list[Hop] = Field(min_length=1, max_length=MAX_CHAIN_HOPS)

    @field_validator("trace_id", mode="after")
    @classmethod
    def _trace_id_is_uuid(cls, v: str) -> str:
        # trace_id must be a syntactically valid UUID; raise otherwise (fail-closed).
        uuid.UUID(v)
        return v

    @model_validator(mode="after")
    def _validate_chain_linkage(self) -> "SwarmTrace":
        """
        Enforce strict ordering and parent linkage:
          * hop_index equals list position (no gaps, no reordering).
          * hop 0 has parent_agent_id is None.
          * every later hop's parent_agent_id == previous hop's agent_id.
        """
        for position, hop in enumerate(self.hops):
            if hop.hop_index != position:
                raise ValueError(
                    f"hop_index {hop.hop_index} != list position {position}"
                )
            if position == 0:
                if hop.parent_agent_id is not None:
                    raise ValueError("root hop must have parent_agent_id=None")
            else:
                expected_parent = self.hops[position - 1].agent_id
                if hop.parent_agent_id != expected_parent:
                    raise ValueError(
                        "hop parent_agent_id must equal previous hop agent_id"
                    )
        return self


# ---------------------------------------------------------------------------
# §1.3  NormalizedIntent — the provider-agnostic ingress payload (NO identity).
# ---------------------------------------------------------------------------
#
# The recursive argument validator lives in bridge.intent_parser to keep the
# walking logic beside the parsers; interfaces.py imports it lazily inside the
# validator to avoid a circular import at module load time.


class NormalizedIntent(BaseModel):
    """
    The canonical shape every provider dialect normalizes into.

    Deliberately carries NO identity fields — identity comes exclusively from the
    verified JWT (§4 of the spec). ``arguments`` is deep-validated by the shared
    ``enforce_argument_safety`` walker (depth/size/char/identity-injection gates).
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    alias: str = Field(min_length=1, max_length=256)
    arguments: dict[str, Any]
    trace: SwarmTrace
    source_format: SourceFormat
    # NEW (A2A connector): recorded-not-trusted correlation provenance carried by the
    # A2A task envelope — task/context/message IDs + the declared (UNVERIFIED) actor/
    # delegation metadata. It is NOT a lock input (the payload lock hashes only
    # {tenant,agent,alias,arguments}; source_format/trace/a2a_context are excluded), is
    # NEVER merged into ``arguments`` (so it can neither enter the lock nor the agent
    # wire), and is surfaced ONLY to the WORM audit ctx as topology-free correlation.
    # None for all six non-A2A dialects — additive, backward-compatible.
    a2a_context: Optional[Mapping[str, Any]] = None

    @field_validator("alias", mode="after")
    @classmethod
    def _clean_alias(cls, v: str) -> str:
        return reject_unsafe_string(v, "alias")

    @field_validator("arguments", mode="after")
    @classmethod
    def _validate_arguments(cls, v: dict[str, Any]) -> dict[str, Any]:
        # Imported lazily: intent_parser imports interfaces, so a top-level import
        # here would be circular. The walker enforces depth/keys/arrays/canonical
        # size, string safety, and the identity-injection hard-deny.
        from bridge.intent_parser import enforce_argument_safety

        return enforce_argument_safety(v)


def project_a2a_context(
    ctx: dict[str, Any], a2a_context: Optional[Mapping[str, Any]]
) -> None:
    """Project a NormalizedIntent's ``a2a_context`` onto the WORM audit ctx.

    Shared by both entrypoints (``app/main.py`` + ``main.py``) so the recorded-not-
    trusted A2A correlation provenance lands identically on ALLOW and every DENY leaf,
    exactly like the ``jti`` / ``delegation_chain`` ctx fields. TOPOLOGY-FREE: the
    task/context/message IDs are opaque handles and the declared actor/metadata is
    UNVERIFIED (MCPIP's authorization identity is JWT-only) — so this authorizes
    NOTHING and is NEVER re-serialized to any agent-wire projection (the authorize
    response / /v1/catalog / tools/list build explicit whitelists and never serialize
    ctx). ``None`` (all six non-A2A dialects) records nothing — additive.
    """
    if a2a_context is None:
        return
    ctx["a2a_task_id"] = a2a_context.get("task_id")
    ctx["a2a_context_id"] = a2a_context.get("context_id")
    ctx["a2a_message_id"] = a2a_context.get("message_id")
    metadata = a2a_context.get("metadata")
    if metadata is not None:
        # Recorded-not-trusted declared metadata (bounded at parse by MAX_A2A_META_BYTES).
        ctx["a2a_metadata"] = metadata
        if isinstance(metadata, Mapping):
            actor = metadata.get("actor")
            if isinstance(actor, str):
                # The DECLARED (unverified) actor, surfaced as an operator correlation
                # hint — never an authorization input.
                ctx["a2a_declared_actor"] = actor


# ---------------------------------------------------------------------------
# §1.4  Identity (post-JWT, frozen) and AuthorizedIntent.
# ---------------------------------------------------------------------------


class Identity(BaseModel):
    """
    Sovereign machine identity, derived EXCLUSIVELY from a verified JWT.

    Frozen: once resolved it cannot be mutated anywhere in the pipeline.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    tenant_id: str
    agent_id: str
    role: str                 # descriptive label ONLY — never an authz input.
    issuer: str
    audience: str
    jti: Optional[str] = None
    # NEW: compartment UUID string this principal is natively scoped to, or None
    # (un-compartmented). Wire value is always a UUID; human labels are display-only.
    compartment: Optional[str] = None
    # NEW: frozen tuple of capability UUID strings the JWT asserts. tuple (not list)
    # so the frozen identity stays immutable and hashable; strict mode validates it.
    capabilities: tuple[str, ...] = ()
    # NEW: sender-constraint. When the JWT carries a `cnf` (confirmation) claim, this
    # is the RFC-7638 thumbprint (`jkt`) of the proof key the token is bound to. A
    # non-None value means the token is NOT a bearer token: the caller must also
    # present a matching proof-of-possession (see auth/pop.py). None → legacy bearer,
    # behaves EXACTLY as before.
    cnf_jkt: Optional[str] = None
    # NEW: delegation actor (RFC 8693 `act.sub`). When set, this token is a delegated
    # token — the agent (`agent_id`) is acting on behalf of the human principal named
    # here. Recorded for audit + used to require that the human factor is key-proven,
    # not merely asserted. None → not a delegation chain.
    act_sub: Optional[str] = None
    # NEW: True iff this token carries a `cnf` AND its minting issuer is designated an
    # ATTESTING issuer (e.g. a workload-identity STS with hardware-rooted attestation),
    # as opposed to a lower-assurance issuer merely trusted for identity. A resource
    # that DEMANDS sender-constraint (`require_sender_constraint`) is satisfied ONLY by
    # an attested cnf — so trusting a weak issuer for identity never downgrades the
    # sender-constraint gate. Single-issuer deployments treat their one issuer as
    # attesting by default, so this is True whenever `cnf_jkt` is set there.
    cnf_attested: bool = False
    # NEW: the FULL RFC-8693 nested delegation chain (`act.sub` -> `act.act.sub` -> ...)
    # as an ORDERED tuple of subjects, immediate actor first. `act_sub` above keeps the
    # single-hop (first) actor for backward compat; this captures every hop. WORM/audit
    # ONLY — like the `role` claim it authorizes NOTHING and never crosses the agent wire.
    # Empty tuple → not a delegation chain (legacy behavior unchanged).
    act_chain: tuple[str, ...] = ()
    # NEW: OPTIONAL session identity (UUID) this token asserts, or None. Distinguishes
    # SESSIONS of one agent_id in the WORM chain — an orchestrator's workers stop
    # collapsing into one indistinguishable principal. WORM/audit ONLY — like ``role``
    # and ``act_chain`` it authorizes NOTHING and never crosses the agent wire. Absent
    # → None, byte-for-byte legacy behavior (docs/SESSION_DELEGATION_DESIGN.md §1).
    session_id: Optional[str] = None
    # NEW: True iff the identity arrived via an ID-JAG token exchange (the token or its
    # header declared the id-jag token-type URN). Recognition ONLY — the token is still a
    # JWT verified exactly as any other. WORM/audit ONLY; authorizes NOTHING.
    id_jag: bool = False


class AuthorizedIntent(BaseModel):
    """A NormalizedIntent bound to a verified Identity plus its correlation id."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    intent: NormalizedIntent
    identity: Identity
    correlation_id: str


# ---------------------------------------------------------------------------
# §1.5  Transport ABC + result model.
# ---------------------------------------------------------------------------


class TransportResult(BaseModel):
    """Non-sensitive outcome of a downstream dispatch."""

    model_config = ConfigDict(extra="forbid", strict=True)

    ok: bool
    target: str
    status_code: int  # transport-native; 0 for mainframe RC=0.
    detail: str = ""
    echo: dict[str, Any] = Field(default_factory=dict)


class BaseTransport(ABC):
    """
    Pluggable execution backend. The pipeline selects an implementation by the
    alias's declared transport, then calls ``execute`` — proving the pipeline is
    fully decoupled from any concrete downstream (REST cloud, legacy mainframe, …).
    """

    @abstractmethod
    async def execute(
        self, intent: AuthorizedIntent, target: str
    ) -> TransportResult:
        """Dispatch ``intent`` to the resolved concrete ``target``."""
        raise NotImplementedError  # pragma: no cover - abstract contract.


# ---------------------------------------------------------------------------
# §1.5b  Authenticator delivery seam — out-of-band one-time-code delivery.
# ---------------------------------------------------------------------------
#
# The payload-bound one-time PIN is minted and locked by the auth engine
# (unchanged: ``secrets`` mint + ``PinValidator.register`` + scrypt/canonical_json).
# ONLY the DELIVERY of that code lives behind this seam: how the operator's enrolled
# authenticator / approver learns the code. The channel receives an immutable notice
# and is responsible for getting it to the out-of-band factor. The channel NEVER
# influences how the OTP is derived or bound — it is strictly downstream of register.


class AuthenticatorNotice(BaseModel):
    """
    Immutable envelope handed to an ``BaseAuthenticatorChannel`` to deliver a staged
    step-up code to the tenant's out-of-band authenticator / approver.

    Frozen (mirrors ``Identity``) and strict/forbid (mirrors ``TransportResult``): it
    is constructed once by the auth engine and passed to ``deliver`` — it is NEVER
    placed into the audit ctx nor returned in the 202 staging response, so the raw
    ``otp`` never crosses the agent wire or the WORM log. (Defence-in-depth: ``otp`` is
    also in the WORM ``_REDACT_KEYS`` set, so a stray copy could not persist.)
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    tenant_id: str
    challenge_id: str        # == the payload lock id the agent later spends.
    agent_id: str
    alias: str               # opaque agent-facing skill name (never the real target).
    risk_tier: RiskTier
    expires_in_s: int        # lock TTL — the receiver knows the approval window.
    otp: str                 # the raw one-time code — delivered, never persisted here.


class BaseAuthenticatorChannel(ABC):
    """
    Pluggable out-of-band delivery backend for the step-up one-time code.

    The composition root selects an implementation by deployment posture (a sandbox
    Redis stash for the runnable demo; a signed HTTPS webhook push in production), then
    the auth engine calls ``deliver`` after registering the payload lock. Delivery is
    fail-closed: a ``deliver`` that raises makes ``register_lock`` fail closed
    (``OTP_DELIVERY_FAILED``) so no unanswerable challenge is ever staged.
    """

    @abstractmethod
    async def deliver(self, notice: AuthenticatorNotice) -> None:
        """
        Deliver ``notice`` to the out-of-band authenticator. Return None on success;
        raise on any delivery failure (the engine maps that to a fail-closed deny).
        """
        raise NotImplementedError  # pragma: no cover - abstract contract.


# ---------------------------------------------------------------------------
# §1.5c  Policy overlay seam — a stateless, DENY-ONLY policy step.
# ---------------------------------------------------------------------------
#
# The policy engine sits between the entitlement/sender-constraint gates and the risk
# gate. It is a DENY-ONLY overlay: the ONLY actionable outcome is ``deny`` (raised as a
# ``POLICY_DENIED`` by the pipeline); ``continue`` merely means "fall through to the
# next gate" (which may itself deny). This is structural, not conventional — the
# decision type carries NO allow/override outcome, so a provider can never turn a
# would-be deny into an allow. ``PolicyContext`` is frozen and carries only
# already-validated pipeline values (never a mutable intent/target/identity handle), so
# a provider can neither mint identity nor mutate the resolved action.


class PolicyContext(BaseModel):
    """
    Immutable snapshot handed to a ``PolicyProvider`` — exactly the already-validated
    pipeline values a deny-only policy needs, and nothing more.

    Frozen + strict/forbid (mirrors ``Identity``/``AuthenticatorNotice``): a provider
    receives the resolved identity, the opaque agent-facing ``alias``, the coarse
    ``transport_class`` (never the real target), the ``risk_tier``, and the
    already-safety-checked ``arguments`` — but cannot mutate any of them, so the policy
    step can never rewrite the intent or the target it evaluates.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    identity: Identity
    alias: str
    transport_class: str
    risk_tier: RiskTier
    arguments: dict[str, Any]


class PolicyDecision(BaseModel):
    """
    A deny-only policy outcome.

    ``outcome`` is a closed two-value literal: ``'continue'`` (fall through to the next
    gate) or ``'deny'`` (the pipeline raises ``POLICY_DENIED``). There is deliberately
    NO ``'allow'``/override value — a policy can never grant what an earlier gate would
    refuse. ``detail`` is the operator-facing cause; it rides ONLY into the WORM
    ``detail`` string and is NEVER a metric label or an agent-facing field.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    outcome: Literal["continue", "deny"]
    detail: str = ""


class PolicyProvider(ABC):
    """
    Pluggable deny-only policy overlay evaluated between the entitlement gates and the
    risk gate. The pipeline treats ONLY ``outcome == 'deny'`` as actionable and wraps
    ``evaluate`` in a fail-closed ``try/except`` (any exception → ``POLICY_DENIED``), so
    even a buggy/raising provider fails closed, never open.
    """

    @abstractmethod
    async def evaluate(self, ctx: PolicyContext) -> PolicyDecision:
        """
        Evaluate the policy for ``ctx``. Return ``PolicyDecision(outcome='deny', …)`` to
        deny (``POLICY_DENIED``); anything else proceeds to the next gate. An
        implementation MUST fail closed (return a ``deny`` decision) on any internal
        evaluation error rather than proceeding.
        """
        raise NotImplementedError  # pragma: no cover - abstract contract.


# ---------------------------------------------------------------------------
# §1.5d  Community-gate seam — a DENY-ONLY author-your-own gate step (Phase 2).
# ---------------------------------------------------------------------------
#
# Phase 2 of the author-your-own extensibility feature (docs/integrate/EXTENSIBILITY.md §8): a
# community-authored declarative gate evaluated at pipeline step 4c′ — right after the
# mandate gate and adjacent to the G3 policy overlay. Like every base gate it is
# DENY-ONLY / monotonic: the ONLY actionable outcome is ``deny`` (raised as
# ``POLICY_GATE_DENIED``); ``continue`` merely means "fall through to the next gate"
# (which may itself deny). This is structural, not conventional — ``GateDecision`` carries
# NO allow/override outcome, so a gate can never turn a would-be deny into an allow.
#
# The CEL parse/lint/evaluate RUNTIME is deliberately DEFERRED — an owner dependency
# decision (cel-python pulls a native-extension chain, google-re2[native]+pendulum, into
# the fail-closed authorizer; see docs/integrate/EXTENSIBILITY.md §8). So this module ships ONLY the
# seam CONTRACT: the whitelisted context, the deny-only decision, and the provider ABC.
# The default provider (``services/community_gate.py``) is a strict NO-OP that always
# ``continue``s — the honest "no community gate engine configured" state, never a
# fabricated pass. Registering a real engine there is the single additive change that
# activates gates.
#
# ``CommunityGateContext`` is intentionally NARROWER than ``PolicyContext``: it carries
# ONLY the opaque agent-facing ``alias``, the coarse ``transport_class``, the ``risk_tier``
# and the ``classification`` — the exact fixed whitelist a gate manifest's
# ``referenced_context_fields`` must be a subset of. It carries NO real target, NO secrets,
# NO topology, NO identity handle, and (v1) NO raw arguments — argument-field exposure is
# deferred to when the CEL engine lands, so a gate predicate can never read the hidden
# target or an argument value prematurely.

# The fixed whitelist of context fields a community gate may reference. A gate manifest's
# ``referenced_context_fields`` MUST be a subset of this set, and ``CommunityGateContext``
# exposes EXACTLY these fields and nothing else. Kept here as the single source of truth so
# the manifest schema (which validates the subset) and the runtime context can never drift.
GATE_CONTEXT_FIELDS: Final[frozenset[str]] = frozenset(
    {"alias", "risk_tier", "transport_class", "classification"}
)

# ---------------------------------------------------------------------------
# AuthZEN-shape alignment (X4) — ONE evaluation model for the Wave-8 COAZ/AuthZEN
# decision surface (``POST /v1/authz/decision``) and the community-gate seam.
# ---------------------------------------------------------------------------
#
# The AuthZEN Authorization API models an evaluation as a SARC tuple —
# Subject / Action / Resource / Context. MCPIP's ``/v1/authz/decision`` already
# builds one ``CommunityGateContext`` from the resolved ``AliasEntry`` and evaluates
# it through the SAME deny chain a real ``/v1/authorize`` call takes, so COAZ and the
# community gate share one context TYPE. This block FORMALIZES that correspondence in
# SARC terms and pins it against drift — additive, dependency-free, statically-analyzable.
#
# ``GATE_CONTEXT_AUTHZEN_ENTITY`` declares, in ONE place, which SARC slot each of the four
# ``GATE_CONTEXT_FIELDS`` derives from. EVERY value is a ``resource.*`` slot — so the
# mapping ENCODES, as data, that the AuthZEN ``subject`` (identity) and ``action``
# (arguments) contribute NOTHING to the gate context: the topology-free / identity-free /
# argument-free guarantee expressed as a whitelist. Its keyset MUST equal
# ``GATE_CONTEXT_FIELDS`` (test-pinned), so the alignment can never drift from the whitelist.
GATE_RESOURCE_TYPE: Final[str] = "mcpip.skill"  # advisory ``resource.type`` label only.

GATE_CONTEXT_AUTHZEN_ENTITY: Final[Mapping[str, str]] = MappingProxyType(
    {
        "alias": "resource.id",
        "risk_tier": "resource.properties.risk_tier",
        "transport_class": "resource.properties.transport_class",
        "classification": "resource.properties.classification",
    }
)


class CommunityGateContext(BaseModel):
    """
    Immutable, topology-free snapshot handed to a ``CommunityGateProvider``.

    Frozen + strict/forbid (mirrors ``Identity``/``PolicyContext``): a gate receives the
    opaque agent-facing ``alias``, the coarse ``transport_class`` (never the real target),
    the ``risk_tier`` and the ``classification`` — exactly ``GATE_CONTEXT_FIELDS`` — and
    cannot mutate any of them. It deliberately carries NO target, NO secret, NO identity
    handle, and NO raw arguments, so a community gate can neither read the hidden target
    nor mint/mutate the resolved action; it can only observe the whitelisted shape and
    return a deny.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    alias: str
    transport_class: str
    risk_tier: RiskTier
    classification: Classification

    def as_authzen_resource(self) -> dict[str, Any]:
        """
        Pure, read-only projection of the shared context to the AuthZEN SARC ``resource``
        entity (the OUTBOUND direction context → AuthZEN resource only).

        Returns the ``{type, id, properties}`` view a COAZ/AuthZEN engine consuming the
        shared ``CommunityGateContext`` sees — the SAME entity shape as
        ``models.schemas.AuthzenResource``: ``id`` is the opaque ``alias``; ``properties``
        carries ONLY the coarse whitelist enums (``risk_tier``/``transport_class``/
        ``classification``), whose keyset is exactly ``GATE_CONTEXT_FIELDS - {'alias'}``.
        ``RiskTier``/``Classification`` are ``str, Enum`` so ``.value`` is a JSON-safe stable
        string.

        It exposes ONLY whitelist fields — NO real target, NO secret, NO subject/identity
        handle, NO action/arguments — so it can never become a topology or identity leak
        even if a future engine logs it. There is deliberately NO inbound helper (reading a
        client-supplied resource into the whitelist): the four coarse fields are
        SERVER-derived from the resolved ``AliasEntry``, so an inbound path would be a
        classification/risk downgrade-injection lane.
        """
        return {
            "type": GATE_RESOURCE_TYPE,
            "id": self.alias,
            "properties": {
                "risk_tier": self.risk_tier.value,
                "transport_class": self.transport_class,
                "classification": self.classification.value,
            },
        }


class GateDecision(BaseModel):
    """
    A deny-only community-gate outcome.

    ``outcome`` is a closed two-value literal: ``'continue'`` (fall through to the next
    gate) or ``'deny'`` (the pipeline raises ``POLICY_GATE_DENIED``). There is deliberately
    NO ``'allow'``/override value — a gate can never grant what an earlier gate would
    refuse. ``detail`` is the operator-facing cause; it rides ONLY into the WORM ``detail``
    string and is NEVER a metric label or an agent-facing field.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    outcome: Literal["continue", "deny"]
    detail: str = ""


class CommunityGateProvider(ABC):
    """
    Pluggable DENY-ONLY community-gate overlay evaluated at pipeline step 4c′ (right after
    the mandate gate, adjacent to the G3 policy gate). The pipeline treats ONLY
    ``outcome == 'deny'`` as actionable and wraps ``evaluate`` in a fail-closed
    ``try/except`` (any exception → ``POLICY_GATE_DENIED``), so even a buggy/raising
    provider fails closed, never open.

    The shipped default is a strict NO-OP (always ``continue``) — the honest "no community
    gate engine configured" state. A future CEL engine implements this by compiling +
    evaluating the pinned CEL with a hard cost bound + eval timeout over the whitelisted
    ``CommunityGateContext``; wiring it in is purely additive.
    """

    @abstractmethod
    async def evaluate(self, ctx: CommunityGateContext) -> GateDecision:
        """
        Evaluate the community gate for ``ctx``. Return ``GateDecision(outcome='deny', …)``
        to deny (``POLICY_GATE_DENIED``); anything else proceeds to the next gate. An
        implementation MUST fail closed (return/raise into a ``deny``) on any internal
        evaluation error rather than proceeding.
        """
        raise NotImplementedError  # pragma: no cover - abstract contract.


# ---------------------------------------------------------------------------
# §1.6  MCPIPDenied — the ONLY exception that reaches the agent boundary.
# ---------------------------------------------------------------------------


class MCPIPDenied(Exception):
    """
    Agent-facing denial. Carries ONLY the opaque correlation id.

    The concrete DenyReason, stack traces, key names, paths, and topology all live
    exclusively in the WORM audit log. This is the fail-closed, opaque-error
    boundary: the agent learns *that* it was denied and a correlation id to quote
    to a human operator, and nothing else.
    """

    def __init__(self, correlation_id: str) -> None:
        self.correlation_id = correlation_id
        super().__init__(f"{AGENT_FACING_DENY_MESSAGE} correlation_id={correlation_id}")


__all__ = [
    # Limits
    "MAX_CHAIN_HOPS",
    "MAX_ARG_DEPTH",
    "MAX_ARG_KEYS",
    "MAX_ARG_ARRAY",
    "MAX_STRING_LEN",
    "MAX_CANONICAL_BYTES",
    "TOTP_DIGITS",
    "TOTP_PERIOD_S",
    "TOTP_DRIFT_STEPS",
    "MAX_TOTP_ATTEMPTS",
    "TOTP_ATTEMPT_WINDOW_S",
    "MAX_AUTHENTICATOR_ROSTER",
    "PIN_TTL_SECONDS",
    "PIN_MAX_ATTEMPTS",
    "PIN_LENGTH",
    "MAX_QUARANTINE_ROSTER",
    "MAX_PENDING_SUBMISSIONS",
    "SKILL_ACCESS_MODES",
    "MAX_SERVICE_LABEL_LEN",
    "MAX_VERIFIED_PUBLISHERS",
    "MAX_PUBLISHER_NAMESPACE_LEN",
    "MAX_REGISTRY_REMOTES",
    "MAX_REGISTRY_META_BYTES",
    "MAX_POLICY_RULES",
    "MAX_POLICY_DOC_BYTES",
    "MAX_GATE_COST",
    "MAX_RELATION_DEPTH",
    "MAX_RELATION_FANOUT",
    "MAX_RELATION_ROSTER",
    "RELATION_KEY_PREFIX",
    "FORENSIC_TTL_SECONDS",
    "MAX_FORENSIC_PAYLOAD_BYTES",
    "MAX_AUTHN_WEBHOOK_RESPONSE_BYTES",
    "MIN_AUTHN_WEBHOOK_TIMEOUT_S",
    "MAX_AUTHN_WEBHOOK_TIMEOUT_S",
    "MIN_TELEMETRY_INTERVAL_S",
    "MAX_TELEMETRY_INTERVAL_S",
    "MAX_TELEMETRY_RESPONSE_BYTES",
    "MAX_TELEMETRY_TENANTS",
    "MIN_RESPONSE_INTERVAL_S",
    "MAX_RESPONSE_INTERVAL_S",
    "MAX_RESPONSE_ACTIONS_PER_TICK",
    "MAX_RESPONSE_SCAN",
    "MAX_RESPONSE_RECIPIENTS",
    "MAX_RESPONSE_ACK_BYTES",
    "RESPONSE_BURST_WINDOW_S",
    "RESPONSE_COOLDOWN_S",
    "RESPONSE_TRIGGER_REASONS",
    "RESPONSE_SINGLE_SHOT_REASONS",
    "MAX_LICENSE_DOC_BYTES",
    "AGENT_FACING_DENY_MESSAGE",
    # Capability / compartment constants
    "CAP_COMPARTMENT_GRANT",
    "CAP_COMPARTMENT_REVOKE",
    "CAP_DIRECTORY_ADMIN",
    "CAP_FORENSIC_READ",
    "CAP_CATALOG_REVIEWER",
    "grant_capability_for",
    "MAX_CAPABILITIES",
    "MAX_GRANT_TTL_SECONDS",
    "MIN_GRANT_TTL_SECONDS",
    "DEFAULT_GRANT_TTL_SECONDS",
    # Primitives
    "reject_unsafe_string",
    "canonical_json",
    "sha256_hex",
    "constant_time_equals",
    # Enums
    "SourceFormat",
    "RiskTier",
    "Decision",
    "DenyReason",
    "Classification",
    # Models
    "Hop",
    "SwarmTrace",
    "NormalizedIntent",
    "Identity",
    "AuthorizedIntent",
    "TransportResult",
    "BaseTransport",
    "AuthenticatorNotice",
    "BaseAuthenticatorChannel",
    "PolicyContext",
    "PolicyDecision",
    "PolicyProvider",
    "GATE_CONTEXT_FIELDS",
    "GATE_CONTEXT_AUTHZEN_ENTITY",
    "GATE_RESOURCE_TYPE",
    "CommunityGateContext",
    "GateDecision",
    "CommunityGateProvider",
    # Exception
    "MCPIPDenied",
]
