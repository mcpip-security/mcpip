"""
mcpip_sdk.models — frozen wire models mirroring the gateway's response contract.

    ◐ "Zero topology leakage — agents name aliases; real systems stay invisible."

Every model is a frozen dataclass parsed from the JSON the gateway actually
sends (``models/schemas.py`` + the admin handlers in ``app/main.py`` are the
source of truth). Parsing is forward-compatible on purpose: unknown keys are
ignored and missing keys degrade to typed defaults — the SERVER is strict on
ingress, the CLIENT is tolerant on egress. Deliberately not pydantic, so the
SDK never collides with a host agent framework's pydantic v1/v2 pin.

Note what is structurally ABSENT: no model carries a real target, a deny
reason (agent side), an OTP, or a secret value — those never cross the wire,
so they cannot exist here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final, Mapping, Optional

# ---------------------------------------------------------------------------
# Protocol constants — byte-identical to the gateway's ``interfaces.py``.
# ---------------------------------------------------------------------------

# Payload-lock TTL: a staged challenge is consumable for this many seconds.
PIN_TTL_SECONDS: Final[int] = 300
# One-time codes are exactly this many decimal digits, zero-padded.
PIN_LENGTH: Final[int] = 6
# Wrong-PIN attempts before the lock self-destructs.
PIN_MAX_ATTEMPTS: Final[int] = 5
# Capability UUID a JWT must carry (in its ``capabilities`` claim) to reach the
# ``/v1/admin/*`` + ``/v1/directory`` operator surface.
CAP_DIRECTORY_ADMIN: Final[str] = "b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20"
# Capability UUID a JWT must carry to read the raw reconstructed query behind a
# correlation id (``GET /v1/admin/forensic/{correlation_id}``). DELIBERATELY
# DISTINCT from ``CAP_DIRECTORY_ADMIN`` — a directory admin does NOT get to read
# raw payloads; forensic read is a separately-grantable, higher-sensitivity
# investigator authority (least privilege). Pinned to ``interfaces.py``.
CAP_FORENSIC_READ: Final[str] = "d5f0c9a2-4b71-4e6a-9c83-1a7f2e6b4d90"
# Capability UUID a JWT must carry to REVIEW community-extension submissions —
# the reviewer half of the author-your-own-skill workflow (``GET
# /v1/admin/extensions/pending`` + ``POST /v1/admin/extensions/{id}/{approve,reject}``).
# DELIBERATELY DISTINCT from BOTH ``CAP_DIRECTORY_ADMIN`` and ``CAP_FORENSIC_READ``:
# "can approve community extensions" ≠ "can revoke a principal" ≠ "can read raw
# forensic payloads", and holding either sibling does NOT confer it (least
# privilege). Submitting an extension (``POST /v1/extensions/submit``) needs NO
# capability — any authenticated principal is a Contributor — only review does.
# Pinned to ``interfaces.py``.
CAP_CATALOG_REVIEWER: Final[str] = "7a1f9c34-2e58-4b6d-9f01-3c7a5e2b8d46"

# Schema tag every verified-publisher allow-list document carries (registry
# governance, X3) — byte-identical to services/registry_publishers.PUBLISHERS_SCHEMA.
PUBLISHERS_SCHEMA: Final[str] = "mcpip-registry-publishers/1"

# Risk tiers (closed enum on the server).
RISK_TIER_AUTO: Final[str] = "auto"
RISK_TIER_PIN_REQUIRED: Final[str] = "pin_required"


class DenyReason(str, Enum):
    """
    The closed set of concrete deny reasons — OPERATOR / WORM-side ONLY.

    Byte-identical mirror of ``interfaces.DenyReason`` (a ``str, Enum`` there
    too): these are exactly the values the admin decision feed's ``deny_reason``
    column (:class:`RecentDecision`) and a :class:`ForensicPayload` can carry, so
    an operator can match a decision against a known member. They NEVER cross the
    agent boundary — a denied agent only ever sees the opaque :class:`MCPIPDenied`
    with a correlation id, no reason. Membership is a ``str`` (each member IS its
    wire value), so ``decision.deny_reason == DenyReason.POLICY_DENIED`` works
    directly against the raw string.

    Note the engine's ``SKILL_DISABLED`` member serializes as ``"alias_disabled"``
    (so it can never trip the ``skill_``-substring metric-label hygiene guard).
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
    COMPARTMENT_DENIED = "compartment_denied"
    CAPABILITY_DENIED = "capability_denied"
    SENDER_CONSTRAINT_REQUIRED = "sender_constraint_required"
    CANARY_TRIPPED = "canary_tripped"
    AGENT_QUARANTINED = "agent_quarantined"
    PRINCIPAL_REVOKED = "principal_revoked"
    SKILL_DISABLED = "alias_disabled"
    # Out-of-band authenticator delivery failed / unconfigured — the step-up code
    # could not be pushed, so the PIN_REQUIRED action fails closed rather than
    # staging an unanswerable challenge. WORM-only; distinct from LOCK_ERROR.
    OTP_DELIVERY_FAILED = "otp_delivery_failed"
    # The deny-only policy overlay denied the action — a velocity cap, an amount
    # ceiling, a non-numeric amount, or a fail-closed policy-evaluation error.
    # WORM-only; distinct from RATE_LIMITED (a different subsystem's DoS guard).
    POLICY_DENIED = "policy_denied"
    # The deny-only COMMUNITY-GATE seam denied the action — a community-authored
    # declarative gate (pipeline step 4c′) denied, OR the gate seam itself failed
    # closed (a registered gate engine raised / timed out / tripped its static cost
    # bound). WORM-only; DISTINCT from POLICY_DENIED (the G3 operator velocity/amount
    # overlay) and from RATE_LIMITED. When NO community gate engine is registered the
    # seam is a strict fail-closed NO-OP (the default provider always continues — the
    # honest 'none configured' state), so this reason surfaces only once a real engine
    # is wired in and denies (or errors). No ``skill_`` substring — clears the
    # metric-label hygiene guard.
    POLICY_GATE_DENIED = "policy_gate_denied"


# ---------------------------------------------------------------------------
# Tolerant field readers — one narrowing point per JSON type.
# ---------------------------------------------------------------------------


def _str_of(payload: Mapping[str, Any], key: str, default: str = "") -> str:
    value = payload.get(key)
    return value if isinstance(value, str) else default


def _opt_str(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) else None


def _int_of(payload: Mapping[str, Any], key: str, default: int = 0) -> int:
    value = payload.get(key)
    # bool is an int subclass — a JSON true/false must not read as 1/0 here.
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _opt_int(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _bool_of(payload: Mapping[str, Any], key: str, default: bool = False) -> bool:
    value = payload.get(key)
    return value if isinstance(value, bool) else default


def _opt_bool(payload: Mapping[str, Any], key: str) -> bool | None:
    value = payload.get(key)
    return value if isinstance(value, bool) else None


def _float_of(payload: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    value = payload.get(key)
    if isinstance(value, bool):
        return default
    return float(value) if isinstance(value, (int, float)) else default


def _str_tuple(payload: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _dict_of(payload: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    return dict(value) if isinstance(value, dict) else {}


def _opt_dict(payload: Mapping[str, Any], key: str) -> dict[str, Any] | None:
    value = payload.get(key)
    return dict(value) if isinstance(value, dict) else None


def _dict_list(payload: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key)
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


# ---------------------------------------------------------------------------
# Agent surface — /v1/authorize outcomes, catalog, health, version, license.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthorizeEnvelope:
    """
    The exact request envelope an ``authorize()`` call sent — kept on a
    :class:`Staged` result so ``complete()`` can resubmit it BYTE-IDENTICALLY.
    The payload lock binds tenant/agent/alias/arguments; any drift at consume
    time is an opaque deny (though the lock survives for a correct retry).
    Exactly one of ``source_format`` / ``vendor`` is set. Do not mutate
    ``tool_call`` between staging and completion.
    """

    tool_call: dict[str, Any]
    source_format: str | None = None
    vendor: str | None = None

    def body(self) -> dict[str, Any]:
        """The ``/v1/authorize`` JSON body for this envelope (no pin fields)."""
        body: dict[str, Any] = {"tool_call": self.tool_call}
        if self.source_format is not None:
            body["source_format"] = self.source_format
        if self.vendor is not None:
            body["vendor"] = self.vendor
        return body


@dataclass(frozen=True, slots=True)
class Allowed:
    """
    HTTP 200 — the action was authorized, audit-logged, and dispatched.

    ``executed_target_class`` is the coarse transport CLASS (``cloud_rest`` /
    ``legacy_mainframe`` / ``cloud_iam``), never the real target — topology
    never crosses the agent boundary. ``worm_sequence`` is the audit anchor an
    operator can quote to locate the decision record. ``vended_credential`` is
    populated only for the ``cloud_iam`` transport: the short-lived scoped
    cloud credential vended for THIS call.
    """

    correlation_id: str
    decision: str
    status: str
    transaction_ref: str
    executed_target_class: str
    worm_sequence: int
    vended_credential: dict[str, Any] | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "Allowed":
        return cls(
            correlation_id=_str_of(payload, "correlation_id"),
            decision=_str_of(payload, "decision"),
            status=_str_of(payload, "status"),
            transaction_ref=_str_of(payload, "transaction_ref"),
            executed_target_class=_str_of(payload, "executed_target_class"),
            worm_sequence=_int_of(payload, "worm_sequence"),
            vended_credential=_opt_dict(payload, "vended_credential"),
        )


@dataclass(frozen=True, slots=True)
class Staged:
    """
    HTTP 202 — a ``pin_required`` alias was recognized; a payload-bound lock
    was staged. This is a RESULT, not an error: obtain the one-time code from
    the enrolled authenticator (out-of-band; sandbox gateways expose
    ``SandboxClient.authenticator_code``) and finish with
    ``client.complete(staged, pin)`` inside ``expires_in`` seconds.

    ``expires_in`` is the protocol's fixed lock TTL (``PIN_TTL_SECONDS``); the
    202 body itself does not carry it. The OTP is NEVER in this response.
    """

    correlation_id: str
    action_required: str
    challenge_id: str
    risk_tier: str
    envelope: AuthorizeEnvelope
    expires_in: int = PIN_TTL_SECONDS

    @classmethod
    def from_wire(
        cls, payload: Mapping[str, Any], envelope: AuthorizeEnvelope
    ) -> "Staged":
        return cls(
            correlation_id=_str_of(payload, "correlation_id"),
            action_required=_str_of(payload, "action_required"),
            challenge_id=_str_of(payload, "challenge_id"),
            risk_tier=_str_of(payload, "risk_tier", RISK_TIER_PIN_REQUIRED),
            envelope=envelope,
        )


@dataclass(frozen=True, slots=True)
class CatalogItem:
    """One agent-visible skill — metadata only, the real target never appears."""

    alias: str
    risk_tier: str
    transport_class: str
    classification: str
    compartment: str | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "CatalogItem":
        return cls(
            alias=_str_of(payload, "alias"),
            risk_tier=_str_of(payload, "risk_tier"),
            transport_class=_str_of(payload, "transport_class"),
            classification=_str_of(payload, "classification"),
            compartment=_opt_str(payload, "compartment"),
        )


@dataclass(frozen=True, slots=True)
class Health:
    """``GET /healthz`` — liveness (no dependency check)."""

    status: str
    glyph: str
    loop: str
    version: str

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "Health":
        return cls(
            status=_str_of(payload, "status"),
            glyph=_str_of(payload, "glyph"),
            loop=_str_of(payload, "loop"),
            version=_str_of(payload, "version"),
        )


@dataclass(frozen=True, slots=True)
class Readiness:
    """``GET /readyz`` — Redis-gated readiness; 503 parses here too, honestly."""

    ready: bool
    status: str
    redis: str

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any], http_status: int) -> "Readiness":
        return cls(
            ready=http_status == 200,
            status=_str_of(payload, "status"),
            redis=_str_of(payload, "redis"),
        )


@dataclass(frozen=True, slots=True)
class ReleaseProvenance:
    """The signed release manifest surfaced by ``/v1/version`` (all-None when
    absent; ``verified`` is None when no release-root public key is configured
    — provenance *stated*, not *proven*)."""

    version: str | None = None
    signing_key_id: str | None = None
    verified: bool | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "ReleaseProvenance":
        return cls(
            version=_opt_str(payload, "version"),
            signing_key_id=_opt_str(payload, "signing_key_id"),
            verified=_opt_bool(payload, "verified"),
        )


@dataclass(frozen=True, slots=True)
class VersionInfo:
    """``GET /v1/version`` — running release + update posture (notifier only)."""

    running: str
    latest: str
    update_available: bool
    channel: str
    update_policy: str
    release: ReleaseProvenance = field(default_factory=ReleaseProvenance)

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "VersionInfo":
        return cls(
            running=_str_of(payload, "running"),
            latest=_str_of(payload, "latest"),
            update_available=_bool_of(payload, "update_available"),
            channel=_str_of(payload, "channel"),
            update_policy=_str_of(payload, "update_policy"),
            release=ReleaseProvenance.from_wire(_dict_of(payload, "release")),
        )


@dataclass(frozen=True, slots=True)
class LicenseInfo:
    """``GET /v1/license`` — the boot-verified entitlement view. A sandbox
    gateway answers ``{"licensed": false}`` and nothing else."""

    licensed: bool
    license_id: str | None = None
    customer: str | None = None
    tier: str | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    entitlements: tuple[str, ...] = ()

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "LicenseInfo":
        return cls(
            licensed=_bool_of(payload, "licensed"),
            license_id=_opt_str(payload, "license_id"),
            customer=_opt_str(payload, "customer"),
            tier=_opt_str(payload, "tier"),
            issued_at=_opt_str(payload, "issued_at"),
            expires_at=_opt_str(payload, "expires_at"),
            entitlements=_str_tuple(payload, "entitlements"),
        )


@dataclass(frozen=True, slots=True)
class AuditAttestation:
    """
    ``GET /v1/audit/attestation`` — a portable, signed snapshot of the CURRENT
    audit state (JWT-gated, READ-ONLY). Mirrors ``audit/worm_logger.py``
    ``WormAttestation`` verbatim — the body the endpoint serves.

    Carries the latest SEALED epoch header (``epoch`` / ``end_seq`` /
    ``merkle_root`` / ``epoch_hash`` / ``signature`` — all ``None`` before the
    first epoch has closed, an honest empty state, never a fabricated header), the
    WORM epoch key's public ``signing_key_id`` (always present — a non-secret
    fingerprint an external verifier binds the epoch ``signature`` to), a FRESH
    chain-verify result (``intact`` + ``first_bad_epoch``), and the
    out-of-tamper-domain anchor low-watermark (``anchor_epoch`` /
    ``anchor_epoch_hash`` — ``None`` when no anchor is configured or nothing has
    been witnessed yet). Every signed field was Ed25519-signed by the WORM key at
    epoch close / anchor append: the endpoint mints no key, signs nothing new, and
    never runs on the emit hot path, so no target, payload, PIN/OTP, or other
    secret ever appears here.

    Unlike the sandbox-only :meth:`~mcpip_sdk.client.SandboxClient.audit_verify` /
    :meth:`~mcpip_sdk.client.SandboxClient.audit_proof`, this is available in
    PRODUCTION (a portable, externally-checkable attestation is a production
    artifact) and stays plain-JWT-gated like ``version`` / ``license`` — it needs
    no ``CAP_DIRECTORY_ADMIN``.
    """

    signing_key_id: str
    intact: bool
    epoch: int | None = None
    end_seq: int | None = None
    merkle_root: str | None = None
    epoch_hash: str | None = None
    signature: str | None = None
    first_bad_epoch: int | None = None
    anchor_epoch: int | None = None
    anchor_epoch_hash: str | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "AuditAttestation":
        return cls(
            signing_key_id=_str_of(payload, "signing_key_id"),
            intact=_bool_of(payload, "intact"),
            epoch=_opt_int(payload, "epoch"),
            end_seq=_opt_int(payload, "end_seq"),
            merkle_root=_opt_str(payload, "merkle_root"),
            epoch_hash=_opt_str(payload, "epoch_hash"),
            signature=_opt_str(payload, "signature"),
            first_bad_epoch=_opt_int(payload, "first_bad_epoch"),
            anchor_epoch=_opt_int(payload, "anchor_epoch"),
            anchor_epoch_hash=_opt_str(payload, "anchor_epoch_hash"),
        )


# ---------------------------------------------------------------------------
# Standards interop — OAuth 2.1 Resource-Server metadata (N2) + the
# OpenID-AuthZEN / COAZ decision surface (N1).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProtectedResourceMetadata:
    """
    ``GET /.well-known/oauth-protected-resource`` — the RFC 9728 OAuth 2.1
    Protected Resource Metadata document (N2). PUBLIC and unauthenticated; a
    conformant MCP client reads it to learn (a) MCPIP's own resource identifier
    and (b) the authorization server(s) that issue tokens for it, so it cannot
    silently route around the gateway to a look-alike endpoint.

    Mirrors ``auth/oauth_metadata.build_protected_resource_metadata`` verbatim —
    the two non-secret discovery identifiers plus the accepted bearer method.
    There is deliberately NO ``scopes_supported`` key (MCPIP has no OAuth scopes;
    the ``role`` claim authorizes nothing), and the document carries NO secret and
    NO alias→target topology.
    """

    resource: str
    authorization_servers: tuple[str, ...] = ()
    bearer_methods_supported: tuple[str, ...] = ()

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "ProtectedResourceMetadata":
        return cls(
            resource=_str_of(payload, "resource"),
            authorization_servers=_str_tuple(payload, "authorization_servers"),
            bearer_methods_supported=_str_tuple(payload, "bearer_methods_supported"),
        )


@dataclass(frozen=True, slots=True)
class AuthzenDecision:
    """
    ``POST /v1/authz/decision`` response — the OpenID-AuthZEN Authorization API
    1.0 decision (N1). MCPIP answers as a PDP: DECISION-ONLY (it executes
    nothing, vends nothing, stages/consumes no PIN, mutates no grant).

    A permit is ``decision=True`` optionally carrying standards-shaped
    ``obligations`` (e.g. ``{"id": "mcpip.step_up.pin"}`` for a PIN_REQUIRED tier,
    ``{"id": "mcpip.sender_constraint.dpop"}`` for a sender-constrained resource).
    A deny is the bare, opaque ``decision=False`` — NO reason/target/topology ever
    crosses the boundary (the concrete cause lives ONLY in the gateway's WORM
    audit log, exactly like :class:`~mcpip_sdk.errors.MCPIPDenied`).

    Identity is derived EXCLUSIVELY from the verified JWT you present; the AuthZEN
    ``subject`` is advisory/echo only and is NEVER an identity input, so identity
    cannot be injected through it.
    """

    decision: bool
    obligations: tuple[dict[str, Any], ...] = ()

    @property
    def obligation_ids(self) -> tuple[str, ...]:
        """The ``id`` of each obligation, in order (dropping any without one)."""
        return tuple(
            o["id"] for o in self.obligations if isinstance(o.get("id"), str)
        )

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "AuthzenDecision":
        return cls(
            decision=_bool_of(payload, "decision"),
            obligations=tuple(_dict_list(payload, "obligations")),
        )


# ---------------------------------------------------------------------------
# Sandbox audit surface — /v1/audit/verify + /v1/audit/proof/{event_id}.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditVerifyResult:
    """``GET /v1/audit/verify`` — signed Merkle-epoch chain verification."""

    intact: bool
    first_bad_epoch: int | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "AuditVerifyResult":
        return cls(
            intact=_bool_of(payload, "intact"),
            first_bad_epoch=_opt_int(payload, "first_bad_epoch"),
        )


@dataclass(frozen=True, slots=True)
class InclusionProof:
    """``GET /v1/audit/proof/{event_id}`` — the O(log n) Merkle inclusion proof
    for one sealed WORM event. ``proof`` is a (side, hex-digest) path."""

    event_id: str
    epoch: int
    index: int
    record: str
    proof: tuple[tuple[str, str], ...]
    merkle_root: str
    epoch_hash: str
    signature: str

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "InclusionProof":
        raw_path = payload.get("proof")
        path: list[tuple[str, str]] = []
        if isinstance(raw_path, list):
            for step in raw_path:
                if isinstance(step, (list, tuple)) and len(step) == 2:
                    path.append((str(step[0]), str(step[1])))
        return cls(
            event_id=_str_of(payload, "event_id"),
            epoch=_int_of(payload, "epoch"),
            index=_int_of(payload, "index"),
            record=_str_of(payload, "record"),
            proof=tuple(path),
            merkle_root=_str_of(payload, "merkle_root"),
            epoch_hash=_str_of(payload, "epoch_hash"),
            signature=_str_of(payload, "signature"),
        )


# ---------------------------------------------------------------------------
# Admin surface — decision feed, forensic reconstruction, rosters, skills,
# cloud, vault, workspace.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RecentDecision:
    """
    One row of ``GET /v1/admin/decisions/recent`` — a strict whitelist
    projection of the tenant's WORM stream (allow/deny only; the real target,
    arguments, and challenge ids NEVER appear). ``deny_reason`` is operator
    visibility — it is never disclosed on the agent side. ``event_id`` is the
    handle ``/v1/audit/proof/{event_id}`` accepts (None on older gateways).
    """

    correlation_id: str
    decision: str
    tenant_id: str
    worm_sequence: int
    timestamp_ns: int
    agent_id: str | None = None
    alias: str | None = None
    deny_reason: str | None = None
    transport: str | None = None
    risk_tier: str | None = None
    classification: str | None = None
    source_format: str | None = None
    transaction_ref: str | None = None
    event_id: str | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "RecentDecision":
        return cls(
            correlation_id=_str_of(payload, "correlation_id"),
            decision=_str_of(payload, "decision"),
            tenant_id=_str_of(payload, "tenant_id"),
            worm_sequence=_int_of(payload, "worm_sequence"),
            timestamp_ns=_int_of(payload, "timestamp_ns"),
            agent_id=_opt_str(payload, "agent_id"),
            alias=_opt_str(payload, "alias"),
            deny_reason=_opt_str(payload, "deny_reason"),
            transport=_opt_str(payload, "transport"),
            risk_tier=_opt_str(payload, "risk_tier"),
            classification=_opt_str(payload, "classification"),
            source_format=_opt_str(payload, "source_format"),
            transaction_ref=_opt_str(payload, "transaction_ref"),
            event_id=_opt_str(payload, "event_id"),
        )


@dataclass(frozen=True, slots=True)
class DecisionPage:
    """
    One page of ``GET /v1/admin/decisions`` — the date-ranged, multi-filtered,
    cursor-paged history over the SAME whitelist projection the live feed serves
    (``decisions`` are ``RecentDecision`` rows, newest first). ``next_cursor`` is
    an opaque resume token: pass it back as ``cursor=`` to fetch the next page;
    ``None`` means the requested time range is fully walked. ``scanned`` is how
    many raw stream entries this call examined (bounded server-side) and
    ``exhausted`` mirrors the ``next_cursor is None`` terminal state.
    """

    decisions: tuple[RecentDecision, ...]
    next_cursor: str | None
    scanned: int
    exhausted: bool

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "DecisionPage":
        return cls(
            decisions=tuple(
                RecentDecision.from_wire(item)
                for item in _dict_list(payload, "decisions")
            ),
            next_cursor=_opt_str(payload, "next_cursor"),
            scanned=_int_of(payload, "scanned"),
            exhausted=bool(payload.get("exhausted", False)),
        )


@dataclass(frozen=True, slots=True)
class ForensicPayload:
    """
    ``GET /v1/admin/forensic/{correlation_id}`` — the reconstructed REAL query
    an agent sent for one correlation id, decrypted from the forensic capture
    store for a ``CAP_FORENSIC_READ`` investigator.

    This is the ADMIN/investigator counterpart to the deliberately opaque agent
    wire and the arguments-omitting decision feed: it carries the opaque
    ``alias`` the agent named, the already-canonicalized ``arguments`` (run
    through the SAME WORM redaction discipline, so pin/jwt/token/secret material
    is scrubbed even here), and the non-secret identity context (``agent_id`` /
    ``source_format`` / ``transport_class``). It is NEVER reachable from an agent
    token — no agent JWT carries ``CAP_FORENSIC_READ``, and even
    ``CAP_DIRECTORY_ADMIN`` does not confer it — and every retrieval is
    WORM-audited (``admin_action='forensic_read'``) BEFORE disclosure.

    Absent (the feature is off, or an unknown/expired correlation id) is an
    honest ``None`` from :meth:`~mcpip_sdk.admin.MCPIPAdminClient.forensic_get`,
    never this model — the miss is opaque and indistinguishable.
    """

    correlation_id: str
    tenant_id: str
    agent_id: str
    role: str
    issuer: str
    alias: str
    arguments: dict[str, Any]
    source_format: str
    decision: str
    deny_reason: str | None = None
    act_sub: str | None = None
    captured_at: float = 0.0

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "ForensicPayload":
        # Mirrors services/forensic_store.py ForensicRecord.public_view() verbatim —
        # the body served under `forensic` by GET /v1/admin/forensic/{correlation_id}.
        return cls(
            correlation_id=_str_of(payload, "correlation_id"),
            tenant_id=_str_of(payload, "tenant_id"),
            agent_id=_str_of(payload, "agent_id"),
            role=_str_of(payload, "role"),
            issuer=_str_of(payload, "issuer"),
            alias=_str_of(payload, "alias"),
            arguments=_dict_of(payload, "arguments"),
            source_format=_str_of(payload, "source_format"),
            decision=_str_of(payload, "decision"),
            deny_reason=_opt_str(payload, "deny_reason"),
            act_sub=_opt_str(payload, "act_sub"),
            captured_at=_float_of(payload, "captured_at"),
        )


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """
    One deny-only policy rule of a tenant's ``GET /v1/admin/policy`` document —
    mirrors ``models/schemas.py`` ``PolicyRuleModel`` / ``services/policy_engine.py``
    ``PolicyRule`` verbatim. A rule MATCHES a request by ``scope`` + ``scope_value``
    (an opaque alias name or a coarse transport class) and, per ``kind``, carries
    EITHER the velocity fields (``max_actions`` + ``window_seconds``) OR the amount
    fields (``amount_field`` + ``max_amount`` — a decimal STRING, no float drift). A
    stored rule read back here carries all keys with the off-kind ones ``None``.
    """

    kind: str  # "velocity" | "amount"
    scope: str  # "alias" | "transport_class"
    scope_value: str
    max_actions: int | None = None
    window_seconds: int | None = None
    amount_field: str | None = None
    max_amount: str | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "PolicyRule":
        return cls(
            kind=_str_of(payload, "kind"),
            scope=_str_of(payload, "scope"),
            scope_value=_str_of(payload, "scope_value"),
            max_actions=_opt_int(payload, "max_actions"),
            window_seconds=_opt_int(payload, "window_seconds"),
            amount_field=_opt_str(payload, "amount_field"),
            max_amount=_opt_str(payload, "max_amount"),
        )


@dataclass(frozen=True, slots=True)
class PolicyDocument:
    """
    A tenant's deny-only policy document (``GET /v1/admin/policy`` → the body
    under ``policy``) — mirrors ``models/schemas.py`` ``PolicyDocumentRequest`` /
    ``services/policy_engine.py`` ``PolicyRuleSet``. Holds ONLY velocity/amount
    rules — never an alias→target mapping or identity — so it can never repoint a
    skill or mint a principal. A gateway with NO stored document answers with the
    honest empty ``{"schema": "mcpip-policy/1", "rules": []}`` (no limits — opt-in),
    so :meth:`~mcpip_sdk.admin.MCPIPAdminClient.policy_get` ALWAYS resolves to a
    document, never None. A policy denial reaches the agent only as the opaque
    :class:`~mcpip_sdk.errors.MCPIPDenied` (WORM-side ``deny_reason`` is
    :data:`DenyReason.POLICY_DENIED`).
    """

    schema: str
    rules: tuple[PolicyRule, ...] = ()

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "PolicyDocument":
        return cls(
            schema=_str_of(payload, "schema"),
            rules=tuple(
                PolicyRule.from_wire(item) for item in _dict_list(payload, "rules")
            ),
        )


@dataclass(frozen=True, slots=True)
class RegisteredSkill:
    """One operator-registered (overlay) alias — the only deregisterable kind."""

    alias: str
    registered_at: str | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "RegisteredSkill":
        return cls(
            alias=_str_of(payload, "alias"),
            registered_at=_opt_str(payload, "registered_at"),
        )


@dataclass(frozen=True, slots=True)
class PendingExtension:
    """
    One PENDING community-extension submission awaiting review — a row of ``GET
    /v1/admin/extensions/pending`` (Reviewer surface, ``CAP_CATALOG_REVIEWER``).

    Two ``kind`` variants share one model (the ``PolicyRule`` pattern — off-kind
    fields degrade to ``None``/``()``), so a caller branches on ``kind`` and reads
    only the fields that variant carries:

    * ``kind == "skill"`` — a declarative ``alias→target`` catalog entry. Carries
      the submitter-declared ``target`` and ``transport``/``risk_tier``/
      ``classification``, plus ``conflicts_existing_alias`` (an approve would be
      refused additive-only if this alias already resolves). The ``target`` is a
      REVIEWER-only surface — it is the reviewer's job to inspect it before
      approving — and it NEVER crosses the agent wire (the agent-facing catalog
      hides real targets). The gate-only fields are ``None``/``()``.
    * ``kind == "gate"`` — a topology-free deny predicate (Phase 2), NOT an
      alias→target. Carries the human ``gate_id``, the CEL ``language``, the
      declared ``max_cost`` and ``referenced_context_fields``, and ``approvable`` —
      the honest reviewer signal that gate approval is BLOCKED until a CEL
      prover/engine is registered on the gateway (the CEL runtime is deferred, so
      ``approvable`` is currently ``False`` and ``extensions_approve`` on a gate is
      an opaque deny). The skill-only fields are ``None``.

    ``submitter_agent_id`` is the AUTHORITATIVE JWT actor (never the manifest's
    self-declared ``author`` label); ``submitter_is_reviewer`` is a
    separation-of-duties hint (the reviewer is also the submitter — procedural, not
    a control). ``manifest_sha256`` is the manifest self-pin captured at submit.
    """

    submission_id: str
    kind: str  # "skill" | "gate"
    author: str
    submitter_agent_id: str
    manifest_sha256: str
    created_at: str
    submitter_is_reviewer: bool
    # --- skill-only (``None`` on a gate) -------------------------------------
    alias: str | None = None
    target: str | None = None
    transport: str | None = None
    risk_tier: str | None = None
    classification: str | None = None
    conflicts_existing_alias: bool | None = None
    # --- gate-only (``None`` / ``()`` on a skill) ----------------------------
    gate_id: str | None = None
    language: str | None = None
    max_cost: int | None = None
    referenced_context_fields: tuple[str, ...] = ()
    approvable: bool | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "PendingExtension":
        return cls(
            submission_id=_str_of(payload, "submission_id"),
            kind=_str_of(payload, "kind"),
            author=_str_of(payload, "author"),
            submitter_agent_id=_str_of(payload, "submitter_agent_id"),
            manifest_sha256=_str_of(payload, "manifest_sha256"),
            created_at=_str_of(payload, "created_at"),
            submitter_is_reviewer=_bool_of(payload, "submitter_is_reviewer"),
            alias=_opt_str(payload, "alias"),
            target=_opt_str(payload, "target"),
            transport=_opt_str(payload, "transport"),
            risk_tier=_opt_str(payload, "risk_tier"),
            classification=_opt_str(payload, "classification"),
            conflicts_existing_alias=_opt_bool(payload, "conflicts_existing_alias"),
            gate_id=_opt_str(payload, "gate_id"),
            language=_opt_str(payload, "language"),
            max_cost=_opt_int(payload, "max_cost"),
            referenced_context_fields=_str_tuple(payload, "referenced_context_fields"),
            approvable=_opt_bool(payload, "approvable"),
        )


@dataclass(frozen=True, slots=True)
class QuarantinedAgent:
    """One canary-tripwire freeze — clears when its Redis TTL expires."""

    agent_id: str
    ttl_seconds: int

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "QuarantinedAgent":
        return cls(
            agent_id=_str_of(payload, "agent_id"),
            ttl_seconds=_int_of(payload, "ttl_seconds"),
        )


@dataclass(frozen=True, slots=True)
class CanaryAlias:
    """One decoy alias seeded into the tenant catalog (operator view only —
    the ``canary`` flag never crosses the agent boundary)."""

    alias: str
    risk_tier: str
    classification: str

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "CanaryAlias":
        return cls(
            alias=_str_of(payload, "alias"),
            risk_tier=_str_of(payload, "risk_tier"),
            classification=_str_of(payload, "classification"),
        )


@dataclass(frozen=True, slots=True)
class RelationEdge:
    """
    One ReBAC relation edge of ``GET /v1/admin/directory/relations`` — mirrors
    ``services/relation_store.py`` ``RelationEdge`` verbatim (the row shape the
    endpoint serves; the wire key ``object`` is exposed as ``object_uuid`` here,
    ``object`` being a Python builtin).

    ``subject`` has ``relation`` to ``object_uuid``. A committed grant projects a
    ``member`` edge (agent → compartment) and a read-time-derived ``grantor`` edge
    (issuing principal → compartment). ``grant_id`` / ``correlation_id`` /
    ``issued_at_ns`` are the projected non-secret grant metadata (``None`` on a
    derived ``grantor`` edge or when the tuple value was unreadable). NO target,
    secret, PIN/OTP, or alias→target mapping is ever here — these are the SAME
    operator-facing identifiers already in the console Principal Directory, not the
    hidden topology.
    """

    object_uuid: str
    relation: str
    subject: str
    grant_id: str | None = None
    correlation_id: str | None = None
    issued_at_ns: int | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "RelationEdge":
        return cls(
            object_uuid=_str_of(payload, "object"),
            relation=_str_of(payload, "relation"),
            subject=_str_of(payload, "subject"),
            grant_id=_opt_str(payload, "grant_id"),
            correlation_id=_opt_str(payload, "correlation_id"),
            issued_at_ns=_opt_int(payload, "issued_at_ns"),
        )


@dataclass(frozen=True, slots=True)
class RelationList:
    """
    ``GET /v1/admin/directory/relations`` — the ReBAC edges projected from the
    admin's OWN tenant's committed grants, plus (only when a FULL
    ``(subject, relation, object)`` triple was queried) the bounded
    transitive-closure ``allowed`` verdict.

    A best-effort PROJECTION backing the operator Knowledge-Graph: the
    gateway/Redis grant state is authoritative, so a transport blip UNDER-reports
    edges (fail-soft empty, never over-reports) — an empty ``relations`` is an
    honest "nothing projected", not a failure. ``allowed`` is ``None`` unless a
    full triple was supplied (only ``member`` is traversable in v1; ``grantor`` is
    a derived display edge). READ/VISUALIZATION ONLY — the authorization pipeline
    NEVER consults it; the capability-UUID + grant gates remain the sole authority.
    """

    relations: tuple[RelationEdge, ...] = ()
    allowed: bool | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "RelationList":
        return cls(
            relations=tuple(
                RelationEdge.from_wire(item)
                for item in _dict_list(payload, "relations")
            ),
            allowed=_opt_bool(payload, "allowed"),
        )


@dataclass(frozen=True, slots=True)
class CloudEnvironment:
    """One cloud IAM environment binding (public view — never holds a secret;
    ``vault_secret_id`` is a REFERENCE to a vault entry, or None for the
    gateway's host identity)."""

    env_id: str
    provider: str
    role: str
    region: str
    session_ttl: int
    compartment: str | None = None
    vault_secret_id: str | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "CloudEnvironment":
        return cls(
            env_id=_str_of(payload, "env_id"),
            provider=_str_of(payload, "provider"),
            role=_str_of(payload, "role"),
            region=_str_of(payload, "region"),
            session_ttl=_int_of(payload, "session_ttl"),
            compartment=_opt_str(payload, "compartment"),
            vault_secret_id=_opt_str(payload, "vault_secret_id"),
        )


@dataclass(frozen=True, slots=True)
class VaultSecret:
    """One vault entry's METADATA — values are write-only and never returned
    by any endpoint. ``fingerprint`` is a keyed, non-secret identity tag."""

    secret_id: str
    vendor: str
    description: str
    fingerprint: str
    created_at: float
    updated_at: float

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "VaultSecret":
        return cls(
            secret_id=_str_of(payload, "secret_id"),
            vendor=_str_of(payload, "vendor"),
            description=_str_of(payload, "description"),
            fingerprint=_str_of(payload, "fingerprint"),
            created_at=_float_of(payload, "created_at"),
            updated_at=_float_of(payload, "updated_at"),
        )


@dataclass(frozen=True, slots=True)
class VaultSecretList:
    """``GET /v1/admin/vault/secrets`` — metadata roster + whether the vault
    feature is configured on this gateway at all."""

    vault_enabled: bool
    secrets: tuple[VaultSecret, ...] = ()

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "VaultSecretList":
        return cls(
            vault_enabled=_bool_of(payload, "vault_enabled"),
            secrets=tuple(
                VaultSecret.from_wire(item)
                for item in _dict_list(payload, "secrets")
            ),
        )


@dataclass(frozen=True, slots=True)
class WorkspaceSummary:
    """Plan size summary echoed by every workspace endpoint."""

    org_units: int
    teams: int
    skills: int

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "WorkspaceSummary":
        return cls(
            org_units=_int_of(payload, "org_units"),
            teams=_int_of(payload, "teams"),
            skills=_int_of(payload, "skills"),
        )


@dataclass(frozen=True, slots=True)
class WorkspaceDraft:
    """``POST /v1/admin/workspace/draft`` — a deterministic plan proposal.
    ``plan`` is operator-reviewable structured data; pass it unchanged to
    ``workspace_validate`` / ``workspace_apply``."""

    plan: dict[str, Any]
    summary: WorkspaceSummary

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "WorkspaceDraft":
        return cls(
            plan=_dict_of(payload, "plan"),
            summary=WorkspaceSummary.from_wire(_dict_of(payload, "summary")),
        )


@dataclass(frozen=True, slots=True)
class PlanValidation:
    """``POST /v1/admin/workspace/plan/validate`` — dry-run outcome."""

    ok: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    summary: WorkspaceSummary

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "PlanValidation":
        return cls(
            ok=_bool_of(payload, "ok"),
            errors=_str_tuple(payload, "errors"),
            warnings=_str_tuple(payload, "warnings"),
            summary=WorkspaceSummary.from_wire(_dict_of(payload, "summary")),
        )


@dataclass(frozen=True, slots=True)
class PlanApplyResult:
    """``POST /v1/admin/workspace/plan/apply`` — idempotent apply outcome."""

    applied: bool
    created: tuple[str, ...]
    skipped: tuple[str, ...]
    summary: WorkspaceSummary

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "PlanApplyResult":
        return cls(
            applied=_bool_of(payload, "applied"),
            created=_str_tuple(payload, "created"),
            skipped=_str_tuple(payload, "skipped"),
            summary=WorkspaceSummary.from_wire(_dict_of(payload, "summary")),
        )


# ---------------------------------------------------------------------------
# Compliance evidence (X1) — the portable bundle assembled from REAL gateway
# state. EVIDENCE, never a CERTIFICATION: each framework block carries a
# `certification_note`, the bundle a `disclaimer`, and every clause is phrased
# "this MCPIP mechanism PROVIDES EVIDENCE FOR this control clause". Mirrors
# services/compliance_evidence.build_evidence_bundle 1:1.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComplianceControlClause:
    """One control-clause → MCPIP-mechanism mapping row. `coverage` is always
    ``"provides-evidence-for"`` — never "certified"/"passed"."""

    clause: str
    mechanism: str
    mcpip_evidence: str
    code_pointer: str
    coverage: str

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "ComplianceControlClause":
        return cls(
            clause=_str_of(payload, "clause"),
            mechanism=_str_of(payload, "mechanism"),
            mcpip_evidence=_str_of(payload, "mcpip_evidence"),
            code_pointer=_str_of(payload, "code_pointer"),
            coverage=_str_of(payload, "coverage"),
        )


@dataclass(frozen=True, slots=True)
class ComplianceFramework:
    """One regulatory framework block (EU AI Act, SEC 17a-4/FINRA, DORA, NIST
    800-53, SOC 2, ISO 42001). `certification_note` restates that the
    certification itself is an EXTERNAL third-party process MCPIP cannot
    produce; `clauses` are the evidence mappings."""

    framework: str
    reference: str
    certification_note: str
    clauses: tuple[ComplianceControlClause, ...]

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "ComplianceFramework":
        return cls(
            framework=_str_of(payload, "framework"),
            reference=_str_of(payload, "reference"),
            certification_note=_str_of(payload, "certification_note"),
            clauses=tuple(
                ComplianceControlClause.from_wire(item)
                for item in _dict_list(payload, "clauses")
            ),
        )


@dataclass(frozen=True, slots=True)
class ComplianceEvidence:
    """
    ``GET /v1/admin/compliance/evidence`` — a portable COMPLIANCE-EVIDENCE bundle
    (``CAP_DIRECTORY_ADMIN``-gated, READ-ONLY). Assembled from REAL running gateway
    state only: the signed :class:`AuditAttestation`, the running
    ``gateway_version`` + signed ``release`` provenance, and a STATIC
    control-mapping manifest.

    It is EVIDENCE, NOT a CERTIFICATION: ``disclaimer`` restates that the bundle
    asserts no SOC 2 report, FedRAMP authorization, ISO/DORA/EU-AI-Act
    certificate, named customer, or auditor sign-off (those are external
    third-party processes this software cannot produce). ``sealed`` is honest:
    before the first epoch is sealed the attestation header fields are ``None``
    and ``empty_state_note`` explains the honest empty state rather than
    fabricating a header. No target/payload/PIN/OTP/secret ever appears — only
    already-signed commitments + static mapping text.
    """

    generated_at: str
    gateway_version: str
    release: ReleaseProvenance
    sealed: bool
    attestation: AuditAttestation
    control_mapping: tuple[ComplianceFramework, ...]
    disclaimer: str
    empty_state_note: str | None = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "ComplianceEvidence":
        return cls(
            generated_at=_str_of(payload, "generated_at"),
            gateway_version=_str_of(payload, "gateway_version"),
            release=ReleaseProvenance.from_wire(_dict_of(payload, "release_provenance")),
            sealed=_bool_of(payload, "sealed"),
            attestation=AuditAttestation.from_wire(_dict_of(payload, "attestation")),
            control_mapping=tuple(
                ComplianceFramework.from_wire(item)
                for item in _dict_list(payload, "control_mapping")
            ),
            disclaimer=_str_of(payload, "disclaimer"),
            empty_state_note=_opt_str(payload, "empty_state_note"),
        )


@dataclass(frozen=True, slots=True)
class VerifiedPublishers:
    """
    The tenant's verified-publisher allow-list (registry governance, X3) — a
    reviewer-PINNED set of allowed publisher NAMESPACES (reverse-DNS prefixes such
    as ``io.github.owner``) consulted fail-closed when a registry-sourced skill is
    approved / re-verified at boot. Read/written via the
    ``CAP_CATALOG_REVIEWER``-gated ``/v1/admin/extensions/publishers`` endpoints.
    Carries ONLY publisher namespaces — never a target or identity. An honest
    empty ``{schema, namespaces: []}`` when nothing is pinned.
    """

    schema: str
    namespaces: tuple[str, ...]

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "VerifiedPublishers":
        return cls(
            schema=_str_of(payload, "schema", PUBLISHERS_SCHEMA),
            namespaces=_str_tuple(payload, "namespaces"),
        )


@dataclass(frozen=True, slots=True)
class DecisionTotals:
    """The tenant's coarse decision totals — the SAME closed enum as the gateway's
    ``core/metrics.py`` decision counters (``allow`` / ``deny`` / ``staged``). Honest
    zeros for a fresh tenant; never a per-alias or per-reason breakdown."""

    allow: int = 0
    deny: int = 0
    staged: int = 0

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "DecisionTotals":
        return cls(
            allow=_int_of(payload, "allow"),
            deny=_int_of(payload, "deny"),
            staged=_int_of(payload, "staged"),
        )


@dataclass(frozen=True, slots=True)
class TelemetryStatus:
    """
    The HONEST opt-in vendor-telemetry posture reported by ``GET /v1/admin/stats``.

    ``status`` is one of ``"air-gap"`` (sandbox — the beacon is structurally disabled
    and no install identity was ever minted), ``"enabled"`` (the beacon is live), or
    ``"disabled"`` (opt-out / unconfigured production). It is NEVER fabricated. No
    install-id, URL, or secret is ever exposed here (nor as a metric label). When the
    beacon is live, ``last_sent`` is the epoch-seconds of the last successful send
    (``None`` until the first) and ``last_result`` is coarse (``"never"`` / ``"ok"`` /
    ``"error"``); ``interval_seconds`` is the clamped beacon cadence.
    """

    status: str = "disabled"
    last_result: str = "never"
    last_sent: float | None = None
    interval_seconds: float | None = None

    @property
    def enabled(self) -> bool:
        """True only when the beacon is actually live (opt-in + configured + not sandbox)."""
        return self.status == "enabled"

    @property
    def air_gapped(self) -> bool:
        """True in sandbox/air-gap — structurally disabled, no identity minted, never phones home."""
        return self.status == "air-gap"

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "TelemetryStatus":
        raw_sent = payload.get("last_sent")
        raw_interval = payload.get("interval_seconds")
        return cls(
            status=_str_of(payload, "status", "disabled"),
            last_result=_str_of(payload, "last_result", "never"),
            last_sent=(
                float(raw_sent)
                if isinstance(raw_sent, (int, float)) and not isinstance(raw_sent, bool)
                else None
            ),
            interval_seconds=(
                float(raw_interval)
                if isinstance(raw_interval, (int, float))
                and not isinstance(raw_interval, bool)
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class FeatureStatus:
    """
    The HONEST posture of ONE opt-in / dark feature, reported inside
    ``GET /v1/admin/stats``'s ``features`` block.

    Posture-only and never fabricated: ``status`` is the coarse machine state (e.g.
    ``"enabled"`` / ``"disabled"`` / ``"absent"`` for forensic capture, or ``"off"`` /
    ``"staged"`` / ``"enforcing"`` for the external PDP), ``reason`` refines WHY when a
    disabled state has several causes (e.g. ``"production-default"`` vs ``"explicit-opt-out"``
    vs ``"flag-on-no-key"``), and ``detail`` is the human-readable explanation + how to
    enable. NO url, key, path, target, tenant, or per-id information is ever carried here —
    the posture is coarse and deployment-wide.
    """

    status: str = "disabled"
    reason: str | None = None
    detail: str = ""

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "FeatureStatus":
        return cls(
            status=_str_of(payload, "status", "disabled"),
            reason=_opt_str(payload, "reason"),
            detail=_str_of(payload, "detail"),
        )


@dataclass(frozen=True, slots=True)
class FeaturesInfo:
    """
    The additive ``features`` posture block on ``GET /v1/admin/stats`` — honest
    disabled/why/how-to-enable states for the opt-in dark features.

    Back-compat: the whole block is OPTIONAL (a gateway that predates it yields the default
    empty postures). ``telemetry`` is NOT here — it stays a top-level ``DeploymentStats``
    field (the finished reference model). MRT step-up is also not here — it is always
    advertised and read live from the unauthenticated ``initialize`` capability, never a
    static posture string.
    """

    forensic_capture: FeatureStatus = field(default_factory=FeatureStatus)
    external_pdp: FeatureStatus = field(
        default_factory=lambda: FeatureStatus(status="off")
    )

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "FeaturesInfo":
        forensic = _opt_dict(payload, "forensic_capture")
        external = _opt_dict(payload, "external_pdp")
        return cls(
            forensic_capture=(
                FeatureStatus.from_wire(forensic)
                if forensic is not None
                else FeatureStatus()
            ),
            external_pdp=(
                FeatureStatus.from_wire(external)
                if external is not None
                else FeatureStatus(status="off")
            ),
        )


@dataclass(frozen=True, slots=True)
class DeploymentStats:
    """
    ``GET /v1/admin/stats`` — the LOCAL live-stats read: the caller's OWN tenant's REAL
    running numbers, served locally (no beacon, no vendor, no network needed).

    This is the client-side view of "see the numbers live" — the same aggregate the
    opt-in beacon would report, but scoped to the caller's tenant and always REAL or an
    honest empty state (never a fabricated client, number, license, or "connected"
    status). ``CAP_DIRECTORY_ADMIN``-gated, tenant-scoped, opaque-deny.

      * ``governed_agent_identity_count`` — the tenant's governed-agent CARDINALITY (a
        HyperLogLog ``PFCOUNT`` integer; the agent_ids themselves are never stored or
        exposed);
      * ``decisions`` — the tenant's real ``{allow, deny, staged}`` totals;
      * ``license`` — the boot-verified tier/status/expiry (honest ``licensed=False``
        when absent — no fabricated customer/tier/date);
      * ``telemetry`` — the honest enabled / disabled / air-gap posture + coarse
        last-sent;
      * ``version`` — the running release.

    NO tenant/agent/alias/target ever crosses this boundary — only the caller's own
    aggregate integers.
    """

    version: str
    governed_agent_identity_count: int
    decisions: DecisionTotals
    license: LicenseInfo
    telemetry: TelemetryStatus
    # OPTIONAL, mirroring the dashboard's `features?` shape: ``None`` means the gateway did
    # NOT report a features block (an older gateway) — an honest UNKNOWN, distinct from a
    # populated block where a feature is genuinely "off". Never misrepresent unknown as off.
    features: Optional[FeaturesInfo] = None

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "DeploymentStats":
        raw_features = payload.get("features")
        return cls(
            version=_str_of(payload, "version"),
            governed_agent_identity_count=_int_of(
                payload, "governed_agent_identity_count"
            ),
            decisions=DecisionTotals.from_wire(_dict_of(payload, "decisions")),
            license=LicenseInfo.from_wire(_dict_of(payload, "license")),
            telemetry=TelemetryStatus.from_wire(_dict_of(payload, "telemetry")),
            # Populate ONLY when the wire actually carries a features dict; absent -> None
            # (unknown), so a pre-features gateway is never reported as all-features-off.
            features=(
                FeaturesInfo.from_wire(raw_features)
                if isinstance(raw_features, Mapping)
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class OperatorUser:
    """One member of the admin-managed operator/team roster (``/v1/admin/users``).

    The ``role`` (``admin``/``member``/``viewer``) is a MANAGEMENT label — it
    authorizes nothing (the role-claim invariant); identity + authz stay JWT +
    capabilities. ``status`` is ``invited``/``active``/``disabled``. The secret
    invite-token hash is server-side only and never appears here.
    """

    email: str
    role: str
    status: str
    invited_by: str = ""
    invited_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "OperatorUser":
        return cls(
            email=_str_of(payload, "email"),
            role=_str_of(payload, "role", "member"),
            status=_str_of(payload, "status", "invited"),
            invited_by=_str_of(payload, "invited_by"),
            invited_at=_str_of(payload, "invited_at"),
            updated_at=_str_of(payload, "updated_at"),
        )


@dataclass(frozen=True, slots=True)
class OperatorUserPage:
    """A cursor page of the operator roster. ``next_cursor == "0"`` ⇒ the scan is
    complete (HSCAN cursor pagination, never an offset — bounded for scale)."""

    users: tuple[OperatorUser, ...]
    next_cursor: str
    count: int
    cap: int

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "OperatorUserPage":
        return cls(
            users=tuple(OperatorUser.from_wire(u) for u in _dict_list(payload, "users")),
            next_cursor=_str_of(payload, "next_cursor", "0"),
            count=_int_of(payload, "count"),
            cap=_int_of(payload, "cap"),
        )


@dataclass(frozen=True, slots=True)
class OperatorInvite:
    """The result of an invite — the created record + the ONE-TIME reference token
    to send (a shareable reference, NOT a credential; stored server-side only as a
    hash and never re-shown)."""

    user: OperatorUser
    invite_token: str

    @classmethod
    def from_wire(cls, payload: Mapping[str, Any]) -> "OperatorInvite":
        return cls(
            user=OperatorUser.from_wire(_dict_of(payload, "user")),
            invite_token=_str_of(payload, "invite_token"),
        )


__all__ = [
    "PIN_TTL_SECONDS",
    "PIN_LENGTH",
    "PIN_MAX_ATTEMPTS",
    "CAP_DIRECTORY_ADMIN",
    "CAP_FORENSIC_READ",
    "CAP_CATALOG_REVIEWER",
    "PUBLISHERS_SCHEMA",
    "RISK_TIER_AUTO",
    "RISK_TIER_PIN_REQUIRED",
    "DenyReason",
    "AuthorizeEnvelope",
    "Allowed",
    "Staged",
    "CatalogItem",
    "Health",
    "Readiness",
    "ReleaseProvenance",
    "VersionInfo",
    "LicenseInfo",
    "AuditAttestation",
    "ProtectedResourceMetadata",
    "AuthzenDecision",
    "AuditVerifyResult",
    "InclusionProof",
    "RecentDecision",
    "ForensicPayload",
    "PolicyRule",
    "PolicyDocument",
    "RegisteredSkill",
    "PendingExtension",
    "QuarantinedAgent",
    "CanaryAlias",
    "RelationEdge",
    "RelationList",
    "CloudEnvironment",
    "VaultSecret",
    "VaultSecretList",
    "WorkspaceSummary",
    "WorkspaceDraft",
    "PlanValidation",
    "PlanApplyResult",
    "ComplianceControlClause",
    "ComplianceFramework",
    "ComplianceEvidence",
    "VerifiedPublishers",
    "DecisionTotals",
    "TelemetryStatus",
    "FeatureStatus",
    "FeaturesInfo",
    "DeploymentStats",
    "OperatorUser",
    "OperatorUserPage",
    "OperatorInvite",
]
