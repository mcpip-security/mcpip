"""
MCPIP V2 — Gateway pipeline + self-verifying demo.

    ◐  MCPIP — The Authorization Layer for Autonomous AI
       "Authorize every AI action before execution."
       AI Reasons. MCPIP Authorizes. Systems Execute.

Pipeline (◐ Bridge → Obfuscator → Auth → Audit):

  1. correlation_id assigned FIRST — every deny carries it, nothing else.
  2. Auth       — verify JWT → sovereign Identity.
  3. Bridge     — normalize provider tool-call → NormalizedIntent (schema rigidity,
                  identity-injection, char/size/depth gates).
  4. Obfuscator — resolve tenant-scoped alias → real target (fail-closed).
  5. Bind AuthorizedIntent; compute the canonical payload hash.
  6. Risk gate  — PIN_REQUIRED aliases consume a payload-bound, exactly-once lock.
  7. Audit      — emit the ALLOW decision to the WORM log.
  8. Dispatch   — hand off to the transport the alias declares.
  9. Any failure → emit a DENY decision, then raise MCPIPDenied(correlation_id).
                  The agent boundary NEVER learns the reason.

Run ``python main.py`` to execute the 10-gate demo; it exits 0 iff all gates hold.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
import uuid
from typing import Any, Awaitable, Callable, Optional

import jwt
import redis.asyncio as redis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from auth import (
    LockError,
    PinValidator,
    StaticPEMKeyProvider,
    TokenClaimsMissing,
    TokenError,
    TokenResolver,
    lock_payload_hash,
)
from audit import AnchorStore, WormLogger, merkle
from audit.worm_logger import ALL_WORM_KEYS, assert_persistence_posture
from bridge import (
    DepthExceeded,
    IdentityInjection,
    SizeExceeded,
    UnknownFormat,
)
from bridge import intent_parser
from interfaces import (
    CAP_COMPARTMENT_GRANT,
    DEFAULT_GRANT_TTL_SECONDS,
    MAX_GRANT_TTL_SECONDS,
    MIN_GRANT_TTL_SECONDS,
    AuthorizedIntent,
    BaseTransport,
    CommunityGateContext,
    Decision,
    DenyReason,
    Hop,
    Identity,
    MCPIPDenied,
    NormalizedIntent,
    PolicyContext,
    RiskTier,
    SourceFormat,
    SwarmTrace,
    TransportResult,
    constant_time_equals,
    grant_capability_for,
    project_a2a_context,
)
from obfuscator import (
    AliasEntry,
    AliasRegistry,
    CrossTenant,
    UnknownAlias,
    build_demo_registry,
)
from obfuscator.tenant_catalog import AEGIS, FALCON
from services import (
    GrantStore,
    ObfuscatorService,
    RelationTupleStore,
    PolicyDocStore,
    QuarantineStore,
    VelocityAmountPolicyEngine,
    active_community_gate_provider,
)
from services.policy_engine import POLICY_SCHEMA

# Default Redis endpoint — host port 63790 maps to the container's 6379.
# Database 15, NOT 0: this proof RESETS the ledger before it runs, and database 0 is
# where the sandbox gateway (and the quickstart) keeps its live chain. Sharing that
# default meant the documented smoke test destroyed the audit evidence of whatever was
# already running. The proof needs no shared state with anything, so it gets its own.
DEFAULT_REDIS_URL = "redis://localhost:63790/15"


# ---------------------------------------------------------------------------
# Internal deny signal — never crosses the agent boundary.
# ---------------------------------------------------------------------------


class _Deny(Exception):
    """Carries the concrete DenyReason + diagnostic detail toward the WORM log."""

    def __init__(self, reason: DenyReason, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}")


# ---------------------------------------------------------------------------
# §7.2  Transports — mock backends proving pipeline/transport decoupling.
# ---------------------------------------------------------------------------


class CloudRESTTransport(BaseTransport):
    """Simulated REST-cloud dispatch."""

    async def execute(self, intent: AuthorizedIntent, target: str) -> TransportResult:
        # A real implementation would issue an HTTP request; the pipeline neither
        # knows nor cares. We echo only non-sensitive routing metadata.
        return TransportResult(
            ok=True,
            target=target,
            status_code=200,
            detail="rest dispatch simulated",
            echo={"method": "POST", "path": target},
        )


class LegacyMainframeTransport(BaseTransport):
    """
    Simulated legacy mainframe dispatch.

    Encodes an EBCDIC cp500 fixed-width 80-byte frame: an 8-char transaction code
    (the last dotted segment of the target, e.g. PAYR / GLPOST) followed by a
    72-char field derived from the canonical arguments. This proves a transport
    can be swapped in without touching the pipeline.
    """

    async def execute(self, intent: AuthorizedIntent, target: str) -> TransportResult:
        frame = self._build_frame(target, intent.intent.arguments)
        # cp500 is single-byte per character, so 80 characters -> exactly 80 bytes.
        assert len(frame) == 80, "mainframe frame must be exactly 80 bytes"
        return TransportResult(
            ok=True,
            target=target,
            status_code=0,  # mainframe RC=0.
            detail="RC=0",
            echo={"frame_hex": frame.hex(), "encoding": "cp500"},
        )

    @staticmethod
    def _build_frame(target: str, arguments: dict[str, Any]) -> bytes:
        # transaction := last dotted segment, upper-cased, clipped to 8 chars.
        transaction = target.rsplit(".", 1)[-1][:8]
        # Deterministic field from canonical arguments, clipped to 72 chars.
        field = json.dumps(arguments, sort_keys=True, separators=(",", ":"))[:72]
        line = f"{transaction:<8}{field:<72}"  # exactly 80 characters.
        # errors="replace" guarantees every char maps to one cp500 byte, so the
        # 80-char string always encodes to 80 bytes even for non-EBCDIC input.
        return line.encode("cp500", errors="replace")


# ---------------------------------------------------------------------------
# §1.7  Grant-mandate argument model + grant-issuing transport.
# ---------------------------------------------------------------------------


class _GrantMandateArgs(BaseModel):
    """Strict shape of a ``skill_compartment_grant`` mandate's arguments."""

    model_config = ConfigDict(extra="forbid", strict=True)

    grantee: str = Field(min_length=1, max_length=256)
    compartment: str
    ttl_seconds: int = Field(
        default=DEFAULT_GRANT_TTL_SECONDS,
        ge=MIN_GRANT_TTL_SECONDS,
        le=MAX_GRANT_TTL_SECONDS,
    )

    @field_validator("compartment")
    @classmethod
    def _uuid(cls, v: str) -> str:
        uuid.UUID(v)
        return v


class GrantIssuingTransport(BaseTransport):
    """Internal transport: commits a compartment grant (no external topology)."""

    def __init__(self, grants: GrantStore) -> None:
        self._grants = grants

    async def execute(self, intent: AuthorizedIntent, target: str) -> TransportResult:
        args = intent.intent.arguments  # already strict-validated in _mandate_gate.
        record = await self._grants.issue(
            tenant_id=intent.identity.tenant_id,
            subject_agent_id=str(args["grantee"]),
            compartment_uuid=str(args["compartment"]),
            issued_by=intent.identity.agent_id,
            capability_used=CAP_COMPARTMENT_GRANT,
            correlation_id=intent.correlation_id,
            ttl_seconds=int(args.get("ttl_seconds", DEFAULT_GRANT_TTL_SECONDS)),
        )
        # Echo carries NO real topology — only the grant identifiers.
        return TransportResult(
            ok=True,
            target="grant_issue",
            status_code=0,
            detail="grant issued",
            echo={
                "grant_id": record.grant_id,
                "compartment": record.compartment_uuid,
                "grantee": record.subject_agent_id,
            },
        )


# ---------------------------------------------------------------------------
# §7  MCPIPGateway — the authorization pipeline.
# ---------------------------------------------------------------------------


class MCPIPGateway:
    """Wires the four stages together behind one ``authorize_and_execute`` entry."""

    def __init__(
        self,
        *,
        redis_client: "redis.Redis",
        resolver: TokenResolver,
        registry: AliasRegistry,
        pin_validator: PinValidator,
        worm: WormLogger,
        grants: GrantStore,
    ) -> None:
        self._redis = redis_client
        self._resolver = resolver
        self._registry = registry
        self._pin = pin_validator
        self._worm = worm
        self._grants = grants
        self._quarantine = QuarantineStore(redis_client)
        # Deny-only policy overlay (velocity + amount ceiling). Its per-tenant policy
        # document is REAL config: the demo writes one via ``_policy_docs`` directly
        # (mirroring how it registers payload locks directly), never a fabricated
        # default. No document → no limits (honest absent state).
        self._policy_docs = PolicyDocStore(redis_client)
        self._policy = VelocityAmountPolicyEngine(redis_client, self._policy_docs)
        # Community-gate seam (DENY-ONLY, Phase 2). The registered provider (a strict
        # NO-OP until a CEL gate engine is registered — the honest "none configured"
        # state) is evaluated at step 4c′. It can ONLY add a POLICY_GATE_DENIED; it never
        # rescues an earlier deny, mints identity, or mutates the intent/target.
        self._community_gate_provider = active_community_gate_provider()
        # Transport selection table — keyed by the alias's declared transport.
        self._transports: dict[str, BaseTransport] = {
            "cloud_rest": CloudRESTTransport(),
            "legacy_mainframe": LegacyMainframeTransport(),
            "grant_issue": GrantIssuingTransport(grants),
        }

    async def authorize_and_execute(
        self,
        token: str,
        raw_call: dict[str, Any],
        source_format: SourceFormat,
        trace: SwarmTrace,
        pin: Optional[str] = None,
        lock_id: Optional[str] = None,
    ) -> TransportResult:
        """
        Run the full pipeline. Returns a TransportResult on ALLOW; raises
        MCPIPDenied (opaque) on any deny — the concrete reason lands only in WORM.

        ``lock_id`` threads the payload-lock identifier from the out-of-band
        registration step into consumption (PinValidator.consume needs it); it is
        required precisely when the resolved alias is PIN_REQUIRED.
        """
        correlation_id = uuid.uuid4().hex

        # Context accumulates as stages succeed, so a late deny can still log what
        # was known (tenant, alias, payload hash) without leaking it to the agent.
        ctx: dict[str, Any] = {"correlation_id": correlation_id}

        try:
            # --- 2) Auth: identity is sovereign, JWT-only. --------------------
            identity = self._authenticate(token)
            ctx["tenant_id"] = identity.tenant_id
            ctx["agent_id"] = identity.agent_id
            ctx["jti"] = identity.jti
            # Full RFC-8693 delegation chain + ID-JAG marker → WORM/audit ONLY,
            # identically ordered with app/main.py. An identity, not a secret: KEPT
            # (not redacted) and never surfaced to the agent. Absent → recorded neither.
            if identity.act_chain:
                ctx["delegation_chain"] = list(identity.act_chain)
            if identity.id_jag:
                ctx["id_jag"] = True

            # --- 2b) Quarantine gate: a canary-tripped agent is frozen. --------
            await self._quarantine_gate(identity)

            # --- 3) Bridge: normalize + deep schema/char/size/injection gates. -
            intent = self._normalize(raw_call, source_format, trace)
            ctx["alias"] = intent.alias
            # A2A task-envelope correlation provenance → WORM/audit ONLY (topology-free,
            # RECORDED-NOT-TRUSTED; declared actor/delegation is UNVERIFIED — MCPIP's
            # identity is JWT-only). Mirrored identically with app/main.py; None for the
            # six non-A2A dialects. Never crosses the agent wire.
            project_a2a_context(ctx, intent.a2a_context)

            # --- 4) Obfuscator: tenant-scoped alias -> real target. -----------
            entry = self._resolve_alias(identity.tenant_id, intent.alias)
            ctx["target"] = entry.target
            ctx["transport"] = entry.transport
            ctx["risk_tier"] = entry.risk_tier.value
            if entry.compartment is not None:
                ctx["compartment"] = entry.compartment
            ctx["classification"] = entry.classification.value

            # --- 4a) Canary tripwire: selecting a decoy quarantines the caller.
            await self._canary_gate(identity, entry, correlation_id)

            # --- 4b) Compartment gate: entitlement to a compartmented alias. --
            await self._compartment_gate(identity, entry)

            # --- 4c) Mandate gate: capability UUID + strict grant-arg shape. --
            await self._mandate_gate(identity, entry, intent)

            # --- 4c′) Community-gate seam (DENY-ONLY, Phase 2). ----------------
            # An author-your-own declarative gate over a topology-free whitelisted
            # context (opaque alias + coarse transport class + risk tier +
            # classification — NO target, NO secrets, NO arguments). A strict NO-OP
            # until a CEL gate engine is registered (honest "none configured"); it can
            # ONLY add a POLICY_GATE_DENIED, never rescue an earlier deny. Read-only —
            # it NEVER recomputes canonical_json / the lock hash. Placed right after the
            # mandate gate and adjacent to the G3 policy gate below (both deny-only
            # overlays sit after the entitlement gates).
            await self._community_gate(entry)

            # --- 5) Bind + canonical payload hash. ----------------------------
            authorized = AuthorizedIntent(
                intent=intent, identity=identity, correlation_id=correlation_id
            )
            payload_hash = lock_payload_hash(
                identity.tenant_id, identity.agent_id, intent.alias, intent.arguments
            )
            ctx["payload_hash"] = payload_hash

            # --- 5b) Policy overlay (DENY-ONLY): velocity + amount ceilings. ---
            # A stateless, opt-in policy step AFTER the entitlement gates and BEFORE
            # the risk gate. It can ONLY add a POLICY_DENIED — never allow what an
            # earlier gate denied, never mint identity, never mutate intent/target.
            # Invoked only on the NON-completion pass (every AUTO request + every PIN
            # STAGING, never PIN COMPLETION) so a PIN_REQUIRED action's velocity is
            # counted exactly once: the amount is payload-locked, so the staging check
            # covers completion. The skip condition REQUIRES risk_tier==PIN_REQUIRED,
            # so an AUTO request always evaluates regardless of any dummy pin (closing
            # the AUTO+dummy-pin velocity-skip bypass).
            if not (entry.risk_tier is RiskTier.PIN_REQUIRED and pin is not None):
                await self._policy_gate(identity, entry, intent)

            # --- 6) Risk gate: PIN_REQUIRED consumes an exactly-once lock. -----
            lock_code: Optional[int] = None
            if entry.risk_tier is RiskTier.PIN_REQUIRED:
                lock_code = await self._consume_pin(
                    identity, entry, intent, pin, lock_id
                )
                ctx["lock_code"] = lock_code

            # --- 7) Audit: emit the ALLOW decision. ---------------------------
            await self._emit_allow(ctx)

            # --- 8) Dispatch to the declared transport. -----------------------
            result = await self._dispatch(authorized, entry)
            return result

        except _Deny as deny:
            # Single choke point: log the concrete reason to WORM, then raise the
            # opaque agent-facing exception.
            await self._emit_deny(ctx, deny)
            raise MCPIPDenied(correlation_id) from None
        except MCPIPDenied:
            # Already opaque — re-raise untouched.
            raise
        except Exception as unexpected:  # noqa: BLE001 - fail-closed catch-all.
            # Anything we did not anticipate is an INTERNAL deny. Never leak it.
            await self._emit_deny(
                ctx, _Deny(DenyReason.INTERNAL, f"{type(unexpected).__name__}")
            )
            raise MCPIPDenied(correlation_id) from None

    # ------------------------------------------------------------------ stages

    def _authenticate(self, token: str) -> Identity:
        """Stage 2 — verify the JWT or deny JWT_INVALID / JWT_CLAIMS_MISSING."""
        try:
            return self._resolver.resolve(token)
        except TokenClaimsMissing as exc:
            raise _Deny(DenyReason.JWT_CLAIMS_MISSING, str(exc)) from exc
        except TokenError as exc:
            raise _Deny(DenyReason.JWT_INVALID, str(exc)) from exc

    def _normalize(
        self, raw_call: dict[str, Any], source_format: SourceFormat, trace: SwarmTrace
    ) -> NormalizedIntent:
        """Stage 3 — parse + deep-validate, mapping each failure to a DenyReason."""
        try:
            return intent_parser.parse(raw_call, source_format, trace)
        except IdentityInjection as exc:
            raise _Deny(DenyReason.IDENTITY_INJECTION, str(exc)) from exc
        except DepthExceeded as exc:
            raise _Deny(DenyReason.DEPTH_EXCEEDED, str(exc)) from exc
        except SizeExceeded as exc:
            raise _Deny(DenyReason.SIZE_EXCEEDED, str(exc)) from exc
        except UnknownFormat as exc:
            raise _Deny(DenyReason.UNKNOWN_FORMAT, str(exc)) from exc
        except ValidationError as exc:
            # A strict-model rejection or a reject_unsafe_string ValueError (which
            # Pydantic wraps). Disambiguate by inspecting the rendered errors.
            raise _Deny(self._classify_validation_error(exc), str(exc)) from exc

    @staticmethod
    def _classify_validation_error(exc: ValidationError) -> DenyReason:
        """Map a Pydantic ValidationError to the most specific DenyReason."""
        blob = str(exc).casefold()
        if "illegal character" in blob:
            return DenyReason.ILLEGAL_CHARACTER
        if "max_string_len" in blob:
            return DenyReason.SIZE_EXCEEDED
        return DenyReason.SCHEMA_VIOLATION

    async def _quarantine_gate(self, identity: Identity) -> None:
        """
        Stage 2b — deny (AGENT_QUARANTINED) while the caller's canary-trip freeze
        is active. One Redis GET; a transport failure denies LOCK_ERROR — an
        unreadable freeze list never lets a possibly-quarantined agent through.
        """
        try:
            frozen = await self._quarantine.is_quarantined(
                identity.tenant_id, identity.agent_id
            )
        except LockError as exc:
            raise _Deny(DenyReason.LOCK_ERROR, str(exc)) from exc
        if frozen:
            raise _Deny(
                DenyReason.AGENT_QUARANTINED,
                "agent is quarantined (canary tripwire)",
            )

    async def _canary_gate(
        self, identity: Identity, entry: AliasEntry, correlation_id: str
    ) -> None:
        """
        Stage 4a — trip the deception tripwire on a canary alias.

        Runs BEFORE the compartment/mandate gates so the trip fires on first touch
        regardless of entitlements. The quarantine mark is best-effort (the deny
        stands even if Redis drops the mark); the deny itself is the same opaque
        MCPIPDenied as every other reason — CANARY_TRIPPED lands only in WORM.
        """
        if not entry.canary:
            return
        await self._quarantine.quarantine(
            tenant_id=identity.tenant_id,
            agent_id=identity.agent_id,
            correlation_id=correlation_id,
            tripped_alias=entry.alias,
        )
        raise _Deny(
            DenyReason.CANARY_TRIPPED, f"canary alias '{entry.alias}' selected"
        )

    def _resolve_alias(self, tenant_id: str, alias: str) -> AliasEntry:
        """Stage 4 — resolve the tenant-scoped alias or deny fail-closed."""
        try:
            return self._registry.resolve(tenant_id, alias)
        except CrossTenant as exc:
            raise _Deny(DenyReason.CROSS_TENANT, str(exc)) from exc
        except UnknownAlias as exc:
            raise _Deny(DenyReason.UNKNOWN_ALIAS, str(exc)) from exc

    async def _compartment_gate(self, identity: Identity, entry: AliasEntry) -> None:
        """
        Deny (COMPARTMENT_DENIED) unless the caller is entitled to entry.compartment.

        Un-compartmented aliases (compartment is None) are always allowed (back-compat).
        Entitlement is either a DIRECT match of the JWT compartment claim (timing-uniform
        compare) or a DELEGATED, active, unexpired grant. No role string is consulted.
        """
        if entry.compartment is None:
            return
        if identity.compartment is not None and constant_time_equals(
            identity.compartment, entry.compartment
        ):
            return
        if await self._grants.has_active_grant(
            identity.tenant_id, identity.agent_id, entry.compartment
        ):
            return
        raise _Deny(
            DenyReason.COMPARTMENT_DENIED,
            f"agent not entitled to compartment {entry.compartment}",
        )

    async def _mandate_gate(
        self, identity: Identity, entry: AliasEntry, intent: NormalizedIntent
    ) -> None:
        """
        Enforce the alias's required capability UUID, then (for grant issuance) the
        strict mandate-argument shape + target-compartment existence.

        Capability is matched with a timing-uniform compare against the JWT's
        ``capabilities`` claim — NEVER the role string.
        """
        if entry.required_capability is None:
            return
        if not any(
            constant_time_equals(c, entry.required_capability)
            for c in identity.capabilities
        ):
            raise _Deny(
                DenyReason.CAPABILITY_DENIED,
                f"missing capability {entry.required_capability}",
            )
        if entry.transport == "grant_issue":
            self._validate_grant_args(identity, entry, intent.arguments)

    def _validate_grant_args(
        self, identity: Identity, entry: AliasEntry, arguments: dict[str, Any]
    ) -> None:
        """
        Strict-validate grant mandate args, confirm the target compartment exists, and
        enforce COMPARTMENT-SCOPED issuance authority.

        Holding the coarse ``CAP_COMPARTMENT_GRANT`` (checked in ``_mandate_gate``) only
        admits a principal to the grant governance alias — it is NOT a tenant-wide master
        key. To issue a grant for compartment ``X`` the issuer must ALSO hold
        ``grant_capability_for(X)`` in its JWT ``capabilities`` claim, matched
        timing-uniformly. This closes the cross-compartment delegation escape: a
        FALCON-scoped delegator cannot mint AEGIS access for a colluding agent.
        """
        try:
            args = _GrantMandateArgs.model_validate(arguments)
        except ValidationError as exc:
            raise _Deny(DenyReason.SCHEMA_VIOLATION, str(exc)) from exc
        if not self._registry.compartment_exists(identity.tenant_id, args.compartment):
            raise _Deny(DenyReason.COMPARTMENT_DENIED, "unknown compartment")
        required_scope = grant_capability_for(args.compartment)
        if not any(
            constant_time_equals(c, required_scope) for c in identity.capabilities
        ):
            raise _Deny(
                DenyReason.CAPABILITY_DENIED,
                f"missing compartment-scoped grant capability for {args.compartment}",
            )

    async def _community_gate(self, entry: AliasEntry) -> None:
        """
        Stage 4c′ — the deny-only COMMUNITY-GATE seam (Phase 2).

        Evaluates the registered community-gate provider over a NARROW, topology-free
        whitelisted context (opaque alias + coarse transport class + risk tier +
        classification — NO target, NO secrets, NO arguments) and denies
        POLICY_GATE_DENIED on a ``deny`` outcome; any other outcome falls through to the
        next gate (which may itself deny). Deny-only + monotonic: it can ONLY add a deny,
        never allow what an earlier gate denied. With no gate engine registered the
        provider is a strict NO-OP (the honest "no community gate engine configured"
        state — no gates enforced), so this is a pass-through until an engine lands.

        ``evaluate`` is wrapped fail-closed: any exception → POLICY_GATE_DENIED, never a
        silent pass. It is a READ-ONLY predicate over already-normalized inputs — it NEVER
        recomputes canonical_json / the lock hash / mutates the intent or target.
        """
        try:
            decision = await self._community_gate_provider.evaluate(
                CommunityGateContext(
                    alias=entry.alias,
                    transport_class=entry.transport,
                    risk_tier=entry.risk_tier,
                    classification=entry.classification,
                )
            )
        except Exception as exc:  # noqa: BLE001 — a raising provider fails closed.
            raise _Deny(
                DenyReason.POLICY_GATE_DENIED, "community gate evaluation failed"
            ) from exc
        if decision.outcome == "deny":
            raise _Deny(DenyReason.POLICY_GATE_DENIED, decision.detail)

    async def _policy_gate(
        self, identity: Identity, entry: AliasEntry, intent: NormalizedIntent
    ) -> None:
        """
        Stage 5b — the deny-only policy overlay.

        Evaluates the tenant's velocity/amount policy and denies POLICY_DENIED on a
        ``deny`` outcome; any other outcome falls through to the risk gate (which may
        itself deny). ``evaluate`` is wrapped fail-closed: even a raising/buggy provider
        yields POLICY_DENIED rather than proceeding, so the gate can never fail open.
        """
        try:
            decision = await self._policy.evaluate(
                PolicyContext(
                    identity=identity,
                    alias=entry.alias,
                    transport_class=entry.transport,
                    risk_tier=entry.risk_tier,
                    arguments=intent.arguments,
                )
            )
        except Exception as exc:  # noqa: BLE001 — a raising provider fails closed.
            raise _Deny(DenyReason.POLICY_DENIED, "policy evaluation failed") from exc
        if decision.outcome == "deny":
            raise _Deny(DenyReason.POLICY_DENIED, decision.detail)

    async def _consume_pin(
        self,
        identity: Identity,
        entry: AliasEntry,
        intent: NormalizedIntent,
        pin: Optional[str],
        lock_id: Optional[str],
    ) -> int:
        """Stage 6 — atomically consume the payload lock; map the Lua code."""
        if pin is None:
            raise _Deny(DenyReason.PIN_REQUIRED, "pin required for high-risk alias")
        if lock_id is None:
            # No lock to consume — treat as not found (fail-closed).
            raise _Deny(DenyReason.PIN_NOT_FOUND, "no lock_id supplied")

        try:
            code = await self._pin.consume(
                identity.tenant_id,
                lock_id,
                identity.agent_id,
                entry.alias,
                intent.arguments,
                pin,
            )
        except LockError as exc:
            raise _Deny(DenyReason.LOCK_ERROR, str(exc)) from exc

        if code == 1:
            return code
        if code == -1:
            raise _Deny(DenyReason.PIN_NOT_FOUND, "lock absent or already spent")
        if code == -2:
            raise _Deny(DenyReason.PIN_MISMATCH, "pin did not match")
        if code == -3:
            raise _Deny(DenyReason.PAYLOAD_MISMATCH, "payload hash mismatch")
        # Unknown code — fail-closed.
        raise _Deny(DenyReason.LOCK_ERROR, f"unexpected lock code {code}")

    async def _dispatch(
        self, authorized: AuthorizedIntent, entry: AliasEntry
    ) -> TransportResult:
        """Stage 8 — select the transport and execute; wrap failures."""
        transport = self._transports.get(entry.transport)
        if transport is None:
            raise _Deny(DenyReason.INTERNAL, f"no transport for {entry.transport}")
        try:
            result = await transport.execute(authorized, entry.target)
        except Exception as exc:  # noqa: BLE001 - any backend failure is opaque.
            raise _Deny(DenyReason.TRANSPORT_ERROR, f"{type(exc).__name__}") from exc
        if not result.ok:
            raise _Deny(DenyReason.TRANSPORT_ERROR, "transport reported failure")
        return result

    # ------------------------------------------------------------------ audit

    async def _emit_allow(self, ctx: dict[str, Any]) -> None:
        """Write the ALLOW decision to the WORM log (redacted, non-sensitive)."""
        event = {**ctx, "decision": Decision.ALLOW.value, "deny_reason": None}
        await self._safe_emit(ctx, event)

    async def _emit_deny(self, ctx: dict[str, Any], deny: _Deny) -> None:
        """Write the DENY decision — the ONLY place the concrete reason is recorded."""
        event = {
            **ctx,
            "decision": Decision.DENY.value,
            "deny_reason": deny.reason.value,
            "detail": deny.detail,
        }
        await self._safe_emit(ctx, event)

    async def _safe_emit(self, ctx: dict[str, Any], event: dict[str, Any]) -> None:
        """
        Emit one decision to WORM under a fail-CLOSED boundary.

        ``WormLogger.emit`` acquires a Redis lock and does Redis/file I/O; under a
        Redis/WORM outage it raises RedisError/TimeoutError/OSError. Such a raw
        internal exception must NEVER escape ``authorize_and_execute`` as itself —
        it would leak a class name / topology to the agent and skip the opaque
        boundary. So any emit failure is converted here into ``MCPIPDenied`` (the
        only agent-facing exception), and a last-resort stderr audit line is
        written so the decision is not lost silently under the outage.

        On the ALLOW path this raise is caught by the ``except MCPIPDenied: raise``
        arm of the pipeline — dispatch never runs (fail-closed). On a DENY path it
        simply replaces the pending ``MCPIPDenied`` with an identical one.
        """
        correlation_id = str(ctx.get("correlation_id", "unknown"))
        try:
            await self._worm.emit(event)
        except Exception as emit_exc:  # noqa: BLE001 - WORM/Redis outage: fail closed.
            self._last_resort_audit(correlation_id, event, emit_exc)
            raise MCPIPDenied(correlation_id) from None

    @staticmethod
    def _last_resort_audit(
        correlation_id: str, event: dict[str, Any], emit_exc: BaseException
    ) -> None:
        """
        Emergency audit sink used ONLY when the WORM write itself fails.

        Written to stderr (server-side; never crosses the agent boundary) so a
        decision made during a WORM/Redis outage still leaves a durable trace for
        the operator. Carries only the non-sensitive decision envelope.
        """
        print(
            "MCPIP WORM-EMIT-FAILURE "
            f"correlation_id={correlation_id} "
            f"decision={event.get('decision')} "
            f"deny_reason={event.get('deny_reason')} "
            f"error={type(emit_exc).__name__}",
            file=sys.stderr,
            flush=True,
        )


# ---------------------------------------------------------------------------
# Demo scaffolding — key material, token minting, trace building.
# ---------------------------------------------------------------------------


class _DemoIdP:
    """Ephemeral in-process identity provider (Ed25519) for the demo run."""

    ISSUER = "mcpip-demo-idp"
    AUDIENCE = "mcpip-gateway"

    def __init__(self) -> None:
        self._private = Ed25519PrivateKey.generate()
        self._private_pem = self._private.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        self.public_pem = self._private.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

    def mint(
        self,
        *,
        tenant_id: str = "tenant-acme",
        agent_id: str = "agent-orchestrator-1",
        role: str = "ops",
        drop_claim: Optional[str] = None,
        compartment: Optional[str] = None,
        capabilities: Optional[list[str]] = None,
        session_id: Optional[str] = None,
        delegation_id: Optional[str] = None,
    ) -> str:
        """Mint a valid EdDSA JWT. ``drop_claim`` omits a required claim to test denial.

        ``compartment`` / ``capabilities`` are OPTIONAL UUID-identified authorization
        claims; when omitted the token is the exact legacy 8-claim shape.
        """
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.ISSUER,
            "aud": self.AUDIENCE,
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "role": role,
            "exp": now + 300,
            "iat": now,
            "nbf": now,
            "jti": uuid.uuid4().hex,
        }
        if compartment is not None:
            claims["compartment"] = compartment
        if capabilities is not None:
            claims["capabilities"] = capabilities
        if session_id is not None:
            claims["session_id"] = session_id
        if delegation_id is not None:
            claims["delegation_id"] = delegation_id
        if drop_claim is not None:
            claims.pop(drop_claim, None)
        return jwt.encode(claims, self._private_pem, algorithm="EdDSA")


def _make_trace(agent_id: str = "agent-orchestrator-1") -> SwarmTrace:
    """Build a minimal single-hop, well-formed SwarmTrace."""
    return SwarmTrace(
        trace_id=str(uuid.uuid4()),
        hops=[
            Hop(
                hop_index=0,
                agent_id=agent_id,
                parent_agent_id=None,
                purpose="demo orchestration",
            )
        ],
    )


def _openai_call(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Wrap arguments in an OpenAI tool_call envelope."""
    return {
        "id": "call_demo",
        "type": "function",
        "function": {"name": alias, "arguments": json.dumps(arguments)},
    }


def _forge_none_token() -> str:
    """
    Craft an unsigned ``{"alg":"none"}`` token by hand — the resolver must reject
    it at the header allow-list check before any verification.
    """

    def b64(obj: dict[str, Any]) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "iss": _DemoIdP.ISSUER,
        "aud": _DemoIdP.AUDIENCE,
        "tenant_id": "tenant-acme",
        "agent_id": "agent-orchestrator-1",
        "role": "ops",
        "exp": now + 300,
        "iat": now,
        "nbf": now,
    }
    return f"{b64(header)}.{b64(payload)}."


def _tamper_signature(token: str) -> str:
    """Flip a character in the token's payload segment so the signature no longer matches."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    # Mutate the last character of the payload segment (still valid base64url).
    mutated = payload_b64[:-1] + ("A" if payload_b64[-1] != "A" else "B")
    return f"{header_b64}.{mutated}.{sig_b64}"


# ---------------------------------------------------------------------------
# Demo harness — runs the 10 gates and a WORM integrity check.
# ---------------------------------------------------------------------------


class _DemoRunner:
    """Executes each scenario, printing PASS/FAIL and tracking overall success."""

    def __init__(self, gateway: MCPIPGateway, worm: WormLogger, idp: _DemoIdP) -> None:
        self._gw = gateway
        self._worm = worm
        self._idp = idp
        self._pin = gateway._pin  # demo drives lock registration directly.
        self.all_ok = True

    def _record(self, label: str, ok: bool, note: str) -> None:
        status = "PASS" if ok else "FAIL"
        self.all_ok = self.all_ok and ok
        print(f"  [{status}] {label:<26} {note}")

    async def _tail_deny_reason(self) -> Optional[str]:
        """Read the last buffered WORM event and return its event.deny_reason (test-only).

        Epoch mode keeps events in the durable Redis stream, so the last-appended
        record — the deny just emitted — is read back via XREVRANGE COUNT 1.
        """
        entries: Any = await self._worm._redis.xrevrange(
            "mcpip:worm:events", count=1
        )
        if not entries:
            return None
        _sid, fields = entries[0]
        record = json.loads(fields["record"])
        reason = record["event"].get("deny_reason")
        return reason if isinstance(reason, str) else None

    async def _expect_allow(
        self,
        label: str,
        coro: Awaitable[TransportResult],
        *,
        check: Callable[[TransportResult], tuple[bool, str]],
    ) -> None:
        """Run an allow-path scenario; the coroutine must return a TransportResult."""
        try:
            result = await coro
        except MCPIPDenied as denied:
            self._record(label, False, f"unexpected DENY corr={denied.correlation_id}")
            return
        ok, note = check(result)
        self._record(label, ok, note)

    async def _expect_deny(
        self, label: str, coro: Awaitable[TransportResult], expected: DenyReason
    ) -> None:
        """Run a deny-path scenario; must raise MCPIPDenied AND log ``expected``."""
        try:
            await coro
        except MCPIPDenied as denied:
            logged = await self._tail_deny_reason()
            ok = logged == expected.value
            note = (
                f"DENY corr={denied.correlation_id[:6]}… reason={logged}"
                if ok
                else f"DENY but reason={logged} (expected {expected.value})"
            )
            self._record(label, ok, note)
            return
        self._record(label, False, "expected DENY but call succeeded")

    async def run(self) -> None:
        idp = self._idp
        acme_token = idp.mint()

        # --- 1) Happy AUTO -------------------------------------------------
        await self._expect_allow(
            "1 AUTO spend_summary",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_spend_summary", {"period": "2026-Q2"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            check=lambda r: (
                r.ok and r.status_code == 200,
                f"ALLOW {r.target} {r.status_code}",
            ),
        )

        # --- 2) Happy PIN_REQUIRED (register then consume) -----------------
        payroll_args = {"run_id": "PR-2026-07", "cycle": "monthly"}
        lock_id = await self._pin.register(
            "tenant-acme", "agent-orchestrator-1",
            "skill_payroll_run", payroll_args, "483920",
        )
        await self._expect_allow(
            "2 PIN payroll_run",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_payroll_run", payroll_args),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
                pin="483920",
                lock_id=lock_id,
            ),
            check=lambda r: (
                r.ok and r.status_code == 0 and len(bytes.fromhex(r.echo["frame_hex"])) == 80,
                f"ALLOW {r.target} RC={r.status_code} frame=80B",
            ),
        )

        # --- 3) PIN replay (same lock, already spent) ----------------------
        await self._expect_deny(
            "3 PIN replay",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_payroll_run", payroll_args),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
                pin="483920",
                lock_id=lock_id,
            ),
            DenyReason.PIN_NOT_FOUND,
        )

        # --- 4) Payload byte-tamper (lock survives) ------------------------
        tamper_args = {"run_id": "PR-2026-07", "cycle": "monthly"}
        tamper_lock = await self._pin.register(
            "tenant-acme", "agent-orchestrator-1",
            "skill_payroll_run", tamper_args, "112233",
        )
        drifted = {"run_id": "PR-2026-07", "cycle": "monthlyX"}  # one byte changed.
        await self._expect_deny(
            "4 payload tamper",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_payroll_run", drifted),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
                pin="112233",
                lock_id=tamper_lock,
            ),
            DenyReason.PAYLOAD_MISMATCH,
        )
        # Prove the lock is still alive: the correct payload+pin still consumes it.
        survive_code = await self._pin.consume(
            "tenant-acme", tamper_lock, "agent-orchestrator-1",
            "skill_payroll_run", tamper_args, "112233",
        )
        self._record(
            "4b lock survived",
            survive_code == 1,
            f"correct retry code={survive_code}",
        )

        # --- 5) Oversize / extra nested arguments --------------------------
        oversize = {f"key_{i}": "x" for i in range(200)}  # > MAX_ARG_KEYS.
        await self._expect_deny(
            "5 schema/oversize",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_spend_summary", oversize),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            DenyReason.SIZE_EXCEEDED,
        )

        # --- 6) Forged JWT signature ---------------------------------------
        await self._expect_deny(
            "6 forged JWT",
            self._gw.authorize_and_execute(
                _tamper_signature(acme_token),
                _openai_call("skill_spend_summary", {"period": "2026-Q2"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            DenyReason.JWT_INVALID,
        )

        # --- 7) alg=none token ---------------------------------------------
        await self._expect_deny(
            "7 alg=none",
            self._gw.authorize_and_execute(
                _forge_none_token(),
                _openai_call("skill_spend_summary", {"period": "2026-Q2"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            DenyReason.JWT_INVALID,
        )

        # --- 8) Identity injection in arguments ----------------------------
        await self._expect_deny(
            "8 identity injection",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_spend_summary", {"tenant_id": "evil"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            DenyReason.IDENTITY_INJECTION,
        )

        # --- 9) Unknown alias ----------------------------------------------
        await self._expect_deny(
            "9 unknown alias",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_does_not_exist", {}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            DenyReason.UNKNOWN_ALIAS,
        )

        # --- 10) Cross-tenant (globex reaching for acme's payroll) ----------
        globex_token = idp.mint(
            tenant_id="tenant-globex", agent_id="agent-globex-1"
        )
        await self._expect_deny(
            "10 cross-tenant",
            self._gw.authorize_and_execute(
                globex_token,
                _openai_call("skill_payroll_run", {"run_id": "x"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace("agent-globex-1"),
            ),
            DenyReason.CROSS_TENANT,
        )

        # ===================================================================
        # Compartmented team-MCP separation (UUID capability/grant model).
        # ===================================================================
        aegis = "aegis-dynamics"

        # --- C1) falcon agent → skill_airframe_telemetry (own compartment) ---
        falcon_token = idp.mint(
            tenant_id=aegis, agent_id="agent-falcon-1", compartment=FALCON
        )
        await self._expect_allow(
            "C1 compartment own",
            self._gw.authorize_and_execute(
                falcon_token,
                _openai_call("skill_airframe_telemetry", {}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace("agent-falcon-1"),
            ),
            check=lambda r: (r.ok, f"ALLOW {r.target} {r.status_code}"),
        )

        # --- C2) aegis agent → falcon alias (wrong compartment) ------------
        aegis1_token = idp.mint(
            tenant_id=aegis, agent_id="agent-aegis-1", compartment=AEGIS
        )
        await self._expect_deny(
            "C2 compartment cross",
            self._gw.authorize_and_execute(
                aegis1_token,
                _openai_call("skill_airframe_telemetry", {}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace("agent-aegis-1"),
            ),
            DenyReason.COMPARTMENT_DENIED,
        )

        # --- C3) aegis agent → un-compartmented alias (back-compat) --------
        aegis3_token = idp.mint(tenant_id=aegis, agent_id="agent-aegis-3")
        await self._expect_allow(
            "C3 uncompartmented ok",
            self._gw.authorize_and_execute(
                aegis3_token,
                _openai_call("skill_status_probe", {}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace("agent-aegis-3"),
            ),
            check=lambda r: (r.ok, f"ALLOW {r.target} {r.status_code}"),
        )

        # --- C4) capability holder issues a compartment grant (step-up) ----
        # The officer carries BOTH the coarse grant-authority capability AND the
        # FALCON-SCOPED grant capability, so it may issue a grant for FALCON — and ONLY
        # for FALCON (see C10, where the same officer is refused an AEGIS grant).
        officer_token = idp.mint(
            tenant_id=aegis,
            agent_id="agent-security-officer-1",
            capabilities=[CAP_COMPARTMENT_GRANT, grant_capability_for(FALCON)],
        )
        grant_args: dict[str, Any] = {
            "grantee": "agent-aegis-2",
            "compartment": FALCON,
            "ttl_seconds": 3600,
        }
        grant_lock = await self._pin.register(
            aegis, "agent-security-officer-1",
            "skill_compartment_grant", grant_args, "654321",
        )
        await self._expect_allow(
            "C4 grant issue",
            self._gw.authorize_and_execute(
                officer_token,
                _openai_call("skill_compartment_grant", grant_args),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace("agent-security-officer-1"),
                pin="654321",
                lock_id=grant_lock,
            ),
            check=lambda r: (
                r.ok and r.target == "grant_issue" and "grant_id" in r.echo,
                f"ALLOW grant_id={str(r.echo.get('grant_id'))[:8]}…",
            ),
        )

        # --- C5) grantee reaches the falcon alias via the delegated grant --
        aegis2_token = idp.mint(
            tenant_id=aegis, agent_id="agent-aegis-2", compartment=AEGIS
        )
        await self._expect_allow(
            "C5 delegated grant",
            self._gw.authorize_and_execute(
                aegis2_token,
                _openai_call("skill_airframe_telemetry", {}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace("agent-aegis-2"),
            ),
            check=lambda r: (r.ok, f"ALLOW {r.target} (via grant)"),
        )

        # --- C6) capability MISSING → grant issuance denied ----------------
        officer2_token = idp.mint(
            tenant_id=aegis, agent_id="agent-security-officer-2"
        )
        await self._expect_deny(
            "C6 capability missing",
            self._gw.authorize_and_execute(
                officer2_token,
                _openai_call("skill_compartment_grant", grant_args),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace("agent-security-officer-2"),
            ),
            DenyReason.CAPABILITY_DENIED,
        )

        # --- C7) grant expiry / revoke → delegated access gone -------------
        await self._gw._grants.revoke(aegis, "agent-aegis-2", FALCON)
        await self._expect_deny(
            "C7 grant expired",
            self._gw.authorize_and_execute(
                aegis2_token,
                _openai_call("skill_airframe_telemetry", {}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace("agent-aegis-2"),
            ),
            DenyReason.COMPARTMENT_DENIED,
        )

        # --- C10) cross-compartment grant escape is DENIED -----------------
        # The FALCON-scoped officer (holds CAP_COMPARTMENT_GRANT + grant_cap(FALCON))
        # attempts to grant a DIFFERENT classified compartment (AEGIS). The coarse
        # capability admits it to the governance alias, but the compartment-scoped
        # authority check refuses: it lacks grant_cap(AEGIS). Without this the delegation
        # capability would be a tenant-wide compartment master key (cross-compartment
        # isolation escape). The deny fires at the mandate gate, before any PIN staging.
        cross_args: dict[str, Any] = {
            "grantee": "agent-mole-1",
            "compartment": AEGIS,
            "ttl_seconds": 3600,
        }
        await self._expect_deny(
            "C10 cross-compartment grant denied",
            self._gw.authorize_and_execute(
                officer_token,
                _openai_call("skill_compartment_grant", cross_args),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace("agent-security-officer-1"),
            ),
            DenyReason.CAPABILITY_DENIED,
        )
        # And the intended grantee never gained AEGIS entitlement (no grant persisted).
        mole_token = idp.mint(tenant_id=aegis, agent_id="agent-mole-1")
        await self._expect_deny(
            "C10b mole cannot reach AEGIS alias",
            self._gw.authorize_and_execute(
                mole_token,
                _openai_call("skill_radar_calibration_set", {}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace("agent-mole-1"),
            ),
            DenyReason.COMPARTMENT_DENIED,
        )

        # --- C11) canary tripwire: a decoy skill freezes the agent ---------
        # A goal-hijacked agent sweeps the catalog and selects a bait skill; the
        # tripwire denies CANARY_TRIPPED and quarantines it, so its NEXT call — an
        # ordinary AUTO skill — is denied AGENT_QUARANTINED before any real work.
        # The agent id is RUN-UNIQUE because the quarantine this gate creates is real
        # and durable: it outlives the process. With a fixed id, a second run against
        # the same Redis had the agent already frozen, so the canary call denied
        # AGENT_QUARANTINED before reaching the tripwire and C11 reported FAIL — the
        # proof failing on a correctly-working gateway. Re-running the proof must be
        # safe, since it is what an operator does to confirm a deployment.
        hijacked_id = f"agent-hijacked-{uuid.uuid4().hex[:12]}"
        canary_agent = idp.mint(tenant_id="tenant-acme", agent_id=hijacked_id)
        await self._expect_deny(
            "C11 canary tripwire trips",
            self._gw.authorize_and_execute(
                canary_agent,
                _openai_call("skill_export_all_credentials", {}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(hijacked_id),
            ),
            DenyReason.CANARY_TRIPPED,
        )
        await self._expect_deny(
            "C11b tripped agent is quarantined",
            self._gw.authorize_and_execute(
                canary_agent,
                _openai_call("skill_spend_summary", {"period": "Q1"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(hijacked_id),
            ),
            DenyReason.AGENT_QUARANTINED,
        )

        # ===================================================================
        # Deny-only policy overlay (velocity cap + amount ceiling) — G3.
        # ===================================================================
        # REAL config: write a tenant policy document directly (as the demo registers
        # locks directly). No document → no limits; this opts tenant-acme in.
        policy_doc = PolicyDocStore.validate(
            {
                "schema": POLICY_SCHEMA,
                "rules": [
                    # After one allowed call, a second in the window denies.
                    {
                        "kind": "velocity",
                        "scope": "alias",
                        "scope_value": "skill_customer_lookup",
                        "max_actions": 1,
                        "window_seconds": 3600,
                    },
                    # Wires over 1000 are denied at the (PIN) staging pass.
                    {
                        "kind": "amount",
                        "scope": "alias",
                        "scope_value": "skill_wire_transfer",
                        "amount_field": "amount",
                        "max_amount": "1000",
                    },
                ],
            }
        )
        await self._gw._policy_docs.put("tenant-acme", policy_doc)

        # --- P1) velocity: first call under the cap is allowed --------------
        await self._expect_allow(
            "P1 velocity under cap",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_customer_lookup", {"id": "cust-1"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            check=lambda r: (r.ok, f"ALLOW {r.target} (count=1)"),
        )
        # --- P1b) velocity: the second call trips the fixed-window cap ------
        await self._expect_deny(
            "P1b velocity exceeded",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_customer_lookup", {"id": "cust-2"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            DenyReason.POLICY_DENIED,
        )

        # --- P2) amount ceiling: an under-ceiling wire has NO amount rule ---
        # trip, so it falls through (deny-only/monotonic) to the risk gate and
        # is denied PIN_REQUIRED — proving 'continue' never turns into an allow.
        await self._expect_deny(
            "P2 under ceiling → risk gate",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_wire_transfer", {"amount": 500, "to": "acct-9"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            DenyReason.PIN_REQUIRED,
        )
        # --- P2b) amount ceiling: an over-ceiling wire denies at staging ----
        await self._expect_deny(
            "P2b amount over ceiling",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_wire_transfer", {"amount": 5000, "to": "acct-9"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            DenyReason.POLICY_DENIED,
        )
        # --- P2c) amount smuggled as a string fails CLOSED (no coercion) ----
        await self._expect_deny(
            "P2c non-numeric amount",
            self._gw.authorize_and_execute(
                acme_token,
                _openai_call("skill_wire_transfer", {"amount": "5000", "to": "acct-9"}),
                SourceFormat.OPENAI_TOOL_CALL,
                _make_trace(),
            ),
            DenyReason.POLICY_DENIED,
        )

        # --- C8) catalog filtering (separation of teams between MCPs) ------
        obf = ObfuscatorService(self._gw._registry)
        falcon_identity = self._gw._authenticate(falcon_token)
        visible = await obf.list_visible(
            self._gw._registry, falcon_identity, self._gw._grants
        )
        names = {e.alias for e in visible}
        c8_ok = (
            "skill_airframe_telemetry" in names
            and "skill_status_probe" in names
            and "skill_radar_calibration_set" not in names
            and "skill_recon_feed_read" not in names
        )
        self._record(
            "C8 catalog filter",
            c8_ok,
            f"visible={len(names)} (falcon+tenant-wide, no aegis/sentinel)",
        )

        # --- C9) WORM epoch integrity (Merkle-epoch, signed root chain) ----
        header = await self._worm.close_epoch()
        intact, bad = await self._worm.verify_chain()
        all_incl_ok = True
        for eid in await self._worm.list_event_ids():
            pr = await self._worm.inclusion_proof(eid)
            all_incl_ok = all_incl_ok and (
                pr is not None
                and merkle.verify_inclusion(
                    merkle.leaf_digest(pr.record.encode("utf-8")),
                    pr.proof,
                    bytes.fromhex(pr.merkle_root),
                )
            )
        self._record(
            "C9 WORM epoch verify",
            intact and bad is None and all_incl_ok and header is not None,
            "INTACT (Merkle-epoch, signed root chain)"
            if intact and all_incl_ok
            else f"BROKEN at epoch {bad}",
        )


# ---------------------------------------------------------------------------
# Bootstrap + entrypoint.
# ---------------------------------------------------------------------------


async def _reset_state(redis_client: "redis.Redis", worm_path: str) -> None:
    """Clear demo-run state so sequencing, the buffer, and the epoch chain start fresh."""
    # Remove any prior WORM JSONL (per_event migration mode only; unused in epoch mode).
    try:
        os.remove(worm_path)
    except FileNotFoundError:
        pass
    # Reset the out-of-tamper-domain signed head anchor so a fresh demo run's epoch chain
    # (a NEW ephemeral signing key) starts from a clean low-watermark — stale lines from a
    # prior run's key would be signature-ignored anyway, but we clear them to stay tidy.
    try:
        os.remove(worm_path + ".anchor")
    except FileNotFoundError:
        pass
    # Reset the epoch-model buffer/chain state + the legacy per-event chain keys.
    await redis_client.delete(*ALL_WORM_KEYS)
    # Best-effort sweep of any leftover demo pin locks, grants, and step-up rate
    # counters from a prior run.
    async for key in redis_client.scan_iter(match="mcpip:pinlock:*"):
        await redis_client.delete(key)
    async for key in redis_client.scan_iter(match="mcpip:grant:*"):
        await redis_client.delete(key)
    async for key in redis_client.scan_iter(match="mcpip:stepup:*"):
        await redis_client.delete(key)
    async for key in redis_client.scan_iter(match="mcpip:policy:*"):
        await redis_client.delete(key)


# ── init banner ─────────────────────────────────────────────────────────────
# Figlet "ANSI Shadow" wordmark, embedded as a constant so the demo stays
# dependency-free.
_MCPIP_WORDMARK = (
    "███╗   ███╗ ██████╗██████╗ ██╗██████╗ \n"
    "████╗ ████║██╔════╝██╔══██╗██║██╔══██╗\n"
    "██╔████╔██║██║     ██████╔╝██║██████╔╝\n"
    "██║╚██╔╝██║██║     ██╔═══╝ ██║██╔═══╝ \n"
    "██║ ╚═╝ ██║╚██████╗██║     ██║██║     \n"
    "╚═╝     ╚═╝ ╚═════╝╚═╝     ╚═╝╚═╝     "
)


def _banner(redis_url: str, worm_path: str) -> None:
    """Print the init banner — the MCPIP wordmark + a one-row version table.

    Emerald on a TTY; a plain, escape-code-free header off-TTY (CI, pipes, files).
    """
    try:
        with open(os.path.join(os.path.dirname(__file__), "VERSION")) as fh:
            version = fh.read().strip()
    except OSError:
        version = "—"
    if not sys.stdout.isatty():
        print(f"MCPIP · version {version}")
        return
    e, d, r = "\033[38;5;42m", "\033[2m", "\033[0m"  # emerald · dim · reset
    word_w = max(len(line) for line in _MCPIP_WORDMARK.split("\n"))
    lw = len("version")
    vw = max(len(version), word_w - lw - 7)  # size the box to the wordmark's width
    print()
    for line in _MCPIP_WORDMARK.split("\n"):
        print(f"{e}{line}{r}")
    print()
    print(f"  {d}┌{'─' * (lw + 2)}┬{'─' * (vw + 2)}┐{r}")
    print(f"  {d}│{r} {e}version{r} {d}│{r} {version:<{vw}} {d}│{r}")
    print(f"  {d}└{'─' * (lw + 2)}┴{'─' * (vw + 2)}┘{r}")
    print()


def _reset_permitted(redis_client: "redis.Redis") -> bool:
    """Did the operator explicitly consent to wiping the target database?"""
    return "--reset" in sys.argv


async def _ledger_is_populated(redis_client: "redis.Redis") -> bool:
    """Does the target Redis already hold WORM state worth protecting?

    Cheap and conservative: any WORM key at all counts. A false positive costs a
    flag; a false negative costs an audit trail.
    """
    try:
        for key in ALL_WORM_KEYS:
            if await redis_client.exists(key):
                return True
        async for _ in redis_client.scan_iter(match="mcpip:worm:*", count=16):
            return True
    except Exception:  # noqa: BLE001 — an unreadable Redis is not a reason to wipe it.
        return True
    return False


async def _amain() -> int:
    redis_url = os.environ.get("MCPIP_REDIS_URL", DEFAULT_REDIS_URL)
    # A distinct default ledger path, so the anchor this proof advances is its own.
    # Sharing ./mcpip_worm.jsonl.anchor with a running gateway made each advance the
    # other's low-watermark, and the gateway then reported its own intact chain as
    # rolled back — a false tamper alarm from nothing but a shared file name.
    worm_path = os.environ.get("MCPIP_WORM_PATH", "./mcpip_proof.jsonl")

    # decode_responses=True: string replies come back as str; integer Lua replies
    # (the lock codes) still arrive as int, which PinValidator normalizes. A pooled
    # client (max_connections + periodic health check) is shared across every
    # component — no per-request client construction (safe-win: connection pooling).
    redis_client = redis.from_url(  # type: ignore[no-untyped-call]
        redis_url,
        decode_responses=True,
        max_connections=32,
        health_check_interval=30,
    )

    # Fail fast + fail-closed if Redis is unreachable.
    try:
        await redis_client.ping()
    except Exception as exc:  # noqa: BLE001
        print(f"◐ MCPIP: cannot reach Redis at {redis_url}: {type(exc).__name__}")
        await redis_client.aclose()
        return 1

    # Advisory durability posture check (the demo is a dev/sandbox run, so this never
    # blocks; a production gateway REFUSES to boot without appendfsync=always — see
    # app.main._lifespan / audit.worm_logger.assert_persistence_posture).
    await assert_persistence_posture(redis_client, require=False)

    # The proof needs a clean slate, so it WIPES the WORM chain, pin locks, grants,
    # step-ups and policies from MCPIP_REDIS_URL — whose default is the sandbox
    # gateway's own Redis. Running it against a live ledger destroys the audit
    # evidence, and the operator docs used to recommend it inside a section headed
    # "read-only, production-safe". Refuse rather than trust the reader.
    # Wiping the proof's OWN database is the point — it must stay re-runnable. The
    # danger is an operator who pointed MCPIP_REDIS_URL at a gateway's database, so
    # that is the only case that needs consent.
    if redis_url != DEFAULT_REDIS_URL and not _reset_permitted(redis_client):
        if await _ledger_is_populated(redis_client):
            print(
                f"◐ MCPIP: refusing to run — {redis_url} already holds a WORM ledger.\n"
                "  This proof RESETS the chain, grants, pin locks and policies before it\n"
                "  runs, which would destroy that audit evidence.\n"
                "  Point it at an empty database (MCPIP_REDIS_URL=redis://localhost:63790/15),\n"
                "  or pass --reset if wiping this one is genuinely what you want."
            )
            await redis_client.aclose()
            return 1

    await _reset_state(redis_client, worm_path)

    # Identity provider + verification key wiring.
    idp = _DemoIdP()
    resolver = TokenResolver(
        StaticPEMKeyProvider(idp.public_pem),
        issuer=_DemoIdP.ISSUER,
        audience=_DemoIdP.AUDIENCE,
    )

    # A dedicated Ed25519 key signs the WORM records (separate from the IdP key). The same
    # key signs the out-of-tamper-domain head anchor, whose fsync'd append-only file lets
    # verify_chain detect a tail-truncation / rollback that also rewrites the in-Redis
    # linkage counters.
    worm_signing_key = Ed25519PrivateKey.generate()
    anchor = AnchorStore(worm_signing_key, worm_path + ".anchor")
    worm = WormLogger(
        redis_client, worm_signing_key, path=worm_path, anchor=anchor
    )

    gateway = MCPIPGateway(
        redis_client=redis_client,
        resolver=resolver,
        registry=build_demo_registry(),
        pin_validator=PinValidator(redis_client),
        worm=worm,
        # The demo wires the OPTIONAL ReBAC relation-tuple projection so the additive
        # member-tuple write/remove is exercised end to end (best-effort, never affects a
        # gate). Without it GrantStore would behave identically.
        grants=GrantStore(
            redis_client, relations=RelationTupleStore(redis_client)
        ),
    )

    # Header.
    _banner(redis_url, worm_path)

    runner = _DemoRunner(gateway, worm, idp)
    try:
        await runner.run()
    finally:
        await redis_client.aclose()

    print("-" * 68)
    if runner.all_ok:
        print("exit 0 — all gates held. ◐")
        return 0
    print("exit 1 — one or more gates FAILED. ◐")
    return 1


def main() -> None:
    """Synchronous entrypoint: run the async demo and exit with its status."""
    sys.exit(asyncio.run(_amain()))


if __name__ == "__main__":
    main()
