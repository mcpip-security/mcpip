"""
MCPIP V2 — Models: the FastAPI request/response wire contract.

    ◐ "Zero topology leakage — agents name aliases; real systems stay invisible."

Every ingress model is strict (``extra="forbid", strict=True``) so a malformed
envelope is rejected at the door with a 422 before any engine work runs. The one
deliberate exception is ``tool_call``: it is a free-form ``dict[str, Any]`` because
the engine's Bridge (``bridge.parse``) is the authoritative deep validator for
provider envelopes. Re-validating the provider shape here would either duplicate that
logic (drift risk) or weaken it — so we pass the raw envelope straight through and let
the Bridge's strict per-provider models + recursive argument walker do the real work.

Response models are the ONLY things that cross the agent boundary, so they are
audited for leakage:

  * ``ExecutionReceipt.executed_target_class`` is the coarse transport *class*
    (``cloud_rest`` / ``legacy_mainframe``) — NEVER ``entry.target`` (the real dotted
    topology). Invariant #4 (zero topology leakage) is enforced structurally here.
  * ``ErrorResponse`` carries ONLY the generic message + correlation id. No reason,
    no field name, no path — those exist solely in the WORM log (invariant #5).
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Re-exported for callers/tests that build API payloads against engine enums/types.
from interfaces import RiskTier, SourceFormat, SwarmTrace, reject_unsafe_string
from interfaces import NormalizedIntent  # noqa: F401 — re-exported convenience type.

# Strict, closed ingress config reused across request models: unknown fields are a
# hard 422, and strict mode forbids lax coercions (e.g. "1" -> 1) at the boundary.
_STRICT = ConfigDict(extra="forbid", strict=True)


class AuthorizeRequest(BaseModel):
    """
    The ``POST /v1/authorize`` request envelope.

    ``jwt`` is optional in the body because identity may instead arrive via the
    ``Authorization: Bearer`` header; ``trace`` is optional because the gateway
    synthesizes a single-hop trace from the VERIFIED agent_id when the caller omits
    one (never from anything attacker-controlled). ``pin`` + ``challenge_id`` are the
    step-up completion pair and must always be supplied together.
    """

    model_config = _STRICT

    # Declared source format. EXACTLY ONE of source_format / vendor must be supplied
    # (never both, never neither — fail-closed 422). The format is DECLARED, never
    # sniffed from the payload bytes.
    source_format: Optional[SourceFormat] = None
    # Declared vendor id (registry-resolved to a format in-pipeline). Free string,
    # NOT the Vendor enum, so an unknown vendor produces a WORM-audited
    # UNKNOWN_VENDOR deny (opaque 403) instead of a silent 422.
    vendor: Optional[str] = Field(default=None, max_length=64)
    # Raw provider envelope — deep-validated by bridge.parse, NOT here (see docstring).
    tool_call: dict[str, Any]
    # Identity; when None it is taken from the Authorization: Bearer header.
    jwt: Optional[str] = None
    # Provenance; when None a single-hop trace is synthesized from the verified id.
    trace: Optional[SwarmTrace] = None
    # 6-digit one-time code at step-up completion.
    pin: Optional[str] = None
    # The lock_id returned by the 202 staging response.
    challenge_id: Optional[str] = None

    @field_validator("source_format", mode="before")
    @classmethod
    def _coerce_source_format(cls, v: Any) -> Any:
        """
        Accept the enum's JSON *string* form under strict mode.

        The envelope is strict (``strict=True``) so nothing else is silently coerced,
        but a JSON body can only deliver ``source_format`` as a string (the §2.7 wire
        example sends ``"openai_tool_call"``). Strict enum validation would otherwise
        demand an actual ``SourceFormat`` instance, which JSON cannot express. We map
        a recognized value string to its member and leave everything else untouched so
        an unknown/mistyped value still fails validation (422) fail-closed.
        """
        if isinstance(v, str):
            return SourceFormat(v)
        return v

    @field_validator("vendor", mode="after")
    @classmethod
    def _clean_vendor(cls, v: Optional[str]) -> Optional[str]:
        # Scrub control/bidi/zero-width from the declared vendor id when present.
        return None if v is None else reject_unsafe_string(v, "vendor")

    @model_validator(mode="after")
    def _exactly_one_dialect_declaration(self) -> "AuthorizeRequest":
        """
        Format is DECLARED, not guessed: the envelope must carry exactly one of
        ``source_format`` / ``vendor``. Absent both, or both, is a 422 fail-closed.
        """
        if (self.source_format is None) == (self.vendor is None):
            raise ValueError("exactly one of source_format / vendor must be supplied")
        return self

    @model_validator(mode="after")
    def _pin_and_challenge_paired(self) -> "AuthorizeRequest":
        """
        A PIN without its challenge (or vice-versa) is a malformed step-up: reject at
        the envelope so the pipeline never has to reason about a half-supplied lock.
        """
        if (self.pin is None) != (self.challenge_id is None):
            raise ValueError("pin and challenge_id must be supplied together")
        return self


class StagedChallenge(BaseModel):
    """
    HTTP 202 — a high-risk alias was recognized but no PIN was supplied yet.

    Returns the ``challenge_id`` (the payload-bound lock id) and a human-facing
    instruction to approve in the enrolled authenticator. The one-time code itself is
    delivered ONLY out-of-band (the sandbox authenticator endpoint stands in for the
    enrolled device) and NEVER appears in this response.
    """

    model_config = ConfigDict(extra="forbid")

    correlation_id: str
    action_required: str
    challenge_id: str
    # Always "pin_required" for a staged action, but typed to the engine enum.
    risk_tier: RiskTier


class ExecutionReceipt(BaseModel):
    """
    HTTP 200 — the action was authorized and dispatched.

    ``executed_target_class`` is intentionally the transport CLASS, not the real
    target: topology never crosses the boundary (invariant #4). ``worm_sequence`` is
    the audit anchor the operator can quote to locate the decision record.
    """

    model_config = ConfigDict(extra="forbid")

    correlation_id: str
    decision: str  # "allow"
    status: str  # "committed"
    transaction_ref: str  # "txn_" + uuid4().hex
    # "cloud_rest" | "legacy_mainframe" | "cloud_iam" — coarse transport class only.
    executed_target_class: str
    worm_sequence: int
    # Populated ONLY for the ``cloud_iam`` transport: the short-lived, scoped cloud
    # credential vended for THIS authorized call (the deliverable — the agent uses it
    # directly, then it expires). Absent for every other transport. NEVER persisted to
    # WORM (dispatch runs after the ALLOW record; the secret never enters the audit ctx).
    vended_credential: Optional[dict[str, Any]] = None


class CatalogItem(BaseModel):
    """
    One agent-visible skill in ``GET /v1/catalog`` — metadata ONLY, never the target.

    Separation of teams between MCPs and AI: the catalog lists only aliases the caller
    is entitled to see (un-compartmented, own-compartment, or granted). It carries the
    coarse ``transport_class`` and ``classification`` for operator display, never the
    real dotted topology.
    """

    model_config = ConfigDict(extra="forbid")

    alias: str
    risk_tier: RiskTier
    transport_class: str          # coarse class, NOT target.
    classification: str
    compartment: Optional[str] = None   # the caller's own/granted compartment uuid.
    # Advisory display access mode ("read"/"write"). BENIGN: derived from the already-
    # projected risk data (an explicit annotation or the risk-tier fallback) — never a
    # target hint, never an enforcement input. The service label deliberately stays OFF
    # this agent-facing shape (operator surfaces only).
    access: Optional[str] = None


class ErrorResponse(BaseModel):
    """
    HTTP 4xx/5xx — the opaque, fail-closed error envelope.

    ``error`` is the generic ``AGENT_FACING_DENY_MESSAGE`` for policy denials (or a
    terse "invalid request" for malformed envelopes); ``correlation_id`` is the only
    handle the agent may quote to a human operator. Nothing else is ever included.
    """

    model_config = ConfigDict(extra="forbid")

    error: str
    correlation_id: str


# ---------------------------------------------------------------------------
# Deny-only policy overlay — the ``/v1/admin/policy`` wire contract (SDK/console
# parity). These describe the strict document shape; the authoritative validator is
# ``services.policy_engine.PolicyDocStore.validate`` (the endpoint validates via the
# store and denies opaquely). The document holds ONLY velocity/amount/argument rules —
# never an
# alias→target mapping or identity, so it can never repoint a skill or mint a principal.
# ---------------------------------------------------------------------------


class PolicyRuleModel(BaseModel):
    """
    One deny-only policy rule on the wire. A rule MATCHES a request by ``scope`` +
    ``scope_value`` (an alias name or coarse transport class) and, per ``kind``, carries
    the velocity fields (``max_actions`` + ``window_seconds``), the amount fields
    (``amount_field`` + ``max_amount`` — a decimal STRING, no float drift), or the
    argument fields (``argument_field`` plus ``allowed_values`` and/or
    ``forbidden_substrings`` — the only kind that can bound an OPEN-ENDED alias whose
    payload is free text rather than a number).

    This model is the WIRE shape only; the authoritative cross-field validator is
    ``services.policy_engine.PolicyRule``. Both must know every field: anything absent
    here is rejected by ``extra="forbid"`` before the real validator ever sees it, which
    is how a new rule kind silently becomes unreachable through the API.
    """

    model_config = _STRICT

    kind: str  # "velocity" | "amount" | "argument"
    scope: str  # "alias" | "transport_class"
    scope_value: str = Field(min_length=1, max_length=256)
    max_actions: Optional[int] = Field(default=None, ge=1)
    window_seconds: Optional[int] = Field(default=None, ge=1, le=86400)
    amount_field: Optional[str] = Field(default=None, min_length=1, max_length=256)
    max_amount: Optional[str] = Field(default=None, min_length=1, max_length=64)
    argument_field: Optional[str] = Field(default=None, min_length=1, max_length=256)
    allowed_values: Optional[list[str]] = Field(default=None, max_length=64)
    forbidden_substrings: Optional[list[str]] = Field(default=None, max_length=64)


class PolicyDocumentRequest(BaseModel):
    """``PUT /v1/admin/policy`` body — a schema tag + a bounded velocity/amount rule list."""

    model_config = _STRICT

    schema_: str = Field(alias="schema")
    rules: list[PolicyRuleModel] = Field(default_factory=list, max_length=64)


class PolicyDocumentResponse(BaseModel):
    """``GET /v1/admin/policy`` body — the stored document (or an honest empty rule list)."""

    model_config = ConfigDict(extra="forbid")

    policy: PolicyDocumentRequest


# ---------------------------------------------------------------------------
# OpenID-AuthZEN / COAZ decision surface — the ``POST /v1/authz/decision`` wire
# contract (Authorization API 1.0 shape). MCPIP answers as a PDP: given a
# subject / action / resource (+ coarse context), return ``{"decision": bool}``
# plus OPTIONAL standards-shaped ``obligations`` — DECISION-ONLY (no execute, no
# vend, no PIN stage/consume, no grant mutation).
#
# SARC → MCPIP mapping (see ``app.main._evaluate_authz_decision``):
#   * ``resource.id``        → the opaque agent-facing alias.
#   * ``action.properties``  → the tool-call arguments (deep-validated by the SAME
#                              bridge argument walker as every other ingress; an
#                              identity-shaped key is a HARD DENY, not a strip).
#   * ``subject``            → ADVISORY / echo ONLY. Identity is derived EXCLUSIVELY
#                              from the verified JWT (Authorization header); the
#                              AuthZEN subject is NEVER an identity input, so
#                              identity injection via ``subject`` is structurally
#                              impossible. It is accepted (bounded) but never read.
# ---------------------------------------------------------------------------


class AuthzenResource(BaseModel):
    """
    The AuthZEN ``resource`` entity. ``id`` maps to MCPIP's opaque alias.

    ``type`` is an OPTIONAL advisory label (echoed by the caller, never authz input);
    ``id`` is the alias string (bounded, non-empty). ``properties`` is a free-form
    advisory bag — it is NEVER consulted for identity or entitlement (arguments arrive
    via ``action.properties``).
    """

    model_config = _STRICT

    type: Optional[str] = Field(default=None, max_length=256)
    id: str = Field(min_length=1, max_length=256)
    properties: Optional[dict[str, Any]] = None


class AuthzenAction(BaseModel):
    """
    The AuthZEN ``action`` entity. ``properties`` carries the tool-call arguments.

    ``name`` is an OPTIONAL advisory verb label. ``properties`` (when present) is the
    argument object that maps onto the MCP ``params.arguments`` — it flows through the
    SAME bridge deep-validator (depth/size/char caps + identity-injection hard-deny) as
    a real call, so a hostile argument shape denies exactly as it would on execute.
    """

    model_config = _STRICT

    name: Optional[str] = Field(default=None, max_length=256)
    properties: Optional[dict[str, Any]] = None


class AuthzenDecisionRequest(BaseModel):
    """
    ``POST /v1/authz/decision`` body — the AuthZEN Authorization API 1.0 request.

    ``subject`` is ADVISORY/echo ONLY and is NEVER consulted for identity (identity
    comes solely from the verified JWT), so a caller cannot inject identity through it.
    ``resource`` maps to the opaque alias; ``action`` to the arguments; ``context`` is
    coarse advisory context (accepted, not an authz input in v1).
    """

    model_config = _STRICT

    subject: dict[str, Any]
    resource: AuthzenResource
    action: AuthzenAction
    context: Optional[dict[str, Any]] = None


class AuthzenDecisionResponse(BaseModel):
    """
    ``POST /v1/authz/decision`` response — the AuthZEN decision + optional obligations.

    A permit is ``{"decision": true}`` optionally carrying standards-shaped
    ``obligations`` (e.g. ``{"id": "mcpip.step_up.pin"}``). A deny is the bare, opaque
    ``{"decision": false}`` — NO reason/target/topology (same discipline as
    ``MCPIPDenied``). ``obligations`` is serialized with ``exclude_none`` so an empty
    obligation list is OMITTED, never an empty array.
    """

    model_config = ConfigDict(extra="forbid")

    decision: bool
    obligations: Optional[list[dict[str, Any]]] = None


__all__ = [
    "AuthorizeRequest",
    "StagedChallenge",
    "ExecutionReceipt",
    "CatalogItem",
    "ErrorResponse",
    "PolicyRuleModel",
    "PolicyDocumentRequest",
    "PolicyDocumentResponse",
    "AuthzenResource",
    "AuthzenAction",
    "AuthzenDecisionRequest",
    "AuthzenDecisionResponse",
    "NormalizedIntent",
    "SwarmTrace",
    "SourceFormat",
    "RiskTier",
]
