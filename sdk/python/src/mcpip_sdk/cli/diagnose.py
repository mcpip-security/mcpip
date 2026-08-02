"""
MCPIP SDK CLI — deny diagnosis (`mcpip why`).

The agent wire is opaque BY DESIGN: a denial carries a generic message and a
correlation id, nothing else. That is a security property, not a rough edge, and
nothing here softens it — this module reads the operator-side surfaces that were
already capability-gated (``/v1/admin/forensic/{id}`` under ``CAP_FORENSIC_READ``,
``/v1/admin/decisions`` under ``CAP_DIRECTORY_ADMIN``) and turns the machine token
they return into the operator's next action.

The gap this closes is a human one. A developer integrating for the first time
gets ``403 request denied by policy`` and a correlation id; the reason exists, is
already readable with the right credential, and is already rendered by the
console — but from a terminal the shortest path was to know that
``admin forensic get`` existed and then to interpret ``unknown_alias`` unaided.

Every string below maps a ``DenyReason`` to what happened and what to do about
it. When the reason cannot be read — no credential, capture disabled, outside the
decision horizon — that is reported as not-known, never guessed.
"""

from __future__ import annotations

from typing import Final, NamedTuple


class Remedy(NamedTuple):
    """What a deny reason means, and the operator's concrete next step."""

    means: str
    fix: str


# Keyed by the DenyReason wire value (interfaces.DenyReason). Kept as plain
# strings so the CLI never imports the gateway package — the SDK is standalone.
REMEDIES: Final[dict[str, Remedy]] = {
    # --- catalog ----------------------------------------------------------
    "unknown_alias": Remedy(
        "The alias does not resolve for this tenant.",
        "Check the spelling, and confirm the alias is in this tenant's catalog: "
        "`mcpip catalog`. Registering one is `mcpip admin skills register`.",
    ),
    "alias_disabled": Remedy(
        "The alias exists but an operator switched it off.",
        "Re-enable it with `mcpip admin skills enable <alias>`, or ask the operator "
        "who disabled it why — a kill-switched skill is usually deliberate.",
    ),
    # --- malformed --------------------------------------------------------
    "unknown_format": Remedy(
        "The declared source_format is not one MCPIP parses.",
        "Use one of: openai_tool_call, anthropic_tool_use, gemini_function_call, "
        "bedrock_tool_use, mcp_jsonrpc, raw_mcp, a2a_task. The envelope for each is "
        "in docs/start/API.md.",
    ),
    "unknown_vendor": Remedy(
        "The declared vendor is not in the pinned vendor registry.",
        "Declare a source_format directly instead, or check the registered vendor "
        "ids in bridge/connectors/registry.py.",
    ),
    "schema_violation": Remedy(
        "The tool_call envelope did not match the declared format's shape.",
        "Every level is extra=\"forbid\", so one stray or misnamed key is enough. "
        "Compare against the envelope for your format in docs/start/API.md — the A2A "
        "shape in particular uses `skill`, not `tool` or `name`.",
    ),
    "depth_exceeded": Remedy(
        "The arguments nest deeper than 8 levels.",
        "Flatten the payload. The bound is a DoS control and is not configurable.",
    ),
    "size_exceeded": Remedy(
        "The canonical arguments exceed 16 KiB.",
        "Send a reference instead of an inline blob — an id the target can resolve.",
    ),
    "illegal_character": Remedy(
        "The payload contained a control, bidi-override, or zero-width character.",
        "Strip them before sending. They are rejected because they let a payload read "
        "differently to a human approver than it does to the machine.",
    ),
    # --- identity ---------------------------------------------------------
    "jwt_invalid": Remedy(
        "The token failed verification — signature, algorithm, expiry, issuer, or audience.",
        "Confirm the gateway's MCPIP_JWT_ISSUER and MCPIP_JWT_AUDIENCE match what your "
        "IdP mints, and that the verification key is the right one. In sandbox, mint a "
        "fresh one with `mcpip sandbox dev-token`.",
    ),
    "jwt_claims_missing": Remedy(
        "The token verified but is missing a required claim.",
        "MCPIP requires exp, iat, nbf, iss, aud plus tenant_id, agent_id and role. "
        "Check what yours carries with `mcpip whoami`.",
    ),
    "identity_injection": Remedy(
        "The tool-call arguments contained an identity- or capability-shaped key.",
        "Remove it. Keys like tenant_id, agent_id, role, capabilities and entitlement "
        "are a hard deny in a payload, never a strip — identity comes only from the "
        "verified JWT, so passing it in arguments can never be the right call.",
    ),
    "sender_constraint_required": Remedy(
        "This alias requires a sender-constrained (proof-of-possession) token.",
        "A plain bearer is not enough for a restricted alias. Present a PoP-bound token "
        "so a stolen bearer cannot be replayed from elsewhere.",
    ),
    "principal_revoked": Remedy(
        "This agent id has been revoked by an operator.",
        "This is the kill switch and it is working. Reactivate deliberately with "
        "`mcpip admin principals reactivate <agent_id>` if the revocation is resolved.",
    ),
    "delegation_invalid": Remedy(
        "The delegated grant behind this token is expired, revoked, or over-broad.",
        "A child grant must stay within its parent: capabilities a subset, compartment "
        "the same or narrower, expiry sooner. Revocation cascades, so an ancestor being "
        "revoked invalidates this one too. Check `mcpip admin` delegation lineage.",
    ),
    # --- not permitted ----------------------------------------------------
    "cross_tenant": Remedy(
        "The alias belongs to a different tenant.",
        "Aliases are tenant-scoped by design. Use this tenant's catalog, or mint an "
        "identity for the tenant that owns the alias.",
    ),
    "compartment_denied": Remedy(
        "The alias is compartmented and this identity is not in that compartment.",
        "Need-to-know separation is working. Either mint an identity carrying the "
        "compartment claim, or have an officer issue a time-boxed delegated grant.",
    ),
    "capability_denied": Remedy(
        "The action requires a capability this token does not carry.",
        "Capabilities are UUIDs in the JWT `capabilities` claim — a role string never "
        "grants one. `mcpip sandbox capabilities` lists the well-known UUIDs.",
    ),
    "policy_denied": Remedy(
        "The tenant's deny-only policy overlay refused it — a velocity cap or an amount ceiling.",
        "Inspect the document with `mcpip admin policy get`. The overlay can only ever "
        "add a deny, so nothing else about the request was necessarily wrong.",
    ),
    "policy_gate_denied": Remedy(
        "A policy gate refused the request.",
        "Inspect the tenant's policy document with `mcpip admin policy get`.",
    ),
    # --- needs a human ----------------------------------------------------
    "pin_required": Remedy(
        "This alias is pin_required — it stages rather than executing.",
        "Not an error: resubmit the same payload with the one-time code and the "
        "challenge_id from the 202. `mcpip complete` finishes a staged call.",
    ),
    "pin_not_found": Remedy(
        "The challenge does not exist — already spent, or expired.",
        "A one-time lock is spent exactly once, so a replay lands here and that is "
        "correct. Stage a fresh challenge.",
    ),
    "pin_mismatch": Remedy(
        "The code did not match the challenge.",
        "Re-read it from the enrolled authenticator. The lock survives a wrong code, so "
        "a correct retry still works.",
    ),
    "payload_mismatch": Remedy(
        "The payload changed after the approval was issued.",
        "The code is bound to the exact canonical bytes that were approved, so one "
        "changed field means the approval no longer covers this action. Resubmit the "
        "payload exactly as staged, or stage a new challenge for the new payload.",
    ),
    "otp_delivery_failed": Remedy(
        "The gateway could not deliver the one-time code, so it refused to stage.",
        "Configure the authenticator channel: MCPIP_AUTHN_WEBHOOK_URL and "
        "MCPIP_AUTHN_WEBHOOK_SECRET_PATH, both or neither. Failing closed here is "
        "deliberate — staging a challenge nobody can answer would be worse.",
    ),
    # --- tripwire ---------------------------------------------------------
    "canary_tripped": Remedy(
        "A decoy alias was called. Nothing legitimate calls a canary.",
        "Treat as an enumeration attempt and investigate the agent. The caller is "
        "quarantined automatically; `mcpip admin` shows the roster.",
    ),
    "agent_quarantined": Remedy(
        "This agent is frozen after tripping a canary.",
        "Investigate before lifting it. The freeze is the response to enumeration, "
        "not a rate limit.",
    ),
    # --- infrastructure ---------------------------------------------------
    "lock_error": Remedy(
        "The payload lock store could not be reached.",
        "This is the gateway's problem, not the caller's. Check `mcpip ready` — a Redis "
        "outage denies everything, because MCPIP cannot authorize what it cannot audit.",
    ),
    "transport_error": Remedy(
        "The request was authorized, but the downstream target failed.",
        "Authorization succeeded; the target did not answer. Check the target and its "
        "credentials, not the policy.",
    ),
    "rate_limited": Remedy(
        "The caller exceeded a rate bound.",
        "Back off and retry. MCPIP never auto-retries on your behalf.",
    ),
    "internal": Remedy(
        "The gateway failed closed on an unexpected condition.",
        "Check `mcpip ready` and the gateway logs. A failure here denies rather than "
        "allowing, which is the intended direction.",
    ),
}

# The operator-facing grouping, mirroring interfaces.DENY_FAMILY.
FAMILY: Final[dict[str, str]] = {
    "canary_tripped": "tripwire",
    "agent_quarantined": "tripwire",
    "cross_tenant": "not permitted",
    "compartment_denied": "not permitted",
    "capability_denied": "not permitted",
    "policy_denied": "not permitted",
    "policy_gate_denied": "not permitted",
    "jwt_invalid": "identity",
    "jwt_claims_missing": "identity",
    "sender_constraint_required": "identity",
    "principal_revoked": "identity",
    "delegation_invalid": "identity",
    "identity_injection": "identity",
    "pin_required": "needs a human",
    "pin_not_found": "needs a human",
    "pin_mismatch": "needs a human",
    "payload_mismatch": "needs a human",
    "otp_delivery_failed": "needs a human",
    "unknown_format": "malformed",
    "unknown_vendor": "malformed",
    "schema_violation": "malformed",
    "depth_exceeded": "malformed",
    "size_exceeded": "malformed",
    "illegal_character": "malformed",
    "unknown_alias": "catalog",
    "alias_disabled": "catalog",
    "lock_error": "infrastructure",
    "transport_error": "infrastructure",
    "rate_limited": "infrastructure",
    "internal": "infrastructure",
}


def explain(reason: str | None) -> Remedy | None:
    """The remedy for a deny reason, or None when the reason is unknown to this CLI."""
    if not reason:
        return None
    return REMEDIES.get(reason)


def family_of(reason: str | None) -> str | None:
    """The operator-facing family of a deny reason, or None when unrecognized."""
    if not reason:
        return None
    return FAMILY.get(reason)
