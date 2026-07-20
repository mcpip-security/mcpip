"""
MCPIP V2 — Core: the opaque-deny boundary control + engine-crypto re-exports.

    ◐ "Fail-closed, opaque errors — the agent sees only a correlation id."

This module is deliberately THIN. It does two things and nothing else:

  1. **Re-export** the engine's crypto/primitive surface (``canonical_json``,
     ``sha256_hex``, ``constant_time_equals``, ``lock_payload_hash``) and the two
     boundary symbols (``MCPIPDenied``, ``AGENT_FACING_DENY_MESSAGE``) so every API
     layer imports them from ONE place and can never accidentally reimplement crypto.

  2. Provide the gateway's internal deny carrier (``GatewayDeny``) and the single
     exception → ``DenyReason`` mapper (``map_engine_exception``). The demo gateway
     (``main.py`` L267–312) maps engine exceptions to deny reasons *inline* across
     several ``try/except`` stages; the FastAPI pipeline instead funnels every
     exception through one mapper so the mapping has exactly one authoritative
     definition shared by all builders.

``new_correlation_id`` is the uuid4-hex generator every request/deny quotes.
"""

from __future__ import annotations

import uuid

# --- Engine crypto / boundary primitives — re-exported, never reimplemented. ----
from interfaces import (
    AGENT_FACING_DENY_MESSAGE,
    DenyReason,
    MCPIPDenied,
    canonical_json,
    constant_time_equals,
    sha256_hex,
)
from auth import LockError, TokenClaimsMissing, TokenError, lock_payload_hash
from bridge import DepthExceeded, IdentityInjection, SizeExceeded, UnknownFormat
from bridge.errors import UnknownVendor
from bridge.intent_parser import ValidationError
from obfuscator import CompartmentDenied, CrossTenant, UnknownAlias


def new_correlation_id() -> str:
    """
    Mint the opaque correlation id carried on every response and every deny.

    uuid4 hex (no dashes) — a 128-bit random token with no embedded structure, so it
    leaks nothing about tenant, timing, or sequence. It is the ONLY internal handle
    the agent ever receives; the concrete reason lives solely in the WORM log.
    """
    return uuid.uuid4().hex


class GatewayDeny(Exception):
    """
    Internal-only carrier of a concrete ``DenyReason`` plus operator-facing detail.

    Raised anywhere in the pipeline, funneled to WORM (where the concrete reason and
    detail are recorded), then converted to an opaque ``MCPIPDenied`` at the agent
    boundary. This type NEVER crosses that boundary — it is the private twin of the
    demo's ``_Deny``.
    """

    def __init__(self, reason: DenyReason, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}")


def map_engine_exception(exc: Exception) -> GatewayDeny:
    """
    Map any exception raised inside the pipeline to a concrete ``GatewayDeny``.

    Single source of truth — mirrors ``MCPIPGateway``'s per-stage mapping
    (``main.py`` L271–303) but collapsed into one dispatch so every builder maps
    identically. Order matters: subclasses are tested before their bases
    (``TokenClaimsMissing`` before ``TokenError``), and ``GatewayDeny`` short-circuits
    so an already-classified deny is never re-wrapped or downgraded to INTERNAL.

    Anything unrecognized becomes ``DenyReason.INTERNAL`` carrying ONLY the exception
    class name (never its message/traceback), preserving the fail-closed, no-leak
    contract for genuinely unexpected failures.
    """
    # Already classified — pass through untouched (idempotent).
    if isinstance(exc, GatewayDeny):
        return exc

    # --- Auth / JWT. ------------------------------------------------------------
    if isinstance(exc, TokenClaimsMissing):
        return GatewayDeny(DenyReason.JWT_CLAIMS_MISSING, str(exc))
    if isinstance(exc, TokenError):
        return GatewayDeny(DenyReason.JWT_INVALID, str(exc))

    # --- Bridge (narrow types raised by the argument walker). -------------------
    if isinstance(exc, IdentityInjection):
        return GatewayDeny(DenyReason.IDENTITY_INJECTION, str(exc))
    if isinstance(exc, DepthExceeded):
        return GatewayDeny(DenyReason.DEPTH_EXCEEDED, str(exc))
    if isinstance(exc, SizeExceeded):
        return GatewayDeny(DenyReason.SIZE_EXCEEDED, str(exc))
    # Subclass-before-base ordering (same discipline as TokenClaimsMissing before
    # TokenError): UnknownVendor subclasses UnknownFormat so a pre-registry funnel
    # still fail-closes, but here it yields the distinct UNKNOWN_VENDOR reason.
    if isinstance(exc, UnknownVendor):
        return GatewayDeny(DenyReason.UNKNOWN_VENDOR, str(exc))
    if isinstance(exc, UnknownFormat):
        return GatewayDeny(DenyReason.UNKNOWN_FORMAT, str(exc))

    # --- Bridge (strict-model rejection or a wrapped reject_unsafe_string). ------
    if isinstance(exc, ValidationError):
        blob = str(exc).casefold()
        if "illegal character" in blob:
            return GatewayDeny(DenyReason.ILLEGAL_CHARACTER, str(exc))
        if "max_string_len" in blob:
            return GatewayDeny(DenyReason.SIZE_EXCEEDED, str(exc))
        return GatewayDeny(DenyReason.SCHEMA_VIOLATION, str(exc))

    # --- Obfuscator (fail-closed alias resolution + compartment separation). ----
    if isinstance(exc, CompartmentDenied):
        return GatewayDeny(DenyReason.COMPARTMENT_DENIED, str(exc))
    if isinstance(exc, CrossTenant):
        return GatewayDeny(DenyReason.CROSS_TENANT, str(exc))
    if isinstance(exc, UnknownAlias):
        return GatewayDeny(DenyReason.UNKNOWN_ALIAS, str(exc))

    # --- Payload lock transport. ------------------------------------------------
    if isinstance(exc, LockError):
        return GatewayDeny(DenyReason.LOCK_ERROR, str(exc))

    # --- Genuinely unexpected — class name only, never the message/traceback. ---
    return GatewayDeny(DenyReason.INTERNAL, type(exc).__name__)


__all__ = [
    # Correlation + deny control.
    "new_correlation_id",
    "GatewayDeny",
    "map_engine_exception",
    # Re-exported engine primitives.
    "canonical_json",
    "sha256_hex",
    "constant_time_equals",
    "lock_payload_hash",
    "MCPIPDenied",
    "DenyReason",
    "AGENT_FACING_DENY_MESSAGE",
]
