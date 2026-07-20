"""
MCPIP V2 — Bridge: narrow exception types the gateway maps to DenyReason.

    ◐ "Fail-closed, opaque errors — the agent sees only a correlation id."

These live in their own leaf module (no imports beyond the stdlib) so that both
``bridge.intent_parser`` and ``bridge.connectors.formats`` can raise them without
an import cycle. ``bridge.intent_parser`` re-exports every one of them, so the
Rust extension's ``PyModule::import(py, "bridge.intent_parser")`` attribute lookup
and every existing ``from bridge import ...`` import path keep resolving the SAME
class objects.
"""

from __future__ import annotations


class UnknownFormat(Exception):
    """Raised when the raw call does not match the declared source format."""


class IdentityInjection(Exception):
    """
    Raised when an identity-shaped key appears anywhere inside ``arguments``.

    Identity is sovereign (JWT-only). An agent that smuggles tenant_id/role/etc.
    into a tool-call payload is HARD-DENIED — never stripped or ignored.
    """


class DepthExceeded(Exception):
    """Argument nesting deeper than MAX_ARG_DEPTH."""


class SizeExceeded(Exception):
    """Too many keys/elements, or canonical payload over MAX_CANONICAL_BYTES."""


class UnknownVendor(UnknownFormat):
    """Raised when a declared vendor string has no registry binding.

    Subclasses UnknownFormat so any funnel that predates the registry still
    fail-closes to UNKNOWN_FORMAT; map_engine_exception tests it FIRST to
    yield the distinct UNKNOWN_VENDOR reason.
    """


__all__ = [
    "UnknownFormat",
    "IdentityInjection",
    "DepthExceeded",
    "SizeExceeded",
    "UnknownVendor",
]
