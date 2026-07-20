"""
MCPIP V2 — Connectors package: pure format parsers + the pinned vendor registry.

    ◐ "Connectors are pure parsers — no SDK, no network, no keys, ever."

Re-exports the connector public API. Import order is load-bearing: ``base`` and
``formats`` carry no package-internal dependencies; ``registry`` imports the nine
vendor binding modules and runs its fail-closed import-time self-checks (hash pin,
duplicate/coverage/parser assertions), so merely importing this package proves the
connector table is consistent.
"""

from __future__ import annotations

from bridge.connectors.base import Candidate, FormatParser
from bridge.connectors.registry import (
    REGISTRY_VERSION,
    Vendor,
    parser_for,
    resolve_vendor,
)

__all__ = [
    "Candidate",
    "FormatParser",
    "Vendor",
    "REGISTRY_VERSION",
    "resolve_vendor",
    "parser_for",
]
