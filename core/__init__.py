"""
MCPIP V2 — Core package (API boundary primitives).

    ◐  MCPIP — The Authorization Layer for Autonomous AI
       "Authorize every AI action before execution."
       AI Reasons. MCPIP Authorizes. Systems Execute.

This package holds the FastAPI orchestration layer's *boundary* concerns that are
deliberately kept out of the engine:

  * ``core.config``   — typed, env-driven ``Settings`` (pydantic-settings).
  * ``core.security`` — THIN re-exports of the engine's crypto/primitives plus the
    single opaque-deny control object (``GatewayDeny``) and the one exception →
    ``DenyReason`` mapper (``map_engine_exception``) that every layer shares, so
    the mapping has exactly one source of truth.

Nothing here reimplements engine crypto — it only re-exports and orchestrates.
"""

from __future__ import annotations

from core.config import Settings, get_settings
from core.security import (
    GatewayDeny,
    map_engine_exception,
    new_correlation_id,
)

__all__ = [
    "Settings",
    "get_settings",
    "GatewayDeny",
    "map_engine_exception",
    "new_correlation_id",
]
