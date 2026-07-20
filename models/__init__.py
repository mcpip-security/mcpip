"""
MCPIP V2 — Models package (API request/response schemas).

    ◐ "Authorize every AI action before execution."

The HTTP wire contract for the FastAPI gateway. These models describe ONLY the API
envelope; the deep, security-critical validation of the provider tool-call lives in
the engine's Bridge (``bridge.parse``), which stays the single authoritative deep
validator. Re-exports the engine ingress types the API surfaces for convenience.
"""

from __future__ import annotations

from models.schemas import (
    AuthorizeRequest,
    CatalogItem,
    ErrorResponse,
    ExecutionReceipt,
    NormalizedIntent,
    RiskTier,
    SourceFormat,
    StagedChallenge,
    SwarmTrace,
)

__all__ = [
    "AuthorizeRequest",
    "StagedChallenge",
    "ExecutionReceipt",
    "CatalogItem",
    "ErrorResponse",
    "NormalizedIntent",
    "SwarmTrace",
    "SourceFormat",
    "RiskTier",
]
