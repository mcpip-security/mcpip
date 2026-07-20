"""
MCPIP V2 — App package (the FastAPI orchestration layer).

    ◐  MCPIP — The Authorization Layer for Autonomous AI
       "Authorize every AI action before execution."
       AI Reasons. MCPIP Authorizes. Systems Execute.

The ASGI application lives in ``app.main:app``. This package initializer is kept
deliberately import-free so ``import app`` does not eagerly build the composition
root (that happens when ``app.main`` is imported by uvicorn or the tests).
"""

from __future__ import annotations

__all__: list[str] = []
