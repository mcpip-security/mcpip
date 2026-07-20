"""
MCPIP V2 — Core: structured JSON logging (stdlib only, no new dependency).

    ◐ "Authorize every AI action before execution."

One JSON object per line on stderr:

    {"ts": "<ISO8601 UTC>", "level": "...", "logger": "...", "msg": "...",
     "correlation_id": "..."?}

``correlation_id`` is included iff the record carries one (via
``logger.info(..., extra={"correlation_id": cid})``). Configuration is applied
once at the top of the app lifespan; it takes over the root logger and
``uvicorn.error`` while deliberately leaving ``uvicorn.access`` untouched (its
format is an operator-facing contract, and access-log shaping belongs to the
edge). The existing ``print(...)`` boot banners are intentionally NOT rerouted —
they predate this module and the regression bar keeps them byte-identical.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """Format every record as a single-line JSON object (UTC timestamps)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, str] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        correlation_id = record.__dict__.get("correlation_id")
        if isinstance(correlation_id, str):
            payload["correlation_id"] = correlation_id
        if record.exc_info is not None and record.exc_info != (None, None, None):
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    """
    Install the JSON formatter on the root logger and ``uvicorn.error``.

    Idempotent: handlers are REPLACED, not appended, so re-entering the lifespan
    (e.g. multiple ``TestClient`` contexts in one process) never duplicates
    output lines. ``uvicorn.access`` keeps whatever uvicorn configured.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())

    uvicorn_error = logging.getLogger("uvicorn.error")
    uvicorn_error.handlers = [handler]
    uvicorn_error.propagate = False
