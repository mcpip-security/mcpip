"""
MCPIP — opt-in WORM synchronous-replication quorum (SOC2_READINESS.md #31, A1.2).

    ◐ "Write-before-execute, extended across a replica — or the request denies."

With ``wait_replicas`` > 0, every emitted audit event must additionally be acknowledged
by that many Redis replicas (``WAIT``) before the receipt is returned; a quorum miss is a
fail-closed raise, so an authorize can never proceed on an audit record a failover could
lose. 0 (the default) issues no WAIT at all — byte-identical single-node behavior.

REAL end-to-end tests against the dev Redis (:63790), which has NO replicas — so a
required quorum of 1 genuinely cannot be met and must fail closed. No mocks of the code
under test. Namespaced to db /13 to stay clear of the API suite's state.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/5")

import pytest
import redis.asyncio as aioredis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.worm_logger import WormLogger

_QUORUM_REDIS_URL = "redis://localhost:63790/13"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


async def _fresh_logger(**kwargs: Any) -> tuple[WormLogger, Any]:
    client: Any = aioredis.from_url(_QUORUM_REDIS_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    await client.flushdb()
    logger = WormLogger(
        client,
        Ed25519PrivateKey.generate(),
        path=os.path.join(os.path.dirname(__file__), ".mcpip_test_quorum_worm.jsonl"),
        **kwargs,
    )
    return logger, client


def test_default_zero_emits_without_wait() -> None:
    """wait_replicas=0 (the default) — emit succeeds exactly as today, no WAIT issued."""
    async def scenario() -> None:
        logger, client = await _fresh_logger()
        try:
            receipt = await logger.emit({"decision": "allow", "tenant_id": "t"})
            assert receipt.event_id and receipt.stream_id and receipt.leaf_hash
        finally:
            await client.aclose()

    _run(scenario())


def test_unmet_quorum_fails_closed() -> None:
    """A required quorum of 1 against a replica-less Redis fails CLOSED: the emit raises
    (the receipt is never returned), so an authorize could never proceed on it."""
    async def scenario() -> None:
        logger, client = await _fresh_logger(wait_replicas=1, wait_timeout_ms=100)
        try:
            with pytest.raises(RuntimeError, match="replica quorum not met"):
                await logger.emit({"decision": "allow", "tenant_id": "t"})
        finally:
            await client.aclose()

    _run(scenario())


def test_constructor_validates_quorum_params() -> None:
    client: Any = object()
    with pytest.raises(ValueError, match="wait_replicas"):
        WormLogger(client, Ed25519PrivateKey.generate(), wait_replicas=-1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="wait_timeout_ms"):
        WormLogger(client, Ed25519PrivateKey.generate(), wait_timeout_ms=0)  # type: ignore[arg-type]
