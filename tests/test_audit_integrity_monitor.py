"""
MCPIP — off-hot-path audit-integrity monitor (SOC2_READINESS.md #8, CC7.3/CC4.1).

    ◐ "verify_chain shouldn't only run when a human asks."

``_run_audit_integrity_check`` is the daemon's loop body: a fresh ``verify_chain`` whose
outcome becomes a continuous, alertable signal — ``mcpip_audit_integrity_total{event}``
plus a CRITICAL ``mcpip.audit`` log naming the first bad epoch on a non-intact chain. It
is swallow-only: a verify error is a counted ``verify_error``, never a raise into serving.

Pure-function tests over a fake WormLogger (no daemon loop, no Redis). Sandbox is set
before importing ``app.main`` so the module's composition root does not trip prod refusals.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/5")

import pytest
from prometheus_client import REGISTRY

from app.main import _run_audit_integrity_check


class _FakeWorm:
    def __init__(self, *, result: Optional[tuple[bool, Optional[int]]] = None, raises: bool = False):
        self._result = result
        self._raises = raises

    async def verify_chain(self, *args: Any, **kwargs: Any) -> tuple[bool, Optional[int]]:
        if self._raises:
            raise RuntimeError("redis unavailable")
        assert self._result is not None
        return self._result


def _count(event: str) -> float:
    return REGISTRY.get_sample_value("mcpip_audit_integrity_total", {"event": event}) or 0.0


def test_intact_chain_records_verified() -> None:
    before = _count("verified")
    asyncio.run(_run_audit_integrity_check(_FakeWorm(result=(True, None))))  # type: ignore[arg-type]
    assert _count("verified") == before + 1


def test_tampered_chain_records_and_logs_critical(caplog: pytest.LogCaptureFixture) -> None:
    before = _count("tamper_detected")
    with caplog.at_level(logging.CRITICAL, logger="mcpip.audit"):
        asyncio.run(_run_audit_integrity_check(_FakeWorm(result=(False, 7))))  # type: ignore[arg-type]
    assert _count("tamper_detected") == before + 1
    assert any(
        "intact=false" in r.getMessage() and "first_bad_epoch=7" in r.getMessage()
        for r in caplog.records
    ), "a CRITICAL mcpip.audit log naming the first bad epoch must be emitted"


def test_verify_error_is_swallowed_and_counted() -> None:
    before = _count("verify_error")
    # Must NOT raise — the monitor is swallow-only so it can never disturb serving.
    asyncio.run(_run_audit_integrity_check(_FakeWorm(raises=True)))  # type: ignore[arg-type]
    assert _count("verify_error") == before + 1
