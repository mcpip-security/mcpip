"""
MCPIP — the executable proof must not destroy a running gateway's audit evidence.

`python main.py` resets the WORM chain, grants, pin locks, step-ups and policies
before it runs, because it needs a clean slate to assert against. Two defaults
made that dangerous:

* It shared Redis database 0 with the sandbox gateway and the quickstart, so the
  documented smoke test wiped whatever chain was already there.
* It shared `./mcpip_worm.jsonl.anchor` with the gateway. The anchor is the
  out-of-tamper-domain low-watermark, so each run advanced the gateway's witness
  past its own chain and the gateway then reported itself rolled back — a tamper
  alarm produced by nothing but a shared filename.

The operator runbook recommended the command inside a section headed "read-only,
production-safe".

The proof now owns database 15 and its own ledger path, and refuses to wipe a
populated database it was explicitly pointed at without `--reset`.
"""

from __future__ import annotations

import os
import re
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

import main as proof  # noqa: E402


def test_proof_does_not_default_to_the_gateway_database() -> None:
    """Database 0 belongs to the gateway; the proof resets whatever it is given."""
    assert proof.DEFAULT_REDIS_URL.endswith("/15"), proof.DEFAULT_REDIS_URL
    assert not proof.DEFAULT_REDIS_URL.endswith("/0")


def test_proof_does_not_default_to_the_gateway_ledger_path() -> None:
    """The anchor derives from the ledger path, so sharing it shares the witness."""
    src = open(os.path.join(_REPO_ROOT, "main.py"), encoding="utf-8").read()
    match = re.search(r'os\.environ\.get\("MCPIP_WORM_PATH",\s*"([^"]+)"\)', src)
    assert match, "main.py no longer reads MCPIP_WORM_PATH with a default"
    default_path = match.group(1)
    assert default_path != "./mcpip_worm.jsonl", (
        "the proof shares its ledger — and therefore its anchor — with the gateway"
    )

    # And the gateway's own default must still be the one the docs describe.
    from core.config import Settings

    gateway_default = Settings().worm_path
    assert default_path != gateway_default, (
        f"proof and gateway both default to {default_path}"
    )


def test_reset_requires_consent_only_for_an_explicit_override() -> None:
    """Wiping the proof's OWN database is the point; wiping someone else's is not."""
    src = open(os.path.join(_REPO_ROOT, "main.py"), encoding="utf-8").read()
    guard = re.search(
        r"if redis_url != DEFAULT_REDIS_URL and not _reset_permitted", src
    )
    assert guard, (
        "the reset guard no longer distinguishes the proof's own database from an "
        "operator-supplied one — it must, or the proof stops being re-runnable"
    )


def test_reset_consent_is_an_explicit_flag() -> None:
    assert proof._reset_permitted(None) is False  # type: ignore[arg-type]
    original = list(sys.argv)
    try:
        sys.argv = ["main.py", "--reset"]
        assert proof._reset_permitted(None) is True  # type: ignore[arg-type]
    finally:
        sys.argv = original


def test_populated_ledger_detection_fails_safe() -> None:
    """An unreadable Redis must read as populated — never as safe to wipe."""
    import asyncio

    class _Broken:
        async def exists(self, *_: object) -> int:
            raise RuntimeError("redis is unreachable")

        def scan_iter(self, **_: object) -> object:
            raise RuntimeError("redis is unreachable")

    assert asyncio.run(proof._ledger_is_populated(_Broken())) is True  # type: ignore[arg-type]
