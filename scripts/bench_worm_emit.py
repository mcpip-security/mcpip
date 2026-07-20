#!/usr/bin/env python3
"""
MCPIP — REAL WORM emit throughput micro-benchmark (durable-before-authorize path).

    ◐ Audit: "Every authorized decision's event is fsync-durable before any effect —
              so the emit path's ceiling IS the gateway's authorize-throughput ceiling."

This measures the ACTUAL sustained ``WormLogger.emit`` rate and per-emit latency against
the running sandbox Redis (default ``redis://localhost:63790``), because ``emit`` is the
durable-before-execute anchor of the pipeline: an ALLOW is only acted on after ``emit``
returns, and (in production) ``emit`` returns only after its atomic INCR+XADD Lua script
is fsync-durable on an ``appendfsync always`` AOF. So the fsync-bound emit rate is a hard
ceiling on authorize throughput.

It measures TWO durability postures and reports the numbers it really saw for each:

  (a) ``appendfsync always`` + ``appendonly yes`` — the PRODUCTION posture
      (``assert_persistence_posture`` refuses to boot without it). Every emit forces one
      fsync, so this is the honest write-before-execute ceiling. Measured ONLY if this
      Redis lets the benchmark set that config; if it cannot, it says so and reports only
      what it could measure — it NEVER fabricates the durable number.
  (b) the AS-FOUND sandbox posture (typically ``appendfsync everysec``) — durability is
      relaxed (a crash can lose ~1s of writes), so this is NOT a production-valid number;
      it is reported as the non-durable contrast that shows how much of the ceiling is the
      per-write fsync itself.

For each posture it runs:
  * a SEQUENTIAL phase (await one emit at a time) → the true per-emit latency distribution
    (p50/p95/p99) and the serial emits/sec, which is what a single authorize caller sees;
  * a CONCURRENCY SWEEP (fire batches with ``asyncio.gather``) → the aggregate emits/sec as
    in-flight concurrency rises. Under ``appendfsync always`` this plateaus at the single
    -fsync ceiling because Redis has no application-triggered group fsync (each write is
    fsync'd independently) — the exact architectural limit ``docs/ARCHITECTURE.md``
    analyses. Under ``everysec`` it keeps climbing because no per-write fsync gates it.

Everything measured is a REAL ``WormLogger.emit`` — the same code the pipeline calls, the
same atomic Lua, the same redaction, the same leaf hashing. Nothing here is simulated.

Isolation & courtesy:
  * Uses a DEDICATED Redis logical DB (default 15) so it never touches a running gateway's
    db-0 WORM state, and flushes exactly ``ALL_WORM_KEYS`` in that DB before/after.
  * Restores the server's ORIGINAL ``appendonly`` / ``appendfsync`` on exit, so the run is
    behavior-neutral on the shared sandbox Redis.
  * The WORM signing key is a throwaway per-run Ed25519 key (like ``main.py``'s demo) — it
    signs nothing here; ``emit`` does not sign (epoch close does), so no key state leaks.

Usage:

    python scripts/bench_worm_emit.py
    python scripts/bench_worm_emit.py --redis-url redis://localhost:63790 --db 15 \
        --emits 3000 --concurrency 1,8,32,128 --json

Exit code is 0 on a clean run, 1 if Redis is unreachable (fail-closed, like the demo).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

import redis.asyncio as redis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Run-from-anywhere: put the repo root on the path (same pattern as the other scripts).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit.worm_logger import (  # noqa: E402 — after the sys.path bootstrap above.
    ALL_WORM_KEYS,
    PersistencePosture,
    WormLogger,
    read_persistence_posture,
)


# A representative redacted decision event — the SAME shape the pipeline hands ``emit``
# (an ALLOW record). Sized like a real authorize decision so leaf hashing / canonical_json
# / XADD costs match production, not a degenerate empty dict.
def _sample_event(i: int) -> dict[str, Any]:
    return {
        "correlation_id": f"bench-{i:08d}-4a1c-8e2f-000000000000",
        "tenant_id": "aegis-dynamics",
        "agent_id": "agent-benchmark-01",
        "alias": "skill_falcon_telemetry",
        "decision": "allow",
        "deny_reason": None,
        "transport": "cloud_rest",
        "risk_tier": "auto",
        "classification": "restricted",
        "source_format": "mcp",
        "transaction_ref": f"txn-{i:08d}",
        "payload_hash": "0" * 64,
        "arguments_shape": {"keys": 4, "depth": 2, "bytes": 312},
    }


# ---------------------------------------------------------------------------
# Result models.
# ---------------------------------------------------------------------------


@dataclass
class SequentialResult:
    """One sequential phase: serial rate + the per-emit latency distribution (ms)."""

    emits: int
    wall_seconds: float
    emits_per_second: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float


@dataclass
class ConcurrencyPoint:
    """One point of the concurrency sweep: aggregate rate at a given in-flight width."""

    concurrency: int
    emits: int
    wall_seconds: float
    emits_per_second: float


@dataclass
class PostureResult:
    """Everything measured under ONE durability posture."""

    label: str
    requested: str
    appendonly: str
    appendfsync: str
    is_durable: bool
    achieved: bool  # False when the posture could not be set (reported honestly).
    note: str = ""
    sequential: Optional[SequentialResult] = None
    sweep: list[ConcurrencyPoint] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Measurement primitives (REAL emits only).
# ---------------------------------------------------------------------------


async def _reset_worm_keys(client: "redis.Redis") -> None:
    """Delete exactly the WORM keys in this logical DB (isolated, no FLUSHDB)."""
    await client.delete(*ALL_WORM_KEYS)


async def _measure_sequential(worm: WormLogger, emits: int) -> SequentialResult:
    """Await one emit at a time; capture each emit's wall latency. This is the true
    fsync-bound per-emit cost a single authorize caller pays."""
    latencies_ms: list[float] = []
    t0 = time.perf_counter()
    for i in range(emits):
        s = time.perf_counter()
        await worm.emit(_sample_event(i))
        latencies_ms.append((time.perf_counter() - s) * 1000.0)
    wall = time.perf_counter() - t0
    latencies_ms.sort()

    def pct(p: float) -> float:
        if not latencies_ms:
            return 0.0
        idx = min(len(latencies_ms) - 1, int(round((p / 100.0) * (len(latencies_ms) - 1))))
        return latencies_ms[idx]

    return SequentialResult(
        emits=emits,
        wall_seconds=wall,
        emits_per_second=(emits / wall) if wall > 0 else 0.0,
        p50_ms=pct(50),
        p95_ms=pct(95),
        p99_ms=pct(99),
        max_ms=latencies_ms[-1] if latencies_ms else 0.0,
        mean_ms=statistics.fmean(latencies_ms) if latencies_ms else 0.0,
    )


async def _measure_concurrent(
    worm: WormLogger, emits: int, concurrency: int
) -> ConcurrencyPoint:
    """Keep ``concurrency`` emits in flight at once (gather in batches); measure the
    aggregate emits/sec. Shows whether in-flight width can beat the per-fsync ceiling."""
    remaining = emits
    base = 0
    t0 = time.perf_counter()
    while remaining > 0:
        batch = min(concurrency, remaining)
        await asyncio.gather(
            *(worm.emit(_sample_event(base + j)) for j in range(batch))
        )
        base += batch
        remaining -= batch
    wall = time.perf_counter() - t0
    return ConcurrencyPoint(
        concurrency=concurrency,
        emits=emits,
        wall_seconds=wall,
        emits_per_second=(emits / wall) if wall > 0 else 0.0,
    )


async def _run_posture(
    client: "redis.Redis",
    worm: WormLogger,
    *,
    label: str,
    requested: str,
    achieved: bool,
    note: str,
    emits: int,
    concurrencies: list[int],
) -> PostureResult:
    """Measure the sequential phase + the concurrency sweep under the CURRENT posture."""
    posture: PersistencePosture = await read_persistence_posture(client)
    result = PostureResult(
        label=label,
        requested=requested,
        appendonly=posture.appendonly,
        appendfsync=posture.appendfsync,
        is_durable=posture.is_durable,
        achieved=achieved,
        note=note,
    )
    if not achieved:
        return result

    # Warm up: register scripts + JIT the first XADD/fsync so the timed runs are steady.
    await _reset_worm_keys(client)
    for i in range(min(50, emits)):
        await worm.emit(_sample_event(i))

    await _reset_worm_keys(client)
    result.sequential = await _measure_sequential(worm, emits)

    for c in concurrencies:
        await _reset_worm_keys(client)
        result.sweep.append(await _measure_concurrent(worm, emits, c))

    await _reset_worm_keys(client)
    return result


# ---------------------------------------------------------------------------
# Config control (restore on exit — behavior-neutral).
# ---------------------------------------------------------------------------


async def _try_set_posture(
    client: "redis.Redis", appendonly: str, appendfsync: str
) -> tuple[bool, str]:
    """Attempt to set (appendonly, appendfsync). Returns (achieved, note). NEVER
    fabricates success — verifies the config read back matches what was requested."""
    try:
        await client.config_set("appendonly", appendonly)
        await client.config_set("appendfsync", appendfsync)
    except Exception as exc:  # noqa: BLE001 — restricted/managed Redis: report honestly.
        return False, f"could not set AOF ({type(exc).__name__}: {exc})"
    posture = await read_persistence_posture(client)
    if (
        posture.appendonly.lower() == appendonly.lower()
        and posture.appendfsync.lower() == appendfsync.lower()
    ):
        return True, f"set appendonly={appendonly} appendfsync={appendfsync}"
    return False, (
        f"CONFIG SET accepted but posture read back appendonly={posture.appendonly} "
        f"appendfsync={posture.appendfsync} (requested {appendonly}/{appendfsync})"
    )


async def _restore_config(
    client: "redis.Redis", original: PersistencePosture
) -> None:
    """Put the server's AOF config back exactly as found (courtesy on a shared Redis)."""
    try:
        await client.config_set("appendfsync", original.appendfsync)
        await client.config_set("appendonly", original.appendonly)
    except Exception as exc:  # noqa: BLE001 — advisory only.
        print(
            f"◐ bench: could not restore original AOF config: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Reporting.
# ---------------------------------------------------------------------------


def _print_posture(r: PostureResult) -> None:
    print("-" * 72)
    print(f"POSTURE: {r.label}   (requested: {r.requested})")
    print(
        f"  observed AOF: appendonly={r.appendonly} appendfsync={r.appendfsync}  "
        f"durable={r.is_durable}"
    )
    if not r.achieved:
        print(f"  NOT MEASURED: {r.note}")
        return
    if r.note:
        print(f"  note: {r.note}")
    s = r.sequential
    if s is not None:
        print(f"  sequential ({s.emits} emits, one in flight):")
        print(
            f"    {s.emits_per_second:9.1f} emits/sec   "
            f"latency ms  p50={s.p50_ms:.3f}  p95={s.p95_ms:.3f}  "
            f"p99={s.p99_ms:.3f}  max={s.max_ms:.3f}  mean={s.mean_ms:.3f}"
        )
    if r.sweep:
        print(f"  concurrency sweep (aggregate emits/sec at in-flight width):")
        for p in r.sweep:
            print(
                f"    concurrency={p.concurrency:>4}   "
                f"{p.emits_per_second:9.1f} emits/sec   "
                f"({p.emits} emits in {p.wall_seconds:.3f}s)"
            )


def _parse_concurrency(raw: str) -> list[int]:
    out: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            out.append(max(1, int(part)))
    return out or [1]


async def _amain(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="REAL WORM emit throughput benchmark.")
    parser.add_argument("--redis-url", default="redis://localhost:63790")
    parser.add_argument(
        "--db", type=int, default=15,
        help="Dedicated logical DB for the benchmark (default 15 — isolates from db 0).",
    )
    parser.add_argument("--emits", type=int, default=2000)
    parser.add_argument("--concurrency", default="1,8,32,128")
    parser.add_argument(
        "--skip-durable", action="store_true",
        help="Do not attempt to set appendfsync=always (measure the as-found posture only).",
    )
    parser.add_argument(
        "--unsafe-durability-contrast", action="store_true",
        help="ALSO run the appendfsync=everysec contrast. WARNING: `CONFIG SET appendfsync "
        "everysec` is SERVER-GLOBAL (not per-DB), so this RELAXES durability for the WHOLE "
        "Redis instance for the duration of that phase — a crash in the window could lose "
        "recent writes on ANY db. Off by default; use ONLY on a throwaway benchmark Redis.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args(argv)

    concurrencies = _parse_concurrency(args.concurrency)
    url = args.redis_url.rstrip("/")
    client: "redis.Redis" = redis.Redis.from_url(
        f"{url}/{args.db}", decode_responses=True
    )
    try:
        await client.ping()
    except Exception as exc:  # noqa: BLE001 — fail-closed, like the demo.
        print(f"◐ bench: cannot reach Redis at {url}/{args.db}: {type(exc).__name__}",
              file=sys.stderr)
        await client.aclose()
        return 1

    original = await read_persistence_posture(client)
    worm = WormLogger(client, Ed25519PrivateKey.generate())

    results: list[PostureResult] = []
    try:
        # (b) AS-FOUND sandbox posture first (before any config mutation).
        results.append(
            await _run_posture(
                client, worm,
                label="as-found (sandbox)",
                requested="(unchanged)",
                achieved=True,
                note=(
                    "as-found posture is already durable (appendfsync=always)"
                    if original.is_durable
                    else "durability RELAXED — a crash may lose recent writes; NOT a "
                    "production-valid number"
                ),
                emits=args.emits,
                concurrencies=concurrencies,
            )
        )

        if args.skip_durable:
            for lbl, req in (
                ("appendfsync=everysec (non-durable contrast)", "everysec"),
                ("appendfsync=always (production)", "always"),
            ):
                results.append(PostureResult(
                    label=lbl, requested=req,
                    appendonly=original.appendonly, appendfsync=original.appendfsync,
                    is_durable=False, achieved=False, note="skipped by --skip-durable",
                ))
        else:
            # NON-DURABLE CONTRAST: appendfsync=everysec (no per-write fsync). Shows how
            # much of the ceiling is the fsync itself — NOT a production-valid number.
            # `CONFIG SET appendfsync everysec` is SERVER-GLOBAL, so it relaxes durability
            # for the WHOLE instance for this phase — OFF unless explicitly opted in on a
            # throwaway bench Redis. (Setting `always` below only STRENGTHENS + restores.)
            if args.unsafe_durability_contrast:
                print(
                    "◐ bench: WARNING — running the everysec contrast RELAXES appendfsync "
                    "for the ENTIRE Redis instance until restored on exit; a crash in this "
                    "window can lose recent writes on any db. Use only on a throwaway Redis.",
                    file=sys.stderr,
                )
                ach_e, note_e = await _try_set_posture(client, "yes", "everysec")
                results.append(
                    await _run_posture(
                        client, worm,
                        label="appendfsync=everysec (non-durable contrast)",
                        requested="appendonly=yes appendfsync=everysec",
                        achieved=ach_e, note=note_e,
                        emits=args.emits, concurrencies=concurrencies,
                    )
                )
            # (a) PRODUCTION posture: appendfsync=always (durable-before-authorize).
            ach_a, note_a = await _try_set_posture(client, "yes", "always")
            results.append(
                await _run_posture(
                    client, worm,
                    label="appendfsync=always (production)",
                    requested="appendonly=yes appendfsync=always",
                    achieved=ach_a, note=note_a,
                    emits=args.emits, concurrencies=concurrencies,
                )
            )
    finally:
        await _reset_worm_keys(client)
        await _restore_config(client, original)
        restored = await read_persistence_posture(client)
        await client.aclose()

    if args.json:
        print(json.dumps(
            {
                "redis_url": f"{url}/{args.db}",
                "emits_per_posture": args.emits,
                "concurrencies": concurrencies,
                "original_posture": asdict(original),
                "restored_posture": asdict(restored),
                "results": [asdict(r) for r in results],
            },
            indent=2,
        ))
    else:
        print("=" * 72)
        print("MCPIP WORM emit throughput — REAL measurement")
        print(f"  redis: {url}/{args.db}   emits/posture: {args.emits}   "
              f"concurrencies: {concurrencies}")
        print(f"  original AOF: appendonly={original.appendonly} "
              f"appendfsync={original.appendfsync}")
        for r in results:
            _print_posture(r)
        print("-" * 72)
        print(f"  restored AOF: appendonly={restored.appendonly} "
              f"appendfsync={restored.appendfsync}")
        print("=" * 72)
    return 0


def main() -> None:
    sys.exit(asyncio.run(_amain()))


if __name__ == "__main__":
    main()
