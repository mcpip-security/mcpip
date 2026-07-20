"""
MCPIP V2 — Audit: out-of-tamper-domain head anchor (rollback / truncation evidence).

    ◐ Audit: "The signed head, mirrored where the Redis attacker cannot rewrite it."

The signed Merkle-epoch WORM keeps its tamper-evidence — signed epoch headers, the
durable event buffer, and the linkage counters — in Redis. An attacker with Redis WRITE
access cannot FORGE a signed epoch root (no Ed25519 private key), but CAN delete the
newest signed epoch(s) together with their buffered events and rewrite the four PLAINTEXT
linkage counters (epoch:num / :head / :last_seq / :cursor) back to an earlier, still
validly-signed epoch. The surviving prefix stays internally consistent, so an
anchorless ``verify_chain`` reports ``intact`` — a silent rollback / tail-truncation.
Root-signing buys nothing here because forgery is never needed, only deletion plus a
counter rewrite, and the counters share the tamper domain with the headers they defend.

``AnchorStore`` persists the epoch head chain OUTSIDE that tamper domain: an fsync'd,
append-only local file (a real disk the Redis attacker does not reach). Each closed
epoch appends ONE Ed25519-signed line committing to ``(epoch, epoch_hash)``.
``verify_chain`` reads the highest durably-witnessed head from here and treats it as a
MONOTONIC LOW-WATERMARK: the reconstructed Redis chain must reach AT LEAST that epoch
with the identical ``epoch_hash``. A chain that stops short (rollback / truncation) or
presents a different hash at the witnessed epoch (substitution) is TAMPER — even though
every surviving signature still verifies.

Crash-safety / ordering. The anchor line is appended AFTER the epoch header is durable in
Redis, so a crash between the two only leaves the anchor LAGGING by the newest not-yet
witnessed epoch(s) — which verify treats as a legitimate "chain ahead of anchor", never a
false tamper. The anchor never moves backward under verification: ``head`` ignores any
line that fails its signature or is not well-formed, and takes the maximum epoch among
the surviving validly-signed lines. An attacker who reaches the file still cannot forge a
higher (or a substitute) signed head without the private key, and cannot LOWER the
watermark by deleting lines any more than they could by deleting Redis headers — a
deleted anchor only removes evidence of MORE-recent state, never fabricates a rollback
that verify would accept.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from interfaces import canonical_json


def _anchor_message(epoch: int, epoch_hash: str) -> bytes:
    """Canonical, domain-separated bytes the anchor signature commits to."""
    return b"MCPIP:WORM:ANCHOR:v1\x00" + canonical_json(
        {"epoch": epoch, "epoch_hash": epoch_hash}
    )


class AnchorStore:
    """
    Append-only, fsync'd, Ed25519-signed mirror of the signed epoch head.

    Held outside the Redis tamper domain so tail-truncation / rollback of the in-Redis
    chain is detectable. One line per closed epoch; ``head`` returns the highest
    validly-signed ``(epoch, epoch_hash)`` witnessed, or ``None`` when nothing is
    recorded (a fresh chain).
    """

    def __init__(self, private_key: Ed25519PrivateKey, path: str) -> None:
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()
        self._path = Path(path)

    async def record(self, epoch: int, epoch_hash: str) -> None:
        """Durably append (and fsync) one signed head line for ``epoch``."""
        signature = self._private_key.sign(_anchor_message(epoch, epoch_hash)).hex()
        line = json.dumps(
            {"epoch": epoch, "epoch_hash": epoch_hash, "sig": signature},
            separators=(",", ":"),
        )
        await asyncio.to_thread(self._append_fsync, line)

    def _append_fsync(self, line: str) -> None:
        """Blocking append + fsync of one line (run off-loop via ``to_thread``)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    async def head(self) -> Optional[tuple[int, str]]:
        """Highest validly-signed ``(epoch, epoch_hash)`` witnessed, else ``None``."""
        return await asyncio.to_thread(self._read_head)

    def _read_head(self) -> Optional[tuple[int, str]]:
        """Scan the append-only file; return the max-epoch validly-signed head."""
        if not self._path.exists():
            return None
        best: Optional[tuple[int, str]] = None
        with self._path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                stripped = raw.strip()
                if not stripped:
                    continue
                parsed = self._parse_verified(stripped)
                if parsed is None:
                    continue
                if best is None or parsed[0] > best[0]:
                    best = parsed
        return best

    def _parse_verified(self, line: str) -> Optional[tuple[int, str]]:
        """Parse one line and return it ONLY if its Ed25519 signature verifies."""
        try:
            record: Any = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(record, dict):
            return None
        epoch = record.get("epoch")
        epoch_hash = record.get("epoch_hash")
        signature = record.get("sig")
        if (
            not isinstance(epoch, int)
            or isinstance(epoch, bool)
            or not isinstance(epoch_hash, str)
            or not isinstance(signature, str)
        ):
            return None
        try:
            self._public_key.verify(
                bytes.fromhex(signature), _anchor_message(epoch, epoch_hash)
            )
        except (InvalidSignature, ValueError):
            return None
        return epoch, epoch_hash

    async def compact(self, min_epoch: int) -> None:
        """
        Rotate the append-only file, dropping witness lines below ``min_epoch``.

        Called after a checkpoint-compaction folds epochs < ``min_epoch`` into a signed
        super-checkpoint: those lines are subsumed and can be discarded, keeping the
        anchor file bounded to O(epochs since the last checkpoint) instead of growing one
        line per epoch forever. The highest witnessed head is preserved (the low-watermark
        the verifier enforces), so rotation never lowers tamper-evidence.
        """
        await asyncio.to_thread(self._compact_file, min_epoch)

    def _compact_file(self, min_epoch: int) -> None:
        """Blocking, crash-safe rewrite keeping only validly-signed lines >= min_epoch."""
        if not self._path.exists():
            return
        survivors: list[str] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                stripped = raw.strip()
                if not stripped:
                    continue
                parsed = self._parse_verified(stripped)
                if parsed is not None and parsed[0] >= min_epoch:
                    survivors.append(stripped)
        # Write survivors to a temp file, fsync, then atomically replace — a crash leaves
        # either the old complete file or the new complete file, never a torn one.
        tmp = self._path.with_name(self._path.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            if survivors:
                handle.write("\n".join(survivors) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self._path)
        dir_fd = os.open(str(self._path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def reset(self) -> None:
        """Remove the anchor file (demo/test lifecycle reset). Best-effort."""
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass


__all__ = ["AnchorStore"]
