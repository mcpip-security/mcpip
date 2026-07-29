"""
MCPIP V2 — Audit package.

    ◐ Audit: "Per-epoch Merkle root, root-chained and Ed25519-signed — O(log n) proofs."

Re-exports the hybrid Merkle-epoch WORM logger, its receipt/header/proof view models,
and the pure Merkle primitives.
"""

from __future__ import annotations

from audit import merkle
from audit.anchor import AnchorStore
from audit.worm_logger import (
    ALL_WORM_KEYS,
    EpochHeader,
    InclusionProof,
    PersistencePosture,
    ProofScope,
    WormLogger,
    WormReceipt,
    assert_persistence_posture,
    read_persistence_posture,
)

__all__ = [
    "WormLogger",
    "WormReceipt",
    "EpochHeader",
    "InclusionProof",
    "ProofScope",
    "PersistencePosture",
    "AnchorStore",
    "read_persistence_posture",
    "assert_persistence_posture",
    "ALL_WORM_KEYS",
    "merkle",
]
