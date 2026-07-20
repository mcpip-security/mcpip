"""
MCPIP V2 — Audit: pure Merkle-tree primitives for the hybrid epoch WORM.

    ◐ Audit: "Per-epoch Merkle root, root-chained and Ed25519-signed — O(log n) proofs."

This module is PURE (no Redis, no signing): domain-separated leaf/node hashing, root
construction, O(log n) inclusion proofs, and proof verification. The WormLogger builds
on it to close epochs, chain + sign per-epoch roots, and answer inclusion queries.

Domain separation (distinct prefixes for leaves, internal nodes, and epoch headers)
guarantees a leaf digest can never collide with an internal-node digest, defeating the
classic second-preimage confusion.

CVE-2012-2459 / duplicate-last note: for an odd level we duplicate the last node.
That is SAFE here because the signed epoch header commits to ``leaf_count`` and the
exact ``[start_seq, end_seq]`` range, and verify rebuilds the tree from exactly those
stored, ordered leaves. No externally supplied tree shape is ever trusted, so the
duplicate-node ambiguity cannot forge an inclusion proof or alter the committed leaf
set.
"""

from __future__ import annotations

import hashlib
from typing import Final

from interfaces import constant_time_equals

# Domain-separation prefixes — a leaf digest can never equal an internal-node digest.
_DOMAIN_LEAF: Final[bytes] = b"MCPIP:WORM:LEAF:v1\x00"
_DOMAIN_NODE: Final[bytes] = b"MCPIP:WORM:NODE:v1\x01"
_DOMAIN_EPOCH: Final[bytes] = b"MCPIP:WORM:EPOCH:v1\x02"

# prev_epoch_hash sentinel for the first epoch in the signed root chain.
_GENESIS_EPOCH_HASH: Final[str] = "GENESIS"


def leaf_digest(record_bytes: bytes) -> bytes:
    """32-byte domain-separated hash of a leaf's canonical record bytes."""
    return hashlib.sha256(_DOMAIN_LEAF + record_bytes).digest()


def node_digest(left: bytes, right: bytes) -> bytes:
    """32-byte domain-separated hash of an internal node (its two children)."""
    return hashlib.sha256(_DOMAIN_NODE + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """
    Compute the Merkle root of ``leaves`` (duplicate-last for odd levels).

    An empty epoch has a fixed, well-defined root so an empty tree still commits to a
    stable value (never confused with a populated one).
    """
    if not leaves:
        return hashlib.sha256(_DOMAIN_LEAF).digest()  # fixed empty-epoch root.
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # DUPLICATE-LAST for odd counts (safe — see header).
        level = [node_digest(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def inclusion_proof(leaves: list[bytes], index: int) -> list[tuple[str, str]]:
    """
    O(log n) Merkle path for ``leaves[index]``.

    Returns ``[(side, sibling_hex), ...]`` where ``side`` ∈ {'L','R'} names which side
    the sibling sits on relative to the running hash.
    """
    proof: list[tuple[str, str]] = []
    idx, level = index, list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if idx % 2 == 0:
            proof.append(("R", level[idx + 1].hex()))
        else:
            proof.append(("L", level[idx - 1].hex()))
        idx //= 2
        level = [node_digest(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return proof


def verify_inclusion(leaf: bytes, proof: list[tuple[str, str]], root: bytes) -> bool:
    """Recompute the root from ``leaf`` + ``proof`` and compare (timing-uniform)."""
    h = leaf
    for side, sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        h = node_digest(sib, h) if side == "L" else node_digest(h, sib)
    return constant_time_equals(h.hex(), root.hex())


__all__ = [
    "leaf_digest",
    "node_digest",
    "merkle_root",
    "inclusion_proof",
    "verify_inclusion",
    "_DOMAIN_LEAF",
    "_DOMAIN_NODE",
    "_DOMAIN_EPOCH",
    "_GENESIS_EPOCH_HASH",
]
