"""
MCPIP V2 — Connectors: the pure-parser contract (Candidate + FormatParser).

    ◐ "Connectors are pure parsers — no SDK, no network, no keys, ever."

This module deliberately contains NO logic: only the extraction-result carrier and
the protocol every format parser satisfies. MCPIP is an authorization interceptor,
not an LLM proxy — the end user's client calls the LLM with its OWN credentials;
MCPIP only ever sees the resulting tool-call payload.
"""

from __future__ import annotations

from typing import Any, Mapping, NamedTuple, Optional, Protocol

from interfaces import SourceFormat


class Candidate(NamedTuple):
    """Pre-normalization extraction result — deliberately a NamedTuple, NOT a
    Pydantic model, so it can never be mistaken for a validation boundary.
    ``arguments`` is UNWALKED here; the ONLY validation authority is
    NormalizedIntent (which runs enforce_argument_safety). Carries no trace:
    provenance is supplied by the ingress, never by a parser."""

    alias: str
    arguments: dict[str, Any]
    source_format: SourceFormat
    # OPTIONAL recorded-not-trusted correlation provenance — populated ONLY by the A2A
    # task-envelope parser (task/context/message IDs + declared UNVERIFIED actor/
    # delegation metadata). Defaults None for all six existing parsers, so this is a
    # strictly additive, backward-compatible field: it never enters ``arguments``, the
    # payload lock, or the agent wire — it rides to the WORM audit ctx only.
    a2a_context: Optional[Mapping[str, Any]] = None


class FormatParser(Protocol):
    """A PURE function: one raw wire dict -> one Candidate. Total constraints:
    no I/O, no network, no SDK imports, no env access, no clock, no randomness,
    no mutation of ``raw``. Structural mismatch raises UnknownFormat or
    pydantic.ValidationError — nothing else."""

    def __call__(self, raw: dict[str, Any]) -> Candidate: ...


__all__ = ["Candidate", "FormatParser"]
