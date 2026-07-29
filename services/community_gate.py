"""
MCPIP V2 — Service: the community-gate seam (author-your-own gate, Phase 2).

    ◐ "A community gate is one more AND-term in the deny chain. It can only ever say no —
       and until an engine is registered it says nothing at all, honestly."

Phase 2 of the author-your-own extensibility feature ships the community-GATE
*scaffold*: the manifest schema (``kind='gate'`` in ``services/extension_manifest.py``),
the ``DenyReason.POLICY_GATE_DENIED`` member, and — here — the DENY-ONLY provider seam the
pipeline invokes at step 4c′ (right after the mandate gate, adjacent to the G3 policy
gate). The actual CEL parse/lint/evaluate RUNTIME is DEFERRED: adopting an in-process CEL
evaluator (``cel-python``/``celpy``) pulls a native-extension chain (``google-re2`` +
``pendulum`` + ``jmespath`` + parser machinery) into a fail-closed authorizer whose pitch
is a small, auditable, air-gappable pure-Python footprint. Whether to take that on is an
OWNER dependency decision, not an implementer default (docs/integrate/EXTENSIBILITY.md §8). So:

  * NOTHING here imports ``celpy`` (it is not installed; importing it is never required to
    import this module or to pass any test).
  * The DEFAULT provider is :class:`NoOpCommunityGateProvider`, a strict fail-closed NO-OP
    that ALWAYS returns ``continue`` — the honest "no community gate engine configured"
    state (there are genuinely no community gates enforced), never a fabricated pass. It is
    deny-only/monotonic BY CONSTRUCTION: a ``GateDecision`` carries no allow/override
    outcome, so it can only ever ADD a ``POLICY_GATE_DENIED``; it never rescues an
    otherwise-denied call, never mints identity, never mutates the intent/target/arguments.
  * A future ``CelGateEngine`` (an OPTIONAL ``services/`` module, guarded so a missing
    ``celpy`` never breaks import) plugs in HERE via :func:`register_community_gate_engine`:
    it (a) implements :class:`CommunityGateProvider` by compiling + evaluating the pinned
    CEL with a hard cost bound + eval timeout over the whitelisted ``CommunityGateContext``,
    and (b) bundles the static cost/whitelist PROVER the reviewer approve path requires.
    Registering it is the SINGLE additive change that activates community gates — the
    schema, the flow, the seam, and the deny reason are already in place.

Gate APPROVAL is fail-closed without that runtime: a gate manifest can be submitted +
schema-validated + stored PENDING now, but approving one requires a static proof
(``max_cost`` ≤ budget by real CEL AST analysis + whitelist-only field refs), and the
prover needs the deferred runtime — so an approval that cannot be statically proven safe is
REFUSED (no approve-without-proof). See ``app.main.approve_extension``.
"""

from __future__ import annotations

from typing import Final, Optional, Sequence

from interfaces import CommunityGateContext, CommunityGateProvider, GateDecision


class NoOpCommunityGateProvider(CommunityGateProvider):
    """
    The default community-gate provider: a strict, fail-closed NO-OP.

    Always returns ``continue`` — NOT a fabricated "allow" but the honest statement that no
    community gate engine is configured, so there are genuinely no community gates to
    enforce. It is deny-only/monotonic by construction: ``GateDecision`` has no allow
    outcome, so this provider can only ever be replaced by one that ADDS a
    ``POLICY_GATE_DENIED`` — it can never turn an otherwise-denied call into an allow, mint
    identity, or mutate the resolved action. It reads NOTHING from ``ctx`` and touches no
    I/O, so it cannot fail.
    """

    async def evaluate(self, ctx: CommunityGateContext) -> GateDecision:
        return GateDecision(outcome="continue")


# The one registered community-gate engine, or None when none is registered (the shipped
# state — no CEL runtime is adopted in this wave). A future optional ``CelGateEngine``
# module registers itself here at import time via ``register_community_gate_engine``; that
# single call is what activates hot-path gate evaluation. Module-level (composition wires
# the provider once at boot, single-threaded), mirroring how an optional cloud SDK or a
# feature module is discovered.
_ENGINE: Optional[CommunityGateProvider] = None

# One shared stateless NO-OP — cheaper than minting a fresh instance per resolve, and safe
# because the provider holds no per-request state.
_NOOP: Final[NoOpCommunityGateProvider] = NoOpCommunityGateProvider()


class DenyOnlyGateChain(CommunityGateProvider):
    """
    Compose several ``CommunityGateProvider`` members into ONE deny-only, monotonic gate.

    Evaluate each member in order; the FIRST ``deny`` wins and short-circuits, else fall
    through to ``continue``. It is deny-only by construction — a ``GateDecision`` has no
    allow/override, so the chain can only ever ADD a deny; no member can rescue what an
    earlier gate (or an earlier member) denied. Used at the composition root to append an
    OPTIONAL ``ExternalPdpGateProvider`` (outbound COAZ PEP mode) after the shipped
    community-gate provider WITHOUT registering a gate ENGINE — so
    ``community_gate_engine_registered()`` stays False and gate-manifest approval is not
    falsely unlocked. Wrapped fail-closed by the pipeline's ``_community_gate`` like any
    other provider, so a raising member still denies.
    """

    def __init__(self, members: Sequence[CommunityGateProvider]) -> None:
        self._members: tuple[CommunityGateProvider, ...] = tuple(members)

    async def evaluate(self, ctx: CommunityGateContext) -> GateDecision:
        for member in self._members:
            decision = await member.evaluate(ctx)
            if decision.outcome == "deny":
                return decision
        return GateDecision(outcome="continue")


def register_community_gate_engine(provider: CommunityGateProvider) -> None:
    """
    Register the community-gate ENGINE — the single additive activation point.

    The DEFERRED CEL runtime (a ``CelGateEngine`` implementing ``CommunityGateProvider``
    plus the static prover the approve path requires) calls this at import time to turn
    community gates on. This is the ONLY mutation of the seam's state; the composition root
    reads the result via :func:`active_community_gate_provider` when it builds the pipeline.

    Refuses to silently overwrite an already-registered engine (a double-register is a
    composition bug, and clobbering a live deny-only gate would be a fail-open regression).
    """
    global _ENGINE
    if _ENGINE is not None:
        raise RuntimeError("a community gate engine is already registered")
    _ENGINE = provider


def active_community_gate_provider() -> CommunityGateProvider:
    """
    The provider the pipeline evaluates at step 4c′.

    Returns the registered engine when one is present, else the shared strict NO-OP — so
    with no engine registered (the shipped state) the seam is a pass-through that enforces
    no gates, honestly. Never returns None: the seam always has a provider to call, and the
    caller wraps ``evaluate`` fail-closed regardless.
    """
    return _ENGINE if _ENGINE is not None else _NOOP


def community_gate_engine_registered() -> bool:
    """
    True iff a community-gate engine (and thus its static prover) is registered.

    The reviewer approve path consults this to stay fail-closed: with no engine there is no
    static cost/whitelist prover, so a ``kind='gate'`` approval cannot be proven safe and is
    refused (no approve-without-proof). In this wave it is always False.
    """
    return _ENGINE is not None


__all__ = [
    "NoOpCommunityGateProvider",
    "DenyOnlyGateChain",
    "register_community_gate_engine",
    "active_community_gate_provider",
    "community_gate_engine_registered",
]
