"""
MCPIP V2 — Obfuscator: per-tenant alias ↔ target resolution.

    ◐ Obfuscator: "Agents call aliases. Real systems stay invisible."

Agents only ever name opaque aliases (``skill_payroll_run``). The Obfuscator maps an
alias to the real downstream target (``mainframe.cics.PAYR``), scoped to the caller's
tenant, and annotates each mapping with its transport and risk tier.

Fail-closed:
  * unknown alias           → UNKNOWN_ALIAS
  * alias not owned by the caller's tenant → CROSS_TENANT

Both a forward (alias→entry) and a reverse (target→alias) map are kept per tenant so
the audit log can render either direction without leaking cross-tenant data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

from interfaces import Classification, RiskTier


class UnknownAlias(Exception):
    """Alias is not registered for the caller's tenant → UNKNOWN_ALIAS."""


class CrossTenant(Exception):
    """Alias exists for another tenant but not this one → CROSS_TENANT."""


class CompartmentDenied(Exception):
    """Alias is compartmented and the caller is not entitled → COMPARTMENT_DENIED."""


@dataclass(frozen=True)
class AliasEntry:
    """An immutable alias → target binding with its transport and risk tier.

    The three trailing fields (all defaulted, so every legacy positional
    construction is byte-identical) carry the compartmented team-MCP separation:

      * ``compartment``          — compartment UUID gating visibility/execution, or
                                   ``None`` for a tenant-wide (un-compartmented) alias.
      * ``classification``       — data-sensitivity label (display/annotation only).
      * ``required_capability``  — capability UUID a caller MUST hold to invoke this
                                   alias (e.g. the grant-issuing governance alias).
      * ``canary``               — deception tripwire. A canary alias is listed in the
                                   catalog like any other skill but is never backed by
                                   a real target: invoking it denies (CANARY_TRIPPED)
                                   and quarantines the caller. The flag itself NEVER
                                   crosses the agent boundary (catalog/tools-list
                                   projections must not surface it).
      * ``require_sender_constraint`` — when True, this alias DEMANDS a key-proven
                                   (sender-constrained) token: a bare bearer JWT is
                                   denied SENDER_CONSTRAINT_REQUIRED at the resource
                                   gate even if it holds the compartment/capability.
                                   This is the resource-side dual of the token-side
                                   ``cnf`` check — it closes the "stolen bearer reaches
                                   a sensitive action" gap for the crown-jewel reads
                                   (CLASSIFIED/PHI/PII) that are AUTO-tier (no PIN).
                                   Defaults False, so every existing catalog row is
                                   unchanged until an operator deliberately opts in.
    """

    alias: str
    target: str
    transport: Literal["cloud_rest", "legacy_mainframe", "grant_issue", "cloud_iam"]
    risk_tier: RiskTier
    compartment: Optional[str] = None
    classification: Classification = Classification.UNCLASSIFIED
    required_capability: Optional[str] = None
    canary: bool = False
    require_sender_constraint: bool = False


@dataclass(frozen=True)
class Compartment:
    """A named, UUID-identified team compartment with a data classification."""

    compartment_uuid: str
    label: str
    classification: Classification


class AliasRegistry:
    """
    In-memory, per-tenant bi-directional alias registry.

    The registry itself is immutable auth state that is safe to share across
    stateless nodes: it is configuration, not per-request synchronization state
    (which lives exclusively in Redis).
    """

    def __init__(self) -> None:
        # tenant_id -> {alias -> AliasEntry}
        self._forward: dict[str, dict[str, AliasEntry]] = {}
        # tenant_id -> {target -> alias}
        self._reverse: dict[str, dict[str, str]] = {}
        # Global set of every alias string, across all tenants, to distinguish
        # "unknown to everyone" (UNKNOWN_ALIAS) from "known but not yours"
        # (CROSS_TENANT).
        self._known_aliases: set[str] = set()
        # tenant_id -> {compartment_uuid -> Compartment}
        self._compartments: dict[str, dict[str, Compartment]] = {}

    def register(self, tenant_id: str, entry: AliasEntry) -> None:
        """Register one alias binding for a tenant (configuration-time)."""
        forward = self._forward.setdefault(tenant_id, {})
        reverse = self._reverse.setdefault(tenant_id, {})
        forward[entry.alias] = entry
        reverse[entry.target] = entry.alias
        self._known_aliases.add(entry.alias)

    def has_alias(self, tenant_id: str, alias: str) -> bool:
        """True iff ``alias`` already resolves for ``tenant_id`` (config or overlay)."""
        return alias in self._forward.get(tenant_id, {})

    def unregister(self, tenant_id: str, alias: str) -> bool:
        """
        Remove a tenant's alias binding. Returns True iff it existed. Used ONLY to
        deregister an operator-added (overlay) skill — config aliases are never
        deregistered by policy; the caller enforces that. ``_known_aliases`` keeps
        the alias if any OTHER tenant still binds it, so cross-tenant existence
        semantics stay intact.
        """
        forward = self._forward.get(tenant_id)
        if forward is None or alias not in forward:
            return False
        entry = forward.pop(alias)
        reverse = self._reverse.get(tenant_id)
        if reverse is not None:
            reverse.pop(entry.target, None)
        still_bound = any(alias in fwd for fwd in self._forward.values())
        if not still_bound:
            self._known_aliases.discard(alias)
        return True

    def register_compartment(self, tenant_id: str, compartment: Compartment) -> None:
        """Register one compartment for a tenant (configuration-time)."""
        self._compartments.setdefault(tenant_id, {})[
            compartment.compartment_uuid
        ] = compartment

    def compartment_exists(self, tenant_id: str, compartment_uuid: str) -> bool:
        """True iff ``compartment_uuid`` is a registered compartment for the tenant."""
        return compartment_uuid in self._compartments.get(tenant_id, {})

    def list_compartments(self, tenant_id: str) -> list[Compartment]:
        """All compartments registered for a tenant (config-time snapshot)."""
        return list(self._compartments.get(tenant_id, {}).values())

    def entries_for_tenant(self, tenant_id: str) -> list[AliasEntry]:
        """All AliasEntry for a tenant (unfiltered). Catalog filtering layers above."""
        return list(self._forward.get(tenant_id, {}).values())

    def all_entries(self) -> list[tuple[str, AliasEntry]]:
        """Every (tenant_id, AliasEntry) across all tenants — config-time introspection
        (e.g. the production sender-constraint boot lint). NOT a per-request path."""
        return [
            (tenant_id, entry)
            for tenant_id, forward in self._forward.items()
            for entry in forward.values()
        ]

    def resolve(self, tenant_id: str, alias: str) -> AliasEntry:
        """
        Resolve ``(tenant_id, alias)`` to its AliasEntry.

        Raises:
            CrossTenant: the alias is registered — but for a different tenant.
            UnknownAlias: the alias is not registered for anyone.
        """
        tenant_map = self._forward.get(tenant_id)
        if tenant_map is not None:
            entry = tenant_map.get(alias)
            if entry is not None:
                return entry

        # Not found for this tenant. Decide which fail-closed reason to raise.
        if alias in self._known_aliases:
            # Someone owns it — but not this caller. Do not reveal who.
            raise CrossTenant(f"alias '{alias}' is not owned by tenant '{tenant_id}'")
        raise UnknownAlias(f"alias '{alias}' is not registered")


def build_demo_registry() -> AliasRegistry:
    """
    Construct the demo registry (§5.1) — 7 rows for ``tenant-acme`` plus a single
    ``skill_status_probe`` for ``tenant-globex`` so the cross-tenant deny is
    demonstrable.
    """
    registry = AliasRegistry()

    acme = "tenant-acme"
    acme_rows: tuple[AliasEntry, ...] = (
        AliasEntry("skill_customer_lookup", "rest.crm.customers.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_spend_summary", "rest.ledger.spend.summary", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_payroll_run", "mainframe.cics.PAYR", "legacy_mainframe", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_ledger_posting", "mainframe.db2.GLPOST", "legacy_mainframe", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_wire_transfer", "rest.payments.wire.create", "cloud_rest", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_emergency_reset", "aws.vpc.prod.db_drop", "cloud_rest", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_status_probe", "rest.health.status.get", "cloud_rest", RiskTier.AUTO),
    )
    for row in acme_rows:
        registry.register(acme, row)

    # Second tenant with exactly one alias — enough to prove cross-tenant denial.
    registry.register(
        "tenant-globex",
        AliasEntry("skill_status_probe", "rest.health.status.get", "cloud_rest", RiskTier.AUTO),
    )

    # Multi-industry tenant catalog (finance / healthcare / government / defense /
    # energy / retail / telecom / pharma) + the compartmented defense tenant. Seeded
    # AFTER the legacy rows so those byte-identical rows are never touched.
    from obfuscator.tenant_catalog import seed_canary_aliases, seed_industry_catalog

    seed_industry_catalog(registry)

    # Deception tripwire rows — every tenant's catalog carries the same decoy
    # skills. Seeded LAST so no legitimate row is ever shadowed by a canary.
    seed_canary_aliases(registry)

    return registry


__all__ = [
    "AliasEntry",
    "AliasRegistry",
    "Compartment",
    "UnknownAlias",
    "CrossTenant",
    "CompartmentDenied",
    "build_demo_registry",
]
