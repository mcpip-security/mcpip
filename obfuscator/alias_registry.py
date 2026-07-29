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

import re
from dataclasses import dataclass
from typing import Final, Literal, Optional

from interfaces import Classification, RiskTier, SKILL_ACCESS_MODES


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
      * ``service`` / ``access``   — ADVISORY DISPLAY metadata for the permission-model
                                   console view (service listed once, Read/Write as
                                   controls — the Cloudflare-API-token shape). ``service``
                                   is a human label ("AWS DynamoDB"); ``access`` is
                                   "read"/"write". NEITHER is ever consulted by the
                                   authorize/PIN/WORM enforcement path, and ``service``
                                   never crosses the agent wire (it can hint at the
                                   target system). Both default None (trailing,
                                   defaulted — every positional construction is
                                   byte-identical).
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
    service: Optional[str] = None
    access: Optional[str] = None


def effective_access(entry: AliasEntry) -> str:
    """
    The display access mode for one alias — PURE, advisory only.

    An explicit, valid ``entry.access`` wins; an unannotated (or invalid) entry falls
    back to the honest risk-derived default: PIN_REQUIRED actions display as "write",
    AUTO reads as "read". Never an enforcement input.
    """
    if entry.access in SKILL_ACCESS_MODES:
        assert entry.access is not None  # membership in a str tuple narrows for mypy.
        return entry.access
    return "write" if entry.risk_tier is RiskTier.PIN_REQUIRED else "read"


def display_service(entry: AliasEntry) -> str:
    """
    The display service label for one alias — PURE, operator surfaces only.

    An explicit ``entry.service`` wins; otherwise the alias is humanized (leading
    ``skill_`` stripped, underscores → spaces). Never projected to the agent wire.
    """
    if entry.service:
        return entry.service
    alias = entry.alias
    if alias.startswith("skill_"):
        alias = alias[len("skill_"):]
    return alias.replace("_", " ")


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

    # Generic scaffolding words in a compartment label. They carry no estate
    # information, so treating them as secret would outlaw half of every sensible alias
    # vocabulary — and a rule nobody can follow gets disabled, which is worse than no rule.
    _GENERIC_LABEL_WORDS: Final[frozenset[str]] = frozenset(
        {"project", "team", "group", "unit", "program", "the", "and"}
    )

    def _compartment_codename_in(self, alias: str, label: str) -> Optional[str]:
        """The compartment codename an alias STRING exposes, if any."""
        haystack = alias.casefold()
        for word in re.split(r"[^a-z0-9]+", label.casefold()):
            if word and word not in self._GENERIC_LABEL_WORDS and word in haystack:
                return word
        return None

    def register(self, tenant_id: str, entry: AliasEntry) -> None:
        """Register one alias binding for a tenant (configuration-time).

        FAIL-CLOSED NAMING GUARD: an alias inside a compartment may describe what it
        DOES, but must not name the compartment it belongs to. The obfuscator hides the
        TARGET; the alias is the one string the agent is guaranteed to see, so an alias
        like ``skill_flight_command_issue`` inside ``project-falcon`` publishes the very
        thing the compartment exists to withhold — that the programme exists, what it is
        called, and what it does — without any resolution ever succeeding.

        Registration is the last moment this is cheap to stop: afterwards the name is in
        the catalog, in ``tools/list``, in the WORM record, and in operator muscle memory,
        so changing it is a migration rather than an edit. The check runs only when the
        compartment is already registered (config order is compartments-then-aliases);
        ``tests/test_alias_naming_hygiene.py`` independently sweeps the assembled registry,
        so an out-of-order registration cannot slip past both.
        """
        # Only SENSITIVE compartments are protected. A departmental compartment
        # ('team-engineering') names an org unit everyone already knows, and banning
        # 'skill_engineering_roadmap' would block a genuinely good name for no security
        # gain. A CLASSIFIED/RESTRICTED compartment names a programme whose EXISTENCE is
        # the secret — that is the case worth failing closed on.
        if entry.compartment and entry.classification in (
            Classification.CLASSIFIED,
            Classification.RESTRICTED,
        ):
            compartment = self._compartments.get(tenant_id, {}).get(entry.compartment)
            if compartment is not None:
                leaked = self._compartment_codename_in(entry.alias, compartment.label)
                if leaked is not None:
                    raise ValueError(
                        f"alias {entry.alias!r} names its own compartment "
                        f"({compartment.label!r} via {leaked!r}). The alias is visible to the "
                        "agent — name what the action DOES, not which compartment it is in."
                    )
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
    "effective_access",
    "display_service",
]
