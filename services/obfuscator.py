"""
MCPIP V2 — Service: ObfuscatorService (fail-closed alias resolution).

    ◐ Obfuscator: "Agents call aliases. Real systems stay invisible."

A thin, fail-closed pass-through over the engine's ``AliasRegistry``. It exposes only
what the pipeline needs — resolve an agent-visible alias to its ``AliasEntry`` (which
carries the real target, transport, and risk tier) and read the risk tier off an
entry. The real target NEVER leaves this layer except into transport dispatch; it is
never returned to the agent and never placed in a receipt (invariant #4).
"""

from __future__ import annotations

from interfaces import Identity, constant_time_equals
from obfuscator import AliasEntry, AliasRegistry
from services.grant_store import GrantStore


class ObfuscatorService:
    """Tenant-scoped alias -> AliasEntry resolution, fail-closed on any miss."""

    def __init__(self, registry: AliasRegistry) -> None:
        self._registry = registry

    def resolve(self, tenant_id: str, alias: str) -> AliasEntry:
        """
        Resolve ``(tenant_id, alias)`` to its ``AliasEntry``.

        Propagates ``UnknownAlias`` / ``CrossTenant`` unchanged so the app's single
        mapper assigns ``UNKNOWN_ALIAS`` / ``CROSS_TENANT`` — both fail-closed denies.
        The registry never discloses which other tenant owns a cross-tenant alias.
        """
        return self._registry.resolve(tenant_id, alias)

    async def list_visible(
        self, registry: AliasRegistry, identity: Identity, grants: GrantStore
    ) -> list[AliasEntry]:
        """
        Aliases the caller may SEE — separation of teams between MCPs and AI.

        An alias is visible iff it is un-compartmented, in the caller's own
        compartment, or the caller holds an active delegated grant to its
        compartment. Fail-closed: an agent literally cannot enumerate another team's
        classified MCP. (This lists metadata only; ``target`` is never surfaced.)
        """
        visible: list[AliasEntry] = []
        for entry in registry.entries_for_tenant(identity.tenant_id):
            if entry.compartment is None:
                visible.append(entry)
                continue
            if identity.compartment is not None and constant_time_equals(
                identity.compartment, entry.compartment
            ):
                visible.append(entry)
                continue
            if await grants.has_active_grant(
                identity.tenant_id, identity.agent_id, entry.compartment
            ):
                visible.append(entry)
        return visible


__all__ = ["ObfuscatorService"]
