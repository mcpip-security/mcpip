"""
MCPIP V2 — Obfuscator package.

    ◐ Obfuscator: "Agents call aliases. Real systems stay invisible."

Re-exports the alias registry API, the compartment model, and the demo registry
builder (which composes the legacy rows + the multi-industry tenant catalog).
"""

from __future__ import annotations

from obfuscator.alias_registry import (
    AliasEntry,
    AliasRegistry,
    Compartment,
    CompartmentDenied,
    CrossTenant,
    UnknownAlias,
    build_demo_registry,
    display_service,
    effective_access,
)
from obfuscator.tenant_catalog import (
    AEGIS,
    FALCON,
    SENTINEL,
    seed_industry_catalog,
)

__all__ = [
    "AliasEntry",
    "AliasRegistry",
    "Compartment",
    "CompartmentDenied",
    "CrossTenant",
    "UnknownAlias",
    "build_demo_registry",
    "display_service",
    "effective_access",
    "seed_industry_catalog",
    "FALCON",
    "AEGIS",
    "SENTINEL",
]
