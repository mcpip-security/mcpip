"""
MCPIP — Alias naming hygiene: the obfuscator must not publish the estate map.

    ◐ "We hide the target. We must not advertise the compartment."

The obfuscator's contract is that an agent sees an opaque alias and never the real
target. That contract is about RESOLUTION, and resolution is sound — an unentitled
caller gets the same opaque ``MCPIPDenied`` whether the alias is unknown or merely
forbidden (proven in ``test_cross_absence.py``).

But an alias is also a STRING, and a string is readable. An alias named
``skill_flight_command_issue`` inside a CLASSIFIED compartment codenamed ``project-falcon``
tells any reader three things the compartment exists to withhold: that the compartment
exists, what it is called, and what it does. No resolution ever had to succeed.

That is a naming-discipline defect, not a crypto one, so it is fixed by discipline:
a registry-level guard that REFUSES such a binding at configuration time, plus a
seed catalog that stops teaching the anti-pattern by example.
"""

from __future__ import annotations

import re

import pytest

from interfaces import Classification, RiskTier
from obfuscator import build_demo_registry
from obfuscator.alias_registry import AliasEntry, AliasRegistry, Compartment


def _codename_tokens(label: str) -> list[str]:
    """Distinctive words in a compartment label, minus generic scaffolding.

    ``project-falcon`` -> ``['falcon']``. Words like 'project' or 'team' are dropped:
    they carry no estate information, and treating them as secret would ban half of
    every reasonable alias vocabulary for no security gain.
    """
    generic = {"project", "team", "group", "unit", "program", "the", "and"}
    return [w for w in re.split(r"[^a-z0-9]+", label.casefold()) if w and w not in generic]


def alias_leaks_compartment(alias: str, compartment_label: str) -> bool:
    """True iff the alias STRING names its own compartment's codename."""
    haystack = alias.casefold()
    return any(token in haystack for token in _codename_tokens(compartment_label))


# ---------------------------------------------------------------------------
# The shipped catalog must not teach the anti-pattern.
# ---------------------------------------------------------------------------


def test_no_shipped_alias_names_its_own_compartment() -> None:
    """The reference catalog is an EXAMPLE — operators copy its shape. An alias that
    names its own classified compartment teaches every reader to leak their estate in
    the one field the agent is guaranteed to see."""
    registry = build_demo_registry()
    offenders: list[str] = []
    for tenant_id, entry in registry.all_entries():
        # Same scope as the runtime guard: only compartments whose EXISTENCE is
        # sensitive. A departmental compartment name is not a secret.
        if not entry.compartment or entry.classification is Classification.UNCLASSIFIED:
            continue
        for compartment in registry.list_compartments(tenant_id):
            if compartment.compartment_uuid != entry.compartment:
                continue
            if alias_leaks_compartment(entry.alias, compartment.label):
                offenders.append(
                    f"{entry.alias} -> {compartment.label} ({entry.classification.value})"
                )
    assert offenders == [], (
        "alias(es) whose STRING names their own compartment codename:\n  "
        + "\n  ".join(offenders)
        + "\nThe obfuscator hides the TARGET; the alias must not publish the COMPARTMENT."
    )


def test_classified_aliases_describe_the_action_not_the_programme() -> None:
    """A classified alias may say what it DOES (an operator has to govern it) but not
    which programme it belongs to. This is the rule the guard enforces, stated as an
    example so its intent survives a future rename."""
    registry = build_demo_registry()
    classified = [
        entry
        for _, entry in registry.all_entries()
        if entry.classification is Classification.CLASSIFIED
    ]
    assert classified, "the reference catalog must exercise the classified path"
    for entry in classified:
        assert entry.alias.startswith("skill_"), entry.alias


# ---------------------------------------------------------------------------
# The guard itself — fail closed at configuration time.
# ---------------------------------------------------------------------------


def test_registry_refuses_an_alias_that_names_its_compartment() -> None:
    """Registration is the last moment this is cheap to stop. After it, the name is in
    the catalog, in ``tools/list``, in every operator's muscle memory, and in the WORM
    record — renaming it later is a migration, not an edit."""
    registry = AliasRegistry()
    registry.register_compartment(
        "tenant-x", Compartment("c-uuid-1", "project-nightfall", Classification.CLASSIFIED)
    )
    with pytest.raises(ValueError, match="compartment"):
        registry.register(
            "tenant-x",
            AliasEntry(
                alias="skill_nightfall_launch",
                target="rest.internal.launch",
                transport="cloud_rest",
                risk_tier=RiskTier.AUTO,
                compartment="c-uuid-1",
                classification=Classification.CLASSIFIED,
            ),
        )


def test_registry_allows_an_alias_that_describes_the_action() -> None:
    """The guard must not be so broad that it blocks legitimate naming — an alias that
    describes the ACTION inside a compartment is exactly what we want operators to write."""
    registry = AliasRegistry()
    registry.register_compartment(
        "tenant-x", Compartment("c-uuid-1", "project-nightfall", Classification.CLASSIFIED)
    )
    registry.register(
        "tenant-x",
        AliasEntry(
            alias="skill_launch_sequence_arm",
            target="rest.internal.launch",
            transport="cloud_rest",
            risk_tier=RiskTier.AUTO,
            compartment="c-uuid-1",
            classification=Classification.CLASSIFIED,
        ),
    )
    assert registry.has_alias("tenant-x", "skill_launch_sequence_arm")


def test_generic_words_in_a_label_are_not_treated_as_secret() -> None:
    """'project'/'team' carry no estate information. Banning them would outlaw half of
    every sensible vocabulary and train operators to disable the guard — a rule nobody
    can follow is worse than no rule."""
    registry = AliasRegistry()
    registry.register_compartment(
        "tenant-x", Compartment("c-uuid-2", "project-atlas", Classification.RESTRICTED)
    )
    registry.register(
        "tenant-x",
        AliasEntry(
            alias="skill_project_status_read",
            target="rest.internal.status",
            transport="cloud_rest",
            risk_tier=RiskTier.AUTO,
            compartment="c-uuid-2",
            classification=Classification.RESTRICTED,
        ),
    )
    assert registry.has_alias("tenant-x", "skill_project_status_read")


def test_guard_only_applies_to_the_alias_own_compartment() -> None:
    """An alias is only checked against the compartment it BELONGS to. Checking it
    against every compartment in the tenant would make unrelated names collide as the
    estate grows, and the guard would start blocking correct work."""
    registry = AliasRegistry()
    registry.register_compartment(
        "tenant-x", Compartment("c-a", "project-falcon", Classification.CLASSIFIED)
    )
    registry.register_compartment(
        "tenant-x", Compartment("c-b", "project-atlas", Classification.RESTRICTED)
    )
    # 'falcon' names compartment c-a, but this alias lives in c-b — allowed.
    registry.register(
        "tenant-x",
        AliasEntry(
            alias="skill_falcon_report_read",
            target="rest.internal.report",
            transport="cloud_rest",
            risk_tier=RiskTier.AUTO,
            compartment="c-b",
            classification=Classification.RESTRICTED,
        ),
    )
    assert registry.has_alias("tenant-x", "skill_falcon_report_read")


def test_uncompartmented_aliases_are_unaffected() -> None:
    """No compartment, nothing to leak — the guard must be inert on the common path."""
    registry = AliasRegistry()
    registry.register(
        "tenant-x",
        AliasEntry(
            alias="skill_falcon_anything",
            target="rest.public.thing",
            transport="cloud_rest",
            risk_tier=RiskTier.AUTO,
        ),
    )
    assert registry.has_alias("tenant-x", "skill_falcon_anything")
