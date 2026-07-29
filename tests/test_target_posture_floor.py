"""
MCPIP — An alias may tighten a target's posture, never weaken it.

    ◐ "Risk was bound to the NAME. It has to be bound to the RESOURCE."

The additive-only invariant guards the alias NAME: registration refuses to repoint an
alias that already resolves. It said nothing about the TARGET, and that gap was a real
policy bypass — reproduced against a live production-posture gateway:

    cf.d1.query  ->  .../{account_id}/d1/database/query   pin_required/restricted  ->  403
    cf.d1.quick  ->  .../{account_id}/d1/database/query   auto/unclassified        ->  200 ALLOW

Byte-identical target, identical destructive payload ("DROP TABLE customers"), opposite
outcomes. Anyone holding ``CAP_DIRECTORY_ADMIN`` could silently downgrade a protected
resource by giving it a second name — and there is deliberately no super-admin above
that capability to appeal to.

The fix is a POSTURE FLOOR keyed on the canonicalized target: a registration may bind a
target at an equal or stricter posture, never a weaker one. These tests pin both halves —
that the bypass and its canonicalization evasions are refused, and that the legitimate
cases (tightening, unrelated targets) are still allowed, since a floor that refuses
everything would be "secure" and useless.
"""

from __future__ import annotations

import os

# Pure-function tests (no Redis round-trip, no request path). Sandbox is set before
# importing app.main, which builds its components at module scope.
os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/5")

import pytest  # noqa: E402

from app.main import _canonical_target  # noqa: E402


class TestCanonicalTarget:
    """Two operators must not be able to write one resource two ways and evade the floor."""

    def test_identical_targets_agree(self) -> None:
        t = "https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/query"
        assert _canonical_target(t) == _canonical_target(t)

    @pytest.mark.parametrize(
        "variant",
        [
            # trailing slash
            "https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/query/",
            # host case
            "https://API.CLOUDFLARE.COM/client/v4/accounts/{account_id}/d1/database/query",
            # explicit default port
            "https://api.cloudflare.com:443/client/v4/accounts/{account_id}/d1/database/query",
            # scheme case
            "HTTPS://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/query",
            # a different NAME for the same template variable — the variable's name is the
            # operator's choice, not part of the resource's identity
            "https://api.cloudflare.com/client/v4/accounts/{acct}/d1/database/query",
            # percent-encoded path segment
            "https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/data%62ase/query",
        ],
    )
    def test_evasions_collapse_to_the_same_canonical_form(self, variant: str) -> None:
        base = "https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/query"
        assert _canonical_target(variant) == _canonical_target(base), (
            "a canonicalization gap is a posture-floor bypass: the attacker just writes "
            "the same URL differently"
        )

    def test_query_parameter_order_is_not_identity(self) -> None:
        a = "https://h/x?b=2&a=1"
        b = "https://h/x?a=1&b=2"
        assert _canonical_target(a) == _canonical_target(b)

    @pytest.mark.parametrize(
        "a,b",
        [
            # genuinely different resources must NOT collide — a floor that over-matches
            # locks operators out of registering legitimate neighbours
            ("https://api.cloudflare.com/v4/d1/query", "https://api.cloudflare.com/v4/d1/list"),
            ("https://api.cloudflare.com/v4/d1/query", "https://api.github.com/v4/d1/query"),
            ("https://h/x?a=1", "https://h/x?a=2"),
            ("http://h/x", "https://h/x"),
            # a placeholder segment is not the same as a literal one
            ("https://h/accounts/{id}/q", "https://h/accounts/literal/q"),
        ],
    )
    def test_distinct_resources_stay_distinct(self, a: str, b: str) -> None:
        assert _canonical_target(a) != _canonical_target(b)

    def test_unparseable_target_is_conservative_not_permissive(self) -> None:
        """No scheme/host ⇒ compare the raw casefolded string.

        The dangerous failure would be returning something that collides with nothing,
        because then the floor silently stops applying. Identical junk must still collide.
        """
        assert _canonical_target("not a url") == _canonical_target("NOT A URL")
        assert _canonical_target("not a url") != _canonical_target("other junk")


class TestConflictDisclosureIsNotAnOracle:
    """The floor must not become a way to probe an estate the caller cannot see.

    ``AliasRegistry.entries_for_tenant`` is deliberately UNFILTERED — "catalog filtering
    layers above" — so the posture floor necessarily inspects COMPARTMENTED aliases. But
    ``CAP_DIRECTORY_ADMIN`` does not imply compartment membership (capabilities here are
    non-hierarchical, and there is no super-admin). If the 409 named a compartmented
    alias, an admin without that compartment could register-at-``auto`` against guessed
    targets and read the compartment's alias names straight out of the error — the exact
    estate disclosure ``test_alias_naming_hygiene.py`` exists to prevent, reintroduced
    through the error path instead of the catalog.
    """

    def test_conflict_helper_reports_a_pair_not_a_bare_name(self) -> None:
        """The signature itself encodes 'conflict' and 'safe to name' as SEPARATE facts.

        A helper returning only Optional[str] cannot express "there is a conflict but you
        may not know which alias" — the shape is what makes the leak unrepresentable.
        """
        import inspect

        from app.main import _target_posture_conflict

        ret = inspect.signature(_target_posture_conflict).return_annotation
        assert "tuple" in str(ret).lower(), (
            "must return (conflict, disclosable_alias); a bare alias cannot express a "
            "non-disclosable conflict"
        )

    def test_compartmented_aliases_exist_in_the_unfiltered_view(self) -> None:
        """Pin the premise: if this ever became filtered, the guard above is dead code."""
        from obfuscator import build_demo_registry

        registry = build_demo_registry()
        compartmented = [
            (tenant, e) for tenant, e in registry.all_entries() if e.compartment is not None
        ]
        assert compartmented, (
            "the demo registry no longer has any compartmented alias; this test can no "
            "longer prove the disclosure guard matters"
        )
        tenant = compartmented[0][0]
        assert any(
            e.compartment is not None for e in registry.entries_for_tenant(tenant)
        ), "entries_for_tenant must stay UNFILTERED for the floor to see every binding"


class TestPostureRanks:
    """The floor's ordering is the whole policy — pin it explicitly."""

    def test_risk_and_classification_are_ordered_weakest_first(self) -> None:
        from app.main import _CLASSIFICATION_RANK, _RISK_RANK

        assert _RISK_RANK["auto"] < _RISK_RANK["pin_required"]
        assert _CLASSIFICATION_RANK["unclassified"] < _CLASSIFICATION_RANK["restricted"]

    def test_every_allowed_overlay_value_has_a_rank(self) -> None:
        """An unranked value would compare as -1 and silently read as 'weakest'."""
        from app.main import (
            _CLASSIFICATION_RANK,
            _OVERLAY_CLASSIFICATION,
            _OVERLAY_RISK,
            _RISK_RANK,
        )

        assert set(_OVERLAY_RISK) <= set(_RISK_RANK)
        assert set(_OVERLAY_CLASSIFICATION) <= set(_CLASSIFICATION_RANK)
