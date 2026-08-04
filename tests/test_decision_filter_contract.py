"""
MCPIP — the decision-filter facet list, pinned across the gateway/SDK boundary.

``GET /v1/admin/decisions`` filters on a whitelist and **ignores** any query
parameter outside it. For a server that is the right call: echoing an unknown
parameter back is an input oracle, and rejecting it breaks forward compatibility
with a newer client. But it makes the client's silence expensive.

    $ mcpip admin decisions-history --filter agentid=someone-else
    allow  skill_spend_summary   …
    allow  skill_wire_transfer   …
    deny   skill_wire_transfer   …
    exit 0

Every row in the window, for every agent, under a command that asked for one —
with exit 0 and no warning. An operator filtering an audit does not re-read their
own flag; they read the rows. The answer was not merely wrong, it looked
authoritative, and `Agent_Id=` (right field, wrong case) did the same thing.

So the SDK refuses an unrecognised facet before it is sent. That only works while
its copy of the whitelist matches the gateway's, and the SDK cannot import the
gateway to check — it is a separate distribution whose only runtime dependency is
httpx. These tests are that check.
"""

from __future__ import annotations

import ast
import os
import re
import sys

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "sdk", "python", "src"))

from mcpip_sdk.admin import (  # noqa: E402
    DECISION_FILTER_FIELDS,
    _reject_unknown_filter_field,
)
from mcpip_sdk.cli.commands.admin import _parse_decision_filters  # noqa: E402
from mcpip_sdk.cli.errors import CLIConfigError  # noqa: E402


def _gateway_filter_fields() -> frozenset[str]:
    """Read ``_DECISION_FILTER_FIELDS`` out of app/main.py without importing it.

    Importing the gateway drags in fastapi/redis/pydantic; this test must be able
    to run anywhere the SDK does.
    """
    with open(os.path.join(_REPO_ROOT, "app", "main.py"), encoding="utf-8") as handle:
        source = handle.read()
    match = re.search(
        r"_DECISION_FILTER_FIELDS:\s*Final\[tuple\[str, \.\.\.\]\]\s*=\s*(\([^)]*\))",
        source,
        re.DOTALL,
    )
    assert match is not None, "could not find _DECISION_FILTER_FIELDS in app/main.py"
    return frozenset(ast.literal_eval(match.group(1)))


def test_the_sdk_whitelist_matches_the_gateway_exactly() -> None:
    """Drift either way is a silent wrong answer, so neither direction is allowed."""
    gateway = _gateway_filter_fields()
    missing = gateway - DECISION_FILTER_FIELDS
    extra = DECISION_FILTER_FIELDS - gateway
    assert not missing, (
        f"the gateway filters on {sorted(missing)} but the SDK refuses them — a working "
        "facet is unreachable; add them to mcpip_sdk.admin.DECISION_FILTER_FIELDS"
    )
    assert not extra, (
        f"the SDK forwards {sorted(extra)} but the gateway ignores them — those filters "
        "silently do nothing and return the range UNFILTERED"
    )


def test_the_two_newest_facets_are_present() -> None:
    """Regression pin: these are the two that had drifted.

    ``session_id`` and ``delegation_id`` were added to the gateway tuple by the
    session-attribution and delegation work, and never reached the SDK, the CLI
    help, or the endpoint docstring — so they shipped filterable and
    undiscoverable.
    """
    assert {"session_id", "delegation_id"} <= DECISION_FILTER_FIELDS


@pytest.mark.parametrize("field", sorted(DECISION_FILTER_FIELDS))
def test_every_known_facet_is_accepted(field: str) -> None:
    _reject_unknown_filter_field(field)
    assert _parse_decision_filters([f"{field}=x"]) == {field: "x"}


@pytest.mark.parametrize("field", ["agentid", "agent-id", "AGENT_ID", "Agent_Id", "tenant_id"])
def test_an_unknown_or_miscased_facet_is_refused_not_forwarded(field: str) -> None:
    """The exact accident: a near-miss key that used to return everything."""
    with pytest.raises(CLIConfigError) as caught:
        _parse_decision_filters([f"{field}=someone-else"])
    message = str(caught.value)
    assert "UNFILTERED" in message, "the error must say what would have happened"
    assert "agent_id" in message, "the error must name the facets that do exist"


def test_a_miscased_facet_gets_a_did_you_mean() -> None:
    with pytest.raises(CLIConfigError) as caught:
        _parse_decision_filters(["Agent_Id=x"])
    assert "did you mean 'agent_id'" in str(caught.value)


@pytest.mark.parametrize("pair", ["agent_id", "=x", "agent_id=", "   ", "=|"])
def test_a_malformed_pair_is_refused_rather_than_dropped(pair: str) -> None:
    """Dropping it silently is the same failure in a different coat."""
    with pytest.raises(CLIConfigError):
        _parse_decision_filters([pair])


def test_repeating_a_facet_still_ors_its_values() -> None:
    """The fix must not break the documented OR behaviour."""
    assert _parse_decision_filters(["decision=allow", "decision=deny"]) == {
        "decision": "allow,deny"
    }


def test_the_cli_help_lists_every_facet_the_gateway_serves() -> None:
    """The help string is generated from the whitelist; prove it stays that way."""
    from mcpip_sdk.cli.main import build_parser

    parser = build_parser()
    admin = parser._subparsers._group_actions[0].choices["admin"]  # type: ignore[union-attr]
    hist = admin._subparsers._group_actions[0].choices["decisions-history"]  # type: ignore[union-attr]
    help_text = next(
        action.help or "" for action in hist._actions if "--filter" in action.option_strings
    )
    for field in _gateway_filter_fields():
        assert field in help_text, f"--filter help does not mention the {field!r} facet"
