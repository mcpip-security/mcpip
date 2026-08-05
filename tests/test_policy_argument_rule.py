"""
MCPIP — the ``argument`` policy rule: bounding an OPEN-ENDED alias.

Everything the alias model buys assumes an alias names a NARROW action. Point one at
``run_shell(cmd)`` or ``execute_sql(query)`` and per-call authorization collapses into
"may this agent shell at all" — one catalog entry, arbitrary payload. A practitioner
running a large skill library put it exactly right in public: *"a per-call gate helps
only if somebody wrote the policy, and shell is where most policies quietly turn into
allow everything."*

``velocity`` and ``amount`` could not reach that: both are numeric. ``argument``
constrains the free-text field itself.

Two properties matter more than the feature and are pinned first:

* **It can only ever DENY.** The overlay is deny-only by construction, so a new rule kind
  cannot introduce an authorization bypass — the worst a malformed one can do is refuse
  traffic. That is what makes this safe to add to the authorization path at all.
* **No regex, anywhere.** A tenant-supplied pattern compiled on the hot path is a ReDoS
  vector and Python's ``re`` has no timeout. Exact match and literal substring only.
"""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from services.policy_engine import PolicyRule, PolicyRuleSet


def _rule(**overrides: object) -> PolicyRule:
    base: dict[str, object] = {
        "kind": "argument",
        "scope": "alias",
        "scope_value": "skill_shell",
        "argument_field": "cmd",
        "allowed_values": ["status", "restart", "tail"],
    }
    base.update(overrides)
    return PolicyRule(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Shape validation — a half-specified rule must never reach the store.
# ---------------------------------------------------------------------------


def test_a_rule_that_constrains_nothing_is_refused() -> None:
    """The worst outcome: a rule that reads as protection and permits everything."""
    with pytest.raises(ValidationError) as caught:
        _rule(allowed_values=None)
    assert "allowed_values or forbidden_substrings" in str(caught.value)


def test_argument_field_is_required() -> None:
    with pytest.raises(ValidationError):
        _rule(argument_field=None)


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_actions": 5, "window_seconds": 60},
        {"amount_field": "total", "max_amount": "100"},
    ],
)
def test_an_argument_rule_may_not_carry_another_kinds_fields(overrides: dict) -> None:
    """Mixed rules are how a half-understood document silently does the wrong thing."""
    with pytest.raises(ValidationError):
        _rule(**overrides)


@pytest.mark.parametrize("other_kind", ["velocity", "amount"])
def test_the_other_kinds_may_not_carry_argument_fields(other_kind: str) -> None:
    fields: dict[str, object] = {"kind": other_kind, "scope": "alias", "scope_value": "a"}
    if other_kind == "velocity":
        fields.update(max_actions=5, window_seconds=60)
    else:
        fields.update(amount_field="total", max_amount="100")
    fields.update(argument_field="cmd", allowed_values=["x"])
    with pytest.raises(ValidationError):
        PolicyRule(**fields)  # type: ignore[arg-type]


def test_empty_and_oversized_lists_are_refused() -> None:
    with pytest.raises(ValidationError):
        _rule(allowed_values=[])
    with pytest.raises(ValidationError):
        _rule(allowed_values=["x" * 257])
    with pytest.raises(ValidationError):
        _rule(allowed_values=[f"v{i}" for i in range(65)])


def test_an_unknown_kind_is_still_refused() -> None:
    with pytest.raises(ValidationError):
        _rule(kind="regex")


def test_an_argument_rule_round_trips_through_a_document() -> None:
    doc = PolicyRuleSet(schema="mcpip-policy/1", rules=[_rule()])  # type: ignore[call-arg]
    assert doc.rules[0].kind == "argument"
    assert doc.rules[0].allowed_values == ["status", "restart", "tail"]


# ---------------------------------------------------------------------------
# Evaluation.
# ---------------------------------------------------------------------------


class _Identity:
    tenant_id = "tenant-acme"
    agent_id = "agent-1"


class _Ctx:
    """Minimal PolicyContext stand-in — _check_argument reads only these."""

    def __init__(self, arguments: dict, alias: str = "skill_shell") -> None:
        self.arguments = arguments
        self.alias = alias
        self.transport_class = "cloud_rest"
        self.identity = _Identity()


def _check(rule: PolicyRule, arguments: dict):  # type: ignore[no-untyped-def]
    from services.policy_engine import VelocityAmountPolicyEngine

    return VelocityAmountPolicyEngine._check_argument(rule, _Ctx(arguments))  # type: ignore[arg-type]


def test_an_allowed_value_passes() -> None:
    assert _check(_rule(), {"cmd": "restart"}).outcome == "continue"


def test_a_value_outside_the_allowlist_denies() -> None:
    decision = _check(_rule(), {"cmd": "rm -rf /"})
    assert decision.outcome == "deny"


def test_the_denial_detail_never_echoes_the_argument_value() -> None:
    """The detail reaches the WORM record and the console; arguments carry customer data."""
    decision = _check(_rule(), {"cmd": "SELECT * FROM patients WHERE ssn='123-45-6789'"})
    assert decision.outcome == "deny"
    assert "123-45-6789" not in (decision.detail or "")
    assert "patients" not in (decision.detail or "")


def test_an_absent_field_is_a_no_op() -> None:
    """A transport-class rule matches many aliases; most will not carry the field."""
    assert _check(_rule(), {"other": "x"}).outcome == "continue"


@pytest.mark.parametrize("value", [{"$ne": None}, ["restart"], 1, True, None])
def test_a_non_string_value_denies_rather_than_coercing(value: object) -> None:
    """A dict/list where a string was expected is precisely the evasion."""
    decision = _check(_rule(), {"cmd": value})
    # None is genuinely absent — every other shape is a refusal to interpret.
    expected = "continue" if value is None else "deny"
    assert decision.outcome == expected


def test_forbidden_substrings_match_case_insensitively() -> None:
    rule = _rule(allowed_values=None, forbidden_substrings=["drop ", "truncate"])
    assert _check(rule, {"cmd": "select 1"}).outcome == "continue"
    assert _check(rule, {"cmd": "DROP TABLE users"}).outcome == "deny"
    assert _check(rule, {"cmd": "  TrUnCaTe patients"}).outcome == "deny"


def test_both_constraints_apply_together() -> None:
    rule = _rule(allowed_values=["status", "tail"], forbidden_substrings=["tail"])
    # Passes the allowlist, then caught by the substring rule.
    assert _check(rule, {"cmd": "tail"}).outcome == "deny"
    assert _check(rule, {"cmd": "status"}).outcome == "continue"


# ---------------------------------------------------------------------------
# The two safety properties.
# ---------------------------------------------------------------------------


def test_the_argument_check_can_only_ever_deny_or_continue() -> None:
    """Deny-only is what makes adding a rule kind to the auth path safe.

    If this ever returns 'allow', the overlay stops being monotonic and a policy
    document becomes capable of GRANTING access.
    """
    from services.policy_engine import VelocityAmountPolicyEngine

    source = inspect.getsource(VelocityAmountPolicyEngine._check_argument)
    assert 'outcome="allow"' not in source and "outcome='allow'" not in source


def test_no_regex_reaches_the_policy_hot_path() -> None:
    """A tenant-supplied pattern on the authorization path is a ReDoS vector."""
    import services.policy_engine as engine

    source = inspect.getsource(engine)
    # Line-exact, so `import redis.asyncio as redis` does not read as `import re`.
    imports = {line.strip() for line in source.splitlines()}
    assert "import re" not in imports, "the policy engine must not gain a regex dependency"
    assert not any(line.startswith("from re import") for line in imports)
    for banned in ("re.compile(", "re.search(", "re.match(", "re.fullmatch("):
        assert banned not in source, f"{banned} in the policy engine is a ReDoS vector"


def test_the_wire_schema_knows_every_field_the_validator_does() -> None:
    """`extra=forbid` on the request model silently makes a new kind unreachable."""
    from models.schemas import PolicyRuleModel

    engine_fields = set(PolicyRule.model_fields)
    wire_fields = set(PolicyRuleModel.model_fields)
    missing = engine_fields - wire_fields
    assert not missing, (
        f"PolicyRuleModel is missing {sorted(missing)} — the API would reject a rule the "
        "engine understands, before the real validator ever runs"
    )
