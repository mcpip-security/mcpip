"""
MCPIP — DenyFamily: the operator triage coarsening over DenyReason.

    ◐ "Twenty-nine reasons for the record. Seven questions for the operator."

``DenyFamily`` exists so a console can sort an incident by WHAT THE OPERATOR DOES NEXT
instead of making them scan a 29-member taxonomy. These tests pin the three properties
that make that safe:

  * **Total** — every ``DenyReason`` maps to exactly one family, so a newly added reason
    cannot silently land in a bucket that implies the wrong remediation.
  * **Coarsening** — the family carries strictly LESS information than the reason, which
    is what makes it safe anywhere the reason is already safe. It is derived, never
    stored, so it cannot drift from the record.
  * **Never agent-facing** — grouping denials for an operator must not un-hide them for
    the caller. The agent boundary still yields ``MCPIPDenied`` + a correlation id.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import interfaces
from interfaces import DENY_FAMILY, DenyFamily, DenyReason, deny_family


def test_deny_family_is_total() -> None:
    """EVERY DenyReason has a family. This is the guard that makes the taxonomy safe to
    add to: a new reason without a family fails here rather than defaulting into a bucket
    whose remediation is wrong for it."""
    unmapped = sorted(r.value for r in DenyReason if r not in DENY_FAMILY)
    assert unmapped == [], (
        f"DenyReason(s) with no DenyFamily: {unmapped} — add them to interfaces.DENY_FAMILY, "
        "grouping by the OPERATOR'S NEXT ACTION, not by which subsystem raised them"
    )


def test_deny_family_maps_nothing_that_is_not_a_reason() -> None:
    """The map has no phantom keys — every key is a live DenyReason member."""
    reasons = set(DenyReason)
    assert set(DENY_FAMILY) <= reasons


def test_every_family_is_used() -> None:
    """A family with no reasons is dead vocabulary — it would show an operator an empty
    bucket and imply a class of failure that cannot happen."""
    used = set(DENY_FAMILY.values())
    unused = sorted(f.value for f in DenyFamily if f not in used)
    assert unused == [], f"DenyFamily member(s) no reason maps to: {unused}"


def test_family_is_a_strict_coarsening() -> None:
    """Strictly fewer families than reasons, and at least one family covers several
    reasons — otherwise it is a rename, not a triage grouping, and buys the operator
    nothing."""
    assert len(set(DENY_FAMILY.values())) < len(list(DenyReason))
    assert any(
        sum(1 for f in DENY_FAMILY.values() if f is family) > 1 for family in DenyFamily
    )


def test_deny_family_accepts_enum_and_wire_string_identically() -> None:
    """Callers hold either the enum (engine side) or the wire string (a WORM row read
    back, an HTTP filter). Both must coarsen the same way or the console and the engine
    would disagree about the same event."""
    for reason in DenyReason:
        assert deny_family(reason) is deny_family(reason.value)
        assert deny_family(reason) is DENY_FAMILY[reason]


def test_unknown_reason_is_ungrouped_not_guessed() -> None:
    """An unrecognized reason returns None so the UI renders it ungrouped. Guessing a
    family would be worse than showing none: it tells an operator to take a remediation
    the event does not warrant."""
    assert deny_family("not_a_real_reason") is None
    assert deny_family("") is None


def test_deny_family_map_is_immutable() -> None:
    """The map is a MappingProxyType — no caller can re-bucket a reason at runtime and
    change what an operator is told to do about it."""
    with pytest.raises(TypeError):
        DENY_FAMILY[DenyReason.INTERNAL] = DenyFamily.MALFORMED  # type: ignore[index]


def test_infrastructure_family_never_blames_the_caller() -> None:
    """Our failures must be OUR bucket. If a Redis lock error or an internal fault were
    grouped as 'malformed', an operator would go debug an integration that is fine —
    the single most expensive wrong turn this taxonomy can cause."""
    ours = {
        DenyReason.LOCK_ERROR,
        DenyReason.TRANSPORT_ERROR,
        DenyReason.RATE_LIMITED,
        DenyReason.INTERNAL,
    }
    for reason in ours:
        assert DENY_FAMILY[reason] is DenyFamily.INFRASTRUCTURE


def test_tripwire_family_is_exactly_the_deception_controls() -> None:
    """The tripwire bucket is the 'investigate now' queue. Anything else landing here
    would cry wolf and erode the one signal that should always be acted on."""
    tripwire = {r for r, f in DENY_FAMILY.items() if f is DenyFamily.TRIPWIRE}
    assert tripwire == {DenyReason.CANARY_TRIPPED, DenyReason.AGENT_QUARANTINED}


def test_step_up_reasons_route_to_a_human() -> None:
    """Every step-up outcome — including a delivery failure — is a human's problem. If
    OTP_DELIVERY_FAILED were 'infrastructure' the operator would page an SRE instead of
    checking why the approver never got asked."""
    for reason in (
        DenyReason.PIN_REQUIRED,
        DenyReason.PIN_NOT_FOUND,
        DenyReason.PIN_MISMATCH,
        DenyReason.PAYLOAD_MISMATCH,
        DenyReason.OTP_DELIVERY_FAILED,
    ):
        assert DENY_FAMILY[reason] is DenyFamily.NEEDS_HUMAN


def test_family_values_are_metric_label_safe() -> None:
    """Families are closed-enum literals with no ``skill_`` substring, so they cannot
    trip the metric-label hygiene guard if a future counter is ever labelled by family."""
    for family in DenyFamily:
        assert family.value.replace("_", "").isalnum()
        assert "skill_" not in family.value


def test_family_never_crosses_the_agent_boundary() -> None:
    """MCPIPDenied carries a correlation id and nothing else. Coarsening deny reasons for
    an OPERATOR must not add a channel that tells the CALLER which bucket it fell into —
    that would hand an enumerating agent a 7-way oracle over a 1-way one."""
    source = inspect.getsource(interfaces.MCPIPDenied)
    assert "DenyFamily" not in source
    assert "deny_family" not in source


def test_no_engine_module_leaks_family_to_a_response_body() -> None:
    """Static guard: the family is an operator-console concept. If it ever appears in the
    agent-facing edge (app/main.py authorize/mcp responses) that is a leak, so the import
    is confined to places that serve OPERATOR reads."""
    root = Path(interfaces.__file__).resolve().parent
    offenders: list[str] = []
    for path in (root / "bridge", root / "obfuscator", root / "auth"):
        if not path.exists():
            continue
        for py in path.rglob("*.py"):
            text = py.read_text(encoding="utf-8")
            if "DenyFamily" in text or "deny_family" in text:
                offenders.append(str(py.relative_to(root)))
    assert offenders == [], (
        f"DenyFamily reached a pipeline stage that serves the AGENT: {offenders}. "
        "It is an operator-console coarsening and belongs only on operator reads."
    )


# ---------------------------------------------------------------------------
# Cross-language parity — the console mirror cannot drift from the engine.
# ---------------------------------------------------------------------------

_TS_MIRROR = (
    Path(interfaces.__file__).resolve().parent / "dashboard" / "src" / "lib" / "denyFamily.ts"
)


def _ts_reason_map() -> dict[str, str]:
    """Parse REASON_TO_FAMILY out of the TS mirror by source scan (no node needed)."""
    import re

    source = _TS_MIRROR.read_text(encoding="utf-8")
    start = source.index("const REASON_TO_FAMILY")
    body = source[start : source.index("};", start)]
    return dict(re.findall(r"^\s*([a-z0-9_]+):\s*'([a-z_]+)',", body, flags=re.MULTILINE))


def test_typescript_mirror_matches() -> None:
    """The dashboard's deny-family mapping must equal the engine's, key for key.

    The console derives the family client-side (the gateway never serves it), so a
    mismatch would have the operator console and the WORM record disagreeing about what
    an event MEANS — with no error anywhere to reveal it. That silence is exactly why
    this is asserted rather than trusted.
    """
    ts = _ts_reason_map()
    py = {reason.value: family.value for reason, family in DENY_FAMILY.items()}
    assert ts == py, (
        "dashboard/src/lib/denyFamily.ts drifted from interfaces.DENY_FAMILY.\n"
        f"  only in TS: {sorted(set(ts) - set(py))}\n"
        f"  only in PY: {sorted(set(py) - set(ts))}\n"
        f"  disagree:   {sorted(k for k in set(ts) & set(py) if ts[k] != py[k])}"
    )


def test_typescript_mirror_declares_every_family() -> None:
    """The TS union and the urgency-ordered list both cover the whole enum — a family
    missing from DENY_FAMILY_ORDER would silently never render as a bucket."""
    source = _TS_MIRROR.read_text(encoding="utf-8")
    for family in DenyFamily:
        assert f"| '{family.value}'" in source or f"'{family.value}'" in source
    order_block = source[source.index("DENY_FAMILY_ORDER") : source.index("interface FamilyMeta")]
    for family in DenyFamily:
        assert f"'{family.value}'" in order_block, (
            f"DenyFamily.{family.name} missing from DENY_FAMILY_ORDER — it would never "
            "appear as a bucket in the console"
        )
