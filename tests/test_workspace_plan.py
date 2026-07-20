"""
Unit tests for the workspace-plan service (services/workspace_plan.py) — pure, no app,
no Redis. Covers the deterministic draft, the structural validator, and the drift guard
that keeps the plan's skill rules in lockstep with the authoritative overlay constants.
"""

from __future__ import annotations

from services.workspace_plan import (
    VALID_RISK,
    VALID_CLASSIFICATION,
    MAX_PLAN_SKILLS,
    detect_domains,
    draft_plan_from_brief,
    validate_plan_structure,
    plan_to_directory_document,
)


def test_draft_is_deterministic_and_valid() -> None:
    brief = "A fintech with engineering, finance, and support teams."
    a = draft_plan_from_brief(brief, "Acme", "acme")
    b = draft_plan_from_brief(brief, "Acme", "acme")
    assert a == b  # deterministic (no randomness / clock)
    assert validate_plan_structure(a) == []
    assert a["tenant"] == "acme"
    # Detected the three named domains as teams.
    labels = {t["label"].lower() for t in a["org_units"][0]["teams"]}
    assert {"engineering", "finance", "support"} <= labels


def test_draft_risk_and_classification_are_policy_safe() -> None:
    """Reads are AUTO+unclassified; mutations are PIN_REQUIRED; sensitive mutations are
    RESTRICTED (and, being PIN_REQUIRED, satisfy the sender-constraint lint)."""
    plan = draft_plan_from_brief("engineering and finance", "Co", "co")
    by_alias = {s["alias"]: s for s in plan["skills"]}
    assert by_alias["skill_engineering_service_status_read"]["risk_tier"] == "auto"
    assert by_alias["skill_engineering_deploy_trigger"]["risk_tier"] == "pin_required"
    fin = by_alias["skill_finance_invoice_post"]
    assert fin["risk_tier"] == "pin_required" and fin["classification"] == "restricted"
    # No RESTRICTED skill is ever AUTO (that would fail the overlay policy).
    assert not any(s["classification"] == "restricted" and s["risk_tier"] != "pin_required" for s in plan["skills"])


def test_empty_brief_still_yields_a_valid_default() -> None:
    plan = draft_plan_from_brief("", "", "")
    assert validate_plan_structure(plan) == []
    assert plan["skills"] and plan["org_units"]


def test_detect_domains_dedupes_and_defaults() -> None:
    assert detect_domains("we love engineering and more engineering") == ["engineering"]
    assert detect_domains("nothing recognizable here") == ["operations", "support"]


def test_validator_rejects_bad_plans() -> None:
    # Restricted + auto (the exact overlay-policy violation).
    bad_restricted = {"org_units": [], "skills": [
        {"alias": "skill_x", "target": "rest.x", "risk_tier": "auto", "classification": "restricted"}]}
    assert any("restricted" in e for e in validate_plan_structure(bad_restricted))
    # Bad alias charset.
    bad_alias = {"org_units": [], "skills": [
        {"alias": "Skill-X!", "target": "rest.x", "risk_tier": "auto", "classification": "unclassified"}]}
    assert any("alias" in e for e in validate_plan_structure(bad_alias))
    # Duplicate alias.
    dup = {"org_units": [], "skills": [
        {"alias": "skill_x", "target": "rest.x", "risk_tier": "auto", "classification": "unclassified"},
        {"alias": "skill_x", "target": "rest.y", "risk_tier": "auto", "classification": "unclassified"}]}
    assert any("duplicate" in e for e in validate_plan_structure(dup))
    # Over the skill cap.
    over = {"org_units": [], "skills": [
        {"alias": f"skill_{i}", "target": "rest.x", "risk_tier": "auto", "classification": "unclassified"}
        for i in range(MAX_PLAN_SKILLS + 1)]}
    assert any("too many skills" in e for e in validate_plan_structure(over))
    # Non-object plan / bad shapes.
    assert validate_plan_structure([]) == ["plan must be an object"]
    assert any("org_units" in e for e in validate_plan_structure({"skills": []}))


def test_plan_to_directory_document_shape() -> None:
    plan = draft_plan_from_brief("engineering", "Co", "co")
    doc = plan_to_directory_document(plan)
    assert doc["schema"] == "mcpip-directory/1" and isinstance(doc["org_units"], list)


def test_drift_guard_matches_authoritative_overlay_constants() -> None:
    """The plan's skill-rule constants MUST equal app/main.py's authoritative overlay
    sets, or the dry-run validator could diverge from what apply enforces."""
    import os
    os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")
    import app.main as m

    assert VALID_RISK == m._OVERLAY_RISK
    assert VALID_CLASSIFICATION == m._OVERLAY_CLASSIFICATION
