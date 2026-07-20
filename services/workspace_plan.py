"""
MCPIP V2 — Service: workspace-plan generation (brief → a governed workspace scaffold).

    ◐ "Describe the company; get a governed catalog — reviewed, validated,
       and applied through the same hardened endpoints an operator uses by hand."

A ``WorkspacePlan`` is a STRUCTURED, reviewable proposal for a tenant's initial
workspace: an org chart (org units + teams) and a starter skill catalog. It is
NEVER applied automatically — the operator reviews it and the gateway re-validates
it fail-closed before applying each element through the existing admin endpoints
(``register_skill`` for skills, ``PUT /v1/directory`` for the org chart), WORM-logged.

Two design commitments keep this honest:

  * **The safety is deterministic; the intelligence is optional.** This module's
    ``draft_plan_from_brief`` is a pure, inference-free heuristic — it ships and is
    fully testable with no model. A richer LLM draft (local-first, against a
    configurable endpoint) is an OPTIONAL layer the console can run to produce the
    SAME plan shape; it flows through the identical validate → review → apply path.
  * **No fabricated capability.** Generated skills are tenant-wide ``cloud_rest``
    catalog entries — exactly what ``register_skill`` supports — with risk tiers and
    classifications that satisfy the production sender-constraint lint (a RESTRICTED
    skill is always PIN-gated). The plan never invents compartments, cloud role ARNs,
    or secrets, because those are not operator-creatable at runtime.

The authoritative per-skill enforcement lives in ``app/main.py`` (shared with
``register_skill``); the structural checks here are a best-effort first pass for the
dry-run UX. The apply path always re-validates against the authoritative rules.
"""

from __future__ import annotations

import re
from typing import Any

# Skill-shape rules. These MIRROR app/main.py's overlay constants (a drift guard test
# asserts equality); the apply endpoint re-checks against the authoritative copy.
VALID_RISK: frozenset[str] = frozenset({"auto", "pin_required"})
VALID_CLASSIFICATION: frozenset[str] = frozenset({"unclassified", "restricted"})

# Per-plan bounds — a single brief scaffolds a starter workspace, not a bulk import.
MAX_PLAN_SKILLS = 64
MAX_PLAN_ORG_UNITS = 8
MAX_PLAN_TEAMS = 24
_MAX_ALIAS_LEN = 256
_MAX_TARGET_LEN = 512
_MAX_LABEL_LEN = 120

_ALIAS_RE = re.compile(r"^[a-z0-9_]+$")

# --- Deterministic draft: brief → domains → teams + a starter skill set. -----------
#
# Each domain contributes a team and a small set of tenant-wide cloud_rest skills.
# Reads are AUTO + unclassified; mutations are PIN_REQUIRED; sensitive domains
# (finance/hr) mark their mutations RESTRICTED (which, being PIN_REQUIRED, satisfies
# the sender-constraint lint). Everything is byte-safe and within bounds.

_DOMAINS: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    # (domain, keyword triggers, sensitive?)
    ("engineering", ("engineer", "engineering", "developer", "dev", "platform", "infra", "devops", "sre", "software"), False),
    ("finance", ("finance", "financial", "accounting", "payroll", "billing", "invoice", "treasury"), True),
    ("sales", ("sales", "revenue", "account executive", "crm", "pipeline", "deal"), False),
    ("support", ("support", "customer service", "help desk", "helpdesk", "success", "ticket"), False),
    ("security", ("security", "infosec", "soc", "compliance", "risk", "threat"), True),
    ("data", ("data", "analytics", "warehouse", "ml", "machine learning", "science", "reporting"), False),
    ("legal", ("legal", "counsel", "contract", "compliance", "gdpr"), True),
    ("hr", ("hr", "human resources", "people", "recruiting", "talent", "personnel"), True),
    ("operations", ("operations", "ops", "logistics", "supply", "procurement", "fulfilment", "fulfillment"), False),
    ("marketing", ("marketing", "growth", "brand", "campaign", "seo", "content"), False),
    ("product", ("product", "roadmap", "design", "ux", "pm"), False),
)

# Skill templates per domain: (suffix, action, mutating?). Reads first, then a mutation.
_DOMAIN_SKILLS: dict[str, tuple[tuple[str, bool], ...]] = {
    "engineering": (("service_status_read", False), ("deploy_trigger", True)),
    "finance": (("report_read", False), ("invoice_post", True)),
    "sales": (("pipeline_read", False), ("quote_create", True)),
    "support": (("ticket_read", False), ("ticket_reply", True)),
    "security": (("posture_read", False), ("incident_open", True)),
    "data": (("dataset_query", False), ("pipeline_run", True)),
    "legal": (("contract_read", False), ("contract_approve", True)),
    "hr": (("directory_read", False), ("record_update", True)),
    "operations": (("inventory_read", False), ("order_place", True)),
    "marketing": (("campaign_read", False), ("campaign_launch", True)),
    "product": (("roadmap_read", False), ("release_note_post", True)),
}

# Two company-wide skills every generated workspace gets — a read and the shared lake.
_COMPANY_SKILLS: tuple[tuple[str, str, str, str], ...] = (
    ("skill_company_overview", "rest.company.overview.read", "auto", "unclassified"),
    ("skill_company_directory_read", "rest.company.directory.read", "auto", "unclassified"),
)


def _slug(text: str) -> str:
    """A lowercase [a-z0-9_] slug (for tenant/team ids), collapsed and trimmed."""
    s = re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")
    return s or "company"


def detect_domains(brief: str) -> list[str]:
    """Ordered, de-duplicated domains whose keywords appear in the brief."""
    low = brief.casefold()
    found: list[str] = []
    for domain, triggers, _sensitive in _DOMAINS:
        if any(t in low for t in triggers) and domain not in found:
            found.append(domain)
    # A brief that named no domain still gets a sensible default pair.
    return found or ["operations", "support"]


def draft_plan_from_brief(brief: str, company: str, tenant: str) -> dict[str, Any]:
    """
    Deterministic (inference-free) draft: a company org unit with a team per detected
    domain, plus company-wide skills and a couple of governed skills per domain.
    Bounded and byte-safe by construction. The result is a proposal to be reviewed.
    """
    company = (company or "My Company").strip()[:_MAX_LABEL_LEN]
    tenant = _slug(tenant or company)
    domains = detect_domains(brief)[:MAX_PLAN_TEAMS]

    teams = [{"id": f"team-{d}", "label": d.capitalize(), "compartment": f"{d[:4]}…{_slug(d)[-3:]}"} for d in domains]
    org_units = [{
        "id": tenant,
        "label": company,
        "tenant": tenant,
        "teams": teams,
    }]

    skills: list[dict[str, str]] = [
        {"alias": a, "target": t, "risk_tier": r, "classification": c} for (a, t, r, c) in _COMPANY_SKILLS
    ]
    for d in domains:
        sensitive = next((s for (dom, _k, s) in _DOMAINS if dom == d), False)
        for suffix, mutating in _DOMAIN_SKILLS.get(d, ()):
            risk = "pin_required" if mutating else "auto"
            classification = "restricted" if (mutating and sensitive) else "unclassified"
            skills.append({
                "alias": f"skill_{d}_{suffix}",
                "target": f"rest.{d}.{suffix.replace('_', '.')}",
                "risk_tier": risk,
                "classification": classification,
            })
    # De-dupe by alias (stable order) and clamp to the plan cap.
    seen: set[str] = set()
    deduped: list[dict[str, str]] = []
    for s in skills:
        if s["alias"] in seen:
            continue
        seen.add(s["alias"])
        deduped.append(s)
    deduped = deduped[:MAX_PLAN_SKILLS]

    return {
        "company": company,
        "tenant": tenant,
        "org_units": org_units,
        "skills": deduped,
    }


def _skill_error(skill: Any) -> str | None:
    """Structural validity of one plan skill, or a short reason. Mirrors the authoritative
    overlay rules (charset, enums, restricted→PIN, bounds); the apply re-checks these."""
    if not isinstance(skill, dict):
        return "skill must be an object"
    alias = skill.get("alias")
    target = skill.get("target")
    risk = skill.get("risk_tier", "auto")
    classification = skill.get("classification", "unclassified")
    if not isinstance(alias, str) or not _ALIAS_RE.match(alias) or len(alias) > _MAX_ALIAS_LEN:
        return f"invalid alias {alias!r} (lowercase a-z0-9_ only)"
    if not isinstance(target, str) or not (1 <= len(target) <= _MAX_TARGET_LEN) or "\n" in target:
        return f"invalid target for {alias!r}"
    if risk not in VALID_RISK:
        return f"invalid risk_tier {risk!r} for {alias!r}"
    if classification not in VALID_CLASSIFICATION:
        return f"invalid classification {classification!r} for {alias!r}"
    if classification == "restricted" and risk != "pin_required":
        return f"restricted skill {alias!r} must be pin_required (sender-constraint policy)"
    return None


def validate_plan_structure(plan: Any) -> list[str]:
    """
    Best-effort structural validation for the dry-run/UX pass. Returns a list of human
    error strings (empty = structurally OK). The apply endpoint re-validates each skill
    against the AUTHORITATIVE overlay rules, so this can only be conservative, never a
    security gate on its own.
    """
    errors: list[str] = []
    if not isinstance(plan, dict):
        return ["plan must be an object"]
    org_units = plan.get("org_units")
    skills = plan.get("skills")
    if not isinstance(org_units, list):
        errors.append("org_units must be a list")
    elif len(org_units) > MAX_PLAN_ORG_UNITS:
        errors.append(f"too many org units ({len(org_units)} > {MAX_PLAN_ORG_UNITS})")
    else:
        team_total = 0
        for ou in org_units:
            if not isinstance(ou, dict) or not isinstance(ou.get("label"), str):
                errors.append("each org unit needs a string label")
                continue
            teams = ou.get("teams", [])
            if not isinstance(teams, list):
                errors.append(f"teams for {ou.get('label')!r} must be a list")
                continue
            team_total += len(teams)
        if team_total > MAX_PLAN_TEAMS:
            errors.append(f"too many teams ({team_total} > {MAX_PLAN_TEAMS})")
    if not isinstance(skills, list):
        errors.append("skills must be a list")
    elif len(skills) > MAX_PLAN_SKILLS:
        errors.append(f"too many skills ({len(skills)} > {MAX_PLAN_SKILLS})")
    else:
        aliases: set[str] = set()
        for skill in skills:
            reason = _skill_error(skill)
            if reason:
                errors.append(reason)
                continue
            alias = skill["alias"]
            if alias in aliases:
                errors.append(f"duplicate alias {alias!r} in plan")
            aliases.add(alias)
    return errors


def plan_to_directory_document(plan: dict[str, Any]) -> dict[str, Any]:
    """Project the plan's org units into a persistable ``mcpip-directory/1`` document."""
    return {"schema": "mcpip-directory/1", "org_units": plan.get("org_units", [])}


__all__ = [
    "VALID_RISK",
    "VALID_CLASSIFICATION",
    "MAX_PLAN_SKILLS",
    "MAX_PLAN_ORG_UNITS",
    "MAX_PLAN_TEAMS",
    "detect_domains",
    "draft_plan_from_brief",
    "validate_plan_structure",
    "plan_to_directory_document",
]
