"""
MCPIP V2 — Obfuscator: multi-industry tenant catalog (clean data).

    ◐ Obfuscator: "Agents call aliases. Real systems stay invisible."

This module is DATA ONLY. It defines representative alias catalogs for eight
industry tenants plus the compartments of the one defense tenant that separates its
teams (project-falcon / project-aegis / project-sentinel). ``seed_industry_catalog``
registers the compartments and aliases into an existing ``AliasRegistry``; the demo
registry calls it AFTER the legacy acme/globex rows so those rows stay byte-identical
and every existing demo scenario keeps passing.

Compartment ids are UUIDs (display labels are cosmetic). Alias targets never reach an
agent — they are the real downstream topology the Obfuscator hides.
"""

from __future__ import annotations

from interfaces import CAP_COMPARTMENT_GRANT, Classification, RiskTier
from obfuscator.alias_registry import AliasEntry, AliasRegistry, Compartment

# --- Defense compartment UUIDs (aegis-dynamics). ----------------------------------
FALCON = "f4100000-0000-4000-8000-0000000fa1c0"    # aegis-dynamics / project-falcon
AEGIS = "ae610000-0000-4000-8000-0000000ae615"     # aegis-dynamics / project-aegis
SENTINEL = "5e470000-0000-4000-8000-0000005e4715"  # aegis-dynamics / project-sentinel

# --- Demo company compartments (mcpip-inc) — the runnable A→Z walkthrough. ---------
# A single small company whose teams are separated by compartment. Used by
# scripts/demo_company.py and docs/start/GETTING_STARTED.md to show team-scoped ALLOW vs
# cross-team DENY over the real MCP endpoint (an Engineering agent reads the company
# overview but is denied the Finance wage sheet; a Finance agent reads it).
MCPIP_ENGINEERING = "e0900000-0000-4000-8000-e0900000e090"  # mcpip-inc / team-engineering
MCPIP_FINANCE = "f1a00000-0000-4000-8000-f1a00000f1a0"      # mcpip-inc / team-finance


# ---------------------------------------------------------------------------
# Compartments — only the defense tenant separates teams.
# ---------------------------------------------------------------------------

INDUSTRY_COMPARTMENTS: dict[str, tuple[Compartment, ...]] = {
    "aegis-dynamics": (
        Compartment(FALCON, "project-falcon", Classification.CLASSIFIED),
        Compartment(AEGIS, "project-aegis", Classification.CLASSIFIED),
        Compartment(SENTINEL, "project-sentinel", Classification.RESTRICTED),
    ),
    "mcpip-inc": (
        Compartment(MCPIP_ENGINEERING, "team-engineering", Classification.RESTRICTED),
        Compartment(MCPIP_FINANCE, "team-finance", Classification.RESTRICTED),
    ),
}


# ---------------------------------------------------------------------------
# Aliases — 3–6 representative rows per industry tenant.
# ---------------------------------------------------------------------------

INDUSTRY_ALIASES: dict[str, tuple[AliasEntry, ...]] = {
    # --- finance ------------------------------------------------------------
    "meridian-retail-bank": (
        AliasEntry("skill_account_balance", "rest.core.dda.balance.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_txn_history", "rest.core.dda.txn.list", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_wire_transfer", "rest.payments.fedwire.create", "cloud_rest", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_core_posting", "mainframe.cics.DDAPOST", "legacy_mainframe", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_card_reissue", "rest.cards.lifecycle.reissue", "cloud_rest", RiskTier.PIN_REQUIRED),
    ),
    # --- healthcare (PHI) ---------------------------------------------------
    "st-caritas-health": (
        AliasEntry("skill_patient_lookup", "rest.ehr.patient.demographics.get", "cloud_rest", RiskTier.AUTO,
                   classification=Classification.RESTRICTED, require_sender_constraint=True),
        AliasEntry("skill_lab_results", "rest.ehr.lab.results.get", "cloud_rest", RiskTier.AUTO,
                   classification=Classification.RESTRICTED, require_sender_constraint=True),
        AliasEntry("skill_rx_order", "rest.ehr.pharmacy.order.create", "cloud_rest", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_claim_submit", "mainframe.ims.CLAIMSUB", "legacy_mainframe", RiskTier.PIN_REQUIRED),
    ),
    # --- government ---------------------------------------------------------
    "us-treasury-fiscal": (
        AliasEntry("skill_disbursement_status", "rest.fiscal.payment.status.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_taxpayer_lookup", "rest.fiscal.taxpayer.get", "cloud_rest", RiskTier.AUTO,
                   classification=Classification.RESTRICTED, require_sender_constraint=True),
        AliasEntry("skill_treasury_disbursement", "mainframe.db2.DISBRUN", "legacy_mainframe", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_grant_award", "rest.fiscal.grants.award.create", "cloud_rest", RiskTier.PIN_REQUIRED),
    ),
    # --- DEFENSE (compartmented) --------------------------------------------
    "aegis-dynamics": (
        # Tenant-wide (un-compartmented) status probe — back-compat behavior.
        AliasEntry("skill_status_probe", "rest.health.status.get", "cloud_rest", RiskTier.AUTO),
        # Governance alias: issuing a compartment grant is an authorization-gated
        # EXECUTE mandate flowing through the SAME pipeline (payload-lock + WORM).
        AliasEntry(
            "skill_compartment_grant",
            "internal.governance.compartment.grant",
            "grant_issue",
            RiskTier.PIN_REQUIRED,
            compartment=None,
            classification=Classification.RESTRICTED,
            required_capability=CAP_COMPARTMENT_GRANT,
        ),
        # project-falcon compartment.
        AliasEntry("skill_airframe_telemetry", "rest.falcon.telemetry.get", "cloud_rest", RiskTier.AUTO,
                   compartment=FALCON, classification=Classification.CLASSIFIED,
                   require_sender_constraint=True),
        AliasEntry("skill_flight_command_issue", "mainframe.cics.FALCMD", "legacy_mainframe", RiskTier.PIN_REQUIRED,
                   compartment=FALCON, classification=Classification.CLASSIFIED),
        # project-aegis compartment.
        AliasEntry("skill_radar_calibration_set", "rest.aegis.radar.calibrate", "cloud_rest", RiskTier.PIN_REQUIRED,
                   compartment=AEGIS, classification=Classification.CLASSIFIED),
        AliasEntry("skill_intercept_plan_submit", "rest.aegis.intercept.plan.create", "cloud_rest", RiskTier.PIN_REQUIRED,
                   compartment=AEGIS, classification=Classification.CLASSIFIED),
        # project-sentinel compartment.
        AliasEntry("skill_recon_feed_read", "rest.sentinel.recon.feed.get", "cloud_rest", RiskTier.AUTO,
                   compartment=SENTINEL, classification=Classification.RESTRICTED,
                   require_sender_constraint=True),
    ),
    # --- energy / utility (OT / SCADA) --------------------------------------
    "voltgrid-utility": (
        AliasEntry("skill_grid_load", "rest.scada.load.snapshot.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_substation_status", "rest.scada.substation.status.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_breaker_trip", "rest.scada.breaker.trip.command", "cloud_rest", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_der_dispatch", "rest.scada.der.dispatch.create", "cloud_rest", RiskTier.PIN_REQUIRED),
    ),
    # --- retail / e-commerce ------------------------------------------------
    "novabuy-commerce": (
        AliasEntry("skill_order_status", "rest.oms.order.status.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_inventory_lookup", "rest.wms.inventory.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_refund_issue", "rest.payments.refund.create", "cloud_rest", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_price_override", "rest.pricing.override.apply", "cloud_rest", RiskTier.PIN_REQUIRED),
    ),
    # --- telecom ------------------------------------------------------------
    "orbital-telecom": (
        AliasEntry("skill_sim_status", "rest.hlr.sim.status.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_usage_summary", "rest.mediation.usage.summary.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_sim_swap", "rest.hlr.sim.swap.execute", "cloud_rest", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_number_port", "mainframe.cics.NUMPORT", "legacy_mainframe", RiskTier.PIN_REQUIRED),
    ),
    # --- pharma / biotech ---------------------------------------------------
    "helix-biotherapeutics": (
        AliasEntry("skill_trial_status", "rest.ctms.trial.status.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_batch_record", "rest.mes.batch.record.get", "cloud_rest", RiskTier.AUTO),
        AliasEntry("skill_batch_release", "rest.qms.batch.release.approve", "cloud_rest", RiskTier.PIN_REQUIRED),
        AliasEntry("skill_assay_result_post", "mainframe.db2.ASSAYPOST", "legacy_mainframe", RiskTier.PIN_REQUIRED),
    ),
    # --- DEMO COMPANY (mcpip-inc) — the runnable A→Z walkthrough. -----------
    # Teams are separated by compartment. The story: a company-wide agent reads the
    # overview; only Engineering reads the roadmap; only Finance reads the wage sheet.
    # Everyone else is denied COMPARTMENT_DENIED — opaque at the agent boundary.
    # Naming convention: ``skill_{platform}_{tool}`` — the access level is the
    # STRUCTURED ``access`` field (advisory display metadata), never a ``_read``/
    # ``_write`` alias suffix. ``service`` is the human permission-table label.
    "mcpip-inc": (
        # Company-wide — any licensed agent OF THE COMPANY may read it (no compartment).
        AliasEntry("skill_company_overview", "rest.mcpip.company.overview.get", "cloud_rest", RiskTier.AUTO,
                   service="Company overview", access="read"),
        # Company-wide default DATA tool — every team reads from the shared data lake
        # (curated, read-only). The default "useful tool out of the box" of the demo.
        AliasEntry("skill_data_lake", "rest.mcpip.datalake.query.get", "cloud_rest", RiskTier.AUTO,
                   service="Data lake", access="read"),
        # Engineering-only. The COMPARTMENT is the team-separation control here — an
        # agent not in team-engineering is denied COMPARTMENT_DENIED. Classification is
        # left UNCLASSIFIED so the sandbox demo works with the bearer tokens it mints:
        # a RESTRICTED AUTO read would (correctly) demand a sender-constrained token
        # under the production boot lint, which the sandbox IdP does not provision.
        AliasEntry("skill_engineering_roadmap", "rest.mcpip.eng.roadmap.get", "cloud_rest", RiskTier.AUTO,
                   compartment=MCPIP_ENGINEERING, service="Engineering roadmap", access="read"),
        # Finance-only — the "financial wage sheet" every non-Finance agent is denied.
        AliasEntry("skill_financial_wage_sheet", "rest.mcpip.finance.payroll.wages.get", "cloud_rest", RiskTier.AUTO,
                   compartment=MCPIP_FINANCE, service="Payroll wage sheet", access="read"),
        # Finance-only, high-risk — posting to the ledger demands a payload-bound PIN.
        AliasEntry("skill_financial_ledger_post", "mainframe.mcpip.GLPOST", "legacy_mainframe", RiskTier.PIN_REQUIRED,
                   compartment=MCPIP_FINANCE, service="General ledger", access="write"),
        # Engineering-only CLOUD IAM skill — executing it VENDS a short-lived, scoped
        # AWS credential (STS AssumeRole) instead of the agent holding a standing key.
        # ``target`` is the env_id of a CloudEnvironment binding (seeded in sandbox by
        # _hydrate_cloud_environments; operator-managed via /v1/admin/cloud/environments).
        AliasEntry("skill_aws_s3", "aws-eng-readonly", "cloud_iam", RiskTier.AUTO,
                   compartment=MCPIP_ENGINEERING, service="AWS S3", access="read"),
        # Engineering-only CLOUD IAM WRITE skill — a DynamoDB PutItem. Because it MUTATES
        # a table it is PIN_REQUIRED: the agent must complete a payload-bound step-up
        # ceremony before the gateway vends a short-lived credential scoped to the
        # WRITE role. The vended credential's blast radius is the role's least-privilege
        # policy (one table, PutItem only) — MCPIP authorizes + vends + audits; it does
        # NOT proxy or content-inspect the downstream DynamoDB call. ``target`` is the
        # env_id of the write-scoped CloudEnvironment binding (seeded in sandbox by
        # _hydrate_cloud_environments; docs/build/INTEGRATIONS.md drives it against a
        # real table with a run-locally least-privilege role).
        AliasEntry("skill_aws_dynamodb", "aws-eng-dynamodb-write", "cloud_iam", RiskTier.PIN_REQUIRED,
                   compartment=MCPIP_ENGINEERING, service="AWS DynamoDB", access="write"),
        # Company-wide GOVERNED-ALIAS reference for a data-egress / email-send tool
        # (docs/build/INTEGRATIONS.md). The lesson of the postmark-mcp / line-jumping
        # class (LANDSCAPE_2026H2 §5.5): a sensitive side-effecting tool is only governed
        # if the AGENT calls it as an MCPIP alias instead of holding the raw third-party
        # MCP server. Registered as cloud_rest + PIN_REQUIRED so the recipient set rides in
        # ``arguments`` and is CRYPTOGRAPHICALLY payload-bound at staging: a covert extra
        # recipient injected at completion changes the hash → PAYLOAD_MISMATCH deny, and the
        # send structurally cannot fire without the out-of-band OTP (the circuit-breaker for
        # a fully line-jumped agent). Un-compartmented so any mcpip-inc bearer agent can
        # drive it; PIN_REQUIRED is the control (and is exempt from the sender-constraint
        # boot-lint, so it stays secure-by-default in production without a cnf token).
        AliasEntry("skill_email_send", "rest.mcpip.notify.email.send", "cloud_rest", RiskTier.PIN_REQUIRED,
                   compartment=None, classification=Classification.UNCLASSIFIED,
                   service="Email", access="write"),
    ),
}


def seed_industry_catalog(registry: AliasRegistry) -> None:
    """Register every industry tenant's compartments and aliases into ``registry``."""
    for tenant_id, compartments in INDUSTRY_COMPARTMENTS.items():
        for comp in compartments:
            registry.register_compartment(tenant_id, comp)
    for tenant_id, entries in INDUSTRY_ALIASES.items():
        for entry in entries:
            registry.register(tenant_id, entry)


# ---------------------------------------------------------------------------
# Canary aliases — deception tripwire rows (GAP_ANALYSIS §3.1).
# ---------------------------------------------------------------------------
#
# Plausible, high-value-looking decoy skills seeded into EVERY tenant's catalog.
# They are visible bait: un-compartmented (so any agent of the tenant can see and
# select them), RiskTier.AUTO (so the tripwire fires on first touch, before any
# step-up ceremony), and never backed by a real system — the pipeline denies
# CANARY_TRIPPED and quarantines the caller BEFORE dispatch, so ``CANARY_TARGET``
# is a label for the WORM record, not a reachable endpoint. A prompt-injected or
# goal-hijacked agent sweeping the catalog for exfiltration/sabotage primitives
# selects one of these long before it finds a real high-risk skill.

CANARY_TARGET = "deception.tripwire.sink"

CANARY_ALIASES: tuple[AliasEntry, ...] = (
    AliasEntry("skill_export_all_credentials", CANARY_TARGET, "cloud_rest", RiskTier.AUTO, canary=True),
    AliasEntry("skill_disable_audit_log", CANARY_TARGET, "cloud_rest", RiskTier.AUTO, canary=True),
)


# The clean end-to-end teaching tenant. Canaries are an operator-OPT-IN deception
# control, not something to force into a customer's real catalog — seeding decoys like
# skill_export_all_credentials here would read as a live vulnerability in the demo
# company's own skill list. The canary feature is still shown on every industry tenant
# and in the dedicated Canary Tripwires panel.
_CANARY_EXCLUDED_TENANTS = frozenset({"mcpip-inc"})


def seed_canary_aliases(registry: AliasRegistry) -> None:
    """
    Register the canary rows for the industry showcase tenants plus the legacy demo
    tenants — call LAST so a canary can never shadow a legitimate alias registration.
    The clean demo company (mcpip-inc) is deliberately excluded (see above).
    """
    tenants = {"tenant-acme", "tenant-globex", *INDUSTRY_ALIASES.keys()} - _CANARY_EXCLUDED_TENANTS
    for tenant_id in sorted(tenants):
        for entry in CANARY_ALIASES:
            registry.register(tenant_id, entry)


__all__ = [
    "FALCON",
    "AEGIS",
    "SENTINEL",
    "MCPIP_ENGINEERING",
    "MCPIP_FINANCE",
    "INDUSTRY_COMPARTMENTS",
    "INDUSTRY_ALIASES",
    "CANARY_TARGET",
    "CANARY_ALIASES",
    "seed_industry_catalog",
    "seed_canary_aliases",
]
