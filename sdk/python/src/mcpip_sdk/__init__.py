"""
mcpip-sdk — the typed Python client for the MCPIP authorization gateway.

    ◐ "Authorize every AI action before execution."

Quickstart (sandbox gateway on :8080)::

    from mcpip_sdk import SandboxClient, Staged

    with SandboxClient("http://localhost:8080") as client:
        client.set_token(client.dev_token(agent_id="agent-quickstart"))
        outcome = client.authorize("skill_spend_summary", {"period": "2026-Q2"})

Three clients, one contract:

* :class:`MCPIPClient` — the agent surface: ``authorize`` (→ :class:`Allowed`
  | :class:`Staged`), ``complete`` (the PIN ceremony), ``catalog``,
  ``mcp_call`` (real JSON-RPC 2.0 on ``/v1/mcp``), ``health``/``ready``/
  ``version``/``license``/``audit_attestation`` (the production-available,
  JWT-gated signed audit snapshot).
* :class:`SandboxClient` — adds the sandbox-only affordances (``dev_token``,
  ``authenticator_code``, ``audit_verify``, ``audit_proof``); each 404s on
  production gateways by design.
* :class:`MCPIPAdminClient` — the ``CAP_DIRECTORY_ADMIN`` control plane:
  skills, principals, decision feed, directory (incl. ``directory_relations``,
  the ReBAC Knowledge-Graph edge read), workspace plans, cloud environments,
  vault secrets, quarantine and canary rosters — plus
  ``forensic_get`` (query reconstruction), gated on the distinct,
  higher-sensitivity ``CAP_FORENSIC_READ`` capability and access-audited, and
  the community-extension review surface (``extensions_pending`` /
  ``extension_approve`` / ``extension_reject``) and the registry-governance
  verified-publisher allow-list (``verified_publishers_get`` /
  ``verified_publishers_put``), gated on the distinct ``CAP_CATALOG_REVIEWER``
  — while ``extension_submit`` (Contributor) needs only a valid token — plus
  ``compliance_evidence`` (the portable, ``CAP_DIRECTORY_ADMIN``-gated evidence
  bundle assembled from the real signed WORM attestation — evidence, never a
  certification).

Design rules inherited from the gateway: fail-closed and opaque (a deny is
:class:`MCPIPDenied` carrying ONLY a correlation id), no auto-retry ever, no
secrets or targets in any response model, tokens refreshed proactively —
never reactively on a deny.
"""

from __future__ import annotations

from typing import Final

from mcpip_sdk import envelopes
from mcpip_sdk._transport import CORRELATION_HEADER, DEFAULT_TIMEOUT
from mcpip_sdk.admin import MCPIPAdminClient
from mcpip_sdk.client import MCPIPClient, SandboxClient
from mcpip_sdk.errors import (
    AGENT_FACING_DENY_MESSAGE,
    MCPIPDenied,
    MCPIPError,
    MCPIPInvalidRequest,
    MCPIPNotFound,
    MCPIPSandboxOnly,
    MCPIPUnavailable,
)
from mcpip_sdk.models import (
    CAP_CATALOG_REVIEWER,
    CAP_DIRECTORY_ADMIN,
    CAP_FORENSIC_READ,
    PIN_LENGTH,
    PIN_MAX_ATTEMPTS,
    PIN_TTL_SECONDS,
    PUBLISHERS_SCHEMA,
    RISK_TIER_AUTO,
    RISK_TIER_PIN_REQUIRED,
    Allowed,
    AuditAttestation,
    AuditVerifyResult,
    AuthorizeEnvelope,
    AuthzenDecision,
    CanaryAlias,
    CatalogItem,
    CloudEnvironment,
    ComplianceControlClause,
    ComplianceEvidence,
    ComplianceFramework,
    DecisionPage,
    DecisionTotals,
    DenyReason,
    DeploymentStats,
    FeatureStatus,
    FeaturesInfo,
    ForensicPayload,
    OperatorInvite,
    OperatorUser,
    OperatorUserPage,
    Health,
    InclusionProof,
    LicenseInfo,
    PendingExtension,
    PlanApplyResult,
    PlanValidation,
    PolicyDocument,
    PolicyRule,
    ProtectedResourceMetadata,
    QuarantinedAgent,
    Readiness,
    RecentDecision,
    RegisteredSkill,
    RelationEdge,
    RelationList,
    ReleaseProvenance,
    Staged,
    TelemetryStatus,
    VaultSecret,
    VaultSecretList,
    VerifiedPublishers,
    VersionInfo,
    WorkspaceDraft,
    WorkspaceSummary,
)
from mcpip_sdk.tokens import TOKEN_EXP_SLACK_SECONDS, TokenProvider, TokenSource

__version__: Final[str] = "0.1.0"

__all__ = [
    "__version__",
    # clients
    "MCPIPClient",
    "SandboxClient",
    "MCPIPAdminClient",
    # errors
    "MCPIPError",
    "MCPIPDenied",
    "MCPIPInvalidRequest",
    "MCPIPUnavailable",
    "MCPIPNotFound",
    "MCPIPSandboxOnly",
    "AGENT_FACING_DENY_MESSAGE",
    # outcomes + models
    "Allowed",
    "Staged",
    "AuthorizeEnvelope",
    "CatalogItem",
    "Health",
    "Readiness",
    "ReleaseProvenance",
    "VersionInfo",
    "LicenseInfo",
    "AuditAttestation",
    "ProtectedResourceMetadata",
    "AuthzenDecision",
    "AuditVerifyResult",
    "InclusionProof",
    "RecentDecision",
    "DecisionPage",
    "ForensicPayload",
    "PolicyRule",
    "PolicyDocument",
    "RegisteredSkill",
    "PendingExtension",
    "QuarantinedAgent",
    "CanaryAlias",
    "RelationEdge",
    "RelationList",
    "CloudEnvironment",
    "VaultSecret",
    "VaultSecretList",
    "WorkspaceSummary",
    "WorkspaceDraft",
    "PlanValidation",
    "PlanApplyResult",
    "ComplianceControlClause",
    "ComplianceFramework",
    "ComplianceEvidence",
    "VerifiedPublishers",
    "DecisionTotals",
    "TelemetryStatus",
    "FeatureStatus",
    "FeaturesInfo",
    "DeploymentStats",
    "OperatorUser",
    "OperatorUserPage",
    "OperatorInvite",
    # protocol constants
    "PIN_TTL_SECONDS",
    "PIN_LENGTH",
    "PIN_MAX_ATTEMPTS",
    "CAP_DIRECTORY_ADMIN",
    "CAP_FORENSIC_READ",
    "CAP_CATALOG_REVIEWER",
    "PUBLISHERS_SCHEMA",
    "RISK_TIER_AUTO",
    "RISK_TIER_PIN_REQUIRED",
    "DenyReason",
    # tokens + transport knobs
    "TokenProvider",
    "TokenSource",
    "TOKEN_EXP_SLACK_SECONDS",
    "DEFAULT_TIMEOUT",
    "CORRELATION_HEADER",
    # envelope builders
    "envelopes",
]
