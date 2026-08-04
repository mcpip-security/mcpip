"""
MCPIP V2 — App: the FastAPI gateway (composition root + endpoints).

    ◐  MCPIP — The Authorization Layer for Autonomous AI
       "Authorize every AI action before execution."
       AI Reasons. MCPIP Authorizes. Systems Execute.

This is the ONLY long-lived process in the deployment: ``uvicorn app.main:app``. It
wires the four engine stages (Bridge → Obfuscator → Auth → Audit) behind a single
``POST /v1/authorize`` choke point that reproduces the demo gateway's call sequence
(``main.py`` L203–248) plus the one added step-up staging branch.

Design contract:

  * **Fail-closed, opaque boundary.** Every deny — forged JWT, identity injection,
    unknown alias, cross-tenant, replay, tamper, transport failure, or an entirely
    unexpected error — leaves the process as HTTP 403 with ONLY
    ``{error, correlation_id}``. The concrete reason exists solely in the WORM log.
  * **Zero topology leakage.** The receipt exposes the coarse transport class, never
    the real dotted target. Aliases are the only agent-facing names.
  * **Correlation everywhere.** A uuid4 correlation id is minted per request in
    middleware, echoed on every response header, and quoted in every body/deny.
  * **Composition once.** All engine objects are built a single time at import and
    shared across stateless requests; all synchronization state lives in Redis.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import json
import os
import stat
import re
import secrets
import sys
import time
import urllib.parse
import uuid
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Final, Optional, Union

import redis.asyncio as redis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from interfaces import (
    AuthorizedIntent,
    BaseAuthenticatorChannel,
    BaseTransport,
    CAP_CATALOG_REVIEWER,
    CAP_COMPARTMENT_GRANT,
    CAP_COMPARTMENT_REVOKE,
    CAP_DIRECTORY_ADMIN,
    CAP_FORENSIC_READ,
    Classification,
    CommunityGateContext,
    CommunityGateProvider,
    Hop,
    Identity,
    NormalizedIntent,
    PolicyContext,
    RESPONSE_SINGLE_SHOT_REASONS,
    RESPONSE_TRIGGER_REASONS,
    PolicyProvider,
    RiskTier,
    SourceFormat,
    SwarmTrace,
    TransportResult,
    MAX_DECISIONS_PAGE,
    MAX_OPERATOR_EMAIL_LEN,
    MAX_OPERATOR_PAGE,
    MAX_OPERATOR_USERS,
    MAX_PENDING_SUBMISSIONS,
    MAX_SERVICE_LABEL_LEN,
    SKILL_ACCESS_MODES,
    constant_time_equals,
    grant_capability_for,
    project_a2a_context,
    reject_unsafe_string,
)
from bridge import parse as bridge_parse
from bridge.connectors.registry import resolve_vendor
from auth import (
    WELL_KNOWN_PRM_PATH,
    LockError,
    PinValidator,
    PopError,
    RedisReplayGuard,
    StaticPEMKeyProvider,
    TokenResolver,
    build_protected_resource_metadata,
    verify_pop_proof,
)
from obfuscator import (
    AliasEntry,
    AliasRegistry,
    CrossTenant,
    UnknownAlias,
    build_demo_registry,
    display_service,
    effective_access,
)
from audit import AnchorStore, WormLogger

from core.config import Settings, get_settings
from core.integrity import verify_boot_integrity, verify_ed25519_signature
from core.licensing import License, load_and_verify_license
from core.logging_setup import configure_logging
from core.metrics import (
    AUDIT_INTEGRITY,
    AUTHENTICATOR,
    DECISIONS,
    FORENSIC,
    LATENCY,
    LICENSE_REFRESH,
    RESPONSE,
    SHED,
    TELEMETRY,
    WORM_EPOCH,
    WORM_SEQUENCE,
    render_metrics,
)
from core.version import get_version, is_newer
from core.security import (
    AGENT_FACING_DENY_MESSAGE,
    DenyReason,
    GatewayDeny,
    MCPIPDenied,
    lock_payload_hash,
    map_engine_exception,
    new_correlation_id,
)
from models.schemas import (
    AuthorizeRequest,
    AuthzenAction,
    AuthzenDecisionRequest,
    AuthzenDecisionResponse,
    AuthzenResource,
    CatalogItem,
    ErrorResponse,
    ExecutionReceipt,
    StagedChallenge,
)
from services.auth_engine import AuthEngine
from services.authn_channel import (
    FanoutAuthenticatorChannel,
    SandboxRedisAuthenticatorChannel,
    TotpVaultAuthenticatorChannel,
    WebhookAuthenticatorChannel,
)
from services.authenticator_enrollment import AuthenticatorEnrollmentStore
from services.grant_cache import NegativeGrantCache
from services.grant_store import GrantStore
from services.relation_store import RelationEdge, RelationTupleStore
from services.obfuscator import ObfuscatorService
from services.quarantine import QuarantineStore
from services.revocation import RevocationStore
from services.delegation import DelegationError, DelegationStore, Grant
from services.skill_gate import SkillGateStore
from services.catalog_overlay import CatalogOverlayStore, MAX_OVERLAY_ENTRIES
from services.community_gate import (
    DenyOnlyGateChain,
    active_community_gate_provider,
    community_gate_engine_registered,
)
from services.external_pdp import ExternalPdpGateProvider
from services.extension_manifest import (
    ExtensionManifestError,
    manifest_kind,
    parse_gate_manifest,
    parse_manifest,
    parse_registry_manifest,
    verify_manifest_pin,
    verify_registry_manifest_pin,
)
from services.extension_submissions import (
    ExtensionSubmissionStore,
    STATE_APPROVED,
    STATE_PENDING,
    STATE_REJECTED,
)
from services.registry_publishers import (
    PUBLISHERS_SCHEMA,
    PublisherAllowListError,
    VerifiedPublisherStore,
)
from services.operator_users import (
    OperatorUserCapExceeded,
    OperatorUserConflict,
    OperatorUserError,
    OperatorUserNotFound,
    OperatorUserStore,
    normalize_email,
)
from services.cloud_broker import (
    CloudBroker,
    CloudEnvironment,
    CloudEnvironmentStore,
    CLOUD_PROVIDERS,
    MAX_ENVIRONMENTS,
    clamp_ttl,
)
from services.directory_store import DirectoryStore, DirectoryDocumentError
from services.policy_engine import (
    PolicyDocStore,
    PolicyDocumentError,
    VelocityAmountPolicyEngine,
    POLICY_SCHEMA,
)
from services.workspace_plan import (
    draft_plan_from_brief,
    validate_plan_structure,
    plan_to_directory_document,
)
from services.secret_vault import (
    SecretVault,
    MAX_VAULT_SECRETS,
    VAULT_VENDORS,
    validate_material,
)
from services.forensic_store import ForensicCaptureStore
from services.license_refresh import LicenseRefresher
from services.response_playbook import (
    EmailChannel,
    ResponseConfig,
    ResponsePlaybook,
    SlackChannel,
)
from services.telemetry import TelemetryBeacon, TelemetryStats
from services.compliance_evidence import build_evidence_bundle
from audit.worm_logger import assert_persistence_posture

# Reused ONLY from the demo module (import-safe; guarded by __main__): the ephemeral
# sandbox IdP, the mock transports, the grant-issuing transport, and the strict grant
# mandate-args model. No other private symbol is touched.
from main import (
    CloudRESTTransport,
    GrantIssuingTransport,
    LegacyMainframeTransport,
    _DemoIdP,
    _GrantMandateArgs,
)


class CloudIAMTransport(BaseTransport):
    """
    The ``cloud_iam`` transport — vends a short-lived, scoped cloud credential for an
    authorized call instead of dispatching to a fixed backend.

    The alias's ``target`` is the ``env_id`` of a stored ``CloudEnvironment`` binding.
    On execute we (1) resolve the binding for the caller's tenant, (2) defense-in-depth
    check its compartment matches the caller's compartment (the alias's compartment gate
    already enforced entitlement; this ensures the binding wasn't mis-scoped), then
    (3) vend via the broker. The vended credential rides back in ``TransportResult.echo``
    so the pipeline can hand it to the agent — it is NEVER written to WORM (dispatch runs
    AFTER the ALLOW record, and the secret material never enters the audit ctx).

    A missing binding, a compartment mismatch, or a vend failure is a fail-closed
    TRANSPORT_ERROR (opaque to the agent), exactly like any other backend failure.
    """

    def __init__(
        self,
        store: CloudEnvironmentStore,
        sandbox_mode: bool,
        vault: Optional[SecretVault] = None,
        worm: Optional[WormLogger] = None,
    ) -> None:
        self._store = store
        self._broker = CloudBroker(sandbox_mode=sandbox_mode, vault=vault, worm=worm)

    async def execute(self, intent: AuthorizedIntent, target: str) -> TransportResult:
        identity = intent.identity
        env = await self._store.get(identity.tenant_id, target)
        if env is None:
            return TransportResult(
                ok=False, target=target, status_code=404, detail="no cloud environment"
            )
        # Defense in depth: a compartmented binding may only serve its own compartment.
        if env.compartment is not None and env.compartment != identity.compartment:
            return TransportResult(
                ok=False, target=target, status_code=403, detail="environment scope mismatch"
            )
        vended = await self._broker.vend(
            env, tenant_id=identity.tenant_id, request_nonce=intent.correlation_id
        )
        return TransportResult(
            ok=True,
            target=target,
            status_code=200,
            detail=vended.fingerprint,
            # The credential envelope for the agent. `_credential` (secret material) is
            # peeled off by the pipeline into the receipt and never reaches WORM.
            echo={
                "provider": vended.provider,
                "region": vended.region,
                "expires_in": vended.expires_in,
                "simulated": vended.simulated,
                "fingerprint": vended.fingerprint,
                "_credential": vended.material,
            },
        )


# --- Constants shared across handlers. --------------------------------------------
_WORM_SEQ_KEY = "mcpip:worm:seq"
_WORM_EPOCH_NUM_KEY = "mcpip:worm:epoch:num"
# Repo/app root (``/app`` in the image) — the base dir the signed integrity
# manifest's relative paths are resolved against.
_REPO_ROOT = Path(__file__).resolve().parent.parent
# Poll interval for the lifespan task that mirrors the last sealed epoch number
# into the ``mcpip_worm_epoch`` gauge (kept off /readyz to stay dependency-minimal).
_EPOCH_GAUGE_INTERVAL_S = 15.0
# Off-hot-path audit-integrity monitor cadence (a fresh verify_chain pass). Longer
# than the epoch-gauge mirror since a full chain verification is heavier than a GET.
_AUDIT_INTEGRITY_INTERVAL_S = 300.0
_AUDIT_LOG = logging.getLogger("mcpip.audit")
_CORRELATION_HEADER = "X-MCPIP-Correlation-Id"
# Hard ceiling on the raw request body, enforced at the ASGI edge BEFORE any JSON
# parsing, model validation, or authentication runs (pre-auth DoS gate). Comfortably
# above a legitimate envelope (a 64 KiB max raw-arguments string + JWT + trace) while
# rejecting the multi-MB bodies an unauthenticated attacker would use to force full
# in-memory JSON parsing at the single choke point.
MAX_REQUEST_BODY_BYTES = 256 * 1024
_STEP_UP_MESSAGE = (
    "Step-up required: approve in your enrolled authenticator to obtain a one-time "
    "code, then resubmit with pin + challenge_id."
)
# The half-circle glyph — the product mark surfaced on the liveness probe.
_GLYPH = "◐"
# Fixed synthetic compartment UUID used ONLY to equalize the Redis work of a denial that
# short-circuits at alias resolution (unknown / cross-tenant) with one that reaches the
# compartment gate (compartment-denied). It is never registered as a real compartment, so
# a grant can never be keyed under it — the decoy GET is always a nil-return miss, exactly
# like a compartment-denied caller's grant miss. See ``_resolve_alias`` (timing-uniform
# denial: closes the cross-compartment alias-existence oracle).
_TIMING_DECOY_COMPARTMENT = "00000000-0000-4000-8000-000000000000"


# ---------------------------------------------------------------------------
# Event-loop policy — install uvloop as the default serving loop (item 1).
# ---------------------------------------------------------------------------


def _install_uvloop() -> str:
    """Install uvloop as the process event-loop policy, or fall back cleanly.

    Returns the loop backend name for the startup banner / ``/healthz`` field.
    uvicorn's own ``--loop`` still governs the served loop; installing the policy
    here makes uvloop the default under ``--loop auto`` and under any direct
    ``asyncio.run`` that imports this module in the worker process. A missing or
    broken uvloop degrades to stdlib asyncio with ZERO behavior change — this is a
    pure performance affordance and must never fail boot.

    The demo (``main.py``) does not import ``app.main``, so this policy never touches
    the demo's ``asyncio.run`` — the "no behavior change" regression bar is satisfied
    automatically. ``uvloop.install()`` already sets the policy; we deliberately do NOT
    also call ``asyncio.set_event_loop_policy`` (double-setting under uvicorn risks a
    conflicting loop).
    """
    try:
        import uvloop  # uvloop 0.22 is present in the venv/image.

        uvloop.install()
        return "uvloop"
    except Exception:  # noqa: BLE001 — availability-only; never fail boot on this.
        return "asyncio"


_LOOP_BACKEND = _install_uvloop()


# ---------------------------------------------------------------------------
# Composition root — built ONCE at import; shared across stateless requests.
# ---------------------------------------------------------------------------


@dataclass
class Components:
    """The fully-wired engine graph plus its transport table and sandbox IdP.

    The Redis-independent ingredients (``resolver``, ``worm_private_key``) are held so
    the Redis-bound trio (``auth`` + its ``PinValidator`` + ``worm``) can be rebuilt on
    the running event loop inside the lifespan — see ``_rebind_redis``. Everything else
    is wired once at import.
    """

    settings: Settings
    resolver: TokenResolver
    worm_private_key: Ed25519PrivateKey
    redis_client: redis.Redis
    auth: AuthEngine
    obf: ObfuscatorService
    registry: AliasRegistry
    grants: GrantStore
    # ReBAC relation-tuple PROJECTION (Zanzibar-style) backing the operator-only, admin-
    # gated Knowledge-Graph relation read. A best-effort projection of committed grants —
    # NOT an authorization source: the pipeline NEVER consults it. Injected into
    # ``grants`` so ``issue``/``revoke`` project/remove the member tuple additively, and
    # rebound with Redis alongside ``grants`` (see ``_rebind_redis``).
    relations: RelationTupleStore
    quarantine: QuarantineStore
    # Admin-issued principal kill-switch. Consulted on the hot path right after the
    # quarantine gate; mutated only by the CAP_DIRECTORY_ADMIN-gated /v1/admin
    # endpoints. A DENY-only control — it never mints identity.
    revocation: RevocationStore
    # Attenuated session delegation grants (docs/SESSION_DELEGATION_DESIGN.md §2-4).
    # Consulted on the hot path ONLY for tokens carrying a delegation_id claim;
    # mutated by /v1/delegate (any authenticated session — registration can only
    # NARROW its own authority) and the admin/parent revoke surfaces. DENY-only in
    # effect: it intersects, never widens, and never mints identity.
    delegation: DelegationStore
    # Operator skill kill-switch. Consulted on the hot path after alias resolution;
    # mutated only by the CAP_DIRECTORY_ADMIN-gated /v1/admin/skills endpoints. A
    # DENY-only control — it never edits the alias→target mapping.
    skill_gate: SkillGateStore
    # Operator-registered skills (additive alias overlay). Persisted and loaded into
    # the in-memory registry at boot; ADD-only — it can never override a config alias.
    catalog_overlay: CatalogOverlayStore
    # Community-extension (author-your-own SKILL) submit/review state. A Contributor (any
    # authenticated principal) submits a manifest → PENDING; a Reviewer (CAP_CATALOG_REVIEWER)
    # approves → the skill is minted through the SAME additive overlay path as an operator
    # register_skill, its manifest sha256 pinned for rug-pull defense. Tenant-scoped; a
    # reviewer only ever reaches its own tenant's queue. Never mints identity, never repoints.
    extension_submissions: ExtensionSubmissionStore
    # Verified-publisher allow-list store (registry governance, X3). A reviewer-PINNED,
    # per-tenant set of allowed publisher NAMESPACES consulted fail-closed at registry-
    # server approve + boot — NEVER on the auth hot path, NEVER a live PKI/registry fetch.
    # Read/written ONLY via the CAP_CATALOG_REVIEWER-gated /v1/admin/extensions/publishers
    # endpoints. A trust-rail control — it never mints identity, never repoints an alias.
    # Rebound on the running loop in the lifespan (Redis-bound) — see ``_rebind_redis``.
    registry_publishers: VerifiedPublisherStore
    # Deny-only policy overlay (velocity + amount ceiling) + its per-tenant policy
    # document store. The engine is invoked on the hot path between the entitlement/
    # sender-constraint gates and the risk gate; the doc store is read/written ONLY via
    # the CAP_DIRECTORY_ADMIN-gated /v1/admin/policy endpoints. A DENY-only control — it
    # never mints identity, never repoints an alias. Rebound on the running loop in the
    # lifespan (Redis-bound, like auth/worm) — see ``_rebind_redis``.
    policy: PolicyProvider
    policy_docs: PolicyDocStore
    # Community-gate seam (DENY-ONLY, Phase 2). Evaluated on the hot path at step 4c′
    # (right after the mandate gate, adjacent to the policy gate). The default is a strict
    # NO-OP provider — the honest "no community gate engine configured" state — so no gates
    # are enforced until a CEL gate engine is registered (docs/integrate/EXTENSIBILITY.md §8). It is
    # deny-only: it can only ever ADD a POLICY_GATE_DENIED, never mint identity or repoint.
    # NOT Redis-bound (stateless), so it is wired once at build and is NOT part of the
    # ``_rebind_redis`` set.
    community_gate: CommunityGateProvider
    # Operator directory (org chart + RBAC) persistence. NON-authoritative metadata:
    # the authorization pipeline NEVER consults it; it never mints identity.
    directory: DirectoryStore
    # Cloud IAM environment bindings (which role a compartment may assume). Holds NO
    # cloud secret — the gateway assumes the role with its own host identity and vends
    # a short-lived scoped credential per authorized cloud_iam call.
    cloud_env: CloudEnvironmentStore
    # Environment secret vault (optional operator broker-credential store, encrypted
    # at rest under vault_master_key). None when no master key is configured in
    # production — the feature is then absent, never plaintext. Values are spent only
    # by the broker; no endpoint ever returns them.
    vault: Optional[SecretVault]
    # Held (like worm_private_key) so the Redis-bound set can be rebuilt on the running
    # event loop inside the lifespan — see ``_rebind_redis``.
    vault_master_key: Optional[bytes]
    # Forensic payload capture store (optional admin/investigator side-channel, encrypted
    # at rest under forensic_master_key). None when capture is off (production default) OR
    # the dedicated master key is absent — the pipeline capture hook is then a no-op and
    # the retrieval endpoint 404s. Never an agent-facing surface; retrieval is
    # CAP_FORENSIC_READ-gated + WORM-audited. Held-key mirrors vault_master_key so the
    # store is rebuilt on the running loop in the lifespan (see ``_rebind_redis``).
    forensic: Optional[ForensicCaptureStore]
    forensic_master_key: Optional[bytes]
    # Opt-in principal-pseudonymization HMAC key (None ⇒ feature OFF, raw delegation-actor
    # identifiers recorded to WORM as today). Held like the master keys; not Redis-bound.
    pseudonym_key: Optional[bytes]
    # Out-of-band authenticator webhook signing secret (raw bytes), loaded once at boot.
    # None in sandbox (the Redis stash+peek channel needs no secret) and in an
    # unconfigured production deploy (delivery is then ABSENT and every PIN_REQUIRED
    # staging fails closed). Held (like the master keys) so the Redis-bound channel is
    # rebuilt on the running loop in the lifespan — see ``_rebind_redis``.
    authn_webhook_secret: Optional[bytes]
    # USER-BASED 2FA (per-principal RFC 6238 TOTP): master key + enrollment store + the
    # TOTP-gated encrypted OTP stash channel (the reveal path). All None when the feature
    # is absent (no key configured in production) — the /v1/authenticator enrollment and
    # reveal endpoints then 404/deny opaquely. The key is held (like the master keys) so
    # the Redis-bound pair is rebuilt on the running loop in the lifespan (_rebind_redis).
    authn_totp_key: Optional[bytes]
    authn_enrollment: Optional[AuthenticatorEnrollmentStore]
    authn_totp: Optional[TotpVaultAuthenticatorChannel]
    worm: WormLogger
    # Opt-in VENDOR telemetry — the ALWAYS-wired, Redis-bound aggregate store (governed-
    # agent HLL cardinality + decision totals, tenant-prefixed). record_agent/record_decision
    # are cheap best-effort side effects on the auth path (swallow-only — a Redis hiccup can
    # NEVER fail a decision); read_tenant backs GET /v1/admin/stats. Only aggregate integers
    # ever leave the box. Redis-bound, so rebuilt on a Redis rebind (see ``_rebind_redis``).
    telemetry_stats: TelemetryStats
    # Admin-managed operator/team roster (email-keyed, per-tenant). A MANAGEMENT surface only
    # — its ``role`` label authorizes NOTHING (the role-claim invariant holds); identity +
    # authz stay JWT + capabilities, and nothing here is read on the auth hot path. Managed
    # via the CAP_DIRECTORY_ADMIN-gated /v1/admin/users endpoints. Redis-bound, so rebuilt on
    # a Redis rebind (see ``_rebind_redis``).
    operator_users: OperatorUserStore
    # The OPTIONAL off-hot-path beacon SENDER. Present only when telemetry is enabled + a URL
    # is configured + NOT sandbox (an air-gapped/offline/opt-out deploy never phones home);
    # None otherwise. Scheduled as ONE lifespan interval task; every send failure is dropped
    # to a metric — never observable to a decision. Reads the boot-verified license (tier/id)
    # ONLY; performs NO license refresh and adds NO trust root. NOT Redis-bound itself (it
    # reaches the live telemetry_stats via a getter), so it is wired once and never rebound.
    telemetry: Optional[TelemetryBeacon]
    # OPTIONAL off-hot-path license REFRESH. Present only when ``license_refresh_url`` is set
    # AND the process booted with a license AND the license-root public key path is known
    # (an air-gapped/sandbox/no-license deploy never pulls). Scheduled as ONE lifespan
    # interval daemon; every failure is swallowed to a metric and RETAINS the last-good
    # license — a refresh can NEVER block/flip a decision (the license gates BOOT only), NEVER
    # add a trust root, NEVER accept a forged license, NEVER fail open to unlicensed, NEVER
    # brick. Its setter atomically swaps ``_components.license``. NOT Redis-bound (reaches the
    # live graph via getter/setter closures), so wired once and never rebound.
    license_refresher: Optional[LicenseRefresher]
    # OPTIONAL deny-response playbook. Present only when ``response_enabled`` AND at least one
    # action is configured (auto-quarantine on OR a channel set). Scheduled as ONE lifespan
    # interval daemon that tails the durable WORM buffer for high-signal deny events and
    # responds deterministically (freeze + alert) off the hot path; every failure is swallowed
    # to a metric — a response can NEVER block/flip a decision (it reads already-committed
    # records). Reaches the live WORM / quarantine / Redis via getters, so it is rebind-safe
    # and wired once.
    response_playbook: Optional[ResponsePlaybook]
    transports: dict[str, BaseTransport]
    # Present only in sandbox mode when no external IdP key is configured; the
    # /v1/dev/token helper uses it. None otherwise (and in production).
    demo_idp: Optional[_DemoIdP]
    # The boot-verified entitlement document (None only in sandbox with no license
    # configured). Held for operator visibility ONLY — the authorization pipeline
    # NEVER consults it: licensing gates process boot, never per-request decisions.
    license: Optional[License]


def _assert_secure_key_file(path: str, *, sandbox_mode: bool, label: str) -> None:
    """
    Harden an operator-provided PRIVATE key / secret file at load (SC-12 / IA-5).

    In production a key protected only by filesystem permissions must not be
    group/world *writable* — a swappable signing key or master secret is a
    fail-closed boot refusal (whoever can rewrite it controls identity/audit/vault).
    Group/world *readable* or not-owned-by-the-runtime-user is a loud WARNING, not a
    refusal: a common Kubernetes secret-volume default is 0644 read-only, a
    legitimate-if-loose pattern, so we recommend tightening to 0600/0400 (or setting
    the secret volume ``defaultMode``) rather than breaking that deployment. Sandbox
    dev keys (auto-provisioned 0600) are exempt. Only PRIVATE material is checked —
    a public verification key is never passed here.
    """
    if sandbox_mode:
        return
    try:
        st = os.stat(path)
    except OSError:
        # The caller's own read fails closed with a clearer error; don't mask it.
        return
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o022:
        raise RuntimeError(
            f"{label} key file {path} is group/world-writable (mode {oct(mode)}); "
            "production refuses a swappable key/secret — chmod 600."
        )
    if (mode & 0o044) or st.st_uid != os.getuid():
        print(
            f"MCPIP WARNING: {label} key file {path} is group/world-readable or not "
            f"owned by the runtime user (mode {oct(mode)}, uid {st.st_uid}); tighten "
            "to 0600/0400 or set the k8s secret volume defaultMode.",
            file=sys.stderr,
            flush=True,
        )


def _load_verifying_pem(settings: Settings) -> tuple[bytes, Optional[_DemoIdP]]:
    """
    Resolve the JWT verification key.

    With ``jwt_public_key_path`` set, load the trusted IdP's PEM from disk. Otherwise
    (only reachable in sandbox mode — enforced in ``_build_components``) boot the
    in-process ``_DemoIdP`` and return its public PEM plus the IdP handle so the
    dev-token endpoint can mint against the same keypair.
    """
    if settings.jwt_public_key_path is not None:
        return Path(settings.jwt_public_key_path).read_bytes(), None
    demo_idp = _DemoIdP()
    return demo_idp.public_pem, demo_idp


# The sandbox dev WORM key lives under the gitignored ``.keys/`` directory so it
# PERSISTS across gateway restarts. Persistence matters even in sandbox: the epoch chain
# in a long-lived Redis outlives the process, and a per-boot ephemeral key made every
# restart render the prior (legitimate) epochs unverifiable — a false "first bad
# epoch: 0" tamper report. One stable dev key keeps an honest chain verifiable.
_SANDBOX_WORM_KEY_PATH = Path(__file__).resolve().parent.parent / ".keys" / "sandbox_worm_ed25519.pem"


def _load_worm_key(settings: Settings) -> Ed25519PrivateKey:
    """
    Resolve the WORM signing key.

    With ``worm_signing_key_path`` set, load a PKCS8 Ed25519 private key from disk and
    assert its type (a non-Ed25519 key is a fail-closed boot error). Otherwise (only
    reachable in sandbox mode) load-or-create the PERSISTENT dev keypair at
    ``_SANDBOX_WORM_KEY_PATH`` (0600, exclusive create). Corrupt/foreign key material at
    the dev path is a fail-closed boot error — never silently rotate a signing key
    (rotation is exactly what makes an existing chain read as tampered).
    """
    if settings.worm_signing_key_path is not None:
        _assert_secure_key_file(
            settings.worm_signing_key_path,
            sandbox_mode=settings.sandbox_mode,
            label="WORM signing",
        )
        loaded = load_pem_private_key(
            Path(settings.worm_signing_key_path).read_bytes(), password=None
        )
        if not isinstance(loaded, Ed25519PrivateKey):
            raise RuntimeError("WORM signing key must be an Ed25519 private key")
        return loaded

    path = _SANDBOX_WORM_KEY_PATH
    if path.exists():
        loaded = load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise RuntimeError(
                f"sandbox dev WORM key at {path} is not an Ed25519 private key — "
                "delete the file to regenerate (this will orphan any existing chain)"
            )
        return loaded

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    path.parent.mkdir(mode=0o700, exist_ok=True)
    try:
        # O_EXCL: never overwrite — a concurrent worker that lost the race loads instead.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        loaded = load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise RuntimeError(
                f"sandbox dev WORM key at {path} is not an Ed25519 private key"
            ) from None
        return loaded
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    print(
        f"MCPIP SANDBOX: generated persistent dev WORM signing key at {path} "
        "(kept across restarts so the audit chain stays verifiable)",
        file=sys.stderr,
        flush=True,
    )
    return key


# The sandbox dev vault master key lives beside the WORM dev key (gitignored .keys/):
# persistent across restarts so stored broker credentials stay decryptable, 0600.
_SANDBOX_VAULT_KEY_PATH = Path(__file__).resolve().parent.parent / ".keys" / "sandbox_vault_aesgcm.key"


def _load_vault_key(settings: Settings) -> Optional[bytes]:
    """
    Resolve the vault's AES-256 master key.

    With ``vault_key_path`` set, load exactly 32 raw bytes from disk (anything else is
    a fail-closed boot error). In production WITHOUT a configured path the vault
    feature is ABSENT — return None; any binding that references a vault entry then
    fails closed at vend time (never a silent plaintext fallback). In sandbox,
    load-or-create a persistent dev key (0600, exclusive create), mirroring the
    sandbox WORM key: a per-boot key would orphan every stored secret on restart.
    """
    if settings.vault_key_path is not None:
        _assert_secure_key_file(
            settings.vault_key_path,
            sandbox_mode=settings.sandbox_mode,
            label="vault master",
        )
        key = Path(settings.vault_key_path).read_bytes()
        if len(key) != 32:
            raise RuntimeError("vault master key file must contain exactly 32 raw bytes")
        return key
    if not settings.sandbox_mode:
        return None

    path = _SANDBOX_VAULT_KEY_PATH
    if path.exists():
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError(
                f"sandbox dev vault key at {path} is not 32 bytes — delete the file to "
                "regenerate (this orphans any stored vault secrets)"
            )
        return key
    key = os.urandom(32)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    try:
        # O_EXCL: never overwrite — a concurrent worker that lost the race loads instead.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError(f"sandbox dev vault key at {path} is not 32 bytes") from None
        return key
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    print(
        f"MCPIP SANDBOX: generated persistent dev vault master key at {path}",
        file=sys.stderr,
        flush=True,
    )
    return key


# The sandbox dev forensic master key lives beside the WORM/vault dev keys (gitignored
# .keys/): persistent across restarts so captured payloads stay decryptable, 0600. It is
# DEDICATED to forensics — never the vault or WORM key — so a forensic-key compromise
# cannot decrypt broker credentials and vice versa.
_SANDBOX_FORENSIC_KEY_PATH = (
    Path(__file__).resolve().parent.parent / ".keys" / "sandbox_forensic_aesgcm.key"
)


def _load_forensic_key(settings: Settings) -> Optional[bytes]:
    """
    Resolve the forensic store's AES-256 master key (mirrors ``_load_vault_key``).

    With ``forensic_key_path`` set, load exactly 32 raw bytes from disk (anything else is
    a fail-closed boot error). In production WITHOUT a configured path the forensic
    feature is ABSENT — return None; the flag alone is never enough, so a flag-on/key-off
    production deploy captures NOTHING (fail-closed, never a plaintext fallback). In
    sandbox, load-or-create a persistent dev key (0600, exclusive create): a per-boot key
    would orphan every captured payload on restart.

    This is only ever called when effective capture is ON, so a sandbox key is
    auto-provisioned solely when capture is actually active.
    """
    if settings.forensic_key_path is not None:
        _assert_secure_key_file(
            settings.forensic_key_path,
            sandbox_mode=settings.sandbox_mode,
            label="forensic master",
        )
        key = Path(settings.forensic_key_path).read_bytes()
        if len(key) != 32:
            raise RuntimeError("forensic master key file must contain exactly 32 raw bytes")
        return key
    if not settings.sandbox_mode:
        return None

    path = _SANDBOX_FORENSIC_KEY_PATH
    if path.exists():
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError(
                f"sandbox dev forensic key at {path} is not 32 bytes — delete the file to "
                "regenerate (this orphans any captured payloads)"
            )
        return key
    key = os.urandom(32)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    try:
        # O_EXCL: never overwrite — a concurrent worker that lost the race loads instead.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError(f"sandbox dev forensic key at {path} is not 32 bytes") from None
        return key
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    print(
        f"MCPIP SANDBOX: generated persistent dev forensic master key at {path}",
        file=sys.stderr,
        flush=True,
    )
    return key


def _resolve_forensic_key(settings: Settings) -> Optional[bytes]:
    """
    Decide whether forensic capture is active and, if so, return its master key.

    The per-env default is resolved HERE (the composition root), never baked into the
    Settings field: an unset flag is ON in sandbox (full debugging visibility) and OFF in
    production (the fail-safe default); an explicit ``MCPIP_FORENSIC_CAPTURE`` always
    wins. Even when the flag is ON, production capture additionally requires a real
    dedicated key file — flag-on/key-off is a feature that is ABSENT (fail-closed, never
    plaintext). Returns None whenever capture is off OR the key is absent, in which case
    the store is not built (``_components.forensic is None``): the capture hook no-ops and
    the retrieval endpoint 404s.
    """
    effective_capture = (
        settings.forensic_capture
        if settings.forensic_capture is not None
        else settings.sandbox_mode
    )
    if not effective_capture:
        return None
    key = _load_forensic_key(settings)
    if not settings.sandbox_mode:
        if key is not None:
            # Loud advisory: raw-payload reconstruction is recoverable in PRODUCTION.
            print(
                "\n"
                "  ############################################################\n"
                "  # MCPIP: FORENSIC PAYLOAD CAPTURE IS LIVE IN PRODUCTION.    #\n"
                "  # The REAL query (alias + normalized arguments + identity   #\n"
                "  # context) of each authorize is captured, encrypted at      #\n"
                "  # rest, and readable ONLY via CAP_FORENSIC_READ + WORM       #\n"
                "  # audit. Secrets stay redacted. Disable with                 #\n"
                "  # MCPIP_FORENSIC_CAPTURE=false to capture nothing.           #\n"
                "  ############################################################\n",
                file=sys.stderr,
                flush=True,
            )
        else:
            # Flag on but no key: fail-closed absent, never a plaintext fallback.
            print(
                "MCPIP: MCPIP_FORENSIC_CAPTURE is enabled but no MCPIP_FORENSIC_KEY_PATH "
                "is configured — forensic capture is ABSENT (fail-closed, never "
                "plaintext). Provide a 32-byte key file to activate it.",
                file=sys.stderr,
                flush=True,
            )
    return key


def _load_authn_webhook_secret(settings: Settings) -> Optional[bytes]:
    """
    Resolve the authenticator-webhook HMAC signing secret (mirrors ``_load_vault_key`` /
    ``_load_forensic_key``).

    With ``authn_webhook_secret_path`` set, load the raw secret from disk and require at
    least 32 bytes (anything shorter is a fail-closed boot error — a step-up delivery
    signature must not be forgeable). Unset -> return None: the webhook channel is then
    only viable if BOTH url and secret are absent (production delivery ABSENT) — a url
    set without a secret is rejected in ``_build_authn_channel``. Sandbox never consults
    this (its stash+peek channel needs no secret).
    """
    if settings.authn_webhook_secret_path is None:
        return None
    _assert_secure_key_file(
        settings.authn_webhook_secret_path,
        sandbox_mode=settings.sandbox_mode,
        label="authenticator webhook",
    )
    secret = Path(settings.authn_webhook_secret_path).read_bytes()
    if len(secret) < 32:
        raise RuntimeError(
            "authenticator webhook signing secret must be at least 32 raw bytes"
        )
    return secret


# The sandbox dev pseudonymization key lives beside the other dev keys (gitignored
# .keys/): persistent across restarts so a pseudonym stays STABLE for the same subject
# (a per-boot key would make the same person map to different pseudonyms over time,
# breaking linkage/erasure).
_SANDBOX_AUTHN_TOTP_KEY_PATH = (
    Path(__file__).resolve().parent.parent / ".keys" / "sandbox_authn_totp.key"
)


def _load_authn_totp_key(settings: Settings) -> Optional[bytes]:
    """
    Resolve the user-based-2FA master key (mirrors ``_load_forensic_key``).

    Production: requires an explicit 32-byte ``MCPIP_AUTHN_TOTP_KEY_PATH`` — absent means
    the per-user authenticator feature is ABSENT (fail-closed: enrollment/reveal endpoints
    404 and no TOTP stash channel is composed; a configured webhook channel is unaffected).
    Sandbox: load-or-create a persistent dev key (0600, exclusive create) so enrollments
    survive restarts — a per-boot key would orphan every enrolled authenticator.
    """
    if settings.authn_totp_key_path is not None:
        _assert_secure_key_file(
            settings.authn_totp_key_path,
            sandbox_mode=settings.sandbox_mode,
            label="authenticator TOTP master",
        )
        key = Path(settings.authn_totp_key_path).read_bytes()
        if len(key) != 32:
            raise RuntimeError(
                "authenticator TOTP master key file must contain exactly 32 raw bytes"
            )
        return key
    if not settings.sandbox_mode:
        return None

    path = _SANDBOX_AUTHN_TOTP_KEY_PATH
    if path.exists():
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError(
                f"sandbox dev authenticator key at {path} is not 32 bytes — delete the "
                "file to regenerate (this orphans existing enrollments)"
            )
        return key
    key = os.urandom(32)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    try:
        # O_EXCL: never overwrite — a concurrent worker that lost the race loads instead.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError(
                f"sandbox dev authenticator key at {path} is not 32 bytes"
            ) from None
        return key
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    print(
        f"MCPIP SANDBOX: generated persistent dev authenticator TOTP master key at {path}",
        file=sys.stderr,
        flush=True,
    )
    return key


_SANDBOX_PSEUDONYM_KEY_PATH = (
    Path(__file__).resolve().parent.parent / ".keys" / "sandbox_pseudonym_hmac.key"
)


def _pseudonymize_principal(value: str, key: Optional[bytes]) -> str:
    """
    Opt-in privacy transform for a delegation-actor identifier recorded to WORM.

    ``key is None`` (the default, feature OFF) ⇒ return the value UNCHANGED — the raw
    identifier is recorded exactly as today. With a key ⇒ return a stable keyed-HMAC
    pseudonym (``psn_`` + truncated HMAC-SHA256 hex): the natural-person link is
    crypto-shreddable (destroy the key and no one can re-derive or confirm the pseudonym)
    while the value is deterministic (the same subject → the same pseudonym, so audit
    correlation still works) and one-way. Pure — takes the key explicitly for testability.
    """
    if key is None:
        return value
    return "psn_" + hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


def _load_pseudonym_key(settings: Settings) -> Optional[bytes]:
    """
    Resolve the principal-pseudonymization HMAC key (mirrors ``_load_forensic_key``).

    OFF (the default) ⇒ None: no key, raw identifiers recorded (byte-identical to today).
    ON with ``pseudonym_key_path`` set ⇒ load ≥32 raw bytes (shorter is a fail-closed boot
    error). ON in PRODUCTION without a key path ⇒ a fail-closed BOOT error (never a silent
    disable of the control). ON in SANDBOX without a path ⇒ load-or-create a persistent dev
    key (0600, exclusive create); a per-boot key would make the same subject map to a new
    pseudonym each restart, breaking linkage.
    """
    if not settings.pseudonymize_principals:
        return None
    if settings.pseudonym_key_path is not None:
        _assert_secure_key_file(
            settings.pseudonym_key_path,
            sandbox_mode=settings.sandbox_mode,
            label="pseudonym",
        )
        key = Path(settings.pseudonym_key_path).read_bytes()
        if len(key) < 32:
            raise RuntimeError("pseudonym key file must contain at least 32 raw bytes")
        return key
    if not settings.sandbox_mode:
        raise RuntimeError(
            "MCPIP_PSEUDONYMIZE_PRINCIPALS=true requires MCPIP_PSEUDONYM_KEY_PATH in "
            "production (a dedicated >=32-byte HMAC key) — flag-on/key-off would silently "
            "disable the erasure control"
        )
    path = _SANDBOX_PSEUDONYM_KEY_PATH
    if path.exists():
        key = path.read_bytes()
        if len(key) < 32:
            raise RuntimeError(
                f"sandbox dev pseudonym key at {path} is < 32 bytes — delete it to regenerate"
            )
        return key
    key = os.urandom(32)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = path.read_bytes()
        if len(key) < 32:
            raise RuntimeError(f"sandbox dev pseudonym key at {path} is < 32 bytes") from None
        return key
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    print(
        f"MCPIP SANDBOX: generated persistent dev pseudonymization key at {path}",
        file=sys.stderr,
        flush=True,
    )
    return key


_SANDBOX_WORM_CONTENT_KEY_PATH = (
    Path(__file__).resolve().parent.parent / ".keys" / "sandbox_worm_content_aesgcm.key"
)


def _load_worm_content_key(settings: Settings) -> Optional[bytes]:
    """
    Resolve the WORM at-rest content-encryption key (mirrors ``_load_forensic_key``).

    OFF (the default) ⇒ None: the event body is stored as a plaintext dict (byte-identical
    to today). ON with ``worm_content_key_path`` ⇒ load exactly 32 raw bytes (AES-256;
    anything else is a fail-closed boot error). ON in PRODUCTION without a path ⇒ a
    fail-closed BOOT error. ON in SANDBOX without a path ⇒ load-or-create a persistent
    0600 dev key (a per-boot key would orphan every previously-encrypted event body).
    """
    if not settings.encrypt_worm_at_rest:
        return None
    if settings.worm_content_key_path is not None:
        _assert_secure_key_file(
            settings.worm_content_key_path,
            sandbox_mode=settings.sandbox_mode,
            label="WORM content",
        )
        key = Path(settings.worm_content_key_path).read_bytes()
        if len(key) != 32:
            raise RuntimeError("WORM content key file must contain exactly 32 raw bytes")
        return key
    if not settings.sandbox_mode:
        raise RuntimeError(
            "MCPIP_ENCRYPT_WORM_AT_REST=true requires MCPIP_WORM_CONTENT_KEY_PATH in "
            "production (a dedicated 32-byte AES-256 key) — flag-on/key-off would silently "
            "disable at-rest confidentiality"
        )
    path = _SANDBOX_WORM_CONTENT_KEY_PATH
    if path.exists():
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError(
                f"sandbox dev WORM content key at {path} is not 32 bytes — delete to regenerate"
            )
        return key
    key = os.urandom(32)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError(f"sandbox dev WORM content key at {path} is not 32 bytes") from None
        return key
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    print(
        f"MCPIP SANDBOX: generated persistent dev WORM content key at {path}",
        file=sys.stderr,
        flush=True,
    )
    return key


def _load_worm_content_key_fallbacks(settings: Settings) -> tuple[bytes, ...]:
    """
    Resolve the RETIRED WORM content keys retained across a rotation (SOC 2 C1.1).

    OFF, or no ``worm_content_key_fallback_paths`` ⇒ empty tuple (single-key behavior). The
    active ``worm_content_key_path`` always seals new events; each retained key here (an
    ``os.pathsep``-separated list of 32-byte files) is additionally tried when READING, so
    bodies sealed under a superseded key stay readable after the active key rotates. Each
    file must be exactly 32 bytes and pass the same permission lint as the active key — a
    malformed retained key is a fail-closed boot error, never a silently dropped key that
    would leave old bodies unreadable.
    """
    if not settings.encrypt_worm_at_rest or not settings.worm_content_key_fallback_paths:
        return ()
    keys: list[bytes] = []
    for raw in settings.worm_content_key_fallback_paths.split(os.pathsep):
        candidate = raw.strip()
        if not candidate:
            continue
        _assert_secure_key_file(
            candidate, sandbox_mode=settings.sandbox_mode, label="WORM content (retired)"
        )
        key = Path(candidate).read_bytes()
        if len(key) != 32:
            raise RuntimeError(
                f"retired WORM content key file {candidate!r} must contain exactly 32 raw bytes"
            )
        keys.append(key)
    return tuple(keys)


def _build_authn_channel(
    settings: Settings,
    redis_client: redis.Redis,
    authn_webhook_secret: Optional[bytes],
    authn_totp_key: Optional[bytes],
) -> tuple[Optional[BaseAuthenticatorChannel], Optional[TotpVaultAuthenticatorChannel]]:
    """
    Compose the out-of-band OTP delivery channel set (runs inside ``_wire_redis_bound``
    so a Redis rebind reconstructs every Redis-bound channel against the fresh client).
    Returns ``(delivery_channel, totp_stash_channel)`` — the second handle is the same
    object the reveal endpoint reads from, or None when user-based 2FA is absent.

    Sandbox: the runnable-demo ``SandboxRedisAuthenticatorChannel`` (stash + peek),
    fanned out with the TOTP-gated encrypted stash (the sandbox auto-provisions the
    master key, so enrollment/reveal are demonstrable end-to-end).

    Production: the signed HTTPS ``WebhookAuthenticatorChannel`` when BOTH url and
    secret are configured (exactly one set is a fail-closed BOOT error), AND/OR the
    ``TotpVaultAuthenticatorChannel`` when the TOTP master key is configured — both
    present fans out to both (fail-closed as a unit: any delivery failure aborts the
    staging with ``OTP_DELIVERY_FAILED``). NEITHER configured -> (None, None): delivery
    is ABSENT and every PIN_REQUIRED staging fails closed rather than staging a
    challenge no authenticator can answer.
    """
    totp_channel = (
        TotpVaultAuthenticatorChannel(redis_client, authn_totp_key)
        if authn_totp_key is not None
        else None
    )
    if settings.sandbox_mode:
        sandbox = SandboxRedisAuthenticatorChannel(redis_client)
        if totp_channel is None:
            return sandbox, None
        return FanoutAuthenticatorChannel((sandbox, totp_channel)), totp_channel

    url = settings.authn_webhook_url
    if (url is None) != (authn_webhook_secret is None):
        raise RuntimeError(
            "production authenticator webhook requires BOTH "
            "MCPIP_AUTHN_WEBHOOK_URL and MCPIP_AUTHN_WEBHOOK_SECRET_PATH "
            "(a half-configuration is refused, fail-closed)"
        )
    webhook = (
        WebhookAuthenticatorChannel(
            url, authn_webhook_secret, settings.authn_webhook_timeout_s
        )
        if url is not None and authn_webhook_secret is not None
        else None
    )
    channels = tuple(c for c in (webhook, totp_channel) if c is not None)
    if not channels:
        # Unconfigured production: honest ABSENT state. register_lock fails closed.
        return None, None
    if len(channels) == 1:
        return channels[0], totp_channel
    return FanoutAuthenticatorChannel(channels), totp_channel


def _build_community_gate(settings: Settings) -> CommunityGateProvider:
    """
    Compose the deny-only community-gate provider (pipeline step 4c′).

    The shipped default is the strict NO-OP (no gates enforced). OUTBOUND COAZ PEP MODE
    (default OFF): only when BOTH ``external_pdp_enabled`` and ``external_pdp_url`` are set is
    an ``ExternalPdpGateProvider`` appended after the base provider via a ``DenyOnlyGateChain``
    (first deny wins, monotonic — it can only ADD a deny). This composes at the Components
    level and NEVER calls ``register_community_gate_engine`` — so
    ``community_gate_engine_registered()`` stays False and gate-manifest approval is not
    falsely unlocked. With the flag OFF the hot path is byte-identical to before (the base
    provider alone).

    The flag ON with NO url is a HALF-CONFIGURATION and a fail-closed BOOT error (same family
    as the authenticator-webhook / integrity / license half-config refusals): silently
    dropping a deny-only control the operator turned on would leave a security control they
    believe is enforcing ABSENT — that is a fail-OPEN. A url set with the flag OFF is the
    legitimate "staged but disabled" state (the flag is the deliberate on/off switch) and is
    NOT a misconfiguration.
    """
    base = active_community_gate_provider()
    if settings.external_pdp_enabled and not settings.external_pdp_url:
        raise RuntimeError(
            "MCPIP_EXTERNAL_PDP_ENABLED is set without MCPIP_EXTERNAL_PDP_URL "
            "(a half-configuration is refused, fail-closed)"
        )
    if settings.external_pdp_enabled and settings.external_pdp_url:
        return DenyOnlyGateChain(
            [base, ExternalPdpGateProvider(url=settings.external_pdp_url)]
        )
    return base


# The vendor-telemetry install identity lives under the gitignored ``.keys/`` directory.
# BOTH files are minted ONCE, the first time an operator turns the beacon on, and then
# PERSIST across restarts so the vendor sees a STABLE install. They are created ONLY when
# the beacon is actually being constructed (enabled + url + not-sandbox), so a disabled /
# air-gapped / sandbox deploy never even mints a telemetry identity.
#
#   * ``mcpip_install_id``       — a random hex token (secrets.token_hex(16)). It is NOT
#     derived from any tenant / customer / host / license identity — it identifies the
#     INSTALL, nothing about who runs it or what it governs.
#   * ``mcpip_telemetry_secret`` — a random 32-byte per-install HMAC secret used ONLY to
#     sign the beacon body so the vendor can trust the origin. Never logged, never a label,
#     never in the beacon body.
_INSTALL_ID_PATH = Path(__file__).resolve().parent.parent / ".keys" / "mcpip_install_id"
_TELEMETRY_SECRET_PATH = (
    Path(__file__).resolve().parent.parent / ".keys" / "mcpip_telemetry_secret"
)


def _load_or_create_text(path: Path, mint: "Callable[[], str]", label: str) -> str:
    """Load-or-create a persistent text credential file (0600, O_EXCL), mirroring
    ``_load_worm_key``'s create-once discipline. A concurrent worker that loses the
    exclusive-create race reads the winner's value instead of overwriting it."""
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    value = mint()
    path.parent.mkdir(mode=0o700, exist_ok=True)
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text(encoding="utf-8").strip()
    with os.fdopen(fd, "w") as fh:
        fh.write(value)
    print(
        f"MCPIP TELEMETRY: minted persistent {label} at {path} "
        "(random, created once, NOT derived from any tenant/customer/host identity)",
        file=sys.stderr,
        flush=True,
    )
    return value


def _load_or_create_install_identity() -> tuple[str, bytes]:
    """
    Load-or-create the persistent, random telemetry install-id + per-install HMAC secret.

    Called ONLY when the beacon is being constructed (enabled + url + not-sandbox), so a
    disabled / air-gapped / sandbox deploy never mints a telemetry identity. The install-id
    is a random hex token generated ONCE and persisted — NEVER derived from tenant / customer
    / host / license data. The secret is 32 random bytes used only to sign the beacon body.
    """
    install_id = _load_or_create_text(
        _INSTALL_ID_PATH, lambda: secrets.token_hex(16), "telemetry install id"
    )
    secret_hex = _load_or_create_text(
        _TELEMETRY_SECRET_PATH, lambda: secrets.token_hex(32), "telemetry signing secret"
    )
    return install_id, bytes.fromhex(secret_hex)


def _build_telemetry_beacon(
    settings: Settings, components: "Components"
) -> Optional[TelemetryBeacon]:
    """
    Compose the OPTIONAL vendor-telemetry beacon (mirrors ``_build_authn_channel`` /
    ``_build_community_gate``'s opt-in-with-fail-closed-half-config discipline).

    OPT-IN + AIR-GAP: the beacon is built ONLY when ``telemetry_enabled`` AND
    ``telemetry_url`` are set AND the process is NOT in sandbox_mode. If the flag is
    unset/false OR the process is sandboxed, NO beacon is built and NO install-id/secret
    file is minted — an air-gapped / offline / opt-out deployment never phones home and
    never even creates a telemetry identity.

    HALF-CONFIG: the flag ON with NO url is a fail-closed BOOT error (same family as the
    authenticator-webhook / external-PDP / integrity / license half-config refusals) —
    silently dropping a beacon the operator turned on would be dishonest about whether the
    vendor is being told anything. Sandbox with the flag ON is NOT an error (air-gap wins):
    the beacon is simply absent and the local stats read reports the honest air-gap state.
    """
    if not settings.telemetry_enabled:
        return None
    if settings.telemetry_url is None:
        raise RuntimeError(
            "MCPIP_TELEMETRY_ENABLED is set without MCPIP_TELEMETRY_URL "
            "(a half-configuration is refused, fail-closed)"
        )
    if settings.sandbox_mode:
        # Air-gap/opt-out wins: a sandbox deploy never phones home and never mints an
        # install identity, even with the flag on. The local stats read says so honestly.
        print(
            "MCPIP TELEMETRY: enabled but sandbox_mode is on — the beacon is DISABLED "
            "(a sandbox/air-gapped deployment never phones home and mints no install id).",
            file=sys.stderr,
            flush=True,
        )
        return None
    install_id, secret = _load_or_create_install_identity()
    print(
        "\n"
        "  ############################################################\n"
        "  # MCPIP: OPT-IN VENDOR TELEMETRY BEACON IS LIVE.           #\n"
        "  # A best-effort, off-hot-path heartbeat sends ONLY: a      #\n"
        "  # random install id, the license tier/id, the version, an  #\n"
        "  # integer count of governed agent identities, coarse        #\n"
        "  # allow/deny/staged totals, uptime, and a timestamp. NO     #\n"
        "  # tenant/agent/alias/target/secret ever leaves the box.     #\n"
        "  # Disable with MCPIP_TELEMETRY_ENABLED=false. See            #\n"
        "  # docs/operate/TELEMETRY.md.                                         #\n"
        "  ############################################################\n",
        file=sys.stderr,
        flush=True,
    )
    return TelemetryBeacon(
        stats_getter=lambda: components.telemetry_stats,
        url=settings.telemetry_url,
        interval_s=settings.telemetry_interval_s,
        install_id=install_id,
        secret=secret,
        license_getter=lambda: components.license,
    )


def _build_license_refresher(
    settings: Settings, components: "Components"
) -> Optional[LicenseRefresher]:
    """
    Compose the OPTIONAL off-hot-path license refresher (T2, additive + fail-open).

    OPT-IN + AIR-GAP: built ONLY when ``license_refresh_url`` is set AND the process
    booted with a license AND the license-root public key path is known. If the URL is
    unset -> None (today's offline-signed-license behavior, byte-identical). If the URL is
    set but there is nothing/no-key to refresh against (a sandbox/no-license boot), the
    feature is simply ABSENT (an honest notice, NOT a boot error) — a refresh cannot invent
    an entitlement out of the unlicensed state, and no trust root is loaded.

    The candidate is verified against the SAME license-root PEM the boot gate loaded
    (reloaded here) via ``verify_license_bytes`` — no new trust root, no widening. The
    refresh request body rides the T1 beacon payload when the beacon is wired (a single
    round-trip reports usage AND pulls entitlement); otherwise a minimal identity subset of
    the same closed field set. This module NEVER mints a telemetry install-id — it consumes
    the beacon's only when the beacon already minted one (privacy: air-gap/opt-out never
    creates a telemetry identity).
    """
    if settings.license_refresh_url is None:
        return None
    if components.license is None:
        print(
            "MCPIP LICENSE-REFRESH: MCPIP_LICENSE_REFRESH_URL is set but the process "
            "booted without a license — refresh is DISABLED (a refresh never invents an "
            "entitlement from the unlicensed state).",
            file=sys.stderr,
            flush=True,
        )
        return None
    if settings.license_public_key_path is None:
        # A license present without a public-key path cannot happen (the boot gate requires
        # both), but be explicit rather than load a wrong/absent trust root.
        print(
            "MCPIP LICENSE-REFRESH: no license-root public key path configured — refresh "
            "is DISABLED (the candidate could not be verified against the existing root).",
            file=sys.stderr,
            flush=True,
        )
        return None
    try:
        public_key_pem = Path(settings.license_public_key_path).read_bytes()
    except OSError:
        # Same opacity as the boot gate — the path goes only to the log; refresh absent.
        print(
            "MCPIP LICENSE-REFRESH: license-root public key unreadable — refresh DISABLED.",
            file=sys.stderr,
            flush=True,
        )
        return None
    # Ride the T1 beacon payload when the beacon is wired (single round-trip reports usage
    # AND pulls entitlement — the payload already carries the install-id + counts); else post
    # a minimal identity subset with NO install-id. This module NEVER mints a telemetry
    # identity (air-gap/opt-out mints none), so the minimal body deliberately omits it.
    beacon = components.telemetry
    payload_provider = beacon.assemble_payload if beacon is not None else None
    print(
        "MCPIP LICENSE-REFRESH: enabled — a best-effort, off-hot-path pull verifies each "
        "candidate against the EXISTING license-root key and swaps in ONLY a strictly-newer "
        "valid license; any failure retains the last-good license (never fails open, never "
        "adds a trust root). Disable by unsetting MCPIP_LICENSE_REFRESH_URL.",
        file=sys.stderr,
        flush=True,
    )
    return LicenseRefresher(
        url=settings.license_refresh_url,
        public_key_pem=public_key_pem,
        current_getter=lambda: components.license,
        license_setter=lambda lic: setattr(components, "license", lic),
        interval_s=settings.license_refresh_interval_s,
        payload_provider=payload_provider,
    )


def _build_response_playbook(
    settings: Settings, components: "Components"
) -> Optional[ResponsePlaybook]:
    """
    Compose the OPTIONAL deny-response playbook (opt-in deterministic automation loop).

    OPT-IN: built ONLY when ``response_enabled``. HALF-CONFIG (the same fail-closed posture
    as the authenticator-webhook / telemetry / external-PDP boot refusals): enabled but with
    NO possible action — auto-quarantine OFF and no channel configured — is a BOOT error,
    because a playbook that can do nothing is a misconfiguration, not a silent no-op. A bad
    trigger reason (outside the closed ``RESPONSE_TRIGGER_REASONS``) is likewise a boot error
    rather than a silently-dropped rule.

    The active trigger set defaults to the single-shot reasons (``canary_tripped``) when
    unset; the operator widens it only within the closed allow-set. The daemon reaches the
    live WORM logger, quarantine store, and Redis via getters so a Redis rebind is always
    reflected (never a stale reader/actor).
    """
    if not settings.response_enabled:
        return None

    # Resolve the active trigger set against the CLOSED allow-list (fail-closed on a stray).
    if settings.response_trigger_reasons is None:
        active = frozenset(RESPONSE_SINGLE_SHOT_REASONS)
    else:
        requested = {
            r.strip() for r in settings.response_trigger_reasons.split(",") if r.strip()
        }
        unknown = requested - RESPONSE_TRIGGER_REASONS
        if unknown:
            raise RuntimeError(
                "MCPIP_RESPONSE_TRIGGER_REASONS contains reasons outside the allowed set "
                f"{sorted(RESPONSE_TRIGGER_REASONS)} (refused, fail-closed)"
            )
        active = frozenset(requested) or frozenset(RESPONSE_SINGLE_SHOT_REASONS)

    slack: Optional[SlackChannel] = None
    if settings.response_slack_webhook_url:
        slack = SlackChannel(settings.response_slack_webhook_url)
    email: Optional[EmailChannel] = None
    if settings.response_email_host or settings.response_email_from or settings.response_email_to:
        # An email channel needs host + from + to together; a partial config is a boot error.
        if not (
            settings.response_email_host
            and settings.response_email_from
            and settings.response_email_to
        ):
            raise RuntimeError(
                "MCPIP_RESPONSE_EMAIL_* is half-configured — host, from, and to are all "
                "required together (refused, fail-closed)"
            )
        recipients = tuple(
            r.strip() for r in settings.response_email_to.split(",") if r.strip()
        )
        email = EmailChannel(
            host=settings.response_email_host,
            port=settings.response_email_port,
            sender=settings.response_email_from,
            recipients=recipients,
            user=settings.response_email_user,
            password=settings.response_email_password,
        )

    if not settings.response_auto_quarantine and slack is None and email is None:
        raise RuntimeError(
            "MCPIP_RESPONSE_ENABLED is set with no possible action (auto-quarantine off and "
            "no Slack/email channel) — a playbook that can do nothing is refused, fail-closed"
        )

    print(
        "MCPIP DENY-RESPONSE: enabled — a best-effort, off-hot-path daemon tails the WORM "
        "buffer for high-signal deny events and responds deterministically (freeze + alert), "
        f"triggers={sorted(active)} auto_quarantine={settings.response_auto_quarantine}. It "
        "reads already-committed records and can NEVER block/flip a decision. Disable with "
        "MCPIP_RESPONSE_ENABLED=false. See docs/operate/RESPONSE_PLAYBOOK.md.",
        file=sys.stderr,
        flush=True,
    )
    return ResponsePlaybook(
        worm_getter=lambda: components.worm,
        quarantine_getter=lambda: components.quarantine.quarantine,
        redis_getter=lambda: components.redis_client,
        cfg=ResponseConfig(
            trigger_reasons=active,
            burst_threshold=settings.response_burst_threshold,
            auto_quarantine=settings.response_auto_quarantine,
        ),
        slack=slack,
        email=email,
        interval_s=settings.response_interval_s,
    )


def _new_redis_client(settings: Settings) -> redis.Redis:
    """
    Construct a Redis client over a BOUNDED, BLOCKING connection pool (no I/O — lazy).

    decode_responses=True: string replies come back as str; integer Lua replies (the
    payload-lock codes) are unaffected. Construction opens no socket; a pool connection
    is bound to whatever event loop first drives I/O, which is precisely why the client
    is (re)built on the running loop inside the lifespan.

    Why BlockingConnectionPool (not the default non-blocking pool): every authorize does
    >=2 Redis ops, so a transient Redis slowdown (GC pause, failover, network blip) can
    momentarily push in-flight ops past ``max_connections``. The DEFAULT pool RAISES
    ``ConnectionError('Too many connections')`` immediately, which the single fail-closed
    funnel maps to an opaque 403 INTERNAL — turning a slow dependency into an
    authorization OUTAGE (a legitimate request DENIED, not delayed). The blocking pool
    instead makes the caller WAIT briefly for a returned connection (bounded by
    ``timeout``), so a short latency excursion queues rather than fail-closes. A genuine
    exhaustion still bounds the wait and surfaces as a transport error — availability
    backpressure, not a silent policy deny.
    """
    pool = redis.BlockingConnectionPool.from_url(
        settings.redis_url,
        decode_responses=True,
        max_connections=settings.redis_max_connections,
        timeout=settings.redis_pool_timeout_s,
        health_check_interval=30,
    )
    return redis.Redis(connection_pool=pool)


def _wire_redis_bound(
    settings: Settings,
    resolver: TokenResolver,
    worm_private_key: Ed25519PrivateKey,
    redis_client: redis.Redis,
    vault_master_key: Optional[bytes],
    forensic_master_key: Optional[bytes],
    authn_webhook_secret: Optional[bytes],
    authn_totp_key: Optional[bytes],
) -> tuple[
    AuthEngine,
    WormLogger,
    GrantStore,
    RelationTupleStore,
    QuarantineStore,
    RevocationStore,
    SkillGateStore,
    CatalogOverlayStore,
    ExtensionSubmissionStore,
    VerifiedPublisherStore,
    DirectoryStore,
    CloudEnvironmentStore,
    Optional[SecretVault],
    Optional[ForensicCaptureStore],
    VelocityAmountPolicyEngine,
    PolicyDocStore,
    TelemetryStats,
    OperatorUserStore,
    Optional[AuthenticatorEnrollmentStore],
    Optional[TotpVaultAuthenticatorChannel],
]:
    """
    Build the Redis-bound engine set (auth + PinValidator + worm + grants) on one client.

    Isolated so it runs identically at import (initial wiring) and inside the lifespan
    (re-wiring on the running loop). ``PinValidator``/``WormLogger`` each register their
    Lua script against this exact client at construction, so re-invoking with a fresh
    client rebinds the scripts too — no connection or script stays tied to a stale loop.
    Security semantics are byte-identical: same resolver, same WORM signing key, same
    atomic consume/append scripts. The GrantStore rides the same client so grants live
    in the same Redis as every other synchronization datum.
    """
    anchor_path = settings.worm_anchor_path or (settings.worm_path + ".anchor")
    anchor = AnchorStore(worm_private_key, anchor_path)
    worm = WormLogger(
        redis_client,
        worm_private_key,
        path=settings.worm_path,
        anchor=anchor,
        wait_replicas=settings.worm_wait_replicas,
        wait_timeout_ms=settings.worm_wait_timeout_ms,
        content_key=_load_worm_content_key(settings),
        content_key_fallbacks=_load_worm_content_key_fallbacks(settings),
    )
    pin = PinValidator(redis_client)
    # Out-of-band OTP delivery channel (sandbox stash+peek / production signed webhook /
    # None when production delivery is unconfigured). Built here so a Redis rebind
    # reconstructs the sandbox channel against the fresh client.
    authn_channel, authn_totp = _build_authn_channel(
        settings, redis_client, authn_webhook_secret, authn_totp_key
    )
    auth = AuthEngine(resolver, pin, redis_client, authn_channel)
    # Per-user authenticator (TOTP 2FA) enrollment store — present only with the master
    # key (sandbox auto-key / MCPIP_AUTHN_TOTP_KEY_PATH). Redis-bound: rebuilt on rebind.
    authn_enrollment = (
        AuthenticatorEnrollmentStore(redis_client, authn_totp_key)
        if authn_totp_key is not None
        else None
    )
    # One fresh per-worker negative grant cache bound to THIS client (item 3). Built
    # here so a client swap (``_rebind_redis``) always constructs a new, empty cache —
    # a negative marker can never outlive the client whose reads produced it.
    # ReBAC relation-tuple projection, bound to THIS client (rebuilt on a Redis swap so a
    # projected tuple can never outlive the client whose grant produced it). Injected into
    # GrantStore below so issue/revoke project/remove the member tuple additively.
    relations = RelationTupleStore(redis_client)
    grants = GrantStore(redis_client, cache=NegativeGrantCache(), relations=relations)
    quarantine = QuarantineStore(redis_client)
    revocation = RevocationStore(redis_client)
    delegation = DelegationStore(redis_client)
    skill_gate = SkillGateStore(redis_client)
    catalog_overlay = CatalogOverlayStore(redis_client)
    extension_submissions = ExtensionSubmissionStore(redis_client)
    registry_publishers = VerifiedPublisherStore(redis_client)
    directory = DirectoryStore(redis_client)
    cloud_env = CloudEnvironmentStore(redis_client)
    vault = SecretVault(redis_client, vault_master_key) if vault_master_key is not None else None
    # Forensic capture store: present only when effective capture is ON and its dedicated
    # master key is configured (auto-provisioned in sandbox). None ⇒ feature absent: the
    # capture hook is a no-op and the retrieval endpoint 404s.
    forensic = (
        ForensicCaptureStore(redis_client, forensic_master_key)
        if forensic_master_key is not None
        else None
    )
    # Deny-only policy overlay: the per-tenant policy-doc store (real config surface) and
    # the engine that reads it per eval. Both bind THIS client so a Redis rebind
    # reconstructs them (the engine re-registers its velocity Lua against the fresh
    # client). No document for a tenant → no limits (honest opt-in absent state).
    policy_docs = PolicyDocStore(redis_client)
    policy = VelocityAmountPolicyEngine(redis_client, policy_docs)
    # Opt-in vendor telemetry aggregate store — ALWAYS wired (the beacon SENDER is the
    # optional part). Bound to THIS client so a Redis rebind reconstructs it; the beacon
    # reaches the current instance via a getter, never a stale reference.
    telemetry_stats = TelemetryStats(redis_client)
    # Admin-managed operator/team roster (email-keyed, per-tenant). A MANAGEMENT
    # surface only — its ``role`` label authorizes nothing; identity + authz stay
    # JWT + capabilities. Bound to THIS client so a Redis rebind reconstructs it.
    operator_users = OperatorUserStore(redis_client)
    return (
        auth,
        worm,
        grants,
        relations,
        quarantine,
        revocation,
        delegation,
        skill_gate,
        catalog_overlay,
        extension_submissions,
        registry_publishers,
        directory,
        cloud_env,
        vault,
        forensic,
        policy,
        policy_docs,
        telemetry_stats,
        operator_users,
        authn_enrollment,
        authn_totp,
    )


def _rebind_redis(components: Components, redis_client: redis.Redis) -> None:
    """Point the component graph at a new Redis client, rebuilding the bound set."""
    components.redis_client = redis_client
    (
        components.auth,
        components.worm,
        components.grants,
        components.relations,
        components.quarantine,
        components.revocation,
        components.delegation,
        components.skill_gate,
        components.catalog_overlay,
        components.extension_submissions,
        components.registry_publishers,
        components.directory,
        components.cloud_env,
        components.vault,
        components.forensic,
        components.policy,
        components.policy_docs,
        components.telemetry_stats,
        components.operator_users,
        components.authn_enrollment,
        components.authn_totp,
    ) = _wire_redis_bound(
        components.settings,
        components.resolver,
        components.worm_private_key,
        redis_client,
        components.vault_master_key,
        components.forensic_master_key,
        components.authn_webhook_secret,
        components.authn_totp_key,
    )
    # Transports that hold a Redis-bound store must be rebuilt against the fresh client
    # too (mirrors the bound-set rebind): the grant-issuing transport (GrantStore) and
    # the cloud-IAM transport (CloudEnvironmentStore + SecretVault).
    components.transports["grant_issue"] = GrantIssuingTransport(components.grants)
    components.transports["cloud_iam"] = CloudIAMTransport(
        components.cloud_env, components.settings.sandbox_mode, components.vault, components.worm
    )


def _enforce_boot_integrity(settings: Settings) -> None:
    """
    Verified boot — fail-closed startup integrity self-check.

    Production (``sandbox_mode=False``): BOTH ``integrity_manifest_path`` and
    ``integrity_public_key_path`` are required and ``verify_boot_integrity`` must
    pass, or this raises and the process exits nonzero BEFORE binding a socket.
    The dev-only ``integrity_dev_bypass`` flag is structurally confined to
    sandbox boots: setting it while ``sandbox_mode=False`` REFUSES boot (an
    injected env var cannot disable verified boot in a production image). In an
    explicitly opted-in sandbox it skips the check behind a loud stderr banner.
    Sandbox: the check runs iff a manifest path is set (and is then still
    fail-closed on mismatch); otherwise a one-line advisory is printed.

    There is NO remediation or self-heal path and NO runtime self-update: on
    failure the operator redeploys a verified immutable image through change
    control (update automation, if ever wanted, is TUF/Sigstore — future work).
    """
    if settings.integrity_dev_bypass:
        if not settings.sandbox_mode:
            # The bypass is structurally confined to sandbox boots: a production
            # image with an injected MCPIP_INTEGRITY_DEV_BYPASS=true refuses to
            # start rather than silently skipping verified boot (mirrors the
            # half-configuration refusals below — fail closed, never fail open).
            raise RuntimeError(
                "MCPIP_INTEGRITY_DEV_BYPASS is set on a production boot "
                "(MCPIP_SANDBOX_MODE=false) — the integrity bypass is sandbox-only; "
                "unset it and boot a verified signed release"
            )
        print(
            "\n"
            "  ############################################################\n"
            "  # MCPIP INTEGRITY DEV BYPASS ACTIVE — NEVER IN PRODUCTION.  #\n"
            "  # The startup integrity self-check has been SKIPPED: this   #\n"
            "  # process cannot prove its source matches a signed release. #\n"
            "  # Unset MCPIP_INTEGRITY_DEV_BYPASS for a verified boot.     #\n"
            "  ############################################################\n",
            file=sys.stderr,
            flush=True,
        )
        return

    manifest_path = settings.integrity_manifest_path
    public_key_path = settings.integrity_public_key_path
    if manifest_path is None or public_key_path is None:
        if not settings.sandbox_mode:
            raise RuntimeError(
                "production boot (MCPIP_SANDBOX_MODE=false) requires both "
                "MCPIP_INTEGRITY_MANIFEST_PATH and MCPIP_INTEGRITY_PUBLIC_KEY_PATH"
            )
        if manifest_path is not None or public_key_path is not None:
            # A half-configured sandbox check is a misconfiguration: refusing is
            # safer than silently skipping a check the operator asked for.
            raise RuntimeError(
                "integrity self-check misconfigured: set both "
                "MCPIP_INTEGRITY_MANIFEST_PATH and MCPIP_INTEGRITY_PUBLIC_KEY_PATH"
            )
        print(
            "MCPIP INTEGRITY: sandbox boot without an integrity manifest — "
            "startup self-check skipped (set MCPIP_INTEGRITY_MANIFEST_PATH to enable)",
            file=sys.stderr,
            flush=True,
        )
        return

    try:
        public_key_pem = Path(public_key_path).read_bytes()
    except OSError:
        # Same opacity as a failed check — the key path goes only to the boot log.
        raise RuntimeError("integrity verification failed") from None
    verify_boot_integrity(Path(manifest_path), public_key_pem, _REPO_ROOT)


def _enforce_license_gate(settings: Settings) -> Optional[License]:
    """
    Offline license/entitlement gate — fail-closed, boot-time only.

    Production requires BOTH ``license_path`` and ``license_public_key_path`` and
    a currently-valid Ed25519-signed license; any failure refuses boot. Sandbox
    skips the gate unless both paths are set. The returned ``License`` is stored
    on ``Components`` for operator visibility but is NEVER consulted by the
    authorization pipeline — licensing gates process boot, never per-request
    decisions. Expiry is re-checked on every redeploy (immutable deployments),
    not on a running process. The boot banner records ONLY license_id, tier, and
    expires_at — never the customer name.
    """
    license_path = settings.license_path
    public_key_path = settings.license_public_key_path
    if license_path is None or public_key_path is None:
        if not settings.sandbox_mode:
            raise RuntimeError(
                "production boot (MCPIP_SANDBOX_MODE=false) requires both "
                "MCPIP_LICENSE_PATH and MCPIP_LICENSE_PUBLIC_KEY_PATH"
            )
        if license_path is not None or public_key_path is not None:
            raise RuntimeError(
                "license gate misconfigured: set both "
                "MCPIP_LICENSE_PATH and MCPIP_LICENSE_PUBLIC_KEY_PATH"
            )
        print(
            "MCPIP LICENSE: sandbox boot without a license — entitlement gate "
            "skipped (set MCPIP_LICENSE_PATH to enable)",
            file=sys.stderr,
            flush=True,
        )
        return None

    try:
        public_key_pem = Path(public_key_path).read_bytes()
    except OSError:
        # Same opacity as a failed verification — the path goes only to the log.
        raise RuntimeError("license verification failed") from None
    verified = load_and_verify_license(Path(license_path), public_key_pem)
    print(
        "MCPIP LICENSE: verified "
        f"license_id={verified.license_id} tier={verified.tier} "
        f"expires_at={verified.expires_at.isoformat()}",
        file=sys.stderr,
        flush=True,
    )
    return verified


# Classifications that, absent a human-in-the-loop PIN step-up, must be reachable
# ONLY with a sender-constrained (key-proven) token in production.
_SENSITIVE_CLASSIFICATIONS: frozenset[Classification] = frozenset(
    {Classification.RESTRICTED, Classification.CLASSIFIED}
)


def _enforce_sender_constraint_policy(
    registry: AliasRegistry, *, sandbox_mode: bool
) -> None:
    """
    Production boot lint: a SENSITIVE alias with NO human step-up MUST be
    sender-constrained, or the process refuses to boot.

    A stolen bearer token that clears the compartment gate would otherwise read
    RESTRICTED/CLASSIFIED data on every request — the telemetry/PHI/PII reads are
    ``RiskTier.AUTO``, so, unlike the ``PIN_REQUIRED`` writes (independently guarded
    by the payload-bound one-time PIN), nothing stands between a captured token and
    the data. In production (``sandbox_mode`` False) we fail closed at boot if any
    such alias lacks ``require_sender_constraint``, so the secure posture cannot be
    silently forgotten when an operator adds a sensitive alias.

    Sandbox/demo is EXEMPT: it demonstrates the compartment/grant model with bearer
    tokens and mints no workload proof keys. ``PIN_REQUIRED`` aliases are exempt: the
    OTP is the human-in-the-loop control there, independent of the token. This mirrors
    the existing production boot-refusals (integrity manifest, license, signing keys).
    """
    if sandbox_mode:
        return
    offenders = sorted(
        entry.alias
        for _tenant, entry in registry.all_entries()
        if entry.classification in _SENSITIVE_CLASSIFICATIONS
        and entry.risk_tier is not RiskTier.PIN_REQUIRED
        and not entry.require_sender_constraint
    )
    if offenders:
        raise RuntimeError(
            "production boot (MCPIP_SANDBOX_MODE=false) requires "
            "require_sender_constraint=True on every RESTRICTED/CLASSIFIED alias that "
            "is not PIN-gated — a bare bearer token would otherwise exfiltrate sensitive "
            f"data on every call. Offending aliases: {', '.join(offenders)}"
        )


_DEMO_JWT_ISSUER = "mcpip-demo-idp"
_DEMO_JWT_AUDIENCE = "mcpip-gateway"


def _enforce_production_config(settings: Settings) -> None:
    """
    Production boot lint for identity + transport config (fail-closed on the
    unambiguously-wrong cases, loud-warn on the loose-but-legitimate ones).

    In production (``sandbox_mode`` False):
      * REFUSE the shipped DEMO ``jwt_issuer``/``jwt_audience``. Leaving them at the
        published defaults (``mcpip-demo-idp``/``mcpip-gateway``) means the gateway
        validates tokens against a predictable, documented issuer/audience. The
        signing key must still match, but a needlessly-predictable audience is a
        downgrade; require the operator to set their own — the same fail-closed
        family as the key-path / integrity / license boot refusals. (CC6.1)
      * WARN on a plaintext ``redis://`` backplane. The payload-lock hashes, the WORM
        buffer, and the rate counters cross it unencrypted + unauthenticated.
        Internal-only network isolation is a valid documented control (T14), so this
        is a loud recommendation to move to ``rediss://`` + AUTH/ACL — not a boot
        refusal that would break an isolated deployment. (SC-8)
    """
    if settings.sandbox_mode:
        return
    if (
        settings.jwt_issuer == _DEMO_JWT_ISSUER
        or settings.jwt_audience == _DEMO_JWT_AUDIENCE
    ):
        raise RuntimeError(
            "production boot (MCPIP_SANDBOX_MODE=false) must set a non-demo "
            "MCPIP_JWT_ISSUER and MCPIP_JWT_AUDIENCE — the shipped demo defaults "
            f"({_DEMO_JWT_ISSUER!r}/{_DEMO_JWT_AUDIENCE!r}) are published and predictable."
        )
    if settings.redis_url.startswith("redis://"):
        print(
            "MCPIP WARNING: MCPIP_REDIS_URL is plaintext (redis://) in production — "
            "the payload-lock hashes, WORM buffer, and rate counters cross it "
            "unencrypted and unauthenticated. Use rediss:// with a CA + AUTH/ACL, or "
            "ensure the Redis link is on an isolated internal-only network.",
            file=sys.stderr,
            flush=True,
        )


def _build_components(settings: Settings) -> Components:
    """
    Wire the whole gateway once.

    Fail-closed boot: with ``sandbox_mode`` False and either key path missing, the
    process REFUSES to start rather than silently minting throwaway identity/audit
    keys. Redis is created lazily (no connect at import); the client is rebuilt on the
    running event loop in the lifespan and the ping happens in the lifespan/readyz probe.
    """
    if not settings.sandbox_mode and (
        settings.jwt_public_key_path is None
        or settings.worm_signing_key_path is None
    ):
        raise RuntimeError(
            "production boot (MCPIP_SANDBOX_MODE=false) requires both "
            "MCPIP_JWT_PUBLIC_KEY_PATH and MCPIP_WORM_SIGNING_KEY_PATH"
        )

    # --- Verified boot + entitlement gate (both fail-closed, both BEFORE any ----
    # --- engine wiring: an unverifiable or unlicensed process never gets far ----
    # --- enough to hold keys or bind a socket). ---------------------------------
    _enforce_boot_integrity(settings)
    license_info = _enforce_license_gate(settings)

    # Identity/transport config lint — runs AFTER the more-fundamental integrity/
    # license gates so those structural boot refusals fire first: refuse the demo
    # jwt issuer/audience defaults in production; warn on a plaintext Redis
    # backplane.
    _enforce_production_config(settings)

    public_pem, demo_idp = _load_verifying_pem(settings)
    resolver = TokenResolver(
        StaticPEMKeyProvider(public_pem),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )
    worm_private_key = _load_worm_key(settings)
    vault_master_key = _load_vault_key(settings)
    forensic_master_key = _resolve_forensic_key(settings)
    pseudonym_key = _load_pseudonym_key(settings)
    authn_webhook_secret = _load_authn_webhook_secret(settings)
    authn_totp_key = _load_authn_totp_key(settings)

    registry = build_demo_registry()
    _enforce_sender_constraint_policy(registry, sandbox_mode=settings.sandbox_mode)
    obf = ObfuscatorService(registry)

    redis_client = _new_redis_client(settings)
    (
        auth,
        worm,
        grants,
        relations,
        quarantine,
        revocation,
        delegation,
        skill_gate,
        catalog_overlay,
        extension_submissions,
        registry_publishers,
        directory,
        cloud_env,
        vault,
        forensic,
        policy,
        policy_docs,
        telemetry_stats,
        operator_users,
        authn_enrollment,
        authn_totp,
    ) = _wire_redis_bound(
        settings,
        resolver,
        worm_private_key,
        redis_client,
        vault_master_key,
        forensic_master_key,
        authn_webhook_secret,
        authn_totp_key,
    )

    transports: dict[str, BaseTransport] = {
        "cloud_rest": CloudRESTTransport(),
        "legacy_mainframe": LegacyMainframeTransport(),
        "grant_issue": GrantIssuingTransport(grants),
        "cloud_iam": CloudIAMTransport(cloud_env, settings.sandbox_mode, vault, worm),
    }

    # Community-gate provider (deny-only, step 4c′), composed with the optional outbound
    # COAZ PEP-mode consult. Half-config is a fail-closed boot error — see
    # ``_build_community_gate``.
    community_gate = _build_community_gate(settings)

    components = Components(
        settings=settings,
        resolver=resolver,
        worm_private_key=worm_private_key,
        redis_client=redis_client,
        auth=auth,
        obf=obf,
        registry=registry,
        grants=grants,
        relations=relations,
        quarantine=quarantine,
        revocation=revocation,
        delegation=delegation,
        skill_gate=skill_gate,
        catalog_overlay=catalog_overlay,
        extension_submissions=extension_submissions,
        registry_publishers=registry_publishers,
        policy=policy,
        policy_docs=policy_docs,
        # The community-gate provider (a strict NO-OP until a CEL gate engine is registered,
        # optionally wrapped in a DenyOnlyGateChain with the outbound external-PDP consult
        # when the default-OFF PEP flag is set). Stateless, so wired once here, never rebound.
        community_gate=community_gate,
        directory=directory,
        cloud_env=cloud_env,
        vault=vault,
        vault_master_key=vault_master_key,
        forensic=forensic,
        forensic_master_key=forensic_master_key,
        pseudonym_key=pseudonym_key,
        authn_webhook_secret=authn_webhook_secret,
        authn_totp_key=authn_totp_key,
        authn_enrollment=authn_enrollment,
        authn_totp=authn_totp,
        worm=worm,
        telemetry_stats=telemetry_stats,
        operator_users=operator_users,
        # The optional beacon SENDER is wired just below, once ``components`` exists (its
        # stats/license getters close over the live graph). None here is a placeholder.
        telemetry=None,
        # The optional license refresher is wired just below too (its getter/setter close
        # over the live graph, and it may ride the beacon payload). None is a placeholder.
        license_refresher=None,
        # The optional deny-response playbook is wired just below too (its getters close over
        # the live graph). None is a placeholder until _build_response_playbook runs.
        response_playbook=None,
        transports=transports,
        demo_idp=demo_idp,
        license=license_info,
    )
    # Opt-in vendor telemetry beacon: built AFTER ``components`` so its getters reach the
    # live telemetry_stats/license. Absent unless enabled + url + not-sandbox; the flag ON
    # with no url is a fail-closed BOOT error (raised here). See ``_build_telemetry_beacon``.
    components.telemetry = _build_telemetry_beacon(settings, components)
    # Opt-in license refresh: built AFTER the beacon so it can ride the beacon payload (and
    # reuse its install-id) when telemetry is on. Absent unless a refresh URL is set AND the
    # process booted with a license. Off the hot path, fail-open. See ``_build_license_refresher``.
    components.license_refresher = _build_license_refresher(settings, components)
    # Opt-in deny-response playbook: built AFTER the Redis-bound graph so its getters resolve
    # the live WORM / quarantine / Redis. Absent unless ``response_enabled``; a config that
    # can do nothing (or names a reason outside the closed set) is a fail-closed BOOT error.
    components.response_playbook = _build_response_playbook(settings, components)
    return components


# Single process-wide component graph (composition root).
_components: Components = _build_components(get_settings())


def _warn_sandbox_affordances(components: Components) -> None:
    """Log a loud banner whenever the sandbox affordances are mounted (never in prod)."""
    if not components.settings.sandbox_mode:
        return
    print(
        "\n"
        "  ############################################################\n"
        "  # MCPIP SANDBOX MODE ENABLED — DO NOT USE IN PRODUCTION.    #\n"
        "  # Mounts /v1/dev/token (mints ANY identity/compartment/     #\n"
        "  # capability), /v1/authenticator (OTP disclosure), and      #\n"
        "  # /v1/audit/* — and permits the in-process IdP / ephemeral  #\n"
        "  # WORM key. Bind to loopback only. Set MCPIP_SANDBOX_MODE   #\n"
        "  # unset/false for a fail-closed deployment.                 #\n"
        "  ############################################################\n",
        file=sys.stderr,
        flush=True,
    )


_warn_sandbox_affordances(_components)


# ---------------------------------------------------------------------------
# Lifespan — connectivity probe on startup, clean shutdown of the Redis pool.
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    """
    Rebind Redis to the running loop, probe readiness, tear down deterministically.

    The composition root builds a Redis client at import, but a redis.asyncio pool
    binds its connections' transports to whichever event loop first drives I/O. To keep
    the single ``POST /v1/authorize`` choke point functional under every runtime — most
    notably Starlette's ``TestClient``, which drives the lifespan and all requests on one
    dedicated portal loop — we discard the import-time client and rebuild the client plus
    its bound engine trio HERE, on the loop that will actually serve requests. Nothing in
    the security posture changes: same keys, same atomic scripts, same fail-closed
    boundary. The stale client opened no sockets at import, so closing it is a no-op.

    We then ping Redis so a misconfiguration surfaces in the logs immediately, but do NOT
    hard-fail on a transient Redis outage — ``/readyz`` reports the true state so an
    orchestrator can gate traffic. The live pool is always closed on shutdown.
    """
    # Structured JSON logging for the serving process (root + uvicorn.error;
    # uvicorn.access untouched). The print(...) boot banners stay as-is.
    configure_logging()

    stale_client = _components.redis_client
    _rebind_redis(_components, _new_redis_client(_components.settings))
    try:
        await stale_client.aclose()
    except Exception:  # noqa: BLE001 — import-time client held no live connections.
        pass

    try:
        await _components.redis_client.ping()
    except Exception:  # noqa: BLE001 — startup probe is advisory; readyz is truth.
        pass

    # Enforce the audit durability posture. write-before-execute is only real if the
    # buffer XADD is fsync-durable BEFORE authorize returns, which requires AOF
    # appendfsync=always. In production (non-sandbox) this refuses to boot otherwise
    # (fail-closed); in sandbox it logs a loud advisory and continues so the runnable
    # demo/test can use a throwaway Redis.
    require_durable = not _components.settings.sandbox_mode
    try:
        await assert_persistence_posture(
            _components.redis_client, require=require_durable
        )
    except RuntimeError:
        raise  # non-durable in production → fail closed.
    except Exception as exc:  # noqa: BLE001 — transport error reading CONFIG.
        if require_durable:
            raise RuntimeError(
                "cannot verify Redis persistence posture at boot"
            ) from exc
        print(
            "MCPIP WORM-DURABILITY: could not read Redis persistence config "
            f"({type(exc).__name__}); sandbox continuing",
            file=sys.stderr,
            flush=True,
        )

    # Hydrate operator-registered skills (catalog overlay) into the in-memory
    # registry. Additive only — a config alias is never overridden — so resolve stays
    # synchronous/in-memory (no I/O on the hot path).
    await _hydrate_catalog_overlay()

    # Sandbox convenience: seed the demo AWS cloud environment so skill_aws_s3
    # vends out of the box. Production operators create bindings via the admin API;
    # nothing is seeded there (and no cloud secret is ever seeded — bindings hold none).
    await _hydrate_cloud_environments()

    # Launch the ~1s background epoch closer (hybrid Merkle-epoch WORM). Every emitted
    # event is durable in the buffer BEFORE authorize returns; the daemon periodically
    # seals a signed epoch root over the pending events.
    _components.worm.start_epoch_daemon()
    # Cheap 15s mirror of the last sealed epoch number into the Prometheus gauge.
    # A dedicated task (not /readyz) keeps the readiness probe dependency-minimal.
    epoch_gauge_task = asyncio.create_task(_epoch_gauge_daemon())
    # Always-on audit-integrity monitor: periodic verify_chain → mcpip_audit_integrity_total
    # + CRITICAL mcpip.audit on tamper. A core integrity control (not opt-in), off the hot
    # path and swallow-only like the epoch-gauge daemon.
    audit_integrity_task = asyncio.create_task(_audit_integrity_daemon())
    # Opt-in vendor-telemetry beacon: ONE off-hot-path interval task, scheduled ONLY when the
    # beacon was constructed (enabled + url + not-sandbox). Modeled on the epoch-gauge daemon
    # — its every send failure is swallowed to a metric, so it can never affect serving, the
    # audit chain, or any authorization decision. Disabled/air-gapped deploys schedule NO task.
    telemetry_task: Optional[asyncio.Task[None]] = None
    if _components.telemetry is not None:
        telemetry_task = asyncio.create_task(_components.telemetry.run())
    else:
        TELEMETRY.labels("skipped").inc()
    # Opt-in license refresh: ONE off-hot-path interval daemon, scheduled ONLY when a
    # refresher was constructed (refresh URL set + booted with a license). Like the beacon /
    # epoch-gauge daemons it can never affect serving, the audit chain, or any decision — a
    # failed pull just retains the last-good license. Absent deploys schedule NO task.
    license_refresh_task: Optional[asyncio.Task[None]] = None
    if _components.license_refresher is not None:
        license_refresh_task = asyncio.create_task(_license_refresh_daemon())
    # Opt-in deny-response playbook: ONE off-hot-path interval daemon, scheduled ONLY when a
    # playbook was constructed (enabled + at least one action). Like the beacon / license /
    # epoch-gauge daemons it reads already-committed records and can never affect serving, the
    # audit chain, or any decision — a failed response is swallowed to a metric. Absent
    # deploys schedule NO task.
    response_task: Optional[asyncio.Task[None]] = None
    if _components.response_playbook is not None:
        response_task = asyncio.create_task(_components.response_playbook.run())
    else:
        RESPONSE.labels("skipped").inc()
    try:
        yield
    finally:
        epoch_gauge_task.cancel()
        with suppress(asyncio.CancelledError):
            await epoch_gauge_task
        audit_integrity_task.cancel()
        with suppress(asyncio.CancelledError):
            await audit_integrity_task
        if telemetry_task is not None:
            telemetry_task.cancel()
            with suppress(asyncio.CancelledError):
                await telemetry_task
        if license_refresh_task is not None:
            license_refresh_task.cancel()
            with suppress(asyncio.CancelledError):
                await license_refresh_task
        if response_task is not None:
            response_task.cancel()
            with suppress(asyncio.CancelledError):
                await response_task
        await _components.worm.stop_epoch_daemon()
        await _components.redis_client.aclose()


async def _epoch_gauge_daemon() -> None:
    """Periodically reflect ``mcpip:worm:epoch:num`` into ``mcpip_worm_epoch``.

    Metrics are strictly advisory: ANY Redis failure here is swallowed — this
    task must never affect serving, shedding, or the audit chain itself.
    """
    while True:
        try:
            raw: Any = await _components.redis_client.get(_WORM_EPOCH_NUM_KEY)
            if raw is not None:
                WORM_EPOCH.set(float(raw))
        except Exception:  # noqa: BLE001 — advisory only; never disturb serving.
            pass
        await asyncio.sleep(_EPOCH_GAUGE_INTERVAL_S)


async def _audit_integrity_daemon() -> None:
    """Off-hot-path audit-chain integrity monitor (SOC 2 CC7.3/CC4.1).

    Periodically runs a FRESH ``verify_chain`` over the signed epoch chain — the SAME
    read ``GET /v1/audit/attestation`` performs — and turns the result into a continuous,
    alertable signal: an ``mcpip_audit_integrity_total{event}`` counter plus, on a
    non-intact chain, a CRITICAL ``mcpip.audit`` log naming the first bad epoch. Without
    this, ``verify_chain`` only ran pull-based (an operator had to ask), so a tamper could
    sit undetected until someone looked.

    Strictly OFF the hot path and swallow-only (mirrors ``_epoch_gauge_daemon``):
    ``verify_chain`` takes only the epoch-close lock, never ``emit``, so this can never
    block/delay/reorder/flip an authorization, and it mutates no audit state (mints no
    key, seals no epoch, writes no counter). Before the first epoch seals it verifies an
    empty chain intact — an honest ``verified``. It checks once at startup, then each
    interval.
    """
    while True:
        await _run_audit_integrity_check(_components.worm)
        await asyncio.sleep(_AUDIT_INTEGRITY_INTERVAL_S)


async def _run_audit_integrity_check(worm: WormLogger) -> None:
    """One audit-integrity verification pass (the daemon's loop body, extracted for tests).

    Runs a fresh ``verify_chain`` and records the outcome to ``mcpip_audit_integrity_total``;
    on a non-intact chain it also emits a CRITICAL ``mcpip.audit`` log naming the first bad
    epoch. Swallow-only — it NEVER raises into the caller, so a Redis/transient failure is a
    counted ``verify_error``, never a disturbance to serving or the audit chain.
    """
    try:
        intact, first_bad = await worm.verify_chain()
        if intact:
            AUDIT_INTEGRITY.labels("verified").inc()
        else:
            AUDIT_INTEGRITY.labels("tamper_detected").inc()
            _AUDIT_LOG.critical(
                "WORM audit chain verification FAILED: intact=false "
                "first_bad_epoch=%s — treat as a security incident "
                "(capture GET /v1/audit/attestation)",
                first_bad,
            )
    except Exception:  # noqa: BLE001 — advisory monitor; never disturb serving.
        AUDIT_INTEGRITY.labels("verify_error").inc()


async def _license_refresh_daemon() -> None:
    """Periodically pull + verify + atomically swap a strictly-newer signed license.

    Mirrors ``_epoch_gauge_daemon`` / the telemetry beacon: strictly OFF the hot path and
    swallow-only. ``refresh_once`` already catches every failure internally (retaining the
    last-good license); the outer guard is belt-and-suspenders so even an unexpected error
    can NEVER disturb serving, the audit chain, or an authorization decision. It sleeps
    first (the boot license is freshly verified) then pulls each interval.
    """
    refresher = _components.license_refresher
    assert refresher is not None  # only started when present (see _lifespan).
    while True:
        await asyncio.sleep(refresher.interval_s)
        try:
            await refresher.refresh_once()
        except Exception:  # noqa: BLE001 — a refresh can NEVER disturb serving.
            LICENSE_REFRESH.labels("transport_error").inc()


app = FastAPI(
    title="MCPIP — The Authorization Layer for Autonomous AI",
    description="Authorize every AI action before execution.  " + _GLYPH,
    version=get_version(),
    lifespan=_lifespan,
)


# ---------------------------------------------------------------------------
# Middleware — mint + echo the correlation id on every response.
# ---------------------------------------------------------------------------


@app.middleware("http")
async def _correlation_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """Assign a fresh correlation id per request and echo it on the response header."""
    correlation_id = new_correlation_id()
    request.state.correlation_id = correlation_id
    response = await call_next(request)
    response.headers[_CORRELATION_HEADER] = correlation_id
    return response


# ---------------------------------------------------------------------------
# Body-size limit — the OUTERMOST middleware (pre-auth DoS gate).
# ---------------------------------------------------------------------------


class BodySizeLimitMiddleware:
    """
    Reject over-large request bodies at the ASGI edge, BEFORE any JSON parsing, model
    validation, or authentication.

    Two-tier: (1) fail fast on an oversized ``Content-Length`` without reading a byte;
    (2) for chunked / header-less requests, buffer with a HARD cap and reject the instant
    the accumulated body exceeds it — so an attacker cannot force unbounded in-memory
    JSON parsing of an arbitrarily large payload at the single ``/v1/authorize`` choke
    point. The bounded body is then replayed to the downstream app unchanged.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self._app = app
        self._max = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        # (1) Reject an oversized declared Content-Length before reading the body.
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > self._max:
                        await self._reject(scope, send)
                        return
                except ValueError:
                    await self._reject(scope, send)
                    return

        # (2) Buffer the body with a hard cap (covers chunked / absent Content-Length).
        body = bytearray()
        more = True
        while more:
            message: Message = await receive()
            if message["type"] != "http.request":
                # e.g. http.disconnect — hand it straight through.
                break
            body.extend(message.get("body", b""))
            if len(body) > self._max:
                await self._reject(scope, send)
                return
            more = bool(message.get("more_body", False))

        buffered = bytes(body)
        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {
                    "type": "http.request",
                    "body": buffered,
                    "more_body": False,
                }
            return await receive()

        await self._app(scope, replay_receive, send)

    async def _reject(self, scope: Scope, send: Send) -> None:
        """Emit an opaque 413 (Payload Too Large) with a fresh correlation id."""
        body = ErrorResponse(
            error="request body too large", correlation_id=new_correlation_id()
        )
        response = JSONResponse(status_code=413, content=body.model_dump())
        await response(scope, _empty_receive, send)


async def _empty_receive() -> Message:
    """A no-op ASGI receive for sending a synthesized response with no request body."""
    return {"type": "http.request", "body": b"", "more_body": False}


# Register the size gate ahead of the correlation middleware and every route, so it runs
# before any body is read, parsed, or authenticated. ``EdgeGateMiddleware`` (below) is
# added AFTER this one, making it the true outermost layer.
app.add_middleware(BodySizeLimitMiddleware, max_bytes=MAX_REQUEST_BODY_BYTES)


# ---------------------------------------------------------------------------
# Edge gate — pre-parse rejects + admission control (items 2 & 2b), OUTERMOST.
# ---------------------------------------------------------------------------

# Liveness/readiness/metrics are NEVER gated, counted, or shed (probes must always
# answer; a Prometheus scrape must never be dropped by admission control). NOTE: /metrics
# is served on the SAME socket as /v1/authorize, so an L3/L4 NetworkPolicy cannot confine
# it separately from the agent-facing authorize path — a scraper reaching this port reaches
# both. The exposition is therefore kept opacity-safe BY CONSTRUCTION (coarse closed-enum
# labels only; the concrete deny_reason is NEVER a label — see core.metrics), not by
# network topology. Per-reason operator visibility, if ever needed, belongs on a SEPARATE
# monitoring-only bind, never here.
_EDGE_EXEMPT_PATHS = frozenset(
    {"/healthz", "/readyz", "/metrics", WELL_KNOWN_PRM_PATH}
)


class EdgeGateMiddleware:
    """
    Drop illegal / excess traffic at the ASGI edge, BEFORE any body read, JSON parse,
    model validation, or authentication — the single deterministic outermost layer.

    Executed in order on every http request that is not a probe / preflight:

      1. **Exempt** ``/healthz``, ``/readyz`` and ``OPTIONS`` — passed straight through
         with NO size/bearer/admission logic. Non-negotiable: probes are never shed.
      2. **Content-Length 413** — reuse ``MAX_REQUEST_BODY_BYTES`` (262144 = the 256 KiB
         raw-body ceiling; the documented x16 headroom over ``MAX_CANONICAL_BYTES``
         = 16384, which caps *canonical arguments only*, NOT the whole HTTP body). A
         declared Content-Length over that, or an unparseable one, is rejected with an
         opaque 413 without reading a byte and WITHOUT taking an admission slot. (This
         duplicates ``BodySizeLimitMiddleware``'s fast check so oversized junk is dropped
         before admission; that inner middleware still hard-caps chunked/absent-CL bodies.)
      3. **Bearer 401 for POST /v1/authorize only** — reject the *bodyless/authless* POST
         (the pure DoS probe the spec names: "a bodyless/authless POST is parsed and
         validated before the missing-token deny") pre-parse, with ZERO allocation. The
         rule fires iff there is NO well-formed ``Authorization: Bearer <non-empty>``
         header AND the request carries no body (Content-Length absent/0 and not chunked).
         RECONCILIATION (deliberate, load-bearing): the schema also permits the token in
         the JSON body ``jwt`` field, and the regression adversarial suite drives identity
         through that body field with no header. The higher-priority regression bar ("the
         full /v1/authorize adversarial suite passes") forbids shedding those legitimate
         body-jwt requests at the edge, so a request WITH a body is passed through to the
         handler, which still enforces JWT-only identity fail-closed (an absent/invalid
         body ``jwt`` → opaque 403). This keeps the edge reject fail-closed and opaque (a
         would-be DENY is never converted to ALLOW: the only requests shed here carry no
         credential AND no body to authorize) while never rejecting a valid caller. Other
         paths keep their own in-handler JWT gate and are not bearer-checked here.

    Admission control / graceful load-shedding (item 2b — resolves the HIGH finding):

      4. A per-worker in-flight counter bounds concurrent in-flight requests. Above
         ``max_in_flight`` a new arrival is shed with an opaque **503 + Retry-After**
         WITHOUT incrementing — excess load fast-fails with bounded tail latency instead
         of queueing unboundedly (the old single-worker failure: p99 → tens of seconds
         and dropped connections). Admitted requests run under a wall-clock ceiling and
         the counter is ALWAYS released in ``finally``.

    Fail-closed / shedding-only invariants (MUST hold):
      * The limiter only ever REJECTS (503) or TIMES OUT — it never lets a request skip a
        gate. It is structurally impossible for it to convert a would-be DENY into an
        ALLOW: a shed request never reaches ``authorize()`` and produces no receipt.
      * Decrement is in ``finally`` → the counter cannot leak on exception, cancellation,
        or client disconnect.
      * Exactly-once safety under timeout: a timeout only cancels the coroutine. If it
        fires after the atomic Lua consume but before the receipt, the lock is already
        spent → the client's retry hits ``PIN_NOT_FOUND`` (a DENY), never a second
        execution. A timeout before consume denies nothing that was allowed. The 15s
        default makes the timeout a backstop, not a normal path.

    The per-worker counter is a plain ``int``: the event loop is single-threaded per
    worker, so ``+= 1`` / ``-= 1`` are atomic without a lock. Shedding is intentionally
    per-process (Redis is not on the shed hot path); scale horizontally with more workers
    and nodes behind a load balancer (see ``Dockerfile`` / ``README`` scaling notes).
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_in_flight: int,
        request_timeout_s: float,
        shed_retry_after_s: int,
    ) -> None:
        self._app = app
        self._max_in_flight = max_in_flight
        self._timeout_s = request_timeout_s
        self._retry_after = shed_retry_after_s
        self._in_flight = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope["path"]
        method = scope["method"]

        # (1) Never gate/shed liveness, readiness, or CORS preflight.
        if path in _EDGE_EXEMPT_PATHS or method == "OPTIONS":
            await self._app(scope, receive, send)
            return

        # (2) Oversized declared Content-Length → opaque 413, no body read, no slot.
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > MAX_REQUEST_BODY_BYTES:
                        SHED.labels("oversized").inc()
                        await self._emit(scope, send, 413, "request body too large")
                        return
                except ValueError:
                    SHED.labels("oversized").inc()
                    await self._emit(scope, send, 413, "request body too large")
                    return

        # (3) Bodyless + authless POST /v1/authorize → opaque 401, pre-parse. A request
        # WITH a body may carry identity in the JSON `jwt` field and is passed through to
        # the handler's fail-closed JWT-only gate (see the class docstring reconciliation).
        if path == "/v1/authorize" and method == "POST":
            if not self._has_bearer(scope) and self._is_bodyless(scope):
                SHED.labels("unauthorized").inc()
                await self._emit(scope, send, 401, "unauthorized")
                return

        # (2b) Admission control — shed above the in-flight bound with a fast 503.
        if self._in_flight >= self._max_in_flight:
            SHED.labels("overload").inc()
            await self._emit(
                scope,
                send,
                503,
                "service overloaded",
                headers={"Retry-After": str(self._retry_after)},
            )
            return

        self._in_flight += 1
        started = False

        async def _tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await asyncio.wait_for(
                self._app(scope, receive, _tracking_send), timeout=self._timeout_s
            )
        except asyncio.TimeoutError:
            # The coroutine was cancelled at the ceiling. If no response byte has left
            # yet, synthesize an opaque 503; otherwise a partial response is already on
            # the wire and nothing more can be safely appended.
            if not started:
                SHED.labels("timeout").inc()
                await self._emit(
                    scope,
                    send,
                    503,
                    "service overloaded",
                    headers={"Retry-After": str(self._retry_after)},
                )
        finally:
            self._in_flight -= 1

    @staticmethod
    def _has_bearer(scope: Scope) -> bool:
        """True iff an ``Authorization: Bearer <non-empty>`` header is present."""
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                if value.lower().startswith(b"bearer "):
                    token = value[7:].strip()
                    return bool(token)
                return False  # header present but not a well-formed bearer.
        return False

    @staticmethod
    def _is_bodyless(scope: Scope) -> bool:
        """
        True iff the request declares no body: no ``Transfer-Encoding`` and a
        ``Content-Length`` that is absent or 0. A chunked or non-empty request is
        treated as body-bearing (it may carry a JSON ``jwt``), so it is NOT shed here.
        Fail-safe on an unparseable Content-Length: treat as body-bearing (do not shed).
        """
        content_length: Optional[bytes] = None
        for name, value in scope.get("headers", []):
            lowered = name.lower()
            if lowered == b"transfer-encoding":
                return False  # chunked/streamed body — has content.
            if lowered == b"content-length":
                content_length = value
        if content_length is None:
            return True  # no CL, no TE → no body.
        try:
            return int(content_length) == 0
        except ValueError:
            return False  # unparseable → do not shed at the edge (fail-safe).

    async def _emit(
        self,
        scope: Scope,
        send: Send,
        status: int,
        error: str,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        """Emit an opaque ``{error, correlation_id}`` response with a fresh id."""
        body = ErrorResponse(error=error, correlation_id=new_correlation_id())
        response = JSONResponse(
            status_code=status, content=body.model_dump(), headers=headers
        )
        await response(scope, _empty_receive, send)


# Register OUTERMOST (added last → wraps BodySizeLimit, the correlation middleware, and
# every route). Pre-parse rejects + admission all run before a byte is parsed.
app.add_middleware(
    EdgeGateMiddleware,
    max_in_flight=_components.settings.max_in_flight,
    request_timeout_s=_components.settings.request_timeout_s,
    shed_retry_after_s=_components.settings.shed_retry_after_s,
)


# ---------------------------------------------------------------------------
# Operator-console CORS — a pure header layer ABOVE the edge gate.
# ---------------------------------------------------------------------------
#
# CORS is a BROWSER control: it only gates the operator console's cross-origin
# fetches (the "Test & Connect" plug-and-play flow). Agent traffic is
# server-to-server and never consults it, and every request is still JWT-authorized
# regardless of origin — this changes nothing about authorization. Registered LAST
# (outermost) so preflights are answered before the edge gate and even opaque
# denials carry the headers the console needs to read them.
#
# Fail-closed: production emits NO CORS headers unless the operator explicitly
# lists console origins via MCPIP_CONSOLE_ORIGINS (comma-separated). Sandbox allows
# any origin so the local console connects out of the box. Credentials stay
# disabled — identity travels in the Authorization header, never cookies.
_console_origins: list[str] = (
    ["*"]
    if _components.settings.sandbox_mode
    else [o.strip() for o in _components.settings.console_origins.split(",") if o.strip()]
)
if _console_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_console_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "DPoP"],
        expose_headers=["X-MCPIP-Correlation-Id"],
        max_age=600,
    )


# ---------------------------------------------------------------------------
# Exception handlers — NO stack trace, key name, or topology ever escapes.
# ---------------------------------------------------------------------------


def _corr(request: Request) -> str:
    """Read the request's correlation id, falling back to a fresh one if unset."""
    value = getattr(request.state, "correlation_id", None)
    return value if isinstance(value, str) else new_correlation_id()


async def _handle_denied(request: Request, exc: Exception) -> Response:
    """``MCPIPDenied`` → 403 opaque; carries only the generic message + correlation."""
    correlation_id = (
        exc.correlation_id if isinstance(exc, MCPIPDenied) else _corr(request)
    )
    body = ErrorResponse(
        error=AGENT_FACING_DENY_MESSAGE, correlation_id=correlation_id
    )
    return JSONResponse(status_code=403, content=body.model_dump())


async def _handle_validation(request: Request, exc: Exception) -> Response:
    """Malformed request envelope → 422 with an opaque message + correlation id."""
    body = ErrorResponse(error="invalid request", correlation_id=_corr(request))
    return JSONResponse(status_code=422, content=body.model_dump())


async def _handle_unexpected(request: Request, exc: Exception) -> Response:
    """Any unhandled exception → 500 fail-closed opaque; never leaks the cause."""
    body = ErrorResponse(
        error=AGENT_FACING_DENY_MESSAGE, correlation_id=_corr(request)
    )
    return JSONResponse(status_code=500, content=body.model_dump())


app.add_exception_handler(MCPIPDenied, _handle_denied)
app.add_exception_handler(RequestValidationError, _handle_validation)
app.add_exception_handler(Exception, _handle_unexpected)


# ---------------------------------------------------------------------------
# Request helpers.
# ---------------------------------------------------------------------------


def _bearer_from_header(request: Request) -> Optional[str]:
    """
    Extract a bearer token from ``Authorization: Bearer <jwt>``.

    Returns ``None`` on any deviation (absent header, wrong scheme, blank token) so
    the caller maps a missing/blank credential to a JWT_INVALID deny fail-closed.
    """
    header = request.headers.get("authorization")
    if header is None:
        return None
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


def _dpop_from_header(request: Request) -> Optional[str]:
    """
    Extract the proof-of-possession JWS from the ``DPoP`` request header (RFC 9449).

    Returns ``None`` when absent/blank. A sender-constrained token (JWT with a
    ``cnf.jkt``) with no proof is denied fail-closed inside the pipeline; a bearer
    token ignores this header entirely. The value is opaque to the edge — only
    ``verify_pop_proof`` interprets it.
    """
    header = request.headers.get("dpop")
    if header is None:
        return None
    proof = header.strip()
    return proof or None


def _synth_single_hop_trace(agent_id: str) -> SwarmTrace:
    """
    Synthesize a well-formed single-hop trace from the VERIFIED agent id.

    Used only when the caller omits ``trace``. It is built from the JWT-derived
    ``agent_id`` (never from anything attacker-controlled), so provenance still
    anchors to the sovereign identity.
    """
    return SwarmTrace(
        trace_id=str(uuid.uuid4()),
        hops=[
            Hop(
                hop_index=0,
                agent_id=agent_id,
                parent_agent_id=None,
                purpose="synthesized single-hop trace",
            )
        ],
    )


async def _resolve_alias(identity: Identity, alias: str) -> AliasEntry:
    """
    Resolve an alias with a TIMING-UNIFORM denial across "alias absent" and "alias
    present but compartment-denied".

    A resolve-SUCCEEDS-but-denied alias reaches the post-resolution gates, which spend
    TWO Redis round trips before denying: the step-4a′ skill-kill-switch ``is_disabled``
    SISMEMBER, then ``_compartment_gate``'s ``has_active_grant`` GET. An unknown /
    cross-tenant alias short-circuits here at resolution WITHOUT either. That ~two-round-
    trip latency gap is a cross-compartment existence oracle: given a valid JWT, an
    attacker could distinguish "this classified alias exists in a compartment I can't see"
    (slower) from "this alias does not exist" (faster) even though both return the same
    opaque body — defeating the obfuscator's team-separation invariant. To close it, a
    resolution miss performs the EQUIVALENT decoy round trips before re-raising — a decoy
    ``is_disabled`` SISMEMBER (an unknown alias is trivially not a member → the same nil
    round trip) AND a decoy grant GET against a fixed synthetic compartment that can never
    hold a grant — so both denial families cost the same Redis work. Both decoys are
    fail-closed on a transport error exactly as their real-path counterparts are, so an
    outage denies symmetrically (never a silent pass, never an asymmetric latency).
    """
    try:
        return _components.obf.resolve(identity.tenant_id, alias)
    except (UnknownAlias, CrossTenant):
        # Decoy SISMEMBER (mirrors step-4a′ is_disabled) + decoy grant GET (mirrors the
        # compartment gate) so the resolve-miss path pays the SAME two round trips the
        # resolve-succeeds-then-denied path pays. Results are ignored; the original
        # UnknownAlias/CrossTenant is re-raised so the opaque deny reason is unchanged.
        await _components.skill_gate.is_disabled(identity.tenant_id, alias)
        await _components.grants.has_active_grant(
            identity.tenant_id, identity.agent_id, _TIMING_DECOY_COMPARTMENT
        )
        raise


async def _compartment_gate(identity: Identity, entry: AliasEntry) -> None:
    """
    Deny (COMPARTMENT_DENIED) unless the caller is entitled to entry.compartment.

    Un-compartmented aliases are always allowed (back-compat). Entitlement is either a
    DIRECT JWT compartment-claim match (timing-uniform) or a DELEGATED, active grant.
    No role string is consulted.
    """
    if entry.compartment is None:
        return
    if identity.compartment is not None and constant_time_equals(
        identity.compartment, entry.compartment
    ):
        return
    if await _components.grants.has_active_grant(
        identity.tenant_id, identity.agent_id, entry.compartment
    ):
        return
    raise GatewayDeny(
        DenyReason.COMPARTMENT_DENIED,
        f"agent not entitled to compartment {entry.compartment}",
    )


async def _mandate_gate(
    identity: Identity, entry: AliasEntry, intent: NormalizedIntent
) -> None:
    """
    Enforce the alias's required capability UUID (timing-uniform, never the role), then
    — for grant issuance — the strict mandate-arg shape + target-compartment existence.
    """
    if entry.required_capability is None:
        return
    if not any(
        constant_time_equals(c, entry.required_capability)
        for c in identity.capabilities
    ):
        raise GatewayDeny(
            DenyReason.CAPABILITY_DENIED,
            f"missing capability {entry.required_capability}",
        )
    if entry.transport == "grant_issue":
        _validate_grant_args(identity, intent.arguments)


async def _community_gate(provider: CommunityGateProvider, entry: AliasEntry) -> None:
    """
    Pipeline step 4c′ — the deny-only COMMUNITY-GATE seam (Phase 2).

    Evaluates ``provider`` over a NARROW, topology-free whitelisted context (opaque alias +
    coarse transport class + risk tier + classification — NO target, NO secrets, NO
    arguments) and denies POLICY_GATE_DENIED on a ``deny`` outcome; any other outcome falls
    through to the next gate (which may itself deny). Deny-only + monotonic: it can ONLY add
    a deny, never allow what an earlier gate denied. With no gate engine registered
    ``provider`` is a strict NO-OP (the honest "no community gate engine configured" state —
    no gates enforced), so this is a pass-through until an engine lands.

    ``evaluate`` is wrapped fail-closed: any exception (a raising/buggy provider, a
    registered engine's eval error/timeout) → POLICY_GATE_DENIED, never a silent pass. It is
    a READ-ONLY predicate over already-normalized inputs — it NEVER recomputes canonical_json
    / the lock hash / mutates the intent or target. Mirrors ``main.MCPIPGateway._community_gate``
    so the two entrypoints stay in lockstep.
    """
    try:
        decision = await provider.evaluate(
            CommunityGateContext(
                alias=entry.alias,
                transport_class=entry.transport,
                risk_tier=entry.risk_tier,
                classification=entry.classification,
            )
        )
    except Exception as exc:  # noqa: BLE001 — a raising provider fails closed.
        raise GatewayDeny(
            DenyReason.POLICY_GATE_DENIED, "community gate evaluation failed"
        ) from exc
    if decision.outcome == "deny":
        raise GatewayDeny(DenyReason.POLICY_GATE_DENIED, decision.detail)


def _validate_grant_args(identity: Identity, arguments: dict[str, Any]) -> None:
    """
    Strict-validate grant mandate args, confirm the target compartment exists, and
    enforce COMPARTMENT-SCOPED issuance authority.

    The coarse ``CAP_COMPARTMENT_GRANT`` (checked in ``_mandate_gate``) only admits the
    caller to the grant governance alias — it is not a tenant-wide master key. To issue
    a grant for compartment ``X`` the issuer must ALSO hold ``grant_capability_for(X)``
    in its JWT ``capabilities`` claim (timing-uniform match). This closes the
    cross-compartment delegation escape: a FALCON-scoped delegator cannot mint AEGIS
    access for a colluding agent.
    """
    try:
        args = _GrantMandateArgs.model_validate(arguments)
    except Exception as exc:  # noqa: BLE001 — ValidationError → schema violation.
        raise GatewayDeny(DenyReason.SCHEMA_VIOLATION, str(exc)) from exc
    if not _components.registry.compartment_exists(
        identity.tenant_id, args.compartment
    ):
        raise GatewayDeny(DenyReason.COMPARTMENT_DENIED, "unknown compartment")
    required_scope = grant_capability_for(args.compartment)
    if not any(
        constant_time_equals(c, required_scope) for c in identity.capabilities
    ):
        raise GatewayDeny(
            DenyReason.CAPABILITY_DENIED,
            f"missing compartment-scoped grant capability for {args.compartment}",
        )


async def _dispatch(authorized: AuthorizedIntent, entry: AliasEntry) -> TransportResult:
    """
    Stage 8 — select the declared transport and execute; wrap failures fail-closed.

    Mirrors the demo's ``_dispatch``: an unknown transport is INTERNAL; any backend
    exception or a ``result.ok is False`` is TRANSPORT_ERROR. The concrete
    ``TransportResult`` topology (target, status) is NOT surfaced to the agent; the
    result is returned so the pipeline can peel off a ``cloud_iam`` vended credential
    (the deliverable) into the receipt — no other transport's result crosses the boundary.
    """
    transport = _components.transports.get(entry.transport)
    if transport is None:
        raise GatewayDeny(DenyReason.INTERNAL, f"no transport for {entry.transport}")
    try:
        result = await transport.execute(authorized, entry.target)
    except Exception as exc:  # noqa: BLE001 — any backend failure is opaque.
        raise GatewayDeny(DenyReason.TRANSPORT_ERROR, type(exc).__name__) from exc
    if not result.ok:
        raise GatewayDeny(DenyReason.TRANSPORT_ERROR, "transport reported failure")
    return result


# ---------------------------------------------------------------------------
# Forensic payload capture — best-effort side-channel, fired AFTER the authoritative
# WORM decision emit at each terminal. It can NEITHER delay, reorder, nor flip the
# ALLOW/DENY or the write-before-execute WORM record: the decision and its WORM record
# are already committed before capture begins, and the encrypted write is dispatched
# fire-and-forget (a tracked task) so a slow/hung capture cannot stall the response.
# ---------------------------------------------------------------------------

# Strong references to in-flight capture tasks so a fire-and-forget task is not GC'd mid-
# run (asyncio holds only a weak reference); the done-callback discards on completion.
_FORENSIC_TASKS: set["asyncio.Task[None]"] = set()


async def _forensic_capture_task(
    store: ForensicCaptureStore,
    tenant_id: str,
    correlation_id: str,
    snapshot: dict[str, Any],
) -> None:
    """Run one encrypted capture, swallowing EVERY failure to a counter + stderr note."""
    try:
        await store.capture(tenant_id, correlation_id, snapshot)
        FORENSIC.labels("captured").inc()
    except Exception as exc:  # noqa: BLE001 — capture failure never blocks/flips a decision.
        FORENSIC.labels("capture_error").inc()
        print(
            f"MCPIP: forensic capture dropped (best-effort): {type(exc).__name__}",
            file=sys.stderr,
            flush=True,
        )


def _capture_forensic(
    *,
    correlation_id: str,
    identity: Optional[Identity],
    intent: Optional[NormalizedIntent],
    decision: str,
    deny_reason: Optional[str],
) -> None:
    """
    Snapshot the agent's QUERY and dispatch a fire-and-forget encrypted capture.

    Called ONLY after the authoritative WORM emit at a terminal. No-op when the feature
    is off (``_components.forensic is None``) or there is no verified identity (an
    unauthenticated deny has no tenant-scoped query to reconstruct). SECRETS ARE NEVER
    PLACED IN THE SNAPSHOT: pin/jwt/pop_proof/vended-credential/challenge_id/lock_code/
    payload_hash/target are never included; the arguments are the already-canonicalized
    ingress object (identity-shaped keys were hard-denied at ingress), and the store runs
    the whole snapshot through the WORM ``_redact`` discipline before encryption.
    """
    forensic = _components.forensic
    if forensic is None or identity is None:
        FORENSIC.labels("capture_skipped").inc()
        return
    snapshot: dict[str, Any] = {
        "correlation_id": correlation_id,
        "tenant_id": identity.tenant_id,
        "agent_id": identity.agent_id,
        "session_id": identity.session_id,
        "role": identity.role,
        "issuer": identity.issuer,
        "act_sub": identity.act_sub,
        "alias": intent.alias if intent is not None else None,
        # A copy of the already-normalized arguments (never mutated). ``capture`` redacts.
        "arguments": dict(intent.arguments) if intent is not None else {},
        "source_format": intent.source_format.value if intent is not None else None,
        "decision": decision,
        "deny_reason": deny_reason,
        "captured_at": time.time(),
    }
    task = asyncio.create_task(
        _forensic_capture_task(forensic, identity.tenant_id, correlation_id, snapshot)
    )
    _FORENSIC_TASKS.add(task)
    task.add_done_callback(_FORENSIC_TASKS.discard)


# ---------------------------------------------------------------------------
# POST /v1/authorize — the full pipeline (§1.8), one choke point.
# ---------------------------------------------------------------------------


async def _run_authorize_pipeline(
    *,
    token: Optional[str],
    source_format: Optional[SourceFormat],
    vendor: Optional[str],
    tool_call: dict[str, Any],
    trace: Optional[SwarmTrace],
    pin: Optional[str],
    challenge_id: Optional[str],
    correlation_id: str,
    pop_proof: Optional[str] = None,
    http_method: Optional[str] = None,
    http_url: Optional[str] = None,
) -> Union[ExecutionReceipt, StagedChallenge]:
    """
    Steps 2–8 of the authorization pipeline — the SINGLE shared choke point behind
    both ``POST /v1/authorize`` and the MCP-native edge (``POST /v1/mcp``).

    Exactly one of ``source_format`` / ``vendor`` is supplied (the envelope
    validator guarantees it for /v1/authorize; the MCP edge always declares
    ``source_format=MCP_JSONRPC``). Vendor resolution runs at step 3 — AFTER JWT
    verification — so ``unknown_vendor`` denials are WORM-recorded with the
    caller's verified identity and never form an unauthenticated vendor-probing
    oracle. Any failure → emit a concrete DENY to WORM, raise the opaque
    ``MCPIPDenied``.
    """
    ctx: dict[str, Any] = {"correlation_id": correlation_id}
    # Tracked for the best-effort forensic capture at the generic-deny funnel (which
    # runs in the except block, where the try-local ``identity``/``intent`` are out of
    # scope). None until the corresponding stage sets them; capture no-ops on a None
    # identity (an unauthenticated deny has no tenant-scoped query to reconstruct).
    captured_identity: Optional[Identity] = None
    captured_intent: Optional[NormalizedIntent] = None

    try:
        # --- 2) Auth: identity is sovereign, JWT-only. --------------------------
        if not token:
            raise GatewayDeny(DenyReason.JWT_INVALID, "no bearer token supplied")
        identity = _components.auth.verify_identity(token)
        captured_identity = identity
        ctx["tenant_id"] = identity.tenant_id
        ctx["agent_id"] = identity.agent_id
        ctx["jti"] = identity.jti
        # Session identity → WORM/audit ONLY, like the delegation chain below: absent →
        # recorded neither, so pre-session tokens produce byte-identical events.
        if identity.session_id is not None:
            ctx["session_id"] = identity.session_id
        # Full RFC-8693 delegation chain + ID-JAG marker → WORM/audit ONLY (optional
        # per-event ctx fields, landing on ALLOW and every DENY leaf like jti). An
        # identity, NOT a secret: the chain is KEPT (not redacted) and never crosses the
        # agent wire (the authorize/catalog/tools-list projections build explicit
        # whitelists and never serialize ctx/Identity). Absent → recorded neither.
        if identity.act_chain:
            # Opt-in pseudonymization (default OFF ⇒ raw, byte-identical): the delegation
            # actors can name natural persons, so with a key each is recorded as a stable
            # keyed-HMAC pseudonym — crypto-shreddable, verify_chain-unaffected. #40b/E.
            ctx["delegation_chain"] = [
                _pseudonymize_principal(s, _components.pseudonym_key)
                for s in identity.act_chain
            ]
        if identity.id_jag:
            ctx["id_jag"] = True

        # --- Opt-in vendor telemetry: fold this governed agent identity into the tenant's
        # cardinality sketch (best-effort HLL PFADD). Placed right after identity resolution
        # so it is TIMING-UNIFORM across aliases/compartments (before any alias resolve —
        # no cross-compartment existence oracle) and covers every authenticated caller. It
        # is swallow-only inside record_agent: a Redis hiccup bumps a metric and returns, it
        # can NEVER block/delay/reorder/flip this authorization. Only the aggregate PFCOUNT
        # integer is ever read back — the agent_id lives solely inside the HLL registers.
        await _components.telemetry_stats.record_agent(
            identity.tenant_id, identity.agent_id
        )

        # --- 2b) Quarantine gate: a canary-tripped agent is frozen fail-closed. --
        # One Redis GET per request, right after identity — a quarantined agent
        # cannot reach parsing, resolution, or any later stage until the TTL
        # lapses. A Redis failure here raises LockError → LOCK_ERROR (fail-closed).
        if await _components.quarantine.is_quarantined(
            identity.tenant_id, identity.agent_id
        ):
            raise GatewayDeny(
                DenyReason.AGENT_QUARANTINED,
                "agent is quarantined (canary tripwire)",
            )

        # --- 2c) Revocation kill-switch: an admin-revoked principal is blocked. --
        # One more Redis GET right beside the quarantine gate. An operator holding
        # CAP_DIRECTORY_ADMIN can revoke a compromised/offboarded principal; every
        # request it makes is then denied PRINCIPAL_REVOKED until an admin
        # reactivates it — enforced BEFORE parsing/resolution, opaque to the agent.
        # A Redis failure raises LockError → LOCK_ERROR (fail-closed). This DENIES a
        # validly-signed token; it never mints one, so IdP sovereignty is untouched.
        if await _components.revocation.is_revoked(
            identity.tenant_id, identity.agent_id
        ):
            raise GatewayDeny(
                DenyReason.PRINCIPAL_REVOKED,
                "principal revoked by an operator (admin kill-switch)",
            )

        # --- 2d) Delegation: a token operating under a grant is INTERSECTED with
        # its live grant — never widened, never silently passed through. Any
        # missing/expired/revoked/mismatched grant (or the feature being disabled
        # while the claim is present) denies DELEGATION_INVALID, fail-closed. The
        # narrowed identity replaces the original for EVERYTHING downstream:
        # compartment visibility, capability gates, forensics.
        if identity.delegation_id is not None:
            ctx["delegation_id"] = identity.delegation_id
            try:
                identity = await _apply_delegation(identity)
            except _DelegationDenied as exc:
                raise GatewayDeny(DenyReason.DELEGATION_INVALID, exc.detail) from None
            captured_identity = identity

        # --- 3) Bridge: declared dialect → parser → normalize + deep gates. ------
        if source_format is not None:
            declared = source_format
        else:
            assert vendor is not None  # envelope validator guarantees exactly-one.
            declared = resolve_vendor(vendor)  # UnknownVendor → funnel → UNKNOWN_VENDOR
        ctx["source_format"] = declared.value
        resolved_trace = trace or _synth_single_hop_trace(identity.agent_id)
        intent = bridge_parse(tool_call, declared, resolved_trace)
        captured_intent = intent
        ctx["alias"] = intent.alias
        # A2A task-envelope correlation provenance → WORM/audit ONLY (topology-free,
        # RECORDED-NOT-TRUSTED). Present only for the a2a_task dialect; the declared
        # actor/delegation metadata is UNVERIFIED (MCPIP's identity is JWT-only), so it
        # authorizes nothing and — like delegation_chain — is never re-serialized to the
        # authorize response / /v1/catalog / tools/list agent-wire projections (those
        # build explicit whitelists and never serialize ctx). None → recorded nothing.
        project_a2a_context(ctx, intent.a2a_context)

        # --- 4) Obfuscator: tenant-scoped alias → real target. ------------------
        # Timing-uniform denial vs. the compartment gate (closes the existence oracle).
        entry = await _resolve_alias(identity, intent.alias)
        ctx["target"] = entry.target
        ctx["transport"] = entry.transport
        ctx["risk_tier"] = entry.risk_tier.value
        if entry.compartment is not None:
            ctx["compartment"] = entry.compartment
        ctx["classification"] = entry.classification.value

        # --- 4a) Canary tripwire: selecting a decoy quarantines the caller. -----
        # Checked BEFORE the compartment/mandate gates so the trip fires on first
        # touch regardless of entitlements. The quarantine mark is best-effort
        # (the deny stands even if Redis drops the mark); the deny itself is the
        # same opaque MCPIPDenied as every other reason — the attacker learns
        # nothing, the operator gets CANARY_TRIPPED in WORM. Timing stays uniform
        # with the neighbouring deny paths: one Redis write here vs. one grant
        # GET on the compartment-denied path vs. one decoy GET on a resolution
        # miss.
        if entry.canary:
            await _components.quarantine.quarantine(
                tenant_id=identity.tenant_id,
                agent_id=identity.agent_id,
                correlation_id=correlation_id,
                tripped_alias=intent.alias,
            )
            raise GatewayDeny(
                DenyReason.CANARY_TRIPPED,
                f"canary alias '{intent.alias}' selected",
            )

        # --- 4a′) Skill kill-switch: an admin-disabled alias is off for everyone. -
        # One Redis SISMEMBER after resolution, before the entitlement gates — a
        # disabled skill is denied regardless of capability. A Redis failure raises
        # LockError → LOCK_ERROR (fail-closed). This never edits alias→target.
        if await _components.skill_gate.is_disabled(identity.tenant_id, intent.alias):
            raise GatewayDeny(
                DenyReason.SKILL_DISABLED,
                f"skill '{intent.alias}' disabled by an operator",
            )

        # --- 4b) Compartment gate + 4c) capability/mandate gate. ----------------
        await _compartment_gate(identity, entry)
        await _mandate_gate(identity, entry, intent)

        # --- 4c′) Community-gate seam (DENY-ONLY, Phase 2). ---------------------
        # An author-your-own declarative gate over a topology-free whitelisted context
        # (opaque alias + coarse transport class + risk tier + classification — NO target,
        # NO secrets, NO arguments). A strict NO-OP until a CEL gate engine is registered
        # (the honest "none configured" state); it can ONLY add a POLICY_GATE_DENIED, never
        # rescue an earlier deny. Read-only — it NEVER recomputes the lock hash. Placed
        # right after the mandate gate and adjacent to the G3 policy gate below (both
        # deny-only overlays sit after the entitlement gates), identically to main.py.
        await _community_gate(_components.community_gate, entry)

        # --- 5) Bind + canonical payload hash. ----------------------------------
        authorized = AuthorizedIntent(
            intent=intent, identity=identity, correlation_id=correlation_id
        )
        payload_hash = lock_payload_hash(
            identity.tenant_id, identity.agent_id, intent.alias, intent.arguments
        )
        ctx["payload_hash"] = payload_hash

        # --- 5a) Sender-constraint (proof-of-possession), resource-aware. --------
        # Two independent triggers demand a key-proof here:
        #   * TOKEN-side  — the JWT carries a `cnf.jkt`, so it is NOT a bearer token
        #                   and the caller must prove possession of the confirmed key.
        #   * RESOURCE-side — the resolved alias is flagged `require_sender_constraint`
        #                   (default False), so even a caller whose JWT is a bare
        #                   bearer must upgrade to a proven token. This closes the
        #                   "stolen bearer reaches a sensitive action" gap at the
        #                   RESOURCE — critical for the CLASSIFIED/PHI/PII reads that
        #                   are AUTO-tier and therefore have NO PIN step-up.
        # The proof binds method+url+token(ath)+payload(pch)+freshness+single-use, so
        # possession of the token is never sufficient and a sniffed/relayed proof
        # cannot be substituted onto another action. Placed AFTER the
        # compartment/mandate gates (a bearer-vs-cnf branch never precedes the
        # Redis-touching entitlement gates, so it leaks no cross-compartment alias
        # existence) and AFTER the payload hash is known (so the proof binds the real
        # action). Bearer token + un-flagged alias → this whole block is skipped:
        # additive and backward-compatible.
        if entry.require_sender_constraint or identity.cnf_jkt is not None:
            # A resource that DEMANDS sender-constraint requires an ATTESTED cnf — one
            # minted by a trusted attesting issuer (identity.cnf_attested), not merely
            # any cnf. Otherwise a lower-assurance issuer trusted only for identity,
            # that also stamps `cnf`, would satisfy the gate (the weak-issuer downgrade
            # lane). A bare bearer (cnf None) is non-attested and refused here too.
            if entry.require_sender_constraint and not identity.cnf_attested:
                raise GatewayDeny(
                    DenyReason.SENDER_CONSTRAINT_REQUIRED,
                    f"alias '{intent.alias}' requires an attested sender-constrained token",
                )
            # Any presented cnf (from any trusted issuer) must still prove key
            # possession — even where the resource itself did not demand it.
            if identity.cnf_jkt is None:
                # Reachable only when require_sender_constraint is True but the token is
                # a bare bearer — already handled by the cnf_attested check above.
                raise GatewayDeny(
                    DenyReason.SENDER_CONSTRAINT_REQUIRED,
                    f"alias '{intent.alias}' requires a sender-constrained token",
                )
            if not pop_proof or not http_method or not http_url:
                raise GatewayDeny(
                    DenyReason.JWT_INVALID,
                    "sender-constrained token requires a proof-of-possession",
                )
            assert token is not None  # a cnf-bearing identity came from a real token.
            try:
                await verify_pop_proof(
                    pop_proof,
                    expected_jkt=identity.cnf_jkt,
                    http_method=http_method,
                    http_url=http_url,
                    access_token=token,
                    expected_payload_hash=payload_hash,
                    now_ts=time.time(),
                    replay=RedisReplayGuard(_components.redis_client),
                )
            except PopError as exc:
                raise GatewayDeny(
                    DenyReason.JWT_INVALID, f"proof-of-possession failed: {exc}"
                ) from exc
            if identity.act_sub is not None:
                # Delegation actor recorded to WORM only (never surfaced to the agent).
                # Opt-in pseudonymization (default OFF ⇒ raw, byte-identical). #40b/E.
                ctx["act_sub"] = _pseudonymize_principal(
                    identity.act_sub, _components.pseudonym_key
                )

        # --- 5b) Deny-only policy overlay: velocity cap + amount ceiling. --------
        # A stateless, opt-in policy step AFTER the entitlement + sender-constraint
        # gates (so a velocity INCR is never a cross-compartment alias-existence
        # side-effect/timing oracle, and an unentitled caller can never burn a
        # victim's budget) and BEFORE the risk gate. It can ONLY add a POLICY_DENIED —
        # never allow what an earlier gate denied, never mint identity, never mutate
        # the intent or target (PolicyContext is frozen and carries no target/identity
        # handle). Invoked only on the NON-completion pass (every AUTO request and
        # every PIN STAGING, never PIN COMPLETION), so a PIN_REQUIRED action's velocity
        # is counted exactly once: the amount is payload-locked (a changed completion
        # payload → PAYLOAD_MISMATCH), so the staging check covers completion, and a
        # completion cannot exist without a policy-passed, velocity-counted staging of
        # the identical payload. The skip condition REQUIRES risk_tier==PIN_REQUIRED,
        # so an AUTO request always evaluates regardless of any dummy pin (closing the
        # AUTO+dummy-pin velocity-skip bypass). evaluate() is wrapped fail-closed: any
        # exception (a raising/buggy provider, Redis down) → POLICY_DENIED. The concrete
        # cause rides only in the WORM detail; the agent sees the opaque MCPIPDenied.
        if not (entry.risk_tier is RiskTier.PIN_REQUIRED and pin is not None):
            try:
                policy_decision = await _components.policy.evaluate(
                    PolicyContext(
                        identity=identity,
                        alias=intent.alias,
                        transport_class=entry.transport,
                        risk_tier=entry.risk_tier,
                        arguments=intent.arguments,
                    )
                )
            except Exception as exc:  # noqa: BLE001 — a raising provider fails closed.
                raise GatewayDeny(
                    DenyReason.POLICY_DENIED, "policy evaluation failed"
                ) from exc
            if policy_decision.outcome == "deny":
                raise GatewayDeny(DenyReason.POLICY_DENIED, policy_decision.detail)

        # --- 6a) [NEW] Step-up staging: high-risk alias, no pin yet. -------------
        if entry.risk_tier is RiskTier.PIN_REQUIRED and pin is None:
            staged_challenge_id = await _components.auth.register_lock(
                identity, intent.alias, intent.arguments, entry.risk_tier
            )
            await _components.worm.emit(
                {
                    **ctx,
                    "decision": "deny",
                    "deny_reason": DenyReason.PIN_REQUIRED.value,
                    "challenge_id": staged_challenge_id,
                }
            )
            # Best-effort capture AFTER the authoritative staged-deny emit (never before).
            _capture_forensic(
                correlation_id=correlation_id,
                identity=identity,
                intent=intent,
                decision="deny",
                deny_reason=DenyReason.PIN_REQUIRED.value,
            )
            # Opt-in vendor telemetry: count this STAGED outcome for the tenant (best-effort,
            # swallow-only — after the decision is already determined). Aggregate integer only.
            await _components.telemetry_stats.record_decision(
                identity.tenant_id, "staged"
            )
            # Prometheus decision counter — incremented HERE, in the shared pipeline,
            # so EVERY edge (POST /v1/authorize AND the MCP-native POST /v1/mcp) counts
            # this staged outcome exactly once. Counting it only in the REST handler let
            # MCP decisions land in WORM/the feed but never in /metrics, so the console's
            # "decisions since start" tile undercounted vs the WORM-backed stream/analytics.
            DECISIONS.labels("staged").inc()
            return StagedChallenge(
                correlation_id=correlation_id,
                action_required=_STEP_UP_MESSAGE,
                challenge_id=staged_challenge_id,
                risk_tier=RiskTier.PIN_REQUIRED,
            )

        # --- 6b) Step-up completion: consume the exactly-once payload lock. ------
        if entry.risk_tier is RiskTier.PIN_REQUIRED:
            if challenge_id is None:
                raise GatewayDeny(DenyReason.PIN_NOT_FOUND, "no challenge_id supplied")
            # The envelope validator guarantees pin is present when challenge_id is.
            assert pin is not None
            ctx["lock_code"] = await _components.auth.consume_and_execute(
                identity, entry, intent.arguments, pin, challenge_id
            )

        # --- 7) Audit ALLOW (between consume and dispatch). ---------------------
        transaction_ref = "txn_" + uuid.uuid4().hex
        ctx["transaction_ref"] = transaction_ref
        await _components.worm.emit(
            {**ctx, "decision": "allow", "deny_reason": None}
        )
        # Best-effort capture AFTER the authoritative ALLOW emit and BEFORE dispatch —
        # it neither delays dispatch (fire-and-forget) nor reorders the emit. The
        # captured payload is the agent's QUERY, never the vended credential dispatch
        # will produce.
        _capture_forensic(
            correlation_id=correlation_id,
            identity=identity,
            intent=intent,
            decision="allow",
            deny_reason=None,
        )
        # Opt-in vendor telemetry: count this ALLOW for the tenant (best-effort, swallow-only —
        # after the authoritative WORM emit, before dispatch; it neither delays nor reorders
        # dispatch and can never fail the decision). Aggregate integer only, never the payload.
        await _components.telemetry_stats.record_decision(identity.tenant_id, "allow")

        # --- 8) Dispatch. -------------------------------------------------------
        dispatch_result = await _dispatch(authorized, entry)

        # cloud_iam: peel the vended short-lived credential off the transport result
        # into the receipt (the deliverable the agent uses). The secret material was
        # NEVER written to WORM — dispatch runs after the ALLOW record and the secret
        # never enters the audit ctx. Every other transport surfaces nothing.
        vended_credential: Optional[dict[str, Any]] = None
        if entry.transport == "cloud_iam":
            echo = dispatch_result.echo
            material = echo.get("_credential")
            vended_credential = {
                "provider": echo.get("provider"),
                "region": echo.get("region"),
                "expires_in": echo.get("expires_in"),
                "simulated": echo.get("simulated"),
                "fingerprint": echo.get("fingerprint"),
                "credential": material if isinstance(material, dict) else {},
            }

        # Read back the audit anchor (best-effort under concurrency; the record_hash
        # and transaction_ref are the authoritative anchors).
        raw_seq: Any = await _components.redis_client.get(_WORM_SEQ_KEY)
        worm_sequence = int(raw_seq) if raw_seq is not None else 0
        WORM_SEQUENCE.set(float(worm_sequence))

        # Prometheus decision counter — incremented HERE (after a successful dispatch,
        # mirroring the deny count in the except-funnel below) so every edge counts an
        # allow exactly once. See the staged note above: this closes the /v1/mcp gap
        # that made the console's decision total disagree with the WORM stream.
        DECISIONS.labels("allow").inc()
        return ExecutionReceipt(
            correlation_id=correlation_id,
            decision="allow",
            status="committed",
            transaction_ref=transaction_ref,
            executed_target_class=entry.transport,  # transport CLASS only, never target.
            worm_sequence=worm_sequence,
            vended_credential=vended_credential,
        )

    except Exception as exc:  # noqa: BLE001 — single fail-closed funnel.
        # Map to a concrete reason, record it to WORM (best-effort), then raise the
        # opaque agent-facing exception. The concrete reason NEVER reaches the agent.
        deny = map_engine_exception(exc)
        # Metric label safety: the exported decisions counter carries ONLY the coarse
        # ``decision`` outcome — the concrete deny reason is NEVER a label, because
        # /metrics is an unauthenticated, agent-reachable surface on the same socket as
        # /v1/authorize (a per-reason count would be a canary / alias-existence oracle).
        # The concrete reason rides ONLY into the WORM record below.
        DECISIONS.labels("deny").inc()
        # Every denial — including a pre-identity JWT failure — is durably audited: the
        # auth-failure trail is deliberate forensics (credential-stuffing / token-forgery
        # detection), covered by tests. NOTE (audit finding, accepted): under
        # appendfsync=always this lets an UNAUTHENTICATED flood amplify fsync writes. The
        # correct mitigation is a cheap pre-identity rate-limit at the edge/ingress
        # (infra), NOT dropping audit records — so we keep the record and rate-limit
        # upstream rather than trade away auth-failure visibility.
        try:
            await _components.worm.emit(
                {
                    **ctx,
                    "decision": "deny",
                    "deny_reason": deny.reason.value,
                    "detail": deny.detail,
                }
            )
        except Exception:  # noqa: BLE001 — a WORM/Redis outage must not un-deny.
            pass
        # Best-effort capture AFTER the authoritative deny emit. Uses the tracked
        # ``captured_identity``/``captured_intent`` (the try-locals are out of scope
        # here); no-ops when identity is None (a pre-auth deny has no query to
        # reconstruct). It cannot alter the deny already committed above.
        _capture_forensic(
            correlation_id=correlation_id,
            identity=captured_identity,
            intent=captured_intent,
            decision="deny",
            deny_reason=deny.reason.value,
        )
        # Opt-in vendor telemetry: count this DENY for the tenant — ONLY when a verified
        # tenant exists (a purely-unauthenticated deny — bad JWT / no tenant — is NOT
        # tenant-attributable and is honestly excluded, the same discipline the forensic
        # capture uses on a None identity). Best-effort, swallow-only, aggregate integer only.
        if captured_identity is not None:
            await _components.telemetry_stats.record_decision(
                captured_identity.tenant_id, "deny"
            )
        raise MCPIPDenied(correlation_id) from None


@app.post("/v1/authorize")
async def authorize(body: AuthorizeRequest, request: Request) -> Response:
    """
    Run the whole authorization pipeline end-to-end and return an opaque result.

    Faithful demo order with the ONE added step-up staging branch:
      1. correlation id (already minted by middleware).
      2. Auth: JWT → sovereign Identity.
      3. Bridge: DECLARED dialect (exactly one of ``source_format`` / ``vendor``)
         → pure format parser → NormalizedIntent (deep schema/char/size/inject).
      4. Obfuscator: tenant-scoped alias → AliasEntry.
      5. Bind + canonical payload hash.
      6. Risk gate — PIN_REQUIRED:
           * no pin  → register a payload-bound lock, emit a pin_required staging
                       record, return 202 StagedChallenge (no ALLOW). Stop.
           * pin     → atomically consume the exactly-once lock (map non-1 to deny).
      7. Audit ALLOW.
      8. Dispatch to the declared transport.
    Any failure → emit a concrete DENY to WORM, raise the opaque ``MCPIPDenied``.

    ONE authorize request authorizes exactly ONE tool call — the exactly-once
    payload lock, PIN step-up, and ExecutionReceipt are all singular. A batch
    (OpenAI ``tool_calls`` list, Gemini ``parts`` list, JSON-RPC batch) is denied;
    clients unbundle and submit one request per call.
    """
    correlation_id = _corr(request)
    token = body.jwt or _bearer_from_header(request)
    # Decision/latency metrics: labels are literals or closed-enum values ONLY —
    # never tenant/agent/alias/correlation data. A deny is counted inside the
    # pipeline's single funnel (with its concrete DenyReason) before the opaque
    # MCPIPDenied propagates; the ``deny`` default below labels its latency.
    started = time.perf_counter()
    decision = "deny"
    try:
        outcome = await _run_authorize_pipeline(
            token=token,
            source_format=body.source_format,
            vendor=body.vendor,
            tool_call=body.tool_call,
            trace=body.trace,
            pin=body.pin,
            challenge_id=body.challenge_id,
            correlation_id=correlation_id,
            pop_proof=_dpop_from_header(request),
            http_method=request.method,
            http_url=str(request.url),
        )
        if isinstance(outcome, StagedChallenge):
            # The DECISIONS staged/allow counters now fire inside _run_authorize_pipeline
            # (so the MCP edge counts too); here we only classify for the latency label.
            decision = "staged"
            return JSONResponse(status_code=202, content=outcome.model_dump())
        decision = "allow"
        return JSONResponse(status_code=200, content=outcome.model_dump())
    finally:
        LATENCY.labels(decision).observe(time.perf_counter() - started)


# ---------------------------------------------------------------------------
# POST /v1/authz/decision — the OpenID-AuthZEN / COAZ decision surface (PDP).
# ---------------------------------------------------------------------------
#
# MCPIP answers as a Policy Decision Point: a shop standardizing on AuthZEN calls
# this to get MCPIP's verdict WITHOUT executing anything. It is DECISION-ONLY — it
# runs the SAME deny chain the authorization pipeline runs from step 2b onward
# (quarantine → revocation → bridge/arg-safety → alias resolve → canary → skill
# kill-switch → compartment → mandate → community gate), but it NEVER computes a
# payload lock, stages/consumes a PIN, issues a grant, dispatches a transport, or
# vends a credential, and it deliberately EXCLUDES the G3 velocity/amount overlay
# (whose velocity INCR would consume real budget on a hypothetical query). A permit
# maps a PIN_REQUIRED tier / sender-constraint demand onto standards-shaped
# OBLIGATIONS rather than leaking a reason string; a deny is the bare, opaque
# ``{"decision": false}``.


# Standards-shaped obligation ids. A PIN_REQUIRED tier surfaces as a step-up
# obligation; a sender-constraint demand (or a cnf-bearing token) as a DPoP
# obligation — never a deny-reason string, so opacity is preserved on a permit.
_OBLIGATION_STEP_UP_PIN: Final = {"id": "mcpip.step_up.pin"}
_OBLIGATION_SENDER_CONSTRAINT_DPOP: Final = {"id": "mcpip.sender_constraint.dpop"}


async def _evaluate_authz_decision(
    *,
    identity: Identity,
    resource: AuthzenResource,
    action: AuthzenAction,
    correlation_id: str,
) -> tuple[bool, list[dict[str, Any]], Optional[str]]:
    """
    Run the pre-execution deny chain for a hypothetical call and return the verdict.

    Returns ``(allowed, obligations, deny_reason)``: on a permit ``(True, [obligation…],
    None)``; on a deny ``(False, [], deny_reason_value)`` where ``deny_reason_value`` is
    the concrete ``DenyReason`` value for the ADVISORY WORM record ONLY — it never crosses
    the agent boundary (the endpoint returns the bare ``{"decision": false}``).

    Reuses the SAME already-factored gate helpers as ``_run_authorize_pipeline`` and is
    READ-ONLY except for the ONE deliberate side effect the 'trip fires on first touch'
    invariant demands: naming a canary alias trips the quarantine (a decision query that
    names bait IS a touch; otherwise the surface would be a canary-safe enumeration
    channel). It NEVER computes ``lock_payload_hash``, registers/consumes a lock, issues a
    grant, dispatches, vends, or evaluates the G3 velocity/amount overlay (its INCR is a
    state mutation that would burn real budget on a hypothetical query — velocity/amount
    are runtime rate controls, not part of a pre-execution authorization verdict). Any
    exception funnels through ``map_engine_exception`` to a fail-closed ``decision:false``.
    """
    try:
        # (a) Quarantine gate — a canary-tripped agent is frozen (fail-closed read).
        if await _components.quarantine.is_quarantined(
            identity.tenant_id, identity.agent_id
        ):
            raise GatewayDeny(
                DenyReason.AGENT_QUARANTINED, "agent is quarantined (canary tripwire)"
            )
        # (b) Revocation kill-switch — an admin-revoked principal is blocked.
        if await _components.revocation.is_revoked(
            identity.tenant_id, identity.agent_id
        ):
            raise GatewayDeny(
                DenyReason.PRINCIPAL_REVOKED, "principal revoked by an operator"
            )
        # (c) Map SARC → the SAME MCP ingress path a real call takes, so the arguments
        # flow through the identity-injection hard-deny + depth/size/char caps of
        # ``enforce_argument_safety`` (used READ-ONLY — never modified here).
        envelope = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "tools/call",
            "params": {"name": resource.id, "arguments": action.properties or {}},
        }
        intent = bridge_parse(
            envelope,
            SourceFormat.MCP_JSONRPC,
            _synth_single_hop_trace(identity.agent_id),
        )
        # (d) Obfuscator — timing-uniform resolution (keeps the decoy-round-trip discipline
        # so this surface is not a lower-friction cross-compartment existence oracle).
        entry = await _resolve_alias(identity, intent.alias)
        # (e) Canary tripwire — the ONE deliberate side effect (see docstring).
        if entry.canary:
            await _components.quarantine.quarantine(
                tenant_id=identity.tenant_id,
                agent_id=identity.agent_id,
                correlation_id=correlation_id,
                tripped_alias=intent.alias,
            )
            raise GatewayDeny(
                DenyReason.CANARY_TRIPPED, f"canary alias '{intent.alias}' selected"
            )
        # (f) Skill kill-switch — a disabled alias is off for everyone.
        if await _components.skill_gate.is_disabled(identity.tenant_id, intent.alias):
            raise GatewayDeny(
                DenyReason.SKILL_DISABLED, f"skill '{intent.alias}' disabled"
            )
        # (g) Compartment gate + (h) capability/mandate gate + (i) community gate.
        await _compartment_gate(identity, entry)
        await _mandate_gate(identity, entry, intent)
        await _community_gate(_components.community_gate, entry)

        # --- Permit: compute standards-shaped obligations. ----------------------
        obligations: list[dict[str, Any]] = []
        # A resource that DEMANDS sender-constraint is satisfied ONLY by an attested cnf —
        # a bare bearer / non-attested token on such a resource is a DENY (mirrors the
        # pipeline's SENDER_CONSTRAINT_REQUIRED), not a permit-with-obligation.
        if entry.require_sender_constraint and not identity.cnf_attested:
            raise GatewayDeny(
                DenyReason.SENDER_CONSTRAINT_REQUIRED,
                f"alias '{intent.alias}' requires an attested sender-constrained token",
            )
        if entry.require_sender_constraint or identity.cnf_jkt is not None:
            obligations.append(dict(_OBLIGATION_SENDER_CONSTRAINT_DPOP))
        if entry.risk_tier is RiskTier.PIN_REQUIRED:
            obligations.append(dict(_OBLIGATION_STEP_UP_PIN))
        return (True, obligations, None)
    except Exception as exc:  # noqa: BLE001 — decision-only fail-closed funnel.
        deny = map_engine_exception(exc)
        return (False, [], deny.reason.value)


@app.post("/v1/authz/decision")
async def authz_decision(body: AuthzenDecisionRequest, request: Request) -> Response:
    """
    OpenID-AuthZEN Authorization API 1.0 decision endpoint — MCPIP as a PDP.

    Control-plane authz query: JWT-gated (a valid own-identity token is required; endpoint
    auth is 'is your JWT valid', DISTINCT from the decision verdict) and tenant-scoped. The
    AuthZEN ``subject`` is NEVER consulted for identity — tenant/agent/role/capabilities all
    come only from the verified JWT, so identity injection via ``subject`` is structurally
    impossible. ``resource.id`` is the opaque alias; ``action.properties`` the arguments.

    Returns ``{"decision": true}`` (optionally with ``obligations``) or the bare opaque
    ``{"decision": false}`` (no reason/target/topology). Emits ONE DISTINCT ADVISORY WORM
    record (``decision='admin_action'``, ``admin_action='authz_decision'``, ``advisory=true``)
    that never reads as an execution ALLOW/DENY and carries no target/secret/subject — the
    surface executes nothing, so write-before-execute is untouched. Available IN PRODUCTION.
    """
    correlation_id = _corr(request)
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(correlation_id)
    try:
        identity = _components.auth.verify_identity(token)
    except Exception:  # noqa: BLE001 — any JWT failure is an opaque deny (never a verdict).
        raise MCPIPDenied(correlation_id) from None
    try:
        identity = await _apply_delegation(identity)
    except _DelegationDenied:
        raise MCPIPDenied(correlation_id) from None

    allowed, obligations, deny_reason = await _evaluate_authz_decision(
        identity=identity,
        resource=body.resource,
        action=body.action,
        correlation_id=correlation_id,
    )

    # ONE distinct advisory record — NEVER decision='allow'/'deny' (so it can't be mistaken
    # for an execution verdict nor pollute the authoritative execution audit), carrying no
    # target/secret/subject. Best-effort like the deny path: a WORM outage never fails the
    # read-only decision (there is nothing to un-execute).
    try:
        await _components.worm.emit(
            {
                "decision": "admin_action",
                "admin_action": "authz_decision",
                "advisory": True,
                "authz_allowed": allowed,
                "deny_reason": deny_reason,
                "obligations": [o["id"] for o in obligations],
                "tenant_id": identity.tenant_id,
                "agent_id": identity.agent_id,
                "session_id": identity.session_id,
                "alias": body.resource.id,
                "correlation_id": correlation_id,
                "ts": time.time(),
            }
        )
    except Exception:  # noqa: BLE001 — a WORM/Redis outage must not fail the query.
        pass

    content = AuthzenDecisionResponse(
        decision=allowed, obligations=obligations or None
    ).model_dump(exclude_none=True)
    return JSONResponse(status_code=200, content=content)


# ---------------------------------------------------------------------------
# POST /v1/mcp — the MCP-native edge (first-class, NOT a proxy).
# ---------------------------------------------------------------------------
#
# MCPIP **is** the MCP server the client connects to; it is the authorization
# boundary. It never forwards to an external MCP server, opens no outbound
# connection, and holds no keys — after ALLOW, dispatch goes through the existing
# BaseTransport table exactly like /v1/authorize. NormalizedIntent stays internal;
# the wire sees only JSON-RPC results and opaque errors.

_MCP_PROTOCOL_VERSION = "2025-06-18"
_MCP_STEP_UP_INSTRUCTION = (
    "Step-up required: complete via POST /v1/authorize with "
    'source_format="mcp_jsonrpc", the identical JSON-RPC tool_call dict, plus '
    "pin + challenge_id. The payload lock is format-independent, so a lock "
    "registered here consumes cleanly via /v1/authorize."
)

# --- MRT / SEP-2322 step-up transport (additive, opt-in) --------------------
# The payload-bound PIN step-up mapped onto the MCP Multi-Round-Trip InputRequired
# shape, on the ``tools/call`` branch ONLY, as a pure TRANSPORT representation over
# the UNCHANGED register_lock / consume_and_execute path. The existing opaque
# ``challenge_id`` (uuid4 hex from PinValidator.register — no topology) IS the MRT
# ``requestState``; there is NO parallel state store. Because the JSON-RPC parsers
# are ``extra="forbid"``, these three OPTIONAL top-level request keys cannot ride
# inside the strict body — they are negotiated at the edge and POPPED before the
# body reaches the parser (so a re-issue's ``params`` stays byte-identical → the
# NormalizedIntent / arguments / lock hash are provably identical, and any OTHER
# unexpected top-level key still trips ``extra=forbid`` → SCHEMA_VIOLATION as today):
#   * ``stepUp`` == "mrt"   — first-call opt-in to the MRT representation
#   * ``requestState``      — the re-issue continuation handle (== ``challenge_id``)
#   * ``inputResponses``    — the answers, ``{"pin": "<one-time PIN>"}``
_MRT_KEYS = frozenset({"stepUp", "requestState", "inputResponses"})
_MCP_MRT_STEP_UP_MESSAGE = (
    "Step-up required. Re-issue this identical tools/call over POST /v1/mcp with "
    'the returned requestState and inputResponses={"pin": "<one-time PIN>"}. The '
    "one-time PIN is delivered out-of-band by your configured authenticator; the "
    "request payload must be byte-identical or the step-up is rejected."
)
_MCP_MRT_PIN_PROMPT = (
    "Enter the one-time PIN delivered out-of-band by your configured authenticator."
)


def _jsonrpc_request_id(payload: dict[str, Any]) -> Union[str, int, None]:
    """Echo the request ``id`` when it is a str/int, else null (never invented)."""
    request_id = payload.get("id")
    if isinstance(request_id, bool):  # bool ⊂ int — a bool id is NOT a valid id.
        return None
    if isinstance(request_id, (str, int)):
        return request_id
    return None


def _jsonrpc_error(
    request_id: Union[str, int, None],
    code: int,
    message: str,
    data: Optional[dict[str, Any]] = None,
) -> JSONResponse:
    """JSON-RPC 2.0 error envelope — HTTP 200, same opacity as the 403 path."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse(
        status_code=200,
        content={"jsonrpc": "2.0", "id": request_id, "error": error},
    )


def _jsonrpc_result(
    request_id: Union[str, int, None], result: dict[str, Any]
) -> JSONResponse:
    """JSON-RPC 2.0 result envelope."""
    return JSONResponse(
        status_code=200,
        content={"jsonrpc": "2.0", "id": request_id, "result": result},
    )


@app.post("/v1/mcp")
async def mcp_edge(request: Request) -> Response:
    """
    Single MCP endpoint — JSON-RPC 2.0 over HTTP (Streamable-HTTP-compatible
    single-request mode). Identity is ``Authorization: Bearer`` header ONLY (no
    jwt-in-body variant on this edge). Method routing by the ``method`` key:

      * ``initialize``                — no auth; static server card, no tenant data.
      * ``notifications/initialized`` — no auth; HTTP 202, empty body.
      * ``tools/list``                — JWT; same visibility as ``/v1/catalog``,
                                        metadata only, never targets.
      * ``tools/call``                — JWT; the full JSON-RPC body dict runs the
                                        shared authorize pipeline as MCP_JSONRPC.
      * anything else                 — JSON-RPC ``-32601 method not found``.

    ONE call per request: a top-level array (a JSON-RPC batch) is rejected with
    ``-32600 invalid request``. A deny is an HTTP 200 JSON-RPC error carrying only
    the generic message + correlation id — same opacity as the 403 path; the
    concrete reason lives only in WORM.
    """
    correlation_id = _corr(request)

    try:
        payload: Any = await request.json()
    except Exception:  # noqa: BLE001 — malformed JSON body.
        return _jsonrpc_error(None, -32700, "parse error")
    if not isinstance(payload, dict):
        # A JSON-RPC batch (top-level array) or any non-object body: one call per
        # request (§2.3) — clients unbundle.
        return _jsonrpc_error(None, -32600, "invalid request")

    request_id = _jsonrpc_request_id(payload)
    method = payload.get("method")

    if method == "initialize":
        return _jsonrpc_result(
            request_id,
            {
                "protocolVersion": _MCP_PROTOCOL_VERSION,
                # ``experimental.mcpipStepUp`` additively advertises the MRT step-up
                # representation on tools/call (SEP-2322). Additive key — MCP clients
                # ignore unknown capability entries, so the classic PIN staging path
                # stays the default and existing initialize assertions hold.
                "capabilities": {
                    "tools": {},
                    "experimental": {"mcpipStepUp": {"mode": "mrt"}},
                },
                "serverInfo": {"name": "mcpip", "version": get_version()},
            },
        )

    if method == "notifications/initialized":
        return Response(status_code=202)

    if method == "tools/list":
        token = _bearer_from_header(request)
        if not token:
            return _jsonrpc_error(
                request_id,
                -32000,
                AGENT_FACING_DENY_MESSAGE,
                {"correlation_id": correlation_id},
            )
        try:
            identity = _components.auth.verify_identity(token)
        except Exception:  # noqa: BLE001 — any JWT failure is an opaque deny.
            return _jsonrpc_error(
                request_id,
                -32000,
                AGENT_FACING_DENY_MESSAGE,
                {"correlation_id": correlation_id},
            )
        try:
            identity = await _apply_delegation(identity)
        except _DelegationDenied:
            return _jsonrpc_error(
                request_id,
                -32000,
                AGENT_FACING_DENY_MESSAGE,
                {"correlation_id": correlation_id},
            )
        visible = await _components.obf.list_visible(
            _components.registry, identity, _components.grants
        )
        tools = [
            {
                "name": entry.alias,
                "description": (
                    f"risk_tier={entry.risk_tier.value}; "
                    f"classification={entry.classification.value}"
                ),
                "inputSchema": {"type": "object"},
            }
            for entry in visible
        ]
        # Advertise COAZ / OpenID-AuthZEN support additively alongside ``tools``. MCP
        # clients ignore unknown result keys, so this breaks no existing consumer; a
        # COAZ-aware client learns MCPIP exposes a decision surface (POST /v1/authz/decision).
        return _jsonrpc_result(request_id, {"tools": tools, "coaz": True})

    if method == "tools/call":
        # MRT (SEP-2322) negotiation at the edge — additive, opt-in, classic default
        # preserved. Pop ONLY the three reserved MRT keys (never reconstruct-whitelist),
        # so a re-issue's ``params`` is byte-identical to the original call (identical
        # NormalizedIntent / arguments / lock hash) and any OTHER unexpected top-level
        # key still trips the parser's ``extra=forbid`` → SCHEMA_VIOLATION exactly as
        # today. When no MRT key is present, ``cleaned == payload`` and both pipeline
        # inputs are None → this branch behaves byte-for-byte like the classic edge.
        cleaned = {k: v for k, v in payload.items() if k not in _MRT_KEYS}
        mrt_optin = (
            payload.get("stepUp") == "mrt"
            or "requestState" in payload
            or "inputResponses" in payload
        )
        request_state = payload.get("requestState")
        input_responses = payload.get("inputResponses")
        mrt_pin: Optional[str] = None
        if isinstance(input_responses, dict):
            candidate = input_responses.get("pin")
            if isinstance(candidate, str):
                mrt_pin = candidate
        # Guard: a continuation handle (requestState) MUST be an opaque string paired
        # with a well-formed pin, mirroring the /v1/authorize envelope's pin+challenge_id
        # pairing invariant. A malformed continuation (non-string requestState, or a
        # missing / non-dict / typed-wrong inputResponses.pin) cannot complete the
        # payload lock and would trip the pipeline's step-6b ``assert pin is not None`` —
        # so fail closed opaquely at the edge. This short-circuit is cheaper than any
        # Redis op and never reaches scrypt; it does NOT weaken the consume-rate
        # pre-throttle, because a well-formed-but-WRONG pin still flows through the
        # pipeline → consume_and_execute → _enforce_consume_rate → the atomic Lua.
        if "requestState" in payload and (
            not isinstance(request_state, str) or mrt_pin is None
        ):
            return _jsonrpc_error(
                request_id,
                -32000,
                AGENT_FACING_DENY_MESSAGE,
                {"correlation_id": correlation_id},
            )
        mrt_challenge_id: Optional[str] = (
            request_state if isinstance(request_state, str) else None
        )
        try:
            outcome = await _run_authorize_pipeline(
                token=_bearer_from_header(request),
                source_format=SourceFormat.MCP_JSONRPC,
                vendor=None,
                tool_call=cleaned,
                trace=None,
                pin=mrt_pin,
                challenge_id=mrt_challenge_id,
                correlation_id=correlation_id,
                pop_proof=_dpop_from_header(request),
                http_method=request.method,
                http_url=str(request.url),
            )
        except MCPIPDenied as denied:
            # Same opacity as the 403 path; concrete reason lives only in WORM. A
            # tampered re-issue → PAYLOAD_MISMATCH, a spent lock → PIN_NOT_FOUND, a
            # failed OTP delivery → OTP_DELIVERY_FAILED — all opaque here.
            return _jsonrpc_error(
                request_id,
                -32000,
                AGENT_FACING_DENY_MESSAGE,
                {"correlation_id": denied.correlation_id},
            )
        if isinstance(outcome, StagedChallenge):
            if mrt_optin:
                # MRT InputRequired representation (opt-in only). ``requestState`` IS the
                # opaque challenge_id (no topology); ``inputRequests`` asks for the
                # sensitive one-time PIN; ``content`` is generic — the OTP is delivered
                # out-of-band and never rides the response. The client completes by
                # re-issuing the identical tools/call with requestState + inputResponses.
                return _jsonrpc_result(
                    request_id,
                    {
                        "requestState": outcome.challenge_id,
                        "inputRequests": [
                            {
                                "name": "pin",
                                "type": "string",
                                "title": "One-time PIN",
                                "description": _MCP_MRT_PIN_PROMPT,
                                "sensitive": True,
                            }
                        ],
                        "content": [
                            {"type": "text", "text": _MCP_MRT_STEP_UP_MESSAGE}
                        ],
                        "isError": True,
                    },
                )
            # Classic staged result (default) — byte-for-byte unchanged. Step-up
            # completion via /v1/authorize (or the MRT re-issue above).
            staged_text = json.dumps(
                {
                    "action_required": _MCP_STEP_UP_INSTRUCTION,
                    "challenge_id": outcome.challenge_id,
                    "correlation_id": outcome.correlation_id,
                    "risk_tier": outcome.risk_tier.value,
                }
            )
            return _jsonrpc_result(
                request_id,
                {
                    "content": [{"type": "text", "text": staged_text}],
                    "isError": True,
                },
            )
        return _jsonrpc_result(
            request_id,
            {
                "content": [{"type": "text", "text": outcome.model_dump_json()}],
                "isError": False,
            },
        )

    return _jsonrpc_error(request_id, -32601, "method not found")


# ---------------------------------------------------------------------------
# Liveness / readiness.
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, Optional[str]]:
    """Liveness — no dependency check; proves the process is up and serving.

    ``loop`` reports the installed event-loop backend (``uvloop`` when available,
    ``asyncio`` on fallback) so operators/tests can confirm the performance loop.
    ``version`` is the release version from the single-source ``VERSION`` file.
    ``region`` is the BEHAVIOR-NEUTRAL operator region tag (``MCPIP_REGION``) — an
    observability label only (``None`` when unset), never consulted for routing,
    authorization, key derivation, or storage (see ``docs/operate/OPERATIONS.md``).
    """
    return {
        "status": "live",
        "glyph": _GLYPH,
        "loop": _LOOP_BACKEND,
        "version": get_version(),
        "region": _components.settings.region,
    }


@app.get(WELL_KNOWN_PRM_PATH)
async def oauth_protected_resource_metadata() -> Response:
    """RFC 9728 Protected Resource Metadata — PUBLIC, unauthenticated discovery doc.

    MCPIP's MCP edge is an OAuth 2.1 RESOURCE SERVER; a conformant client reads this
    document to learn (a) the resource identifier tokens must be audience-bound to
    (RFC 8707) and (b) the authorization server(s) that issue them, so it presents a
    correctly-scoped token instead of routing around the gateway. Derived entirely from
    live Settings + the trusted-issuer resolver — it carries NO secret and NO
    alias→target topology, only the two non-secret discovery identifiers RFC 9728 exists
    to publish. Reachable in BOTH sandbox and production (a discovery doc must be findable),
    and exempt from edge shedding (parity with /healthz + /metrics), like any well-known.
    """
    return JSONResponse(
        status_code=200,
        content=build_protected_resource_metadata(
            _components.resolver, _components.settings
        ),
    )


@app.get("/metrics")
async def metrics() -> Response:
    """
    Prometheus exposition — aggregate counters/latencies/chain heights ONLY.

    Label discipline is enforced by construction in ``core.metrics``: every label
    value anywhere in the codebase is a string literal or a closed-enum value, so
    no tenant, agent, alias, compartment, capability UUID, correlation id, JWT
    material, or approval code can appear here. Exempt from edge shedding (a
    scrape is never dropped); NETWORK exposure is confined by the deployment's
    NetworkPolicy, not by this process.
    """
    payload, content_type = render_metrics()
    return Response(content=payload, media_type=content_type)


@app.get("/readyz")
async def readyz() -> Response:
    """Readiness — gated on Redis reachability (all sync state lives there)."""
    try:
        pong = await _components.redis_client.ping()
    except Exception:  # noqa: BLE001 — any failure means not-ready, fail-closed.
        pong = False
    if pong:
        return JSONResponse(status_code=200, content={"status": "ready", "redis": "up"})
    return JSONResponse(
        status_code=503, content={"status": "not-ready", "redis": "down"}
    )


# ---------------------------------------------------------------------------
# Sandbox-only affordances — refuse to exist when sandbox_mode is False.
# ---------------------------------------------------------------------------


class _DevTokenRequest(BaseModel):
    """Body for the sandbox dev-token minter; identity fields default to the demo.

    ``compartment`` / ``capabilities`` are OPTIONAL — omitted → the legacy 8-claim
    token; supplied → the UUID-identified compartment/capability claims.
    """

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = "tenant-acme"
    agent_id: str = "agent-orchestrator-1"
    role: str = "ops"
    compartment: Optional[str] = None
    capabilities: Optional[list[str]] = None
    # OPTIONAL session identity (UUID) — stamped into the token so the WORM chain can
    # tell sessions of one agent apart. The resolver enforces UUID-or-deny, so the
    # forge pre-checks it with compartment/capabilities for a diagnosable 400 here
    # rather than an opaque 403 on the first governed call.
    session_id: Optional[str] = None
    # OPTIONAL delegation grant reference (UUID) — sandbox testing of the
    # delegated-token path; the resolver enforces UUID-or-deny like session_id.
    delegation_id: Optional[str] = None


@app.post("/v1/dev/token")
async def dev_token(body: _DevTokenRequest) -> Response:
    """
    SANDBOX ONLY — mint a valid EdDSA JWT via the in-process ``_DemoIdP``.

    Returns 404 (the endpoint "does not exist") when ``sandbox_mode`` is False or no
    in-process IdP is configured, preserving identity sovereignty in production.
    """
    if not _components.settings.sandbox_mode or _components.demo_idp is None:
        return JSONResponse(status_code=404, content={"error": "not found"})
    # Fail fast on malformed capability/compartment UUIDs. Non-UUID caps (e.g. a
    # literal "undefined") otherwise mint a token that only fails much later as an
    # undiagnosable opaque 403 on the first governed call. The check runs AFTER the
    # sandbox gate so production still returns a flat 404 for every body (the
    # endpoint "does not exist"). Well-known UUIDs: GET /v1/dev/capabilities.
    def _bad(values: object) -> list[str]:
        out: list[str] = []
        for v in values if isinstance(values, list) else ([values] if values else []):
            try:
                uuid.UUID(str(v))
            except (ValueError, AttributeError, TypeError):
                out.append(str(v))
        return out

    malformed = (
        _bad(body.capabilities)
        + _bad(body.compartment)
        + _bad(body.session_id)
        + _bad(body.delegation_id)
    )
    if malformed:
        return JSONResponse(
            status_code=400,
            content={
                "error": f"not a UUID: {', '.join(malformed)}",
                "hint": "the well-known capability UUIDs are at GET /v1/dev/capabilities",
            },
        )
    token = _components.demo_idp.mint(
        tenant_id=body.tenant_id,
        agent_id=body.agent_id,
        role=body.role,
        compartment=body.compartment,
        capabilities=body.capabilities,
        session_id=body.session_id,
        delegation_id=body.delegation_id,
    )
    return JSONResponse(status_code=200, content={"jwt": token})


@app.get("/v1/dev/capabilities")
async def dev_capabilities() -> Response:
    """
    SANDBOX ONLY — the well-known, fixed capability UUIDs so an operator does not
    have to read source to mint an admin/audit token. 404 outside sandbox.

    These are constants (interfaces.py), not per-tenant grants; they gate the admin
    control plane and the forensic read. `role` in a token authorizes NOTHING — only
    these capabilities do.
    """
    if not _components.settings.sandbox_mode:
        return JSONResponse(status_code=404, content={"error": "not found"})
    return JSONResponse(
        status_code=200,
        content={
            "capabilities": {
                "CAP_DIRECTORY_ADMIN": str(CAP_DIRECTORY_ADMIN),
                "CAP_FORENSIC_READ": str(CAP_FORENSIC_READ),
                "CAP_CATALOG_REVIEWER": str(CAP_CATALOG_REVIEWER),
                "CAP_COMPARTMENT_GRANT": str(CAP_COMPARTMENT_GRANT),
                "CAP_COMPARTMENT_REVOKE": str(CAP_COMPARTMENT_REVOKE),
            }
        },
    )


class _DelegateRequest(BaseModel):
    """Body for ``POST /v1/delegate`` (docs/SESSION_DELEGATION_DESIGN.md §2)."""

    model_config = ConfigDict(extra="forbid")

    child_agent_id: str
    child_session_id: str
    capabilities: list[str] = []
    compartment: Optional[str] = None
    expires_in_s: int = 3600


class _DelegateRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str


def _verified_token_exp(token: str) -> Optional[int]:
    """The ``exp`` of an ALREADY-VERIFIED token (display-free re-read of the same
    payload the resolver just validated — never used on an unverified token)."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
        exp = claims.get("exp")
        return int(exp) if isinstance(exp, (int, float)) else None
    except Exception:  # noqa: BLE001 — absent exp just means no token-exp clamp.
        return None


async def _delegation_caller(request: Request) -> Identity:
    """Verify + kill-switch-check + delegation-narrow the calling session for the
    /v1/delegate surfaces. A revoked or quarantined principal must not spawn or
    revoke children; a delegated caller operates under its EFFECTIVE authority."""
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        identity = _components.auth.verify_identity(token)
    except Exception:  # noqa: BLE001 — any JWT failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        revoked = await _components.revocation.is_revoked(
            identity.tenant_id, identity.agent_id
        )
        quarantined = await _components.quarantine.is_quarantined(
            identity.tenant_id, identity.agent_id
        )
    except Exception:  # noqa: BLE001 — a store failure denies (fail-closed).
        raise MCPIPDenied(_corr(request)) from None
    if revoked or quarantined:
        raise MCPIPDenied(_corr(request))
    try:
        return await _apply_delegation(identity)
    except _DelegationDenied:
        raise MCPIPDenied(_corr(request)) from None


@app.post("/v1/delegate")
async def delegate(body: _DelegateRequest, request: Request) -> Response:
    """
    Register an ATTENUATED grant for a child session (docs/SESSION_DELEGATION_DESIGN.md §2).

    Requires no capability — deliberately: registration can only NARROW the
    caller's own authority (capabilities strictly ⊆ its effective set, compartment
    same-or-narrower, expiry min-of-three), so a dispatcher agent is a normal
    caller, not an admin event. Rule violations are refused with a diagnosable
    400, never silently intersected. The grant is WORM-sealed BEFORE it becomes
    readable by the authorize path; if the chain cannot be written, no grant
    exists. 404 when the deployment has delegation disabled.
    """
    if not _components.settings.delegation_enabled:
        return JSONResponse(status_code=404, content={"error": "not found"})
    token = _bearer_from_header(request) or ""
    identity = await _delegation_caller(request)
    if identity.session_id is None:
        return JSONResponse(
            status_code=400,
            content={"error": "the delegating token must carry a session_id claim"},
        )

    def _bad_uuid(values: list[str]) -> list[str]:
        out = []
        for v in values:
            try:
                uuid.UUID(str(v))
            except (ValueError, AttributeError, TypeError):
                out.append(str(v))
        return out

    malformed = _bad_uuid([body.child_session_id]) + _bad_uuid(body.capabilities)
    if body.compartment is not None:
        malformed += _bad_uuid([body.compartment])
    if malformed:
        return JSONResponse(
            status_code=400, content={"error": f"not a UUID: {', '.join(malformed)}"}
        )

    parent_grant = None
    if identity.delegation_id is not None:
        parent_grant = await _components.delegation.fetch(
            identity.tenant_id, identity.delegation_id
        )
        if parent_grant is None:
            raise MCPIPDenied(_corr(request))

    try:
        grant = DelegationStore.prepare(
            tenant_id=identity.tenant_id,
            parent_session_id=identity.session_id,
            parent_agent_id=identity.agent_id,
            parent_effective_capabilities=identity.capabilities,
            parent_effective_compartment=identity.compartment,
            parent_token_exp=_verified_token_exp(token),
            parent_grant=parent_grant,
            child_agent_id=body.child_agent_id,
            child_session_id=body.child_session_id,
            capabilities=body.capabilities,
            compartment=body.compartment,
            expires_in_s=body.expires_in_s,
        )
    except DelegationError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    # Write-before-execute: the grant is sealed to the chain BEFORE it can be
    # read by the authorize path. An unsealable grant must not exist.
    try:
        await _components.worm.emit(
            {
                "decision": "admin_action",
                "admin_action": "delegation_granted",
                "tenant_id": grant.tenant_id,
                "agent_id": identity.agent_id,
                "session_id": grant.parent_session_id,
                "delegation_id": grant.delegation_id,
                "child_session_id": grant.child_session_id,
                "child_agent_id": grant.child_agent_id,
                "capabilities": list(grant.capabilities),
                "compartment": grant.compartment,
                "expires_at": grant.expires_at,
                "depth": grant.depth,
                "correlation_id": _corr(request),
                "ts": time.time(),
            }
        )
    except Exception:  # noqa: BLE001 — no seal, no grant (fail-closed).
        return JSONResponse(status_code=503, content={"error": "audit unavailable"})
    await _components.delegation.persist(grant)
    return JSONResponse(
        status_code=201,
        content={
            "delegation_id": grant.delegation_id,
            "child_session_id": grant.child_session_id,
            "expires_at": grant.expires_at,
            "depth": grant.depth,
        },
    )


@app.post("/v1/delegate/revoke")
async def delegate_revoke(body: _DelegateRevokeRequest, request: Request) -> Response:
    """
    A parent session revokes one of its own DESCENDANTS — routine dispatcher
    cleanup, not an admin event, which is why no capability is required. The
    caller must actually be an ancestor of the target session; anything else
    (including a target that does not exist) is an opaque deny, so this surface
    is not an existence oracle. Cascades: every grant whose chain passes through
    the revoked session dies on its next liveness probe.
    """
    if not _components.settings.delegation_enabled:
        return JSONResponse(status_code=404, content={"error": "not found"})
    identity = await _delegation_caller(request)
    if identity.session_id is None:
        raise MCPIPDenied(_corr(request))
    grants = await _components.delegation.list_grants(identity.tenant_id)
    is_descendant = any(
        g.child_session_id == body.session_id and identity.session_id in g.ancestors
        for g in grants
    )
    if not is_descendant:
        raise MCPIPDenied(_corr(request))
    try:
        await _components.worm.emit(
            {
                "decision": "admin_action",
                "admin_action": "delegation_revoked",
                "tenant_id": identity.tenant_id,
                "agent_id": identity.agent_id,
                "session_id": identity.session_id,
                "revoked_session_id": body.session_id,
                "correlation_id": _corr(request),
                "ts": time.time(),
            }
        )
    except Exception:  # noqa: BLE001 — no seal, no revocation record; still revoke.
        pass
    await _components.delegation.revoke_session(
        tenant_id=identity.tenant_id, session_id=body.session_id
    )
    return JSONResponse(status_code=200, content={"revoked": body.session_id})


@app.get("/v1/admin/delegations")
async def admin_list_delegations(request: Request) -> Response:
    """Every LIVE grant for the admin's tenant (CAP_DIRECTORY_ADMIN; 404 when the
    deployment has delegation disabled). Read-only; feeds the console lineage tree."""
    if not _components.settings.delegation_enabled:
        return JSONResponse(status_code=404, content={"error": "not found"})
    identity = await _require_directory_admin(request)
    grants = await _components.delegation.list_grants(identity.tenant_id)
    return JSONResponse(
        status_code=200,
        content={
            "delegations": [
                {
                    "delegation_id": g.delegation_id,
                    "parent_session_id": g.parent_session_id,
                    "child_session_id": g.child_session_id,
                    "child_agent_id": g.child_agent_id,
                    "capabilities": list(g.capabilities),
                    "compartment": g.compartment,
                    "expires_at": g.expires_at,
                    "depth": g.depth,
                }
                for g in grants
            ]
        },
    )


@app.post("/v1/admin/delegations/revoke")
async def admin_revoke_delegation(
    body: _DelegateRevokeRequest, request: Request
) -> Response:
    """Admin kill-switch for a session subtree (CAP_DIRECTORY_ADMIN) — same
    cascade as the parent-side revoke, without the ancestry requirement."""
    if not _components.settings.delegation_enabled:
        return JSONResponse(status_code=404, content={"error": "not found"})
    identity = await _require_directory_admin(request)
    try:
        await _components.worm.emit(
            {
                "decision": "admin_action",
                "admin_action": "delegation_revoked",
                "tenant_id": identity.tenant_id,
                "agent_id": identity.agent_id,
                "session_id": identity.session_id,
                "revoked_session_id": body.session_id,
                "correlation_id": _corr(request),
                "ts": time.time(),
            }
        )
    except Exception:  # noqa: BLE001 — best-effort record; the block still lands.
        pass
    await _components.delegation.revoke_session(
        tenant_id=identity.tenant_id, session_id=body.session_id
    )
    return JSONResponse(status_code=200, content={"revoked": body.session_id})


@app.get("/v1/whoami")
async def whoami(request: Request) -> Response:
    """
    Echo the VERIFIED identity of the presented JWT — tenant, agent, role,
    compartment, and the effective capability UUIDs — so an operator can confirm
    what a token actually carries instead of discovering it via opaque denies.

    Reflects ONLY the caller's own verified token (no cross-identity lookup, no
    targets/aliases/reasons) — so it leaks nothing the caller does not already hold.
    Requires a valid JWT; any auth failure is the same opaque ``MCPIPDenied`` as
    every other choke point. Not gated to sandbox — a production operator confirming
    their own token is legitimate.
    """
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        identity = _components.auth.verify_identity(token)
    except Exception:  # noqa: BLE001 — any JWT failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        identity = await _apply_delegation(identity)
    except _DelegationDenied:
        # A delegated token with no live backing grant is denied EVERYWHERE, not
        # only on /v1/authorize — fail-closed, opaque like any deny.
        raise MCPIPDenied(_corr(request)) from None
    return JSONResponse(
        status_code=200,
        content={
            "tenant_id": identity.tenant_id,
            "agent_id": identity.agent_id,
            "role": identity.role,
            "compartment": identity.compartment,
            "capabilities": list(identity.capabilities),
            "session_id": identity.session_id,
            "sender_constrained": identity.cnf_jkt is not None,
        },
    )


@app.get("/v1/catalog")
async def catalog(request: Request) -> Response:
    """
    List the skills the JWT-identified caller may SEE — metadata only, never targets.

    Separation of teams between MCPs and AI: an agent cannot enumerate another team's
    classified MCP. Any auth failure is an opaque ``MCPIPDenied``.
    """
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        identity = _components.auth.verify_identity(token)
    except Exception:  # noqa: BLE001 — any JWT failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        identity = await _apply_delegation(identity)
    except _DelegationDenied:
        # A delegated token with no live backing grant is denied EVERYWHERE, not
        # only on /v1/authorize — fail-closed, opaque like any deny.
        raise MCPIPDenied(_corr(request)) from None

    visible = await _components.obf.list_visible(
        _components.registry, identity, _components.grants
    )
    items = [
        CatalogItem(
            alias=e.alias,
            risk_tier=e.risk_tier,
            transport_class=e.transport,
            classification=e.classification.value,
            compartment=e.compartment,
            # Advisory display metadata, derived from already-projected risk data.
            # The service label is deliberately NOT projected here (operator-only).
            access=effective_access(e),
        ).model_dump()
        for e in visible
    ]
    return JSONResponse(status_code=200, content={"catalog": items})


# Repo root — the signed release manifest ships alongside the source it describes.
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_signed_release() -> dict[str, Optional[object]]:
    """
    Best-effort read of the signed release manifest shipped on this host.

    Returns ``{"version", "signing_key_id", "verified"}`` where ``verified`` is
    ``True``/``False`` when the release-root PUBLIC key is configured and the
    embedded Ed25519 signature was checked, or ``None`` when no key is configured
    (the provenance is *stated*, not *proven*). All-``None`` when no manifest is
    present. Fail-soft: never raises — a missing/broken manifest degrades the
    version surface, it does not take the process down.
    """
    result: dict[str, Optional[object]] = {
        "version": None,
        "signing_key_id": None,
        "verified": None,
    }
    try:
        document = json.loads((_REPO_ROOT / "release" / "manifest.json").read_bytes())
    except (OSError, ValueError):
        return result
    if not isinstance(document, dict):
        return result
    version = document.get("version")
    key_id = document.get("signing_key_id")
    result["version"] = version if isinstance(version, str) else None
    result["signing_key_id"] = key_id if isinstance(key_id, str) else None

    pubkey_path = _components.settings.integrity_public_key_path
    if pubkey_path is not None:
        try:
            verify_ed25519_signature(document, Path(pubkey_path).read_bytes())
            result["verified"] = True
        except Exception:  # noqa: BLE001 — any failure => unverified, fail-soft.
            result["verified"] = False
    return result


def _read_update_feed() -> Optional[str]:
    """
    Read the OPTIONAL signed update feed and return the newest APPROVED version.

    The feed (``MCPIP_UPDATE_MANIFEST_PATH``) is a ``latest.json`` the operator's
    change-control pipeline drops in — there is NO network call. The advertised
    version is returned ONLY when the release-root PUBLIC key is configured AND the
    file's Ed25519 signature verifies; an unverifiable update claim is ignored
    (fail-closed — a forged "upgrade now" must never surface). Returns ``None`` when
    the feed is unconfigured, unreadable, unverifiable, or malformed. Never raises.
    """
    feed_path = _components.settings.update_manifest_path
    pubkey_path = _components.settings.integrity_public_key_path
    if feed_path is None or pubkey_path is None:
        return None
    try:
        document = json.loads(Path(feed_path).read_bytes())
        if not isinstance(document, dict):
            return None
        verify_ed25519_signature(document, Path(pubkey_path).read_bytes())
    except Exception:  # noqa: BLE001 — unreadable/unverifiable => no update, fail-soft.
        return None
    version = document.get("version")
    return version if isinstance(version, str) else None


@app.get("/v1/version")
async def version_info(request: Request) -> Response:
    """
    Report the running release, its signed provenance, the entitlement channel, and
    — when a signed update feed is configured — whether a newer APPROVED release
    exists. NOTIFIER ONLY: the gateway never downloads or executes anything; an
    upgrade is an immutable, signed *redeploy* (``update_policy: "redeploy"``). The
    console compares this against its own build to surface console↔gateway skew.

    JWT-gated — the version/provenance surface is not for anonymous callers; any
    auth failure is an opaque ``MCPIPDenied`` like every other choke point.
    """
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        await _apply_delegation(_components.auth.verify_identity(token))
    except Exception:  # noqa: BLE001 — any JWT/delegation failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None

    running = get_version()
    feed_latest = _read_update_feed()

    latest = running
    if feed_latest is not None:
        try:
            if is_newer(feed_latest, running):
                latest = feed_latest
        except ValueError:
            pass  # malformed feed version => ignore, fail-soft.

    try:
        update_available = is_newer(latest, running)
    except ValueError:
        update_available = False

    channel = (
        _components.license.tier if _components.license is not None else "sandbox"
    )

    return JSONResponse(
        status_code=200,
        content={
            "running": running,
            "latest": latest,
            "update_available": update_available,
            "channel": channel,
            "update_policy": "redeploy",
            "release": _read_signed_release(),
            # BEHAVIOR-NEUTRAL region tag (MCPIP_REGION) — an observability label for
            # console/SDK display and log correlation ONLY (None when unset). It is
            # NEVER consulted for routing, authorization, key derivation, or storage;
            # region pinning is an edge concern (see docs/operate/OPERATIONS.md).
            "region": _components.settings.region,
        },
    )


@app.get("/v1/license")
async def license_info(request: Request) -> Response:
    """
    Reflect the boot-verified entitlement document for OPERATOR VISIBILITY.

    This read-only view mirrors ``Components.license``; it is NEVER consulted by the
    authorization pipeline (licensing gates process boot, never per-request
    decisions). JWT-gated; any auth failure is an opaque deny. When the process
    booted WITHOUT a license (sandbox), returns ``{"licensed": false}`` and no
    entitlement fields — nothing to disclose.
    """
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        await _apply_delegation(_components.auth.verify_identity(token))
    except Exception:  # noqa: BLE001 — any JWT/delegation failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None

    lic = _components.license
    if lic is None:
        return JSONResponse(status_code=200, content={"licensed": False})
    content: dict[str, Any] = {
        "licensed": True,
        "license_id": lic.license_id,
        "customer": lic.customer,
        "tier": lic.tier,
        "issued_at": lic.issued_at.isoformat(),
        "expires_at": lic.expires_at.isoformat(),
        "entitlements": sorted(lic.entitlements),
    }
    # Additive, honest provenance — surfaced ONLY when the optional off-hot-path refresh is
    # configured, so the licensed view is byte-identical to today when refresh is off. Never
    # fabricated: ``source`` is "refresh" once a strictly-newer license was actually swapped
    # in, else "boot"; ``refreshed_at`` is None until a real swap has occurred.
    refresher = _components.license_refresher
    if refresher is not None:
        content["source"] = "refresh" if refresher.last_refreshed_at else "boot"
        content["refreshed_at"] = refresher.last_refreshed_at
    return JSONResponse(status_code=200, content=content)


# ---------------------------------------------------------------------------
# Directory administration — the operator principal kill-switch. JWT + the
# CAP_DIRECTORY_ADMIN capability, opaque deny, WORM-logged. DENY-only: these
# endpoints block/unblock a principal's requests; they NEVER mint identity.
# ---------------------------------------------------------------------------

# Bound on an operator-supplied agent_id path/segment — mirrors the grant
# mandate's grantee bound so a revocation target can't smuggle an oversized value.
_MAX_AGENT_ID_LEN = 256


class _RevokeBody(BaseModel):
    """Optional operator-supplied justification for a principal revocation."""

    model_config = ConfigDict(extra="forbid")

    reason: Optional[str] = None


class _DelegationDenied(Exception):
    """Internal: a delegated token has no live backing grant. The detail is a
    WORM-safe cause string; it NEVER crosses the agent wire."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


async def _apply_delegation(identity: Identity) -> Identity:
    """
    Narrow a delegated identity to the INTERSECTION of its JWT claims and its live
    grant — or refuse (docs/SESSION_DELEGATION_DESIGN.md §3).

    A token WITHOUT a ``delegation_id`` claim passes through untouched: the
    un-delegated path is byte-for-byte legacy. A token WITH the claim is narrowed
    or denied — never silently passed through un-narrowed, including when the
    deployment has delegation disabled, because ignoring the claim would grant
    MORE than the token was minted for. Grant liveness + the revocation cascade
    are key-presence reads, O(depth ≤ 4), fail-closed on transport (LockError
    propagates to the caller's funnel exactly like the revocation gate).
    """
    if identity.delegation_id is None:
        return identity
    if not _components.settings.delegation_enabled:
        raise _DelegationDenied("delegation disabled on this deployment")
    grant = await _components.delegation.fetch(
        identity.tenant_id, identity.delegation_id
    )
    if grant is None:
        raise _DelegationDenied("no live grant backs the delegation_id claim")
    # Strong binding: the grant names ONE child session and agent. A delegation id
    # replayed inside any other token denies — a grant is not a bearer widget.
    if identity.session_id is None or identity.session_id != grant.child_session_id:
        raise _DelegationDenied("session binding does not match the grant")
    if identity.agent_id != grant.child_agent_id:
        raise _DelegationDenied("agent binding does not match the grant")
    if grant.expires_at <= int(time.time()):
        raise _DelegationDenied("grant expired")
    if await _components.delegation.is_chain_revoked(identity.tenant_id, grant):
        raise _DelegationDenied("a session in the delegation chain is revoked")
    # PRINCIPAL kill-switch CASCADE: a revoked or quarantined ANCESTOR agent must
    # sever every delegated descendant, or a compromised admin escapes containment
    # via a pre-positioned escape token (a child minted BEFORE the revocation, on a
    # fresh agent_id, holding delegated authority). The child's OWN agent is checked
    # by the standard revocation/quarantine gates; this extends that up the chain.
    # Fail-closed: a store error raises LockError → opaque deny, like every gate.
    for anc_agent in grant.ancestor_agents:
        if await _components.revocation.is_revoked(identity.tenant_id, anc_agent):
            raise _DelegationDenied("an ancestor principal is revoked")
        if await _components.quarantine.is_quarantined(identity.tenant_id, anc_agent):
            raise _DelegationDenied("an ancestor principal is quarantined")
    effective = tuple(sorted(set(identity.capabilities) & set(grant.capabilities)))
    # Effective compartment: NEVER wider than the child's OWN verified JWT claim.
    # Delegation NARROWS an IdP-issued identity — it can subtract compartment
    # access, never add it. A grant conveys compartment X only when BOTH the grant
    # AND the child's JWT already carry X; any disagreement (grant None, JWT None,
    # or two different compartments) collapses to None — no compartmented access.
    if grant.compartment is not None and grant.compartment == identity.compartment:
        eff_compartment = grant.compartment
    else:
        eff_compartment = None
    return identity.model_copy(
        update={"capabilities": effective, "compartment": eff_compartment}
    )


async def _require_directory_admin(request: Request) -> Identity:
    """
    Verify the JWT, require the ``CAP_DIRECTORY_ADMIN`` capability, AND enforce the
    principal kill-switches (revocation + canary quarantine) — else opaque deny. The
    capability is matched in constant time (timing-uniform, like every other capability
    gate). Returns the verified admin ``Identity``.

    The kill-switch enforcement here is load-bearing: without it a revoked/quarantined
    admin token still passed CAP_DIRECTORY_ADMIN and could reactivate itself or keep
    mutating the control plane (vault, cloud bindings, other principals), defeating the
    very control whose purpose is to contain a compromised principal *before* the IdP
    rotates its token. Both reads are fail-closed (a Redis error raises ``LockError`` →
    opaque deny), exactly like the hot-path gates in ``_run_authorize_pipeline``.
    """
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        identity = _components.auth.verify_identity(token)
    except Exception:  # noqa: BLE001 — any JWT failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        identity = await _apply_delegation(identity)
    except _DelegationDenied:
        # A delegated token with no live backing grant is denied EVERYWHERE, not
        # only on /v1/authorize — fail-closed, opaque like any deny.
        raise MCPIPDenied(_corr(request)) from None
    if not any(
        constant_time_equals(c, CAP_DIRECTORY_ADMIN) for c in identity.capabilities
    ):
        raise MCPIPDenied(_corr(request))
    # Kill-switches: a revoked or quarantined principal is denied the admin surface too,
    # not just the /v1/authorize hot path. Fail-closed on a store error.
    try:
        revoked = await _components.revocation.is_revoked(identity.tenant_id, identity.agent_id)
        quarantined = await _components.quarantine.is_quarantined(identity.tenant_id, identity.agent_id)
    except Exception:  # noqa: BLE001 — a store failure denies (fail-closed).
        raise MCPIPDenied(_corr(request)) from None
    if revoked or quarantined:
        raise MCPIPDenied(_corr(request))
    return identity


def _valid_agent_id(agent_id: str) -> bool:
    """A revocation target must be a non-empty, bounded, single-line id."""
    return bool(agent_id) and len(agent_id) <= _MAX_AGENT_ID_LEN and "\n" not in agent_id


# A correlation id is a bounded, single-line, URL-safe segment (the minted ids are uuid4
# hex). Validating the SHAPE before touching Redis keeps a malformed/oversized/newline/
# glob/path-traversal segment from widening the ``mcpip:forensic:{tenant}:{corr}`` key or
# scanning another namespace, and guarantees the endpoint stays opaque (no 5xx) on junk.
_MAX_CORRELATION_ID_LEN = 128
_CORRELATION_ID_ALPHABET = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


def _valid_correlation_id(correlation_id: str) -> bool:
    """True iff ``correlation_id`` is a non-empty, bounded, URL-safe single-segment id."""
    return (
        bool(correlation_id)
        and len(correlation_id) <= _MAX_CORRELATION_ID_LEN
        and all(ch in _CORRELATION_ID_ALPHABET for ch in correlation_id)
    )


async def _require_forensic_read(request: Request) -> Identity:
    """
    Verify the JWT, require the ``CAP_FORENSIC_READ`` capability, AND enforce the
    principal kill-switches (revocation + canary quarantine) — else opaque deny. Mirrors
    ``_require_directory_admin`` but gates on the DISTINCT forensic-read capability:
    holding ``CAP_DIRECTORY_ADMIN`` (or any other capability, or the ``role`` claim) does
    NOT confer raw-payload read. The capability is matched constant-time (timing-uniform).
    Both kill-switch reads fail closed (a Redis error → opaque deny). Returns the verified
    investigator ``Identity`` (tenant-scoped: it only ever reads its own tenant's rows).
    """
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        identity = _components.auth.verify_identity(token)
    except Exception:  # noqa: BLE001 — any JWT failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        identity = await _apply_delegation(identity)
    except _DelegationDenied:
        # A delegated token with no live backing grant is denied EVERYWHERE, not
        # only on /v1/authorize — fail-closed, opaque like any deny.
        raise MCPIPDenied(_corr(request)) from None
    if not any(
        constant_time_equals(c, CAP_FORENSIC_READ) for c in identity.capabilities
    ):
        # A token WITHOUT the forensic capability (e.g. a directory-admin-only or agent
        # token) probing the retrieval route — the closed-enum ``read_denied`` signal.
        FORENSIC.labels("read_denied").inc()
        raise MCPIPDenied(_corr(request))
    try:
        revoked = await _components.revocation.is_revoked(identity.tenant_id, identity.agent_id)
        quarantined = await _components.quarantine.is_quarantined(identity.tenant_id, identity.agent_id)
    except Exception:  # noqa: BLE001 — a store failure denies (fail-closed).
        raise MCPIPDenied(_corr(request)) from None
    if revoked or quarantined:
        FORENSIC.labels("read_denied").inc()
        raise MCPIPDenied(_corr(request))
    return identity


async def _enforce_kill_switches(request: Request, identity: Identity) -> None:
    """Deny (opaque, fail-closed) if the principal is revoked OR canary-quarantined.

    The shared kill-switch enforcement both community-extension gate helpers use: a
    principal an operator has frozen can neither SUBMIT nor APPROVE an extension, exactly
    as it is denied the /v1/authorize hot path and the other admin surfaces. Both reads
    fail closed (a Redis error → opaque deny).
    """
    try:
        revoked = await _components.revocation.is_revoked(identity.tenant_id, identity.agent_id)
        quarantined = await _components.quarantine.is_quarantined(
            identity.tenant_id, identity.agent_id
        )
    except Exception:  # noqa: BLE001 — a store failure denies (fail-closed).
        raise MCPIPDenied(_corr(request)) from None
    if revoked or quarantined:
        raise MCPIPDenied(_corr(request))


async def _require_authenticated(request: Request) -> Identity:
    """
    Verify the JWT and enforce the principal kill-switches ONLY — no capability required.

    The Contributor gate for ``POST /v1/extensions/submit``: submitting a community-skill
    manifest for review is open to ANY live authenticated principal (that is the point —
    turn users into the feature factory), but a REVOKED or QUARANTINED principal still
    cannot submit (the kill-switches fail closed). Authorization to APPROVE is a separate,
    distinct capability (``_require_catalog_reviewer``) — separation of duties. Returns the
    verified, tenant-scoped ``Identity`` (the tenant comes only from the JWT).
    """
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        identity = _components.auth.verify_identity(token)
    except Exception:  # noqa: BLE001 — any JWT failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        identity = await _apply_delegation(identity)
    except _DelegationDenied:
        # A delegated token with no live backing grant is denied EVERYWHERE, not
        # only on /v1/authorize — fail-closed, opaque like any deny.
        raise MCPIPDenied(_corr(request)) from None
    await _enforce_kill_switches(request, identity)
    return identity


async def _require_catalog_reviewer(request: Request) -> Identity:
    """
    Verify the JWT, require ``CAP_CATALOG_REVIEWER``, AND enforce the principal
    kill-switches (revocation + quarantine) — else opaque deny. Mirrors
    ``_require_directory_admin``/``_require_forensic_read`` but gates on the DISTINCT
    community-review capability: holding ``CAP_DIRECTORY_ADMIN`` or ``CAP_FORENSIC_READ``
    (or any other capability, or the ``role`` claim) does NOT confer the authority to
    approve a community extension. The capability is matched constant-time (timing-uniform)
    and both kill-switch reads fail closed. Returns the verified, tenant-scoped reviewer
    ``Identity`` — its pending/approved reads and the register apply all target its OWN
    tenant only, so a cross-tenant approve is structurally impossible.
    """
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        identity = _components.auth.verify_identity(token)
    except Exception:  # noqa: BLE001 — any JWT failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        identity = await _apply_delegation(identity)
    except _DelegationDenied:
        # A delegated token with no live backing grant is denied EVERYWHERE, not
        # only on /v1/authorize — fail-closed, opaque like any deny.
        raise MCPIPDenied(_corr(request)) from None
    if not any(
        constant_time_equals(c, CAP_CATALOG_REVIEWER) for c in identity.capabilities
    ):
        raise MCPIPDenied(_corr(request))
    await _enforce_kill_switches(request, identity)
    return identity


@app.get("/v1/admin/forensic/{correlation_id}")
async def forensic_read(correlation_id: str, request: Request) -> Response:
    """
    Retrieve the reconstructed, REDACTED query an agent sent for ``correlation_id`` — the
    SOLE forensic retrieval route, and an ADMIN/investigator surface ONLY. Gated by
    ``_require_forensic_read`` (CAP_FORENSIC_READ, fail-closed, kill-switch-enforced).

    Deny-by-default:
      * feature off (``_components.forensic is None``) → opaque 404;
      * malformed/oversized correlation id → opaque 404 (validated before Redis);
      * unknown/expired id, or one owned by ANOTHER tenant → indistinguishable 404 (the
        key namespace + AAD both bind the caller's tenant, so cross-tenant is a miss).

    Audit-before-disclosure: every access emits a WORM ``admin_action='forensic_read'``
    (who read whose payload, and whether it was found) BEFORE the payload is returned. The
    reconstructed payload is NOT re-embedded in that WORM record — it already lives in the
    encrypted store, and re-embedding would duplicate the query/topology into the chain.
    """
    identity = await _require_forensic_read(request)
    if _components.forensic is None or not _valid_correlation_id(correlation_id):
        FORENSIC.labels("read_miss").inc()
        return JSONResponse(status_code=404, content={"error": "not found"})

    # Tenant-scoped read: the caller only ever sees its OWN tenant's captures.
    record = await _components.forensic.retrieve(identity.tenant_id, correlation_id)
    found = record is not None

    # Emit the read to WORM BEFORE disclosing anything (an investigator read is itself an
    # audited event). The payload is NOT copied into this record.
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "forensic_read",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "subject_correlation_id": correlation_id,
            "found": found,
            "correlation_id": _corr(request),
            "ts": time.time(),
        }
    )

    if not found:
        FORENSIC.labels("read_miss").inc()
        return JSONResponse(status_code=404, content={"error": "not found"})
    assert record is not None
    FORENSIC.labels("read_hit").inc()
    return JSONResponse(
        status_code=200, content={"found": True, "forensic": record.public_view()}
    )


@app.post("/v1/admin/principals/{agent_id}/revoke")
async def revoke_principal(agent_id: str, request: Request, body: _RevokeBody) -> Response:
    """
    Revoke a principal in the ADMIN's OWN tenant — a persistent kill-switch. Every
    subsequent request from ``(tenant, agent_id)`` is denied ``PRINCIPAL_REVOKED``
    until an admin reactivates it. WORM-logged (actor, subject, reason). Requires
    ``CAP_DIRECTORY_ADMIN``; any failure is an opaque ``MCPIPDenied``.

    IdP sovereignty: this DENIES a principal's requests; it never mints, edits, or
    re-signs a credential. The IdP remains the sole source of identity.
    """
    identity = await _require_directory_admin(request)
    if not _valid_agent_id(agent_id):
        raise MCPIPDenied(_corr(request))
    corr = _corr(request)
    # WORM-log the admin action BEFORE returning (an IAM control must be audited).
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "principal_revoke",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "subject_agent_id": agent_id,
            "reason": body.reason,
            "correlation_id": corr,
        }
    )
    await _components.revocation.revoke(
        tenant_id=identity.tenant_id,
        agent_id=agent_id,
        issued_by=identity.agent_id,
        correlation_id=corr,
        reason=body.reason,
    )
    return JSONResponse(status_code=200, content={"revoked": agent_id})


@app.post("/v1/admin/principals/{agent_id}/reactivate")
async def reactivate_principal(agent_id: str, request: Request) -> Response:
    """
    Lift a principal revocation in the admin's own tenant. WORM-logged. Requires
    ``CAP_DIRECTORY_ADMIN``; any failure is an opaque ``MCPIPDenied``. ``removed``
    reports whether a revocation was actually in force.
    """
    identity = await _require_directory_admin(request)
    if not _valid_agent_id(agent_id):
        raise MCPIPDenied(_corr(request))
    corr = _corr(request)
    removed = await _components.revocation.reactivate(
        tenant_id=identity.tenant_id, agent_id=agent_id
    )
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "principal_reactivate",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "subject_agent_id": agent_id,
            "removed": removed,
            "correlation_id": corr,
        }
    )
    return JSONResponse(status_code=200, content={"reactivated": agent_id, "removed": removed})


@app.get("/v1/admin/principals/revoked")
async def list_revoked_principals(request: Request) -> Response:
    """
    List the agent_ids currently revoked in the admin's own tenant. Requires
    ``CAP_DIRECTORY_ADMIN``; any failure is an opaque ``MCPIPDenied``. Read-only.
    """
    identity = await _require_directory_admin(request)
    revoked = await _components.revocation.list_revoked(identity.tenant_id)
    return JSONResponse(status_code=200, content={"revoked": sorted(revoked)})


# ---------------------------------------------------------------------------
# Operator directory persistence — the org chart + RBAC the console edits. Same
# CAP_DIRECTORY_ADMIN gate, opaque deny, WORM-logged, tenant-scoped. This is
# NON-AUTHORITATIVE metadata: the authorization pipeline never consults it and it
# never mints identity (IdP sovereignty stands).
# ---------------------------------------------------------------------------


@app.get("/v1/directory")
async def get_directory(request: Request) -> Response:
    """
    Return the persisted operator directory document for the admin's own tenant,
    or ``{"document": null}`` when nothing has been saved yet. Requires
    ``CAP_DIRECTORY_ADMIN``; any failure is an opaque ``MCPIPDenied``.
    """
    identity = await _require_directory_admin(request)
    document = await _components.directory.get(identity.tenant_id)
    return JSONResponse(status_code=200, content={"document": document})


@app.put("/v1/directory")
async def put_directory(request: Request) -> Response:
    """
    Persist the operator directory document for the admin's own tenant. The body is
    validated (schema ``mcpip-directory/1``, bounded size, ``org_units`` list) and
    stored as-is — it is operator metadata the gateway never interprets for
    authorization. WORM-logged. Requires ``CAP_DIRECTORY_ADMIN``; any auth/validation
    failure is an opaque ``MCPIPDenied``.
    """
    identity = await _require_directory_admin(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 — malformed JSON is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        document = _components.directory.validate(body)
    except DirectoryDocumentError:
        # A malformed/oversized document is rejected with the same opacity as any
        # other deny — the concrete cause is not disclosed to the caller.
        raise MCPIPDenied(_corr(request)) from None

    corr = _corr(request)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "directory_put",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "org_unit_count": len(document.get("org_units", [])),
            "correlation_id": corr,
        }
    )
    await _components.directory.put(identity.tenant_id, document)
    return JSONResponse(status_code=200, content={"ok": True})


# ---------------------------------------------------------------------------
# Deny-only policy overlay — an admin reads/writes the per-tenant velocity/amount
# policy document. CAP_DIRECTORY_ADMIN-gated, opaque deny, WORM-logged (emit-before-
# mutate), tenant-scoped. The stored document only ever holds velocity/amount rules —
# NEVER an alias→target mapping or identity — so it can never repoint a skill or mint
# a principal. No document → the engine imposes no limits (honest opt-in absent state).
# ---------------------------------------------------------------------------


@app.get("/v1/admin/policy")
async def get_policy(request: Request) -> Response:
    """
    Return the persisted deny-only policy document for the admin's own tenant, or an
    honest empty ``{"schema": "mcpip-policy/1", "rules": []}`` when nothing is stored.
    Requires ``CAP_DIRECTORY_ADMIN``; any failure is an opaque ``MCPIPDenied``.
    """
    identity = await _require_directory_admin(request)
    document = await _components.policy_docs.get(identity.tenant_id)
    if document is None:
        document = {"schema": POLICY_SCHEMA, "rules": []}
    return JSONResponse(status_code=200, content={"policy": document})


@app.put("/v1/admin/policy")
async def put_policy(request: Request) -> Response:
    """
    Persist the deny-only policy document for the admin's own tenant. The body is
    strict-validated (schema ``mcpip-policy/1``, ``<= MAX_POLICY_RULES`` well-formed
    velocity/amount rules, ``<= MAX_POLICY_DOC_BYTES``) and stored canonically. WORM-
    logged emit-before-mutate. Requires ``CAP_DIRECTORY_ADMIN``; any auth/validation
    failure is an opaque ``MCPIPDenied`` (a malformed doc never leaks its cause). The
    document carries ONLY velocity/amount rules — never alias→target or identity.
    """
    identity = await _require_directory_admin(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 — malformed JSON is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        document = _components.policy_docs.validate(body)
    except PolicyDocumentError:
        # A malformed/oversized document is rejected with the same opacity as any other
        # deny — the concrete cause is not disclosed to the caller.
        raise MCPIPDenied(_corr(request)) from None

    corr = _corr(request)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "policy_put",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "rule_count": len(document.get("rules", [])),
            "correlation_id": corr,
        }
    )
    await _components.policy_docs.put(identity.tenant_id, document)
    return JSONResponse(status_code=200, content={"ok": True})


@app.post("/v1/admin/policy/delete")
async def delete_policy(request: Request) -> Response:
    """
    Delete the admin's own tenant's policy document (back to the honest no-limits
    state). WORM-logged emit-before-mutate. Requires ``CAP_DIRECTORY_ADMIN``; any
    failure is an opaque ``MCPIPDenied``.
    """
    identity = await _require_directory_admin(request)
    corr = _corr(request)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "policy_delete",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "correlation_id": corr,
        }
    )
    await _components.policy_docs.delete(identity.tenant_id)
    return JSONResponse(status_code=200, content={"ok": True})


# ---------------------------------------------------------------------------
# Skill kill-switch — an admin can disable/enable an alias for its tenant. Same
# CAP_DIRECTORY_ADMIN gate, opaque deny, WORM-logged, tenant-scoped. DENY-only:
# it never edits the alias→target mapping (the obfuscation layer is immutable).
# ---------------------------------------------------------------------------


@app.get("/v1/admin/skills/disabled")
async def list_disabled_skills(request: Request) -> Response:
    """List the alias names currently disabled in the admin's own tenant. Read-only."""
    identity = await _require_directory_admin(request)
    disabled = await _components.skill_gate.list_disabled(identity.tenant_id)
    return JSONResponse(status_code=200, content={"disabled": disabled})


@app.get("/v1/admin/decisions/recent")
async def list_recent_decisions(request: Request) -> Response:
    """
    Operator-visibility feed of the most recent AUTHORIZE decisions in the admin's OWN
    tenant — the live decision stream the console renders, so REAL agent traffic (e.g. a
    Claude MCP client) shows up in the WORM ledger / Command Center as it happens.

    ``CAP_DIRECTORY_ADMIN``-gated, tenant-scoped, read-only, and a strict WHITELIST
    projection (alias, decision, deny_reason, transport CLASS, risk/classification,
    correlation id, worm seq, timestamp) — the real target and payload never appear, so
    the agent-facing opacity boundary is untouched (this is an OPERATOR read of WORM data
    operators already own). It is a bounded RECENT tail for live display, NOT the
    authoritative audit record — that remains the signed epoch chain (``/v1/audit/verify``
    / ``mcpip export-audit``). Any failure is an opaque ``MCPIPDenied``.
    """
    identity = await _require_directory_admin(request)
    try:
        limit = int(request.query_params.get("limit", "50"))
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(limit, 200))
    decisions = await _components.worm.recent_decisions(identity.tenant_id, limit)
    return JSONResponse(status_code=200, content={"decisions": decisions})


# Filterable facets for the decision-history query — the subset of the operator whitelist
# projection that makes sense as a filter (all topology-free/secret-free). Kept here (not in
# the WORM layer) because it is an HTTP-surface contract; the WORM layer independently
# rejects any field outside its own _DECISION_SAFE_KEYS, so this can only ever narrow.
_DECISION_FILTER_FIELDS: Final[tuple[str, ...]] = (
    "decision",
    "deny_reason",
    "alias",
    "transport",
    "risk_tier",
    "classification",
    "agent_id",
    "source_format",
    "correlation_id",
    "transaction_ref",
    "session_id",
    "delegation_id",
)
_STREAM_ID_RE: Final = re.compile(r"^\d+-\d+$")


@app.get("/v1/admin/decisions")
async def query_decisions(request: Request) -> Response:
    """
    Operator decision-HISTORY: the date-ranged, multi-filtered, cursor-paged view over the
    admin's OWN tenant — the "activity at scale" surface (not just the recent tail). Same
    ``CAP_DIRECTORY_ADMIN`` gate, tenant-scoped, read-only, and the IDENTICAL strict
    WHITELIST projection ``/recent`` serves (``recent_decisions`` and ``query_decisions``
    share ``_project_decision_row``), so nothing new is exposed — the real target, payload,
    and secrets never appear; the agent-facing opacity boundary is untouched. It is a bounded
    scan over the durable event buffer, NOT the authoritative record (that stays the signed
    epoch chain — ``/v1/audit/verify`` / ``mcpip export-audit``).

    Query params (all optional): ``from_ms``/``to_ms`` (inclusive epoch-millisecond window),
    ``cursor`` (opaque resume token = the prior page's ``next_cursor``; overrides ``to_ms``),
    ``limit`` (rows per page, clamped to ``MAX_DECISIONS_PAGE``), and any of the twelve
    whitelist facets in ``_DECISION_FILTER_FIELDS`` as comma-separated value lists (OR within
    a facet, AND across facets). Malformed bounds / cursor are ignored (fail toward a wider,
    never a wrong, window; a bad cursor never reaches Redis). Returns
    ``{decisions, next_cursor, scanned, exhausted}``. Any auth failure is an opaque
    ``MCPIPDenied``.

    An unrecognised query parameter is IGNORED here, which is correct for a server —
    echoing it back would be an input oracle, and rejecting it would break forward
    compatibility. The cost lands on the client: an unknown facet means the range comes
    back UNFILTERED, not empty. That is why the SDK refuses the key before it is sent
    (``mcpip_sdk.admin.DECISION_FILTER_FIELDS``), and why the two lists are pinned to each
    other by ``tests/test_decision_filter_contract.py`` rather than kept in step by hand —
    this docstring itself had drifted two fields behind the tuple below.
    """
    identity = await _require_directory_admin(request)
    params = request.query_params

    try:
        limit = int(params.get("limit", "100"))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, MAX_DECISIONS_PAGE))

    def _bound_ms(name: str) -> Optional[int]:
        raw = params.get(name)
        if raw is None:
            return None
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        return value if value >= 0 else None

    from_ms = _bound_ms("from_ms")
    to_ms = _bound_ms("to_ms")
    start_id = str(from_ms) if from_ms is not None else "-"

    cursor = params.get("cursor")
    if cursor is not None and _STREAM_ID_RE.match(cursor):
        # Resume strictly before the prior page's last examined entry (exclusive).
        end_id = f"({cursor}"
    elif to_ms is not None:
        end_id = str(to_ms)
    else:
        end_id = "+"

    filters: dict[str, frozenset[str]] = {}
    for field in _DECISION_FILTER_FIELDS:
        raw = params.get(field)
        if raw is None:
            continue
        values = frozenset(v for v in (part.strip() for part in raw.split(",")) if v)
        if values:
            filters[field] = values

    result = await _components.worm.query_decisions(
        identity.tenant_id,
        start_id=start_id,
        end_id=end_id,
        limit=limit,
        filters=filters,
    )
    return JSONResponse(status_code=200, content=result)


# ---------------------------------------------------------------------------
# Canary-tripwire rosters — the operator's live view of the deception control.
# Same CAP_DIRECTORY_ADMIN gate, opaque deny, tenant-scoped, read-only: neither
# endpoint mutates state, and neither is reachable by a plain agent token.
# ---------------------------------------------------------------------------


@app.get("/v1/admin/quarantine")
async def list_quarantined_agents(request: Request) -> Response:
    """
    List the agents currently frozen by the canary tripwire in the admin's OWN tenant,
    each with the seconds remaining on its TTL-bounded freeze, **which alias tripped it,
    and the correlation id of the tripping request**. Requires ``CAP_DIRECTORY_ADMIN``;
    any failure is an opaque ``MCPIPDenied``. Read-only — the freeze is written only by
    the pipeline's canary gate and expiry is Redis's clock (there is no un-quarantine
    mutation; a false trip self-heals at TTL, and a deliberate persistent block is the
    SEPARATE revocation kill-switch).

    The roster used to answer ``{agent_id, ttl_seconds}`` only, while the store had been
    recording the trip details all along — so the one screen that tells an operator an
    agent is frozen could not tell them *why*, and distinguishing a credential-theft
    enumeration sweep from one mistyped alias meant leaving for the WORM log to look up a
    correlation id this response was already holding. Nothing new is disclosed: the
    caller has proven ``CAP_DIRECTORY_ADMIN``, the scan is tenant-scoped, and the same
    fields sit in the WORM record for that correlation id. The opacity boundary is the
    AGENT's wire — the tripping request and every subsequent one still receive the same
    generic deny — not the operator's console.
    """
    identity = await _require_directory_admin(request)
    roster = await _components.quarantine.list_quarantined(identity.tenant_id)
    rows = [
        {
            "agent_id": record.agent_id,
            "ttl_seconds": record.ttl_seconds,
            "tripped_alias": record.tripped_alias,
            "correlation_id": record.correlation_id,
            "quarantined_at_ns": record.quarantined_at_ns,
        }
        for record in roster
    ]
    return JSONResponse(status_code=200, content={"quarantined": rows})


def _response_status() -> dict[str, Any]:
    """
    Honest deny-response-playbook posture for ``GET /v1/admin/stats`` — never fabricated.

    ``disabled`` when the playbook is off / unbuilt; otherwise the coarse, secret-free
    ``status()`` (auto-quarantine flag, channels on/off, active triggers, cadence, and the
    in-memory ``last_action`` / ``last_result`` — ``never`` until the first response). No
    webhook url, SMTP password, tenant, agent, or target is ever exposed here (nor to a
    metric label).
    """
    playbook = _components.response_playbook
    if playbook is None:
        return {"status": "disabled", "last_action": None, "last_result": "never"}
    return playbook.status()


def _telemetry_status() -> dict[str, Any]:
    """
    Honest telemetry posture for ``GET /v1/admin/stats`` — never fabricated.

    Three states: ``air-gap`` (sandbox — the beacon is structurally disabled and no install
    identity was ever minted), ``enabled`` (the beacon is live; also surfaces the coarse
    in-memory ``last_sent`` / ``last_result`` — ``never`` until the first send), or
    ``disabled`` (opt-out / unconfigured production — the flag is off or no URL is set). NO
    install id, url, or secret is ever exposed here (nor to any metric label).
    """
    settings = _components.settings
    if settings.sandbox_mode:
        return {"status": "air-gap", "last_sent": None, "last_result": "never"}
    beacon = _components.telemetry
    if beacon is not None:
        state = beacon.status()
        return {
            "status": "enabled",
            "interval_seconds": beacon.interval_s,
            "last_sent": state["last_sent"],
            "last_result": state["last_result"],
        }
    return {"status": "disabled", "last_sent": None, "last_result": "never"}


def _forensic_status() -> dict[str, Any]:
    """
    Honest forensic-capture POSTURE for ``GET /v1/admin/stats`` — coarse, deployment-wide,
    and never a per-correlation-id oracle.

    This surfaces WHY reconstruction is (un)available, distinguishing the three real
    reasons the per-id ``GET /v1/admin/forensic/{corr}`` 404 DELIBERATELY conflates
    (feature-off / unknown / expired / cross-tenant all look identical at the per-id route,
    the exists-elsewhere-oracle invariant — that route is NOT touched). Every field is
    derived from settings + the composition-root resolution (``_components.forensic``); NO
    key, path, target, tenant, or per-id information is exposed. Four states:

      * ``enabled`` — the store was built (flag effectively on AND a key is present).
      * ``absent`` — flag on but no key (fail-closed, never plaintext).
      * ``disabled`` / ``explicit-opt-out`` — ``MCPIP_FORENSIC_CAPTURE=false``.
      * ``disabled`` / ``production-default`` — unset flag in production (fail-safe off).
    """
    settings = _components.settings
    effective_capture = (
        settings.forensic_capture
        if settings.forensic_capture is not None
        else settings.sandbox_mode
    )
    if not effective_capture:
        if settings.forensic_capture is False:
            return {
                "status": "disabled",
                "reason": "explicit-opt-out",
                "detail": (
                    "Forensic capture is disabled by configuration "
                    "(MCPIP_FORENSIC_CAPTURE=false). Reconstruction is intentionally off."
                ),
            }
        return {
            "status": "disabled",
            "reason": "production-default",
            "detail": (
                "Forensic capture is off on this gateway (production default). No captures "
                "are taken, so GET /v1/admin/forensic returns 404 for every correlation id "
                "— this is not an error. Enable with MCPIP_FORENSIC_CAPTURE=true + a 32-byte "
                "MCPIP_FORENSIC_KEY_PATH, then redeploy. Retrieval always stays "
                "CAP_FORENSIC_READ-gated and WORM-audited."
            ),
        }
    # Flag effectively ON. A built store means a real key was resolved; None means the
    # flag-on/key-off ABSENT state (production fail-closed, never a plaintext fallback).
    if _components.forensic is None:
        return {
            "status": "absent",
            "reason": "flag-on-no-key",
            "detail": (
                "MCPIP_FORENSIC_CAPTURE is on but no MCPIP_FORENSIC_KEY_PATH is configured "
                "— capture is ABSENT, fail-closed, never plaintext. Provide a 32-byte key "
                "file to activate it."
            ),
        }
    return {
        "status": "enabled",
        "detail": (
            "Forensic capture is live. The real query (alias + normalized arguments + "
            "identity context) of each authorize is encrypted at rest and readable only "
            "via CAP_FORENSIC_READ + a WORM-audited read. Secrets stay redacted."
        ),
    }


def _external_pdp_status() -> dict[str, Any]:
    """
    Honest outbound external-PDP POSTURE for ``GET /v1/admin/stats``.

    Derived from ``settings.external_pdp_enabled`` + ``settings.external_pdp_url`` (the same
    two signals ``_build_community_gate`` composes on). The URL itself is NEVER exposed —
    posture only. Three states mirror the composition-root legality:

      * ``off`` — neither set (the shipped no-op seam; hot path unchanged).
      * ``staged`` — url set but flag OFF (the legitimate staged-but-disabled state).
      * ``enforcing`` — both set (deny-only, monotonic, fail-closed consult).
    """
    settings = _components.settings
    if settings.external_pdp_enabled and settings.external_pdp_url:
        return {
            "status": "enforcing",
            "detail": (
                "External PDP consult is enforcing — every authorization additionally "
                "consults an external AuthZEN PDP as a deny-only, monotonic, fail-closed "
                "term. It can only add a deny, never grant."
            ),
        }
    if settings.external_pdp_url:
        return {
            "status": "staged",
            "detail": (
                "External PDP consult is staged but NOT enforcing — MCPIP_EXTERNAL_PDP_URL "
                "is set but MCPIP_EXTERNAL_PDP_ENABLED is off. No decision is consulted. Set "
                "the flag and redeploy to enforce."
            ),
        }
    return {
        "status": "off",
        "detail": (
            "External PDP consult is off — no outbound AuthZEN Policy Decision Point is "
            "configured. The community-gate seam is the shipped no-op; the hot path is "
            "unchanged."
        ),
    }


def _features_status() -> dict[str, Any]:
    """
    The additive ``features`` posture block on ``GET /v1/admin/stats``.

    Posture-only (status + reason + human detail) — NO install-id/url/secret/target/tenant,
    the same privacy boundary the stats surface already enforces. ``telemetry`` stays a
    top-level key (back-compat) and is the finished reference model; forensic-capture and
    external-PDP are folded in here. MRT step-up is NOT here: it is ALWAYS advertised and
    read LIVE from the unauthenticated ``initialize`` capability by the console, never a
    static posture string.
    """
    return {
        "forensic_capture": _forensic_status(),
        "external_pdp": _external_pdp_status(),
    }


def _license_status() -> dict[str, Any]:
    """
    Honest license posture for ``GET /v1/admin/stats`` — mirrors ``GET /v1/license``.

    Reads the boot-verified ``Components.license`` (the pipeline NEVER consults it). An
    unlicensed sandbox boot returns ``{"licensed": false}`` and no entitlement fields —
    never a fabricated customer/tier/date.
    """
    lic = _components.license
    if lic is None:
        return {"licensed": False}
    return {
        "licensed": True,
        "license_id": lic.license_id,
        "tier": lic.tier,
        "customer": lic.customer,
        "issued_at": lic.issued_at.isoformat(),
        "expires_at": lic.expires_at.isoformat(),
    }


@app.get("/v1/admin/stats")
async def admin_stats(request: Request) -> Response:
    """
    The LOCAL live-stats read: the operator's OWN tenant's REAL running numbers.

    This is what "see the numbers live" means CLIENT-SIDE — the same aggregate the opt-in
    beacon would report, but scoped to the caller's tenant and served locally (no beacon,
    no vendor, no network needed). ``CAP_DIRECTORY_ADMIN``-gated via
    ``_require_directory_admin`` (JWT + capability + revocation/quarantine kill-switch,
    opaque deny, tenant-scoped); any failure is an opaque ``MCPIPDenied``.

    Returns REAL counts or an HONEST empty/disabled state — never a fabricated client,
    number, license, or "connected" status:
      * ``governed_agent_identity_count`` — the caller's tenant HLL PFCOUNT (an integer
        cardinality; the agent_ids themselves are never stored or exposed);
      * ``decisions`` — the tenant's real {allow, deny, staged} totals;
      * ``license`` — the boot-verified tier/status/expiry (honest ``{"licensed": false}``
        when absent);
      * ``telemetry`` — enabled / disabled / air-gap[sandbox] + coarse last_sent/last_result;
      * ``features`` — honest opt-in/dark-feature POSTURE (forensic_capture + external_pdp):
        status + reason + a human ``detail`` explaining WHY a feature is off and how to
        enable it — coarse, deployment-wide, NO url/key/target/tenant (MRT step-up is not
        here; it is always advertised and read live from ``initialize``);
      * ``version`` — the running release.
    A fresh tenant with nothing yet flowed gets honest zeros. NO tenant/agent/alias/target
    is ever exposed — only the caller's OWN aggregate integers cross this admin boundary.
    """
    identity = await _require_directory_admin(request)
    count, decisions = await _components.telemetry_stats.read_tenant(identity.tenant_id)
    return JSONResponse(
        status_code=200,
        content={
            "version": get_version(),
            "governed_agent_identity_count": count,
            "decisions": decisions,
            "license": _license_status(),
            "telemetry": _telemetry_status(),
            "response_playbook": _response_status(),
            "features": _features_status(),
        },
    )


def _valid_relation_filter(value: str) -> bool:
    """A relation-read filter (subject/relation/object) must be a bounded, single-line id.

    Bounding the SHAPE before it reaches Redis keeps a malformed/oversized/newline value
    from bloating a ``check`` key lookup, and — with the SCAN's own ``_glob_escape`` — keeps
    a wildcard-bearing value from ever widening the tenant-scoped scan.
    """
    return bool(value) and len(value) <= _MAX_AGENT_ID_LEN and "\n" not in value


@app.get("/v1/admin/directory/relations")
async def list_directory_relations(request: Request) -> Response:
    """
    List the ReBAC relation edges projected from the admin's OWN tenant's committed grants
    — the authoritative edge source for the operator Knowledge-Graph. Requires
    ``CAP_DIRECTORY_ADMIN`` (mirrors ``GET /v1/admin/quarantine``); any failure is an
    opaque ``MCPIPDenied``. Read-only and tenant-scoped: it only ever lists the caller's
    own tenant, SCANned under the glob-escaped tenant prefix so a wildcard-bearing tenant
    id can never widen the scan.

    Each committed grant projects a ``member`` edge (subject → compartment) and a
    read-time-derived ``grantor`` edge (issuing principal → compartment). Optional
    ``?subject=`` / ``?relation=`` / ``?object=`` filters narrow the emitted edges; when a
    FULL ``(subject, relation=member, object)`` triple is supplied the response also
    carries ``allowed`` — the result of the BOUNDED transitive-closure ``check`` (hop- and
    fanout-capped, fail-closed). The check is READ/VISUALIZATION ONLY — the authorization
    pipeline NEVER consults it; the capability-UUID + grant gates remain the SOLE authority.

    This is a BEST-EFFORT PROJECTION: the gateway/Redis grant state is authoritative. A
    transport error yields an honest empty ``{"relations": []}`` (fail-soft — it backs a
    listing, never a decision). Tuples carry only operator-facing identifiers + non-secret
    grant metadata; NO target, secret, or alias→target mapping is ever exposed, and nothing
    here crosses the agent boundary.
    """
    identity = await _require_directory_admin(request)

    params = request.query_params
    subject = params.get("subject")
    relation = params.get("relation")
    object_uuid = params.get("object")
    for value in (subject, relation, object_uuid):
        if value is not None and not _valid_relation_filter(value):
            # A provided-but-malformed filter is an opaque deny (never a 5xx or a hint).
            raise MCPIPDenied(_corr(request))

    edges = await _components.relations.list_relations(
        identity.tenant_id,
        subject=subject,
        relation=relation,
        object_uuid=object_uuid,
    )
    rows = [
        {
            "object": edge.object_uuid,
            "relation": edge.relation,
            "subject": edge.subject,
            "grant_id": edge.grant_id,
            "correlation_id": edge.correlation_id,
            "issued_at_ns": edge.issued_at_ns,
        }
        for edge in _sorted_relation_edges(edges)
    ]
    content: dict[str, Any] = {"relations": rows}

    # A FULL triple exposes the bounded closure check as an authoritative-for-visualization
    # boolean. Only 'member' is traversable in v1 (grantor is a derived display edge).
    if subject is not None and relation is not None and object_uuid is not None:
        content["allowed"] = await _components.relations.check(
            tenant_id=identity.tenant_id,
            subject=subject,
            relation=relation,
            object_uuid=object_uuid,
        )
    return JSONResponse(status_code=200, content=content)


def _sorted_relation_edges(edges: list[RelationEdge]) -> list[RelationEdge]:
    """Deterministic ordering for the roster (object, then relation, then subject)."""
    return sorted(edges, key=lambda e: (e.object_uuid, e.relation, e.subject))


@app.get("/v1/admin/canaries")
async def list_canary_aliases(request: Request) -> Response:
    """
    List the canary decoy aliases seeded into the admin's OWN tenant catalog — the
    operator side of the tripwire, so the console can show which rows are bait.
    Requires ``CAP_DIRECTORY_ADMIN``; any failure is an opaque ``MCPIPDenied``.

    Boundary discipline: the ``canary`` flag itself still NEVER crosses the agent
    boundary — ``/v1/catalog`` and MCP ``tools/list`` keep hiding it. This is the ONLY
    surface that reveals it, it exposes alias metadata only (never the tripwire sink
    label or any target), and it sits behind the same admin gate as every other
    operator read.
    """
    identity = await _require_directory_admin(request)
    canaries = [
        {
            "alias": entry.alias,
            "risk_tier": entry.risk_tier.value,
            "classification": entry.classification.value,
        }
        for entry in sorted(
            _components.registry.entries_for_tenant(identity.tenant_id),
            key=lambda e: e.alias,
        )
        if entry.canary
    ]
    return JSONResponse(status_code=200, content={"canaries": canaries})


@app.get("/v1/admin/skills/registered")
async def list_registered_skills(request: Request) -> Response:
    """
    List the OPERATOR-registered (overlay) alias names for the admin's own tenant —
    the only skills that are deregisterable (config aliases are immutable). Read-only,
    ``CAP_DIRECTORY_ADMIN``-gated. Lets the console show a deregister affordance only
    on skills an operator actually added.
    """
    identity = await _require_directory_admin(request)
    overlay = await _components.catalog_overlay.list_for_tenant(identity.tenant_id)
    entries: list[dict[str, Optional[str]]] = []
    for alias, fields in sorted(overlay.items()):
        row: dict[str, Optional[str]] = {
            "alias": alias,
            "registered_at": fields.get("registered_at"),
        }
        # Permission-model display metadata (operator surface only): the human service
        # label + read/write access mode, with the risk-derived fallback for
        # unannotated rows. Advisory — never an enforcement input.
        entry = _overlay_entry(alias, fields)
        if entry is not None:
            row["service"] = display_service(entry)
            row["access"] = effective_access(entry)
        entries.append(row)
    # `registered` (names) kept for backward-compat; `entries` carries the metadata.
    return JSONResponse(
        status_code=200,
        content={"registered": sorted(overlay.keys()), "entries": entries},
    )


@app.post("/v1/admin/skills/{alias}/disable")
async def disable_skill(alias: str, request: Request) -> Response:
    """
    Disable an alias for the admin's own tenant — every invocation is then denied
    ``SKILL_DISABLED`` until re-enabled. WORM-logged. Requires ``CAP_DIRECTORY_ADMIN``;
    any failure is an opaque ``MCPIPDenied``. Never edits the alias→target mapping.
    """
    identity = await _require_directory_admin(request)
    if not _valid_agent_id(alias):
        raise MCPIPDenied(_corr(request))
    corr = _corr(request)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "skill_disable",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "alias": alias,
            "correlation_id": corr,
        }
    )
    await _components.skill_gate.disable(identity.tenant_id, alias)
    return JSONResponse(status_code=200, content={"disabled": alias})


@app.post("/v1/admin/skills/{alias}/enable")
async def enable_skill(alias: str, request: Request) -> Response:
    """
    Re-enable an alias for the admin's own tenant. WORM-logged. Requires
    ``CAP_DIRECTORY_ADMIN``; any failure is an opaque ``MCPIPDenied``.
    """
    identity = await _require_directory_admin(request)
    if not _valid_agent_id(alias):
        raise MCPIPDenied(_corr(request))
    corr = _corr(request)
    removed = await _components.skill_gate.enable(identity.tenant_id, alias)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "skill_enable",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "alias": alias,
            "removed": removed,
            "correlation_id": corr,
        }
    )
    return JSONResponse(status_code=200, content={"enabled": alias, "removed": removed})


# ---------------------------------------------------------------------------
# Operator-registered skills — add a NEW alias→target at runtime. CAP_DIRECTORY_ADMIN,
# opaque deny, WORM-logged, tenant-scoped. ADDITIVE ONLY: registration is refused if
# the alias already resolves (config OR overlay) — an operator can introduce a new
# skill but can NEVER repoint an existing one. cloud_rest transport only. Persisted
# to Redis and loaded into the in-memory registry at boot (resolve stays in-memory).
# ---------------------------------------------------------------------------

_OVERLAY_TRANSPORT = "cloud_rest"
_OVERLAY_RISK = frozenset({"auto", "pin_required"})
_OVERLAY_CLASSIFICATION = frozenset({"unclassified", "restricted"})
_MAX_TARGET_LEN = 512


def _overlay_entry(alias: str, fields: dict[str, str]) -> Optional[AliasEntry]:
    """Build an ``AliasEntry`` from stored overlay fields, or None if malformed."""
    target = fields.get("target")
    if not isinstance(target, str) or fields.get("transport") != _OVERLAY_TRANSPORT:
        return None
    # Advisory display metadata — an invalid stored value degrades to None (the
    # risk-derived fallback), never a refused row: neither field is an enforcement input.
    access = fields.get("access")
    if access not in SKILL_ACCESS_MODES:
        access = None
    service = fields.get("service")
    if not isinstance(service, str) or not service:
        service = None
    try:
        return AliasEntry(
            alias=alias,
            target=target,
            transport="cloud_rest",
            risk_tier=RiskTier(fields.get("risk_tier", "auto")),
            classification=Classification(fields.get("classification", "unclassified")),
            service=service,
            access=access,
        )
    except ValueError:
        return None


async def _hydrate_catalog_overlay() -> None:
    """Load operator-registered skills into the in-memory registry (additive only)."""
    try:
        tenants = await _components.catalog_overlay.all_tenants()
    except Exception:  # noqa: BLE001 — boot hydration is advisory, never fatal.
        return
    loaded = 0
    for tenant_id in tenants:
        entries = await _components.catalog_overlay.list_for_tenant(tenant_id)
        for alias, fields in entries.items():
            if _components.registry.has_alias(tenant_id, alias):
                continue  # never shadow config (or a duplicate).
            entry = _overlay_entry(alias, fields)
            if entry is None:
                continue
            # Fail closed on a persisted offender: a restricted+non-PIN overlay entry
            # (e.g. stored before the registration guard, or via a direct Redis write)
            # violates the sender-constraint policy — never load it into the registry.
            if (
                entry.classification is Classification.RESTRICTED
                and entry.risk_tier is not RiskTier.PIN_REQUIRED
                and not entry.require_sender_constraint
            ):
                continue
            # Community (author-your-own) rows carry a hash-pinned manifest — RE-VERIFY it
            # before load (rug-pull defense). Any post-approval edit to the stored manifest
            # OR to these overlay fields (target/risk/classification) changes/desyncs the
            # digest, so the entry is SKIPPED (load refused → re-review required). Operator
            # rows (no ``source`` key) are unaffected — additive, no behavior change.
            if fields.get("source") == _OVERLAY_SOURCE_COMMUNITY:
                if not await _community_pin_valid(tenant_id, alias, entry, fields):
                    continue
            _components.registry.register(tenant_id, entry)
            loaded += 1
    if loaded:
        print(
            f"MCPIP CATALOG: loaded {loaded} operator-registered skill(s) from overlay",
            file=sys.stderr,
            flush=True,
        )


async def _community_pin_valid(
    tenant_id: str, alias: str, entry: AliasEntry, fields: dict[str, str]
) -> bool:
    """
    Re-verify a community overlay row's manifest hash-pin at boot-load (rug-pull defense).

    Fail-closed: returns True ONLY if the approved manifest is still present, still parses
    (schema/charset/identity guards), its ``sha256`` self-pin still holds, the digest still
    matches the pin captured at approval, AND the overlay fields the registry would load
    from (alias/target/risk/classification/transport) still equal the pinned manifest.
    Any miss, transport error, malformed record, edited manifest, or edited overlay field
    → False → the hydrator SKIPS the entry (re-review required). Structurally identical in
    spirit to the connector registry that "refuses to boot on unexpected edits".
    """
    record = await _components.extension_submissions.get_approved(tenant_id, alias)
    if record is None:
        return False
    canonical = record.get("manifest")
    pinned = record.get("sha256")
    if not isinstance(canonical, dict) or not isinstance(pinned, str):
        return False
    # Registry-sourced (X3) rows re-verify through the registry parser AND re-confirm the
    # publisher namespace is STILL allow-listed (fail-closed) — a de-listed publisher makes
    # the boot re-verify skip the row (re-review required). Skill rows use the skill parser.
    if manifest_kind(canonical) == "registry_server":
        return await _registry_pin_valid(tenant_id, alias, entry, fields, canonical, pinned)
    manifest = verify_manifest_pin(canonical)
    if manifest is None:
        return False
    # The pin captured at approval must still match the manifest's recomputed digest —
    # constant-time. Catches an edit to the stored canonical manifest that consistently
    # rewrote its embedded sha256 (the self-pin alone would then pass).
    if not constant_time_equals(pinned, manifest.computed_sha256()):
        return False
    # The overlay hash the registry loads from MUST agree with the pinned manifest —
    # catches a direct edit of the overlay row (e.g. repointing ``target``) that left the
    # approved manifest untouched.
    return (
        manifest.alias == alias
        and manifest.target == entry.target
        and manifest.transport == fields.get("transport")
        and manifest.risk_tier == fields.get("risk_tier")
        and manifest.classification == fields.get("classification")
        and constant_time_equals(pinned, fields.get("manifest_sha256", ""))
    )


async def _registry_pin_valid(
    tenant_id: str,
    alias: str,
    entry: AliasEntry,
    fields: dict[str, str],
    canonical: dict[str, Any],
    pinned: str,
) -> bool:
    """
    Boot-load re-verify for a registry-server (X3) community row — fail-closed.

    Identical rug-pull discipline to the skill path (re-parse via the registry parser, the
    pin captured at approval must still match the recomputed digest, and the overlay fields
    the registry loads from must equal the PROJECTED manifest fields) PLUS the X3-specific
    re-check that the publisher namespace is STILL a pinned member of the verified-publisher
    allow-list. Any tamper, transport error, or de-listed publisher → False → the hydrator
    SKIPS the entry (re-review required).
    """
    manifest = verify_registry_manifest_pin(canonical)
    if manifest is None:
        return False
    if not constant_time_equals(pinned, manifest.computed_sha256()):
        return False
    if not (
        manifest.alias == alias
        and manifest.target == entry.target
        and manifest.transport == fields.get("transport")
        and manifest.risk_tier == fields.get("risk_tier")
        and manifest.classification == fields.get("classification")
        and constant_time_equals(pinned, fields.get("manifest_sha256", ""))
    ):
        return False
    # Re-confirm the publisher namespace is STILL allow-listed — fail-closed (a de-listed or
    # errored allow-list makes the boot re-verify skip the row, the stronger trust posture).
    return await _components.registry_publishers.is_verified(tenant_id, manifest.publisher)


# The demo AWS environments for mcpip-inc / team-engineering — seeded in SANDBOX only so
# the cloud_iam skills vend out of the box. Role ARNs are placeholders (000000000000) and
# NO cloud secret is stored (the gateway would assume the role with its own host identity).
# One READ binding (skill_aws_s3) and one write-scoped WRITE binding
# (skill_aws_dynamodb). docs/integrate/INTEGRATIONS.md registers the real write binding
# against a live account via /v1/admin/cloud/environments.
_DEMO_CLOUD_ENV = CloudEnvironment(
    env_id="aws-eng-readonly",
    provider="aws",
    role="arn:aws:iam::000000000000:role/mcpip-eng-readonly",
    region="us-east-1",
    compartment="e0900000-0000-4000-8000-e0900000e090",  # mcpip-inc / team-engineering.
    session_ttl=900,
)
# The WRITE binding backing skill_aws_dynamodb — same compartment, a separate role whose
# real-world least-privilege policy is exactly dynamodb:PutItem on one table (the vended
# credential can do nothing else). Distinct env_id so a read binding can never satisfy a
# write skill (and vice versa).
_DEMO_DYNAMODB_ENV = CloudEnvironment(
    env_id="aws-eng-dynamodb-write",
    provider="aws",
    role="arn:aws:iam::000000000000:role/mcpip-eng-dynamodb-write",
    region="us-east-1",
    compartment="e0900000-0000-4000-8000-e0900000e090",  # mcpip-inc / team-engineering.
    session_ttl=900,
)
_DEMO_CLOUD_ENVS: tuple[CloudEnvironment, ...] = (_DEMO_CLOUD_ENV, _DEMO_DYNAMODB_ENV)


async def _hydrate_cloud_environments() -> None:
    """Seed the demo cloud environments (SANDBOX ONLY). Idempotent; never fatal."""
    if not _components.settings.sandbox_mode:
        return
    for env in _DEMO_CLOUD_ENVS:
        try:
            existing = await _components.cloud_env.get("mcpip-inc", env.env_id)
            if existing is None:
                await _components.cloud_env.put("mcpip-inc", env)
                print(
                    f"MCPIP CLOUD: seeded demo AWS environment '{env.env_id}' (sandbox)",
                    file=sys.stderr,
                    flush=True,
                )
        except Exception:  # noqa: BLE001 — advisory seed, never blocks boot.
            continue


class _RegisterSkillBody(BaseModel):
    """Body for registering a new operator skill (a new alias→target)."""

    model_config = ConfigDict(extra="forbid")

    alias: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LEN)
    target: str = Field(min_length=1, max_length=_MAX_TARGET_LEN)
    risk_tier: str = "auto"
    classification: str = "unclassified"
    # Advisory display metadata (permission-model console view) — optional, validated
    # in register_skill, never consulted by the auth pipeline.
    service: Optional[str] = Field(default=None, max_length=MAX_SERVICE_LABEL_LEN)
    access: Optional[str] = None


def _overlay_skill_invalid(alias: str, target: str, risk_tier: str, classification: str) -> bool:
    """
    AUTHORITATIVE per-skill validity for an operator-registered (overlay) skill — the
    single source of truth shared by ``register_skill`` and workspace-plan apply. True
    when the skill is INVALID: bad alias, risk/classification outside the allowed sets,
    a newline or over-length target, or a RESTRICTED skill that is not PIN_REQUIRED
    (which would bypass the production sender-constraint boot-lint — overlay entries can
    never carry ``require_sender_constraint``).
    """
    return (
        not _valid_agent_id(alias)
        or risk_tier not in _OVERLAY_RISK
        or classification not in _OVERLAY_CLASSIFICATION
        or not (1 <= len(target) <= _MAX_TARGET_LEN)
        or "\n" in target
        or (classification == "restricted" and risk_tier != "pin_required")
        # The target must ALREADY be its own canonical form. This is what makes the
        # posture floor structural rather than best-effort: the registrable set becomes
        # the fixed point of ``_canonical_target``, so two accepted targets are equal
        # iff their canonical forms are, and a fold this codebase has not thought of can
        # only reject a legal spelling (loud, reported) instead of silently admitting a
        # weaker duplicate (quiet, exploitable). See _canonical_target.
        or target.strip() != _canonical_target(target)
    )


#: Risk tiers ordered weakest → strongest. A registration may never bind a target to a
#: WEAKER tier than one it already resolves at (see ``_target_posture_conflict``).
_RISK_RANK: Final[dict[str, int]] = {"auto": 0, "pin_required": 1}
#: Classifications ordered likewise; ``restricted`` already implies ``pin_required``.
_CLASSIFICATION_RANK: Final[dict[str, int]] = {"unclassified": 0, "restricted": 1}


def _canonical_target(target: str) -> str:
    """
    Canonical form of a target — a REGISTRATION GRAMMAR, not merely a comparator.

    The distinction is the whole security property, and getting it the other way round
    was a live bug. Used only to COMPARE, a canonicalizer is a losing game: the space of
    ways to spell one URL is unbounded, and every spelling it fails to fold silently
    PERMITS a duplicate at a weaker posture. Measured against the shipped comparator,
    nine of ten hand-written variants of one Cloudflare endpoint produced a different key
    — ``?x=1``, ``/db/../db/query``, ``/db/./query``, ``//accounts``, trailing-dot host,
    ``;v=1``, ``%7Baccount_id%7D``, a literal id in place of ``{account_id}``, and path
    case. Each was another ``cf.d1.quick``.

    So this is instead enforced as a FIXED POINT: ``_overlay_skill_invalid`` refuses any
    target that is not already equal to its own canonical form. The failure mode inverts
    — a fold this function misses can now only REJECT A LEGAL SPELLING, which an operator
    notices and reports, never silently admit a bypass. Comparison downstream is then
    exact equality over a normalized set, and the comparator can no longer disagree with
    what was stored.

    Folds applied (each an observed evasion):
      * scheme and host case, the default port, a trailing dot on the host (DNS-equal);
      * ``.``/``..`` path segments, empty segments from ``//``, a trailing slash;
      * percent-decoding BEFORE the ``{placeholder}`` test — decoding after it let
        ``%7Baccount_id%7D`` survive as a literal and miss the sentinel entirely;
      * ``;`` path parameters, dropped;
      * query parameters sorted; the fragment dropped (never sent to an origin).

    Path CASE is deliberately NOT folded: RFC 3986 paths are case-sensitive, so
    ``/Query`` and ``/query`` may be different resources and folding them would
    over-match, refusing legitimate neighbours. That leaves a residual gap where an
    origin treats them alike — see ``_target_subsumes`` for the class this cannot cover.

    Deliberately conservative on shapes that are not URLs (the ``rest.ops.notify.send``
    style targets the legacy transports use): the raw string is returned casefolded, so
    identical non-URL targets still collide rather than silently comparing unequal.
    """
    raw = target.strip()
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return raw.casefold()
    if not parsed.scheme or not parsed.netloc:
        return raw.casefold()
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")  # trailing dot is DNS-equal
    port = parsed.port
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    netloc = host + (f":{port}" if port else "")

    resolved: list[str] = []
    for seg in parsed.path.split("/"):
        # Percent-decode FIRST: a placeholder written %7Bx%7D must reach the {} test.
        seg = urllib.parse.unquote(seg)
        seg = seg.split(";", 1)[0]  # drop legacy path parameters
        if seg in ("", "."):
            continue  # empty segments come from "//"; "." addresses the same place
        if seg == "..":
            if resolved:
                resolved.pop()
            continue
        resolved.append(seg)
    path = "/" + "/".join(resolved) if resolved else ""
    # The QUERY IS DROPPED, exactly like the fragment — not sorted and kept.
    #
    # Sorting folded parameter ORDER and left parameter PRESENCE alone, so
    # ``…/query?x=1`` was its own canonical form, passed the fixed-point grammar, and
    # did not subsume against ``…/query`` (``_target_subsumes`` splits on "/", so the
    # query rode inside the final segment). That registered a second alias at
    # ``auto/unclassified`` beside a ``pin_required/restricted`` binding on the same
    # endpoint — the original bypass, reopened through a parameter nobody had to
    # smuggle anywhere. ``?x=1`` was listed FIRST among the observed evasions in this
    # docstring while the code below still admitted it.
    #
    # Dropping it is both safer and more honest: an operator target that differs only
    # by a query string is the same resource for posture purposes, and a target that
    # genuinely needs one now fails the grammar loudly at registration instead of
    # silently opening a second, weaker door. No shipped catalog target carries one.
    return f"{scheme}://{netloc}{path}"


def _target_subsumes(broad: str, narrow: str) -> bool:
    """
    True when ``broad`` covers every resource ``narrow`` addresses.

    Canonicalization folds SPELLINGS of one string; it cannot relate two genuinely
    different strings that address the same endpoint at call time. The live case:
    ``/accounts/{account_id}/d1/database/query`` and
    ``/accounts/12345/d1/database/query`` are distinct canonical targets, but the
    template covers the literal — so registering the literal at ``auto`` downgrades
    account 12345 out from under a template bound ``pin_required``. Segment-wise
    subsumption closes it: the ``{}`` sentinel matches any single segment, every other
    segment must match exactly, and lengths must agree.

    Directional on purpose. The floor asks "does anything ALREADY-REGISTERED cover what
    is now being registered", so a narrow new binding is measured against a broad
    existing one — and, because the reverse is equally exploitable (register the broad
    template weakly AFTER a strict literal), the caller checks both directions.
    """
    if broad == narrow:
        return True
    if "://" not in broad or "://" not in narrow:
        return False
    b_head, _, b_rest = broad.partition("://")
    n_head, _, n_rest = narrow.partition("://")
    if b_head != n_head:
        return False
    b_parts = b_rest.split("/")
    n_parts = n_rest.split("/")
    if len(b_parts) != len(n_parts):
        return False

    def _is_placeholder(seg: str) -> bool:
        return seg.startswith("{") and seg.endswith("}") and len(seg) >= 2

    # A placeholder segment matches ANY single segment, including a differently-NAMED
    # placeholder: {account_id} and {acct} are one operator's choice of variable name for
    # the same position, so they must not be registrable as two postures for one resource.
    return all(
        _is_placeholder(b) or _is_placeholder(n) or b == n
        for b, n in zip(b_parts, n_parts)
    )


async def _target_posture_conflict(
    tenant_id: str, target: str, risk_tier: str, classification: str
) -> tuple[bool, Optional[str]]:
    """
    The alias a caller names must never be a way to WEAKEN a resource's posture.

    The additive-only invariant guards the alias NAME: it refuses to repoint an existing
    alias. It says nothing about the TARGET, so without this check a second alias for the
    SAME resource at a lower tier silently downgrades it — ``cf.d1.query`` (pin_required)
    and ``cf.d1.quick`` (auto) pointing at one URL means the identical destructive payload
    is staged for step-up under one name and allowed outright under the other. Risk was
    bound to the name; it has to be bound to the resource.

    Returns ``(conflict, disclosable_alias)``:
      * ``conflict`` — True when this registration would bind ``target`` MORE WEAKLY
        (lower risk tier, or lower classification) than an alias that already resolves to
        the same canonical target. An EQUAL or STRICTER posture is allowed: a duplicate
        name may tighten, never loosen.
      * ``disclosable_alias`` — the conflicting alias, but ONLY when naming it discloses
        nothing. ``entries_for_tenant`` is deliberately UNFILTERED (catalog filtering
        layers above it), so it includes COMPARTMENTED aliases the caller may hold no
        grant for — and ``CAP_DIRECTORY_ADMIN`` does not imply compartment membership,
        because capabilities here are non-hierarchical. Naming such an alias would turn
        this route into a probing oracle: register-at-``auto`` against a guessed target,
        read the compartment's alias name out of the error. That is exactly the estate
        disclosure ``test_alias_naming_hygiene.py`` exists to prevent, and it must not be
        reintroduced through the error path. Compartmented conflicts therefore report
        ``None`` — the operator learns the target is spoken for, never by what.
        Un-compartmented (tenant-wide) aliases are already visible to any tenant member
        via ``/v1/catalog``, so naming those adds nothing.

    Fails CLOSED on a storage error: the overlay read raising is treated as "cannot prove
    this is safe", and the caller refuses without naming anything.
    """
    canon = _canonical_target(target)
    new_risk = _RISK_RANK.get(risk_tier, -1)
    new_class = _CLASSIFICATION_RANK.get(classification, -1)

    def _weaker_than(existing_risk: str, existing_class: str) -> bool:
        return (
            new_risk < _RISK_RANK.get(existing_risk, 0)
            or new_class < _CLASSIFICATION_RANK.get(existing_class, 0)
        )

    # Config-shipped + live-registered bindings held in memory on this worker.
    for entry in _components.registry.entries_for_tenant(tenant_id):
        existing = _canonical_target(entry.target)
        # Both directions: a template already bound strictly must cover a narrow literal
        # registered now, AND a broad template registered now must not undercut a strict
        # literal already bound.
        if not (_target_subsumes(existing, canon) or _target_subsumes(canon, existing)):
            continue
        if _weaker_than(entry.risk_tier, entry.classification or "unclassified"):
            # Disclose the name only for a tenant-wide alias (see docstring).
            return True, (entry.alias if entry.compartment is None else None)
    # The authoritative cross-worker overlay: a peer may have registered a stricter
    # binding this worker has not hydrated yet. Overlay skills are always
    # un-compartmented (``_overlay_entry`` never sets one), so naming them is safe.
    try:
        overlay = await _components.catalog_overlay.list_for_tenant(tenant_id)
    except Exception:  # noqa: BLE001 — cannot prove safety ⇒ refuse, disclose nothing.
        return True, None
    for alias, fields in overlay.items():
        stored = fields.get("target")
        if not isinstance(stored, str):
            continue
        stored_canon = _canonical_target(stored)
        if not (
            _target_subsumes(stored_canon, canon) or _target_subsumes(canon, stored_canon)
        ):
            continue
        if _weaker_than(
            str(fields.get("risk_tier", "auto")),
            str(fields.get("classification", "unclassified")),
        ):
            return True, alias
    return False, None


def _overlay_fields(
    target: str,
    risk_tier: str,
    classification: str,
    *,
    service: Optional[str] = None,
    access: Optional[str] = None,
) -> dict[str, str]:
    """The persisted overlay field map for one skill (transport forced to cloud_rest).

    ``service``/``access`` are ADVISORY DISPLAY metadata (permission-model console
    view) — stored only when set, never consulted by the auth pipeline.
    """
    fields = {
        "target": target,
        "transport": _OVERLAY_TRANSPORT,
        "risk_tier": risk_tier,
        "classification": classification,
        # Operator-visibility metadata: when this skill was registered (UTC, ISO-8601).
        # Ignored by _overlay_entry (fields.get), never consulted by the auth pipeline.
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    if service is not None:
        fields["service"] = service
    if access is not None:
        fields["access"] = access
    return fields


# Marks an overlay row as minted from the community (author-your-own) path rather than the
# operator register_skill path. Purely a boot-hydration discriminator: a "community" row's
# manifest sha256 pin is re-verified against ``mcpip:ext:approved:{tenant}`` before load
# (rug-pull defense), while an operator row (no ``source`` key) hydrates exactly as before.
_OVERLAY_SOURCE_COMMUNITY = "community"


def _community_overlay_fields(
    target: str, risk_tier: str, classification: str, manifest_sha256: str
) -> dict[str, str]:
    """The persisted overlay field map for a COMMUNITY-approved skill.

    Same shape as ``_overlay_fields`` (transport forced to cloud_rest; ``_overlay_entry``
    reads only target/transport/risk/classification) plus two inert-to-the-pipeline
    discriminators: ``source='community'`` and the pinned ``manifest_sha256``. The pin is
    re-verified on boot-load against the stored canonical manifest — any post-approval edit
    changes the digest and the entry is refused.
    """
    fields = _overlay_fields(target, risk_tier, classification)
    fields["source"] = _OVERLAY_SOURCE_COMMUNITY
    fields["manifest_sha256"] = manifest_sha256
    return fields


async def _apply_overlay_skill(
    tenant_id: str, alias: str, entry: AliasEntry, fields: dict[str, str], corr: str
) -> None:
    """
    Mint one overlay skill — the SINGLE apply path shared by ``register_skill`` (operator)
    and the community ``extension_approve`` handler.

    ATOMIC additive-only: the persist is a Redis ``HSETNX`` (``catalog_overlay.add``) that
    returns whether the field was NEWLY created. The alias is registered live on THIS
    worker ONLY when the atomic add reports a genuine create — if the field already existed
    (a concurrent second admin register, or a community approval racing on another worker
    whose stale in-memory ``has_alias`` pre-check said "absent"), the add refuses to
    overwrite and this raises an opaque ``MCPIPDenied``, so a stale in-memory check can
    NEVER silently repoint an existing overlay alias to an attacker target under horizontal
    scaling. The in-memory ``has_alias`` pre-check the callers still run stays as a
    fast-path/UX refusal; THIS HSETNX is the authoritative cross-worker one. Both callers
    WORM-emit BEFORE calling this (write-before-execute), and the persist fails CLOSED
    (``add`` raises ``LockError`` on a Redis error → opaque deny), so a skill is never
    registered live without also being durably stored, and never repoints an existing one.
    """
    # POSTURE floor, checked here so EVERY caller of this apply path is covered: a new
    # alias may never bind a target more weakly than one it already resolves at. The
    # callers check this too (to fail before the WORM emit and give the operator a
    # distinguishable answer); this is the authoritative cross-worker backstop, exactly
    # as the HSETNX below is for the alias name.
    conflict, _ = await _target_posture_conflict(
        tenant_id, entry.target, entry.risk_tier, entry.classification or "unclassified"
    )
    if conflict:
        raise MCPIPDenied(corr)
    created = await _components.catalog_overlay.add(tenant_id, alias, fields)
    if not created:
        # The alias already resolves in the authoritative Redis overlay — additive-only
        # refusal (never repoint). Do NOT register it live on this worker.
        raise MCPIPDenied(corr)
    _components.registry.register(tenant_id, entry)


@app.post("/v1/admin/skills/register")
async def register_skill(request: Request, body: _RegisterSkillBody) -> Response:
    """
    Register a NEW skill for the admin's own tenant — additive only. Refused (opaque
    deny) if the alias already resolves (config or a prior overlay), if the alias is
    malformed, or if risk/classification are outside the allowed set. cloud_rest
    transport only. Persisted + registered live on this worker; WORM-logged. Requires
    ``CAP_DIRECTORY_ADMIN``.
    """
    identity = await _require_directory_admin(request)
    alias = body.alias.strip()
    if _overlay_skill_invalid(alias, body.target, body.risk_tier, body.classification):
        raise MCPIPDenied(_corr(request))
    # Advisory display metadata — validated on the way in (closed access enum; charset-
    # safe, bounded service label), but NEVER an enforcement input.
    if body.access is not None and body.access not in SKILL_ACCESS_MODES:
        raise MCPIPDenied(_corr(request))
    if body.service is not None:
        if not (1 <= len(body.service) <= MAX_SERVICE_LABEL_LEN):
            raise MCPIPDenied(_corr(request))
        try:
            reject_unsafe_string(body.service, "service")
        except Exception:  # noqa: BLE001 — any ingress-guard failure is an opaque deny.
            raise MCPIPDenied(_corr(request)) from None
    # ADDITIVE-ONLY invariant: never override/shadow an existing alias.
    #
    # This route is CAP_DIRECTORY_ADMIN-gated and its caller can already read the whole
    # catalog, so a conflict is answered CONCRETELY (409) rather than with the opaque
    # deny the agent-facing surfaces use. An operator who cannot tell "already registered"
    # from "refused" learns to ignore the refusal — which is how a real denial gets
    # missed. No agent-reachable surface gains an oracle from this.
    if _components.registry.has_alias(identity.tenant_id, alias):
        return JSONResponse(
            status_code=409,
            content={"error": "alias_exists", "alias": alias,
                     "detail": "this alias already resolves; registration is additive-only"},
        )
    conflict, disclosable = await _target_posture_conflict(
        identity.tenant_id, body.target, body.risk_tier, body.classification
    )
    if conflict:
        content: dict[str, Any] = {
            "error": "target_posture_conflict",
            "alias": alias,
            "detail": (
                "another alias already binds this target at a stricter posture; a "
                "second alias may tighten it but never weaken it"
            ),
        }
        # Named only when the conflicting alias is tenant-wide. A compartmented one is
        # withheld so this route cannot be used to probe an estate the caller holds no
        # grant for (see _target_posture_conflict).
        if disclosable is not None:
            content["conflicting_alias"] = disclosable
        return JSONResponse(status_code=409, content=content)
    if await _components.catalog_overlay.count(identity.tenant_id) >= MAX_OVERLAY_ENTRIES:
        raise MCPIPDenied(_corr(request))

    fields = _overlay_fields(
        body.target,
        body.risk_tier,
        body.classification,
        service=body.service,
        access=body.access,
    )
    entry = _overlay_entry(alias, fields)
    if entry is None:
        raise MCPIPDenied(_corr(request))

    corr = _corr(request)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "skill_register",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "alias": alias,
            "transport": _OVERLAY_TRANSPORT,
            "risk_tier": body.risk_tier,
            "correlation_id": corr,
        }
    )
    # Persist first (durable, ATOMIC additive-only), then register live on this worker —
    # the shared mint path. A concurrent race on the same alias is refused here (HSETNX).
    await _apply_overlay_skill(identity.tenant_id, alias, entry, fields, corr)
    return JSONResponse(status_code=200, content={"registered": alias})


@app.post("/v1/admin/skills/{alias}/deregister")
async def deregister_skill(alias: str, request: Request) -> Response:
    """
    Remove an OPERATOR-registered skill for the admin's own tenant. Config aliases can
    never be deregistered (only overlay entries are removable); a request for a
    non-overlay alias is a no-op success. WORM-logged. Requires ``CAP_DIRECTORY_ADMIN``.
    """
    identity = await _require_directory_admin(request)
    if not _valid_agent_id(alias):
        raise MCPIPDenied(_corr(request))
    # Only overlay-registered aliases are removable — config stays immutable.
    stored = await _components.catalog_overlay.get(identity.tenant_id, alias)
    corr = _corr(request)
    removed = False
    if stored is not None:
        await _components.catalog_overlay.remove(identity.tenant_id, alias)
        removed = _components.registry.unregister(identity.tenant_id, alias)
        # Clear any disable mark so a future re-register starts clean.
        await _components.skill_gate.enable(identity.tenant_id, alias)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "skill_deregister",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "alias": alias,
            "removed": removed,
            "correlation_id": corr,
        }
    )
    return JSONResponse(status_code=200, content={"deregistered": alias, "removed": removed})


# ---------------------------------------------------------------------------
# Community extensions (author-your-own SKILLS + GATES). A Contributor (ANY authenticated
# principal) submits an ``mcpip-extension/1`` manifest for review; a Reviewer holding the
# DISTINCT ``CAP_CATALOG_REVIEWER`` acts on it. Every surface is opaque-deny + WORM-audited
# and the SAME submit/review/WORM/hash-pin flow serves both kinds (routed by ``kind``):
#   * SKILLS (Phase 1) — approve mints the skill through the SAME hardened additive overlay
#     path (``_apply_overlay_skill`` — the one ``register_skill`` uses), its manifest sha256
#     pinned for rug-pull defense. The agent wire is untouched (an agent still sees only
#     MCPIPDenied + correlation_id — the submitter-declared target is a reviewer-only surface).
#   * GATES (Phase 2, kind='gate') — the manifest SCHEMA + submit/store/review flow ship here
#     and the DENY-ONLY ``CommunityGateProvider`` seam is wired at pipeline step 4c′, but the
#     CEL parse/lint/evaluate RUNTIME is DEFERRED (an owner dependency decision — see
#     docs/integrate/EXTENSIBILITY.md §8). A gate is therefore stored PENDING but APPROVAL is refused
#     (no static prover ⇒ no approve-without-proof); enabling a CEL engine is purely additive.
# ---------------------------------------------------------------------------


class _ExtensionSubmitBody(BaseModel):
    """Body for a community-extension submission — the raw manifest under review.

    The manifest is operator/community-authored structured data validated in code by the
    strict ``ExtensionManifest`` schema (not a fixed pydantic sub-model here), so the
    wrapper is deliberately a single opaque ``dict`` — every field/charset/identity/self-pin
    check happens fail-closed inside ``parse_manifest``.
    """

    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]


def _valid_submission_id(submission_id: str) -> bool:
    """A submission id is a server-minted uuid4 hex (32 lowercase hex chars).

    Validating the SHAPE before touching Redis keeps a malformed/oversized/newline id from
    ever reaching a hash field and guarantees the endpoint stays opaque on junk input.
    """
    return len(submission_id) == 32 and all(ch in "0123456789abcdef" for ch in submission_id)


async def _submit_gate_extension(
    identity: Identity, corr: str, raw_manifest: dict[str, Any]
) -> Response:
    """
    Submit path for a community GATE manifest (``kind='gate'``, Phase 2).

    Mirrors the skill submit flow EXACTLY (validate fail-closed → bound the pending queue →
    WORM ``extension_submit`` BEFORE the store → PENDING), differing only in the manifest
    variant and the gate-shaped record/WORM fields. Validation is DATA-only
    (``parse_gate_manifest``: strict schema + charset + identity-shape + whitelist-subset +
    ``max_cost`` bound + ``sha256`` self-pin) — NO CEL parse, so no CEL runtime is needed to
    submit + schema-validate + store a gate. A gate stays PENDING and is NOT enforced: it can
    only be APPROVED once the deferred CEL prover/engine is registered (approve refuses until
    then). Any failure → opaque ``MCPIPDenied`` + correlation_id; the reason lives only in WORM.
    """
    try:
        gate = parse_gate_manifest(raw_manifest)
    except ExtensionManifestError:
        raise MCPIPDenied(corr) from None
    # Bound the shared pending queue (fail-soft count; the add below is fail-closed).
    pending = await _components.extension_submissions.count_pending(identity.tenant_id)
    if pending >= MAX_PENDING_SUBMISSIONS:
        raise MCPIPDenied(corr)

    submission_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    record: dict[str, Any] = {
        "state": STATE_PENDING,
        "submission_id": submission_id,
        # The AUTHORITATIVE actor is the JWT agent_id — never the manifest's ``author`` label.
        "submitter_agent_id": identity.agent_id,
        "author": gate.author,
        # A gate has no alias/target; ``gate_id`` is its human-facing handle (metadata only).
        "gate_id": gate.id,
        "manifest": gate.canonical_dict(),
        "manifest_sha256": gate.sha256,
        "created_at": now,
    }
    # WORM the submission BEFORE the store mutation (write-before-execute).
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "extension_submit",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "kind": "gate",
            "manifest_sha256": gate.sha256,
            "actor_agent_id": identity.agent_id,
            "submitter_agent_id": identity.agent_id,
            "gate_id": gate.id,
            "language": gate.language,
            "max_cost": gate.max_cost,
            "correlation_id": corr,
        }
    )
    await _components.extension_submissions.add_pending(
        identity.tenant_id, submission_id, record
    )
    return JSONResponse(status_code=200, content={"submission_id": submission_id})


async def _submit_registry_extension(
    identity: Identity, corr: str, raw_manifest: dict[str, Any]
) -> Response:
    """
    Submit path for a registry-server manifest (``kind='registry_server'``, X3).

    Mirrors the skill submit flow EXACTLY (validate fail-closed → the authoritative
    ``_overlay_skill_invalid`` on the PROJECTED overlay fields → bound the shared pending
    queue → WORM ``extension_submit`` BEFORE the store → PENDING), differing only in the
    manifest variant and the registry-shaped record/WORM fields (publisher namespace +
    server provenance). The verified-publisher allow-list is NOT consulted here (it is the
    APPROVE-time gate) and alias existence is NOT probed (submit is broadly reachable — a
    catalog lookup would be an existence oracle). Any failure → opaque ``MCPIPDenied`` +
    correlation_id; the reason lives only in WORM.
    """
    try:
        manifest = parse_registry_manifest(raw_manifest)
    except ExtensionManifestError:
        raise MCPIPDenied(corr) from None
    # Authoritative per-skill validity over the PROJECTED overlay fields — the SAME
    # predicate register_skill / community-skill approve share (cloud_rest is forced by the
    # projection; restricted⇒pin_required + alias charset + target length/newline enforced).
    if _overlay_skill_invalid(
        manifest.alias, manifest.target, manifest.risk_tier, manifest.classification
    ):
        raise MCPIPDenied(corr)
    # Bound the shared pending queue (fail-soft count; the add below is fail-closed).
    pending = await _components.extension_submissions.count_pending(identity.tenant_id)
    if pending >= MAX_PENDING_SUBMISSIONS:
        raise MCPIPDenied(corr)

    submission_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    publisher = manifest.publisher
    provenance = manifest.provenance()
    record: dict[str, Any] = {
        "state": STATE_PENDING,
        "submission_id": submission_id,
        # The AUTHORITATIVE actor is the JWT agent_id — never the manifest's ``author`` label.
        "submitter_agent_id": identity.agent_id,
        "author": manifest.author,
        "alias": manifest.alias,
        # Registry-specific reviewer surface: the publisher namespace + server metadata.
        "publisher_namespace": publisher,
        "server_name": manifest.server.name,
        "server_version": manifest.server.version,
        "manifest": manifest.canonical_dict(),
        "manifest_sha256": manifest.sha256,
        "created_at": now,
    }
    # WORM the submission BEFORE the store mutation (write-before-execute). The server.json
    # ``_meta`` provenance is RECORDED here for audit but is NEVER trusted for authz (the
    # verified-publisher verdict rides the pinned allow-list only).
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "extension_submit",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "kind": "registry_server",
            "manifest_sha256": manifest.sha256,
            "actor_agent_id": identity.agent_id,
            "submitter_agent_id": identity.agent_id,
            "alias": manifest.alias,
            "transport": _OVERLAY_TRANSPORT,
            "risk_tier": manifest.risk_tier,
            "publisher_namespace": publisher,
            "server_name": manifest.server.name,
            "server_provenance": provenance,
            "correlation_id": corr,
        }
    )
    await _components.extension_submissions.add_pending(
        identity.tenant_id, submission_id, record
    )
    return JSONResponse(status_code=200, content={"submission_id": submission_id})


@app.post("/v1/extensions/submit")
async def submit_extension(request: Request, body: _ExtensionSubmitBody) -> Response:
    """
    Submit a community SKILL manifest for review — Contributor surface, ANY authenticated
    principal (kill-switch enforced). Deliberately placed OUTSIDE the ``/v1/admin/*`` prefix
    so the "everything under /v1/admin is admin-gated" convention holds and an operator can
    never misread this as an admin-only surface.

    Validates the manifest fail-closed (strict schema + charset + identity-shape + sha256
    self-pin via ``parse_manifest``, then the authoritative ``_overlay_skill_invalid``
    predicate ``register_skill`` shares), bounds the pending queue, WORM-records
    ``extension_submit`` BEFORE storing, and stores PENDING. Any failure → opaque
    ``MCPIPDenied`` + correlation_id; the concrete reason lives only in WORM.

    It does NOT probe alias existence (no ``registry.has_alias``): submit is broadly
    reachable, so a catalog lookup here would be an alias-existence/timing oracle for
    un-entitled contributors. Conflict/additive-only resolution is deferred to the
    reviewer-gated, opaque approve.

    A ``kind='gate'`` manifest (Phase 2) routes to :func:`_submit_gate_extension` — the SAME
    submit/WORM/store flow, validated as pure DATA (no CEL runtime). A gate is stored PENDING
    but can never be approved/enforced until the deferred CEL prover/engine is registered.
    """
    identity = await _require_authenticated(request)
    corr = _corr(request)
    # Route by declared kind — a hint only; each branch fully validates fail-closed, so a
    # spoofed/absent kind cannot smuggle an unvalidated manifest through.
    kind = manifest_kind(body.manifest)
    if kind == "gate":
        return await _submit_gate_extension(identity, corr, body.manifest)
    if kind == "registry_server":
        return await _submit_registry_extension(identity, corr, body.manifest)
    try:
        manifest = parse_manifest(body.manifest)
    except ExtensionManifestError:
        raise MCPIPDenied(corr) from None
    # Authoritative per-skill validity — the SAME predicate register_skill enforces.
    if _overlay_skill_invalid(
        manifest.alias, manifest.target, manifest.risk_tier, manifest.classification
    ):
        raise MCPIPDenied(corr)
    # Bound the pending queue against flooding. count is fail-soft (0 on a Redis error), but
    # the add_pending write below is fail-closed, so an outage denies rather than overruns.
    pending = await _components.extension_submissions.count_pending(identity.tenant_id)
    if pending >= MAX_PENDING_SUBMISSIONS:
        raise MCPIPDenied(corr)

    submission_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    record: dict[str, Any] = {
        "state": STATE_PENDING,
        "submission_id": submission_id,
        # The AUTHORITATIVE actor is the JWT agent_id — never the manifest's ``author``
        # label (untrusted operator-facing metadata). Recorded to WORM + the review surface.
        "submitter_agent_id": identity.agent_id,
        "author": manifest.author,
        "alias": manifest.alias,
        "manifest": manifest.canonical_dict(),
        "manifest_sha256": manifest.sha256,
        "created_at": now,
    }
    # WORM the submission BEFORE the store mutation (write-before-execute).
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "extension_submit",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "kind": "skill",
            "manifest_sha256": manifest.sha256,
            "actor_agent_id": identity.agent_id,
            "submitter_agent_id": identity.agent_id,
            "alias": manifest.alias,
            "transport": _OVERLAY_TRANSPORT,
            "risk_tier": manifest.risk_tier,
            "correlation_id": corr,
        }
    )
    await _components.extension_submissions.add_pending(
        identity.tenant_id, submission_id, record
    )
    return JSONResponse(status_code=200, content={"submission_id": submission_id})


@app.get("/v1/admin/extensions/pending")
async def list_pending_extensions(request: Request) -> Response:
    """
    List the tenant's PENDING community-skill submissions for review — Reviewer surface
    (``CAP_CATALOG_REVIEWER``), read-only, tenant-scoped. A strict WHITELIST projection of
    manifest fields plus a rendered diff vs the live catalog (``conflicts_existing_alias``
    — an approve would be refused additive-only) and a separation-of-duties hint
    (``submitter_is_reviewer``). The submitter-declared ``target`` is visible to the
    reviewer here (an operator/reviewer surface) but NEVER crosses the agent wire.
    """
    identity = await _require_catalog_reviewer(request)
    records = await _components.extension_submissions.list_pending(identity.tenant_id)
    items: list[dict[str, Any]] = []
    for sid, record in records.items():
        if record.get("state") != STATE_PENDING:
            continue  # only PENDING awaits review; approved/rejected are terminal history.
        manifest = record.get("manifest")
        if not isinstance(manifest, dict):
            continue
        submitter = str(record.get("submitter_agent_id", ""))
        if manifest_kind(manifest) == "gate":
            # Community GATE (Phase 2): a topology-free deny predicate, NOT an alias→target.
            # ``approvable`` is the honest reviewer signal — gate approval is BLOCKED until
            # the deferred CEL prover/engine is registered (docs/integrate/EXTENSIBILITY.md §8), so a
            # reviewer sees WHY it cannot yet approve rather than a silent dead button.
            items.append(
                {
                    "submission_id": sid,
                    "kind": "gate",
                    "gate_id": str(record.get("gate_id", "")),
                    "language": str(manifest.get("language", "")),
                    "max_cost": manifest.get("max_cost"),
                    "referenced_context_fields": manifest.get(
                        "referenced_context_fields", []
                    ),
                    "author": str(record.get("author", "")),
                    "submitter_agent_id": submitter,
                    "manifest_sha256": str(record.get("manifest_sha256", "")),
                    "created_at": str(record.get("created_at", "")),
                    "submitter_is_reviewer": submitter == identity.agent_id,
                    "approvable": community_gate_engine_registered(),
                }
            )
            continue
        if manifest_kind(manifest) == "registry_server":
            # Registry-server (X3): a governed server.json projection. The target URL +
            # provenance are reviewer-only surfaces (they NEVER cross the agent wire).
            # ``verified`` is the honest, live signal — is the publisher namespace CURRENTLY
            # allow-listed? (an approve would be refused fail-closed otherwise).
            parsed = verify_registry_manifest_pin(manifest)
            publisher = str(record.get("publisher_namespace", ""))
            reg_alias = str(record.get("alias", ""))
            verified = (
                await _components.registry_publishers.is_verified(
                    identity.tenant_id, publisher
                )
                if publisher
                else False
            )
            items.append(
                {
                    "submission_id": sid,
                    "kind": "registry_server",
                    "alias": reg_alias,
                    # Reviewer-only: the derived cloud_rest target URL.
                    "target": parsed.target if parsed is not None else "",
                    "transport": _OVERLAY_TRANSPORT,
                    "risk_tier": str(manifest.get("risk_tier", "")),
                    "classification": str(manifest.get("classification", "")),
                    "publisher_namespace": publisher,
                    "server_name": str(record.get("server_name", "")),
                    "server_version": str(record.get("server_version", "")),
                    # Provenance is RECORDED-not-trusted; surfaced to the reviewer only.
                    "provenance": (parsed.provenance() if parsed is not None else None),
                    "author": str(record.get("author", "")),
                    "submitter_agent_id": submitter,
                    "manifest_sha256": str(record.get("manifest_sha256", "")),
                    "created_at": str(record.get("created_at", "")),
                    "verified": verified,
                    "conflicts_existing_alias": (
                        _components.registry.has_alias(identity.tenant_id, reg_alias)
                        or await _components.catalog_overlay.exists(
                            identity.tenant_id, reg_alias
                        )
                    ),
                    "submitter_is_reviewer": submitter == identity.agent_id,
                }
            )
            continue
        alias = str(record.get("alias", ""))
        items.append(
            {
                "submission_id": sid,
                "kind": "skill",
                "alias": alias,
                "target": str(manifest.get("target", "")),
                "transport": str(manifest.get("transport", "")),
                "risk_tier": str(manifest.get("risk_tier", "")),
                "classification": str(manifest.get("classification", "")),
                "author": str(record.get("author", "")),
                "submitter_agent_id": submitter,
                "manifest_sha256": str(record.get("manifest_sha256", "")),
                "created_at": str(record.get("created_at", "")),
                # Additive-only diff: does this alias already resolve (config OR overlay)?
                # Computed from the AUTHORITATIVE cross-worker sources — the in-memory
                # registry (config + hydrated overlay) OR the Redis overlay HEXISTS — so a
                # stale per-worker registry can't deceive the reviewer into approving a
                # repoint that the atomic apply would (correctly) refuse.
                "conflicts_existing_alias": (
                    _components.registry.has_alias(identity.tenant_id, alias)
                    or await _components.catalog_overlay.exists(
                        identity.tenant_id, alias
                    )
                ),
                # Separation-of-duties hint for the console (procedural, not a control).
                "submitter_is_reviewer": submitter == identity.agent_id,
            }
        )
    return JSONResponse(status_code=200, content={"pending": items})


async def _approve_registry_extension(
    identity: Identity, corr: str, submission_id: str, record: dict[str, Any]
) -> Response:
    """
    Approve a PENDING registry-server submission (X3) — Reviewer surface, fail-closed.

    Re-runs the AUTHORITATIVE checks over the PROJECTED overlay fields BEFORE any effect —
    re-parse + re-pin (``parse_registry_manifest``), pin still matches the stored value,
    ``_overlay_skill_invalid``, additive-only (``registry.has_alias``), the
    ``MAX_OVERLAY_ENTRIES`` ceiling — THEN the VERIFIED-PUBLISHER gate: the publisher
    namespace parsed from the manifest MUST be a member of the tenant's reviewer-pinned
    allow-list, read FAIL-CLOSED (a Redis error / absent / malformed allow-list ⇒ NOT
    verified ⇒ approval REFUSED). Any failure → opaque deny, no state change.

    On success: WORM ``extension_approve`` (``kind='registry_server'`` + publisher +
    provenance) BEFORE apply (write-before-execute), persist the pinned approved manifest,
    then mint the skill through the SAME shared overlay path (``_apply_overlay_skill``) as an
    operator ``register_skill`` — additive-only HSETNX, cloud_rest forced by the projection.
    The server.json provenance is recorded but NEVER trusted — the verdict rode the pinned
    allow-list only.
    """
    try:
        manifest = parse_registry_manifest(record.get("manifest"))
    except ExtensionManifestError:
        raise MCPIPDenied(corr) from None
    # The pin must still match the value captured at submit (catches a pending-record edit).
    stored_pin = record.get("manifest_sha256")
    if not isinstance(stored_pin, str) or not constant_time_equals(stored_pin, manifest.sha256):
        raise MCPIPDenied(corr)
    # Authoritative per-skill validity over the projected overlay fields.
    if _overlay_skill_invalid(
        manifest.alias, manifest.target, manifest.risk_tier, manifest.classification
    ):
        raise MCPIPDenied(corr)
    # ADDITIVE-ONLY: never repoint/shadow an existing alias (config OR a prior overlay).
    if _components.registry.has_alias(identity.tenant_id, manifest.alias):
        raise MCPIPDenied(corr)
    # Registry skills share the operator applied-skill ceiling.
    if await _components.catalog_overlay.count(identity.tenant_id) >= MAX_OVERLAY_ENTRIES:
        raise MCPIPDenied(corr)
    # VERIFIED-PUBLISHER gate — fail-closed. The publisher namespace parsed from the server
    # name MUST be a pinned member of this tenant's reviewer allow-list; an absent/errored/
    # malformed allow-list is NOT-verified → refuse. Consulted OFF the auth hot path.
    publisher = manifest.publisher
    if not await _components.registry_publishers.is_verified(identity.tenant_id, publisher):
        raise MCPIPDenied(corr)

    fields = _community_overlay_fields(
        manifest.target, manifest.risk_tier, manifest.classification, manifest.sha256
    )
    entry = _overlay_entry(manifest.alias, fields)
    if entry is None:
        raise MCPIPDenied(corr)

    submitter = str(record.get("submitter_agent_id", ""))
    provenance = manifest.provenance()
    now = datetime.now(timezone.utc).isoformat()
    # WORM the approval BEFORE any store mutation / registry apply (write-before-execute).
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "extension_approve",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "kind": "registry_server",
            "manifest_sha256": manifest.sha256,
            "actor_agent_id": identity.agent_id,
            "submitter_agent_id": submitter,
            "alias": manifest.alias,
            "transport": _OVERLAY_TRANSPORT,
            "risk_tier": manifest.risk_tier,
            "publisher_namespace": publisher,
            "server_name": manifest.server.name,
            "server_provenance": provenance,
            "correlation_id": corr,
        }
    )
    # Persist the pinned approved manifest FIRST (source of truth for the boot pin re-verify),
    # then mint the skill through the shared overlay path. The approved record carries the
    # publisher namespace so the boot re-verify can re-confirm it is still allow-listed.
    approved_record: dict[str, Any] = {
        "manifest": manifest.canonical_dict(),
        "sha256": manifest.sha256,
        "publisher_namespace": publisher,
        "reviewer_agent_id": identity.agent_id,
        "submitter_agent_id": submitter,
        "approved_at": now,
    }
    await _components.extension_submissions.add_approved(
        identity.tenant_id, manifest.alias, approved_record
    )
    await _apply_overlay_skill(identity.tenant_id, manifest.alias, entry, fields, corr)
    # Mark the submission terminal (APPROVED).
    record["state"] = STATE_APPROVED
    record["reviewer_agent_id"] = identity.agent_id
    record["approved_at"] = now
    await _components.extension_submissions.set_state(
        identity.tenant_id, submission_id, record
    )
    return JSONResponse(status_code=200, content={"approved": manifest.alias})


@app.post("/v1/admin/extensions/{submission_id}/approve")
async def approve_extension(submission_id: str, request: Request) -> Response:
    """
    Approve a PENDING community-skill submission — Reviewer surface
    (``CAP_CATALOG_REVIEWER``), tenant-scoped, opaque deny.

    Re-runs the AUTHORITATIVE checks fail-closed BEFORE any effect: re-parse + re-validate
    the manifest (``parse_manifest`` re-runs schema/charset/identity + the sha256 self-pin),
    confirm the pin still matches what was stored at submit, re-run ``_overlay_skill_invalid``,
    enforce additive-only (``registry.has_alias``) and the ``MAX_OVERLAY_ENTRIES`` ceiling.
    ANY failure → approval REFUSED (opaque deny, no state change).

    On success: WORM ``extension_approve`` BEFORE apply (write-before-execute → the approval
    is a hash-chained, Ed25519-epoch-signed, non-repudiable record), then persist the pinned
    approved manifest, mint the skill through the SAME overlay path as ``register_skill``
    (``_apply_overlay_skill``), and mark the submission APPROVED.
    """
    identity = await _require_catalog_reviewer(request)
    corr = _corr(request)
    if not _valid_submission_id(submission_id):
        raise MCPIPDenied(corr)
    record = await _components.extension_submissions.get_pending(
        identity.tenant_id, submission_id
    )
    if record is None or record.get("state") != STATE_PENDING:
        raise MCPIPDenied(corr)
    # --- Community GATE approval (Phase 2) is fail-closed WITHOUT the deferred CEL prover. --
    # A gate is submitted + schema-validated + stored PENDING, but APPROVING one requires a
    # STATIC cost/whitelist proof over the CEL AST (max_cost ≤ budget + whitelist-only field
    # refs) — and that prover needs the DEFERRED CEL runtime (docs/integrate/EXTENSIBILITY.md §8). The
    # prover ships BUNDLED with a community-gate ENGINE; with none registered a gate cannot be
    # proven safe, so approval is REFUSED — opaque, fail-closed, no approve-without-proof.
    # Registering an engine is the single additive change that supplies BOTH the hot-path
    # provider AND this prove-and-apply path; this wave deliberately ships no unprovable apply,
    # so even a registered-but-un-wired engine still fails closed here (the second refuse).
    if manifest_kind(record.get("manifest")) == "gate":
        if not community_gate_engine_registered():
            raise MCPIPDenied(corr)
        raise MCPIPDenied(corr)
    # --- Registry-server approval (X3) — the verified-publisher gate. -------------------
    # A registry submission is governed by PROJECTING it into the SAME hardened overlay
    # path a community skill uses; the ONLY extra gate is the reviewer-pinned verified-
    # publisher allow-list, consulted fail-closed HERE (and re-checked at boot).
    if manifest_kind(record.get("manifest")) == "registry_server":
        return await _approve_registry_extension(identity, corr, submission_id, record)
    # Re-parse + re-validate the manifest authoritatively (schema/charset/identity/self-pin).
    try:
        manifest = parse_manifest(record.get("manifest"))
    except ExtensionManifestError:
        raise MCPIPDenied(corr) from None
    # The pin must still match the value captured at submit (catches a pending-record edit).
    stored_pin = record.get("manifest_sha256")
    if not isinstance(stored_pin, str) or not constant_time_equals(stored_pin, manifest.sha256):
        raise MCPIPDenied(corr)
    # Authoritative per-skill validity — SAME predicate register_skill enforces.
    if _overlay_skill_invalid(
        manifest.alias, manifest.target, manifest.risk_tier, manifest.classification
    ):
        raise MCPIPDenied(corr)
    # ADDITIVE-ONLY: never repoint/shadow an existing alias (config OR a prior overlay).
    if _components.registry.has_alias(identity.tenant_id, manifest.alias):
        raise MCPIPDenied(corr)
    # Community skills share the operator applied-skill ceiling.
    if await _components.catalog_overlay.count(identity.tenant_id) >= MAX_OVERLAY_ENTRIES:
        raise MCPIPDenied(corr)

    fields = _community_overlay_fields(
        manifest.target, manifest.risk_tier, manifest.classification, manifest.sha256
    )
    entry = _overlay_entry(manifest.alias, fields)
    if entry is None:
        raise MCPIPDenied(corr)

    submitter = str(record.get("submitter_agent_id", ""))
    now = datetime.now(timezone.utc).isoformat()
    # WORM the approval BEFORE any store mutation / registry apply (write-before-execute).
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "extension_approve",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "kind": "skill",
            "manifest_sha256": manifest.sha256,
            "actor_agent_id": identity.agent_id,
            "submitter_agent_id": submitter,
            "alias": manifest.alias,
            "transport": _OVERLAY_TRANSPORT,
            "risk_tier": manifest.risk_tier,
            "correlation_id": corr,
        }
    )
    # Persist the pinned approved manifest FIRST so a later boot's pin re-verify has its
    # source of truth; then mint the skill through the shared overlay path (overlay row +
    # live registry.register). Ordering this before _apply_overlay_skill means a Redis
    # failure can never orphan an unpinned community overlay row.
    approved_record: dict[str, Any] = {
        "manifest": manifest.canonical_dict(),
        "sha256": manifest.sha256,
        "reviewer_agent_id": identity.agent_id,
        "submitter_agent_id": submitter,
        "approved_at": now,
    }
    await _components.extension_submissions.add_approved(
        identity.tenant_id, manifest.alias, approved_record
    )
    await _apply_overlay_skill(identity.tenant_id, manifest.alias, entry, fields, corr)
    # Mark the submission terminal (APPROVED).
    record["state"] = STATE_APPROVED
    record["reviewer_agent_id"] = identity.agent_id
    record["approved_at"] = now
    await _components.extension_submissions.set_state(
        identity.tenant_id, submission_id, record
    )
    return JSONResponse(status_code=200, content={"approved": manifest.alias})


@app.post("/v1/admin/extensions/{submission_id}/reject")
async def reject_extension(submission_id: str, request: Request) -> Response:
    """
    Reject a PENDING community-skill submission — Reviewer surface
    (``CAP_CATALOG_REVIEWER``), tenant-scoped, opaque deny. WORM-records
    ``extension_reject`` BEFORE marking the submission REJECTED; NOTHING is applied to the
    catalog. Any failure (unknown/terminal id, malformed id, store error) → opaque deny.
    """
    identity = await _require_catalog_reviewer(request)
    corr = _corr(request)
    if not _valid_submission_id(submission_id):
        raise MCPIPDenied(corr)
    record = await _components.extension_submissions.get_pending(
        identity.tenant_id, submission_id
    )
    if record is None or record.get("state") != STATE_PENDING:
        raise MCPIPDenied(corr)
    # Reject works uniformly for both kinds (it only marks REJECTED, applying NOTHING); the
    # WORM ``kind`` is taken from the stored manifest so the trail stays honest. ``alias`` is
    # empty for a gate (a gate has no alias) — the ``manifest_sha256`` identifies it.
    kind = manifest_kind(record.get("manifest")) or "skill"
    alias = str(record.get("alias", ""))
    now = datetime.now(timezone.utc).isoformat()
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "extension_reject",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "kind": kind,
            "manifest_sha256": str(record.get("manifest_sha256", "")),
            "actor_agent_id": identity.agent_id,
            "submitter_agent_id": str(record.get("submitter_agent_id", "")),
            "alias": alias,
            "correlation_id": corr,
        }
    )
    record["state"] = STATE_REJECTED
    record["reviewer_agent_id"] = identity.agent_id
    record["rejected_at"] = now
    await _components.extension_submissions.set_state(
        identity.tenant_id, submission_id, record
    )
    return JSONResponse(status_code=200, content={"rejected": submission_id})


@app.get("/v1/admin/extensions/publishers")
async def get_verified_publishers(request: Request) -> Response:
    """
    Return the tenant's VERIFIED-PUBLISHER allow-list (registry governance, X3) — Reviewer
    surface (``CAP_CATALOG_REVIEWER``), read-only, tenant-scoped, opaque deny.

    An honest empty ``{"schema": "mcpip-registry-publishers/1", "namespaces": []}`` when
    nothing is stored — never a fabricated default. The read is fail-SOFT (a transport error
    yields the empty document, exactly like ``GET /v1/admin/policy``); the AUTHORITATIVE
    read the approve/boot gate uses is the separate fail-CLOSED ``is_verified``.
    """
    identity = await _require_catalog_reviewer(request)
    document = await _components.registry_publishers.get(identity.tenant_id)
    if document is None:
        document = {"schema": PUBLISHERS_SCHEMA, "namespaces": []}
    return JSONResponse(status_code=200, content={"publishers": document})


@app.put("/v1/admin/extensions/publishers")
async def put_verified_publishers(request: Request) -> Response:
    """
    Set the tenant's VERIFIED-PUBLISHER allow-list (registry governance, X3) — Reviewer
    surface (``CAP_CATALOG_REVIEWER``), tenant-scoped, opaque deny.

    The body is strict-validated (schema ``mcpip-registry-publishers/1``, ``<=
    MAX_VERIFIED_PUBLISHERS`` charset-safe / identity-safe / de-duplicated namespaces) and
    stored canonically. WORM-logged emit-before-mutate (``registry_publishers_put``). Any
    auth/validation failure is an opaque ``MCPIPDenied`` (a malformed doc never leaks its
    cause). The allow-list carries ONLY publisher namespaces — never a target or identity.
    """
    identity = await _require_catalog_reviewer(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 — malformed JSON is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        document = _components.registry_publishers.validate(body)
    except PublisherAllowListError:
        raise MCPIPDenied(_corr(request)) from None

    corr = _corr(request)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "registry_publishers_put",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "publisher_count": len(document.get("namespaces", [])),
            "correlation_id": corr,
        }
    )
    await _components.registry_publishers.put(identity.tenant_id, document)
    return JSONResponse(status_code=200, content={"ok": True})


# ---------------------------------------------------------------------------
# Operator/team USER MANAGEMENT — the admin-managed, email-keyed console roster
# (invite / list / role+status / remove). CAP_DIRECTORY_ADMIN, tenant-scoped,
# opaque deny, WORM emit-before-mutate. A MANAGEMENT surface ONLY: the ``role``
# label authorizes NOTHING (the role-claim invariant) and nothing here is read on
# the authorize hot path — identity + authz stay JWT + capabilities. "Send" is a
# one-time invite REFERENCE token (returned once), never a credential; the invited
# person authenticates through the configured IdP.
# ---------------------------------------------------------------------------
_OPERATOR_ROLES: Final[frozenset[str]] = frozenset(("admin", "member", "viewer"))
_OPERATOR_STATUSES: Final[frozenset[str]] = frozenset(("invited", "active", "disabled"))


def _admin_body_error(exc: ValidationError, *, expected: dict[str, object]) -> Response:
    """
    A helpful 400 for an ALREADY-AUTHENTICATED admin whose request body was malformed.

    Reached ONLY after the ``CAP_DIRECTORY_ADMIN`` gate, so naming the offending
    fields + the expected shape leaks nothing to outsiders — an unauthenticated or
    unauthorized caller still gets the opaque ``MCPIPDenied`` *before* any body is
    parsed. This turns the control plane's "typo → undiagnosable opaque 403" into a
    self-fixable error for the operator who is allowed to see it.
    """
    invalid = [".".join(str(p) for p in e.get("loc", ())) or "(body)" for e in exc.errors()]
    return JSONResponse(
        status_code=400,
        content={"error": "invalid request body", "invalid_fields": invalid, "expected": expected},
    )


class _OperatorInviteBody(BaseModel):
    """Invite an operator: an email + a role LABEL (authorizes nothing)."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=MAX_OPERATOR_EMAIL_LEN)
    role: str = Field(default="member")


class _OperatorUpdateBody(BaseModel):
    """Update an operator's role and/or status (at least one required)."""

    model_config = ConfigDict(extra="forbid")

    role: Optional[str] = None
    status: Optional[str] = None


@app.get("/v1/admin/users")
async def list_operator_users(request: Request) -> Response:
    """
    List the tenant's operator/team roster — cursor-paginated for SCALE (HSCAN, never
    an offset), CAP_DIRECTORY_ADMIN, tenant-scoped, opaque deny. Honest empty roster
    when nothing is stored. The secret invite-token hash is NEVER projected.
    """
    identity = await _require_directory_admin(request)
    cursor = request.query_params.get("cursor", "0")
    limit_raw = request.query_params.get("limit")
    try:
        limit = int(limit_raw) if limit_raw is not None else MAX_OPERATOR_PAGE
    except (TypeError, ValueError):
        limit = MAX_OPERATOR_PAGE
    users, next_cursor = await _components.operator_users.list(identity.tenant_id, cursor, limit)
    total = await _components.operator_users.count(identity.tenant_id)
    return JSONResponse(
        status_code=200,
        content={
            "users": [u.public() for u in users],
            "next_cursor": next_cursor,
            "count": total,
            "cap": MAX_OPERATOR_USERS,
        },
    )


@app.post(
    "/v1/admin/users/invite",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _OperatorInviteBody.model_json_schema()}},
        }
    },
)
async def invite_operator_user(request: Request) -> Response:
    """
    Invite a NEW operator by email. Additive-only (an existing email is an opaque
    conflict; a full roster is an opaque deny). WORM emit-before-mutate
    (``operator_user_invite`` — records the email + role, NEVER the token). Returns the
    record + the RAW one-time invite reference token ONCE (the admin sends it; it is not
    a credential and is stored only as a hash).

    Body: ``{email: str, role: "admin"|"member"|"viewer"}`` (role defaults to member).
    An authenticated admin who sends a malformed body / unknown role gets a helpful
    400; unauthenticated callers get the opaque deny before the body is read.
    """
    identity = await _require_directory_admin(request)
    corr = _corr(request)
    try:
        body = _OperatorInviteBody.model_validate(await request.json())
    except ValidationError as exc:
        return _admin_body_error(exc, expected={"email": "string", "role": sorted(_OPERATOR_ROLES)})
    except Exception:  # noqa: BLE001 — non-JSON / unreadable body is an opaque deny.
        raise MCPIPDenied(corr) from None
    if body.role not in _OPERATOR_ROLES:
        return JSONResponse(
            status_code=400,
            content={"error": "unknown role", "got": body.role, "allowed": sorted(_OPERATOR_ROLES)},
        )
    try:
        email = normalize_email(body.email)
    except OperatorUserError:
        raise MCPIPDenied(corr) from None
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "operator_user_invite",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "operator_email": email,
            "operator_role": body.role,
            "correlation_id": corr,
        }
    )
    try:
        record, token = await _components.operator_users.invite(
            identity.tenant_id, email, body.role, identity.agent_id
        )
    except (OperatorUserError, OperatorUserConflict, OperatorUserCapExceeded):
        raise MCPIPDenied(corr) from None
    return JSONResponse(
        status_code=201, content={"user": record.public(), "invite_token": token}
    )


@app.put("/v1/admin/users/{email}")
async def update_operator_user(request: Request) -> Response:
    """
    Update an existing operator's role and/or status (enable/disable). WORM
    emit-before-mutate (``operator_user_update``). A non-member / malformed field is an
    opaque deny. CAP_DIRECTORY_ADMIN, tenant-scoped.
    """
    identity = await _require_directory_admin(request)
    corr = _corr(request)
    try:
        email = normalize_email(request.path_params.get("email", ""))
    except OperatorUserError:
        raise MCPIPDenied(corr) from None
    try:
        body = _OperatorUpdateBody.model_validate(await request.json())
    except ValidationError as exc:
        return _admin_body_error(
            exc, expected={"role": sorted(_OPERATOR_ROLES), "status": sorted(_OPERATOR_STATUSES)}
        )
    except Exception:  # noqa: BLE001 — non-JSON / unreadable body is an opaque deny.
        raise MCPIPDenied(corr) from None
    # Authenticated admin: name what's wrong instead of an opaque deny.
    if body.role is None and body.status is None:
        return JSONResponse(status_code=400, content={"error": "provide at least one of role, status"})
    if body.role is not None and body.role not in _OPERATOR_ROLES:
        return JSONResponse(
            status_code=400,
            content={"error": "unknown role", "got": body.role, "allowed": sorted(_OPERATOR_ROLES)},
        )
    if body.status is not None and body.status not in _OPERATOR_STATUSES:
        return JSONResponse(
            status_code=400,
            content={"error": "unknown status", "got": body.status, "allowed": sorted(_OPERATOR_STATUSES)},
        )
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "operator_user_update",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "operator_email": email,
            "operator_role": body.role,
            "operator_status": body.status,
            "correlation_id": corr,
        }
    )
    try:
        record = await _components.operator_users.update(
            identity.tenant_id, email, role=body.role, status=body.status
        )
    except (OperatorUserError, OperatorUserNotFound):
        raise MCPIPDenied(corr) from None
    return JSONResponse(status_code=200, content={"user": record.public()})


@app.delete("/v1/admin/users/{email}")
async def remove_operator_user(request: Request) -> Response:
    """
    Remove an operator from the roster. WORM emit-before-mutate
    (``operator_user_remove``). CAP_DIRECTORY_ADMIN, tenant-scoped, opaque deny.
    """
    identity = await _require_directory_admin(request)
    corr = _corr(request)
    try:
        email = normalize_email(request.path_params.get("email", ""))
    except OperatorUserError:
        raise MCPIPDenied(corr) from None
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "operator_user_remove",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "operator_email": email,
            "correlation_id": corr,
        }
    )
    try:
        removed = await _components.operator_users.remove(identity.tenant_id, email)
    except LockError:
        raise MCPIPDenied(corr) from None
    return JSONResponse(status_code=200, content={"removed": removed})


# ---------------------------------------------------------------------------
# Workspace Generate — brief → a governed workspace scaffold (org chart + skills),
# reviewed by the operator and applied through the SAME hardened endpoints. Three
# steps, all CAP_DIRECTORY_ADMIN, opaque deny, tenant-scoped:
#   draft         — deterministic (inference-free) brief → plan proposal.
#   plan/validate — dry-run: authoritative per-skill checks, no mutation.
#   plan/apply    — re-validate fail-closed, then register each new skill + persist the
#                   org chart; idempotent (existing aliases skipped); WORM-logged.
# The gateway stays inference-free; a richer LLM draft is an optional console-side layer
# producing the SAME plan shape that flows through validate → apply unchanged.
# ---------------------------------------------------------------------------


class _WorkspaceDraftBody(BaseModel):
    """Body for the deterministic draft — a free-text company brief + names."""

    model_config = ConfigDict(extra="forbid")

    brief: str = Field(default="", max_length=8192)
    company: str = Field(default="My Company", max_length=120)
    tenant: str = Field(default="", max_length=120)


class _WorkspacePlanBody(BaseModel):
    """Body carrying a workspace plan for validate/apply. The plan shape is checked in
    code (it is operator-authored structured data, not a fixed pydantic schema)."""

    model_config = ConfigDict(extra="forbid")

    plan: dict[str, Any]


def _plan_list(plan: dict[str, Any], key: str) -> list[Any]:
    """The plan's ``key`` as a list, or [] — a single narrowing point for mypy + safety."""
    value = plan.get(key)
    return value if isinstance(value, list) else []


def _plan_skill_display_meta(skill: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """
    Extract + validate one plan skill's ADVISORY ``service``/``access`` display fields —
    the same ingress rules ``register_skill`` applies (closed access enum; charset-safe,
    1..MAX_SERVICE_LABEL_LEN service label). Raises ``ValueError`` on an invalid value;
    the apply path maps that to the opaque deny. Never an enforcement input.
    """
    service_raw = skill.get("service")
    access_raw = skill.get("access")
    service: Optional[str] = None
    access: Optional[str] = None
    if service_raw is not None:
        if not isinstance(service_raw, str) or not (1 <= len(service_raw) <= MAX_SERVICE_LABEL_LEN):
            raise ValueError("invalid service label")
        reject_unsafe_string(service_raw, "service")
        service = service_raw
    if access_raw is not None:
        if not isinstance(access_raw, str) or access_raw not in SKILL_ACCESS_MODES:
            raise ValueError("invalid access mode")
        access = access_raw
    return service, access


def _plan_summary(plan: dict[str, Any]) -> dict[str, int]:
    org_units = _plan_list(plan, "org_units")
    skills = _plan_list(plan, "skills")
    teams = 0
    for ou in org_units:
        if isinstance(ou, dict) and isinstance(ou.get("teams"), list):
            teams += len(ou["teams"])
    return {"org_units": len(org_units), "teams": teams, "skills": len(skills)}


@app.post("/v1/admin/workspace/draft")
async def workspace_draft(request: Request, body: _WorkspaceDraftBody) -> Response:
    """Deterministic brief → plan proposal (inference-free). No mutation. Read-only —
    the operator reviews the returned plan and submits it to plan/apply."""
    identity = await _require_directory_admin(request)
    plan = draft_plan_from_brief(body.brief, body.company, body.tenant or identity.tenant_id)
    return JSONResponse(status_code=200, content={"plan": plan, "summary": _plan_summary(plan)})


@app.post("/v1/admin/workspace/plan/validate")
async def workspace_plan_validate(request: Request, body: _WorkspacePlanBody) -> Response:
    """
    Dry-run validation of a plan for the admin's own tenant — no mutation. Runs the
    structural checks AND the authoritative per-skill overlay rules, and marks which
    skills already exist (they would be skipped on apply). Returns errors + warnings.
    """
    identity = await _require_directory_admin(request)
    plan = body.plan
    errors = validate_plan_structure(plan)
    warnings: list[str] = []
    skills = _plan_list(plan, "skills")
    for skill in skills:
        if not isinstance(skill, dict):
            continue
        alias = str(skill.get("alias", ""))
        target = str(skill.get("target", ""))
        risk = str(skill.get("risk_tier", "auto"))
        classification = str(skill.get("classification", "unclassified"))
        # Authoritative gate — the exact rule apply will enforce.
        if _overlay_skill_invalid(alias, target, risk, classification):
            errors.append(f"skill {alias!r} fails the overlay policy (charset / enum / restricted-needs-PIN)")
        elif _components.registry.has_alias(identity.tenant_id, alias):
            warnings.append(f"skill {alias!r} already exists — it will be skipped")
    # Directory doc must validate too (schema + size).
    try:
        _components.directory.validate(plan_to_directory_document(plan))
    except DirectoryDocumentError:
        errors.append("org chart is malformed or exceeds the size cap")
    return JSONResponse(
        status_code=200,
        content={"ok": not errors, "errors": errors, "warnings": warnings, "summary": _plan_summary(plan)},
    )


@app.post("/v1/admin/workspace/plan/apply")
async def workspace_plan_apply(request: Request, body: _WorkspacePlanBody) -> Response:
    """
    Apply a reviewed plan for the admin's own tenant. Re-validates fail-closed (a
    structurally-invalid plan, any policy-violating skill, or a malformed org chart is an
    opaque deny — nothing is applied). Then: persist the org chart (directory doc) and
    register each NEW skill via the authoritative overlay path; EXISTING aliases are
    skipped (idempotent). One ``workspace_plan_apply`` WORM record summarizes the outcome.
    Requires ``CAP_DIRECTORY_ADMIN``.
    """
    identity = await _require_directory_admin(request)
    plan = body.plan
    tenant = identity.tenant_id

    # Fail-closed re-validation — the client's dry-run is never trusted for the mutation.
    if validate_plan_structure(plan):
        raise MCPIPDenied(_corr(request))
    try:
        directory_doc = _components.directory.validate(plan_to_directory_document(plan))
    except DirectoryDocumentError:
        raise MCPIPDenied(_corr(request)) from None
    skills = _plan_list(plan, "skills")
    normalized: list[tuple[str, str, str, str, Optional[str], Optional[str]]] = []
    for skill in skills:
        if not isinstance(skill, dict):
            raise MCPIPDenied(_corr(request))
        alias = str(skill.get("alias", "")).strip()
        target = str(skill.get("target", ""))
        risk = str(skill.get("risk_tier", "auto"))
        classification = str(skill.get("classification", "unclassified"))
        if _overlay_skill_invalid(alias, target, risk, classification):
            raise MCPIPDenied(_corr(request))
        # Advisory display metadata — same ingress validation as register_skill
        # (closed access enum; charset-safe, bounded service label), never enforcement.
        try:
            service, access = _plan_skill_display_meta(skill)
        except ValueError:
            raise MCPIPDenied(_corr(request)) from None
        normalized.append((alias, target, risk, classification, service, access))
    # Capacity: the new (non-existing) skills must fit under the per-tenant overlay cap.
    fresh = [row for row in normalized if not _components.registry.has_alias(tenant, row[0])]
    existing_count = await _components.catalog_overlay.count(tenant)
    if existing_count + len(fresh) > MAX_OVERLAY_ENTRIES:
        raise MCPIPDenied(_corr(request))

    corr = _corr(request)
    created: list[str] = []
    skipped: list[str] = []
    # Persist the org chart first (metadata), then register the fresh skills.
    await _components.directory.put(tenant, directory_doc)
    for alias, target, risk, classification, service, access in normalized:
        if _components.registry.has_alias(tenant, alias):
            skipped.append(alias)
            continue
        fields = _overlay_fields(target, risk, classification, service=service, access=access)
        entry = _overlay_entry(alias, fields)
        if entry is None:  # defensive — validation already passed.
            raise MCPIPDenied(_corr(request))
        # POSTURE floor: a plan may not introduce a weaker binding for a target that
        # already resolves more strictly. Skipped like an existing alias rather than
        # failing the whole apply — one bad row must not strand the org chart already
        # persisted above — and reported in `skipped` so the operator sees it.
        plan_conflict, _ = await _target_posture_conflict(tenant, target, risk, classification)
        if plan_conflict:
            skipped.append(alias)
            continue
        # ATOMIC additive-only: HSETNX decides the create cross-worker. If the alias was
        # already added (by config-hydration on another worker or a concurrent apply), the
        # add refuses to overwrite — skip it and do NOT register live (never repoint).
        newly_created = await _components.catalog_overlay.add(tenant, alias, fields)
        if not newly_created:
            skipped.append(alias)
            continue
        _components.registry.register(tenant, entry)
        created.append(alias)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "workspace_plan_apply",
            "deny_reason": None,
            "tenant_id": tenant,
            "actor_agent_id": identity.agent_id,
            "org_unit_count": len(directory_doc.get("org_units", [])),
            "skills_created": len(created),
            "skills_skipped": len(skipped),
            "correlation_id": corr,
        }
    )
    return JSONResponse(
        status_code=200,
        content={"applied": True, "created": created, "skipped": skipped, "summary": _plan_summary(plan)},
    )


# ---------------------------------------------------------------------------
# Cloud IAM environments — operator-managed bindings for the cloud_iam transport.
# CAP_DIRECTORY_ADMIN, opaque deny, WORM-logged, tenant-scoped. Bindings hold NO
# cloud secret: the gateway assumes the role with its own host identity and vends a
# short-lived scoped credential per authorized call.
# ---------------------------------------------------------------------------


class _CloudEnvBody(BaseModel):
    """Body for creating/updating a cloud environment binding. No secrets."""

    model_config = ConfigDict(extra="forbid")

    env_id: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=16)
    role: str = Field(min_length=1, max_length=512)
    region: str = Field(min_length=1, max_length=64)
    compartment: Optional[str] = Field(default=None, max_length=128)
    session_ttl: int = Field(default=900, ge=1)
    # Optional REFERENCE to a SecretVault entry (never a value). None = host identity.
    vault_secret_id: Optional[str] = Field(default=None, max_length=128)


@app.get("/v1/admin/cloud/environments")
async def list_cloud_environments(request: Request) -> Response:
    """List the cloud environment bindings for the admin's own tenant. Read-only."""
    identity = await _require_directory_admin(request)
    envs = await _components.cloud_env.list_for_tenant(identity.tenant_id)
    return JSONResponse(status_code=200, content={"environments": [e.public_view() for e in envs]})


@app.put("/v1/admin/cloud/environments")
async def put_cloud_environment(request: Request, body: _CloudEnvBody) -> Response:
    """
    Create or update one cloud environment binding for the admin's own tenant. Refused
    (opaque deny) if the provider is unknown, the env_id is malformed, or the per-tenant
    cap is exceeded. WORM-logged. Requires ``CAP_DIRECTORY_ADMIN``. Holds no cloud secret.
    """
    identity = await _require_directory_admin(request)
    env_id = body.env_id.strip()
    if not _valid_agent_id(env_id) or body.provider not in CLOUD_PROVIDERS or "\n" in body.role:
        raise MCPIPDenied(_corr(request))
    existing = await _components.cloud_env.get(identity.tenant_id, env_id)
    if existing is None and await _components.cloud_env.count(identity.tenant_id) >= MAX_ENVIRONMENTS:
        raise MCPIPDenied(_corr(request))
    # A vault reference must point at an EXISTING entry of this tenant (fail closed:
    # a dangling pointer is refused at write time, not discovered at vend time).
    vault_secret_id = (body.vault_secret_id or "").strip() or None
    if vault_secret_id is not None:
        if _components.vault is None or not _valid_agent_id(vault_secret_id):
            raise MCPIPDenied(_corr(request))
        if await _components.vault.get(identity.tenant_id, vault_secret_id) is None:
            raise MCPIPDenied(_corr(request))
    env = CloudEnvironment(
        env_id=env_id,
        provider=body.provider,
        role=body.role,
        region=body.region,
        compartment=(body.compartment or None),
        session_ttl=clamp_ttl(body.session_ttl),
        vault_secret_id=vault_secret_id,
    )
    corr = _corr(request)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "cloud_env_put",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "env_id": env_id,
            "provider": body.provider,
            "correlation_id": corr,
        }
    )
    await _components.cloud_env.put(identity.tenant_id, env)
    return JSONResponse(status_code=200, content={"environment": env.public_view()})


@app.post("/v1/admin/cloud/environments/{env_id}/delete")
async def delete_cloud_environment(env_id: str, request: Request) -> Response:
    """Remove one cloud environment binding for the admin's own tenant. WORM-logged."""
    identity = await _require_directory_admin(request)
    if not _valid_agent_id(env_id):
        raise MCPIPDenied(_corr(request))
    removed = await _components.cloud_env.remove(identity.tenant_id, env_id)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "cloud_env_delete",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "env_id": env_id,
            "removed": removed,
            "correlation_id": _corr(request),
        }
    )
    return JSONResponse(status_code=200, content={"deleted": env_id, "removed": removed})


# ---------------------------------------------------------------------------
# Environment secret vault — operator-stored broker credentials (write-only values).
# CAP_DIRECTORY_ADMIN, opaque deny, WORM-logged (metadata only — the value and its
# material NEVER enter the audit ctx). No endpoint ever returns a stored value; the
# single reader is the broker (SecretVault.get_material) at vend time.
# ---------------------------------------------------------------------------


class _VaultSecretBody(BaseModel):
    """Body for storing one broker credential. The ONLY request that carries a value."""

    model_config = ConfigDict(extra="forbid")

    secret_id: str = Field(min_length=1, max_length=128)
    vendor: str = Field(min_length=1, max_length=16)
    description: str = Field(default="", max_length=200)
    # The credential envelope (e.g. {"access_key_id": ..., "secret_access_key": ...}).
    # Flat map of bounded strings; validated by services.secret_vault.validate_material.
    material: dict[str, str]


@app.get("/v1/admin/vault/secrets")
async def list_vault_secrets(request: Request) -> Response:
    """List vault entries for the admin's own tenant — METADATA ONLY, never values."""
    identity = await _require_directory_admin(request)
    if _components.vault is None:
        return JSONResponse(status_code=200, content={"vault_enabled": False, "secrets": []})
    secrets = await _components.vault.list_for_tenant(identity.tenant_id)
    return JSONResponse(
        status_code=200,
        content={"vault_enabled": True, "secrets": [s.public_view() for s in secrets]},
    )


@app.put("/v1/admin/vault/secrets")
async def put_vault_secret(request: Request, body: _VaultSecretBody) -> Response:
    """
    Store (create/rotate) one broker credential, encrypted at rest. Refused (opaque
    deny) when the vault is not configured, the vendor is unknown, the id is malformed,
    the material fails shape validation, or the per-tenant cap is exceeded. WORM-logged
    with metadata + fingerprint only. The value is never returned — not even here.
    """
    identity = await _require_directory_admin(request)
    if _components.vault is None:
        raise MCPIPDenied(_corr(request))
    secret_id = body.secret_id.strip()
    if (
        not _valid_agent_id(secret_id)
        or body.vendor not in VAULT_VENDORS
        or not validate_material(body.material)
    ):
        raise MCPIPDenied(_corr(request))
    existing = await _components.vault.get(identity.tenant_id, secret_id)
    if existing is None and await _components.vault.count(identity.tenant_id) >= MAX_VAULT_SECRETS:
        raise MCPIPDenied(_corr(request))
    corr = _corr(request)
    # Emit the admin action to WORM BEFORE the mutation (matches revoke/put_cloud_env):
    # a crash between the two must never leave a stored/rotated secret with no audit
    # trail. The fingerprint is deterministic from the material, so it is known here.
    fingerprint = _components.vault.fingerprint(body.material)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "vault_secret_put",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "secret_id": secret_id,
            "vendor": body.vendor,
            "fingerprint": fingerprint,
            "rotated": existing is not None,
            "correlation_id": corr,
        }
    )
    record = await _components.vault.put(
        identity.tenant_id, secret_id, body.vendor, body.description, body.material
    )
    return JSONResponse(status_code=200, content={"secret": record.public_view()})


@app.post("/v1/admin/vault/secrets/{secret_id}/delete")
async def delete_vault_secret(secret_id: str, request: Request) -> Response:
    """Remove one vault entry for the admin's own tenant. WORM-logged."""
    identity = await _require_directory_admin(request)
    if _components.vault is None or not _valid_agent_id(secret_id):
        raise MCPIPDenied(_corr(request))
    # Emit BEFORE the mutation (audit-before-effect). `removed` reflects the pre-delete
    # existence check; the response reports the actual removal outcome.
    existed = await _components.vault.get(identity.tenant_id, secret_id) is not None
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "vault_secret_delete",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "secret_id": secret_id,
            "removed": existed,
            "correlation_id": _corr(request),
        }
    )
    removed = await _components.vault.remove(identity.tenant_id, secret_id)
    return JSONResponse(status_code=200, content={"deleted": secret_id, "removed": removed})


@app.get("/v1/audit/verify")
async def audit_verify(request: Request) -> Response:
    """
    SANDBOX ONLY — force an epoch close then verify the signed Merkle-epoch chain.

    Returns ``{intact, first_bad_epoch}``. JWT-gated; the concrete reason of any
    tamper is the epoch number, never engine internals.
    """
    if not _components.settings.sandbox_mode:
        return JSONResponse(status_code=404, content={"error": "not found"})
    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        await _apply_delegation(_components.auth.verify_identity(token))
    except Exception:  # noqa: BLE001 — any JWT/delegation failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None

    await _components.worm.close_epoch()
    intact, bad = await _components.worm.verify_chain()
    return JSONResponse(
        status_code=200, content={"intact": intact, "first_bad_epoch": bad}
    )


@app.get("/v1/audit/proof/{event_id}")
async def audit_proof(event_id: str, request: Request) -> Response:
    """
    SANDBOX ONLY — return the O(log n) inclusion proof for one buffered event.

    CAP_DIRECTORY_ADMIN-gated and TENANT-SCOPED. The sealed record carries the
    obfuscator's hidden real target and the payload hash; this endpoint once
    returned it to ANY authenticated caller of ANY tenant (a zero-capability agent
    could read another tenant's topology). It is now gated on the same admin
    capability that DEFINES the alias→target mappings (so the target is nothing new
    to that caller) and scoped to the caller's own tenant. A cross-tenant, unknown,
    or not-yet-sealed event is an indistinguishable 404 — never an existence oracle.
    """
    if not _components.settings.sandbox_mode:
        return JSONResponse(status_code=404, content={"error": "not found"})
    identity = await _require_directory_admin(request)

    proof = await _components.worm.inclusion_proof(event_id)
    if proof is None:
        return JSONResponse(
            status_code=404,
            content={"error": "not found", "correlation_id": _corr(request)},
        )
    # Tenant scoping: an admin may prove inclusion only for its OWN tenant's events.
    # A cross-tenant (or unparseable) record is a 404 — same shape as "unknown", so
    # this can never be an existence oracle for another tenant's event ids.
    try:
        record_doc = json.loads(proof.record)
        event_body = record_doc.get("event", record_doc)
        record_tenant = event_body.get("tenant_id")
    except (ValueError, AttributeError, TypeError):
        record_tenant = None
    if record_tenant != identity.tenant_id:
        return JSONResponse(
            status_code=404,
            content={"error": "not found", "correlation_id": _corr(request)},
        )
    return JSONResponse(
        status_code=200,
        content={
            "event_id": proof.event_id,
            "epoch": proof.epoch,
            "index": proof.index,
            "record": proof.record,
            "proof": proof.proof,
            "merkle_root": proof.merkle_root,
            "epoch_hash": proof.epoch_hash,
            "signature": proof.signature,
        },
    )


@app.get("/v1/audit/attestation")
async def audit_attestation(request: Request) -> Response:
    """
    Return a portable, signed attestation of the CURRENT audit state — READ-ONLY.

    The latest SEALED epoch header (``epoch``/``end_seq``/``merkle_root``/``epoch_hash``/
    ``signature``) plus the WORM epoch key's public ``signing_key_id``, a FRESH
    ``verify_chain`` result (``intact`` + ``first_bad_epoch``), and the out-of-tamper-domain
    anchor low-watermark (``anchor_epoch``/``anchor_epoch_hash``). Every signed field was
    Ed25519-signed by the WORM key at epoch close / anchor append — this endpoint mints no
    key, signs nothing new, closes no epoch, and touches no counter: it never runs on or
    blocks the emit hot path. Any auth failure OR any engine/transport error is an opaque
    ``MCPIPDenied``.

    **``CAP_DIRECTORY_ADMIN``-gated.** The attestation commits to the GLOBAL WORM head —
    ``epoch``/``end_seq`` is a single fleet-wide ledger height, NOT a per-tenant view — and,
    unlike the SANDBOX-ONLY ``/v1/audit/verify`` + ``/v1/audit/proof``, it is available in
    PRODUCTION (a portable, externally-checkable attestation is a production artifact). So a
    plain agent JWT must not read it: that would leak cross-tenant activity volume and let any
    principal force a full ``verify_chain``. ``_require_directory_admin`` also enforces the
    revocation/quarantine kill-switches, fail-closed.
    """
    await _require_directory_admin(request)

    try:
        att = await _components.worm.attestation()
    except Exception:  # noqa: BLE001 — any engine/transport failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None

    return JSONResponse(
        status_code=200,
        content={
            "epoch": att.epoch,
            "end_seq": att.end_seq,
            "merkle_root": att.merkle_root,
            "epoch_hash": att.epoch_hash,
            "signature": att.signature,
            "signing_key_id": att.signing_key_id,
            "intact": att.intact,
            "first_bad_epoch": att.first_bad_epoch,
            "anchor_epoch": att.anchor_epoch,
            "anchor_epoch_hash": att.anchor_epoch_hash,
        },
    )


@app.get("/v1/admin/compliance/evidence")
async def compliance_evidence(request: Request) -> Response:
    """
    Export a portable COMPLIANCE-EVIDENCE bundle — READ-ONLY, ``CAP_DIRECTORY_ADMIN``-gated.

    Assembles a bundle from REAL gateway state ONLY: the existing signed ``WormAttestation``
    (latest SEALED epoch header + merkle_root + epoch_hash + signature + public
    ``signing_key_id``), a FRESH ``verify_chain`` verdict (``intact``/``first_bad_epoch``), the
    anchor low-watermark, the running version + signed release provenance, and a static
    control-mapping manifest (which MCPIP mechanism PROVIDES EVIDENCE FOR which control clause
    across EU AI Act, SEC 17a-4/FINRA, DORA, NIST 800-53, SOC 2, and ISO 42001).

    It reuses ``WormLogger.attestation`` EXACTLY like ``/v1/audit/attestation`` — it mints no
    key, signs nothing new, closes no epoch, touches no counter, and never runs on / blocks /
    reorders the write-before-execute emit path. Epoch fields are ``None`` before the first
    seal (honest empty state, never a fabricated header). The bundle NEVER asserts a
    certification, an authorization, a customer, or an auditor sign-off — evidence is not a
    certificate, and every framework block says so. No target/payload/PIN/OTP/secret ever
    crosses the boundary; the attestation fields are the SAME signed commitments
    ``/v1/audit/attestation`` already surfaces.

    **``CAP_DIRECTORY_ADMIN``-gated** (mirrors ``audit_attestation``): the bundle commits to the
    GLOBAL WORM head, so a plain agent JWT must not read it. ``_require_directory_admin`` also
    enforces the revocation/quarantine kill-switches, fail-closed. Available in PRODUCTION (a
    portable, externally-checkable evidence bundle is a production artifact). Any auth OR
    engine/transport failure is an opaque ``MCPIPDenied``.
    """
    await _require_directory_admin(request)

    try:
        att = await _components.worm.attestation()
        # The MEASURED per-event proof window. Fetched in the same fail-closed try as the
        # attestation: a bundle that silently omitted its scope would read as unlimited
        # coverage, which is exactly the overclaim the scope block exists to prevent.
        scope = await _components.worm.proof_scope()
    except Exception:  # noqa: BLE001 — any engine/transport failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None

    bundle = build_evidence_bundle(
        attestation=att,
        gateway_version=get_version(),
        release_provenance=_read_signed_release(),
        generated_at=datetime.now(timezone.utc).isoformat(),
        proof_scope=scope,
    )
    return JSONResponse(status_code=200, content=bundle)


@app.get("/v1/authenticator/{challenge_id}")
async def authenticator(challenge_id: str, request: Request) -> Response:
    """
    SANDBOX ONLY — stand-in for the enrolled device delivering the one-time code.

    Requires a valid JWT (the OTP is tenant-scoped to the verified identity) and is
    404 when ``sandbox_mode`` is False — it is never exposed on the agent MCP channel
    in production. Returns 404 when the challenge is unknown or its OTP has expired.
    """
    if not _components.settings.sandbox_mode:
        return JSONResponse(status_code=404, content={"error": "not found"})

    token = _bearer_from_header(request)
    if not token:
        raise MCPIPDenied(_corr(request))
    try:
        identity = _components.auth.verify_identity(token)
    except Exception:  # noqa: BLE001 — any JWT failure is an opaque deny.
        raise MCPIPDenied(_corr(request)) from None
    try:
        identity = await _apply_delegation(identity)
    except _DelegationDenied:
        # A delegated token with no live backing grant is denied EVERYWHERE, not
        # only on /v1/authorize — fail-closed, opaque like any deny.
        raise MCPIPDenied(_corr(request)) from None

    otp = await _components.auth.peek_authenticator_otp(identity, challenge_id)
    if otp is None:
        return JSONResponse(
            status_code=404,
            content={"error": "not found", "correlation_id": _corr(request)},
        )
    return JSONResponse(
        status_code=200, content={"challenge_id": challenge_id, "otp": otp}
    )


# ---------------------------------------------------------------------------
# Per-user authenticator (USER-BASED 2FA) — enrollment + TOTP-gated OTP reveal.
#
# Identity still comes exclusively from the verified JWT; enrollment binds extra
# proof-of-possession (an RFC 6238 authenticator app) to that principal and confers
# no capability. The payload-bound PIN and its lock are untouched: TOTP only gates
# WHO may read a staged code out of the encrypted stash. Feature-absent (no master
# key) => every surface below is an opaque 404/deny. All mutations are WORM-logged
# BEFORE the store changes; the reveal is WORM-logged BEFORE disclosure (mirrors
# forensic_read). The TOTP secret is returned exactly ONCE at enroll time and never
# enters WORM, metrics, or any other response.
# ---------------------------------------------------------------------------


class _AuthnCodeBody(BaseModel):
    """A single authenticator code (enroll-confirm / self-disable ceremonies)."""

    model_config = ConfigDict(extra="forbid")

    code: str


class _AuthnRevealBody(BaseModel):
    """TOTP-gated release of one staged step-up code."""

    model_config = ConfigDict(extra="forbid")

    challenge_id: str
    code: str


def _valid_challenge_ref(challenge_id: str) -> bool:
    """Shape-check a challenge id (uuid-hex family) before it reaches Redis."""
    return (
        isinstance(challenge_id, str)
        and 8 <= len(challenge_id) <= 64
        and all(c in "0123456789abcdef-" for c in challenge_id)
    )


@app.get("/v1/authenticator")
async def authenticator_status(request: Request) -> Response:
    """
    The caller's OWN enrollment state (enrolled / pending / enrolled_at). Metadata
    only — never the secret. 404 when user-based 2FA is absent (no master key).
    """
    identity = await _require_authenticated(request)
    store = _components.authn_enrollment
    if store is None:
        return JSONResponse(status_code=404, content={"error": "not found"})
    status = await store.status(identity.tenant_id, identity.agent_id)
    return JSONResponse(status_code=200, content=status.public_view())


@app.post("/v1/authenticator/enroll")
async def authenticator_enroll(request: Request) -> Response:
    """
    Begin enrollment: mint a fresh TOTP secret and return the provisioning material
    (otpauth:// URI + manual-entry key) EXACTLY ONCE. Refused while an ACTIVE
    enrollment exists — replacing a live authenticator requires the disable ceremony
    (a valid current code), so a stolen bearer token alone can never swap the
    human's second factor. WORM-logged before the store changes; the secret is NOT
    in the WORM record.
    """
    identity = await _require_authenticated(request)
    store = _components.authn_enrollment
    if store is None:
        return JSONResponse(status_code=404, content={"error": "not found"})
    corr = _corr(request)
    current = await store.status(identity.tenant_id, identity.agent_id)
    if current.enrolled:
        raise MCPIPDenied(corr)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "authenticator_enroll",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "correlation_id": corr,
            "ts": time.time(),
        }
    )
    begin = await store.begin(identity.tenant_id, identity.agent_id)
    if begin is None:
        raise MCPIPDenied(corr)
    AUTHENTICATOR.labels("enroll_begin").inc()
    return JSONResponse(
        status_code=200,
        content={
            "secret": begin.secret_base32,
            "provisioning_uri": begin.provisioning_uri,
            "digits": begin.digits,
            "period_s": begin.period_s,
        },
    )


@app.post("/v1/authenticator/enroll/confirm")
async def authenticator_enroll_confirm(request: Request, body: _AuthnCodeBody) -> Response:
    """
    Prove possession: verify a live code from the just-provisioned app and ACTIVATE
    the enrollment. Wrong/replayed code or lockout => opaque deny (the attempt is
    burned in the shared limiter). WORM-logged before the activation flip.
    """
    identity = await _require_authenticated(request)
    store = _components.authn_enrollment
    if store is None:
        return JSONResponse(status_code=404, content={"error": "not found"})
    corr = _corr(request)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "authenticator_confirm",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "correlation_id": corr,
            "ts": time.time(),
        }
    )
    if not await store.confirm(identity.tenant_id, identity.agent_id, body.code):
        AUTHENTICATOR.labels("verify_fail").inc()
        raise MCPIPDenied(corr)
    AUTHENTICATOR.labels("enroll_confirm").inc()
    return JSONResponse(status_code=200, content={"enrolled": True})


@app.post("/v1/authenticator/disable")
async def authenticator_disable(request: Request, body: _AuthnCodeBody) -> Response:
    """
    Self-service 2FA-off ceremony: requires a valid CURRENT code (a bearer token
    alone cannot strip the human's factor — standard authenticator-removal rule).
    Lost-device removal is the admin surface below. WORM-logged before removal.
    """
    identity = await _require_authenticated(request)
    store = _components.authn_enrollment
    if store is None:
        return JSONResponse(status_code=404, content={"error": "not found"})
    corr = _corr(request)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "authenticator_disable",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "correlation_id": corr,
            "ts": time.time(),
        }
    )
    if not await store.disable(identity.tenant_id, identity.agent_id, body.code):
        AUTHENTICATOR.labels("verify_fail").inc()
        raise MCPIPDenied(corr)
    AUTHENTICATOR.labels("disable").inc()
    return JSONResponse(status_code=200, content={"enrolled": False})


@app.post("/v1/authenticator/reveal")
async def authenticator_reveal(request: Request, body: _AuthnRevealBody) -> Response:
    """
    USER-BASED 2FA release of a staged step-up code: verify a fresh, un-replayed
    TOTP from the CALLER's enrolled authenticator, then release the sealed OTP for
    ``challenge_id`` exactly once (GETDEL). The caller then completes the classic
    two-step with the payload-bound PIN — the lock itself is untouched.

    Fail-closed & opaque at every step: absent feature, unenrolled caller, bad/
    replayed/locked-out code, unknown/expired/already-revealed challenge, and a
    cross-tenant challenge (AAD-bound) are all indistinguishable denials. The
    disclosure is WORM-logged BEFORE the code is returned (mirrors forensic_read;
    the OTP itself is never in the record).
    """
    identity = await _require_authenticated(request)
    store = _components.authn_enrollment
    totp_channel = _components.authn_totp
    if store is None or totp_channel is None:
        return JSONResponse(status_code=404, content={"error": "not found"})
    corr = _corr(request)
    if not _valid_challenge_ref(body.challenge_id):
        raise MCPIPDenied(corr)
    if not await store.verify(identity.tenant_id, identity.agent_id, body.code):
        AUTHENTICATOR.labels("verify_fail").inc()
        raise MCPIPDenied(corr)
    AUTHENTICATOR.labels("verify_ok").inc()

    # Single-use spend of the sealed code (GETDEL), THEN the audit record, THEN the
    # disclosure — an emit failure after the spend loses the code (fail-closed: the
    # action can be re-staged), but a disclosure can never precede its audit record.
    otp = await totp_channel.reveal(identity.tenant_id, body.challenge_id)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "otp_reveal",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "challenge_id": body.challenge_id,
            "found": otp is not None,
            "correlation_id": corr,
            "ts": time.time(),
        }
    )
    if otp is None:
        AUTHENTICATOR.labels("reveal_miss").inc()
        return JSONResponse(
            status_code=404, content={"error": "not found", "correlation_id": corr}
        )
    AUTHENTICATOR.labels("reveal_hit").inc()
    return JSONResponse(
        status_code=200, content={"challenge_id": body.challenge_id, "otp": otp}
    )


@app.get("/v1/admin/authenticator/enrollments")
async def authenticator_enrollments(request: Request) -> Response:
    """
    Bounded admin roster of THIS tenant's enrollments (principal + state + time) —
    metadata only, never a secret. CAP_DIRECTORY_ADMIN; read-only (no WORM emit,
    mirrors the quarantine roster read).
    """
    identity = await _require_directory_admin(request)
    store = _components.authn_enrollment
    if store is None:
        return JSONResponse(status_code=404, content={"error": "not found"})
    rows = await store.list_enrolled(identity.tenant_id)
    return JSONResponse(status_code=200, content={"enrollments": rows})


@app.delete("/v1/admin/authenticator/{agent_id}")
async def authenticator_admin_disable(agent_id: str, request: Request) -> Response:
    """
    Lost-device removal: a directory admin strips a principal's enrollment in the
    admin's OWN tenant (cross-tenant is structurally impossible — the store key is
    tenant-bound). The principal can then re-enroll. WORM-logged before removal.
    """
    identity = await _require_directory_admin(request)
    store = _components.authn_enrollment
    if store is None:
        return JSONResponse(status_code=404, content={"error": "not found"})
    if not _valid_agent_id(agent_id):
        raise MCPIPDenied(_corr(request))
    corr = _corr(request)
    await _components.worm.emit(
        {
            "decision": "admin_action",
            "admin_action": "authenticator_admin_disable",
            "deny_reason": None,
            "tenant_id": identity.tenant_id,
            "actor_agent_id": identity.agent_id,
            "subject_agent_id": agent_id,
            "correlation_id": corr,
            "ts": time.time(),
        }
    )
    removed = await store.admin_disable(identity.tenant_id, agent_id)
    AUTHENTICATOR.labels("disable").inc()
    return JSONResponse(status_code=200, content={"removed": removed})
