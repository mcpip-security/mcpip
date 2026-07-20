"""
mcpip_sdk.admin — the operator (control-plane) client.

Most methods here target the ``/v1/admin/*`` + ``/v1/directory`` surface: the
Bearer JWT must carry the :data:`~mcpip_sdk.models.CAP_DIRECTORY_ADMIN`
capability UUID in its ``capabilities`` claim, and the admin principal itself
must not be revoked or quarantined. A few carry a DISTINCT, separately-grantable
capability instead (least privilege, holding directory-admin does NOT confer
them): ``forensic_get`` needs :data:`~mcpip_sdk.models.CAP_FORENSIC_READ`, and
the community-extension REVIEW methods (``extensions_pending`` /
``extension_approve`` / ``extension_reject``) need
:data:`~mcpip_sdk.models.CAP_CATALOG_REVIEWER`; ``extension_submit`` is the lone
Contributor surface needing NO capability (any valid, un-revoked token). Any
failure — missing/insufficient capability, bad token, malformed input, policy
refusal — is the SAME opaque :class:`~mcpip_sdk.errors.MCPIPDenied` as
everywhere else.

Scope discipline: every operation acts on the ADMIN'S OWN TENANT (taken from
the verified JWT — there is no cross-tenant administration), every mutation is
WORM-logged by the gateway before it takes effect, and no read here ever
returns a secret value or a real target.
"""

from __future__ import annotations

from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import quote

from mcpip_sdk._transport import _BaseClient, _json_object
from mcpip_sdk.models import (
    PUBLISHERS_SCHEMA,
    CanaryAlias,
    CloudEnvironment,
    ComplianceEvidence,
    DeploymentStats,
    ForensicPayload,
    OperatorInvite,
    DecisionPage,
    OperatorUser,
    OperatorUserPage,
    PendingExtension,
    PlanApplyResult,
    PlanValidation,
    PolicyDocument,
    QuarantinedAgent,
    RecentDecision,
    RegisteredSkill,
    RelationList,
    VaultSecret,
    VaultSecretList,
    VerifiedPublishers,
    WorkspaceDraft,
    _dict_list,
    _str_tuple,
)


def _segment(value: str) -> str:
    """URL-encode one path segment (aliases/ids are operator input)."""
    return quote(value, safe="")


class MCPIPAdminClient(_BaseClient):
    """
    Control-plane client for one MCPIP gateway.

    ``token`` must resolve to a JWT carrying ``CAP_DIRECTORY_ADMIN`` — mint it
    from your IdP in production (see ``scripts/mint_principal.py`` for the
    claim reference) or via ``SandboxClient.dev_token(capabilities=[...])``
    against a sandbox gateway. Accepts a static string or a zero-arg callable
    (refreshed proactively before its ``exp``), like every SDK client.
    """

    # -- skills (alias kill-switch + additive overlay registry) --------------

    def skills_register(
        self,
        alias: str,
        target: str,
        risk_tier: str = "auto",
        classification: str = "unclassified",
    ) -> str:
        """
        Register a NEW overlay skill (``POST /v1/admin/skills/register``).
        ADDITIVE ONLY: an alias that already resolves (config or overlay) is
        an opaque deny — an operator can introduce a skill but never repoint
        one. Transport is forced to ``cloud_rest``; a ``restricted``
        classification requires ``risk_tier="pin_required"``. Returns the
        registered alias.
        """
        response = self._request(
            "POST",
            "/v1/admin/skills/register",
            json_body={
                "alias": alias,
                "target": target,
                "risk_tier": risk_tier,
                "classification": classification,
            },
        )
        return str(_json_object(response).get("registered", alias))

    def skills_deregister(self, alias: str) -> bool:
        """
        Remove an OPERATOR-registered skill (``POST
        /v1/admin/skills/{alias}/deregister``). Config aliases are immutable —
        deregistering one is a no-op success. Returns whether an overlay entry
        was actually removed.
        """
        response = self._request(
            "POST", f"/v1/admin/skills/{_segment(alias)}/deregister"
        )
        return bool(_json_object(response).get("removed", False))

    def skills_disable(self, alias: str) -> str:
        """
        Skill kill-switch (``POST /v1/admin/skills/{alias}/disable``): the
        alias is denied for EVERY caller until re-enabled. Never edits the
        alias→target mapping. Returns the disabled alias.
        """
        response = self._request(
            "POST", f"/v1/admin/skills/{_segment(alias)}/disable"
        )
        return str(_json_object(response).get("disabled", alias))

    def skills_enable(self, alias: str) -> bool:
        """Lift a skill disable (``POST /v1/admin/skills/{alias}/enable``).
        Returns whether a disable mark was actually in force."""
        response = self._request(
            "POST", f"/v1/admin/skills/{_segment(alias)}/enable"
        )
        return bool(_json_object(response).get("removed", False))

    def skills_registered(self) -> list[RegisteredSkill]:
        """The operator-registered (deregisterable) aliases with their
        registration timestamps (``GET /v1/admin/skills/registered``)."""
        payload = _json_object(self._request("GET", "/v1/admin/skills/registered"))
        entries = _dict_list(payload, "entries")
        if entries:
            return [RegisteredSkill.from_wire(item) for item in entries]
        # Legacy gateways sent names only — degrade honestly (no timestamps).
        return [
            RegisteredSkill(alias=name) for name in _str_tuple(payload, "registered")
        ]

    def skills_disabled(self) -> list[str]:
        """Alias names currently disabled in this tenant
        (``GET /v1/admin/skills/disabled``)."""
        payload = _json_object(self._request("GET", "/v1/admin/skills/disabled"))
        return list(_str_tuple(payload, "disabled"))

    # -- community extensions (author-your-own skills & gates) ----------------

    def extension_submit(self, manifest: Mapping[str, Any]) -> str:
        """
        Submit a community-extension manifest for review (``POST
        /v1/extensions/submit``) and return the server-minted ``submission_id``.

        CONTRIBUTOR surface — the ONE extension method that needs NO capability:
        any authenticated principal may submit (the bearer JWT need only be valid
        and not revoked/quarantined; it does NOT need ``CAP_CATALOG_REVIEWER`` or
        ``CAP_DIRECTORY_ADMIN``). Deliberately OUTSIDE the ``/v1/admin/*`` prefix,
        so it is served here purely for workflow cohesion.

        ``manifest`` is the raw ``mcpip-extension/1`` manifest as a plain dict —
        a ``kind='skill'`` alias→target entry or a ``kind='gate'`` deny predicate
        (Phase 2). The gateway validates it fail-closed (strict schema + charset +
        identity-shape + ``sha256`` self-pin; skills also re-run the authoritative
        overlay rules), bounds the pending queue, and WORM-records the submission
        BEFORE storing it PENDING. Any validation/queue failure is the SAME opaque
        :class:`~mcpip_sdk.errors.MCPIPDenied` — the concrete reason lives only in
        the WORM log. The submission is NOT applied to the catalog until a reviewer
        approves it (a gate can never be approved until a CEL prover/engine is
        registered on the gateway).
        """
        response = self._request(
            "POST", "/v1/extensions/submit", json_body={"manifest": dict(manifest)}
        )
        return str(_json_object(response).get("submission_id", ""))

    def extensions_pending(self) -> list[PendingExtension]:
        """
        List the tenant's PENDING extension submissions awaiting review (``GET
        /v1/admin/extensions/pending``).

        REVIEWER surface — the bearer JWT must carry
        :data:`~mcpip_sdk.models.CAP_CATALOG_REVIEWER` (DISTINCT from
        ``CAP_DIRECTORY_ADMIN``; holding directory-admin does NOT confer it). A
        strict whitelist projection of each manifest, tenant-scoped to the caller's
        own JWT tenant. Each row is a :class:`~mcpip_sdk.models.PendingExtension`;
        branch on ``kind`` (``"skill"`` | ``"gate"``). The submitter-declared
        ``target`` on a skill row is a reviewer-only surface (it never crosses the
        agent wire); a gate row's ``approvable`` is the honest signal that gate
        approval is blocked until a CEL prover/engine is registered.
        """
        payload = _json_object(
            self._request("GET", "/v1/admin/extensions/pending")
        )
        return [
            PendingExtension.from_wire(item)
            for item in _dict_list(payload, "pending")
        ]

    def extension_approve(self, submission_id: str) -> str:
        """
        Approve a PENDING community-SKILL submission (``POST
        /v1/admin/extensions/{submission_id}/approve``) and return the approved
        ``alias``.

        REVIEWER surface (:data:`~mcpip_sdk.models.CAP_CATALOG_REVIEWER`),
        tenant-scoped, opaque deny. The gateway re-runs the AUTHORITATIVE checks
        fail-closed BEFORE any effect (re-parse + re-validate the manifest, confirm
        the ``sha256`` pin still matches, re-run the overlay validity rules, enforce
        additive-only and the overlay ceiling); ANY failure → approval REFUSED with
        no state change (opaque :class:`~mcpip_sdk.errors.MCPIPDenied`). On success
        it WORM-records ``extension_approve`` BEFORE applying, then mints the skill
        through the SAME hardened overlay path ``skills_register`` uses and pins the
        approved manifest against post-approval rug-pulls.

        A ``kind='gate'`` submission ALWAYS denies here (no approve-without-proof):
        gate approval needs a STATIC CEL cost/whitelist proof that requires the
        deferred CEL prover/engine, so until one is registered on the gateway an
        approve is an opaque deny — check the row's ``approvable`` flag first.
        """
        response = self._request(
            "POST", f"/v1/admin/extensions/{_segment(submission_id)}/approve"
        )
        return str(_json_object(response).get("approved", ""))

    def extension_reject(self, submission_id: str) -> str:
        """
        Reject a PENDING community-extension submission (``POST
        /v1/admin/extensions/{submission_id}/reject``) and return the rejected
        ``submission_id``.

        REVIEWER surface (:data:`~mcpip_sdk.models.CAP_CATALOG_REVIEWER`),
        tenant-scoped, opaque deny. Works uniformly for both kinds (it only marks
        the submission REJECTED — NOTHING is applied to the catalog); the gateway
        WORM-records ``extension_reject`` BEFORE marking it terminal. An
        unknown/terminal/malformed id is the SAME opaque
        :class:`~mcpip_sdk.errors.MCPIPDenied`.
        """
        response = self._request(
            "POST", f"/v1/admin/extensions/{_segment(submission_id)}/reject"
        )
        return str(_json_object(response).get("rejected", submission_id))

    # -- registry governance (verified-publisher allow-list, X3) --------------

    def verified_publishers_get(self) -> VerifiedPublishers:
        """
        The tenant's VERIFIED-PUBLISHER allow-list (``GET
        /v1/admin/extensions/publishers``) — the reviewer-PINNED set of allowed
        publisher NAMESPACES (reverse-DNS prefixes such as ``io.github.owner``)
        that a registry-sourced skill must belong to before it can be approved
        or re-verified at boot.

        REVIEWER surface (:data:`~mcpip_sdk.models.CAP_CATALOG_REVIEWER`),
        read-only, tenant-scoped, opaque deny. ALWAYS resolves to a document:
        when nothing is pinned the gateway returns the honest empty
        ``{"schema": "mcpip-registry-publishers/1", "namespaces": []}`` — never a
        fabricated default. This admin read is fail-SOFT; the AUTHORITATIVE
        fail-CLOSED membership check runs server-side at approve/boot. The
        document carries ONLY publisher namespaces — never a target or identity.
        """
        payload = _json_object(
            self._request("GET", "/v1/admin/extensions/publishers")
        )
        publishers = payload.get("publishers")
        return VerifiedPublishers.from_wire(
            publishers if isinstance(publishers, dict) else {}
        )

    def verified_publishers_put(self, namespaces: list[str]) -> None:
        """
        Set the tenant's VERIFIED-PUBLISHER allow-list (``PUT
        /v1/admin/extensions/publishers``) — replaces the pinned set with
        ``namespaces`` (reverse-DNS publisher prefixes).

        REVIEWER surface (:data:`~mcpip_sdk.models.CAP_CATALOG_REVIEWER`),
        tenant-scoped, opaque deny. The body is strict-validated server-side
        (schema ``mcpip-registry-publishers/1``, ``<= 256`` charset-safe /
        identity-safe / de-duplicated namespaces) and stored canonically;
        WORM-logged emit-before-mutate. A malformed list is the SAME opaque
        :class:`~mcpip_sdk.errors.MCPIPDenied` that never leaks its cause.
        """
        self._request(
            "PUT",
            "/v1/admin/extensions/publishers",
            json_body={"schema": PUBLISHERS_SCHEMA, "namespaces": list(namespaces)},
        )

    # -- compliance evidence (portable bundle, X1) ----------------------------

    def compliance_evidence(self) -> ComplianceEvidence:
        """
        Export a portable COMPLIANCE-EVIDENCE bundle (``GET
        /v1/admin/compliance/evidence``) — ``CAP_DIRECTORY_ADMIN``-gated,
        READ-ONLY.

        Assembled from REAL running gateway state ONLY: the existing signed WORM
        :class:`~mcpip_sdk.models.AuditAttestation` (latest sealed epoch header +
        a FRESH ``verify_chain`` verdict + the public ``signing_key_id``), the
        running version + signed release provenance, and a STATIC control-mapping
        manifest (which MCPIP mechanism PROVIDES EVIDENCE FOR which control clause
        across EU AI Act, SEC 17a-4/FINRA, DORA, NIST 800-53, SOC 2, ISO 42001).

        It reuses the SAME signed commitments ``audit_attestation`` surfaces — it
        mints no key, signs nothing new, closes no epoch, and never runs on / blocks
        the write-before-execute emit path. EVIDENCE, NOT a CERTIFICATION: the
        returned :attr:`~mcpip_sdk.models.ComplianceEvidence.disclaimer` (and each
        framework's ``certification_note``) restates that the bundle asserts no
        SOC 2 report, FedRAMP authorization, ISO/DORA/EU-AI-Act certificate, named
        customer, or auditor sign-off. Epoch fields are ``None`` before the first
        seal (honest empty state, never a fabricated header). No
        target/payload/PIN/OTP/secret ever crosses the boundary. Any auth OR
        engine/transport failure is an opaque :class:`~mcpip_sdk.errors.MCPIPDenied`.
        """
        payload = _json_object(
            self._request("GET", "/v1/admin/compliance/evidence")
        )
        return ComplianceEvidence.from_wire(payload)

    # -- deployment / license & usage stats (local live numbers) --------------

    def stats(self) -> DeploymentStats:
        """
        The LOCAL live-stats read (``GET /v1/admin/stats``) — this admin's OWN
        tenant's REAL running numbers, served locally with NO beacon, NO vendor,
        and NO network: the client-side "see the numbers live" surface.

        ``CAP_DIRECTORY_ADMIN``-gated, tenant-scoped, opaque deny. Returns the
        REAL governed-agent identity CARDINALITY (a HyperLogLog ``PFCOUNT`` — the
        agent_ids are never stored or exposed), the tenant's ``{allow, deny,
        staged}`` decision totals, the boot-verified license tier/status (honest
        :attr:`~mcpip_sdk.models.LicenseInfo.licensed` ``False`` when absent —
        never a fabricated customer/tier/date), the HONEST opt-in vendor-telemetry
        posture (``enabled`` / ``disabled`` / ``air-gap`` + coarse last-sent — an
        air-gapped/sandbox deployment reports ``air-gap`` and never phones home),
        and the running version.

        This is the SAME aggregate the opt-in beacon would report, but scoped to
        the caller's own tenant. A fresh tenant with nothing yet flowed gets honest
        zeros. NO tenant/agent/alias/target ever crosses this boundary — only the
        caller's own aggregate integers. Any auth OR engine failure is the SAME
        opaque :class:`~mcpip_sdk.errors.MCPIPDenied`.
        """
        payload = _json_object(self._request("GET", "/v1/admin/stats"))
        return DeploymentStats.from_wire(payload)

    # -- operator/team USER management (email-keyed roster) --------------------

    def users_list(self, cursor: str = "0", limit: int = 200) -> OperatorUserPage:
        """
        A cursor page of the admin-managed operator/team roster (``GET
        /v1/admin/users``) — ``CAP_DIRECTORY_ADMIN``, tenant-scoped, opaque deny.

        Paginated by cursor for SCALE (HSCAN, never an offset): follow
        :attr:`~mcpip_sdk.models.OperatorUserPage.next_cursor` until it is ``"0"``.
        An honest empty roster is ``users=()`` — never a fabricated member. The
        secret invite-token hash is never projected. The per-user ``role`` is a
        MANAGEMENT label; it authorizes nothing.
        """
        payload = _json_object(
            self._request(
                "GET",
                "/v1/admin/users",
                params={"cursor": cursor, "limit": str(limit)},
            )
        )
        return OperatorUserPage.from_wire(payload)

    def users_invite(self, email: str, role: str = "member") -> OperatorInvite:
        """
        Invite a NEW operator by email (``POST /v1/admin/users/invite``) —
        ``CAP_DIRECTORY_ADMIN``, tenant-scoped, WORM emit-before-mutate
        (``operator_user_invite``; the email + role are recorded, NEVER the token).

        Additive-only: an email already on the roster (or an invalid email/role, or
        a full roster) is the SAME opaque :class:`~mcpip_sdk.errors.MCPIPDenied`.
        Returns the created record + the ONE-TIME invite REFERENCE token to send —
        a shareable reference, NOT a credential (the invited person still
        authenticates through the configured IdP).
        """
        response = self._request(
            "POST",
            "/v1/admin/users/invite",
            json_body={"email": email, "role": role},
        )
        return OperatorInvite.from_wire(_json_object(response))

    def users_update(
        self, email: str, *, role: str | None = None, status: str | None = None
    ) -> OperatorUser:
        """
        Update an existing operator's role and/or status (``PUT
        /v1/admin/users/{email}``) — e.g. activate an invited member or disable
        access. At least one of ``role`` / ``status`` must be given.
        ``CAP_DIRECTORY_ADMIN``, WORM emit-before-mutate (``operator_user_update``).
        A non-member / malformed field is an opaque
        :class:`~mcpip_sdk.errors.MCPIPDenied`.
        """
        body: dict[str, str] = {}
        if role is not None:
            body["role"] = role
        if status is not None:
            body["status"] = status
        response = self._request(
            "PUT", f"/v1/admin/users/{_segment(email)}", json_body=body
        )
        return OperatorUser.from_wire(_json_object(response).get("user", {}))

    def users_remove(self, email: str) -> bool:
        """
        Remove an operator from the roster (``DELETE /v1/admin/users/{email}``) —
        ``CAP_DIRECTORY_ADMIN``, WORM emit-before-mutate (``operator_user_remove``).
        Returns whether a record was actually deleted (idempotent).
        """
        response = self._request("DELETE", f"/v1/admin/users/{_segment(email)}")
        payload = _json_object(response)
        return bool(payload.get("removed", False))

    # -- live decision feed ---------------------------------------------------

    def decisions_recent(self, limit: int = 50) -> list[RecentDecision]:
        """
        The tenant's recent allow/deny decisions, newest first (``GET
        /v1/admin/decisions/recent?limit=N``, clamped 1..200 server-side). A
        strict whitelist projection — targets/arguments never appear;
        ``deny_reason`` is operator-side visibility the agent never saw. A
        bounded recent tail for live display; the authoritative record is the
        signed epoch chain.
        """
        response = self._request(
            "GET", "/v1/admin/decisions/recent", params={"limit": str(limit)}
        )
        payload = _json_object(response)
        return [
            RecentDecision.from_wire(item)
            for item in _dict_list(payload, "decisions")
        ]

    def decisions_query(
        self,
        *,
        from_ms: int | None = None,
        to_ms: int | None = None,
        cursor: str | None = None,
        limit: int = 100,
        filters: Mapping[str, str | Sequence[str]] | None = None,
    ) -> DecisionPage:
        """
        One page of the tenant's decision HISTORY at scale (``GET
        /v1/admin/decisions``) — date-ranged, multi-filtered, cursor-paged over
        the SAME whitelist projection ``decisions_recent`` serves (targets /
        arguments never appear). ``from_ms``/``to_ms`` bound an inclusive
        epoch-millisecond window; ``filters`` maps a whitelist facet
        (``decision``/``deny_reason``/``alias``/``transport``/``risk_tier``/
        ``classification``/``agent_id``/``source_format``/``correlation_id``/
        ``transaction_ref``) to one value or a list (OR within a facet, AND across
        facets). Pass the returned ``next_cursor`` back as ``cursor=`` for the
        next page; ``None`` means the range is fully walked. ``limit`` is clamped
        server-side to ``MAX_DECISIONS_PAGE``.
        """
        params: dict[str, str] = {"limit": str(limit)}
        if from_ms is not None:
            params["from_ms"] = str(from_ms)
        if to_ms is not None:
            params["to_ms"] = str(to_ms)
        if cursor is not None:
            params["cursor"] = cursor
        for field, value in (filters or {}).items():
            joined = value if isinstance(value, str) else ",".join(str(v) for v in value)
            if joined:
                params[field] = joined
        response = self._request("GET", "/v1/admin/decisions", params=params)
        return DecisionPage.from_wire(_json_object(response))

    def decisions_iter(
        self,
        *,
        from_ms: int | None = None,
        to_ms: int | None = None,
        filters: Mapping[str, str | Sequence[str]] | None = None,
        page_limit: int = 200,
        max_pages: int = 100000,
    ) -> Iterator[RecentDecision]:
        """
        Stream EVERY matching decision across the whole window, newest first,
        following ``next_cursor`` transparently — the "export all" primitive over
        ``decisions_query``. ``page_limit`` sizes each underlying page (clamped
        server-side); ``max_pages`` is a runaway backstop.
        """
        cursor: str | None = None
        for _ in range(max_pages):
            page = self.decisions_query(
                from_ms=from_ms,
                to_ms=to_ms,
                cursor=cursor,
                limit=page_limit,
                filters=filters,
            )
            yield from page.decisions
            cursor = page.next_cursor
            if cursor is None:
                break

    # -- forensic reconstruction (investigator-only, access-audited) ----------

    def forensic_get(self, correlation_id: str) -> ForensicPayload | None:
        """
        Reconstruct the REAL query behind one ``correlation_id`` (``GET
        /v1/admin/forensic/{correlation_id}``).

        ADMIN/INVESTIGATOR-ONLY and a HIGHER bar than the rest of this client:
        the Bearer JWT must carry :data:`~mcpip_sdk.models.CAP_FORENSIC_READ`,
        which is DISTINCT from ``CAP_DIRECTORY_ADMIN`` — holding directory-admin
        does NOT grant raw-payload read. The gateway WORM-logs an
        ``admin_action='forensic_read'`` (who read whose payload) BEFORE
        disclosing anything, so every access is audited.

        Returns the decrypted :class:`~mcpip_sdk.models.ForensicPayload` — the
        opaque alias, the already-canonicalized (and secret-redacted) arguments,
        and non-secret identity context — tenant-scoped to the caller's own JWT
        tenant. Returns ``None`` for an honest, OPAQUE miss: the feature is off
        on this gateway, or the ``correlation_id`` is unknown, expired past its
        TTL, or owned by another tenant (an indistinguishable not-found — there
        is no cross-tenant existence oracle). A missing/insufficient capability
        is the usual opaque :class:`~mcpip_sdk.errors.MCPIPDenied`, never a
        ``None``.
        """
        response = self._request(
            "GET",
            f"/v1/admin/forensic/{_segment(correlation_id)}",
            tolerate=(404,),
        )
        if response.status_code == 404:
            return None
        payload = _json_object(response)
        if not payload.get("found"):
            return None
        forensic = payload.get("forensic")
        return ForensicPayload.from_wire(
            forensic if isinstance(forensic, dict) else {}
        )

    # -- principals (revocation kill-switch) ----------------------------------

    def principals_revoke(self, agent_id: str, reason: str | None = None) -> str:
        """
        Persistent principal kill-switch (``POST
        /v1/admin/principals/{agent_id}/revoke``): every subsequent request
        from (tenant, agent_id) is denied until reactivated. DENY-only — never
        mints or edits identity (the IdP stays sovereign). Returns the revoked
        agent id.
        """
        response = self._request(
            "POST",
            f"/v1/admin/principals/{_segment(agent_id)}/revoke",
            json_body={"reason": reason},
        )
        return str(_json_object(response).get("revoked", agent_id))

    def principals_reactivate(self, agent_id: str) -> bool:
        """Lift a revocation (``POST
        /v1/admin/principals/{agent_id}/reactivate``). Returns whether a
        revocation was actually in force."""
        response = self._request(
            "POST", f"/v1/admin/principals/{_segment(agent_id)}/reactivate"
        )
        return bool(_json_object(response).get("removed", False))

    def principals_revoked(self) -> list[str]:
        """Agent ids currently revoked in this tenant
        (``GET /v1/admin/principals/revoked``) — the authoritative list."""
        payload = _json_object(
            self._request("GET", "/v1/admin/principals/revoked")
        )
        return list(_str_tuple(payload, "revoked"))

    # -- canary tripwire rosters ----------------------------------------------

    def quarantine(self) -> list[QuarantinedAgent]:
        """
        Agents currently frozen by the canary tripwire, with seconds remaining
        on each TTL-bounded freeze (``GET /v1/admin/quarantine``). Read-only:
        the freeze is written only by the pipeline's canary gate and expires on
        Redis's clock — a deliberate persistent block is ``principals_revoke``.
        """
        payload = _json_object(self._request("GET", "/v1/admin/quarantine"))
        return [
            QuarantinedAgent.from_wire(item)
            for item in _dict_list(payload, "quarantined")
        ]

    def canaries(self) -> list[CanaryAlias]:
        """
        The canary decoy aliases seeded into this tenant's catalog (``GET
        /v1/admin/canaries``). This admin surface is the ONLY place the canary
        flag is ever revealed — the agent-facing catalog and MCP ``tools/list``
        keep hiding it (the bait must look real).
        """
        payload = _json_object(self._request("GET", "/v1/admin/canaries"))
        return [
            CanaryAlias.from_wire(item) for item in _dict_list(payload, "canaries")
        ]

    # -- operator directory (org chart; non-authoritative metadata) ------------

    def directory_get(self) -> dict[str, Any] | None:
        """The persisted directory document for this tenant, or None when none
        was saved (``GET /v1/directory``). Metadata only — the authorization
        pipeline never consults it."""
        payload = _json_object(self._request("GET", "/v1/directory"))
        document = payload.get("document")
        return dict(document) if isinstance(document, dict) else None

    def directory_put(self, document: Mapping[str, Any]) -> None:
        """Persist the directory document (``PUT /v1/directory`` — the body IS
        the document; schema ``mcpip-directory/1``, bounded size, ``org_units``
        list required). A malformed document is an opaque deny."""
        self._request("PUT", "/v1/directory", json_body=document)

    def directory_relations(
        self,
        *,
        subject: str | None = None,
        relation: str | None = None,
        object_uuid: str | None = None,
    ) -> RelationList:
        """
        The ReBAC relation edges projected from this tenant's committed grants —
        the authoritative edge source for the operator Knowledge-Graph (``GET
        /v1/admin/directory/relations``). A best-effort PROJECTION, tenant-scoped
        to the caller's own JWT; the gateway/Redis grant state stays the
        authoritative record. Read-only — like ``quarantine`` / ``canaries``, it
        emits no WORM record.

        Each committed grant projects a ``member`` edge (subject → compartment)
        and a read-time-derived ``grantor`` edge (issuing principal →
        compartment). The optional ``subject`` / ``relation`` / ``object_uuid``
        filters narrow the emitted edges (a malformed filter is an opaque
        :class:`~mcpip_sdk.errors.MCPIPDenied`). Supplying a FULL
        ``(subject, relation, object_uuid)`` triple additionally populates
        :attr:`~mcpip_sdk.models.RelationList.allowed` — the BOUNDED
        transitive-closure check (hop/fanout-capped, fail-closed). Only ``member``
        is traversable in v1 (``grantor`` is a derived display edge).

        READ/VISUALIZATION ONLY: the authorization pipeline NEVER consults this —
        the capability-UUID + grant gates remain the sole authority. A transport
        error yields an honest empty roster (fail-soft — the projection
        under-reports during a blip, never over-reports). Tuples carry only
        operator-facing identifiers + non-secret grant metadata; no target,
        secret, or alias→target mapping ever appears.
        """
        params: dict[str, str] = {}
        if subject is not None:
            params["subject"] = subject
        if relation is not None:
            params["relation"] = relation
        if object_uuid is not None:
            params["object"] = object_uuid
        payload = _json_object(
            self._request(
                "GET",
                "/v1/admin/directory/relations",
                params=params or None,
            )
        )
        return RelationList.from_wire(payload)

    # -- deny-only policy overlay (velocity cap + amount ceiling) ---------------

    def policy_get(self) -> PolicyDocument:
        """
        The tenant's deny-only policy document (``GET /v1/admin/policy``, schema
        ``mcpip-policy/1``). ALWAYS resolves to a document: when nothing is
        stored the gateway returns the honest empty ``{"schema":
        "mcpip-policy/1", "rules": []}`` (no limits — opt-in), never None. The
        document holds ONLY velocity/amount rules — never an alias→target mapping
        or identity.
        """
        payload = _json_object(self._request("GET", "/v1/admin/policy"))
        policy = payload.get("policy")
        return PolicyDocument.from_wire(policy if isinstance(policy, dict) else {})

    def policy_put(self, document: Mapping[str, Any]) -> None:
        """
        Persist the tenant's deny-only policy document (``PUT /v1/admin/policy``
        — the body IS the document ``{"schema", "rules"}``). Strict-validated
        server-side (``<= 64`` well-formed ``velocity``/``amount`` rules,
        size-bounded); a malformed document is the SAME opaque ``MCPIPDenied``
        that never leaks its cause. WORM-logged emit-before-mutate.
        """
        self._request("PUT", "/v1/admin/policy", json_body=document)

    def policy_delete(self) -> bool:
        """
        Remove the tenant's policy document (``POST /v1/admin/policy/delete``),
        back to the honest no-limits state. Idempotent (deleting an absent
        document still acknowledges). Returns the server's ``ok``.
        """
        response = self._request("POST", "/v1/admin/policy/delete")
        return bool(_json_object(response).get("ok", False))

    # -- workspace generate (draft → validate → apply) --------------------------

    def workspace_draft(
        self, brief: str = "", company: str = "My Company", tenant: str = ""
    ) -> WorkspaceDraft:
        """Deterministic, inference-free brief → plan proposal (``POST
        /v1/admin/workspace/draft``). No mutation — review the plan, then
        validate and apply it."""
        response = self._request(
            "POST",
            "/v1/admin/workspace/draft",
            json_body={"brief": brief, "company": company, "tenant": tenant},
        )
        return WorkspaceDraft.from_wire(_json_object(response))

    def workspace_validate(self, plan: Mapping[str, Any]) -> PlanValidation:
        """Dry-run plan validation (``POST /v1/admin/workspace/plan/validate``)
        — structural checks plus the authoritative per-skill overlay rules; no
        mutation."""
        response = self._request(
            "POST",
            "/v1/admin/workspace/plan/validate",
            json_body={"plan": dict(plan)},
        )
        return PlanValidation.from_wire(_json_object(response))

    def workspace_apply(self, plan: Mapping[str, Any]) -> PlanApplyResult:
        """Apply a reviewed plan (``POST /v1/admin/workspace/plan/apply``).
        Re-validates fail-closed server-side, persists the org chart, registers
        each NEW skill through the hardened overlay path; existing aliases are
        skipped (idempotent)."""
        response = self._request(
            "POST",
            "/v1/admin/workspace/plan/apply",
            json_body={"plan": dict(plan)},
        )
        return PlanApplyResult.from_wire(_json_object(response))

    # -- cloud IAM environments -------------------------------------------------

    def cloud_environments_list(self) -> list[CloudEnvironment]:
        """The tenant's cloud environment bindings — public views, never
        secrets (``GET /v1/admin/cloud/environments``)."""
        payload = _json_object(
            self._request("GET", "/v1/admin/cloud/environments")
        )
        return [
            CloudEnvironment.from_wire(item)
            for item in _dict_list(payload, "environments")
        ]

    def cloud_environments_put(
        self,
        env_id: str,
        provider: str,
        role: str,
        region: str,
        *,
        compartment: str | None = None,
        session_ttl: int = 900,
        vault_secret_id: str | None = None,
    ) -> CloudEnvironment:
        """
        Create/update one binding (``PUT /v1/admin/cloud/environments``). Holds
        NO cloud secret: the gateway assumes ``role`` with its own host
        identity, or with the broker credential referenced by
        ``vault_secret_id`` — which must name an EXISTING vault entry of this
        tenant (a dangling reference is refused at write time, fail-closed).
        """
        body: dict[str, Any] = {
            "env_id": env_id,
            "provider": provider,
            "role": role,
            "region": region,
            "session_ttl": session_ttl,
        }
        if compartment is not None:
            body["compartment"] = compartment
        if vault_secret_id is not None:
            body["vault_secret_id"] = vault_secret_id
        response = self._request(
            "PUT", "/v1/admin/cloud/environments", json_body=body
        )
        payload = _json_object(response)
        environment = payload.get("environment")
        return CloudEnvironment.from_wire(
            environment if isinstance(environment, dict) else {}
        )

    def cloud_environments_delete(self, env_id: str) -> bool:
        """Remove one binding (``POST
        /v1/admin/cloud/environments/{env_id}/delete`` — delete-via-POST, this
        API has no HTTP DELETE). Returns whether a binding was removed."""
        response = self._request(
            "POST", f"/v1/admin/cloud/environments/{_segment(env_id)}/delete"
        )
        return bool(_json_object(response).get("removed", False))

    # -- secret vault (write-only values) ----------------------------------------

    def vault_secrets_list(self) -> VaultSecretList:
        """Vault entries for this tenant — METADATA + fingerprint only, values
        are write-only (``GET /v1/admin/vault/secrets``). ``vault_enabled`` is
        False when the gateway has no vault master key configured."""
        payload = _json_object(self._request("GET", "/v1/admin/vault/secrets"))
        return VaultSecretList.from_wire(payload)

    def vault_secrets_put(
        self,
        secret_id: str,
        vendor: str,
        material: Mapping[str, str],
        description: str = "",
    ) -> VaultSecret:
        """
        Store/rotate one broker credential (``PUT /v1/admin/vault/secrets``) —
        the ONLY request in the whole API that carries a secret value.
        ``material`` is a flat map of bounded strings (e.g. ``access_key_id`` /
        ``secret_access_key``), encrypted at rest; NO endpoint ever returns it.
        The response is the public view (metadata + keyed fingerprint).
        """
        response = self._request(
            "PUT",
            "/v1/admin/vault/secrets",
            json_body={
                "secret_id": secret_id,
                "vendor": vendor,
                "description": description,
                "material": dict(material),
            },
        )
        payload = _json_object(response)
        secret = payload.get("secret")
        return VaultSecret.from_wire(secret if isinstance(secret, dict) else {})

    def vault_secrets_delete(self, secret_id: str) -> bool:
        """Remove one vault entry (``POST
        /v1/admin/vault/secrets/{secret_id}/delete``). Returns whether an
        entry was removed."""
        response = self._request(
            "POST", f"/v1/admin/vault/secrets/{_segment(secret_id)}/delete"
        )
        return bool(_json_object(response).get("removed", False))


__all__ = ["MCPIPAdminClient"]
