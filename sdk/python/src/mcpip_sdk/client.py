"""
mcpip_sdk.client — the agent-side clients.

    ◐ "Authorize every AI action before execution."

:class:`MCPIPClient` speaks the gateway's agent surface: ``/v1/authorize`` (the
single choke point), ``/v1/catalog``, the ``/v1/mcp`` JSON-RPC 2.0 edge, and
the liveness/version/license reads. :class:`SandboxClient` adds the
SANDBOX-ONLY affordances (dev-token minting, the stand-in authenticator, audit
verify/proof) — every one of them answers 404 on a production gateway.

The step-up ceremony in three calls::

    staged = client.authorize("skill_payroll_run", {"run_id": "PR-7"})
    if isinstance(staged, Staged):
        pin = client.authenticator_code(staged.challenge_id)  # sandbox only;
        receipt = client.complete(staged, pin)                # prod: OTP arrives
                                                              # out-of-band

``complete`` resubmits the IDENTICAL envelope — the lock is payload-bound, so
any drift in arguments is an opaque deny (the lock survives a correct retry).
"""

from __future__ import annotations

import itertools
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import quote

import httpx

from mcpip_sdk import envelopes
from mcpip_sdk._transport import (
    DEFAULT_TIMEOUT,
    _BaseClient,
    _body_correlation,
    _correlation_of,
    _json_object,
)
from mcpip_sdk.errors import (
    MCPIPDenied,
    MCPIPError,
    MCPIPInvalidRequest,
    MCPIPNotFound,
    MCPIPSandboxOnly,
)
from mcpip_sdk.models import (
    Allowed,
    AuditAttestation,
    AuditVerifyResult,
    AuthorizeEnvelope,
    AuthzenDecision,
    CatalogItem,
    Health,
    InclusionProof,
    LicenseInfo,
    ProtectedResourceMetadata,
    Readiness,
    Staged,
    VersionInfo,
)
from mcpip_sdk.tokens import TokenProvider

# JSON-RPC methods that carry the Bearer JWT on the /v1/mcp edge. ``initialize``
# and ``notifications/initialized`` are unauthenticated there by contract.
_MCP_AUTHED_METHODS = frozenset({"tools/list", "tools/call"})


class MCPIPClient(_BaseClient):
    """
    Agent-side client for one MCPIP gateway.

    Identity is a verified JWT: pass ``token`` as a literal string (production:
    minted and rotated by YOUR IdP — the gateway only verifies) or a zero-arg
    callable returning one (invoked lazily, cached, refreshed ~30 seconds
    before its ``exp``). The SDK NEVER retries a request: denials are opaque
    (expiry and policy are indistinguishable on the wire) and a retried
    step-up consume is a real audit event.

    This class does NOT mint tokens — it only presents one you supply. There is
    no ``dev_token`` here: sandbox token minting lives on the
    :class:`SandboxClient` subclass (``POST /v1/dev/token`` exists only under
    ``MCPIP_SANDBOX_MODE=true``). So "import a client and mint a token" means
    :class:`SandboxClient`, not ``MCPIPClient``.

    TOKEN LIFETIME — a static token EXPIRES (a sandbox dev-token lives only
    ~5 minutes) and then denies OPAQUELY: an expired token is indistinguishable
    from a policy deny on the wire. For anything longer than a one-shot call,
    pass ``token`` as a zero-arg CALLABLE (auto-refreshed ~30s before ``exp``)
    rather than a literal string — see the constructor below.

    Use as a context manager or call :meth:`close` when done.
    """

    def __init__(
        self,
        base_url: str,
        token: TokenProvider | None = None,
        *,
        timeout: httpx.Timeout | float = DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """
        ``token`` is a bearer SOURCE, not a minter — one of:

        * a literal JWT string, used verbatim and NEVER refreshed. A static
          sandbox dev-token expires in ~5 minutes, after which every call is an
          OPAQUE deny (looks identical to a policy deny — there is no "token
          expired" signal on the wire);
        * a zero-arg callable returning a fresh JWT — invoked lazily, cached,
          and auto-refreshed ~30s before its ``exp``. This is the fix for
          expiry; use it for any long-running session;
        * ``None`` — no Authorization header is sent.

        This client cannot MINT a token. To mint a sandbox dev-token use
        :meth:`SandboxClient.dev_token`, and wrap it in a callable so it
        auto-refreshes::

            client = SandboxClient(base_url)
            client.set_token(lambda: client.dev_token(agent_id="agent-x"))
        """
        super().__init__(base_url, token, timeout=timeout, transport=transport)
        self._jsonrpc_ids: Iterator[int] = itertools.count(1)

    # -- /v1/authorize -------------------------------------------------------

    def authorize(
        self,
        alias: str | None = None,
        arguments: Mapping[str, Any] | None = None,
        *,
        source_format: str | None = None,
        vendor: str | None = None,
        tool_call: Mapping[str, Any] | None = None,
        pin: str | None = None,
        challenge_id: str | None = None,
    ) -> Allowed | Staged:
        """
        Authorize exactly ONE tool call through the gateway's choke point.

        Two calling styles:

        * ``authorize(alias, arguments)`` — the SDK builds the envelope
          (default ``source_format="raw_mcp"``; pass any of the six formats to
          exercise a specific provider dialect).
        * ``authorize(tool_call=..., source_format=...)`` or
          ``authorize(tool_call=..., vendor=...)`` — a raw provider envelope
          is sent verbatim (exactly one of source_format/vendor, mirroring the
          wire contract).

        Returns :class:`Allowed` (HTTP 200 — executed, receipt fields include
        the ``correlation_id`` audit handle) or :class:`Staged` (HTTP 202 — a
        ``pin_required`` alias staged a payload-bound lock; finish with
        :meth:`complete`).

        Raises :class:`MCPIPDenied` on any policy deny. The denial is OPAQUE
        BY DESIGN: it carries only a ``correlation_id`` — no reason ever
        crosses the agent boundary (the concrete cause lives in the gateway's
        WORM audit log, resolvable by an operator). Never retry a deny.
        """
        if (pin is None) != (challenge_id is None):
            raise ValueError("pin and challenge_id must be supplied together")
        if tool_call is None:
            if alias is None:
                raise ValueError("alias is required when tool_call is not supplied")
            if vendor is not None:
                raise ValueError(
                    "vendor declarations require an explicit tool_call — the SDK "
                    "builds envelopes by source_format only"
                )
            declared = source_format if source_format is not None else envelopes.RAW_MCP
            envelope = AuthorizeEnvelope(
                tool_call=envelopes.build(declared, alias, arguments or {}),
                source_format=declared,
            )
        else:
            if alias is not None or arguments is not None:
                raise ValueError(
                    "pass either (alias, arguments) or a prebuilt tool_call, not both"
                )
            if (source_format is None) == (vendor is None):
                raise ValueError(
                    "exactly one of source_format / vendor must accompany tool_call"
                )
            envelope = AuthorizeEnvelope(
                tool_call=dict(tool_call), source_format=source_format, vendor=vendor
            )
        return self._authorize(envelope, pin=pin, challenge_id=challenge_id)

    def complete(self, staged: Staged, pin: str) -> Allowed:
        """
        Finish a staged step-up: resubmit the IDENTICAL envelope plus the
        one-time code and the challenge id from the 202.

        The lock is bound to (tenant, agent, alias, arguments) — the token may
        have rotated in between (same principal), but any argument drift is an
        opaque deny (the lock survives for a correct retry, until its
        ``expires_in`` elapses or :data:`~mcpip_sdk.models.PIN_MAX_ATTEMPTS`
        wrong PINs destroy it). A spent challenge can never be replayed.
        """
        outcome = self._authorize(
            staged.envelope, pin=pin, challenge_id=staged.challenge_id
        )
        if isinstance(outcome, Staged):
            # A conforming gateway treats pin+challenge_id as a consume; a 202
            # here means something is off — fail loud rather than loop.
            raise MCPIPError("gateway re-staged a step-up completion")
        return outcome

    def _authorize(
        self,
        envelope: AuthorizeEnvelope,
        *,
        pin: str | None,
        challenge_id: str | None,
    ) -> Allowed | Staged:
        body = envelope.body()
        if pin is not None and challenge_id is not None:
            body["pin"] = pin
            body["challenge_id"] = challenge_id
        response = self._request("POST", "/v1/authorize", json_body=body)
        payload = _json_object(response)
        if response.status_code == 202:
            return Staged.from_wire(payload, envelope)
        return Allowed.from_wire(payload)

    # -- /v1/mcp (JSON-RPC 2.0) ----------------------------------------------

    def mcp_call(self, method: str, params: Mapping[str, Any] | None = None) -> Any:
        """
        Speak real JSON-RPC 2.0 to the gateway's ``/v1/mcp`` edge (one request
        object per POST — Streamable-HTTP single-request mode) and return the
        JSON-RPC ``result`` member.

        * ``initialize`` / ``notifications/initialized`` go unauthenticated
          (per the edge contract); ``tools/list`` / ``tools/call`` carry the
          Bearer. Notifications return None (the gateway answers 202, empty).
        * A policy deny arrives as JSON-RPC error ``-32000`` inside an HTTP
          200 — raised as :class:`MCPIPDenied` with the ``data.correlation_id``.
        * A staged step-up on this edge is a RESULT with ``isError: true``
          whose text payload carries the ``challenge_id``; completion is done
          via ``authorize(tool_call=<the same JSON-RPC dict>,
          source_format="mcp_jsonrpc", pin=..., challenge_id=...)`` — the lock
          is format-independent.
        """
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if not method.startswith("notifications/"):
            body["id"] = next(self._jsonrpc_ids)
        if params is not None:
            body["params"] = dict(params)
        response = self._request(
            "POST",
            "/v1/mcp",
            json_body=body,
            authenticated=method in _MCP_AUTHED_METHODS,
        )
        if response.status_code == 202 or not response.content:
            return None  # notification acknowledged — no JSON-RPC response object.
        payload = _json_object(response)
        error = payload.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            data = error.get("data")
            correlation = ""
            if isinstance(data, dict):
                corr_value = data.get("correlation_id")
                if isinstance(corr_value, str):
                    correlation = corr_value
            if code == -32000:
                # The MCP-edge deny: same opacity as the REST 403 (HTTP is 200).
                raise MCPIPDenied(
                    correlation or _correlation_of(response),
                    http_status=response.status_code,
                )
            raise MCPIPInvalidRequest(
                f"JSON-RPC error {code}: {error.get('message')!r}",
                correlation_id=correlation or None,
            )
        return payload.get("result")

    # -- reads ----------------------------------------------------------------

    def catalog(self) -> list[CatalogItem]:
        """The skills THIS identity may see — metadata only, never targets.
        An empty list means this identity enumerates nothing (a real answer,
        distinct from a failure, which raises)."""
        response = self._request("GET", "/v1/catalog")
        payload = _json_object(response)
        items = payload.get("catalog")
        if not isinstance(items, list):
            return []
        return [CatalogItem.from_wire(item) for item in items if isinstance(item, dict)]

    # -- standards interop (AuthZEN decision · OAuth 2.1 RS metadata) ---------

    def authz_decision(
        self,
        alias: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        subject: Mapping[str, Any] | None = None,
        context: Mapping[str, Any] | None = None,
        action_name: str | None = None,
    ) -> AuthzenDecision:
        """
        Ask the gateway for a PRE-EXECUTION authorization verdict on a
        hypothetical call — ``POST /v1/authz/decision``, the OpenID-AuthZEN /
        COAZ decision surface (MCPIP as a PDP). DECISION-ONLY: nothing executes,
        vends, stages/consumes a PIN, or mutates a grant.

        The AuthZEN ``resource.id`` is the opaque ``alias`` and ``action.properties``
        the ``arguments`` (deep-validated by the SAME bridge walker as a real call —
        an identity-shaped key is a hard deny). ``subject`` is advisory/echo ONLY and
        is NEVER consulted for identity: identity comes solely from the Bearer JWT this
        client presents, so it cannot be injected through the subject.

        Returns an :class:`~mcpip_sdk.models.AuthzenDecision`. A permit is
        ``decision=True`` optionally carrying standards-shaped ``obligations``
        (``mcpip.step_up.pin`` for a PIN_REQUIRED tier, ``mcpip.sender_constraint.dpop``
        for a sender-constrained resource); a deny is the bare opaque
        ``decision=False`` — no reason, target, or topology ever crosses the wire
        (the concrete cause lives only in the WORM log). A verdict is NOT an
        authorization to act — a subsequent :meth:`authorize` still runs the full
        pipeline (including the runtime velocity/amount controls a decision query
        deliberately does not evaluate).

        This endpoint is JWT-gated: an invalid/absent token is an opaque
        :class:`~mcpip_sdk.errors.MCPIPDenied`, distinct from a ``decision=False``.
        """
        body: dict[str, Any] = {
            "subject": dict(subject) if subject is not None else {},
            "resource": {"id": alias, "type": "mcpip.tool"},
            "action": {
                "name": action_name if action_name is not None else "invoke",
                "properties": dict(arguments or {}),
            },
        }
        if context is not None:
            body["context"] = dict(context)
        response = self._request("POST", "/v1/authz/decision", json_body=body)
        return AuthzenDecision.from_wire(_json_object(response))

    def protected_resource_metadata(self) -> ProtectedResourceMetadata:
        """
        ``GET /.well-known/oauth-protected-resource`` — the RFC 9728 OAuth 2.1
        Protected Resource Metadata document. PUBLIC and unauthenticated (no
        Bearer sent), never shed, available in sandbox AND production.

        A conformant MCP client reads this to discover MCPIP's own resource
        identifier and the authorization server(s) that issue tokens for it (RFC
        8707 audience binding), so it presents a token bound to THIS resource
        rather than talking to a look-alike endpoint. The document carries only
        non-secret discovery identifiers — no scopes (MCPIP has none), no secret,
        no alias→target topology.
        """
        response = self._request(
            "GET",
            "/.well-known/oauth-protected-resource",
            authenticated=False,
        )
        return ProtectedResourceMetadata.from_wire(_json_object(response))

    def health(self) -> Health:
        """``GET /healthz`` — liveness, unauthenticated, never shed. The SDK's
        connectivity probe."""
        response = self._request("GET", "/healthz", authenticated=False)
        return Health.from_wire(_json_object(response))

    def ready(self) -> Readiness:
        """``GET /readyz`` — readiness gated on Redis. A 503 is an HONEST
        not-ready answer (``ready=False``), not an exception."""
        response = self._request(
            "GET", "/readyz", authenticated=False, tolerate=(503,)
        )
        return Readiness.from_wire(_json_object(response), response.status_code)

    def version(self) -> VersionInfo:
        """``GET /v1/version`` — running release + signed provenance + update
        posture (JWT-gated; the gateway never self-updates: policy is redeploy)."""
        response = self._request("GET", "/v1/version")
        return VersionInfo.from_wire(_json_object(response))

    def license(self) -> LicenseInfo:
        """``GET /v1/license`` — the boot-verified entitlement view (JWT-gated;
        sandbox gateways answer ``licensed=False`` and nothing else)."""
        response = self._request("GET", "/v1/license")
        return LicenseInfo.from_wire(_json_object(response))

    def audit_attestation(self) -> AuditAttestation:
        """
        ``GET /v1/audit/attestation`` — a portable, signed snapshot of the
        CURRENT audit state (``CAP_DIRECTORY_ADMIN``-gated, READ-ONLY).

        Unlike the sandbox-only :meth:`SandboxClient.audit_verify` /
        :meth:`SandboxClient.audit_proof`, this is available in PRODUCTION — a
        portable, externally-checkable attestation is a production artifact.
        It requires ``CAP_DIRECTORY_ADMIN`` (the caller's JWT must carry it): the
        attestation commits to the GLOBAL, cross-tenant WORM head, so it is not
        readable by a plain agent token. Returns the latest SEALED epoch header, the WORM
        epoch key's public ``signing_key_id``, a FRESH chain-verify result, and
        the anchor low-watermark; the epoch fields are ``None`` before the first
        epoch is sealed. The endpoint mints no key and signs nothing new — it only
        discloses already-signed commitments, so no target, payload, or secret
        crosses the wire.
        """
        response = self._request("GET", "/v1/audit/attestation")
        return AuditAttestation.from_wire(_json_object(response))


class SandboxClient(MCPIPClient):
    """
    :class:`MCPIPClient` plus the gateway's SANDBOX-ONLY affordances.

    Every extra method here targets an endpoint that EXISTS ONLY when the
    gateway runs with ``MCPIP_SANDBOX_MODE=true``. Against production, each
    answers 404 by design (identity stays IdP-sovereign; step-up codes arrive
    only out-of-band; audit is verified by external tooling) and the SDK
    raises :class:`MCPIPSandboxOnly`. Do not ship agents that depend on these.
    """

    def dev_token(
        self,
        tenant_id: str = "tenant-acme",
        agent_id: str = "agent-orchestrator-1",
        role: str = "ops",
        *,
        compartment: str | None = None,
        capabilities: Sequence[str] | None = None,
        session_id: str | None = None,
    ) -> str:
        """
        SANDBOX ONLY — mint a valid EdDSA JWT from the in-process demo IdP
        (``POST /v1/dev/token``, unauthenticated). Tokens expire after ~5
        minutes; pair with a callable provider for long-running sessions::

            client.set_token(lambda: client.dev_token(agent_id="agent-x"))

        ``capabilities`` takes UUID claims (e.g.
        :data:`~mcpip_sdk.models.CAP_DIRECTORY_ADMIN` for an admin token);
        ``compartment`` scopes the principal to one compartment UUID. Raises
        :class:`MCPIPSandboxOnly` on production gateways (404 there).
        """
        body: dict[str, Any] = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "role": role,
        }
        if compartment is not None:
            body["compartment"] = compartment
        if capabilities is not None:
            body["capabilities"] = list(capabilities)
        if session_id is not None:
            body["session_id"] = session_id
        response = self._request(
            "POST", "/v1/dev/token", json_body=body, authenticated=False,
            tolerate=(404,),
        )
        if response.status_code == 404:
            raise MCPIPSandboxOnly("/v1/dev/token")
        payload = _json_object(response)
        token = payload.get("jwt")
        if isinstance(token, str) and token:
            return token
        legacy = payload.get("token")  # older gateways used {"token": ...}.
        if isinstance(legacy, str) and legacy:
            return legacy
        raise MCPIPError("dev-token response carried no jwt")

    def capabilities(self) -> dict[str, str]:
        """
        SANDBOX ONLY — the well-known capability UUIDs by name
        (``GET /v1/dev/capabilities``, unauthenticated).

        Privileged actions gate on capability UUIDs in the JWT ``capabilities``
        claim, never on a role string, so minting an admin token means knowing
        the UUID. This is how you learn it without reading ``interfaces.py``::

            caps = client.capabilities()
            token = client.dev_token(capabilities=[caps["CAP_DIRECTORY_ADMIN"]])

        Production mints no identity, so there is nothing to enumerate: raises
        :class:`MCPIPSandboxOnly` there (404).
        """
        response = self._request(
            "GET", "/v1/dev/capabilities", authenticated=False, tolerate=(404,)
        )
        if response.status_code == 404:
            raise MCPIPSandboxOnly("/v1/dev/capabilities")
        payload = _json_object(response)
        caps = payload.get("capabilities")
        if not isinstance(caps, dict):
            raise MCPIPError("dev-capabilities response carried no capabilities map")
        return {str(k): str(v) for k, v in caps.items()}

    def authenticator_code(self, challenge_id: str) -> str:
        """
        SANDBOX ONLY — fetch the one-time step-up code for a staged challenge
        (``GET /v1/authenticator/{challenge_id}``, Bearer-gated: the OTP is
        tenant-scoped to the verified identity). This endpoint stands in for
        the ENROLLED AUTHENTICATOR DEVICE; in production it 404s and the code
        reaches the approver out-of-band — model production OTP acquisition as
        your own callback, with this method as the sandbox default.

        Raises :class:`MCPIPNotFound` when the challenge is unknown/expired
        and :class:`MCPIPSandboxOnly` when the endpoint does not exist.
        """
        response = self._request(
            "GET",
            f"/v1/authenticator/{quote(challenge_id, safe='')}",
            tolerate=(404,),
        )
        if response.status_code == 404:
            correlation = _body_correlation(response)
            if correlation is not None:
                raise MCPIPNotFound(
                    "challenge unknown or expired", correlation_id=correlation
                )
            raise MCPIPSandboxOnly("/v1/authenticator/{challenge_id}")
        payload = _json_object(response)
        otp = payload.get("otp")
        if isinstance(otp, str) and otp:
            return otp
        raise MCPIPError("authenticator response carried no otp")

    def audit_verify(self) -> AuditVerifyResult:
        """
        SANDBOX ONLY — force an epoch close, then verify the signed
        Merkle-epoch WORM chain (``GET /v1/audit/verify``, Bearer-gated).
        Production gateways 404 here: the authoritative check runs out-of-band
        (``mcpip export-audit`` + external verifier), never on the agent edge.
        """
        response = self._request("GET", "/v1/audit/verify", tolerate=(404,))
        if response.status_code == 404:
            raise MCPIPSandboxOnly("/v1/audit/verify")
        return AuditVerifyResult.from_wire(_json_object(response))

    def audit_proof(self, event_id: str) -> InclusionProof:
        """
        SANDBOX ONLY — the O(log n) Merkle inclusion proof for one WORM event
        (``GET /v1/audit/proof/{event_id}``, Bearer-gated). ``event_id`` comes
        from the admin decisions feed. Raises :class:`MCPIPNotFound` when the
        event is unknown or not yet sealed into a signed epoch (run
        :meth:`audit_verify` first to force a seal), :class:`MCPIPSandboxOnly`
        on production gateways.
        """
        response = self._request(
            "GET", f"/v1/audit/proof/{quote(event_id, safe='')}", tolerate=(404,)
        )
        if response.status_code == 404:
            correlation = _body_correlation(response)
            if correlation is not None:
                raise MCPIPNotFound(
                    "event unknown or not yet sealed", correlation_id=correlation
                )
            raise MCPIPSandboxOnly("/v1/audit/proof/{event_id}")
        return InclusionProof.from_wire(_json_object(response))


__all__ = ["MCPIPClient", "SandboxClient"]
