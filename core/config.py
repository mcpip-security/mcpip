"""
MCPIP V2 — Core: typed, environment-driven configuration.

    ◐ "Authorize every AI action before execution."

A single ``Settings`` object (pydantic-settings ``BaseSettings``) is the sole source
of runtime configuration for the FastAPI gateway. Every field is env-prefixed
``MCPIP_`` so the same object drives local dev (defaults point at the host-published
Redis on 63790), the Docker image, and Compose (which points ``MCPIP_REDIS_URL`` at
the internal ``redis:6379``).

Two switches decide whether the process boots against real key material or the
sandbox stand-ins:

  * ``jwt_public_key_path``     — PEM of the trusted IdP's public key. When ``None``
                                  *and* ``sandbox_mode`` is True the composition root
                                  boots the reused in-process ``_DemoIdP`` instead.
  * ``worm_signing_key_path``   — Ed25519 PKCS8 PEM used to sign the WORM chain. When
                                  ``None`` *and* ``sandbox_mode`` is True an ephemeral
                                  key is generated at startup.

``sandbox_mode=False`` with either key path missing is a fail-closed boot error: the
composition root refuses to start rather than silently minting throwaway identity /
audit keys in what is claimed to be production. That policy is enforced in
``app.main`` (this module only *carries* the flags); keeping the decision beside the
place that reads the PEMs keeps the failure obvious at boot.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from interfaces import PIN_TTL_SECONDS


class Settings(BaseSettings):
    """
    Immutable-by-convention runtime settings, populated from ``MCPIP_*`` env vars.

    ``extra="ignore"`` means unrelated environment variables never make the process
    fail to start; ``env_file=None`` keeps configuration explicit (no implicit
    ``.env`` discovery) so a stray dotfile can never alter security-relevant flags.
    """

    model_config = SettingsConfigDict(
        env_prefix="MCPIP_",
        env_file=None,
        extra="ignore",
    )

    # --- Redis (all synchronization state lives here; nodes stay stateless). ----
    # Default targets the host-published dev container (63790 -> 6379). In Compose
    # this is overridden to redis://redis:6379/0 on the internal network.
    redis_url: str = Field(default="redis://localhost:63790/0")
    # BOUNDED, BLOCKING pool sizing. The pool blocks (up to redis_pool_timeout_s) for a
    # free connection under burst instead of RAISING 'Too many connections' — a transient
    # Redis latency excursion then QUEUES rather than fail-closing legitimate authorizes.
    # Each worker holds its own pool, so size per-worker against the shared Redis maxclients.
    redis_max_connections: int = Field(default=64, ge=1)
    redis_pool_timeout_s: float = Field(default=5.0, ge=0.0)

    # --- JWT identity sovereignty. ----------------------------------------------
    jwt_issuer: str = Field(default="mcpip-demo-idp")
    jwt_audience: str = Field(default="mcpip-gateway")
    # PEM public key of the trusted IdP. None + sandbox_mode -> reuse _DemoIdP.
    jwt_public_key_path: str | None = Field(default=None)

    # --- Attenuated session delegation (docs/SESSION_DELEGATION_DESIGN.md). ------
    # Default OFF. When off, /v1/delegate does not exist (404) and any token
    # carrying a delegation_id claim is denied DELEGATION_INVALID — fail-closed,
    # because ignoring the claim would grant MORE than the token was minted for.
    delegation_enabled: bool = Field(default=False)

    # --- WORM audit sink. -------------------------------------------------------
    worm_path: str = Field(default="./mcpip_worm.jsonl")
    # Ed25519 PKCS8 PEM used to sign the chain. None + sandbox_mode -> ephemeral.
    worm_signing_key_path: str | None = Field(default=None)
    # Out-of-tamper-domain signed head anchor. An fsync'd, append-only file that MUST
    # live on durable storage the Redis attacker cannot rewrite (a mounted volume, NOT
    # the same store as the epoch headers). None -> derived as ``worm_path + '.anchor'``.
    # verify_chain uses it as a monotonic low-watermark so a tail-truncation / rollback
    # that also rewrites the in-Redis linkage counters is still detected.
    worm_anchor_path: str | None = Field(default=None)
    # Opt-in synchronous-replication quorum for the WORM event emit (HA without losing
    # the durability contract). 0 (default) = no WAIT, byte-identical single-node
    # behavior. N>0 = every emitted audit event must ALSO be acknowledged by N Redis
    # replicas (``WAIT N timeout``) before the authorize proceeds — write-before-execute
    # extended across a replica, so promoting a synced replica after a master loss never
    # drops an acked record. FAIL-CLOSED: quorum miss/timeout = the emit fails = the
    # request denies. This is the supported HA posture (run Redis with >=N synced
    # replicas + a promotion runbook, docs/operate/OPERATIONS.md §"Availability"); plain async
    # replication WITHOUT this quorum can silently lose acked writes on failover and is
    # NOT a supported durability posture. Scope is the event emit only — every other
    # Redis datum fails closed when lost.
    worm_wait_replicas: int = Field(default=0, ge=0)
    # WAIT quorum timeout per emit, in milliseconds.
    worm_wait_timeout_ms: int = Field(default=2000, gt=0)
    # Opt-in at-rest CONFIDENTIALITY for the WORM event body (OFF by default). The chain
    # is always INTEGRITY-protected (Merkle/Ed25519), but the event body — the resolved
    # real target, alias, and identifiers — is otherwise cleartext in Redis + AOF. With
    # this enabled the sensitive payload is AES-256-GCM-wrapped before it is stored; the
    # signed leaf hashes the stored (encrypted) record, so ``verify_chain`` is UNAFFECTED
    # and the chain stays verifiable WITHOUT the key — only READING a body needs it, and
    # destroying the key crypto-shreds the bodies while the integrity proof survives.
    # Default OFF ⇒ plaintext bodies, byte-identical to today. When ON a dedicated key is
    # required — ``MCPIP_WORM_CONTENT_KEY_PATH`` (32 raw bytes) in production; auto-
    # provisioned under ``.keys/`` in sandbox. Flag-on/key-off in production is a
    # fail-closed BOOT error.
    encrypt_worm_at_rest: bool = Field(default=False)
    worm_content_key_path: str | None = Field(default=None)
    # RETIRED content keys retained across a rotation, so bodies sealed under a superseded
    # key stay readable after the active key rotates (the active ``worm_content_key_path``
    # always seals new events; every key here plus the active one is tried on READ). An
    # ``os.pathsep``-separated list of 32-byte key files. Empty ⇒ no rotation history, the
    # single-key behavior. Rotating without listing the prior key here leaves its bodies
    # unreadable — retain retired keys for the audit-retention window (destroying one
    # crypto-shreds every body it sealed).
    worm_content_key_fallback_paths: str | None = Field(default=None)

    # --- Environment secret vault (OPTIONAL operator broker-credential store). ----
    # Raw 32-byte AES-256 master key file encrypting vault entries at rest (Redis holds
    # ciphertext only). None + sandbox_mode -> a persistent dev key is auto-provisioned
    # under .keys/. None in production -> the vault feature is ABSENT (any binding that
    # references it fails closed); it is never silently downgraded to plaintext.
    vault_key_path: str | None = Field(default=None)

    # --- Forensic payload capture (OPTIONAL admin/investigator side-channel). -----
    # Reconstructs the REAL query an agent sent (alias + normalized arguments +
    # non-secret identity context) for a given correlation_id, closing the gap left by
    # the deliberately opaque agent wire. Tri-state: None (unset) resolves per-env at
    # the composition root — ON in sandbox (full debugging visibility), OFF in
    # production (the fail-safe default). An explicit true/false ALWAYS wins. Turning
    # it on in production additionally REQUIRES a real ``forensic_key_path`` — the flag
    # alone is not enough; without the key the feature is ABSENT (fail-closed, never
    # plaintext). CAPTURE breadth is all this controls; RETRIEVAL is always
    # CAP_FORENSIC_READ-gated + WORM-audited regardless of env.
    forensic_capture: bool | None = Field(default=None)
    # Raw 32-byte AES-256 master key file encrypting forensic captures at rest (Redis
    # holds ciphertext only), DEDICATED to forensics — never the vault or WORM key.
    # None + sandbox -> a persistent dev key auto-provisions under .keys/. None in
    # production -> the forensic feature is ABSENT even if the flag is on (any capture
    # is dropped, retrieval 404s); it is never silently downgraded to plaintext.
    forensic_key_path: str | None = Field(default=None)

    # --- Opt-in principal pseudonymization (OFF by default). --------------------
    # When enabled, the delegation-actor identifiers recorded to the permanent WORM
    # ledger — ``act_sub`` and each ``delegation_chain`` entry (RFC 8693 actors that can
    # name a natural person) — are replaced with a keyed-HMAC pseudonym, so the
    # natural-person link becomes CRYPTO-SHREDDABLE (destroy the key ⇒ sever linkage)
    # while the signed audit record stays intact and ``verify_chain``-able. This is the
    # reconciliation of the immutable ledger with GDPR/CCPA erasure (docs/operate/COMPLIANCE.md
    # §2.1). Default OFF ⇒ byte-identical to today: the raw identifiers are recorded
    # (better forensic readability), so enable it only when an erasure posture is needed.
    # When ON a dedicated key is required — ``MCPIP_PSEUDONYM_KEY_PATH`` (≥32 raw bytes)
    # in production; auto-provisioned under ``.keys/`` in sandbox. Flag-on/key-off in
    # production is a fail-closed BOOT error (never a silent disable of the control).
    pseudonymize_principals: bool = Field(default=False)
    pseudonym_key_path: str | None = Field(default=None)

    # --- Out-of-band authenticator delivery (step-up OTP push). -------------------
    # In production the payload-bound step-up code is NOT stashed in Redis; it is PUSHED
    # to a tenant-configured authenticator/approver sink over an SSRF-guarded,
    # HMAC-SHA256-signed HTTPS webhook. BOTH the URL and the signing-secret path are
    # required to activate the channel: with either unset in production the delivery
    # channel is ABSENT and every PIN_REQUIRED staging fails closed
    # (``OTP_DELIVERY_FAILED``) rather than staging a challenge no authenticator can
    # answer. Sandbox ignores these (it uses the Redis stash + peek demo channel). A URL
    # set without a secret (or a wrong-size secret) is a fail-closed BOOT error — the
    # same posture as the vault/forensic key loaders. The URL must be https and its host
    # must not resolve into a private/loopback/link-local/reserved range (enforced at
    # delivery time, connection pinned to the validated IP to defeat DNS-rebinding).
    authn_webhook_url: str | None = Field(default=None)
    # Path to the raw HMAC-SHA256 signing secret (>=32 bytes) used to sign each pushed
    # notice (``X-MCPIP-Signature``). Loaded as raw bytes; never logged, never a metric
    # label, never in the notice body. None in production -> the channel is ABSENT.
    authn_webhook_secret_path: str | None = Field(default=None)
    # Bounded connect+read wall-clock ceiling for one webhook push (clamped to
    # [MIN_AUTHN_WEBHOOK_TIMEOUT_S, MAX_AUTHN_WEBHOOK_TIMEOUT_S] at construction).
    authn_webhook_timeout_s: float = Field(default=5.0, gt=0.0)
    # Path to the 32-byte AES-256 master key for USER-BASED 2FA (per-principal TOTP
    # enrollment secrets + the TOTP-gated encrypted OTP stash). Presence activates the
    # feature: principals can enroll an authenticator app, and step-up codes become
    # revealable only against a verified, fresh, un-replayed TOTP. None in production
    # -> the enrollment surface is ABSENT (fail-closed; the webhook channel, if
    # configured, still works). Sandbox auto-provisions a persistent dev key.
    authn_totp_key_path: str | None = Field(default=None)

    # --- Payload-lock policy. ---------------------------------------------------
    # Exposed for operators; the engine's own PIN_TTL_SECONDS remains authoritative
    # for the Redis TTL, so this defaults to it and never silently diverges.
    lock_ttl_seconds: int = Field(default=PIN_TTL_SECONDS)

    # --- Deployment posture. ----------------------------------------------------
    # SECURE-BY-DEFAULT (False): the process demands real PEMs, fails CLOSED at boot if
    # they are missing, and refuses to expose ANY sandbox affordance. Sandbox mode —
    # which mounts the /v1/dev/token identity-forge oracle, the /v1/authenticator OTP
    # disclosure, and the in-process IdP / ephemeral WORM key — must be opted into
    # EXPLICITLY with MCPIP_SANDBOX_MODE=true. Defaulting this open would make a
    # bare/misconfigured deployment a complete authorization bypass (self-mint any
    # tenant/compartment/capability), so the default is fail-closed.
    sandbox_mode: bool = Field(default=False)

    # --- Verified boot: startup integrity self-check (fail-closed). --------------
    # Signed integrity manifest (release/integrity_manifest.json) + the release-root
    # PUBLIC key that signed it. In production (sandbox_mode=False) BOTH are required
    # and the check must pass, or the process refuses to start. In sandbox the check
    # runs iff the manifest path is set (still fail-closed on mismatch).
    integrity_manifest_path: str | None = Field(default=None)
    integrity_public_key_path: str | None = Field(default=None)
    # DEV-ONLY escape hatch: skips the integrity self-check with a loud stderr
    # banner. NEVER set in production — the Dockerfile, Helm chart, and k8s
    # manifests deliberately do not expose it.
    integrity_dev_bypass: bool = Field(default=False)

    # --- License / entitlement gate (offline Ed25519-signed, fail-closed). -------
    # License JSON (signed by the SEPARATE license-root key) + its PUBLIC key. In
    # production BOTH are required and the license must verify or boot fails
    # closed; sandbox skips unless both are set. Licensing gates process BOOT only
    # — it is never consulted by the per-request authorization pipeline.
    license_path: str | None = Field(default=None)
    license_public_key_path: str | None = Field(default=None)

    # --- Opt-in license REFRESH (OFF by default; OFF the hot path; fail-open). ----
    # Optional HTTPS endpoint the client may PULL a fresh signed license from, tying
    # entitlement to the same authenticated round-trip the telemetry beacon uses. It
    # is OPT-IN and additive: None (the default) => NO refresh, the boot-gate license
    # stays authoritative until its own expiry — byte-identical to today's air-gapped /
    # offline-signed-license behavior. A candidate is verified against the EXISTING
    # license-root Ed25519 key (``license_public_key_path``) with the SAME boot checks
    # (schema / signature / closed-tier / validity window) and only a fully-valid,
    # STRICTLY-NEWER license is atomically swapped in; ANY failure (network, signature,
    # expired, wrong root, not-newer) RETAINS the last-good license — it NEVER adds a
    # trust root, NEVER accepts a forged/unsigned license, NEVER fails open to
    # unlicensed, and NEVER bricks a running gateway. The refresh runs as a swallowed
    # off-hot-path background daemon (like the epoch-gauge / telemetry tasks); its
    # outcome can NEVER block, delay, reorder, or flip an authorization decision (the
    # license gates BOOT only and is never read per-request). The URL is dialed over a
    # HERMETIC (trust_env=False, proxy=None), SSRF-guarded, IP-pinned https client — the
    # same guard the authenticator webhook / JWKS refresher / telemetry beacon use. In
    # sandbox / air-gap (no boot license) the feature is simply absent. See
    # docs/operate/TELEMETRY.md.
    license_refresh_url: str | None = Field(default=None)
    # Background license-pull cadence in seconds (off the hot path). Default 1h.
    license_refresh_interval_s: float = Field(default=3600.0, gt=0.0)

    # --- Update feed (OPTIONAL, offline, no phone-home). ------------------------
    # Path to a signed ``latest.json`` naming the newest APPROVED release. The
    # operator's change-control pipeline drops the file in — the gateway NEVER
    # reaches out to a network to discover it. ``/v1/version`` reports the
    # advertised version ONLY when the release-root PUBLIC key
    # (``integrity_public_key_path``) is configured AND the file's Ed25519
    # signature verifies; an unverifiable update claim is ignored (fail-closed).
    # Unset -> the gateway reports no newer release (skew is then judged console-
    # side). MCPIP never auto-installs regardless: an upgrade is a signed redeploy.
    update_manifest_path: str | None = Field(default=None)

    # --- Admission control / load-shedding. -------------------------------------
    # Max concurrent in-flight /v1/authorize-class requests PER WORKER before new
    # arrivals are shed with an opaque 503+Retry-After. Bounds tail latency: excess
    # load fast-fails instead of queueing unboundedly. Sized so in-flight * per-req
    # Redis ops stays within redis_max_connections (64) headroom; default 64.
    max_in_flight: int = Field(default=64, ge=1)
    # Server-side per-request wall-clock ceiling (backstop for a stuck dependency).
    request_timeout_s: float = Field(default=15.0, gt=0.0)
    # Retry-After seconds advertised on a shed (503).
    shed_retry_after_s: int = Field(default=1, ge=0)

    # --- Operator-console CORS (browser plug-and-play). --------------------------
    # Comma-separated list of origins the OPERATOR CONSOLE may call this gateway
    # from (e.g. "https://console.corp.example,https://ops.corp.example"). CORS is
    # a BROWSER control: it gates the console's cross-origin fetches only — agent
    # traffic is server-to-server and never consults it, and every request is still
    # JWT-authorized regardless of origin. Fail-closed default: empty ⇒ NO CORS
    # headers are emitted in production (a cross-origin console is refused by the
    # browser). Sandbox mode allows any origin so the local plug-and-play
    # experience ("Test & Connect" from the Vite dev server) works out of the box.
    console_origins: str = Field(default="")

    # --- Multi-region observability (BEHAVIOR-NEUTRAL region tag). ----------------
    # An opaque operator-chosen label for the region/cell this gateway instance runs in
    # (e.g. "us-east-1", "eu-frankfurt", "gov-cloud"). It is PURELY an observability
    # annotation surfaced read-only on ``/healthz`` and ``/v1/version`` for console/SDK
    # display and log correlation. It changes NOTHING about routing, authorization, Redis
    # key derivation, or storage — every key is already tenant-prefixed, so region pinning
    # is an edge/deployment concern (one MCPIP + Redis stack per region), NOT a data-plane
    # behavior this process implements. See ``docs/operate/OPERATIONS.md``. It is deliberately
    # NEVER a metric label (a free-form operator string would break the closed-enum label
    # discipline in ``core/metrics.py``). None -> the tag is simply absent (honest
    # unset state); boot is byte-for-byte unchanged when it is not set.
    region: str | None = Field(default=None)

    # --- Outbound COAZ PEP mode (OPTIONAL external AuthZEN PDP; DEFAULT OFF). ------
    # When MCPIP acts as a COAZ Policy Enforcement Point it can consult an external
    # AuthZEN Policy Decision Point as one more DENY-ONLY term in the community-gate
    # deny chain (pipeline step 4c′). It is MONOTONIC: it can only ever ADD a deny,
    # never turn a DENY into an ALLOW, and it FAILS CLOSED to deny on any error
    # (transport / non-2xx / SSRF-blocked host / parse). BOTH the flag and the URL must
    # be set to activate it; either unset ⇒ the outbound PEP is ABSENT and the hot path
    # is byte-identical to today (the community gate stays the shipped NO-OP). The URL is
    # dialed over a HERMETIC (trust_env=False, proxy=None), SSRF-guarded, IP-pinned httpx
    # client (the same guard the authenticator webhook / JWKS refresher use). Composing it
    # does NOT register a community-gate ENGINE, so gate-manifest approval is NOT unlocked.
    external_pdp_enabled: bool = Field(default=False)
    external_pdp_url: str | None = Field(default=None)

    # --- Opt-in VENDOR telemetry beacon (OFF by default; NEVER on the hot path). ---
    # A best-effort, off-hot-path heartbeat that lets the ORG THAT SHIPS MCPIP (the
    # vendor) see which DEPLOYMENTS run it, enforce license tiers, and read live
    # aggregate numbers — WITHOUT surveilling the agent wire. It is OPT-IN and
    # PRIVACY-BY-DESIGN. The beacon body is a CLOSED set of ONLY: a random, once-generated,
    # persisted install-id (NOT derived from any tenant/customer/host identity), the license
    # tier/id (or "unlicensed"), the MCPIP version, a single integer CARDINALITY of distinct
    # governed agent identities, coarse decision totals (allow/deny/staged — the SAME
    # closed-enum as core/metrics.py), uptime, and a timestamp. It NEVER carries a tenant
    # id, agent id, alias, target, capability, correlation id, secret, payload, argument, or
    # any per-tenant breakdown — only aggregate integers ever leave the box (the same opacity
    # discipline as the metric labels). See docs/operate/TELEMETRY.md.
    #
    # AIR-GAP / OPT-IN: this flag DEFAULTS OFF. If it is unset/false OR the process is in
    # sandbox_mode, NO beacon task is ever scheduled and NO install-id/secret file is ever
    # minted — an air-gapped / offline deployment never phones home and never even creates a
    # telemetry identity. A half-configuration (enabled=True with no URL) is a fail-closed
    # BOOT error (the same posture as the authenticator-webhook half-config). The URL is
    # dialed over a HERMETIC (trust_env=False, proxy=None), SSRF-guarded, IP-pinned https
    # client; a send failure (network, air-gap, non-2xx) is caught and dropped to a metric —
    # it can NEVER block, delay, reorder, or flip an authorization decision.
    telemetry_enabled: bool = Field(default=False)
    # HTTPS endpoint of the vendor telemetry receiver. None -> the beacon is ABSENT even if
    # the flag were set (which is then a boot error). The receiver itself is out of scope for
    # this deployment — it is specced in docs/operate/TELEMETRY.md, not built here.
    telemetry_url: str | None = Field(default=None)
    # Beacon cadence in seconds, clamped to [MIN_TELEMETRY_INTERVAL_S,
    # MAX_TELEMETRY_INTERVAL_S] at beacon construction (default 1h).
    telemetry_interval_s: float = Field(default=3600.0, gt=0.0)

    # --- Deny-response playbook (opt-in deterministic automation loop). ----------
    # OFF by default. When enabled, an off-hot-path daemon tails the durable WORM buffer for
    # high-signal deny events and, per a deterministic policy, responds: freeze the offending
    # agent (quarantine) and alert operators (Slack/email). It reads already-committed audit
    # records and acts asynchronously — a response can NEVER block, delay, reorder, or flip an
    # authorization. ``enabled`` with NO action (auto-quarantine off AND no channel) is a
    # fail-closed BOOT error (a playbook that can do nothing is a misconfiguration, refused).
    response_enabled: bool = Field(default=False)
    # Poll cadence in seconds, clamped to [MIN_RESPONSE_INTERVAL_S, MAX_RESPONSE_INTERVAL_S].
    response_interval_s: float = Field(default=30.0, gt=0.0)
    # Freeze the offending (tenant, agent) via the quarantine store on a triggered response.
    response_auto_quarantine: bool = Field(default=True)
    # Denials of a (non-single-shot) trigger reason by ONE agent within RESPONSE_BURST_WINDOW_S
    # before a response fires. ``canary_tripped`` always fires on the first occurrence.
    response_burst_threshold: int = Field(default=5, ge=1)
    # Comma-separated subset of RESPONSE_TRIGGER_REASONS to act on. None -> the single-shot
    # default (``canary_tripped`` only). A member outside the closed allow-set is a boot error.
    response_trigger_reasons: str | None = Field(default=None)
    # Optional Slack (or Slack-compatible) incoming-webhook URL for alerts. https only.
    response_slack_webhook_url: str | None = Field(default=None)
    # Optional SMTP alert channel. host + from + to are all required together for email.
    response_email_host: str | None = Field(default=None)
    response_email_port: int = Field(default=587)
    response_email_from: str | None = Field(default=None)
    response_email_to: str | None = Field(default=None)  # comma-separated recipient list.
    response_email_user: str | None = Field(default=None)
    response_email_password: str | None = Field(default=None)

    # --- HTTP bind (informational; uvicorn is invoked with explicit host/port). -
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8080)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the process-wide ``Settings`` singleton.

    ``lru_cache`` makes this a lazily-built singleton: the environment is read once,
    at first access, and every subsequent caller (composition root, endpoints,
    tests) sees the identical frozen view — no per-request env re-parsing.
    """
    return Settings()
