"""
MCPIP V2 — Service: AuthEngine (identity + payload-lock orchestration).

    ◐ Auth: "A payload-bound PIN that's spent exactly once, or the action never runs."

``AuthEngine`` is a thin seam over two engine pillars:

  * ``TokenResolver`` — JWT -> frozen ``Identity`` (algorithm-pinned, claim-verified).
  * ``PinValidator``  — register / atomically consume the canonical payload lock.

It adds ONE piece of orchestration the engine deliberately leaves out: out-of-band
delivery of the one-time code. ``register_lock`` still mints the random OTP with
``secrets`` and still registers the payload-bound lock via ``PinValidator.register``
(scrypt / canonical_json / register / consume — and the Rust mirror — all UNCHANGED);
only the DELIVERY of the code lives behind a pluggable ``BaseAuthenticatorChannel``.
In sandbox the channel stashes the code in Redis for the demo authenticator endpoint;
in production the channel PUSHES it to the tenant's enrolled authenticator/approver and
the raw value is NEVER persisted. The OTP is NEVER returned in the 202 staging response
and NEVER logged (WORM redacts ``pin``/``token``/``otp`` keys regardless).

Delivery is fail-closed: with NO channel configured (production, unconfigured) or a
channel whose ``deliver`` raises, ``register_lock`` raises
``GatewayDeny(OTP_DELIVERY_FAILED)`` through the app's single funnel — no 202 /
challenge_id is produced, so the PIN_REQUIRED action cannot complete, honestly, rather
than staging a challenge no authenticator can ever answer.

Services stay thin:
  * ``verify_identity`` lets engine exceptions propagate — the app's single mapper
    (``map_engine_exception``) classifies them, so there is no duplicate mapping here.
  * ``consume_and_execute`` is the ONE place raw Lua lock codes exist, so it — and
    only it — translates them into ``GatewayDeny`` reasons.
"""

from __future__ import annotations

import secrets
from typing import Any, Final

import redis.asyncio as redis

from interfaces import (
    AuthenticatorNotice,
    BaseAuthenticatorChannel,
    DenyReason,
    Identity,
    PIN_LENGTH,
    PIN_TTL_SECONDS,
    RiskTier,
)
from obfuscator import AliasEntry
from auth import IdentityResolver, LockError, PinValidator
from core.security import GatewayDeny
from services.authn_channel import (
    FanoutAuthenticatorChannel,
    SandboxRedisAuthenticatorChannel,
)

# Per-identity step-up staging rate limit — a CHEAP fixed-window pre-check that runs
# BEFORE the memory-hard scrypt in register_lock, so a single valid-JWT holder cannot
# spam un-pinned PIN_REQUIRED requests to force unbounded scrypt work (finding: scrypt
# CPU+memory DoS amplifier). One atomic INCR+EXPIRE; over the cap → fail-closed deny with
# NO scrypt spent. Sized generously above any legitimate agent's staging cadence.
_STEPUP_RATE_MAX: Final[int] = 60
_STEPUP_RATE_WINDOW_S: Final[int] = 60
# Per-identity PIN-COMPLETION (consume) rate limit — the SAME cheap fixed-window guard,
# but on the consume path. ``PinValidator.consume`` derives the memory-hard scrypt PIN
# hash BEFORE the atomic Lua even checks whether the challenge exists, so a completion
# FLOOD (bogus challenge_id / bogus PIN) is an unthrottled scrypt CPU+RAM amplifier — the
# register-side self-destruct/attempt budget guards only a REAL challenge, not this flood.
# This throttle runs before any scrypt in consume_and_execute so a completion flood from
# one identity fails closed with O(1) Redis work and ZERO derivation. A DISTINCT key from
# staging so a normal stage→complete pair never contends against the staging budget.
_CONSUME_RATE_MAX: Final[int] = 60
_CONSUME_RATE_WINDOW_S: Final[int] = 60
# INCR the window counter and, on the first hit, atomically arm its TTL so a crashed
# process can never leave a counter without expiry (which would wedge an identity).
_RATE_LIMIT_LUA: Final[str] = (
    "local c = redis.call('INCR', KEYS[1]) "
    "if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end "
    "return c"
)


class AuthEngine:
    """Identity verification + payload-lock lifecycle, over the engine pillars."""

    def __init__(
        self,
        resolver: IdentityResolver,
        pin: PinValidator,
        redis_client: "redis.Redis",
        channel: BaseAuthenticatorChannel | None,
    ) -> None:
        self._resolver = resolver
        self._pin = pin
        self._redis = redis_client
        # Out-of-band OTP DELIVERY channel. Sandbox wires a Redis stash+peek stand-in;
        # production wires a signed HTTPS push (or None when unconfigured). A None
        # channel makes register_lock fail closed — no code can be delivered, so no
        # challenge is staged. The channel NEVER touches how the OTP is derived/bound.
        self._channel = channel
        # Cached rate-limit script (uploaded once; EVALSHA thereafter).
        self._rate_script = redis_client.register_script(_RATE_LIMIT_LUA)

    # ------------------------------------------------------------------ identity

    def verify_identity(self, token: str) -> Identity:
        """
        Resolve a JWT into a sovereign ``Identity``.

        Raises ``TokenError`` / ``TokenClaimsMissing`` on any verification failure —
        deliberately UN-caught here so the app's single exception mapper assigns the
        precise ``JWT_INVALID`` / ``JWT_CLAIMS_MISSING`` deny reason. Keeping the
        mapping in one place (``map_engine_exception``) is the whole point of letting
        it propagate.
        """
        return self._resolver.resolve(token)

    # ------------------------------------------------------------------ step-up

    async def register_lock(
        self,
        identity: Identity,
        alias: str,
        arguments: dict[str, Any],
        risk_tier: RiskTier,
    ) -> str:
        """
        Stage a high-risk action: mint a one-time PIN, register the payload-bound
        lock, and DELIVER the OTP out-of-band. Returns the ``challenge_id`` (== lock_id).

        The PIN is generated with ``secrets`` (CSPRNG), zero-padded to ``PIN_LENGTH``.
        ``PinValidator.register`` stores only a salted scrypt digest of it — never the
        raw value — and binds the lock to SHA-256(canonical_json(tenant, agent, alias,
        arguments)), so any later payload drift yields PAYLOAD_MISMATCH. NONE of that
        derivation changes here; only the delivery of the code is orchestrated below.

        Delivery is fail-closed. With NO channel configured (production, unconfigured)
        this raises ``GatewayDeny(OTP_DELIVERY_FAILED)`` BEFORE any scrypt is spent, so
        an unconfigured gateway never stages a dead challenge. Otherwise the code is
        minted, the lock registered, and the notice handed to ``channel.deliver``; if
        delivery raises, the lock is left to expire on its TTL (its challenge_id is
        never returned, so it is unspendable) and this raises
        ``GatewayDeny(OTP_DELIVERY_FAILED)``. The OTP NEVER appears in the 202 response
        and is never persisted outside the channel's own delivery mechanism.
        """
        # Cheap per-identity throttle BEFORE the memory-hard scrypt in register: bounds a
        # single identity's staging-induced scrypt work, so an authenticated flood of
        # un-pinned PIN_REQUIRED requests cannot amplify into a CPU/RAM DoS.
        await self._enforce_stepup_rate(identity)

        # Fail closed BEFORE minting/scrypt if there is no way to deliver the code: an
        # unconfigured production gateway must not stage a challenge no one can answer.
        if self._channel is None:
            raise GatewayDeny(
                DenyReason.OTP_DELIVERY_FAILED,
                "no authenticator delivery channel configured",
            )

        otp = f"{secrets.randbelow(10 ** PIN_LENGTH):0{PIN_LENGTH}d}"
        lock_id = await self._pin.register(
            identity.tenant_id, identity.agent_id, alias, arguments, otp
        )
        notice = AuthenticatorNotice(
            tenant_id=identity.tenant_id,
            challenge_id=lock_id,
            agent_id=identity.agent_id,
            alias=alias,
            risk_tier=risk_tier,
            expires_in_s=PIN_TTL_SECONDS,
            otp=otp,
        )
        try:
            await self._channel.deliver(notice)
        except GatewayDeny:
            raise
        except Exception as exc:  # noqa: BLE001 — any delivery failure is fail-closed.
            # The lock stays registered but its challenge_id is NEVER returned, so it is
            # unspendable and simply expires on its TTL. Fail closed with the distinct
            # reason so the WORM trail separates a delivery failure from a lock error.
            raise GatewayDeny(
                DenyReason.OTP_DELIVERY_FAILED,
                "authenticator delivery failed",
            ) from exc
        return lock_id

    async def consume_and_execute(
        self,
        identity: Identity,
        entry: AliasEntry,
        arguments: dict[str, Any],
        pin: str,
        challenge_id: str,
    ) -> int:
        """
        Atomically SPEND the exactly-once payload lock ("execute" == run the
        consume-and-compare Lua). Returns ``1`` on success; raises ``GatewayDeny`` on
        any lock failure.

        This is the only place raw Lua codes (1 / -1 / -2 / -3) are interpreted, so
        the code -> ``DenyReason`` mapping lives here and nowhere else (mirrors the
        demo's ``_consume_pin``). Transport dispatch is a SEPARATE app step: the AUTO
        path dispatches without any consume, and the ALLOW WORM record must be written
        BETWEEN consume and dispatch (demo stages 6 -> 7 -> 8), so this service must
        not couple the two.
        """
        # Cheap per-identity throttle BEFORE the memory-hard scrypt inside consume: bounds
        # a single identity's completion-induced scrypt work, so a flood of PIN completions
        # (even with bogus challenge_id / PIN, which still derive scrypt before the atomic
        # Lua rejects them) cannot amplify into a CPU/RAM DoS. Mirrors register_lock's
        # pre-scrypt guard; the atomic Lua remains the authoritative exactly-once check, so
        # payload/PIN binding is untouched.
        await self._enforce_consume_rate(identity)
        try:
            code = await self._pin.consume(
                identity.tenant_id,
                challenge_id,
                identity.agent_id,
                entry.alias,
                arguments,
                pin,
            )
        except LockError as exc:
            raise GatewayDeny(DenyReason.LOCK_ERROR, str(exc)) from exc

        if code == 1:
            return 1
        if code == -1:
            raise GatewayDeny(DenyReason.PIN_NOT_FOUND, "lock absent or already spent")
        if code == -2:
            raise GatewayDeny(DenyReason.PIN_MISMATCH, "pin did not match")
        if code == -3:
            raise GatewayDeny(DenyReason.PAYLOAD_MISMATCH, "payload hash mismatch")
        # Any other value is impossible per the Lua contract — fail closed.
        raise GatewayDeny(DenyReason.LOCK_ERROR, f"unexpected lock code {code}")

    async def _enforce_stepup_rate(self, identity: Identity) -> None:
        """
        Fail closed if this identity has exceeded the step-up staging window quota.

        Atomic INCR+EXPIRE fixed window keyed by (tenant, agent). Runs BEFORE any scrypt,
        so a rejected request spends O(1) Redis work and ZERO memory-hard derivation. A
        Redis transport failure is fail-closed (denies), consistent with the boundary.
        """
        key = f"mcpip:stepup:rate:{identity.tenant_id}:{identity.agent_id}"
        try:
            raw = await self._rate_script(
                keys=[key], args=[str(_STEPUP_RATE_WINDOW_S)]
            )
            count = int(raw)
        except Exception as exc:  # noqa: BLE001 — transport failure is fail-closed.
            raise GatewayDeny(
                DenyReason.RATE_LIMITED, "step-up rate check unavailable"
            ) from exc
        if count > _STEPUP_RATE_MAX:
            raise GatewayDeny(
                DenyReason.RATE_LIMITED, "step-up staging rate exceeded"
            )

    async def _enforce_consume_rate(self, identity: Identity) -> None:
        """
        Fail closed if this identity has exceeded the PIN-completion (consume) window quota.

        Atomic INCR+EXPIRE fixed window keyed by (tenant, agent) on a DISTINCT namespace
        from staging, run BEFORE the memory-hard scrypt in ``PinValidator.consume`` — so a
        completion flood spends O(1) Redis work and ZERO memory-hard derivation before it is
        refused. A Redis transport failure is fail-closed (denies), consistent with the
        boundary and with the staging guard.
        """
        key = f"mcpip:consume:rate:{identity.tenant_id}:{identity.agent_id}"
        try:
            raw = await self._rate_script(
                keys=[key], args=[str(_CONSUME_RATE_WINDOW_S)]
            )
            count = int(raw)
        except Exception as exc:  # noqa: BLE001 — transport failure is fail-closed.
            raise GatewayDeny(
                DenyReason.RATE_LIMITED, "completion rate check unavailable"
            ) from exc
        if count > _CONSUME_RATE_MAX:
            raise GatewayDeny(
                DenyReason.RATE_LIMITED, "pin-completion rate exceeded"
            )

    # ------------------------------------------------------------------ sandbox

    async def peek_authenticator_otp(
        self, identity: Identity, challenge_id: str
    ) -> str | None:
        """
        SANDBOX ONLY — read back the out-of-band OTP for a staged challenge.

        Stands in for the enrolled device surfacing the one-time code to the operator.
        Delegates to the sandbox channel's ``peek``; when the wired channel is anything
        other than a ``SandboxRedisAuthenticatorChannel`` (i.e. production's webhook push
        or an unconfigured None), there is no readable stash and this returns ``None`` —
        so the sandbox authenticator endpoint yields the same 404 it always did outside
        sandbox. Returns ``None`` if the challenge is unknown or its OTP has expired.
        """
        channel: object = self._channel
        if isinstance(channel, FanoutAuthenticatorChannel):
            # The sandbox composition fans out to (sandbox stash, TOTP stash); the
            # peek oracle reads only the sandbox leg. Unwrapping preserves the exact
            # pre-fanout behavior — production compositions have no sandbox leg, so
            # peek still yields None (the endpoint's 404) there.
            channel = next(
                (
                    leg
                    for leg in channel.channels
                    if isinstance(leg, SandboxRedisAuthenticatorChannel)
                ),
                None,
            )
        if not isinstance(channel, SandboxRedisAuthenticatorChannel):
            return None
        return await channel.peek(identity.tenant_id, challenge_id)


__all__ = ["AuthEngine"]
