"""
MCPIP V2 — Service: the deny-only policy overlay (velocity cap + amount ceiling).

    ◐ "A policy can only ever say no. It never mints identity, never repoints a skill."

This module ships the v1 ``PolicyProvider``: a minimal, stateless, DENY-ONLY policy
layer evaluated between the entitlement/sender-constraint gates and the risk gate. It
enforces exactly two rule kinds against a per-tenant policy document:

  * **velocity** — a fixed-window action cap (atomic ``INCR`` + first-hit ``EXPIRE``,
    reusing the ``auth_engine._enforce_stepup_rate`` pattern) keyed by
    ``mcpip:policy:vel:{tenant}:{scope}:{scope_value}``. Over the cap → deny.
  * **amount**   — a ceiling on a named numeric argument field. A JSON number over the
    ceiling denies; a present-but-non-numeric value fails CLOSED (we refuse to
    interpret a string/object/bool amount rather than coerce it — that is exactly the
    evasion); an ABSENT field is a no-op (the stateless engine does not know each
    skill's schema, so an operator attaches amount rules only to skills whose schema
    guarantees the field).

Opt-in, honest states:
  * NO tenant policy document (Redis ``GET`` returns ``None``) → ``continue`` — no
    limits, never a fabricated default rule.
  * a matching-rule miss → ``continue``.
  * a Redis transport error OR a malformed stored document → fail CLOSED (a ``deny``
    decision the pipeline surfaces as ``POLICY_DENIED``).

The engine NEVER raises for a known condition — it converts every error into a ``deny``
decision — but the pipeline also wraps ``evaluate`` in a fail-closed ``try/except`` so a
genuinely unexpected bug still denies. The amount ceiling (pure) is evaluated BEFORE the
state-mutating velocity ``INCR`` so an over-ceiling request denies without consuming
velocity budget.

This velocity Lua is a DISTINCT script from the payload-lock Lua and carries NO
Python/Rust byte-identity obligation — that rule binds only ``canonical_json`` /
``enforce_argument_safety`` / the PIN-hash derivation.
"""

from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation
from typing import Any, Final, Optional

import redis.asyncio as redis
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from redis.exceptions import RedisError

from auth import LockError
from interfaces import (
    MAX_POLICY_DOC_BYTES,
    MAX_POLICY_RULES,
    PolicyContext,
    PolicyDecision,
    PolicyProvider,
)

# Schema tag every stored/accepted policy document must carry (mirrors the directory
# store's ``mcpip-directory/1`` discipline). A bump means a breaking rule-shape change.
POLICY_SCHEMA: Final[str] = "mcpip-policy/1"

# Redis key prefixes — every key is tenant-prefixed from the JWT-derived tenant id, so a
# wildcard-bearing tenant id can never widen into another tenant's namespace and the
# velocity counters can never collide cross-tenant.
_DOC_KEY_PREFIX: Final[str] = "mcpip:policy:doc:"
_VEL_KEY_PREFIX: Final[str] = "mcpip:policy:vel:"

# INCR the fixed-window counter and, on the first hit, atomically arm its TTL so a
# crashed process can never leave a counter without expiry (which would wedge a scope).
# Identical shape to auth_engine._RATE_LIMIT_LUA; a SEPARATE script (no byte-identity
# obligation with the payload-lock Lua).
_VELOCITY_LUA: Final[str] = (
    "local c = redis.call('INCR', KEYS[1]) "
    "if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end "
    "return c"
)

# Bounds on rule numerics (fail-closed strict validation at write time). A velocity
# window is at least a second and at most a day; an action cap is at least one.
_MIN_WINDOW_SECONDS: Final[int] = 1
_MAX_WINDOW_SECONDS: Final[int] = 86400
#: Bounds on an ``argument`` rule's lists. The whole document is already capped by
#: MAX_POLICY_RULES + MAX_POLICY_DOC_BYTES; these keep any SINGLE rule's per-request
#: work bounded too, since every value is compared on the hot path.
_MAX_ARGUMENT_VALUES: Final[int] = 64
_MAX_ARGUMENT_VALUE_LEN: Final[int] = 256


class PolicyDocumentError(ValueError):
    """The supplied policy document is malformed or too large (caller → opaque deny)."""


class PolicyError(Exception):
    """
    Internal engine failure reading/parsing the stored policy document (Redis transport
    error or a malformed persisted doc). The engine converts this into a fail-closed
    ``deny`` decision — it never propagates to the caller as itself.
    """


class PolicyRule(BaseModel):
    """
    One deny-only policy rule (frozen). A rule MATCHES a request by ``scope`` +
    ``scope_value`` (the request's alias or coarse transport class) and, per ``kind``,
    enforces a fixed-window velocity cap, a numeric amount ceiling, or a constraint on
    a named STRING argument.

    A single model carries every kind's fields (the off-kind fields default None); a
    strict ``model_validator`` enforces that a rule of each kind carries exactly the
    fields it needs, so a half-specified rule is a fail-closed validation error at write
    time (the console can never store one) rather than a silently-ignored rule.

    **Why ``argument`` exists.** Everything the alias model buys assumes an alias names a
    NARROW action. Point one at ``run_shell(cmd)`` or ``execute_sql(query)`` and per-call
    authorization collapses into "may this agent shell at all" — the alias is one catalog
    entry and the payload is arbitrary. ``velocity`` and ``amount`` could not reach that:
    both are numeric. An ``argument`` rule constrains the free-text field itself, which is
    the only place that class of tool can be governed at all.

    **No regex, deliberately.** A tenant-supplied pattern compiled inside the
    authorization path is a ReDoS vector, and Python's ``re`` has no timeout — one
    catastrophic pattern would hang the choke point every request. Exact-match and
    literal-substring are linear in the input and cannot be made pathological.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: str  # "velocity" | "amount" | "argument" — validated below.
    scope: str  # "alias" | "transport_class" — what field the rule keys on.
    scope_value: str = Field(min_length=1, max_length=256)
    # velocity fields (required iff kind == "velocity"):
    max_actions: Optional[int] = Field(default=None, ge=1)
    window_seconds: Optional[int] = Field(
        default=None, ge=_MIN_WINDOW_SECONDS, le=_MAX_WINDOW_SECONDS
    )
    # amount fields (required iff kind == "amount"):
    amount_field: Optional[str] = Field(default=None, min_length=1, max_length=256)
    # Decimal-from-STRING (no float drift). Stored/validated as a string; parsed to
    # Decimal at compare time.
    max_amount: Optional[str] = Field(default=None, min_length=1, max_length=64)
    # argument fields (required iff kind == "argument"; at least one constraint):
    argument_field: Optional[str] = Field(default=None, min_length=1, max_length=256)
    allowed_values: Optional[list[str]] = Field(
        default=None, max_length=_MAX_ARGUMENT_VALUES
    )
    forbidden_substrings: Optional[list[str]] = Field(
        default=None, max_length=_MAX_ARGUMENT_VALUES
    )

    @model_validator(mode="after")
    def _validate_kind_shape(self) -> "PolicyRule":
        if self.scope not in ("alias", "transport_class"):
            raise ValueError("scope must be 'alias' or 'transport_class'")
        argument_fields = (
            self.argument_field,
            self.allowed_values,
            self.forbidden_substrings,
        )
        if self.kind == "velocity":
            if self.max_actions is None or self.window_seconds is None:
                raise ValueError("velocity rule requires max_actions and window_seconds")
            if self.amount_field is not None or self.max_amount is not None:
                raise ValueError("velocity rule must not carry amount fields")
            if any(field is not None for field in argument_fields):
                raise ValueError("velocity rule must not carry argument fields")
        elif self.kind == "amount":
            if self.amount_field is None or self.max_amount is None:
                raise ValueError("amount rule requires amount_field and max_amount")
            if self.max_actions is not None or self.window_seconds is not None:
                raise ValueError("amount rule must not carry velocity fields")
            if any(field is not None for field in argument_fields):
                raise ValueError("amount rule must not carry argument fields")
            try:
                Decimal(self.max_amount)
            except InvalidOperation as exc:
                raise ValueError("max_amount is not a valid decimal") from exc
        elif self.kind == "argument":
            if self.argument_field is None:
                raise ValueError("argument rule requires argument_field")
            if self.allowed_values is None and self.forbidden_substrings is None:
                # A rule that constrains nothing would read as protection while
                # permitting everything — the exact failure this kind exists to stop.
                raise ValueError(
                    "argument rule requires allowed_values or forbidden_substrings"
                )
            for values in (self.allowed_values, self.forbidden_substrings):
                if values is None:
                    continue
                if not values:
                    raise ValueError("argument rule lists must not be empty")
                for value in values:
                    if not 1 <= len(value) <= _MAX_ARGUMENT_VALUE_LEN:
                        raise ValueError(
                            "argument rule values must be 1.."
                            f"{_MAX_ARGUMENT_VALUE_LEN} characters"
                        )
            if self.max_actions is not None or self.window_seconds is not None:
                raise ValueError("argument rule must not carry velocity fields")
            if self.amount_field is not None or self.max_amount is not None:
                raise ValueError("argument rule must not carry amount fields")
        else:
            raise ValueError("kind must be 'velocity', 'amount' or 'argument'")
        return self

    def matches(self, ctx: PolicyContext) -> bool:
        """True iff this rule's scope selects ``ctx``'s alias or transport class."""
        if self.scope == "alias":
            return self.scope_value == ctx.alias
        return self.scope_value == ctx.transport_class


class PolicyRuleSet(BaseModel):
    """A validated per-tenant policy document: a schema tag + a bounded rule list."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    # ``schema`` is a reserved attribute on pydantic BaseModel, so the wire/stored field
    # is ``schema`` via an alias while the Python attribute is ``schema_``.
    schema_: str = Field(alias="schema")
    # Frozen at the model level (``rules`` cannot be reassigned); evaluate() only ever
    # READS it. A list (not tuple) so a JSON array validates under strict mode.
    rules: list[PolicyRule] = Field(default_factory=list, max_length=MAX_POLICY_RULES)

    @model_validator(mode="after")
    def _validate_schema(self) -> "PolicyRuleSet":
        if self.schema_ != POLICY_SCHEMA:
            raise ValueError("unknown or missing policy schema")
        return self


class PolicyDocStore:
    """
    Redis-backed per-tenant policy document store (real config surface).

    ``validate`` is the strict write-time gate the admin PUT endpoint uses (opaque deny
    on malformed). ``load`` is the fail-CLOSED read the engine uses per eval (a Redis
    error or a malformed persisted doc raises ``PolicyError``). ``get`` is the fail-SOFT
    operator read backing the admin GET (a transport error yields None). Every key is
    tenant-scoped — an admin reads/writes ONLY its own tenant's document.
    """

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _key(tenant_id: str) -> str:
        return f"{_DOC_KEY_PREFIX}{tenant_id}"

    @staticmethod
    def validate(document: object) -> dict[str, Any]:
        """
        Strict-validate an operator-supplied policy document. Fail-closed.

        Enforces the ``mcpip-policy/1`` schema, ``<= MAX_POLICY_RULES`` well-formed
        rules, and a ``<= MAX_POLICY_DOC_BYTES`` JSON encoding. Raises
        ``PolicyDocumentError`` on any violation. Returns the canonical stored dict (the
        re-serialized validated document) so a stored doc always round-trips through the
        same strict model the engine parses.
        """
        if not isinstance(document, dict):
            raise PolicyDocumentError("policy document must be a JSON object")
        try:
            ruleset = PolicyRuleSet.model_validate(document)
        except ValidationError as exc:
            raise PolicyDocumentError("malformed policy document") from exc
        stored = ruleset.model_dump(by_alias=True)
        try:
            encoded = json.dumps(stored, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise PolicyDocumentError("policy document is not JSON-serializable") from exc
        if len(encoded) > MAX_POLICY_DOC_BYTES:
            raise PolicyDocumentError("policy document exceeds the size cap")
        return stored

    async def get(self, tenant_id: str) -> Optional[dict[str, Any]]:
        """Return the stored document for ``tenant_id``, or None. Fail-SOFT (admin read)."""
        try:
            raw: Any = await self._redis.get(self._key(tenant_id))
        except RedisError:
            return None
        if raw is None:
            return None
        try:
            loaded = json.loads(raw)
        except (ValueError, TypeError):
            return None
        return loaded if isinstance(loaded, dict) else None

    async def load(self, tenant_id: str) -> Optional[PolicyRuleSet]:
        """
        Fail-CLOSED read used by the engine per eval. Returns the parsed rule set, or
        None when NO document is stored (opt-in — no fabricated default). Raises
        ``PolicyError`` on a Redis transport error OR a malformed persisted document, so
        the engine fails that tenant's policy-scoped actions closed until it is repaired.
        """
        try:
            raw: Any = await self._redis.get(self._key(tenant_id))
        except RedisError as exc:
            raise PolicyError("policy document transport failure") from exc
        if raw is None:
            return None
        try:
            loaded = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise PolicyError("stored policy document is not valid JSON") from exc
        try:
            return PolicyRuleSet.model_validate(loaded)
        except ValidationError as exc:
            raise PolicyError("stored policy document is malformed") from exc

    async def put(self, tenant_id: str, document: dict[str, Any]) -> None:
        """
        Persist a validated document for ``tenant_id``. Fail-closed: a transport error
        raises ``LockError`` so the caller learns the save did not durably land. Callers
        MUST pass a document already through :meth:`validate`.
        """
        payload = json.dumps(document, separators=(",", ":"))
        try:
            await self._redis.set(self._key(tenant_id), payload)
        except RedisError as exc:
            raise LockError("policy document transport failure during put") from exc

    async def delete(self, tenant_id: str) -> None:
        """Remove ``tenant_id``'s policy document (back to the honest no-limits state)."""
        try:
            await self._redis.delete(self._key(tenant_id))
        except RedisError as exc:
            raise LockError("policy document transport failure during delete") from exc


class VelocityAmountPolicyEngine(PolicyProvider):
    """
    The v1 deny-only policy engine: amount ceilings (pure) then fixed-window velocity
    caps (state-mutating), all fail-closed against evasion and transport failure.
    """

    def __init__(
        self, redis_client: "redis.Redis", doc_store: PolicyDocStore
    ) -> None:
        self._redis = redis_client
        self._docs = doc_store
        # Cached velocity script (uploaded once; EVALSHA thereafter).
        self._vel_script = redis_client.register_script(_VELOCITY_LUA)

    async def evaluate(self, ctx: PolicyContext) -> PolicyDecision:
        """
        Evaluate the tenant's policy for ``ctx``. Deny-only + monotonic: the first
        matching rule that denies wins; otherwise fall through to ``continue``.
        """
        try:
            ruleset = await self._docs.load(ctx.identity.tenant_id)
        except PolicyError:
            # Redis down or a malformed stored doc → fail closed for this tenant.
            return PolicyDecision(outcome="deny", detail="policy evaluation unavailable")
        if ruleset is None:
            # No policy configured — honest no-limits state (opt-in, no fabricated rule).
            return PolicyDecision(outcome="continue")

        # Pure checks FIRST, so a rejected request denies WITHOUT consuming any
        # velocity budget (neither the ceiling nor the argument check mutates state).
        for rule in ruleset.rules:
            if rule.kind == "amount" and rule.matches(ctx):
                decision = self._check_amount(rule, ctx)
                if decision.outcome == "deny":
                    return decision
        for rule in ruleset.rules:
            if rule.kind == "argument" and rule.matches(ctx):
                decision = self._check_argument(rule, ctx)
                if decision.outcome == "deny":
                    return decision

        # Then state-mutating velocity INCRs.
        for rule in ruleset.rules:
            if rule.kind == "velocity" and rule.matches(ctx):
                decision = await self._check_velocity(rule, ctx)
                if decision.outcome == "deny":
                    return decision

        return PolicyDecision(outcome="continue")

    @staticmethod
    def _check_amount(rule: PolicyRule, ctx: PolicyContext) -> PolicyDecision:
        """
        Amount ceiling, fail-closed against evasion.

        Absent field → no-op (``continue``). A real JSON number (int/float, excluding
        bool) over the ceiling → deny. A present-but-non-numeric value (str/dict/list/
        bool) → deny: a string amount is exactly the evasion, so we refuse to interpret
        rather than coerce. ``max_amount`` is a config string → Decimal (no float drift).
        """
        value = ctx.arguments.get(rule.amount_field)  # type: ignore[arg-type]
        if value is None:
            return PolicyDecision(outcome="continue")
        # bool is a subclass of int — exclude it before the numeric branch.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return PolicyDecision(
                outcome="deny",
                detail=f"amount field '{rule.amount_field}' is non-numeric",
            )
        assert rule.max_amount is not None  # guaranteed by rule validation.
        try:
            amount = Decimal(str(value))
            ceiling = Decimal(rule.max_amount)
        except InvalidOperation:
            return PolicyDecision(
                outcome="deny", detail="amount could not be evaluated"
            )
        # A non-finite amount (NaN/±Infinity — json.loads accepts bare NaN/Infinity by
        # default, and numeric leaves are not string-validated upstream) constructs a
        # Decimal without error, but `Decimal('NaN') > ceiling` raises InvalidOperation.
        # Reject it here as its own fail-closed deny rather than letting the comparison
        # throw — same "refuse to interpret rather than coerce" stance as a string amount.
        if not amount.is_finite():
            return PolicyDecision(
                outcome="deny",
                detail=f"amount field '{rule.amount_field}' is not a finite number",
            )
        if amount > ceiling:
            return PolicyDecision(
                outcome="deny",
                detail=f"amount {amount} exceeds ceiling {ceiling}",
            )
        return PolicyDecision(outcome="continue")

    @staticmethod
    def _check_argument(rule: PolicyRule, ctx: PolicyContext) -> PolicyDecision:
        """
        String-argument constraint, fail-closed against evasion.

        This is the only rule kind that can govern an OPEN-ENDED alias — one whose
        payload is free text (``cmd``, ``query``, ``path``) rather than a number. It
        cannot make such an alias safe; it can bound it.

        Semantics, deliberately mirroring ``_check_amount``:

        * Absent field → ``continue``. A rule scoped to a transport class matches many
          aliases, most of which will not carry the field, and denying those would make
          a narrow rule act as a blanket one.
        * Present but NOT a string → **deny**. A dict/list/number where a string was
          expected is precisely how a constraint gets smuggled past; refuse to interpret
          rather than coerce.
        * ``allowed_values`` and the value is not exactly one of them → deny.
        * ``forbidden_substrings`` and any appears (case-insensitive) → deny.

        Both lists are literal — no regex anywhere on this path. See ``PolicyRule``.
        """
        value = ctx.arguments.get(rule.argument_field)  # type: ignore[arg-type]
        if value is None:
            return PolicyDecision(outcome="continue")
        if not isinstance(value, str):
            return PolicyDecision(
                outcome="deny",
                detail=f"argument field '{rule.argument_field}' is not a string",
            )
        if rule.allowed_values is not None and value not in rule.allowed_values:
            # The value itself is NOT echoed: this detail reaches the WORM record and
            # the operator console, and an argument can carry customer data.
            return PolicyDecision(
                outcome="deny",
                detail=f"argument '{rule.argument_field}' is not in the allowed set",
            )
        if rule.forbidden_substrings is not None:
            lowered = value.lower()
            for needle in rule.forbidden_substrings:
                if needle.lower() in lowered:
                    return PolicyDecision(
                        outcome="deny",
                        detail=(
                            f"argument '{rule.argument_field}' contains a forbidden "
                            f"substring"
                        ),
                    )
        return PolicyDecision(outcome="continue")

    async def _check_velocity(
        self, rule: PolicyRule, ctx: PolicyContext
    ) -> PolicyDecision:
        """
        Fixed-window velocity cap (atomic INCR + first-hit EXPIRE). A Redis transport
        error fails closed (deny), consistent with the fail-closed boundary.
        """
        key = (
            f"{_VEL_KEY_PREFIX}{ctx.identity.tenant_id}:"
            f"{rule.scope}:{rule.scope_value}"
        )
        try:
            raw = await self._vel_script(
                keys=[key], args=[str(rule.window_seconds)]
            )
            count = int(raw)
        except Exception:  # noqa: BLE001 — transport failure is fail-closed.
            return PolicyDecision(
                outcome="deny", detail="velocity check unavailable"
            )
        assert rule.max_actions is not None  # guaranteed by rule validation.
        if count > rule.max_actions:
            return PolicyDecision(
                outcome="deny",
                detail=f"velocity cap exceeded for {rule.scope} '{rule.scope_value}'",
            )
        return PolicyDecision(outcome="continue")


__all__ = [
    "POLICY_SCHEMA",
    "PolicyDocStore",
    "PolicyDocumentError",
    "PolicyError",
    "PolicyRule",
    "PolicyRuleSet",
    "VelocityAmountPolicyEngine",
]
