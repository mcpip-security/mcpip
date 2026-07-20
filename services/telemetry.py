"""
MCPIP V2 — Service: opt-in VENDOR telemetry (aggregate stats + best-effort beacon).

    ◐ "Count the deployment, never the agent."

MCPIP's headline promise is self-hosted / air-gapped / inspectable — NO black box, NO
surveillance of the agent wire. This module lets the ORG THAT SHIPS MCPIP (the vendor)
see which DEPLOYMENTS run it, enforce license tiers, and read live aggregate numbers
WITHOUT breaking that promise. The "client" is the org running MCPIP; the end user /
agent is NEVER tracked.

Two cleanly-separated pieces, NEITHER of which can affect an authorization decision:

  * :class:`TelemetryStats` — an ALWAYS-wired, Redis-bound aggregation store. It owns ONLY
    tenant-prefixed AGGREGATE counters:
      - a governed-agent CARDINALITY per tenant (a Redis HyperLogLog, key
        ``mcpip:telemetry:agents:{tenant}``): ``record_agent`` PFADDs the agent_id into the
        HLL registers, which is a LOSSY sketch — the id is NEVER stored in a readable set,
        only ``PFCOUNT`` (an integer) is ever read back;
      - three tenant-prefixed decision counters
        ``mcpip:telemetry:dec:{tenant}:{allow|deny|staged}`` (plain INCR).
    Both ``record_*`` are invoked on the auth path as CHEAP, BEST-EFFORT side effects that
    CANNOT fail a decision: every one swallows a Redis error to
    ``mcpip_telemetry_total{event="record_error"}``. ``read_tenant`` backs the local
    admin stats read; ``aggregate`` backs the beacon (deployment-wide UNION cardinality +
    summed decision totals) and is off-hot-path + fail-soft (honest zeros on any error).
    Only aggregate integers ever leave the box — the id set never does.

  * :class:`TelemetryBeacon` — the OPTIONAL, off-hot-path sender (modeled on the lifespan
    interval daemons / the forensic capture side-channel). It assembles a CLOSED payload
    of exactly eight fields, canonical-JSON serializes it, signs it with a per-install
    HMAC secret, and POSTs it over a HERMETIC, SSRF-guarded, IP-pinned https client (the
    SAME discipline as ``WebhookAuthenticatorChannel`` / ``jwks_refresher`` /
    ``external_pdp``). EVERY failure (disabled, air-gap, DNS, SSRF-block, non-2xx, timeout)
    is caught and dropped to a metric — never observable to, and never able to
    block/delay/reorder/flip, an authorization. It NEVER refreshes or re-verifies the
    license; it only READS the boot-verified tier/id for the payload.

THE PRIVACY BOUNDARY (the load-bearing rule). The beacon body is a CLOSED set of exactly:
``install_id`` (random, once-generated, persisted, NOT derived from any tenant/host/
customer/license identity), ``license_tier`` + ``license_id`` (or "unlicensed"/None),
``version``, ``governed_agent_identity_count`` (a single integer CARDINALITY),
``decisions`` {allow,deny,staged} (the SAME closed-enum outcomes as
``core/metrics.py``), ``uptime_seconds``, and ``sent_at``. It MUST NEVER carry a tenant
id, agent id, alias, target, capability, compartment, correlation id, secret, payload,
argument, or any per-tenant breakdown — the identical opacity discipline as the metric
labels. Only ``PFCOUNT``/``INCR`` aggregate integers ever leave the box.

This module lives in ``services/`` (NOT ``bridge/connectors/``), so ``httpx`` is
permitted — the connector-purity AST scan does not apply here.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import socket
import time
from datetime import datetime, timezone
from typing import Any, Callable, Final, Optional
from urllib.parse import urlsplit

import httpx

from core.licensing import License
from core.metrics import TELEMETRY
from core.version import get_version
from interfaces import (
    MAX_TELEMETRY_INTERVAL_S,
    MAX_TELEMETRY_RESPONSE_BYTES,
    MAX_TELEMETRY_TENANTS,
    MIN_TELEMETRY_INTERVAL_S,
)

# Reuse the authenticator-webhook SSRF primitive (resolve + reject internal ranges). A
# module-level import is safe here (``services`` already imports ``services``).
from services.authn_channel import _is_blocked_ip

# The closed set of decision outcomes the telemetry layer counts — the SAME closed enum
# as ``core/metrics.py`` DECISIONS. Anything else is refused at the record boundary so a
# stray outcome can never mint an out-of-vocabulary Redis key segment.
_DECISION_OUTCOMES: Final[tuple[str, ...]] = ("allow", "deny", "staged")

_KEY_PREFIX: Final[str] = "mcpip:telemetry"
_AGENTS_MATCH: Final[str] = f"{_KEY_PREFIX}:agents:*"
_DEC_MATCH: Final[str] = f"{_KEY_PREFIX}:dec:*"

# Beacon signature headers (the receiver reconstructs HMAC-SHA256(secret, ts + "." + body)
# and constant-time-compares the hex). Distinct from the authenticator-webhook headers so
# a receiver can tell the two signed channels apart.
_SIG_HEADER: Final[str] = "X-MCPIP-Telemetry-Signature"
_TS_HEADER: Final[str] = "X-MCPIP-Timestamp"

# The EXACT closed key set of a beacon body — asserted by a test. Signature + timestamp
# ride as HEADERS only, never in the body.
BEACON_PAYLOAD_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "install_id",
        "license_tier",
        "license_id",
        "version",
        "governed_agent_identity_count",
        "decisions",
        "uptime_seconds",
        "sent_at",
    }
)


# ---------------------------------------------------------------------------
# TelemetryStats — always-wired, Redis-bound aggregate store (best-effort).
# ---------------------------------------------------------------------------


class TelemetryStats:
    """
    Tenant-prefixed AGGREGATE counters: a governed-agent HLL cardinality + decision totals.

    Every ``record_*`` is a cheap, swallow-only side effect on the auth path — a Redis
    hiccup bumps ``mcpip_telemetry_total{event="record_error"}`` and returns, it NEVER
    raises into (and so never blocks/flips) a decision. Only aggregate integers are ever
    read back: the agent_id lives solely inside the HLL registers and is never materialized
    into a readable set.
    """

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    @staticmethod
    def _agents_key(tenant_id: str) -> str:
        """Per-tenant HyperLogLog key (holds only HLL registers, never a member set)."""
        return f"{_KEY_PREFIX}:agents:{tenant_id}"

    @staticmethod
    def _dec_key(tenant_id: str, outcome: str) -> str:
        """Per-tenant, per-outcome decision counter key."""
        return f"{_KEY_PREFIX}:dec:{tenant_id}:{outcome}"

    async def record_agent(self, tenant_id: str, agent_id: str) -> None:
        """
        Fold ``agent_id`` into the tenant's HLL cardinality sketch (best-effort PFADD).

        The id is hashed into the HLL registers and is NEVER retrievable — only the
        aggregate ``PFCOUNT`` integer is ever read. Any Redis error is swallowed to a
        metric: this is a side effect of a decision, it can NEVER fail one.
        """
        try:
            await self._redis.pfadd(self._agents_key(tenant_id), agent_id)
        except Exception:  # noqa: BLE001 — a stat write can NEVER fail a decision.
            TELEMETRY.labels("record_error").inc()

    async def record_decision(self, tenant_id: str, outcome: str) -> None:
        """
        Increment the tenant's decision counter for ``outcome`` (best-effort INCR).

        ``outcome`` MUST be one of the closed enum {allow, deny, staged}; anything else is a
        no-op (defence-in-depth — a caller can never mint an out-of-vocabulary key segment).
        Any Redis error is swallowed to a metric — never raised into a decision.
        """
        if outcome not in _DECISION_OUTCOMES:
            return
        try:
            await self._redis.incr(self._dec_key(tenant_id, outcome))
        except Exception:  # noqa: BLE001 — a stat write can NEVER fail a decision.
            TELEMETRY.labels("record_error").inc()

    async def read_tenant(self, tenant_id: str) -> tuple[int, dict[str, int]]:
        """
        Return ``(governed_agent_cardinality, {allow,deny,staged})`` for ONE tenant.

        Backs the local ``GET /v1/admin/stats`` read (the operator's OWN tenant). Fail-soft:
        any Redis error yields an honest zero/empty state (never a fabricated number), since
        this backs a listing, never a decision.
        """
        try:
            raw_count: Any = await self._redis.pfcount(self._agents_key(tenant_id))
            count = int(raw_count) if raw_count is not None else 0
        except Exception:  # noqa: BLE001 — fail-soft to an honest zero.
            count = 0
        decisions: dict[str, int] = {}
        for outcome in _DECISION_OUTCOMES:
            try:
                raw: Any = await self._redis.get(self._dec_key(tenant_id, outcome))
                decisions[outcome] = int(raw) if raw is not None else 0
            except Exception:  # noqa: BLE001 — fail-soft to an honest zero.
                decisions[outcome] = 0
        return count, decisions

    async def aggregate(self) -> tuple[int, dict[str, int]]:
        """
        Deployment-wide numbers for the beacon: UNION agent cardinality + summed decisions.

        Off the hot path (only the beacon / the admin stats read touch it) and FAIL-SOFT:
        any error returns honest zeros. A bounded ``scan_iter`` collects the tenant HLL keys
        (capped by ``MAX_TELEMETRY_TENANTS``); a single ``PFCOUNT`` over them returns the
        UNION cardinality WITHOUT materializing a merged key (so the id set never leaves the
        box). Decision totals are the summed per-tenant counters. Only aggregate integers
        are produced — never a tenant/agent/alias.
        """
        try:
            agent_keys: list[str] = []
            async for key in self._redis.scan_iter(match=_AGENTS_MATCH, count=512):
                agent_keys.append(key)
                if len(agent_keys) >= MAX_TELEMETRY_TENANTS:
                    break
            if agent_keys:
                raw_count: Any = await self._redis.pfcount(*agent_keys)
                count = int(raw_count) if raw_count is not None else 0
            else:
                count = 0
        except Exception:  # noqa: BLE001 — off-hot-path aggregate is fail-soft.
            count = 0

        decisions: dict[str, int] = {outcome: 0 for outcome in _DECISION_OUTCOMES}
        try:
            # Bound the decision-key scan too (3 outcomes per tenant). Each key ends with
            # ``:{outcome}`` — a suffix check buckets it correctly regardless of any colon
            # in the tenant id, so summation is robust to the tenant's shape.
            seen = 0
            cap = MAX_TELEMETRY_TENANTS * len(_DECISION_OUTCOMES)
            async for key in self._redis.scan_iter(match=_DEC_MATCH, count=512):
                seen += 1
                if seen > cap:
                    break
                bucket: Optional[str] = None
                for outcome in _DECISION_OUTCOMES:
                    if key.endswith(f":{outcome}"):
                        bucket = outcome
                        break
                if bucket is None:
                    continue
                try:
                    raw: Any = await self._redis.get(key)
                    decisions[bucket] += int(raw) if raw is not None else 0
                except Exception:  # noqa: BLE001 — skip an unreadable counter.
                    continue
        except Exception:  # noqa: BLE001 — off-hot-path aggregate is fail-soft.
            decisions = {outcome: 0 for outcome in _DECISION_OUTCOMES}
        return count, decisions


# ---------------------------------------------------------------------------
# TelemetryBeacon — optional, off-hot-path, hermetic SSRF-guarded sender.
# ---------------------------------------------------------------------------


class TelemetryBeacon:
    """
    Assemble the CLOSED aggregate payload, sign it, and POST it over a hermetic client.

    Constructed ONLY when telemetry is enabled + a URL is configured + NOT sandbox (the
    composition root enforces that). Runs as ONE lifespan interval task; every send failure
    is caught and dropped to ``mcpip_telemetry_total`` — never observable to a decision.

    SSRF guard (mirrors ``WebhookAuthenticatorChannel`` verbatim, all per-send so a rotated
    DNS record cannot bypass it): https-only; resolve + reject ANY private / loopback /
    link-local (169.254.169.254 metadata) / reserved / multicast / unspecified address;
    connection PINNED to the validated IP (original hostname drives SNI + cert); no
    redirects; bounded timeout; bounded response read. The client is HERMETIC
    (``trust_env=False`` + ``proxy=None``) so no ambient HTTPS_PROXY / SSL_CERT_FILE /
    SSLKEYLOGFILE can reroute or MITM the beacon.
    """

    def __init__(
        self,
        *,
        stats_getter: Callable[[], TelemetryStats],
        url: str,
        interval_s: float,
        install_id: str,
        secret: bytes,
        license_getter: Callable[[], Optional[License]],
        timeout_s: float = MAX_TELEMETRY_INTERVAL_S,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ValueError("telemetry URL must be https")
        if not parts.hostname:
            raise ValueError("telemetry URL must have a host")
        if not secret:
            raise ValueError("telemetry signing secret must be non-empty")
        if not install_id:
            raise ValueError("telemetry install id must be non-empty")
        # A GETTER (not a captured object) so a Redis rebind — which rebuilds the
        # Redis-bound ``TelemetryStats`` — is always reflected, never a stale client.
        self._stats_getter = stats_getter
        self._url = url
        self._host: str = parts.hostname
        self._port: int = parts.port or 443
        self._install_id = install_id
        self._secret = secret
        self._license_getter = license_getter
        # Clamp the cadence into the shared interfaces safety band (no duplicated limits).
        self._interval_s = max(
            MIN_TELEMETRY_INTERVAL_S, min(MAX_TELEMETRY_INTERVAL_S, interval_s)
        )
        # A bounded per-send wall-clock ceiling; kept modest — well under the cadence.
        self._timeout_s = 10.0
        self._start_monotonic = time.monotonic()
        # Coarse in-memory status for the local stats read (never a metric label).
        self.last_sent: Optional[float] = None
        self.last_result: str = "never"

    @property
    def interval_s(self) -> float:
        """The clamped beacon cadence (seconds)."""
        return self._interval_s

    def status(self) -> dict[str, Any]:
        """Coarse status for ``GET /v1/admin/stats`` — never fabricated, never a label."""
        return {"last_sent": self.last_sent, "last_result": self.last_result}

    async def assemble_payload(self) -> dict[str, Any]:
        """
        Build the CLOSED eight-field aggregate payload — the ONLY thing that leaves the box.

        Reads the deployment-wide UNION cardinality + summed decision totals from
        ``TelemetryStats.aggregate`` and the boot-verified license tier/id (READ-only; no
        refresh, no re-verify, no trust root). NO tenant/agent/alias/target/secret/argument
        is ever placed here — only aggregate integers + the opaque install-id + coarse
        license/version/uptime fields.
        """
        count, decisions = await self._stats_getter().aggregate()
        lic = self._license_getter()
        return {
            "install_id": self._install_id,
            "license_tier": lic.tier if lic is not None else "unlicensed",
            "license_id": lic.license_id if lic is not None else None,
            "version": get_version(),
            "governed_agent_identity_count": count,
            "decisions": {outcome: decisions.get(outcome, 0) for outcome in _DECISION_OUTCOMES},
            "uptime_seconds": int(time.monotonic() - self._start_monotonic),
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _serialize(payload: dict[str, Any]) -> bytes:
        """
        Deterministic JSON body for the signed beacon (INDEPENDENT of the payload lock).

        Uses its own compact, sorted serialization — it never touches
        ``interfaces.canonical_json`` / the payload-lock canonicalizer / the Rust mirror.
        """
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    async def send_once(self) -> None:
        """
        Assemble + sign + POST exactly one beacon; swallow EVERY failure to a metric.

        A send that returns 2xx bumps ``sent`` and records ``ok``; any failure (assembly,
        DNS, SSRF-block, transport, non-2xx, timeout) bumps ``send_error`` and records
        ``error``. It NEVER raises — the caller is an interval task off the hot path.
        """
        try:
            payload = await self.assemble_payload()
            body = self._serialize(payload)
            await self._post(body)
        except Exception:  # noqa: BLE001 — a beacon failure is never observable to a decision.
            TELEMETRY.labels("send_error").inc()
            self.last_result = "error"
            return
        TELEMETRY.labels("sent").inc()
        self.last_sent = time.time()
        self.last_result = "ok"

    async def run(self) -> None:
        """
        The lifespan interval loop: send once at startup (deployment registration), then
        every clamped ``interval_s``. Cancellation (shutdown) propagates out of the sleep —
        ``send_once`` swallows only ``Exception``, and ``CancelledError`` is a
        ``BaseException`` in 3.12, so it is never absorbed.
        """
        while True:
            await self.send_once()
            await asyncio.sleep(self._interval_s)

    async def _post(self, body: bytes) -> None:
        """Sign and push the body to the receiver over the hermetic, IP-pinned client."""
        validated_ip = await self._resolve_and_validate()
        timestamp = str(int(time.time()))
        signature = hmac.new(
            self._secret, timestamp.encode("ascii") + b"." + body, hashlib.sha256
        ).hexdigest()
        authority = self._host if self._port == 443 else f"{self._host}:{self._port}"
        headers = {
            "Content-Type": "application/json",
            "Host": authority,
            _TS_HEADER: timestamp,
            _SIG_HEADER: f"sha256={signature}",
        }
        # Pin the connection to the validated IP; keep the original hostname for SNI + cert.
        ip_url = httpx.URL(self._url).copy_with(host=validated_ip)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout_s),
            follow_redirects=False,
            verify=True,
            # Hermetic by construction: a guard that hand-rolls SSRF validation + IP-pinning
            # must NOT honor ambient env, or HTTPS_PROXY would reroute the beacon through an
            # unvalidated intermediary and SSL_CERT_FILE could trust a MITM CA (voiding the
            # pin + TLS verification). trust_env=False + no proxy forces the direct, pinned,
            # validated TLS connection the guard promises.
            trust_env=False,
            proxy=None,
        ) as client:
            request = client.build_request(
                "POST",
                ip_url,
                content=body,
                headers=headers,
                extensions={"sni_hostname": self._host},
            )
            response = await client.send(request, stream=True)
            try:
                status = response.status_code
                read = 0
                async for chunk in response.aiter_raw():
                    read += len(chunk)
                    if read >= MAX_TELEMETRY_RESPONSE_BYTES:
                        break
            finally:
                await response.aclose()
        if not 200 <= status < 300:
            raise RuntimeError(f"telemetry receiver returned non-2xx status {status}")

    async def _resolve_and_validate(self) -> str:
        """Resolve the host, reject every internal address, return one validated IP."""
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(self._host, self._port, type=socket.SOCK_STREAM)
        if not infos:
            raise RuntimeError("telemetry host did not resolve")
        chosen: str | None = None
        for info in infos:
            ip_text = info[4][0]
            if _is_blocked_ip(ip_text):
                # Any single blocked answer refuses the whole send (mixed-answer SSRF).
                raise RuntimeError("telemetry host resolves to a disallowed address")
            if chosen is None:
                chosen = ip_text
        assert chosen is not None
        return chosen


__all__ = [
    "BEACON_PAYLOAD_FIELDS",
    "TelemetryBeacon",
    "TelemetryStats",
]
