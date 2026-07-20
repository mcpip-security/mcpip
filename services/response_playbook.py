"""
Deny-response PLAYBOOK — MCPIP's deterministic automation loop.

    ◐ "A tripped wire should not wait for a human to notice."

This is the response counterpart to the pipeline's inline enforcement: an OPTIONAL,
off-hot-path daemon that tails the durable WORM buffer for high-signal deny events and,
per a **deterministic** policy, closes the loop automatically — it freezes the offending
agent (quarantine) and alerts the operator's channels (Slack / email). Today the pipeline
auto-quarantines only on a canary trip; this playbook extends that deterministic response
to any configured deny pattern (e.g. a burst of ``payload_mismatch`` / ``cross_tenant``
probes) and records every response as a signed WORM incident.

Non-negotiable postures (all structurally enforced here):

  * **Off the decision path.** The playbook reads already-committed audit records
    (``WormLogger.scan_alerts`` — an ``XRANGE`` over the durable buffer) on an interval. It
    NEVER runs on ``emit`` / dispatch, holds no lock the hot path takes, and every failure
    is swallowed to the closed-enum ``RESPONSE`` metric — a response outcome can never
    block, delay, reorder, or flip an authorization.

  * **Deterministic, not inferred.** The decision to respond is a fixed rule over a
    verified signal (a deny reason in a CLOSED allow-set) and a deterministic per-agent
    fixed-window count — NEVER a model, a score, or a heuristic. ``decide_response`` is a
    pure function; the same signal yields the same response every time.

  * **Write-before-execute, applied to the response.** The signed WORM incident record is
    emitted BEFORE the freeze / alert. A protective freeze still proceeds if that append
    hiccups (safety-first for a tripped agent), and the miss is counted — but the record
    leads the action, never trails it.

  * **Idempotent + bounded.** A response fires at most once per ``(tenant, agent, reason)``
    within ``RESPONSE_COOLDOWN_S`` (a Redis ``SET NX EX`` claim), so a redeploy or a repeated
    probe never re-storms the operator. Every cadence / scan / fan-out bound lives in
    ``interfaces.py``.

  * **Whitelist-only egress.** The alert body and the incident record carry ONLY the
    operator-safe projection (``_ALERT_SAFE_KEYS`` — tenant / agent / alias / reason /
    correlation). The real target, the argument payload, and every secret NEVER leave the
    box, and the Slack webhook URL / SMTP password never enter a log, a metric label, the
    WORM record, or the status posture.

This module lives in ``services/`` (NOT ``bridge/connectors/``), so ``httpx`` / ``smtplib``
are permitted. The Slack client is HERMETIC (``trust_env=False`` + ``proxy=None``),
https-only, redirect-free, and read-bounded; the SMTP send runs in a thread executor so a
slow relay never stalls the event loop.
"""

from __future__ import annotations

import asyncio
import smtplib
import time
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlsplit

import httpx
import redis.asyncio as redis
from redis.exceptions import RedisError

from audit import WormLogger
from core.metrics import RESPONSE
from interfaces import (
    MAX_RESPONSE_ACK_BYTES,
    MAX_RESPONSE_ACTIONS_PER_TICK,
    MAX_RESPONSE_INTERVAL_S,
    MAX_RESPONSE_RECIPIENTS,
    MAX_RESPONSE_SCAN,
    MIN_RESPONSE_INTERVAL_S,
    RESPONSE_BURST_WINDOW_S,
    RESPONSE_COOLDOWN_S,
    RESPONSE_SINGLE_SHOT_REASONS,
)

# The async signature of ``QuarantineStore.quarantine`` — kept as a callable so the daemon
# never captures a store that a Redis rebind would stale (the getter resolves it live).
QuarantineFn = Callable[..., Awaitable[None]]


# --------------------------------------------------------------------------- alert channels


class SlackChannel:
    """A Slack (or Slack-compatible, e.g. self-hosted Mattermost) incoming-webhook sink.

    The webhook URL is TRUSTED deployment config (an operator env var), not runtime input,
    so an internal self-hosted target is legitimate and not blocked. The client is hermetic +
    https + redirect-free + bounded so a misconfigured URL cannot reroute through ambient
    proxies or stream an unbounded body. Every send failure is swallowed (never raised).
    """

    def __init__(self, url: str, *, timeout_s: float = 8.0) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("slack webhook URL must be https with a host")
        self._url = url
        self._timeout_s = timeout_s

    async def send(self, text: str) -> bool:
        """POST ``{text}`` to the webhook; True on 2xx, False (swallowed) on any failure."""
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout_s),
                follow_redirects=False,
                verify=True,
                trust_env=False,
                proxy=None,
            ) as client:
                response = await client.post(self._url, json={"text": text})
                _ = response.content[:MAX_RESPONSE_ACK_BYTES]  # bound the ACK read.
                status = response.status_code
        except Exception:  # noqa: BLE001 — a webhook failure is never observable to a decision.
            RESPONSE.labels("slack_error").inc()
            return False
        if 200 <= status < 300:
            RESPONSE.labels("slack_sent").inc()
            return True
        RESPONSE.labels("slack_error").inc()
        return False


class EmailChannel:
    """A plaintext SMTP email sink (STARTTLS when the relay offers it, optional auth).

    The SMTP host is trusted operator config — an internal relay is a legitimate, common
    target, so no address is blocked. The blocking ``smtplib`` send runs in a thread executor
    with a bounded timeout so a slow relay never stalls the async poll loop. The password
    never leaves this object (never logged, never in status/metrics).
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        sender: str,
        recipients: tuple[str, ...],
        user: Optional[str],
        password: Optional[str],
        timeout_s: float = 12.0,
    ) -> None:
        if not host or not sender or not recipients:
            raise ValueError("email channel needs host, sender, and at least one recipient")
        self._host = host
        self._port = port
        self._sender = sender
        self._recipients = recipients[:MAX_RESPONSE_RECIPIENTS]
        self._user = user
        self._password = password
        self._timeout_s = timeout_s

    def _send_blocking(self, subject: str, text: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self._sender
        msg["To"] = ", ".join(self._recipients)
        msg.set_content(text)
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout_s) as smtp:
            smtp.ehlo()
            try:
                smtp.starttls()
                smtp.ehlo()
            except smtplib.SMTPException:
                pass  # relay does not offer STARTTLS — send over the plain channel.
            if self._user and self._password:
                smtp.login(self._user, self._password)
            smtp.send_message(msg)

    async def send(self, subject: str, text: str) -> bool:
        """Dispatch one email off the loop; True on success, False (swallowed) otherwise."""
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._send_blocking, subject, text)
        except Exception:  # noqa: BLE001 — an email failure is never observable to a decision.
            RESPONSE.labels("email_error").inc()
            return False
        RESPONSE.labels("email_sent").inc()
        return True


# --------------------------------------------------------------------------- the pure policy


@dataclass(frozen=True)
class ResponseConfig:
    """The deterministic response policy — fixed rules, no inference."""

    trigger_reasons: frozenset[str]  # active subset of RESPONSE_TRIGGER_REASONS
    burst_threshold: int             # in-window deny count for non-single-shot reasons
    auto_quarantine: bool            # freeze the offending agent on a triggered response


@dataclass(frozen=True)
class ResponsePlan:
    """What a triggered response does (the incident record is always written)."""

    quarantine: bool
    notify: bool


def decide_response(
    reason: str,
    window_count: int,
    *,
    cfg: ResponseConfig,
    has_channel: bool,
) -> Optional[ResponsePlan]:
    """
    PURE: given a deny ``reason`` and the agent's in-window count of that reason, decide
    whether to respond and with what actions. Returns ``None`` when no response is due.

    A ``canary_tripped`` (single-shot) reason fires on the first occurrence; every other
    trigger reason fires only once the per-agent window count reaches ``burst_threshold``.
    The incident record is written by the caller on any non-``None`` plan; the plan's flags
    gate only the freeze and the alert.
    """
    if reason not in cfg.trigger_reasons:
        return None
    if reason not in RESPONSE_SINGLE_SHOT_REASONS and window_count < cfg.burst_threshold:
        return None
    return ResponsePlan(quarantine=cfg.auto_quarantine, notify=has_channel)


def _format_alert(alert: dict[str, Any], plan: ResponsePlan) -> str:
    """The whitelist-only alert line — tenant/agent/alias/reason/correlation ONLY.

    No target, no payload, no secret ever appears (the projection guarantees it upstream;
    this formatter reads only the safe keys and would render nothing else even if present).
    """
    actions = ", ".join(
        a for a, on in (("quarantined", plan.quarantine), ("alerted", plan.notify)) if on
    )
    return (
        "MCPIP deny-response — automated action taken.\n"
        f"  reason:      {alert.get('deny_reason')}\n"
        f"  action:      {actions or 'recorded'}\n"
        f"  tenant:      {alert.get('tenant_id')}\n"
        f"  agent:       {alert.get('agent_id')}\n"
        f"  alias:       {alert.get('alias')}\n"
        f"  correlation: {alert.get('correlation_id')}\n"
        f"  worm_seq:    {alert.get('worm_sequence')}"
    )


# --------------------------------------------------------------------------- the daemon


class ResponsePlaybook:
    """
    The off-hot-path daemon: poll the WORM buffer for new trigger-worthy deny events, and
    for each agent that meets the deterministic policy — once per cooldown — record a signed
    incident, freeze the agent, and alert every configured channel. Constructed ONLY when at
    least one action is possible (auto-quarantine on OR a channel present; the composition
    root enforces that).

    The boot cursor anchors at the CURRENT stream tail (``stream_tail_id``), so a restart
    only ever responds to events NEWER than boot — never a replay of the whole audit history.
    """

    def __init__(
        self,
        *,
        worm_getter: Callable[[], WormLogger],
        quarantine_getter: Callable[[], QuarantineFn],
        redis_getter: Callable[[], "redis.Redis"],
        cfg: ResponseConfig,
        slack: Optional[SlackChannel],
        email: Optional[EmailChannel],
        interval_s: float,
    ) -> None:
        # Getters (not captured objects) so a Redis rebind — which rebuilds the WormLogger and
        # the QuarantineStore — is always reflected, never a stale reader/actor.
        self._worm_getter = worm_getter
        self._quarantine_getter = quarantine_getter
        self._redis_getter = redis_getter
        self._cfg = cfg
        self._slack = slack
        self._email = email
        self._has_channel = slack is not None or email is not None
        self._interval_s = max(
            MIN_RESPONSE_INTERVAL_S, min(MAX_RESPONSE_INTERVAL_S, interval_s)
        )
        self._cursor: Optional[str] = None  # resolved to the stream tail on first poll.
        # Coarse in-memory posture for the admin stats read (never a metric label, no secret).
        self.last_action: Optional[float] = None
        self.last_result: str = "never"

    @property
    def interval_s(self) -> float:
        """The clamped poll cadence (seconds)."""
        return self._interval_s

    def status(self) -> dict[str, Any]:
        """Coarse, secret-free posture for ``GET /v1/admin/stats`` — never a label."""
        return {
            "status": "enabled",
            "auto_quarantine": self._cfg.auto_quarantine,
            "channels": {"slack": self._slack is not None, "email": self._email is not None},
            "triggers": sorted(self._cfg.trigger_reasons),
            "burst_threshold": self._cfg.burst_threshold,
            "interval_seconds": self._interval_s,
            "last_action": self.last_action,
            "last_result": self.last_result,
        }

    async def poll_once(self) -> None:
        """
        One poll: resolve the boot cursor if needed, scan for new triggers, and respond to
        each that meets the policy. NEVER raises — the caller is an interval task off the hot
        path; any unexpected error is swallowed and retried next tick.
        """
        try:
            worm = self._worm_getter()
            if self._cursor is None:
                self._cursor = await worm.stream_tail_id()
                return  # first tick only anchors — respond to events strictly AFTER boot.
            result = await worm.scan_alerts(
                self._cursor,
                self._cfg.trigger_reasons,
                limit=MAX_RESPONSE_ACTIONS_PER_TICK,
                scan=MAX_RESPONSE_SCAN,
            )
            if result.get("error"):
                RESPONSE.labels("scan_error").inc()
            self._cursor = str(result.get("cursor", self._cursor))
            for alert in result.get("alerts", []):
                RESPONSE.labels("matched").inc()
                await self._consider(alert)
        except Exception:  # noqa: BLE001 — a playbook failure is never observable to a decision.
            return

    async def _consider(self, alert: dict[str, Any]) -> None:
        """Apply the deterministic policy to one scanned deny; respond if it is due."""
        tenant = alert.get("tenant_id")
        agent = alert.get("agent_id")
        reason = alert.get("deny_reason")
        if not (isinstance(tenant, str) and isinstance(agent, str) and isinstance(reason, str)):
            return  # cannot act without a concrete subject + reason.
        try:
            count = await self._bump_window(tenant, agent, reason)
            plan = decide_response(
                reason, count, cfg=self._cfg, has_channel=self._has_channel
            )
            if plan is None:
                RESPONSE.labels("skipped").inc()
                return
            if not await self._claim(tenant, agent, reason):
                RESPONSE.labels("skipped").inc()  # already handled within the cooldown.
                return
            await self._respond(alert, tenant, agent, reason, plan)
        except Exception:  # noqa: BLE001 — swallow; the next matching event retries.
            return

    async def _bump_window(self, tenant: str, agent: str, reason: str) -> int:
        """Deterministic per-agent fixed-window deny count (INCR, EXPIRE on first hit)."""
        key = f"mcpip:response:win:{tenant}:{agent}:{reason}"
        client = self._redis_getter()
        count = int(await client.incr(key))
        if count == 1:
            await client.expire(key, RESPONSE_BURST_WINDOW_S)
        return count

    async def _claim(self, tenant: str, agent: str, reason: str) -> bool:
        """Win the once-per-cooldown right to respond (SET NX EX). True iff first responder."""
        key = f"mcpip:response:claim:{tenant}:{agent}:{reason}"
        client = self._redis_getter()
        got = await client.set(key, "1", nx=True, ex=RESPONSE_COOLDOWN_S)
        return bool(got)

    async def _respond(
        self,
        alert: dict[str, Any],
        tenant: str,
        agent: str,
        reason: str,
        plan: ResponsePlan,
    ) -> None:
        """Record the incident (before acting), then freeze + alert per the plan."""
        RESPONSE.labels("responded").inc()
        actions = [
            a for a, on in (("quarantine", plan.quarantine), ("notify", plan.notify)) if on
        ] or ["record"]
        # Write-before-execute: seal the incident before the freeze / alert.
        await self._emit_incident(alert, tenant, agent, reason, actions)
        if plan.quarantine:
            await self._quarantine(tenant, agent, alert)
        if plan.notify:
            await self._notify(alert, plan)
        self.last_action = time.time()
        self.last_result = "ok"

    async def _emit_incident(
        self,
        alert: dict[str, Any],
        tenant: str,
        agent: str,
        reason: str,
        actions: list[str],
    ) -> None:
        """Emit a signed WORM ``admin_action='response_action'`` — whitelist-safe, best-effort.

        The record leads the action (write-before-execute). If the append hiccups the freeze
        still proceeds (safety-first for a tripped agent) and the miss is counted — the
        automation never leaves a triggered agent un-frozen because one audit write failed.
        """
        try:
            await self._worm_getter().emit(
                {
                    "decision": "admin_action",
                    "admin_action": "response_action",
                    "deny_reason": None,
                    "tenant_id": tenant,
                    "subject_agent_id": agent,
                    "trigger_reason": reason,
                    "alias": alert.get("alias"),
                    "actions": actions,
                    "correlation_id": alert.get("correlation_id"),
                }
            )
            RESPONSE.labels("incident").inc()
        except Exception:  # noqa: BLE001 — best-effort; the freeze proceeds regardless.
            RESPONSE.labels("incident_error").inc()

    async def _quarantine(self, tenant: str, agent: str, alert: dict[str, Any]) -> None:
        """Freeze the (tenant, agent). Idempotent — a re-freeze (or the pipeline's own canary
        freeze) is harmless; the store just refreshes the TTL-bounded mark."""
        try:
            await self._quarantine_getter()(
                tenant_id=tenant,
                agent_id=agent,
                correlation_id=str(alert.get("correlation_id") or ""),
                tripped_alias=str(alert.get("alias") or alert.get("deny_reason") or "response"),
            )
            RESPONSE.labels("quarantined").inc()
        except Exception:  # noqa: BLE001 — best-effort; a lost freeze never crashes the daemon.
            return

    async def _notify(self, alert: dict[str, Any], plan: ResponsePlan) -> None:
        """Send one whitelist-projected alert to every configured channel (best-effort)."""
        text = _format_alert(alert, plan)
        ok = False
        if self._slack is not None:
            ok = await self._slack.send(text) or ok
        if self._email is not None:
            ok = await self._email.send("MCPIP deny-response", text) or ok
        if ok:
            RESPONSE.labels("notified").inc()
        else:
            RESPONSE.labels("notify_error").inc()

    async def run(self) -> None:
        """
        The lifespan interval loop: poll, then sleep the clamped cadence. Cancellation
        (shutdown) propagates out of the sleep — ``poll_once`` swallows only ``Exception``,
        and ``CancelledError`` is a ``BaseException``, so it is never absorbed.
        """
        while True:
            await self.poll_once()
            await asyncio.sleep(self._interval_s)


__all__ = [
    "EmailChannel",
    "ResponseConfig",
    "ResponsePlan",
    "ResponsePlaybook",
    "SlackChannel",
    "decide_response",
]
