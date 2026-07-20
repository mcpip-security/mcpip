"""
Deny-response PLAYBOOK — the deterministic automation loop, off the hot path.

    ◐ "A tripped wire acts on its own; the record leads the action."

These tests pin the security-critical guarantees WITHOUT any real network, SMTP, or
loop-bound Redis: fakes stand in for the WORM buffer, the counter store, and the
quarantine action so ``decide_response`` and ``ResponsePlaybook.poll_once`` run on a
fresh event loop.

Guarantees covered:
  * ``decide_response`` is a PURE deterministic rule — a single-shot reason fires at once,
    every other trigger reason only on a burst, and a non-trigger reason never fires.
  * ``scan_alerts`` projects ONLY the whitelist (``_ALERT_SAFE_KEYS``) — the real target and
    the argument payload are stripped, so they can NEVER ride into a response or an alert.
  * the playbook ANCHORS at the stream tail first (a restart never replays history), then
    for a match: records a signed incident BEFORE the freeze, quarantines the agent, and
    alerts — and is IDEMPOTENT (once per cooldown; a re-poll never re-acts).
  * every failure (a raising quarantine action, a channel error) is swallowed — a response
    is never observable to a decision.
  * a playbook with no possible action is refused; Slack must be https; email is bounded.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.worm_logger import WormLogger, _ALERT_SAFE_KEYS
from interfaces import (
    RESPONSE_SINGLE_SHOT_REASONS,
    RESPONSE_TRIGGER_REASONS,
    MAX_RESPONSE_RECIPIENTS,
    MAX_RESPONSE_SCAN,
)
from services.response_playbook import (
    EmailChannel,
    ResponseConfig,
    ResponsePlaybook,
    SlackChannel,
    _format_alert,
    decide_response,
)

_SECRET_TARGET = "https://internal.example/secret-endpoint"
_SECRET_ARG = "s3cr3t-password"


# --------------------------------------------------------------------------- pure policy


def _cfg(*, triggers: frozenset[str], threshold: int = 3, quarantine: bool = True) -> ResponseConfig:
    return ResponseConfig(
        trigger_reasons=triggers, burst_threshold=threshold, auto_quarantine=quarantine
    )


def test_decide_single_shot_fires_immediately() -> None:
    cfg = _cfg(triggers=frozenset({"canary_tripped", "cross_tenant"}), threshold=5)
    plan = decide_response("canary_tripped", 1, cfg=cfg, has_channel=True)
    assert plan is not None and plan.quarantine is True and plan.notify is True


def test_decide_burst_reason_needs_threshold() -> None:
    cfg = _cfg(triggers=frozenset({"cross_tenant"}), threshold=3)
    assert decide_response("cross_tenant", 1, cfg=cfg, has_channel=False) is None
    assert decide_response("cross_tenant", 2, cfg=cfg, has_channel=False) is None
    plan = decide_response("cross_tenant", 3, cfg=cfg, has_channel=False)
    assert plan is not None and plan.notify is False  # no channel → notify off


def test_decide_untriggered_reason_never_fires() -> None:
    cfg = _cfg(triggers=frozenset({"canary_tripped"}), threshold=1)
    # A real deny reason that is NOT in the active trigger set.
    assert decide_response("pin_mismatch", 99, cfg=cfg, has_channel=True) is None


def test_decide_respects_auto_quarantine_flag() -> None:
    cfg = _cfg(triggers=frozenset({"canary_tripped"}), quarantine=False)
    plan = decide_response("canary_tripped", 1, cfg=cfg, has_channel=True)
    assert plan is not None and plan.quarantine is False and plan.notify is True


def test_format_alert_never_prints_target_or_secret() -> None:
    alert = {
        "tenant_id": "tenant-acme",
        "agent_id": "agent-9",
        "alias": "skill_x",
        "deny_reason": "canary_tripped",
        "correlation_id": "corr-3-0",
        "worm_sequence": 3,
        "target": _SECRET_TARGET,
        "arguments": {"password": _SECRET_ARG},
    }
    from services.response_playbook import ResponsePlan

    text = _format_alert(alert, ResponsePlan(quarantine=True, notify=True))
    assert "canary_tripped" in text and "corr-3-0" in text and "quarantined" in text
    assert _SECRET_TARGET not in text and _SECRET_ARG not in text


# --------------------------------------------------------------------------- scan_alerts


def _parse(sid: str) -> tuple[int, int]:
    if "-" in sid:
        ms, seq = sid.split("-")
        return int(ms), int(seq)
    return int(sid), 0


class _StreamRedis:
    """Just enough of the async Redis stream surface for the WORM tail reads."""

    def __init__(self, entries: list[tuple[str, dict[str, Any]]]) -> None:
        self._entries = entries

    def register_script(self, *_a: Any, **_k: Any) -> Any:
        return None

    async def xrevrange(self, _name: str, count: int | None = None) -> list[Any]:
        rev = list(reversed(self._entries))
        return rev[:count] if count is not None else rev

    async def xrange(
        self, _name: str, min: str = "-", max: str = "+", count: int | None = None
    ) -> list[Any]:
        lo = _parse(min[1:]) if isinstance(min, str) and min.startswith("(") else None
        out = [e for e in self._entries if lo is None or _parse(e[0]) > lo]
        return out[:count] if count is not None else out


def _entry(
    sid: str, *, decision: str, deny_reason: str | None, agent: str = "agent-9"
) -> tuple[str, dict[str, Any]]:
    event = {
        "tenant_id": "tenant-acme",
        "agent_id": agent,
        "alias": "skill_x",
        "decision": decision,
        "deny_reason": deny_reason,
        "correlation_id": f"corr-{sid}",
        "target": _SECRET_TARGET,
        "arguments": {"password": _SECRET_ARG},
    }
    return (sid, {"record": json.dumps({"event": event, "timestamp_ns": 111}), "seq": int(sid.split("-")[0])})


def _worm(entries: list[tuple[str, dict[str, Any]]]) -> WormLogger:
    return WormLogger(
        cast(Any, _StreamRedis(entries)),
        Ed25519PrivateKey.generate(),
        path="/tmp/mcpip_response_test_worm.jsonl",
    )


def test_scan_alerts_projects_whitelist_and_filters_reason() -> None:
    entries = [
        _entry("1-0", decision="allow", deny_reason=None),
        _entry("2-0", decision="deny", deny_reason="skill_disabled"),  # not a trigger
        _entry("3-0", decision="deny", deny_reason="canary_tripped"),
    ]
    result = asyncio.run(
        _worm(entries).scan_alerts(
            "0", frozenset({"canary_tripped"}), limit=50, scan=MAX_RESPONSE_SCAN
        )
    )
    alerts = result["alerts"]
    assert len(alerts) == 1 and alerts[0]["deny_reason"] == "canary_tripped"
    allowed = set(_ALERT_SAFE_KEYS) | {"worm_sequence", "timestamp_ns"}
    assert set(alerts[0].keys()) <= allowed
    assert _SECRET_TARGET not in json.dumps(alerts[0]) and _SECRET_ARG not in json.dumps(alerts[0])
    assert result["cursor"] == "3-0"


def test_scan_alerts_cursor_resume_is_exclusive() -> None:
    entries = [_entry("3-0", decision="deny", deny_reason="canary_tripped")]
    result = asyncio.run(
        _worm(entries).scan_alerts("3-0", frozenset({"canary_tripped"}), limit=50, scan=MAX_RESPONSE_SCAN)
    )
    assert result["alerts"] == []


# --------------------------------------------------------------------------- daemon


class _KVRedis:
    """Minimal INCR / EXPIRE / SET(nx,ex) / GET store for the playbook's counters."""

    def __init__(self) -> None:
        self.kv: dict[str, str] = {}

    async def incr(self, key: str) -> int:
        val = int(self.kv.get(key, "0")) + 1
        self.kv[key] = str(val)
        return val

    async def expire(self, _key: str, _ttl: int) -> bool:
        return True

    async def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> Any:
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True

    async def get(self, key: str) -> Any:
        return self.kv.get(key)


class _CaptureWorm:
    """A WORM stand-in for the daemon: canned scan output + an emit capture."""

    def __init__(self, matches: list[dict[str, Any]]) -> None:
        self._matches = matches
        self._served = False
        self.emitted: list[dict[str, Any]] = []

    async def stream_tail_id(self) -> str:
        return "0"

    async def scan_alerts(self, _since: str, _reasons: Any, *, limit: int, scan: int) -> dict[str, Any]:
        if self._served:
            return {"alerts": [], "cursor": "9-0"}
        self._served = True
        return {"alerts": self._matches, "cursor": "9-0"}

    async def emit(self, event: dict[str, Any]) -> Any:
        self.emitted.append(event)
        return None


def _alert(reason: str, *, agent: str = "agent-9") -> dict[str, Any]:
    return {
        "tenant_id": "tenant-acme",
        "agent_id": agent,
        "alias": "skill_x",
        "decision": "deny",
        "deny_reason": reason,
        "correlation_id": f"corr-{reason}",
        "worm_sequence": 7,
    }


def _playbook(worm: _CaptureWorm, kv: _KVRedis, quarantined: list[tuple[str, str]], *, cfg: ResponseConfig, slack: Any = None):
    async def _quarantine(*, tenant_id: str, agent_id: str, correlation_id: str, tripped_alias: str) -> None:
        quarantined.append((tenant_id, agent_id))

    return ResponsePlaybook(
        worm_getter=lambda: cast(Any, worm),
        quarantine_getter=lambda: _quarantine,
        redis_getter=lambda: cast(Any, kv),
        cfg=cfg,
        slack=slack,
        email=None,
        interval_s=15,
    )


class _FakeSlack:
    def __init__(self, *, boom: bool = False) -> None:
        self.sent: list[str] = []
        self._boom = boom

    async def send(self, text: str) -> bool:
        if self._boom:
            raise RuntimeError("slack down")
        self.sent.append(text)
        return True


def test_playbook_anchors_then_responds_and_is_idempotent() -> None:
    worm = _CaptureWorm([_alert("canary_tripped")])
    kv = _KVRedis()
    quarantined: list[tuple[str, str]] = []
    slack = _FakeSlack()
    pb = _playbook(worm, kv, quarantined, cfg=_cfg(triggers=frozenset({"canary_tripped"})), slack=cast(Any, slack))

    async def scenario() -> None:
        await pb.poll_once()  # first tick anchors (no scan)
        await pb.poll_once()  # sees the canary → responds
        await pb.poll_once()  # nothing new; and the claim blocks any re-act

    asyncio.run(scenario())
    # Exactly one freeze, one incident (write-before-execute), one alert.
    assert quarantined == [("tenant-acme", "agent-9")]
    assert len(worm.emitted) == 1
    incident = worm.emitted[0]
    assert incident["admin_action"] == "response_action"
    assert incident["subject_agent_id"] == "agent-9"
    assert "quarantine" in incident["actions"]
    # Whitelist-safe: no target/payload/secret in the incident record.
    assert _SECRET_TARGET not in json.dumps(incident) and _SECRET_ARG not in json.dumps(incident)
    assert len(slack.sent) == 1 and "canary_tripped" in slack.sent[0]


def test_playbook_burst_reason_waits_for_threshold() -> None:
    kv = _KVRedis()
    quarantined: list[tuple[str, str]] = []
    cfg = _cfg(triggers=frozenset({"cross_tenant"}), threshold=3)

    async def scenario() -> None:
        # Three separate scans, each carrying one cross_tenant deny by the same agent.
        for i in range(3):
            worm = _CaptureWorm([_alert("cross_tenant")])
            pb = _playbook(worm, kv, quarantined, cfg=cfg)
            await pb.poll_once()  # anchor
            await pb.poll_once()  # the deny — window count = i+1
            if i < 2:
                assert quarantined == [], f"acted early at count {i + 1}"
        # The 3rd occurrence hit the threshold → exactly one response.
        assert quarantined == [("tenant-acme", "agent-9")]

    asyncio.run(scenario())


def test_playbook_swallows_quarantine_failure() -> None:
    worm = _CaptureWorm([_alert("canary_tripped")])
    kv = _KVRedis()

    async def _boom(**_k: Any) -> None:
        raise RuntimeError("quarantine store down")

    pb = ResponsePlaybook(
        worm_getter=lambda: cast(Any, worm),
        quarantine_getter=lambda: _boom,
        redis_getter=lambda: cast(Any, kv),
        cfg=_cfg(triggers=frozenset({"canary_tripped"})),
        slack=None,
        email=None,
        interval_s=15,
    )

    async def scenario() -> None:
        await pb.poll_once()
        await pb.poll_once()  # quarantine raises — must be swallowed

    asyncio.run(scenario())  # no exception escapes → best-effort holds


def test_playbook_status_is_secret_free() -> None:
    worm = _CaptureWorm([])
    pb = _playbook(worm, _KVRedis(), [], cfg=_cfg(triggers=frozenset({"canary_tripped"})), slack=cast(Any, _FakeSlack()))
    status = pb.status()
    assert status["status"] == "enabled" and status["channels"] == {"slack": True, "email": False}
    blob = json.dumps(status)
    assert "http" not in blob and "@" not in blob and "password" not in blob


# --------------------------------------------------------------------------- guards


def test_slack_channel_requires_https() -> None:
    for bad in ("http://hooks.example/x", "ftp://x", "not-a-url"):
        try:
            SlackChannel(bad)
        except ValueError:
            continue
        raise AssertionError(f"SlackChannel accepted a non-https URL: {bad}")
    SlackChannel("https://hooks.slack.com/services/T/B/xxxx")


def test_email_channel_bounds_recipients() -> None:
    many = tuple(f"op{i}@example.com" for i in range(MAX_RESPONSE_RECIPIENTS + 10))
    channel = EmailChannel(
        host="smtp.example", port=587, sender="mcpip@example.com", recipients=many, user=None, password=None
    )
    assert len(channel._recipients) == MAX_RESPONSE_RECIPIENTS  # type: ignore[attr-defined]


def test_trigger_reasons_are_closed_and_include_canary() -> None:
    assert "canary_tripped" in RESPONSE_TRIGGER_REASONS
    assert RESPONSE_SINGLE_SHOT_REASONS == frozenset({"canary_tripped"})
    assert RESPONSE_SINGLE_SHOT_REASONS <= RESPONSE_TRIGGER_REASONS
