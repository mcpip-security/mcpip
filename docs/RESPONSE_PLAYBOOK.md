# Deny-Response Playbook — the deterministic automation loop

> ◐ *"A tripped wire should not wait for a human to notice."*

The response playbook is MCPIP's **automation counterpart to inline enforcement**. The
pipeline decides and blocks in the hot path; the playbook closes the loop *after* the fact
— it watches the durable audit record for high-signal deny patterns and responds
automatically: it **freezes** the offending agent and **alerts** operators, recording every
response as a signed WORM incident.

It exists because today the gateway auto-quarantines on exactly one signal — a canary trip,
inside the pipeline. The playbook generalizes that deterministic response to **any configured
deny pattern** (for example a burst of `payload_mismatch` or `cross_tenant` probes from one
agent), which nothing does today, without adding a probabilistic detector to the decision
path.

It is **opt-in and OFF by default**, and — this is the whole point — **deterministic**. It
never runs a model, a score, or a heuristic. That is the line between MCPIP and the
detection-and-response products it is often compared to: their automation reacts to a
behavioral anomaly baseline; MCPIP's reacts to a verified deny reason and a deterministic
count.

## What it is not

- **Not a detector.** The trigger is a `deny` event whose reason is in a closed allow-set,
  plus a deterministic per-agent fixed-window count — never inferred intent.
- **Not on the hot path.** It reads already-committed WORM records on an interval. It holds
  no lock the decision path takes and can never block, delay, reorder, or flip an
  authorization. Every failure is swallowed to a metric.
- **Not a new egress of secrets.** The alert body and the incident record carry only the
  operator-safe projection — tenant / agent / alias / reason / correlation. No target, no
  payload, no PIN/OTP, ever.

## How it works

```
 WORM buffer  ──tail (XRANGE, off hot path)──▶  deny event in the trigger set?
      │                                                │ yes
      │                                       per-agent fixed-window count (INCR)
      │                                                │
      │                          decide_response(reason, count) — PURE, deterministic
      │                                                │ respond
      │                          claim once-per-cooldown (SET NX EX)  ──already? skip
      │                                                │ first responder
      │              ┌─────────────────────────────────┼──────────────────────────┐
      ▼              ▼ write-before-execute             ▼ deterministic action      ▼ best-effort
  (unchanged)   signed WORM incident            quarantine (freeze the agent)   Slack / email alert
                (admin_action=response_action)   idempotent TTL mark             whitelist projection
```

1. **Anchor.** On boot the daemon anchors at the current stream tail, so a restart only ever
   responds to events newer than boot — never a replay of the whole audit history.
2. **Tail.** Each interval it forward-scans the durable buffer (`WormLogger.scan_alerts`,
   bounded) for new `deny` events whose reason is in the active trigger set.
3. **Decide.** `decide_response` (a pure function) fires for a single-shot reason
   (`canary_tripped`) on the first occurrence, and for every other trigger reason only once
   the agent's in-window deny count reaches `response_burst_threshold`.
4. **Claim.** A `SET NX EX` claim makes the response idempotent — at most once per
   `(tenant, agent, reason)` within `RESPONSE_COOLDOWN_S`, so a redeploy or a repeated probe
   never re-storms the operator.
5. **Respond.** The signed WORM incident is emitted **before** the action (write-before-
   execute). A protective freeze still proceeds if that append hiccups (safety-first for a
   tripped agent), and the miss is counted. Then the agent is quarantined (idempotent with
   the pipeline's own canary freeze) and every configured channel is alerted.

## Configuration (all `MCPIP_`-prefixed, OFF by default)

| Setting | Default | Meaning |
|---|---|---|
| `RESPONSE_ENABLED` | `false` | Master switch. |
| `RESPONSE_INTERVAL_S` | `30` | Poll cadence, clamped to `[15, 3600]`. |
| `RESPONSE_AUTO_QUARANTINE` | `true` | Freeze the offending agent on a triggered response. |
| `RESPONSE_BURST_THRESHOLD` | `5` | In-window deny count for a non-single-shot reason. |
| `RESPONSE_TRIGGER_REASONS` | *(canary only)* | Comma list, a subset of the closed allow-set. |
| `RESPONSE_SLACK_WEBHOOK_URL` | — | Optional https Slack/Mattermost webhook. |
| `RESPONSE_EMAIL_HOST` / `_PORT` / `_FROM` / `_TO` / `_USER` / `_PASSWORD` | — | Optional SMTP alert channel (host+from+to required together). |

The **closed** trigger allow-set (an operator can never widen beyond it):
`canary_tripped`, `identity_injection`, `cross_tenant`, `compartment_denied`,
`payload_mismatch`, `pin_mismatch`, `sender_constraint_required`, `unknown_alias`.
`canary_tripped` is the only single-shot reason; the rest need a burst.

**Fail-closed config.** `RESPONSE_ENABLED` with no possible action (auto-quarantine off *and*
no channel) is a boot error, as is a trigger reason outside the allow-set or a half-configured
email channel — the same discipline as the authenticator-webhook / telemetry half-config
refusals. A playbook that can do nothing, or that silently drops a rule, is a misconfiguration,
not a no-op.

## Posture & observability

- `GET /v1/admin/stats` reports a coarse, secret-free `response_playbook` posture (enabled/
  disabled, auto-quarantine flag, channels on/off, active triggers, cadence, and the in-memory
  `last_action` / `last_result`). No webhook URL, SMTP password, tenant, agent, or target is
  ever exposed there or in a metric label.
- The closed-enum `mcpip_response_total{event}` counter tracks matches, responses,
  quarantines, notifications, incident emits, and per-channel outcomes — caller-data-free.
- Every response is a WORM `admin_action='response_action'` record, visible in the operator
  decision feed like any other admin action.

## Where it sits vs. detection-and-response

Identity/NHI detection-and-response platforms automate the same *shape* — watch, then react
— but their trigger is a behavioral baseline (probabilistic, model-driven) and they act from
out of band. The response playbook is the deterministic-enforcement analog: a verified deny
reason and a fixed count drive a bounded, idempotent, WORM-audited response. It **composes
with** an identity-governance plane (let its inventory feed which agents exist); it does not
try to become an anomaly detector — that stays out of scope by design.

## Roadmap (next increments)

- **Credential rotation** as a response action (rotate the agent's vended STS/vault
  credential on a trigger) — deferred here because it touches the broker/vault vend path.
- **Per-reason action mapping** (notify-only vs quarantine+notify per trigger reason) for
  finer operator control.
