"""
MCPIP V2 — Core: Prometheus metrics (label discipline enforced by construction).

    ◐ "Authorize every AI action before execution."

Every collector lives here so the label vocabulary has ONE auditable source of
truth. Label discipline (normative):

  * ``decision``    ∈ {"allow", "deny", "staged"} — literals at the call sites.
  * ``cause``       ∈ {"overload", "timeout", "oversized", "unauthorized"}.
  * ``event`` (forensic)   ∈ {"captured", "capture_skipped", "capture_error",
                              "read_hit", "read_miss", "read_denied"}.
  * ``event`` (relation)   ∈ {"projected", "project_error", "removed"}.
  * ``event`` (telemetry)  ∈ {"sent", "send_error", "skipped", "record_error"}.
  * ``event`` (license-refresh) ∈ {"refreshed", "verify_failed", "not_newer",
                                   "transport_error"}.

The concrete ``deny_reason`` is DELIBERATELY NOT a metric label. ``/metrics`` is an
UNAUTHENTICATED, agent-reachable surface served on the SAME socket as
``/v1/authorize`` (it is edge-exempt, never gated), so a per-reason decisions counter
would leak the concrete deny reason to any scraper — defeating wire opacity and
turning the counter into a canary / cross-compartment alias-existence oracle
(``deny_reason="canary_tripped"`` / ``"compartment_denied"`` vs ``"unknown_alias"``
incrementing tells the caller exactly which). The concrete reason therefore stays in
the WORM log ONLY (the stated fail-closed-and-opaque invariant); the exported counter
carries just the coarse ``decision`` outcome. An L3/L4 NetworkPolicy cannot confine
``/metrics`` separately from ``/v1/authorize`` on one shared port, so this cannot be
delegated to network topology — the label must simply not exist. If per-reason
operator visibility is ever needed it must live on a SEPARATE registry rendered on a
distinct monitoring-only bind, never on this socket.

NO tenant_id, agent_id, alias, compartment, capability UUID, correlation id,
challenge_id, deny_reason, JWT material, or approval code may EVER appear in a metric
name or label. This is enforced by construction: every label value written anywhere in
the codebase is either a string literal or a coarse closed-enum outcome — never request
data or a concrete deny reason. ``/metrics`` therefore exposes only aggregate counts,
latencies, and audit chain heights, all safe for a shared Prometheus.

Multiprocess: with ``PROMETHEUS_MULTIPROC_DIR`` set (the Dockerfile default for
multi-worker uvicorn), :func:`render_metrics` aggregates across workers via
``multiprocess.MultiProcessCollector``; otherwise it renders the in-process
default ``REGISTRY``.
"""

from __future__ import annotations

import os

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
)

DECISIONS = Counter(
    "mcpip_authorize_decisions_total",
    "Authorization decisions (coarse outcome only — the concrete deny reason is WORM-only)",
    ["decision"],
)

LATENCY = Histogram(
    "mcpip_authorize_latency_seconds",
    "End-to-end /v1/authorize latency",
    ["decision"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 15.0),
)

# cause ∈ {overload, timeout, oversized, unauthorized} — closed set, edge only.
SHED = Counter(
    "mcpip_requests_shed_total",
    "Edge-shed requests",
    ["cause"],
)

# multiprocess_mode="max": chain heights are monotonic, so the aggregate across
# workers is the highest value any worker has observed.
WORM_EPOCH = Gauge(
    "mcpip_worm_epoch",
    "Last sealed audit epoch",
    multiprocess_mode="max",
)

WORM_SEQUENCE = Gauge(
    "mcpip_worm_sequence",
    "Monotonic WORM event sequence height",
    multiprocess_mode="max",
)

# Forensic capture/read side-channel counters. ``event`` is a CLOSED enum of literals —
# never a tenant/agent/alias/correlation_id — so /metrics stays free of caller data. The
# WORM ``admin_action='forensic_read'`` string is audit data, not a metric label, and
# does not appear here (so it can never trip the skill_-substring label-hygiene guard).
FORENSIC = Counter(
    "mcpip_forensic_total",
    "Forensic capture/read side-channel events",
    ["event"],
)


# ReBAC relation-tuple projection counter. ``event`` is a CLOSED enum of literals
# (``projected`` / ``project_error`` / ``removed``) — NEVER a tenant/compartment/agent/
# uuid/correlation_id — so /metrics stays free of caller data. The tuple layer is a
# best-effort projection of already-WORM-logged grant actions; its write/remove outcome
# rides here as an aggregate count only. ``project_error`` covers a swallowed Redis error
# on either the projection write or the best-effort remove (the projection self-heals at
# TTL regardless, so a failed remove is not a distinct alarm).
RELATION_PROJECTION = Counter(
    "mcpip_relation_projection_total",
    "ReBAC relation-tuple projection events (best-effort grant projection)",
    ["event"],
)


# Opt-in vendor-telemetry beacon counters. ``event`` is a CLOSED enum of literals
# (``sent`` / ``send_error`` / ``skipped`` / ``record_error``) — NEVER an install-id,
# tenant, agent, alias, url, license id, or any caller/deployment identifier — so
# /metrics stays free of caller data and the beacon's own opacity discipline is mirrored
# here. ``sent`` = one beacon POST returned 2xx; ``send_error`` = a beacon send failed
# (network / air-gap / SSRF-block / non-2xx / timeout — all swallowed off the hot path);
# ``skipped`` = the beacon was disabled/sandboxed and did nothing; ``record_error`` = a
# best-effort on-path record_agent/record_decision side effect swallowed a Redis error
# (it never fails a decision). The install-id is an OPAQUE beacon-body field, never a label.
TELEMETRY = Counter(
    "mcpip_telemetry_total",
    "Opt-in vendor-telemetry beacon events (best-effort, off the hot path)",
    ["event"],
)


# Opt-in license-REFRESH counters. ``event`` is a CLOSED enum of literals
# (``refreshed`` / ``verify_failed`` / ``not_newer`` / ``identity_mismatch`` /
# ``transport_error``) — NEVER an install-id, tenant, agent, license id, url, or any
# caller/deployment identifier — so /metrics stays free of caller data, the same
# discipline as the telemetry/forensic counters. The refresh runs OFF the hot path (a
# swallowed background daemon), so a refresh outcome is structurally incapable of
# blocking/flipping an authorization.
# ``refreshed`` = a strictly-newer, fully-valid candidate was atomically swapped in;
# ``verify_failed`` = the candidate failed license-root verification (bad/forged/
# wrong-root/expired signature, schema, tier, malformed doc) — last-good retained;
# ``not_newer`` = a valid candidate that was not strictly newer than the running
# license — retained; ``identity_mismatch`` = a valid, newer candidate carried a
# DIFFERENT customer or license_id than the running license (a refresh is a renewal of
# the SAME entitlement, never a cross-customer/cross-license swap — the tenant + license
# separation boundary) — retained; ``transport_error`` = the fetch failed (network /
# air-gap / SSRF-block / non-2xx / oversized body — all swallowed) — retained.
LICENSE_REFRESH = Counter(
    "mcpip_license_refresh_total",
    "Opt-in license-refresh events (best-effort, off the hot path, verify-against-root-only)",
    ["event"],
)


# Opt-in deny-response PLAYBOOK counters. ``event`` is a CLOSED enum of literals — NEVER a
# tenant, agent, alias, reason, url, or any caller/deployment identifier — so /metrics stays
# free of caller data, the same discipline as the telemetry/forensic/license counters. The
# playbook runs OFF the hot path (a swallowed background daemon over already-committed audit
# records), so a response outcome is structurally incapable of blocking/flipping a decision.
# ``matched`` = a deny event in the active trigger set was scanned; ``responded`` = a
# deterministic policy fired a response for one (tenant,agent,reason); ``quarantined`` = the
# agent was frozen; ``notified`` = an alert reached at least one channel; ``incident`` /
# ``incident_error`` = the signed WORM incident emit succeeded / failed; ``skipped`` = a
# match that did not meet the burst threshold or was already handled within the cooldown;
# ``scan_error`` = a WORM read failed (retried next poll); ``slack_sent`` / ``slack_error`` /
# ``email_sent`` / ``email_error`` / ``notify_error`` = per-channel egress outcomes.
RESPONSE = Counter(
    "mcpip_response_total",
    "Opt-in deny-response playbook events (best-effort, off the hot path, deterministic)",
    ["event"],
)


def render_metrics() -> tuple[bytes, str]:
    """
    Render the exposition payload: ``(body_bytes, content_type)``.

    With ``PROMETHEUS_MULTIPROC_DIR`` set, build a fresh ``CollectorRegistry``
    fed by the ``MultiProcessCollector`` so a scrape of ANY worker returns the
    aggregate across all workers; otherwise render the default registry.
    """
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        # prometheus_client ships py.typed but leaves this constructor untyped.
        multiprocess.MultiProcessCollector(registry)  # type: ignore[no-untyped-call]
        return generate_latest(registry), CONTENT_TYPE_LATEST
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
