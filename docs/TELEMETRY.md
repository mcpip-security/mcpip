# MCPIP — Opt-in Vendor Telemetry

> **TL;DR.** MCPIP can tell the **vendor** (the org that ships MCPIP) *which
> deployments are running it*, *what license tier they hold*, and *live aggregate
> numbers* — **without ever surveilling the agent wire**. It is **OFF by default**,
> **opt-in**, **privacy-by-design**, and an **air-gapped / sandbox deployment never
> phones home**. The **client** is the org running MCPIP; the **end user / agent is
> NEVER tracked**.

This is the one place MCPIP is allowed to talk to the vendor, and it is deliberately
the narrowest possible channel: a periodic, best-effort **beacon** of a **closed set of
aggregate counters**, plus a **local** admin read (`GET /v1/admin/stats`) that shows an
operator their own live numbers with no network at all.

---

## The privacy boundary (the single most important rule)

The beacon body is a **CLOSED set of EXACTLY eight fields**. Nothing else ever leaves
the box:

| Field | What it is | What it is NOT |
|---|---|---|
| `install_id` | A random hex token generated **once** and persisted (`.keys/mcpip_install_id`). | **NOT** derived from any tenant / customer / host / license identity. It identifies the *install*, nothing about who runs it or what it governs. |
| `license_tier` | The boot-verified license tier (`cloud` / `self-hosted` / `air-gapped`), or `"unlicensed"`. | Read-only; the beacon performs **no** license refresh and adds **no** trust root. |
| `license_id` | The boot-verified license id, or `null`. | — |
| `version` | The running MCPIP version. | — |
| `governed_agent_identity_count` | A single **integer CARDINALITY** of distinct governed agent identities (a Redis HyperLogLog `PFCOUNT`). | **NEVER** the set of agent ids. The ids live only inside the HLL registers and are never read back. |
| `decisions` | Coarse totals `{allow, deny, staged}` — the **SAME closed enum** as `core/metrics.py` `DECISIONS`. | Never a per-tenant, per-alias, or per-reason breakdown. |
| `uptime_seconds` | Monotonic process uptime. | — |
| `sent_at` | UTC ISO-8601 timestamp. | — |

The body **MUST NEVER** contain a tenant id, agent id, alias, target, capability,
compartment, correlation id, secret, payload, argument, or any per-tenant breakdown.
**Only aggregate integers ever leave the box.** This is the identical opacity discipline
as the closed-enum metric labels in `core/metrics.py` — a leak here would break the
product's headline promise.

A test (`tests/test_telemetry.py::test_beacon_payload_is_closed_eight_field_set`)
asserts the serialized body's key set is *exactly* those eight fields and scans the bytes
for any request-identifying string.

**Signature/timestamp ride only as HEADERS**, never in the body:
`X-MCPIP-Telemetry-Signature: sha256=<hmac>` over `timestamp + "." + body`, plus
`X-MCPIP-Timestamp`, using a per-install HMAC-SHA256 secret
(`.keys/mcpip_telemetry_secret`) so the vendor can trust the origin.

---

## How to turn it on (and the air-gap / opt-in guarantees)

| Setting (env) | Default | Meaning |
|---|---|---|
| `MCPIP_TELEMETRY_ENABLED` | `false` | **OPT-IN.** Off by default. |
| `MCPIP_TELEMETRY_URL` | `null` | HTTPS endpoint of the vendor receiver. |
| `MCPIP_TELEMETRY_INTERVAL_S` | `3600` | Beacon cadence, clamped to `[MIN_TELEMETRY_INTERVAL_S, MAX_TELEMETRY_INTERVAL_S]`. |

Rules, all enforced at the composition root (`app/main.py::_build_telemetry_beacon`):

- **Default OFF.** With the flag unset/false, **no beacon task is scheduled** and **no
  install-id/secret file is ever minted**. The hot path is byte-identical to a build
  without this feature.
- **Air-gap / sandbox never phones home.** In `MCPIP_SANDBOX_MODE=true`, the beacon is
  **structurally disabled** even with the flag on — **and no telemetry identity is ever
  minted**. An offline/air-gapped deployment therefore never even creates
  `.keys/mcpip_install_id`. (Air-gap wins over the flag; this is not an error.)
- **Half-config fails boot.** `MCPIP_TELEMETRY_ENABLED=true` **without**
  `MCPIP_TELEMETRY_URL` is a **fail-closed BOOT error** — the same posture as the
  authenticator-webhook / external-PDP / integrity / license half-configs. Silently
  dropping a beacon the operator turned on would be dishonest about whether the vendor is
  being told anything.

`.keys/` is gitignored; the install id and secret persist across restarts so the vendor
sees a **stable** install, and are created **once** (0600, `O_EXCL`).

---

## Fail-open, off the hot path — it can NEVER affect a decision

The beacon is **best-effort** and runs **off the authorization hot path**, exactly like
the epoch-gauge daemon / the forensic capture side-channel:

- The **sender** is **one lifespan interval task**. Every send failure (disabled,
  air-gap, DNS failure, SSRF-block, non-2xx, timeout) is **caught and dropped** to
  `mcpip_telemetry_total{event="send_error"}`. It can **never block, delay, reorder, or
  flip** an authorization decision. It is *never* called synchronously on `/v1/authorize`.
- The **on-path recorders** — `record_agent` (a HyperLogLog `PFADD` right after identity
  resolution, timing-uniform across aliases/compartments) and `record_decision` (an
  `INCR` beside each determined outcome, tenant-attributable only) — are **cheap,
  swallow-only side effects**. A Redis hiccup bumps
  `mcpip_telemetry_total{event="record_error"}` and returns; it **cannot fail a decision**.
  A purely-unauthenticated deny (bad JWT / no tenant) is not tenant-attributable and is
  **honestly excluded** from the per-tenant count.

`mcpip_telemetry_total{event}` uses a **closed enum** — `sent` / `send_error` / `skipped`
/ `record_error` — and **never** carries an install-id, tenant, agent, alias, url, or
license id as a label.

---

## Hermetic + SSRF-guarded outbound

The beacon dial-out reuses the **verbatim** discipline of `WebhookAuthenticatorChannel`
/ `auth/jwks_refresher.py` / `services/external_pdp.py` (it lives in `services/`, where
`httpx` is permitted — not `bridge/connectors/`):

1. scheme **MUST be https** (refused at construction otherwise);
2. the host is resolved and **every** resolved address is rejected if private / loopback /
   link-local (covers `169.254.169.254` cloud metadata) / reserved / multicast /
   unspecified (via the reused `services.authn_channel._is_blocked_ip`);
3. the connection is **PINNED to the validated IP** (original hostname drives SNI + cert)
   to defeat DNS-rebinding;
4. **redirects are NOT followed**; connect+read are bounded; the response read is bounded
   (`MAX_TELEMETRY_RESPONSE_BYTES`);
5. the client is **HERMETIC** (`trust_env=False`, `proxy=None`) — no ambient
   `HTTPS_PROXY` / `SSL_CERT_FILE` / `SSLKEYLOGFILE` can reroute or MITM the beacon.

---

## License is READ-only

The beacon reads the already-boot-verified `Components.license` for the `license_tier` /
`license_id` fields **only**. It performs **no** license refresh, adds **no** new trust
root, and never re-verifies or widens anything. The license-root Ed25519 gate and the
boot posture are untouched. (Any future signed-license refresh is a separate, out-of-scope
item.)

---

## The local live-stats read — `GET /v1/admin/stats`

This is what *"see the numbers live"* means **client-side**: the operator's **own**
tenant's REAL running numbers, served **locally** (no beacon, no vendor, no network
needed). It is `CAP_DIRECTORY_ADMIN`-gated (JWT + capability + revocation/quarantine
kill-switch), opaque-deny, and tenant-scoped.

```json
{
  "version": "2.1.0",
  "governed_agent_identity_count": 42,
  "decisions": { "allow": 1201, "deny": 88, "staged": 17 },
  "license": { "licensed": false },
  "telemetry": { "status": "air-gap", "last_sent": null, "last_result": "never" }
}
```

- Numbers are the caller's tenant HLL `PFCOUNT` + real decision totals — **never
  fabricated**; a fresh tenant gets honest zeros.
- `license` mirrors `GET /v1/license` (honest `{"licensed": false}` when absent).
- `telemetry.status` is honest: `air-gap` (sandbox — structurally disabled, no identity
  minted), `enabled` (beacon live; also surfaces coarse `last_sent` / `last_result` —
  `never` until the first send), or `disabled` (opt-out / unconfigured production).
- **No tenant/agent/alias/target** is ever exposed — only the caller's **own** aggregate
  integers cross this admin boundary.

### Client surfaces over `/v1/admin/stats` (SDK · CLI · console)

The same local read is wired through every operator surface — REAL numbers or an honest
disabled/air-gap/empty state, **never** a fabricated client, number, or "connected" badge:

| Surface | How |
|---|---|
| **Python SDK** | `MCPIPAdminClient.stats()` → `DeploymentStats` (`governed_agent_identity_count`, `decisions`, `license`, `telemetry` with `.enabled` / `.air_gapped`, `version`). |
| **TypeScript SDK** | `McpipAdminClient.stats()` → `DeploymentStats` (same shape). |
| **`mcpip` CLI** | `mcpip admin stats` (human block) / `mcpip admin stats --json` (the raw aggregate); `--quiet` prints just the governed-agent cardinality. |
| **Operator console** | Gateway → **Updates & License** → the *"Deployment · License & Usage"* panel reads `GET /v1/admin/stats` live: the governed-agent count, allow/deny/staged totals, license tier/status, the telemetry `enabled` / `disabled` / `air-gap` posture + last-sent, and the version. Offline/unauthorized renders an honest empty state (no fixture). |

All are `CAP_DIRECTORY_ADMIN`-gated, tenant-scoped, opaque-deny — and read the caller's
own aggregates only.

---

## The vendor-side receiver is OUT OF SCOPE

This deployment **ships the emitter only**. The vendor-side receiver — the service that
ingests beacons, deduplicates by `install_id`, verifies the HMAC signature, and renders
the fleet view — is **specced here, not built here**. A reference receiver must:

- verify `X-MCPIP-Telemetry-Signature` against the per-install secret (origin trust);
- treat `install_id` as an opaque install handle (never attempt to re-identify a
  customer/host from it);
- store **only** the eight aggregate fields — it receives nothing else;
- be resilient to a deployment that opts out (silence is a valid, expected state).

---

## Where it lives

| Piece | File |
|---|---|
| `TelemetryStats` (HLL cardinality + decision counters, best-effort) + `TelemetryBeacon` (hermetic SSRF-guarded POST) | `services/telemetry.py` |
| Settings (`telemetry_enabled` / `telemetry_url` / `telemetry_interval_s`) | `core/config.py` |
| Hard limits (`MIN/MAX_TELEMETRY_INTERVAL_S`, `MAX_TELEMETRY_RESPONSE_BYTES`, `MAX_TELEMETRY_TENANTS`) | `interfaces.py` |
| Closed-enum counter `mcpip_telemetry_total{event}` | `core/metrics.py` |
| Wiring (`Components.telemetry_stats` / `.telemetry`, `_build_telemetry_beacon`, `_load_or_create_install_identity`, on-path recorders, `GET /v1/admin/stats`) | `app/main.py` |
| Tests | `tests/test_telemetry.py` |
