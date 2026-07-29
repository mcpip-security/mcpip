# ◐ MCPIP — Privacy & Data-Handling Policy

**Version 3.0.0 · Applies to: the MCPIP software distribution.**

MCPIP is **self-hosted software**, not a service. You run it inside your own
boundary, against your own datastore, under your own keys. The practical
consequence is the first and most important statement in this policy:

> **By default, the MCPIP maintainers receive no data from your deployment.**
> No account, no registration, no license check-in, no usage report, no crash
> reporter, no analytics. A deployment with no outbound network path is a fully
> supported, fully functional deployment.

Everything below documents (a) what the software processes **inside your
boundary**, and (b) the two narrow, **opt-in, default-off** channels that can
send anything **out** of it.

---

## 1. Roles

| Role | Who | Why it matters |
|---|---|---|
| **Controller** of the data MCPIP processes | **You**, the operator running the gateway | You choose the tenants, the agent identities, the retention window, and the storage. The maintainers have no access to it and no ability to obtain it. |
| **Processor / vendor** | The MCPIP maintainers | Only ever in scope for the opt-in telemetry beacon (§4) and the opt-in license refresh (§5). Both are off unless you turn them on. |

If you are performing a DPIA or filling in a vendor-diligence questionnaire: for
a self-hosted MCPIP deployment with telemetry disabled, there is **no vendor
data flow to assess**. [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) carries the
control cross-walk; [`docs/TELEMETRY.md`](docs/TELEMETRY.md) carries the beacon
specification.

---

## 2. What MCPIP processes inside your boundary

MCPIP sits between an agent's tool call and the system that executes it, so it
necessarily sees the call. What it *keeps* is deliberately narrow.

| Data | Where it lives | Notes |
|---|---|---|
| **Agent identity claims** (issuer, subject/principal, tenant, capabilities) | Verified from the JWT per request; written to the audit event | Identity comes only from a verified token. Identity-shaped keys inside tool arguments are a hard deny, never a data source. |
| **Tool call intent** (opaque alias + normalized arguments) | Redacted into the audit event; held for the life of the request | Arguments pass a redaction discipline before they are written; the decision feed omits arguments entirely. |
| **Authorization decisions** (allow / deny / staged, reason, correlation id) | The WORM audit ledger | The ledger is the point of the product: hash-chained, Ed25519-signed, written *before* execution. |
| **Operator roster** (email, role label, invite status) | Redis, per tenant | A management surface only — the role label authorizes nothing. |
| **Cloud/broker secrets** (if you use the vault) | Redis, AES-256-GCM under a master key held **outside** Redis | Write-only to every operator surface; the broker is the single reader at vend time. |
| **Forensic captures** (opt-in) | Redis, AES-256-GCM under a **separate** master key, TTL-bounded | Default **off** in production, on in sandbox (`MCPIP_FORENSIC_CAPTURE`). Secrets are never captured; reads require a distinct capability and are themselves audited before disclosure. |

**Never stored, by construction:** the downstream credential the broker vends
(short-lived, never persisted), the one-time PIN (only a payload-bound hash),
the real target behind an alias on any agent-facing surface, and any secret that
the redaction discipline recognizes.

### Personal data

MCPIP is machine-to-machine infrastructure; the identifiers it handles are
normally agent principals, not natural persons. Two exceptions deserve a
compliance note:

- **Principal identifiers may name a person** in some deployments (e.g. an agent
  acting for a named employee). Set `MCPIP_PSEUDONYMIZE_PRINCIPALS=true` with a
  pseudonym key and principals are replaced with a keyed-HMAC pseudonym in the
  ledger. Off by default because it trades investigability for minimization —
  your call, not ours.
- **Operator emails** in the console roster are personal data you control
  directly (`/v1/admin/users`, delete supported).

### Retention

You set it. The ledger trims events out of the hot buffer past the configured
retention window while the signed roots remain, so tamper-evidence survives
minimization. Deployment guidance is in
[`docs/OPERATIONS.md`](docs/OPERATIONS.md); optional at-rest encryption of the
event body is `MCPIP_ENCRYPT_WORM_AT_REST`.

---

## 3. Network posture

MCPIP makes **no outbound connection** unless an operator configures one. Every
outbound client the product ships is hermetic (no ambient proxy/env trust),
SSRF-guarded, and IP-pinned. The complete list of configurable egress:

| Channel | Default | Purpose |
|---|---|---|
| Authenticator delivery webhook | off | Delivers the out-of-band step-up code to your channel. |
| External PDP consult (AuthZEN) | off | Deny-only consult to *your* policy decision point. |
| JWKS refresh | off | Fetches *your* identity provider's key set. |
| Telemetry beacon | **off** | §4 — the only vendor-bound channel. |
| License refresh | **off** | §5 — vendor-bound, opt-in. |

The first three point at infrastructure **you** designate; the maintainers never
see them.

---

## 4. Telemetry beacon — opt-in, aggregate-only

Disabled unless you set `MCPIP_TELEMETRY_ENABLED=true` **and** a receiver URL. A
sandbox or air-gapped deployment never phones home.

When enabled, the beacon sends a **closed set of exactly eight fields**:

`install_id` · `license_tier` · `license_id` · `version` ·
`governed_agent_identity_count` · `decisions{allow,deny,staged}` ·
`uptime_seconds` · `sent_at`

- `install_id` is **random**, generated once, and **not derived** from any
  tenant, customer, host, or license identity.
- `governed_agent_identity_count` is a single integer cardinality read from a
  HyperLogLog. The agent identities themselves are never readable from it and
  never leave the box.
- The body **never** contains a tenant id, agent id, alias, target, capability,
  compartment, correlation id, argument, payload, secret, or any per-tenant
  breakdown. **Only aggregate integers leave the box.**

This is enforced, not merely promised: a test asserts the serialized body's key
set is exactly those eight fields and scans the bytes for request-identifying
strings. Full specification, including the HMAC signing headers and how to
disable it: [`docs/TELEMETRY.md`](docs/TELEMETRY.md).

To turn it off: unset `MCPIP_TELEMETRY_ENABLED` (or set it to `false`). No task
is scheduled and no client is constructed.

---

## 5. License refresh — opt-in, minimal

If — and only if — you set `MCPIP_LICENSE_REFRESH_URL`, booted with a license,
and hold the license-root key, MCPIP will periodically ask for a newer
entitlement document. The report body is the telemetry aggregate above when the
beacon is configured, otherwise a minimal `{license_id, version}`. It mints no
install identity of its own.

The refresh is fail-open by design: it can never block a decision, never adds a
trust root, never accepts an unverified document, and never fails your gateway
into an unlicensed state. Air-gapped deployments simply do not configure it and
install signed license files by hand.

---

## 6. Interacting with the project

Issues, pull requests, discussions, and private security advisories are hosted on
GitHub and governed by **GitHub's** privacy policy. Please do not paste real
audit-log contents, tokens, principal identifiers, or customer data into a public
issue — [`SECURITY.md`](SECURITY.md) describes the private channel for anything
sensitive, and a minimal synthetic reproduction is always more useful to us than
a real one.

---

## 7. Changes to this policy

This document is versioned in the repository. Material changes ship in
[`CHANGELOG.md`](CHANGELOG.md) with the release that makes them, so you can diff
the policy exactly as you diff the code. There is no silent update channel — the
gateway never patches itself.

Questions about data handling: open a GitHub issue titled `privacy: <question>`,
or use the private channel in [`SECURITY.md`](SECURITY.md) if the question itself
is sensitive.
