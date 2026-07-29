# Security Policy

MCPIP is a fail-closed, opaque zero-trust authorization gateway. Security is the product, so a
credible coordinated-disclosure path is part of it. This file is the **process** policy; the
**technical** adversary model, the per-threat attack→defense→code matrix, and the honest
residual-risk analysis live in [`docs/SECURITY_THREAT_MODEL.md`](docs/SECURITY_THREAT_MODEL.md) (including
the §17 OWASP ASI-2026 coverage map).

## Supported versions

MCPIP is currently at `3.0.0` (the `VERSION` file is the single source of truth). Security fixes
target the latest released minor line. There is **no runtime self-update** — a fix is delivered as
a new signed release that the operator verifies and redeploys ([`docs/operate/RELEASE.md`](docs/operate/RELEASE.md)); the
gateway never patches itself.

| Version | Supported |
|---|---|
| `3.0.x` | ✅ |
| `< 3.0` | Upgrade to the latest release |

## Reporting a vulnerability

**Please do not open a public issue for a suspected vulnerability.** Report it privately so a fix
can ship before the details are public:

- **Preferred:** open a [GitHub private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository ("Security" tab → "Report a vulnerability"). This keeps the report, the fix,
  and the disclosure in one coordinated place.
- If that is unavailable to you, contact the maintainer through the private channel listed on the
  repository's profile and mark the subject **`[SECURITY]`**.

Please include, as far as you can:

- the affected version / commit and the deployment mode (sandbox vs. production);
- a minimal reproduction (a request shape, a token, a config) — **never** include a real
  production secret, JWT, PIN, or vended credential in the report;
- the impact you observed and, if known, the invariant it breaks (see the list below).

## What we treat as in scope

A finding is most valuable when it breaks one of the load-bearing invariants:

- **Fail-closed opacity** — any path that returns a concrete reason, stack trace, target,
  topology, or another tenant's data to the agent instead of the generic `MCPIPDenied` +
  `correlation_id`.
- **Identity sovereignty** — anything that authorizes on the `role` claim, accepts an
  identity/capability-shaped key smuggled in `arguments`, or widens the `{EdDSA, RS256}` alg gate
  (e.g. `alg=none` / HMAC confusion).
- **The payload lock (TOCTOU)** — any way to spend a PIN against a different payload, replay a
  spent lock, or make register↔consume or Python↔Rust canonicalization disagree.
- **WORM integrity** — any way to dispatch before the decision is durably emitted, or to mutate /
  truncate the signed epoch chain without `verify_chain` detecting it.
- **Cross-tenant reach** — any way to resolve, enumerate, or act on another tenant's aliases,
  grants, locks, or captured payloads.
- **Secret exposure** — any OTP, JWT, vended credential, or vault material reaching a log, a WORM
  field, an operator projection, or the agent wire.
- **SSRF / boot-gate bypass** — reaching an internal address through the authenticator webhook,
  JWKS refresher, telemetry beacon, or external-PDP client; or booting production past verified
  boot / the license gate / the sender-constraint lint.

## What we do NOT consider a vulnerability

- The agent receiving only an opaque denial — that is the design, not a leak.
- A **dark feature being off** (forensic capture, external-PDP, telemetry, MRT step-up default to
  off/opt-in and say so honestly).
- The in-tree signed `release/manifest.json` legitimately lagging `VERSION` before the owner's
  offline re-sign ([`docs/operate/RELEASE.md §0`](docs/operate/RELEASE.md)) — this is the documented honest boundary.
- Out-of-scope-by-design gaps that are disclosed plainly (e.g. in-agent memory poisoning / ASI06 —
  MCPIP governs the tool call, not the agent's memory; [`docs/SECURITY_THREAT_MODEL.md §17`](docs/SECURITY_THREAT_MODEL.md)).
- Denial-of-service from misconfigured Redis durability or unbounded client load beyond the
  documented ceilings.

## Coordinated disclosure

We aim to acknowledge a report within a few business days, agree on a severity and a remediation
timeline, and credit the reporter in the release notes unless anonymity is requested. Please give
us a reasonable window to ship a signed fix before public disclosure. Reports made in good faith
under this policy will not be pursued.
