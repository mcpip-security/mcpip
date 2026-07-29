# Contributing to ◐ MCPIP

Thank you for considering a contribution. MCPIP is an authorization gateway —
the component that stands between an autonomous agent and the systems it can
affect. That makes the bar for a change here higher than for most projects, and
it makes the reasons for that bar worth stating up front rather than discovering
in review.

This guide is the whole contract: what to do before you write code, how to run
the gates, what will get a change rejected, and what happens after you open a
pull request.

---

## 0. Before anything else

**Found a vulnerability? Do not open a pull request.** A public PR is a public
disclosure. Report it privately per [`SECURITY.md`](../SECURITY.md) and we will
coordinate a fix and a release. This applies to anything that weakens
authorization, identity, the payload lock, the audit chain, opacity, or the boot
gates — including a fix you have already written.

For everything else, an issue first is welcome but not required for small,
self-evident changes. For anything touching the security core (§3), open an
issue and get agreement on the approach *before* writing the code. It is a
better use of your time than a rewrite in review.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## 1. Development setup

Requirements: **Python 3.12**, a local **Redis**, Node 18+ if you touch the
console or the TypeScript SDK.

```bash
git clone https://github.com/mcpip-security/mcpip.git && cd mcpip
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt        # includes the runtime deps

# Fastest way to see the whole thing running (Redis + sandbox gateway + a live
# governed walkthrough, idempotent, macOS/Linux):
./scripts/quickstart_demo.sh
```

The test suite expects Redis on **`localhost:63790`** (the quickstart starts one
there). Suites namespace themselves to databases 9/10 and run the gateway in
sandbox mode.

---

## 2. The gates your change must pass

Run these locally before pushing; CI runs the same set on every pull request and
a red gate blocks the merge.

```bash
pytest                                     # full suite — Redis required
mypy --strict .                            # typecheck (flags come from the CLI, not pyproject.toml)

cd dashboard && npm ci && npm run build    # console builds clean
cd sdk/typescript && npx tsc --noEmit      # TS SDK typechecks
```

Three suites deserve specific mention because they are gates rather than tests:

| Suite | Why it exists |
|---|---|
| `tests/test_fastwalk_differential.py` | The Rust accelerator ships **only** if it is byte-identical to the Python implementation. If this fails, the fast path does not ship. |
| `tests/test_connector_conformance.py` | An AST scan that fails if any connector module imports an SDK, an HTTP client, a socket, or environment credentials. Connectors are pure parsers. |
| `tests/test_deny_family.py` | Pins the console's deny-triage buckets to `interfaces.DENY_FAMILY`. Operator-facing labels cannot drift from the enum. |

New behavior needs a test. A bug fix needs a test that fails before it and
passes after. "Zero placeholders" (invariant 7) is enforced socially and in
review: no TODOs, no stubs, no partially implemented paths.

---

## 3. The security core — read this before editing it

The [seven security invariants](../README.md#security-invariants) are not
guidelines. A change that weakens one will be rejected regardless of what else
it improves. The paths below are the ones where an innocent-looking edit does
the most damage:

- **Identity** (`auth/`, `bridge/intent_parser.py`) — identity comes only from a
  verified JWT. The `role` claim authorizes nothing; entitlements are capability
  UUIDs and Redis-held grants. An identity- or capability-shaped key in a tool
  payload is a **hard deny**, never a strip.
- **Canonicalization and the payload lock** (`interfaces.py`,
  `auth/pin_validator.py`, `rust/`) — `canonical_json`,
  `enforce_argument_safety`, and the PIN-hash derivation must stay
  **byte-identical** between register and consume, and between Python and Rust.
  A change on one side without the other is a silent authorization bypass.
- **The audit ledger** (`audit/`) — the WORM emit happens **before** dispatch. A
  failed emit is a deny, not a dropped log line. Do not reorder it, do not make
  it concurrent, do not make it best-effort.
- **Opacity** (`core/security.py`, every response path) — agents receive a
  generic denial and a `correlation_id`. Reasons, paths, key names, targets, and
  topology go to the WORM log only. Metric labels are closed-enum literals; a
  free-form label is a leak.
- **The connector registry** (`bridge/connectors/registry.py`) — hash-pinned. It
  refuses to import on drift, which is the point.
- **Hard limits** live only in `interfaces.py`. Do not introduce a second place
  where a bound is defined.

### Adding a connector vendor

1. Add or extend a thin binding module (`VENDORS` / `SOURCE_FORMAT` / `PARSER`
   only — no logic, no SDK, no network).
2. Add the `_BINDINGS` entry and the `Vendor` enum member.
3. **Deliberately re-pin** the registry: bump `REGISTRY_VERSION` and recompute
   `_PINNED_REGISTRY_SHA256`. Recompute it — never hand-write it.
4. Add a conformance vector to `tests/fixtures/connectors/registry.json`. A test
   mechanically requires one per registered vendor.

### Changing anything hash-pinned or signed

Release manifests and integrity manifests are signed offline by the maintainer
([`docs/operate/RELEASE.md`](../docs/operate/RELEASE.md)). If your change requires a re-sign, say so in the
PR; do not fabricate a digest to make a check pass.

---

## 4. Pull requests

- **Branch** from `main`, one logical change per PR. A large refactor bundled
  with a behavior change is very hard to review safely, and here that means it
  will be reviewed slowly.
- **Fill in the PR template.** It is the project's change-management record, not
  bureaucracy — it asks what changed, what invariant it touches, and how it was
  verified.
- **CODEOWNERS review is required** on the invariant-critical paths listed in
  [`.github/CODEOWNERS`](CODEOWNERS). Expect substantive review there.
- **Keep the documentation with the code.** If you change the pipeline, an
  invariant, a limit, a configuration flag, or a development command, update the
  affected document in the *same* commit. A stale document about an authorizer
  is worse than no document.
- **Commit messages**: imperative subject, scope prefix where it helps
  (`feat(auth):`, `fix(worm):`, `docs:`). Explain *why* in the body when the
  *what* is not self-evident.

### Developer Certificate of Origin

All commits must be signed off, certifying you wrote the patch or have the right
to submit it under the file's license (DCO 1.1, <https://developercertificate.org/>):

```bash
git commit -s -m "fix(auth): reject a JWT whose iss_binding disagrees with the verified issuer"
```

This adds `Signed-off-by: Your Name <you@example.com>`. There is no CLA.

### Licensing of contributions

Contributions are accepted under the license covering the file you are changing:
**BSL 1.1** for the gateway core, **Apache-2.0** for `sdk/python` and
`sdk/typescript` ([`docs/policies/LICENSING.md`](../docs/policies/LICENSING.md)). By submitting a contribution
you agree to license it accordingly and confirm you are able to do so.

---

## 5. What tends to get rejected

Stated plainly, so nobody spends a weekend on one:

- A change that makes a denial *more informative to the agent*. Opacity is the
  product, not an oversight.
- A "fast path" that skips the WORM emit, the lock, or the identity check under
  some condition.
- Caching an authorization decision. The negative-only grant cache is
  deliberately the only cache on that path.
- A new dependency on the hot path, or any dependency in a connector module.
- Free-form metric labels, log fields carrying targets or arguments, or a new
  place where a real target could reach an agent-facing surface.
- Speculative extension points with no shipping consumer. This codebase prefers
  a smaller surface that is fully implemented.
- Reformatting or renaming unrelated code inside a functional PR.

None of these are personal, and none of them mean the underlying idea is wrong —
open an issue and we will find the version that fits the invariants.

---

## 6. Documentation-only contributions

Very welcome, and held to the same honesty standard as the code: no invented
benchmark, no implied certification, no capability described as shipped when it
is deferred. If you find a document claiming more than the code does, that is a
bug worth reporting on its own.

---

## 7. Releases

Cutting a release is a maintainer action involving offline signing keys and a
documented ceremony ([`docs/operate/RELEASE.md`](../docs/operate/RELEASE.md)). Contributors never need to
touch `release/`, `VERSION`, or the signed manifests — and PRs that do will be
asked to drop those files.

---

Questions that are not vulnerabilities: open a GitHub issue, or see
[`.github/SUPPORT.md`](SUPPORT.md).
