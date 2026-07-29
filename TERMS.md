# ◐ MCPIP — Terms of Use

**Version 3.0.0 · Applies to: the MCPIP software distribution (source, container
images, signed release artifacts, SDKs, and CLI).**

MCPIP is distributed software, not a hosted service — there is no account to
create and no service for these terms to govern. These terms therefore do one
job: state plainly the conditions on which the software is made available, and
where the boundary of the maintainers' responsibility sits.

**The license text controls.** Where anything here could be read to conflict with
[`LICENSE`](LICENSE) (Business Source License 1.1) or with the Apache-2.0 license
covering the SDKs, **the license governs**. These terms neither widen nor narrow
the rights granted there.

---

## 1. The license grant, in one table

| Component | License | In plain terms |
|---|---|---|
| Gateway core — everything except `sdk/` | **BSL 1.1** ([`LICENSE`](LICENSE)) | Read it, audit it, modify it, self-host it, and run it in production for your own or your organization's purposes. You may **not** offer it to third parties as a hosted or managed authorization-gateway service. Converts to **Apache-2.0** on the Change Date (**2030-07-16**). |
| Client SDKs — `sdk/python`, `sdk/typescript` | **Apache-2.0** | Permissive on purpose. Integrating an agent should carry zero license friction. |
| Enterprise entitlements | Commercial | Certain features are gated by an Ed25519-signed entitlement document verified **at boot only** — never per request. |

The full map and rationale: [`LICENSING.md`](LICENSING.md). The name and mark are
governed separately by [`TRADEMARK.md`](TRADEMARK.md); no trademark rights are
granted by the source license.

**On terminology:** BSL 1.1 is **source-available**, not an OSI-approved open
source license. This project says "source-available" and means it.

---

## 2. Entitlement licenses

If you hold a commercial entitlement:

- It is verified **offline**, at process boot, against a pinned signing root. No
  network call is required to run MCPIP, and none is made unless you explicitly
  configure the optional refresh ([`PRIVACY.md`](PRIVACY.md) §5).
- Licensing gates **boot**, never an authorization decision. An expiring
  entitlement can never silently change what your gateway allows or denies.
- Air-gapped deployment is a first-class, supported path. Entitlement documents
  install as files.
- Do not modify, forge, or circumvent an entitlement document, or redistribute
  one issued to you. Where a separate commercial agreement exists, that
  agreement governs the paid surface and supersedes this section.

---

## 3. Acceptable use

MCPIP is authorization infrastructure. Use it on systems you own or are
authorized to govern. Specifically, you agree not to use MCPIP:

- to intercept, gate, or broker access to systems **you are not authorized to
  administer**;
- to circumvent, weaken, or disable another party's authorization, audit, or
  monitoring controls;
- to construct a deceptive audit record — including operating a modified build
  that presents itself as MCPIP while altering the fail-closed, opaque, or
  write-before-execute behavior (see [`TRADEMARK.md`](TRADEMARK.md));
- in violation of applicable law, including export control and sanctions
  regimes. You are responsible for determining whether your deployment,
  redistribution, or re-export is permitted from and to your jurisdictions.

Security research on your **own** deployment is welcome and needs no permission.
Findings that affect the software itself go through
[`SECURITY.md`](SECURITY.md), privately, before publication.

---

## 4. Operator responsibilities

MCPIP is a **control**, not a guarantee. It enforces exactly the invariants it
documents, and its guarantees hold only when it is deployed as documented. You
are responsible for:

- **Key custody** — the WORM signing key, license root, vault and forensic
  master keys. Losing them costs you verifiability; leaking them costs you the
  guarantee. The gateway holds no copy for you and the maintainers hold none at
  all.
- **Durability** — the audit ledger's tamper-evidence depends on the documented
  Redis durability profile (`appendfsync always`). Weakening it weakens the
  guarantee.
- **Non-bypassability** — MCPIP authorizes the calls that reach it. If an agent
  retains a network path around the gateway, or holds a standing credential to
  the downstream system, the control is bypassed. Network enforcement is a
  deployment responsibility; [`docs/OPERATIONS.md`](docs/OPERATIONS.md) ships
  the manifests.
- **Configuration** — which skills exist, which are auto-allowed vs. step-up
  gated, who holds which capability, and what your retention window is.
- **Verification** — verifying signed releases before deployment
  ([`RELEASE.md`](RELEASE.md), `mcpip verify`).

The project documents its residual risks rather than hiding them:
[`SECURITY_THREAT_MODEL.md`](SECURITY_THREAT_MODEL.md) states what MCPIP does
**not** defend against, including areas that are out of scope by design.

---

## 5. No certification, no assurance opinion

MCPIP produces **evidence** — signed audit chains, attestations, a control
cross-walk to SOC 2 / EU AI Act / NIST 800-53 and others. Evidence is not a
certification. Nothing in this repository is a SOC 2 report, an audit opinion, a
FedRAMP authorization, or a regulatory approval; those can only be issued by
independent qualified third parties, about **your** organization, after an
examination. Deploying MCPIP does not make you compliant with anything. See
[`docs/COMPLIANCE.md`](docs/COMPLIANCE.md), which says the same thing at length.

---

## 6. No warranty; limitation of liability

The software is provided **"AS IS", without warranty of any kind**, express or
implied, including the warranties of merchantability, fitness for a particular
purpose, title, and non-infringement, as stated in [`LICENSE`](LICENSE).

To the maximum extent permitted by applicable law, the maintainers and
contributors are **not liable** for any claim, damages, or other liability —
including indirect, incidental, special, consequential, exemplary, or punitive
damages, or loss of profits, revenue, data, or business — arising from or
connected with the software or its use, whether in contract, tort, or otherwise,
even if advised of the possibility.

Some jurisdictions do not allow the exclusion of certain warranties or the
limitation of certain liabilities; in those jurisdictions the exclusions and
limitations above apply to the fullest extent permitted.

Nothing in this section limits any liability that cannot lawfully be limited.

---

## 7. Third-party components

MCPIP incorporates third-party open source components under their own licenses;
attributions and license texts are in [`NOTICES.md`](NOTICES.md) and the SBOM
shipped with each signed release. Your use of those components is governed by
their respective licenses.

---

## 8. Contributions

Contributions are accepted under the terms in
[`CONTRIBUTING.md`](CONTRIBUTING.md). In summary: you contribute under the
license covering the file you are changing, and you certify (via a
`Signed-off-by` line, the Developer Certificate of Origin) that you have the
right to do so.

---

## 9. Changes

These terms are versioned in the repository and change only by commit. Material
changes are recorded in [`CHANGELOG.md`](CHANGELOG.md) with the release that
carries them. A release you have already deployed is governed by the terms
shipped in it — the maintainers cannot alter the terms of software already in
your possession.

---

## 10. Contact

- **Vulnerabilities:** [`SECURITY.md`](SECURITY.md) — privately, always.
- **Licensing, entitlements, trademark:** open a GitHub issue with a
  `licensing:` / `trademark:` prefix, or use the private channel on the
  repository profile.
- **Everything else:** [`SUPPORT.md`](SUPPORT.md).
