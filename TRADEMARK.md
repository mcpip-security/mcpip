# ◐ MCPIP — Trademark & Naming Policy

The **MCPIP** name and the **◐** mark identify this project and the software
released by its maintainers. The source license ([`LICENSE`](LICENSE), Business
Source License 1.1) grants rights in the **code**. Like nearly every source
license — Apache-2.0 included — it grants **no rights in the name or the mark**.
This document says plainly what you may do with them, so that you do not have to
guess.

The goal is narrow and specific: when someone runs a binary or a fork that calls
itself "MCPIP", they should be able to rely on it behaving like MCPIP —
fail-closed, opaque, write-before-execute. That guarantee is the only thing this
policy protects.

## What you may do without asking

- **Say what your software does.** "Works with MCPIP", "MCPIP-compatible",
  "built on MCPIP", "an MCPIP client", "we deploy MCPIP internally" — accurate,
  descriptive (nominative) use is always fine.
- **Redistribute the unmodified release** under its name, including mirrors,
  internal package registries, and air-gapped bundles. Keep the license,
  [`NOTICES.md`](NOTICES.md), and the signed release artifacts intact.
- **Write about it.** Documentation, talks, blog posts, courses, comparisons,
  and critical reviews may use the name. You do not need permission to say
  something negative about the project.
- **Use the name in a repository or package that plugs into MCPIP**, as long as
  the name makes clear it is yours, not ours — `mcpip-terraform-provider` by a
  third party is fine; `mcpip-official-provider` is not.
- **Reference the mark in screenshots** of the operator console.

## What requires a different name

- **A modified build distributed to others.** If you change behavior — in
  particular anything in the [security invariants](README.md) — and ship it to
  anyone else, ship it under your own name. You may state factually that it is
  "a fork of MCPIP" or "derived from MCPIP". This is the whole point of the
  policy: a third party must not be able to hand someone a weakened authorizer
  that presents itself as MCPIP.
- **A hosted or managed service.** Note that offering the Licensed Work to third
  parties as a hosted authorization-gateway service is separately restricted by
  the BSL Additional Use Grant (see [`LICENSING.md`](LICENSING.md)) until the
  Change Date. Where such use is permitted, it must not be branded as MCPIP
  without written permission.
- **Anything implying endorsement, affiliation, or certification.** "Official",
  "certified", "endorsed by", "MCPIP Inc.", or a company/product name in which
  MCPIP is the dominant element.
- **Domain names, social accounts, and org names** whose principal element is
  MCPIP.
- **Logo modification.** Do not alter the ◐ mark's proportions, colors, or
  composition, and do not incorporate it into another logo.

## Security-sensitive claims

Do not describe a deployment, fork, or derivative as **certified**, **audited**,
or **compliant** on the strength of the MCPIP name. The project ships
*evidence* — signed audit chains, a control cross-walk, a threat model — and is
explicit that evidence is [not a certification](docs/COMPLIANCE.md). Attributing
a certification to MCPIP misrepresents both the project and the mark.

## Requests and enforcement

For any use this policy does not clearly permit, open a GitHub issue titled
`trademark: <intended use>` describing the use, or contact the maintainer
through the private channel on the repository profile. Reasonable requests are
generally granted, in writing, and usually quickly.

Enforcement is proportionate and correction-first: our preferred outcome is a
rename or a clarifying sentence, not a dispute. We reserve all rights in the
marks, and nothing in this document is a waiver of them.

---

*This policy governs the marks only. It does not narrow, widen, or reinterpret
the rights granted by [`LICENSE`](LICENSE) — where the two could be read to
conflict, the license governs the code and this policy governs the name.*
