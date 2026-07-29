# Support & Working With Us

MCPIP is maintainer-run and source-available (BSL core, Apache-2.0 SDKs). Every
channel below is real and monitored — no channel listed here is aspirational.

## Getting help

| Need | Channel |
| --- | --- |
| Bug reports, questions, evaluation help | [GitHub Issues](https://github.com/mcpip-security/mcpip/issues) |
| Security vulnerabilities | **Never** a public issue — use GitHub private vulnerability reporting per [`SECURITY.md`](../SECURITY.md) |
| Evaluating MCPIP for your org | Open an issue titled `evaluation: <your use case>` — includes a guided walkthrough of the sandbox, the threat model, and the compliance-evidence export |

Response posture, honestly: best-effort by the maintainer, typically within a
few business days. There is no paid SLA yet — an SLA ships with the enterprise
tier ([`docs/policies/LICENSING.md`](../docs/policies/LICENSING.md)).

## Design-partner program

We work with a small number of design partners in regulated / high-consequence
environments (payments, ledger posts, production infrastructure) — a time-boxed
pilot on one real workflow, self-hosted in your boundary, with direct maintainer
support. Structure and commercial terms are shared directly on request.

Interested: open a GitHub issue titled `design-partner: <company>` (or reach the
maintainer through the repository profile) with one sentence on the workflow you
want governed. You'll get a working session against the live sandbox, not a
slide deck.

## What to try before asking

```bash
git clone https://github.com/mcpip-security/mcpip && cd mcpip
./scripts/quickstart_demo.sh     # sandbox gateway + live walkthrough, one command
```

Then [`docs/start/GETTING_STARTED.md`](../docs/start/GETTING_STARTED.md) (connect an agent in
one URL) and [`docs/README.md`](../docs/README.md) (the full documentation index).

## Policies

[`docs/policies/TERMS.md`](../docs/policies/TERMS.md) (terms of use) · [`docs/policies/PRIVACY.md`](../docs/policies/PRIVACY.md) (data
handling — self-hosted, no vendor data flow by default) ·
[`SECURITY.md`](../SECURITY.md) (coordinated disclosure) ·
[`docs/policies/TRADEMARK.md`](../docs/policies/TRADEMARK.md) (name & mark) ·
[`.github/CONTRIBUTING.md`](CONTRIBUTING.md) · [`.github/CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
