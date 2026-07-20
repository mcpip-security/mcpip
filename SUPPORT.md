# Support & Working With Us

MCPIP is maintainer-run and source-available (BSL core, Apache-2.0 SDKs). Every
channel below is real and monitored — no channel listed here is aspirational.

## Getting help

| Need | Channel |
| --- | --- |
| Bug reports, questions, evaluation help | [GitHub Issues](https://github.com/katzyuval/mcpip/issues) |
| Security vulnerabilities | **Never** a public issue — use GitHub private vulnerability reporting per [`SECURITY.md`](SECURITY.md) |
| Evaluating MCPIP for your org | Open an issue titled `evaluation: <your use case>` — includes a guided walkthrough of the sandbox, the threat model, and the compliance-evidence export |

Response posture, honestly: best-effort by the maintainer, typically within a
few business days. There is no paid SLA yet — an SLA ships with the enterprise
tier ([`LICENSING.md`](LICENSING.md)).

## Design-partner program

We work with a small number of design partners in regulated / high-consequence
environments (payments, ledger posts, production infrastructure) — a time-boxed
pilot on one real workflow, self-hosted in your boundary, with direct maintainer
support. Structure and pricing are published openly in
[`docs/GTM_PRICING.md`](docs/GTM_PRICING.md).

Interested: open a GitHub issue titled `design-partner: <company>` (or reach the
maintainer through the repository profile) with one sentence on the workflow you
want governed. You'll get a working session against the live sandbox, not a
slide deck.

## What to try before asking

```bash
git clone https://github.com/katzyuval/mcpip && cd mcpip
./scripts/quickstart_demo.sh     # sandbox gateway + live walkthrough, one command
```

Then [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) (connect an agent in
one URL) and [`docs/README.md`](docs/README.md) (the full documentation index).
