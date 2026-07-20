# ◐ MCPIP — Licensing

MCPIP uses an **open-core, source-available** model. The rationale (why source-available and not
pure Apache or fully proprietary) is in [`docs/STRATEGY.md`](docs/STRATEGY.md).

## The map

| Component | Path | License | Notes |
|---|---|---|---|
| **Gateway core** (Bridge · Obfuscator · Auth · Audit, app, services, CLI, dashboard) | repo root + everything **except** `sdk/` | **Business Source License 1.1** (see [`LICENSE`](LICENSE)) | Read, self-host, modify, and make **production use** for your own/organizational purposes and evaluation. You may **not** offer MCPIP to third parties as a hosted/managed authorization-gateway service. Converts to **Apache-2.0** on the Change Date (**2030-07-16**), or four years after a version's first public release, whichever is first. |
| **Client SDKs** | [`sdk/python`](sdk/python), [`sdk/typescript`](sdk/typescript) | **Apache-2.0** (see each dir's `LICENSE`) | Permissive on purpose — integrating an agent should have zero license friction. |
| **Product tiers / entitlements** | n/a (runtime) | Commercial | Enterprise features and support are gated by an **Ed25519-signed entitlement license** verified at boot (`core/licensing.py`, `scripts/gen_license.py`). This is unchanged by the source-available move — the *code* is source-available; the *paid product surface* (SSO, HA, compliance evidence, managed decoy intelligence, support/SLA) is licensed. See [`docs/STRATEGY.md`](docs/STRATEGY.md) for the open-core boundary. |

## What the BSL grant means, in plain terms

- ✅ Read and audit the full source (the whole point — you shouldn't trust an authorizer you can't inspect).
- ✅ Run it in production for your own company, including regulated/air-gapped deployments.
- ✅ Modify it and self-host your modifications.
- ✅ Evaluate it freely.
- ❌ Resell it to third parties as a competing hosted/managed authorization-gateway service.
- ⏳ On **2030-07-16** the then-covered versions become **Apache-2.0** (fully open source).

## ⚖️ Legal note (please read before public release)

This licensing change (from the previously-stated Apache-2.0 to BSL 1.1 for the core) is a
deliberate strategic decision and **should be reviewed by legal counsel before any public
release**, in particular:

- BSL 1.1 is *source-available*, **not** an OSI-approved "open source" license — public messaging
  should say "source-available," not "open source," for the core.
- The **Change License** (Apache-2.0) and the **Additional Use Grant** wording should be confirmed
  by counsel (including the BSL covenant that the Change License be GPL-compatible; Apache-2.0 is
  compatible with GPLv3). An alternative vehicle purpose-built for "source-available now, Apache
  later" is the **Functional Source License (FSL-1.1-Apache-2.0)** — a lighter option if preferred.
- Confirm the **Licensor** legal entity name (currently "The MCPIP Authors" as a placeholder) and
  the copyright holder before publishing.
