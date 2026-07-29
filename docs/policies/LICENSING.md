# ◐ MCPIP — Licensing

MCPIP uses an **open-core, source-available** model. What that model means for your
deployment in practice is set out in [`docs/policies/TERMS.md`](TERMS.md).

## The map

| Component | Path | License | Notes |
|---|---|---|---|
| **Gateway core** (Bridge · Obfuscator · Auth · Audit, app, services, CLI, dashboard) | repo root + everything **except** `sdk/` | **Business Source License 1.1** (see [`LICENSE`](../../LICENSE)) | Read, self-host, modify, and make **production use** for your own/organizational purposes and evaluation. You may **not** offer MCPIP to third parties as a hosted/managed authorization-gateway service. Converts to **Apache-2.0** on the Change Date (**2030-07-16**), or four years after a version's first public release, whichever is first. |
| **Client SDKs** | [`sdk/python`](../../sdk/python), [`sdk/typescript`](../../sdk/typescript) | **Apache-2.0** (see each dir's `LICENSE`) | Permissive on purpose — integrating an agent should have zero license friction. |
| **Product tiers / entitlements** | n/a (runtime) | Commercial | Enterprise features and support are gated by an **Ed25519-signed entitlement license** verified at boot (`core/licensing.py`, `scripts/gen_license.py`). This is unchanged by the source-available move — the *code* is source-available; the *paid product surface* (SSO, HA, compliance evidence, managed decoy intelligence, support/SLA) is licensed. |

## What the BSL grant means, in plain terms

- ✅ Read and audit the full source (the whole point — you shouldn't trust an authorizer you can't inspect).
- ✅ Run it in production for your own company, including regulated/air-gapped deployments.
- ✅ Modify it and self-host your modifications.
- ✅ Evaluate it freely.
- ❌ Resell it to third parties as a competing hosted/managed authorization-gateway service.
- ⏳ On **2030-07-16** the then-covered versions become **Apache-2.0** (fully open source).

