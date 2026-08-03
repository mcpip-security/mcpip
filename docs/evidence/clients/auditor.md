# Client type: auditor

Verifies that the ledger has not been tampered with, exports it, and produces period
evidence. **The most consequential client type in this whole exercise** — it is the one
that degrades every other one, and finding that was the point of splitting load by
client type at all.

| | |
|---|---|
| **Surface** | `GET /v1/admin/forensic/{corr}` · `/v1/audit/verify` (sandbox) · `mcpip-verify export-audit --verify` (offline, no gateway) |
| **Capabilities** | `CAP_FORENSIC_READ` = `d5f0c9a2-4b71-4e6a-9c83-1a7f2e6b4d90` |
| **Second identity** | `GET /v1/audit/attestation` and `GET /v1/admin/compliance/evidence` are **`CAP_DIRECTORY_ADMIN`**-gated — the measurements for them below were taken with an operator token, not this one |

> **Two capabilities, deliberately disjoint.** `CAP_FORENSIC_READ` opens
> `/v1/admin/forensic/{corr}` and nothing else; `CAP_DIRECTORY_ADMIN` opens attestation,
> stats and the evidence bundle but is **refused** on the forensic route. Neither contains
> the other, so a real audit function either carries both claims or is two identities. That
> is the no-super-admin property working, and it is why this page's `403` table and its
> attestation numbers cannot come from one token. Verified live:
>
> | route | `CAP_FORENSIC_READ` | `CAP_DIRECTORY_ADMIN` |
> |---|---|---|
> | `GET /v1/admin/forensic/{corr}` | `200` | `403` |
> | `GET /v1/audit/attestation` | `403` | `200` |
> | `GET /v1/admin/stats` | `403` | `200` |
> | `GET /v1/admin/compliance/evidence` | `403` | `200` |
| **Share of load** | ÷20 |
| **Transcript** | [`E2E_WALKTHROUGH.md` §12, §13a](../E2E_WALKTHROUGH.md#12-evidence--the-worm-ledger) · [`ORGANIZATION_AT_SCALE.md` §5a](../ORGANIZATION_AT_SCALE.md#5a-reporting-across-the-period) |

## What it may and may not do

| route | auditor |
|---|---|
| `GET /v1/catalog` | `200` |
| `GET /v1/admin/stats` | `403` |
| `GET /v1/admin/decisions/recent` | `403` |
| `POST /v1/admin/skills/register` | `403` |
| `GET /v1/admin/forensic/{corr}` | `404`¹ |

¹ `404`, not `403` — the auditor **is** authorized; no forensic capture existed for
that correlation id. An authorized-but-empty lookup stays distinguishable from a
capability refusal, which matters when the question is "was there evidence?" rather
than "am I allowed to ask?".

An auditor cannot read tenant statistics or the decision feed, and cannot register an
alias. Capabilities are non-hierarchical in both directions.

## Latency — and the starvation finding

| rate | p50 | p95 | p99 |
|---|---:|---:|---:|
| 50/s | **146.9 ms** | **359.4 ms** | 458.5 ms |
| 150/s (past the knee) | 46.1 ms | **10,259 ms** | — |

Slowest at both rates, and the p95 at 150/s is not a rounding difference — it is
**16× the next worst client type**. `verify_chain` re-hashes every epoch, recomputes
every Merkle root, and checks every Ed25519 signature. That is CPU-bound work on the
event loop, so while it runs it does not merely slow itself down:

> **`/v1/audit/attestation` starves the authorization hot path.** Agent p95 went from
> 219 ms to 636 ms with the auditor running concurrently. A single auditor at ÷20 of
> the base rate is enough.

This is the real bug the load exercise produced — not the shedding, which is correct
behaviour. Details and the correction of an earlier wrong reading in
[`LOAD_AT_SCALE.md`](../LOAD_AT_SCALE.md#the-actual-bug-the-auditor-starves-the-hot-path).

## Cost

| step | HTTP | req B | resp B | ~in tok | ~out tok | ms |
|---|---|---:|---:|---:|---:|---:|
| `audit/attestation` | `200` | 0 | 560 | 0 | 140 | 526.3 |

560 bytes out for half a second of work: the response is small and the computation
behind it is not. Cost here is CPU, not tokens.

## What to watch

* **Do not poll attestation.** Run it on a schedule, off-peak, or against a read
  replica. It is a verification sweep, not a health check.
* **`mcpip-verify export-audit --verify` is the continuous check**, not `/v1/audit/verify`
  (which is sandbox-gated). It runs the same five checks `verify_chain` runs — chain
  linkage, Merkle roots, `epoch_hash` recomputation, Ed25519 epoch signatures, and the
  out-of-tamper-domain anchor low-watermark — read-only, no lock, offline.
* **The decision history is not the authoritative record.** It is a bounded scan over
  a *trimmed* buffer. `scripts/soc2_report.py` now labels a period **partially
  retained** when it starts before the retention horizon, and reports `cursor_lost`
  rather than claiming a completeness the gateway never asserted. For any trimmed
  span, the signed epoch chain is the record.
