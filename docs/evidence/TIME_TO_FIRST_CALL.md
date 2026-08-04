# Time to first authorized call

**The question this answers:** how long does it take to get from *nothing* — no clone, no
keys, no catalog — to a governed allow and a governed deny, first on the sandbox path and
then on the real fail-closed production path?

> **Provenance.** Every number and every transcript below came from **one continuous
> session on 2026-08-04**, on the machine named under [The machine](#the-machine), against
> commit `4eb002f`. Nothing is spliced from an earlier run and nothing is estimated. Two
> figures are network-dependent and are reported with the reason (see
> [What this does not prove](#what-this-does-not-prove)).
>
> These are timings of the *documented* paths, taken by executing them — not a claim that
> your machine will match. `scripts/quickstart.sh` prints its own figure every time it
> runs, so the headline is not something you have to take from this page.

---

## The headline

| Path | Wall clock | Commands |
|---|---:|---:|
| Cold `git clone` → 9 governed decisions (sandbox) | **13 s** | 2 |
| …then → **your own** alias registered and authorized | **+1.2 s** | +5 |
| Production posture: keys · roots · license · integrity manifest | **0.31 s** | 4 |
| Production fail-closed boot, all six paths verified | **1.05 s** | 1 |
| Production: mint two principals → register → authorize | **0.28 s** | 4 |

Cold clone to a **production-posture** first authorized call is **≈ 15 s** on this machine,
of which ~13 s is `pip install`. The gateway's own north-star budget is 300 s.

## The machine

4 vCPU · 15 GiB RAM · Linux 6.18 · Python 3.11.15 (venv; the gateway itself pins ≥3.12 and
runs here under the interpreter the quickstart provisions) · Redis 7.0.15 · MCPIP `3.0.0`.
Ordinary cloud container, no tuning.

---

## Track A — the sandbox path, which is what a visitor runs

```console
$ git clone https://github.com/mcpip-security/mcpip.git && cd mcpip
$ ./scripts/quickstart.sh
◐ checking prerequisites
  python3 · redis-server ✓
◐ creating virtualenv .venv
◐ installing dependencies (requirements.txt)
◐ starting redis on :63790
◐ starting sandbox gateway on :8080
{"status":"live","glyph":"◐","loop":"uvloop","version":"3.0.0","region":null}
◐ running the live company walkthrough (mcpip-inc)
```

The walkthrough issues **nine real `/v1/mcp` round-trips** across three identities in one
tenant, and each one is a decision, not a print statement:

```
Scenario 1 — Engineering agent
  tools/list → skill_company_overview, skill_data_lake, skill_engineering_roadmap, …
    ALLOW  skill_company_overview            ✓
    ALLOW  skill_engineering_roadmap         ✓
    DENY   skill_financial_wage_sheet        opaque · correlation 7e7ebd59…  ✓

Scenario 2 — Finance agent
    ALLOW  skill_financial_wage_sheet        ✓
    DENY   skill_engineering_roadmap         opaque · correlation 85d3256b…  ✓

Scenario 3 — Company agent, no team
    ALLOW  skill_company_overview            ✓
    ALLOW  skill_data_lake                   ✓
    DENY   skill_financial_wage_sheet        opaque · correlation a7cf8d4b…  ✓
    DENY   skill_engineering_roadmap         opaque · correlation 1c65440b…  ✓

✓ All decisions matched — team separation enforced at the choke point.
◐ zero → first governed calls: 13s (north star: < 300s)
```

Note what the deny lines *do not* contain: no reason, no target, no indication the alias
exists. The finance wage sheet never appears in Engineering's `tools/list` at all.

**Measured twice.** 13 s with a warm pip cache and 13 s again with `PIP_NO_CACHE_DIR=1`
into a second fresh clone — the second run genuinely re-downloaded the dependency set
(`cryptography 50.0.0`, `fastapi 0.141.1`, `pydantic 2.13.4`, `uvicorn 0.52.1`, …), so the
figure is not an artefact of a primed cache. It *is* an artefact of this machine's network;
see the caveats.

### …and then your own alias

The walkthrough runs against a pre-seeded catalog, which proves the pipeline but not that
*you* can put your own system behind it. That is the step that actually matters, so it was
measured separately, against the gateway the quickstart had just left running:

```console
$ mcpip login --gateway http://localhost:8080 --sandbox --context sbx
sandbox         : true
reachable       : true
gateway_version : 3.0.0
ready           : true
redis           : up

$ mcpip --context sbx sandbox dev-token --agent admin-1 \
    --cap b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20        # CAP_DIRECTORY_ADMIN
token_written : true
context_wired : true
agent_id      : admin-1

$ mcpip --context sbx admin skills register skill_my_crm crm.internal.contacts.read
registered : skill_my_crm

$ mcpip --context sbx sandbox dev-token --agent app-1   # a plain agent, no capability

$ mcpip --context sbx catalog
ALIAS                         RISK_TIER   TRANSPORT_CLASS   CLASSIFICATION  COMPARTMENT
skill_my_crm                  auto        cloud_rest        unclassified    -

$ mcpip --context sbx authorize skill_my_crm
decision              : allow
status                : committed
transaction_ref       : txn_aef04ed3ae2b4bb7bbb4576964b4bb79
executed_target_class : cloud_rest
worm_sequence         : 77
correlation_id        : 355f2c3e20f8441db5826dfc268155e1
```

**1,238 ms across five commands**, timed end to end from `login` to the `allow`. The
capability UUID is the only value you have to know, and `mcpip sandbox capabilities` prints
all five.

---

## Track B — production posture, fail-closed

Sandbox mints identities for you. Production does not: it verifies a JWT signed by *your*
IdP, refuses to boot without a signed license and a signed boot-integrity manifest, and
404s the token forge. Nothing here is gated behind a purchase — the license is minted
against **your own** root, with no vendor call.

```console
$ python scripts/provision_gateway_keys.py --keys-dir prod --public-dir prod
  WORM epoch-signing  ed25519:15818fb1d0badff3
    private (0600)    prod/worm_signing_ed25519.key   -> MCPIP_WORM_SIGNING_KEY_PATH
    public            prod/worm_signing_ed25519.pub.pem -> auditors
  IdP identity-signing ed25519:33237705a26aaa65
    private (0600)    prod/idp_signing_ed25519.key   -> the token minter, NEVER the gateway
    public            prod/idp_signing_ed25519.pub.pem -> MCPIP_JWT_PUBLIC_KEY_PATH

$ python scripts/gen_release_keys.py
generated license-root: ed25519:bc3e8c402907640f

$ python scripts/gen_license.py --customer "Your Org" --tier self-hosted --days 365 \
    --private-key .keys/license_root_ed25519.pem --out prod/license.json
minted license f056c6c1-15ff-4a93-97e5-123b0c2d990e (tier=self-hosted, expires=2027-08-04T21:53:09Z)

$ python scripts/gen_integrity_manifest.py \
    --private-key .keys/license_root_ed25519.pem --out prod/integrity.json
integrity manifest: 87 files -> prod/integrity.json
  key id: ed25519:bc3e8c402907640f
```

**311 ms for all four.** Then the boot, with the six paths plus your issuer and audience:

```console
$ MCPIP_SANDBOX_MODE=false \
  MCPIP_JWT_PUBLIC_KEY_PATH=prod/idp_signing_ed25519.pub.pem \
  MCPIP_WORM_SIGNING_KEY_PATH=prod/worm_signing_ed25519.key \
  MCPIP_LICENSE_PATH=prod/license.json \
  MCPIP_LICENSE_PUBLIC_KEY_PATH=release/keys/license_root_ed25519.pub.pem \
  MCPIP_INTEGRITY_MANIFEST_PATH=prod/integrity.json \
  MCPIP_INTEGRITY_PUBLIC_KEY_PATH=release/keys/license_root_ed25519.pub.pem \
  MCPIP_JWT_ISSUER=your-idp MCPIP_JWT_AUDIENCE=your-gateway \
  uvicorn app.main:app --port 8081

$ curl -s http://localhost:8081/healthz
{"status":"live","glyph":"◐","loop":"uvloop","version":"3.0.0","region":null}
```

**1,049 ms**, including re-hashing all 87 files in the integrity manifest and verifying
both signatures. The sandbox forge is gone, as it must be:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8081/v1/dev/token \
    -H 'content-type: application/json' -d '{"tenant_id":"t","agent_id":"a"}'
404
```

Two principals, signed by the IdP key the gateway only ever *verifies*, then the same
register-and-authorize cycle over plain HTTP:

```console
$ python scripts/mint_principal.py --idp-key prod/idp_signing_ed25519.key \
    --tenant tenant-acme --agent admin-1 --issuer your-idp --audience your-gateway \
    --capability b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20 --out prod/admin.jwt
$ python scripts/mint_principal.py --idp-key prod/idp_signing_ed25519.key \
    --tenant tenant-acme --agent app-1 --issuer your-idp --audience your-gateway \
    --out prod/agent.jwt

$ curl -s -X POST http://localhost:8081/v1/admin/skills/register \
    -H "authorization: Bearer $ADMIN_JWT" -H 'content-type: application/json' \
    -d '{"alias":"skill_prod_crm","target":"crm.prod.contacts.read"}'
{"registered":"skill_prod_crm"}                                          HTTP 200

$ curl -s -X POST http://localhost:8081/v1/authorize \
    -H "authorization: Bearer $AGENT_JWT" -H 'content-type: application/json' \
    -d '{"source_format":"raw_mcp","tool_call":{"tool":"skill_prod_crm","arguments":{}}}'
{"correlation_id":"20a8b64059a04939bc9fc33fbda0d5d5","decision":"allow",
 "status":"committed","transaction_ref":"txn_ec2d4288b1394f628d500ae54e5646dd",
 "executed_target_class":"cloud_rest","worm_sequence":4,
 "vended_credential":null}                                               HTTP 200
```

**275 ms** for the four calls. `worm_sequence: 4` is the audit record — written before the
decision was returned, on a gateway whose ledger was four events old.

---

## Two pieces of friction, recorded because they were hit

**1. `sandbox dev-token` overwrites the context's token.** Minting the agent identity in
Track A replaced the admin identity in the same context — the store holds one bearer per
context, so an operator who wants to hold both at once needs a second context or `--out
FILE`. That is not wrong, but nothing says so at the moment it happens, and the sequence
above only works because the admin token is used before the agent token is minted. Re-order
those two commands and `register` fails.

**2. A plausible extra key in a request body is a bare `422 invalid request`.** The first
register attempt sent `"transport_class": "cloud_rest"` — a field that does not exist on
`_RegisterSkillBody`, whose model config is `extra="forbid"`:

```console
{"error":"invalid request","correlation_id":"ee8b62ee73b54c0d8e245bba9a59347f"}   HTTP 422
```

No field is named. **This is correct and should not be changed:** the handler
(`_handle_validation`, `app/main.py:2697`) runs on `RequestValidationError`, which fires
*before* any capability check, so anything it disclosed would be disclosed to an
unauthenticated caller. The same route answers an alias *conflict* concretely with a 409 —
because by then the caller has proven `CAP_DIRECTORY_ADMIN`. The asymmetry is the design,
not an oversight. It is recorded here because it costs a first-time integrator a few
minutes, and `docs/start/API.md` is where the field list should be read first.

---

## What this does not prove

- **Not your network.** The 13 s figure is dominated by `pip install` against PyPI from a
  well-connected cloud container. A laptop on hotel wifi will differ, and no page can
  promise otherwise — which is why `quickstart.sh` prints your figure rather than ours.
- **Not a signed release.** Track B mints a license and an integrity manifest against a
  **locally generated** root. That is the documented, free, self-issued production path,
  and it exercises every fail-closed gate — but it is not the offline-signed release
  ceremony in [`RELEASE.md`](../operate/RELEASE.md) §2, and it must not be read as one.
- **Not a real IdP.** `mint_principal.py` stands in for your token minter. JWKS rotation,
  `kid` selection and issuer federation are configured, not measured here.
- **Not execution.** Every `allow` above is an authorization decision plus a WORM record.
  MCPIP does not call your downstream system; whether `crm.prod.contacts.read` is reachable
  is your runtime's business, and deliberately outside the boundary.
- **Not multi-node.** Single gateway process, single Redis. Concurrency behaviour lives in
  [`ORGANIZATION_AT_SCALE.md`](ORGANIZATION_AT_SCALE.md) and
  [`LOAD_AT_SCALE.md`](LOAD_AT_SCALE.md).
- **Not a cold *machine*.** Python, Redis and a C toolchain were already present. The
  quickstart installs Redis via Homebrew on macOS and prints the apt line on Linux; that
  install is not in the 13 s.

## Reproducing

```bash
git clone https://github.com/mcpip-security/mcpip.git && cd mcpip
./scripts/quickstart.sh            # prints its own zero → first governed calls figure
```

For Track B, the four provisioning commands and the boot line are quoted verbatim above and
in [Getting Started](../start/GETTING_STARTED.md#boot-production-fail-closed-zero-hardcoded-secrets). Run them from a
fresh clone; every artefact they write lands in a gitignored directory.
