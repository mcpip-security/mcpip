# Load testing MCPIP

k6 scenarios organised **by client type**, because that is the axis along which
MCPIP's behaviour actually differs — and because one aggregate requests/sec number
hides the thing you need to know: which surface degrades first.

```
load/
├── k6/
│   ├── by-client-type.js     all five client types concurrently, at a sustained rate
│   └── lib/
│       ├── config.js         base URL, tokens, aliases, thresholds
│       └── envelopes.js      real wire shapes per client type
├── cost_by_client_type.py    bytes and latency of ONE step, per client type
└── concurrent_agents.py      many identities at once, optionally from many hosts
```

The two Python harnesses need no k6 and no dependencies beyond the standard library.
They answer narrower questions than the k6 suite: what a single governed step costs a
caller, and whether attribution and per-identity verdicts hold when several agents
fire at once. Both regenerate tables in `docs/evidence/`.

## Correctness first

These are not throughput benchmarks. **A gateway that gets fast by letting a
`pin_required` call through has not improved, it has broken.** Behavioural checks
are tagged `{kind:invariant}` and thresholded at `rate==1.0`; a breach fails the run
regardless of the latency numbers. Never relax an invariant threshold to make a run
pass — that deletes the result rather than achieving it.

## Running

```bash
export MCPIP_BASE=http://127.0.0.1:8080
export MCPIP_AGENT_TOKEN=... MCPIP_DEV_TOKEN=... \
       MCPIP_ADMIN_TOKEN=... MCPIP_AUDITOR_TOKEN=...

MCPIP_RATE=50 MCPIP_DURATION=45s k6 run load/k6/by-client-type.js
k6 run --scenario agent load/k6/by-client-type.js     # a single client type

# per-step cost, as the table in LOAD_AT_SCALE.md
python load/cost_by_client_type.py --allow-alias <auto alias> \
  --stepup-alias <pin_required alias> --markdown

# many identities at once, as the tables in ORGANIZATION_AT_SCALE.md
python load/concurrent_agents.py --agent name=token.jwt:alias [...] \
  --calls 12 --workers 24 [--bind-source-ips]
```

`MCPIP_RATE` is the **agent** arrival rate; other types scale from it (developer ÷2,
pdp ÷5, operator ÷10, auditor ÷20).

Tokens are supplied, never minted here — MCPIP never issues identity, so a load test
must not either. Mint them with `scripts/mint_principal.py`. Note the
non-obvious one: the **auditor token needs `CAP_DIRECTORY_ADMIN`**, because
`/v1/audit/attestation` commits to the global WORM head; `CAP_FORENSIC_READ` buys
the payload-capture route instead.

## Results

Measured runs, the failure direction under saturation, and the honest limits are in
[`docs/evidence/LOAD_AT_SCALE.md`](../docs/evidence/LOAD_AT_SCALE.md) for the
cross-type comparison, and one detail sheet per caller under
[`docs/evidence/clients/`](../docs/evidence/clients/).

## The driving skill

`.claude/skills/mcpip-load-test/SKILL.md` teaches Claude Code to run these, choose a
rate, and interpret the output without treating a deny as a failure.

Note that `.claude/` is **excluded from the built distribution** by
`scripts/build_production_package.py` (`EXCLUDE_PATHS`), which holds agent tooling
out of the product. The scenarios under `load/` ship; the skill that drives them is
repo-only. Move it if you want it in the package.
