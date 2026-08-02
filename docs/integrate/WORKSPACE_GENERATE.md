# Workspace Generate — brief → a governed workspace

Describe the company; get a **governed workspace scaffold** — an org chart and a starter
skill catalog with safe risk tiers — that the operator reviews and applies through the
same hardened admin endpoints they'd use by hand.

**Where it lives in the console: first-run setup.** The three endpoints below are ordinary
admin routes and can be driven from a terminal at any time — what is setup-only is the
console *entry point*, not the capability. In the onboarding "Describe your company" step
the operator types a brief, MCPIP drafts a starter workspace (teams + tools), they review
and refine it, and on launch the drafted workspace is **provisioned to the connected
gateway** — validated and WORM-audited — instead of only being written to local config.
There is no separate console tab: setup is where a workspace is generated, and tools are
refined afterwards from **Skills & Tools** (the Alias Registry) like any other skill.

## What it is — and is not

- **The safety is deterministic; the intelligence is optional.** The draft is a pure,
  inference-free heuristic — `services/workspace_plan.py`'s `draft_plan_from_brief` on the
  gateway, mirrored client-side by `lib/starterKit.ts` for the offline setup flow. It
  ships and is fully tested with **no model**. A richer **local-model draft** (below) is an
  OPTIONAL packaged toolchain that produces the SAME plan shape and would flow through the
  identical validate → review → apply path. **The gateway core stays inference-free.**

## Local-model drafting (optional, air-gapped, packaged toolchain)

The company brief describes the customer's own company, so **it must never leave the
perimeter** — MCPIP never calls a hosted/cloud model. The packaged workspace model is a
**slim, self-hosted open-source model** an operator runs entirely inside the boundary and
calls directly (the gateway stays inference-free; inference is client-side). Setup itself
uses the deterministic draft; the local model is shipped as a specialization toolchain you
can provision and wire in — see `training/README.md` and
`./scripts/provision_workspace_model.sh`.

1. Install [Ollama](https://ollama.com) and pull a slim model:
   ```bash
   ollama pull llama3.2:1b        # or qwen2.5:1.5b, phi3:mini — a 1–2B model is plenty
   ```
2. Allow the console's origin to call Ollama (browser CORS):
   ```bash
   OLLAMA_ORIGINS='*' ollama serve      # or set it to the console origin
   ```
3. Provision the specialized model (Apache-2.0 base, synthetic labels from the deterministic
   teacher — no customer data): `./scripts/provision_workspace_model.sh`.

Any OpenAI-compatible server works (Ollama, llama.cpp `llama-server`, vLLM, LM Studio). The
model only **drafts** — its output is normalized (`normalizePlan`: valid alias charset,
risk/classification enums, `restricted`⇒PIN, dedupe, cap) and then **re-validated by the
gateway's authoritative rules** and reviewed by a human before anything applies. A rough
draft from a tiny model is caught by the same guardrail as a hand-typed one. The canonical
inference contract lives in `dashboard/src/lib/localModel.ts` (`SYSTEM_PROMPT`), which the
training pipeline (`scripts/gen_workspace_dataset.py`) and parity test
(`tests/test_workspace_model_assets.py`) bind to.

- **No fabricated capability.** Generated skills are tenant-wide `cloud_rest` catalog
  entries — exactly what `register_skill` supports — with risk tiers and classifications
  that satisfy the production sender-constraint lint (a RESTRICTED skill is always
  PIN-gated). The plan never invents compartments, cloud role ARNs, or secrets, because
  those are not operator-creatable at runtime. Wiring a real backend behind a generated
  skill remains a separate, explicit step (as it is for any registered skill).
- **Human-in-the-loop, fail-closed.** Nothing applies without the operator's action. The
  gateway **re-validates** the plan on apply (a structurally-invalid plan, any
  policy-violating skill, or a malformed org chart is an opaque deny — nothing is
  applied). Every apply is WORM-logged (`workspace_plan_apply`). Apply is **idempotent** —
  existing aliases are skipped.

## The endpoints (all `CAP_DIRECTORY_ADMIN`, tenant-scoped, opaque deny)

| Endpoint | Does |
|----------|------|
| `POST /v1/admin/workspace/draft` | Deterministic brief → plan proposal. No mutation. |
| `POST /v1/admin/workspace/plan/validate` | Dry-run: structural + authoritative per-skill checks; flags existing aliases as "will be skipped". No mutation. |
| `POST /v1/admin/workspace/plan/apply` | Re-validate fail-closed, then persist the org chart (directory doc) + register each NEW skill via the authoritative overlay path. Idempotent; WORM-logged. Setup's launch step calls this. |

The per-skill enforcement (`_overlay_skill_invalid`) is the **single source of truth**
shared with `register_skill`; the plan service's structural checks are a best-effort
first pass, and apply always re-checks against the authoritative rule.

## The plan shape

```json
{
  "company": "Acme Co",
  "tenant": "acme-co",
  "org_units": [
    { "id": "acme-co", "label": "Acme Co", "tenant": "acme-co",
      "teams": [ { "id": "team-engineering", "label": "Engineering", "compartment": "…" } ] }
  ],
  "skills": [
    { "alias": "skill_company_overview",            "target": "rest.company.overview.read", "risk_tier": "auto",         "classification": "unclassified" },
    { "alias": "skill_finance_invoice_post",        "target": "rest.finance.invoice.post",  "risk_tier": "pin_required", "classification": "restricted" }
  ]
}
```

Drafting rules: reads are `auto`+`unclassified`; mutations are `pin_required`; sensitive
domains (finance/hr/security/legal) mark their mutations `restricted` (and, being
`pin_required`, they satisfy the sender-constraint lint).

## Try it (sandbox)

```bash
./scripts/quickstart.sh          # gateway on :8080
# in the console: run first-run setup → "Describe your company" → type a brief →
#                 Design my workspace → review/remove tools → Enter console (provisions)
# or from a terminal, with an admin token:
curl -s http://localhost:8080/v1/admin/workspace/draft \
     -H "Authorization: Bearer $ADMIN" -H 'content-type: application/json' \
     -d '{"brief":"engineering, finance, support","company":"Acme","tenant":"acme"}'
```

The generated skills become **real** registered skills (visible in the Alias Registry),
the org chart persists to the directory, and the apply appears in the WORM ledger.

## Limitations (honest)

- **Skills are tenant-wide.** Operator-registered (overlay) skills are always tenant-wide
  `cloud_rest` — `register_skill` does not support compartment-scoping — so generated
  skills are company-wide catalog entries. The org chart captures the team structure;
  scoping a skill to a compartment stays a company-init / boot concern.
- **Targets are placeholders.** A generated skill's `target` is a plausible internal
  label the operator repoints at a real system; the `cloud_rest` transport is a
  simulation until a real backend is wired.
