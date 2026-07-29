# Specializing the Workspace-Generate model

> **None of this is required.** The gateway is inference-free by invariant — it ships
> no weights and never calls a model. The optional drafting path talks to *any*
> OpenAI-compatible endpoint you run, so you can point it at whatever model you
> already have and skip this directory entirely. See
> [`docs/integrate/LOCAL_MODEL.md`](../docs/integrate/LOCAL_MODEL.md) for the (two-setting)
> contract.
>
> This file is for the case where a stock model isn't clearing your quality bar and
> you want to specialize one. The Qwen2.5 + QLoRA recipe below is **one worked
> example**, not a recommendation for your situation.

Make a **slim, local, open-source** model good at one narrow job: turn a company brief into
a governed `WorkspacePlan`. Everything here is local and air-gapped — the brief never
leaves the perimeter — and every draft still passes through the gateway's authoritative
validation + human review, so the model only has to be *good*, never *trusted*.

Climb this ladder only as far as you need — most people stop at Tier 0:

## Tier 0 — nothing (try first)
The local-model path already works with a stock base + our system prompt, and
`normalizePlan` + the gateway re-validate every draft. Point the console at any small
instruct model you already run — `qwen2.5:1.5b`, `llama3.2:1b`, `phi3:mini`, or a model
served by llama.cpp / vLLM / LM Studio — and see if quality is fine. Often it is, and
you are done.

## Tier 1 — prompt + few-shot (minutes, no GPU)
Bake the system prompt + a couple of exemplars into a custom Ollama model:
```bash
ollama pull qwen2.5:1.5b
ollama create mcpip-workspace -f training/Modelfile.workspace
OLLAMA_ORIGINS='*' ollama serve
```
Console → Tenants → Workspace Generate → model settings → `http://localhost:11434/v1`,
model `mcpip-workspace`.

## Tier 2 — QLoRA fine-tune (≈1h on one GPU)
When you want reliable JSON + your house conventions in the weights:
```bash
# 1. Synthesize the dataset (policy-correct labels from OUR own generator — no customer data).
python scripts/gen_workspace_dataset.py --out training/data/workspace.jsonl -n 2000 --split

# 2. Fine-tune (axolotl QLoRA on the Apache-2.0 base).
accelerate launch -m axolotl.cli.train training/qlora_workspace.yaml

# 3. Merge + convert to GGUF (llama.cpp), then register with Ollama with the SYSTEM block.
#    ollama create mcpip-workspace -f <Modelfile pointing at the GGUF>

# 4. Score it against held-out briefs with the SAME rules the gateway enforces.
python scripts/eval_workspace_model.py --data training/data/workspace.eval.jsonl \
    --endpoint http://localhost:11434/v1 --model mcpip-workspace
```

The eval prints `usable %` — the share of drafts the gateway would accept as-is. Ship the
model when that's high enough for your operators; the guardrail covers the rest.

## Distillation (optional data augmentation)
The default labels come from MCPIP's deterministic generator — perfect on policy, limited
on nuance. To add nuance ("HIPAA telehealth" → PHI-aware classifications), you can augment
the dataset with a **capable model** run **once, offline, at build time** on synthetic
briefs. That's a build step, never a runtime dependency, and uses no customer data — so it
doesn't change the air-gap or legal posture of what you ship.

## Why the Apache-2.0 base
`Qwen/Qwen2.5-1.5B-Instruct` is Apache-2.0 — clean to fine-tune **and redistribute**, with
none of the Llama Community License strings (naming, attribution, acceptable-use, MAU
clause). Since you'll ship the fine-tuned model to customers, that removes the license
question instead of managing it. See `NOTICES.md` for the full legal posture.

## Turnkey (part of the app)

For Tier 1, `scripts/provision_workspace_model.sh` does the whole setup in one command —
checks for Ollama, pulls the Apache-2.0 base, builds `mcpip-workspace` from the Modelfile,
and verifies a draft. It's referenced from `scripts/quickstart_demo.sh` so the model is
part of standard bring-up, not a side chore.
