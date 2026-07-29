# Bring your own model

Short version: **you don't need one.** And if you want one, MCPIP does not care
which — anything that speaks the OpenAI `/chat/completions` shape works, and
nothing in the gateway changes.

## What the gateway does with a model

Nothing. That is a hard invariant, not a default.

`services/workspace_plan.py` and `POST /v1/admin/workspace/draft` are
**inference-free**: brief → plan is a deterministic heuristic. The gateway ships
no weights, imports no inference library, and makes no outbound model call. Turn
off every model in your estate and MCPIP behaves identically.

The optional model lives entirely **client-side**, in the console
(`dashboard/src/lib/localModel.ts`). It exists because the brief describes the
customer's own company and must not leave the perimeter, so the console calls an
endpoint *you* run, directly — never a hosted model, and never through the
gateway.

> **Current status.** The drafting client is retained for the model toolchain but
> is **not wired into a console panel** today: workspace generation uses the
> deterministic offline starter draft (`lib/starterKit.ts`). If you are looking for
> a model-powered panel in the UI, it isn't there yet. Everything below describes
> the contract that toolchain binds to.

## The whole contract

Two settings:

| setting | what it is | example |
|---|---|---|
| `endpoint` | any OpenAI-compatible base URL | `http://localhost:11434/v1` |
| `model` | whatever that endpoint calls the model | `qwen2.5:1.5b` |

The client POSTs `{endpoint}/chat/completions` with a system prompt and the brief,
and reads back a plan. That is the entire integration surface. If your runtime
serves that shape, it works.

Known-good runtimes — none of them special-cased, they simply speak the protocol:

| runtime | typical base URL |
|---|---|
| Ollama | `http://localhost:11434/v1` |
| llama.cpp (`llama-server`) | `http://localhost:8080/v1` |
| vLLM | `http://localhost:8000/v1` |
| LM Studio | `http://localhost:1234/v1` |
| Your own internal OpenAI-compatible gateway | whatever you serve |

Model size is your call too. The task is narrow and every draft is re-validated,
so a 1B model is a reasonable starting point — but a 70B on your own hardware is
equally fine, and so is a model you trained yourself with no relationship to
anything in `training/`.

## Why you can be relaxed about model quality

The model only **drafts**. Its output is normalized, then re-validated by the
gateway's authoritative rules, then reviewed by a human before anything applies. A
weak model produces a rough draft that the same guardrail catches — it cannot
produce an unsafe outcome, only an unhelpful one.

This is why "use whatever you have" is honest advice rather than a shrug: the
blast radius of a bad model here is a wasted click, not a bad authorization. The
authorization path never consults a model at all.

## Checking whether your model is good enough

`scripts/eval_workspace_model.py` scores any endpoint against held-out briefs
using the same rules the gateway enforces:

```bash
python3 scripts/eval_workspace_model.py \
  --data training/data/workspace.eval.jsonl \
  --endpoint http://localhost:8000/v1 \
  --model my-own-model
```

It prints `usable %` — the share of drafts the gateway would accept as-is. Pick
the threshold that suits your operators. Run it with no `--endpoint` for an
offline self-check of the dataset itself.

Keep the system prompt from `training/Modelfile.workspace` if you want inference to
match what the toolchain assumes; `dashboard/src/lib/localModel.ts` holds the
canonical `SYSTEM_PROMPT` and is the single source of truth for that contract.

## If you want to specialize a model

Entirely optional, and only worth it if a stock model isn't clearing your bar.
[`training/README.md`](../../training/README.md) walks a four-tier ladder whose
first tier is "try a stock model and see" — most people stop there.

The QLoRA recipe in `training/qlora_workspace.yaml` is **one worked example**, not
a requirement or a recommendation for your situation. It happens to fine-tune
Qwen2.5-1.5B because that base is Apache-2.0 and therefore clean to redistribute
if you ship the result to customers — see [`docs/policies/NOTICES.md`](../../docs/policies/NOTICES.md) for that
reasoning. If you are not redistributing, the licence question mostly evaporates
and you should use whatever base you already trust.

Swap the base, swap the trainer, swap the serving runtime — nothing downstream
depends on those choices. The only thing that has to hold is the
`/chat/completions` shape above.

## What MCPIP ships

The recipe, never weights. No model is bundled, downloaded at install, or
required at boot. That keeps the air-gap story simple and means adopting MCPIP
never obliges you to adopt someone else's model.
