# NOTICES — third-party components & legal posture

This file records MCPIP's stance on third-party code and models, so the legal position is
explicit and defensible. It is informational, not legal advice — have counsel confirm
before you redistribute.

## Bundled / referenced open-source models

MCPIP's **Workspace Generate** feature can be powered by a slim, self-hosted model that the
operator runs locally (the brief never leaves the perimeter; MCPIP never calls a hosted
model). MCPIP ships the **recipe**, not model weights:

- **Recommended base — Qwen2.5 (0.5–1.5B), Apache-2.0.** Chosen deliberately because
  Apache-2.0 is clean to fine-tune **and redistribute** with no field-of-use, naming,
  attribution, or MAU restrictions. This is the base wired into
  `training/Modelfile.workspace` and `training/qlora_workspace.yaml`.
- **Not used as the shipping base — Llama 3.2.** Excellent model, but the Llama 3.2
  Community License carries conditions (a "Built with Llama" attribution, a derivative
  **naming** requirement, an acceptable-use policy, and a 700M-MAU clause). Operators may
  point the console at a local Llama model for their own internal use, but MCPIP does not
  ship or fine-tune Llama as a redistributable artifact — avoiding the license question
  rather than managing it.

If you swap the base, keep it Apache-2.0 / MIT for anything you redistribute, and preserve
the upstream LICENSE + NOTICE with the shipped weights.

## Training data

The fine-tune dataset is **synthetic and self-authored**: `scripts/gen_workspace_dataset.py`
generates `(brief → plan)` pairs whose labels come from MCPIP's **own** deterministic
generator (`services/workspace_plan.py`). It contains **no customer data** and **no output
copied from a third-party model**. Optional distillation (augmenting nuance with a capable
model, once, at build time, on synthetic briefs) is a build step, not a runtime dependency,
and still uses no customer data — but if you use a hosted model to generate data, check
that provider's terms on training competing models.

## Clean-room re: xai-org/grok-build

The open-source Grok Build (Apache-2.0) prompted a design discussion but **none of its code
was cloned, read, or copied** into this repository. Workspace Generate was built entirely
from MCPIP's own components. Any future connector for the Grok/xAI dialect will be a
**clean-room** implementation against the documented wire schema; if code is ever vendored,
this file and the shipped tree will carry Apache-2.0's required LICENSE + NOTICE, retained
notices, and a statement of changes. MCPIP uses no xAI/Grok trademarks or branding.

## Python / JS dependencies

Runtime dependencies are declared in `pyproject.toml` / `requirements.txt` and
`dashboard/package.json`; a CycloneDX SBOM is produced per release
(`scripts/build_sbom.sh`) and shipped in the air-gap bundle. Review the SBOM for the full
transitive license set before distribution.
