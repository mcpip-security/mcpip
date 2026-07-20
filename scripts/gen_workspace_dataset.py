#!/usr/bin/env python3
"""
MCPIP — synthetic training-data generator for the Workspace-Generate model.

Emits chat-format JSONL pairs (company brief → WorkspacePlan JSON) to fine-tune a SLIM
local model to draft governed workspaces. The teacher is MCPIP's OWN deterministic
generator (``services.workspace_plan.draft_plan_from_brief``), so every target is
policy-correct by construction: reads AUTO+unclassified, mutations PIN_REQUIRED,
sensitive-domain mutations RESTRICTED+PIN, valid alias charset.

    ◐ "Distill the policy into the weights: the deterministic generator teaches the
       tiny model our exact rules — once, offline, from synthetic briefs only."

CLEAN BY CONSTRUCTION:
  * No customer data — every brief is synthesized here from an industry/team/size grid.
  * No external model call — the labels come from our own code, not a hosted LLM.
  * Output is the SAME {teams, skills} contract the console's local-model path expects
    (``dashboard/src/lib/localModel.ts`` SYSTEM_PROMPT), so a model trained on this data
    drops straight into the wired path and its drafts flow through the same guardrail.

Usage:
    python scripts/gen_workspace_dataset.py --out training/data/workspace.jsonl -n 1200
    python scripts/gen_workspace_dataset.py --split            # also write a 10% eval set
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from services.workspace_plan import draft_plan_from_brief  # noqa: E402

# MUST match dashboard/src/lib/localModel.ts SYSTEM_PROMPT — the fine-tune has to learn the
# exact contract the console sends at inference. Kept verbatim (a test asserts parity).
SYSTEM_PROMPT = """You design a workspace for a zero-trust security gateway.
Given a company description, output ONLY a JSON object (no prose, no markdown) of this exact shape:
{"teams":["Team Name", ...],
 "skills":[{"alias":"skill_<team>_<action>","target":"rest.<team>.<action>","risk_tier":"auto"|"pin_required","classification":"unclassified"|"restricted"}]}
Rules:
- alias: lowercase letters, digits, underscores only; start with "skill_".
- Reads/queries: risk_tier "auto", classification "unclassified".
- Writes/mutations (create/update/delete/post/approve/deploy): risk_tier "pin_required".
- Sensitive-domain writes (finance, payroll, hr, security, legal, health): classification "restricted" AND risk_tier "pin_required".
- Never use classification "restricted" with risk_tier "auto".
- 2-4 skills per team; at most 24 skills total. Output JSON only."""

# --- Brief synthesis grid (all synthetic — no real companies). ---------------------

_INDUSTRIES = [
    ("fintech", ["engineering", "finance", "support", "security", "data"]),
    ("digital bank", ["engineering", "finance", "security", "legal", "support"]),
    ("telehealth platform", ["engineering", "support", "data", "legal", "hr"]),
    ("hospital network", ["operations", "hr", "legal", "data", "security"]),
    ("e-commerce marketplace", ["engineering", "sales", "support", "operations", "marketing"]),
    ("SaaS startup", ["engineering", "product", "sales", "support", "finance"]),
    ("logistics company", ["operations", "engineering", "finance", "support"]),
    ("gaming studio", ["engineering", "product", "marketing", "data"]),
    ("biotech lab", ["data", "engineering", "legal", "operations", "security"]),
    ("law firm", ["legal", "finance", "hr", "operations"]),
    ("marketing agency", ["marketing", "sales", "finance", "support"]),
    ("manufacturer", ["operations", "engineering", "finance", "hr"]),
    ("edtech company", ["engineering", "product", "support", "data", "marketing"]),
    ("media company", ["marketing", "product", "engineering", "legal"]),
    ("energy utility", ["operations", "engineering", "security", "finance"]),
    ("insurance company", ["finance", "legal", "data", "support", "security"]),
    ("real-estate platform", ["engineering", "sales", "finance", "operations"]),
    ("consulting firm", ["operations", "finance", "hr", "sales"]),
    ("cybersecurity vendor", ["security", "engineering", "sales", "support", "data"]),
    ("nonprofit", ["operations", "finance", "marketing", "hr"]),
]

_SIZES = ["small", "mid-sized", "fast-growing", "enterprise", "early-stage", "global", "regional"]

_TEMPLATES = [
    "A {size} {industry} with {teams} teams.",
    "We're a {size} {industry}. Our teams are {teams}.",
    "{industry_cap} — {size}, organized into {teams}.",
    "A {industry} running {teams}.",
    "Our company is a {size} {industry} with {teams} functions.",
]


def _join_teams(teams: list[str]) -> str:
    if len(teams) == 1:
        return teams[0]
    return ", ".join(teams[:-1]) + " and " + teams[-1]


def _project(plan: dict[str, Any]) -> dict[str, Any]:
    """Project the teacher's full plan to the {teams, skills} contract the model emits."""
    org = plan.get("org_units") or [{}]
    teams = [t.get("label", "") for t in (org[0].get("teams") or [])]
    skills = [
        {"alias": s["alias"], "target": s["target"], "risk_tier": s["risk_tier"], "classification": s["classification"]}
        for s in plan.get("skills", [])
    ]
    return {"teams": teams, "skills": skills}


def _make_example(rng: random.Random) -> dict[str, Any]:
    industry, team_pool = rng.choice(_INDUSTRIES)
    k = rng.randint(2, min(5, len(team_pool)))
    teams = rng.sample(team_pool, k)
    size = rng.choice(_SIZES)
    template = rng.choice(_TEMPLATES)
    company = f"{industry.title()} Co"
    brief = template.format(
        size=size, industry=industry, industry_cap=industry.capitalize(), teams=_join_teams(teams)
    )
    # The teacher is keyword-driven; the brief names the teams so it detects them.
    plan = draft_plan_from_brief(brief, company, company.lower().replace(" ", "-"))
    target = _project(plan)
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Company: {company}\nBrief: {brief}"},
            {"role": "assistant", "content": json.dumps(target, separators=(",", ":"))},
        ]
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Synthesize brief→plan JSONL for the workspace model.")
    ap.add_argument("--out", default="training/data/workspace.jsonl")
    ap.add_argument("-n", "--count", type=int, default=1200)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--split", action="store_true", help="also write a 10%% held-out eval set (.eval.jsonl)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    # De-dup by (user brief) so the set is diverse, not repetitive.
    seen: set[str] = set()
    examples: list[dict[str, Any]] = []
    attempts = 0
    while len(examples) < args.count and attempts < args.count * 50:
        attempts += 1
        ex = _make_example(rng)
        key = ex["messages"][1]["content"]
        if key in seen:
            continue
        seen.add(key)
        examples.append(ex)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    n_eval = len(examples) // 10 if args.split else 0
    train, evalset = examples[n_eval:], examples[:n_eval]

    with out.open("w") as f:
        for ex in train:
            f.write(json.dumps(ex) + "\n")
    print(f"wrote {len(train)} train examples → {out}")
    if args.split:
        ep = out.with_suffix(".eval.jsonl")
        with ep.open("w") as f:
            for ex in evalset:
                f.write(json.dumps(ex) + "\n")
        print(f"wrote {len(evalset)} eval examples → {ep}")
    print(f"(unique briefs: {len(seen)}; deterministic under --seed {args.seed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
