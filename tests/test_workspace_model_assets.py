"""
Guards for the Workspace-Generate model assets — the training/inference contract must not
drift, and the synthetic labels must stay policy-correct. Pure, no network, no model.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent


def _load(path: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, _ROOT / path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_GEN = _load("scripts/gen_workspace_dataset.py", "gen_workspace_dataset")
_EVAL = _load("scripts/eval_workspace_model.py", "eval_workspace_model")


def _normalize(s: str) -> str:
    """Collapse whitespace so a TS template literal and a Python string compare cleanly."""
    return re.sub(r"\s+", " ", s).strip()


def test_system_prompt_parity_python_vs_console() -> None:
    """The prompt the dataset trains on MUST equal the one the console sends at inference,
    or the fine-tune learns a contract it is never asked to fulfill (train/serve skew)."""
    ts = (_ROOT / "dashboard/src/lib/localModel.ts").read_text()
    m = re.search(r"const SYSTEM_PROMPT = `([\s\S]*?)`;", ts)
    assert m, "could not find SYSTEM_PROMPT in localModel.ts"
    assert _normalize(m.group(1)) == _normalize(_GEN.SYSTEM_PROMPT), "training/inference prompt drift"


def test_generated_targets_are_policy_correct() -> None:
    """Every synthetic label obeys the overlay policy — the teacher can never mislabel."""
    import random

    rng = random.Random(7)
    n = restricted = 0
    for _ in range(60):
        ex = _GEN._make_example(rng)
        target = json.loads(ex["messages"][2]["content"])
        for s in target["skills"]:
            n += 1
            assert re.match(r"^skill_[a-z0-9_]+$", s["alias"]), s["alias"]
            assert s["risk_tier"] in ("auto", "pin_required")
            assert s["classification"] in ("unclassified", "restricted")
            if s["classification"] == "restricted":
                restricted += 1
                assert s["risk_tier"] == "pin_required"
    assert n > 0 and restricted > 0  # we actually exercised both tiers.


def test_eval_scorer_accepts_a_good_plan_and_flags_a_bad_one() -> None:
    good = {"skills": [{"alias": "skill_finance_invoice_post", "target": "rest.x", "risk_tier": "pin_required", "classification": "restricted"}]}
    bad = {"skills": [{"alias": "Bad Alias!", "target": "rest.x", "risk_tier": "auto", "classification": "restricted"}]}
    gs = _EVAL._score(good)
    bs = _EVAL._score(bad)
    assert gs["usable"] is True
    assert bs["usable"] is False and bs["aliases_valid"] is False and bs["policy_ok"] is False


def test_eval_extract_json_handles_fences_and_prose() -> None:
    assert _EVAL._extract_json('prefix ```json\n{"skills":[]}\n``` suffix') == {"skills": []}
    assert _EVAL._extract_json("no json here") is None
