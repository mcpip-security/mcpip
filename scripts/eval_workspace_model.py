#!/usr/bin/env python3
"""
MCPIP — eval harness for the Workspace-Generate model.

Scores a model's drafts against the SAME rules the gateway enforces on apply, so you can
tell whether a base / fine-tuned / prompted model is good enough BEFORE wiring it in.
Metrics per held-out brief:

  * json_valid       — the model returned a parseable JSON object.
  * skills_present   — it produced at least one skill.
  * aliases_valid    — every alias matches ^skill_[a-z0-9_]+$.
  * enums_valid      — every risk_tier / classification is in the allowed set.
  * policy_ok        — no RESTRICTED skill is AUTO (the sender-constraint rule).
  * usable           — all of the above (a draft the gateway would accept as-is).

Run against your local model:
    python scripts/eval_workspace_model.py --data training/data/workspace.eval.jsonl \
        --endpoint http://localhost:11434/v1 --model mcpip-workspace

Offline self-check (no endpoint): scores the dataset's OWN targets — must be 100%, which
proves the scorer + data are correct.
    python scripts/eval_workspace_model.py --data training/data/workspace.eval.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

_ALIAS_RE = re.compile(r"^skill_[a-z0-9_]+$")
_RISK = {"auto", "pin_required"}
_CLASS = {"unclassified", "restricted"}


def _extract_json(text: str) -> Optional[dict[str, Any]]:
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE)
    candidate = m.group(1) if m else text
    i, j = candidate.find("{"), candidate.rfind("}")
    if i == -1 or j <= i:
        return None
    try:
        obj = json.loads(candidate[i : j + 1])
        return obj if isinstance(obj, dict) else None
    except (ValueError, TypeError):
        return None


def _score(raw: Optional[dict[str, Any]]) -> dict[str, bool]:
    if raw is None:
        return {k: False for k in ("json_valid", "skills_present", "aliases_valid", "enums_valid", "policy_ok", "usable")}
    skills = raw.get("skills") if isinstance(raw.get("skills"), list) else []
    aliases_valid = all(isinstance(s, dict) and isinstance(s.get("alias"), str) and _ALIAS_RE.match(s["alias"]) for s in skills) if skills else False
    enums_valid = all(isinstance(s, dict) and s.get("risk_tier", "auto") in _RISK and s.get("classification", "unclassified") in _CLASS for s in skills) if skills else False
    policy_ok = all(not (s.get("classification") == "restricted" and s.get("risk_tier") != "pin_required") for s in skills if isinstance(s, dict))
    r = {
        "json_valid": True,
        "skills_present": len(skills) > 0,
        "aliases_valid": bool(aliases_valid),
        "enums_valid": bool(enums_valid),
        "policy_ok": bool(policy_ok),
    }
    r["usable"] = all(r.values())
    return r


def _call_model(endpoint: str, model: str, system: str, user: str) -> str:
    body = json.dumps({
        "model": model, "temperature": 0.2, "stream": False,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }).encode()
    req = urllib.request.Request(endpoint.rstrip("/") + "/chat/completions", data=body,
                                headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return str(((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "")


def main() -> int:
    ap = argparse.ArgumentParser(description="Score a workspace model's drafts vs the gateway rules.")
    ap.add_argument("--data", required=True, help="held-out JSONL (chat format)")
    ap.add_argument("--endpoint", default=None, help="OpenAI-compatible base URL; omit for offline self-check")
    ap.add_argument("--model", default="mcpip-workspace")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    rows = [json.loads(l) for l in Path(args.data).read_text().splitlines() if l.strip()]
    if args.limit:
        rows = rows[: args.limit]
    if not rows:
        print("no eval rows found", file=sys.stderr)
        return 2

    agg = {k: 0 for k in ("json_valid", "skills_present", "aliases_valid", "enums_valid", "policy_ok", "usable")}
    n = 0
    for ex in rows:
        msgs = ex["messages"]
        system = next(m["content"] for m in msgs if m["role"] == "system")
        user = next(m["content"] for m in msgs if m["role"] == "user")
        if args.endpoint:
            try:
                content = _call_model(args.endpoint, args.model, system, user)
            except (urllib.error.URLError, TimeoutError) as exc:
                print(f"model call failed: {exc}", file=sys.stderr)
                return 2
        else:
            # Offline self-check: score the dataset's own target (must be perfect).
            content = next(m["content"] for m in msgs if m["role"] == "assistant")
        s = _score(_extract_json(content))
        for k in agg:
            agg[k] += int(s[k])
        n += 1

    print(f"scored {n} briefs{' via ' + args.endpoint + ' (' + args.model + ')' if args.endpoint else ' (offline self-check)'}")
    for k in ("json_valid", "skills_present", "aliases_valid", "enums_valid", "policy_ok", "usable"):
        print(f"  {k:15s} {agg[k]:4d}/{n}  {100.0 * agg[k] / n:5.1f}%")
    if not args.endpoint and agg["usable"] != n:
        print("SELF-CHECK FAILED — the dataset or scorer is wrong", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
