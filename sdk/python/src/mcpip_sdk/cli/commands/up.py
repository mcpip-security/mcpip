"""
mcpip_sdk.cli.commands.up — the one blessed front door for a local sandbox.

``mcpip up`` boots the complete local stack — prerequisite checks, Redis
(:63790), a SANDBOX gateway (:8080), and the live company walkthrough — by
running the repo's canonical ``scripts/quickstart.sh``. One source of
truth: the CLI never re-implements the boot steps, so the script and the verb
can never drift. Idempotent (anything already running is reused), sandbox-only
(the script exports ``MCPIP_SANDBOX_MODE=true``; production stays fail-closed
and untouched by this command).

On top of the boot the verb adds two thin, sandbox-only layers of its own:

* **the proof beat** — after a successful boot it fetches the signed audit
  attestation and prints the "you're governed" line (chain intact, WORM head
  seq, Merkle root, signing key). Success is something you can SEE, not
  "the script exited 0". Warn-only: a failed proof never masks a good boot.
* **``--auto``** (self-driving) — drafts a deny-by-default workspace plan from
  a company brief via the gateway's own draft endpoint (deterministic,
  inference-free), validates it, and prints the proposal for review. Nothing
  is applied without explicit consent: ``--yes`` or an interactive "y". The
  apply path is the SAME hardened, WORM-logged admin endpoint the console
  uses — this verb only composes existing surface, it adds none.

The gateway itself ships in the source checkout, not on PyPI, so ``up`` needs
an MCPIP repo to run from: it auto-detects one by walking upward from the
current directory, or takes ``--repo PATH`` explicitly. Outside a checkout it
fails with the exact `git clone` line to run — never a stack trace.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcpip_sdk import (
    CAP_DIRECTORY_ADMIN,
    MCPIPAdminClient,
    MCPIPSandboxOnly,
    SandboxClient,
)
from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.errors import CLIConfigError, ExitCode

# Both must exist for a directory to count as an MCPIP checkout — the script
# alone could be a stray copy; interfaces.py anchors the actual gateway source.
_MARKERS = ("scripts/quickstart.sh", "interfaces.py")

_CLONE_HINT = (
    "mcpip up boots the sandbox gateway from an MCPIP source checkout, and none was "
    "found here.\n"
    "  Get one:   git clone https://github.com/mcpip-security/mcpip && cd mcpip && mcpip up\n"
    "  Or point at an existing checkout:   mcpip up --repo /path/to/mcpip"
)

# Where a reviewed-but-not-applied --auto proposal is saved, so the operator can
# apply it later through the same hardened path: mcpip admin workspace apply --file …
_PROPOSAL_FILE = "mcpip-workspace-plan.json"


def _is_checkout(candidate: Path) -> bool:
    return all((candidate / marker).is_file() for marker in _MARKERS)


def find_repo_root(explicit: str | None) -> Path | None:
    """The MCPIP checkout to boot from: ``--repo`` verbatim, else cwd upward."""
    if explicit is not None:
        root = Path(explicit).expanduser().resolve()
        return root if _is_checkout(root) else None
    cwd = Path.cwd().resolve()
    for candidate in (cwd, *cwd.parents):
        if _is_checkout(candidate):
            return candidate
    return None


# ---------------------------------------------------------------------------
# the proof beat — "you're governed", visibly
# ---------------------------------------------------------------------------


def _print_proof(base_url: str) -> None:
    """
    Fetch the signed audit attestation and print the success beat. Warn-only by
    contract: the boot already succeeded (the walkthrough made real governed
    calls and checked every verdict), so a proof hiccup is reported, never
    escalated into a failed exit.
    """
    try:
        with SandboxClient(base_url) as sandbox:
            sandbox.set_token(
                lambda: sandbox.dev_token(
                    agent_id="up-verify", capabilities=[CAP_DIRECTORY_ADMIN]
                )
            )
            att = sandbox.audit_attestation()
    except Exception as exc:  # noqa: BLE001 — warn-only beat, boot already verified
        print(f"! proof unavailable ({exc.__class__.__name__}) — the stack is up;")
        print("  inspect the chain any time:  mcpip audit attestation")
        return
    intact = "intact ✓" if att.intact else "NOT INTACT ✗"
    head = (
        f"head seq {att.end_seq}"
        if att.end_seq is not None
        # Epoch fields are None until the first epoch seals — a young chain, not a gap.
        else "first epoch not yet sealed (young chain)"
    )
    print()
    print("You're governed — proof, straight from the signed audit chain:")
    print(f"  worm chain     {intact} · {head}")
    if att.merkle_root:
        print(f"  merkle root    {att.merkle_root}")
    print(f"  signing key    {att.signing_key_id}")
    print("  every verdict above was sealed to this chain BEFORE it executed.")


# ---------------------------------------------------------------------------
# --auto: draft → validate → review → (consented) apply
# ---------------------------------------------------------------------------


def _render_proposal(plan: dict[str, Any], summary: str) -> list[str]:
    """Pure renderer for the reviewable proposal — testable without a gateway."""
    def _label(entry: dict[str, Any]) -> str:
        # The plan names things by `label` (display) with `id` as the stable key.
        return str(entry.get("label") or entry.get("id") or "?")

    lines = [f"Workspace proposal ({summary}) — deny-by-default until applied:"]
    org_units = plan.get("org_units")
    if isinstance(org_units, list):
        for ou in org_units:
            if not isinstance(ou, dict):
                continue
            raw_teams = ou.get("teams")
            teams: list[Any] = raw_teams if isinstance(raw_teams, list) else []
            names = ", ".join(_label(t) for t in teams if isinstance(t, dict))
            lines.append(f"  org  {_label(ou)}" + (f"  · teams: {names}" if names else ""))
    skills = plan.get("skills")
    if isinstance(skills, list):
        for sk in skills:
            if not isinstance(sk, dict):
                continue
            alias = str(sk.get("alias", "?"))
            target = str(sk.get("target", "")).strip()
            risk = str(sk.get("risk_tier", "")).strip()
            detail = " · ".join(part for part in (f"→ {target}" if target else "", risk) if part)
            lines.append(f"  skill  {alias}" + (f"  {detail}" if detail else ""))
    lines.append(
        "  nothing here is callable until applied; apply registers the skills and org"
    )
    lines.append("  chart through the hardened admin endpoints, sealed into the WORM log.")
    return lines


def _auto(base_url: str, args: argparse.Namespace) -> int:
    """The self-driving proposal loop. Sandbox-only; consent-gated apply."""
    try:
        with SandboxClient(base_url) as sandbox:
            token = sandbox.dev_token(
                agent_id="up-auto", capabilities=[CAP_DIRECTORY_ADMIN]
            )
    except MCPIPSandboxOnly as exc:
        raise CLIConfigError(
            "mcpip up --auto is sandbox-only: it mints a local dev identity to draft the"
            " plan. Against production, provision through your IdP and use"
            " `mcpip admin workspace draft|validate|apply` instead."
        ) from exc

    with MCPIPAdminClient(base_url, token) as admin:
        draft = admin.workspace_draft(brief=args.brief, company=args.company)
        validation = admin.workspace_validate(draft.plan)
        summary = (
            f"org_units={validation.summary.org_units}"
            f" teams={validation.summary.teams} skills={validation.summary.skills}"
        )
        print()
        for line in _render_proposal(draft.plan, summary):
            print(line)
        if not validation.ok:
            print(f"✕ the draft did not validate: {validation.errors}")
            return int(ExitCode.INVALID_REQUEST)
        for warning in validation.warnings:
            print(f"  warning: {warning}")

        # Consent gate — the "policy PR" is only merged by a human. --yes is the
        # explicit non-interactive consent; otherwise ask, and off-TTY save the
        # proposal for review instead of applying anything.
        if not args.yes:
            if sys.stdin.isatty():
                answer = input("Apply this plan now? [y/N] ").strip().lower()
                if answer not in ("y", "yes"):
                    _save_proposal(draft.plan)
                    return int(ExitCode.OK)
            else:
                _save_proposal(draft.plan)
                print("  (not a TTY and no --yes: proposal saved, nothing applied)")
                return int(ExitCode.OK)

        result = admin.workspace_apply(draft.plan)
        created = list(result.created)
        skipped = list(result.skipped)
        print(
            f"✓ applied · {len(created)} skill(s) registered"
            + (f", {len(skipped)} already present" if skipped else "")
            + " · sealed to the WORM log (admin_action=workspace_plan_apply)"
        )
        for alias in created:
            print(f"    + {alias}")
        print("  see it live:  mcpip admin skills ls   ·   the operator console")
    return int(ExitCode.OK)


def _save_proposal(plan: dict[str, Any]) -> None:
    path = Path.cwd() / _PROPOSAL_FILE
    path.write_text(json.dumps({"plan": plan}, indent=2) + "\n", encoding="utf-8")
    print(f"  proposal saved to {path.name} — review it, then apply with:")
    print(f"    mcpip admin workspace apply --file {path.name}")


# ---------------------------------------------------------------------------
# the verb
# ---------------------------------------------------------------------------


def cmd_up(rt: Runtime, args: argparse.Namespace) -> int:
    root = find_repo_root(args.repo)
    if root is None:
        raise CLIConfigError(_CLONE_HINT)
    script = root / "scripts" / "quickstart.sh"
    if args.print_only:
        # Plan only — nothing starts. Used by tests and the cautious.
        print(f"mcpip up · checkout: {root}")
        print(f"would run: bash {script}")
        print("(prereq checks -> Redis :63790 -> sandbox gateway :8080 -> live walkthrough)")
        print("then: fetch the signed audit attestation and print the governed proof")
        if args.auto:
            print(
                "then (--auto): draft a deny-by-default workspace plan -> validate ->"
                " review -> apply only on explicit consent (--yes or interactive y)"
            )
        return 0
    # Hand the terminal to the script — its own say/note output IS the UX.
    rc = subprocess.call(["bash", str(script)], cwd=str(root))
    if rc != 0:
        return rc
    # The global --gateway flag rides along when given (its default is SUPPRESS,
    # so the attribute may be absent); the quickstart's sandbox port otherwise.
    gateway = getattr(args, "gateway", None) or "http://localhost:8080"
    _print_proof(gateway)
    if args.auto:
        return _auto(gateway, args)
    return 0
