# Branch rulesets

GitHub rulesets are repository *settings*, not repository *files* — nothing in this
directory takes effect on its own. These JSON documents exist so the protection on
this repo is reviewable in git, and so it can be restored exactly rather than
reconstructed from memory after an accident or a migration.

## Importing

**Settings → Rules → Rulesets → New ruleset → Import a ruleset**, then upload
`main-protection.json`. Direct link:

```
https://github.com/mcpip-security/mcpip/settings/rules/new?target=branch&enforcement=disabled
```

The URL above creates it **disabled**. That is a good way to land it, but do not
leave it there: a disabled ruleset enforces nothing. Import, read what it says, then
set enforcement to **Active**. (`main-protection.json` ships with
`"enforcement": "active"` so the imported ruleset is correct as written; the query
parameter in the link is what starts it disabled.)

## What `main-protection.json` enforces, and why each rule is there

| Rule | What it stops |
|---|---|
| `deletion` | Deleting the branch. |
| `non_fast_forward` | Force-pushing — rewriting published history. On a repository whose value proposition is a tamper-evident audit trail, a rewritable trunk is the wrong first impression. |
| `pull_request` (1 approval, code-owner review, stale dismissal, last-push approval, thread resolution) | Direct pushes to trunk, and self-merging a change nobody read. `require_last_push_approval` is the one people skip: without it, an approved PR can be amended after approval and merged with the approval still showing. |
| `required_status_checks` (all four CI jobs, strict) | Merging red, and merging green-against-a-stale-base. `strict_required_status_checks_policy` forces the branch to be up to date first, which is what makes "CI was green" mean anything. |

The four contexts are the `name:` values in `.github/workflows/ci.yml`. **They are
matched as literal strings** — rename a job there and the check silently stops being
required, which fails open. Change both together.

## Two things deliberately NOT in it

**No `required_signed_commits`.** It would be defensible here given the release
signing ceremony, but it is a workflow decision with real friction (every
contributor and every automation needs a signing key) and it locks out unsigned
automation immediately. Turn it on when the contributor set is ready for it, not
because it sounds strict.

**No bypass actors.** `"bypass_actors": []` means the rules apply to everyone,
admins included. Adding yourself as a bypass actor is the most common way a
protected branch quietly becomes unprotected. If you need an escape hatch, prefer
temporarily disabling the ruleset — that is visible in the audit log; a standing
bypass is not.

## Before you enable it

Two facts about this repository as it stands:

1. **The default branch is `claude/new-session-6g22zk`, not `main`.** The ruleset
   targets both (`refs/heads/main` and `~DEFAULT_BRANCH`) so it is correct either
   way — but the default should be switched to `main` (Settings → Branches), after
   which the session branch can be deleted.
2. **CI does not run on this repo's pull requests until a PR exists that triggers
   it.** `ci.yml` runs on `pull_request: {}` and on pushes to `main`, so required
   checks will resolve normally — but a required context that has *never* reported
   blocks the first PR until it does. If that happens, push any commit to a PR once
   to register the contexts, or temporarily set enforcement to Evaluate.
