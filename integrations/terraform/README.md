# Terraform provider for MCPIP

Declare the catalog and the deny-only policy overlay as code, and review changes to
them the way security teams already review everything else — in a pull request, with a
plan attached.

```hcl
resource "mcpip_skill" "ledger_post" {
  alias          = "skill_ledger_post"
  target         = "cloud_rest:https://ledger.internal/v1/postings"
  risk_tier      = "pin_required"
  classification = "restricted"
}

resource "mcpip_policy" "limits" {
  document = jsonencode({
    schema = "mcpip-policy/1"
    rules = [{
      kind         = "amount"
      scope        = "alias"
      scope_value  = mcpip_skill.ledger_post.alias
      amount_field = "amount"
      max_amount   = "500.00"
    }]
  })
}
```

A worked example with velocity limits and a drift assertion is in
[`examples/main.tf`](examples/main.tf).

---

## Read this before pointing it at production

**The state file holds the alias→target mapping.**

No admin route on the gateway ever returns `target`. Keeping that mapping inside the
gateway is the product's central invariant — it is why a compromised agent's tool names
are worthless anywhere else. Managing aliases from Terraform necessarily writes the map
into `terraform.tfstate`.

That is not a bug in the provider and it is not something the provider can fix; it is
the cost of declaring the catalog somewhere other than the gateway. Decide deliberately:

- Use an **encrypted remote backend** with access control (S3 + KMS, Terraform Cloud,
  or equivalent). Never a local state file, never git.
- Treat state as **secret material of the same class as the gateway's own directory**.
  Anyone who can read it can enumerate every real system your agents can reach.
- `target` is marked sensitive, so it is redacted in plan output and `terraform show` —
  but that is cosmetic. The state file itself is the exposure.

If that trade is not one you want to make, keep the catalog in gateway config and use
this provider only for `mcpip_policy`, which carries no targets and no identities.

---

## What it manages, and what it deliberately does not

| | |
|---|---|
| `mcpip_skill` | An operator-registered alias→target binding. Create, read, delete. |
| `mcpip_policy` | The tenant's deny-only policy document. Full CRUD, with real drift detection. |
| `mcpip_skills` | Data source: the aliases the gateway actually has. |

**`mcpip_skill` can never update in place.** Every attribute forces replacement, because
`POST /v1/admin/skills/register` is additive-only and there is no update route at all.
A plan that changes a target shows `-/+ destroy and then create replacement`, which is
exactly what happens. That is the gateway's invariant surfacing in the plan, not a
limitation the provider chose.

**Drift detection on `mcpip_skill` is existence-only.** The gateway will say whether an
alias is registered and hand back the advisory `service` / `access` labels. It will not
say what the alias points at. So Terraform notices a deregistration, and cannot notice
that someone deregistered and re-registered the same alias against a different target.
`mcpip_policy` has no such gap — `GET /v1/admin/policy` returns the stored document, so
drift on it is fully detected.

**There is no `mcpip_user` resource.** `PUT /v1/admin/users/{email}` updates an existing
operator; operators are created through an invite flow that mints a secret. A resource
whose Create cannot create is worse than no resource.

**Import is limited for aliases.** `terraform import mcpip_skill.x skill_name` recovers
the alias and its advisory metadata; `target`, `risk_tier` and `classification` cannot
be recovered from any route, so the next plan proposes a replacement. Import is useful
for adopting aliases whose target you are re-declaring anyway, not for discovering one.

---

## Denials

Every admin call this provider makes can be refused opaquely — a generic message and a
correlation id, and nothing else. That is deliberate: a structured reason is an oracle.

The provider surfaces the id and the command that resolves it:

```
Error: Could not register the alias

  gateway refused the call (HTTP 403): MCPIP: request denied by policy.

  correlation_id: 363ad199e5634b1b9dfdea05f666f0f7
  The concrete reason is never returned over the wire — it lives in the audit
  record. Run:  mcpip why 363ad199e5634b1b9dfdea05f666f0f7
```

The most common causes, none of which the gateway will name for you:

- the token's principal does not hold `CAP_DIRECTORY_ADMIN`;
- the target is not already in its canonical form (the register grammar is a fixed
  point — see `_canonical_target` in `app/main.py`);
- `classification = "restricted"` without `risk_tier = "pin_required"`;
- the target already resolves at a stronger posture than the one being registered.

`risk_tier`, `classification` and `access` are validated at **plan** time against the
gateway's allowed sets, so a typo there fails locally with a readable message instead of
becoming a 403 halfway through an apply.

---

## Building it

Not on the Terraform Registry yet — publishing requires extracting this directory to a
repository named `mcpip-security/terraform-provider-mcpip` (the registry enforces the
name), a GPG signing key, and a registry account. Until then, use a dev override.

```bash
cd integrations/terraform
go build -o ~/.terraform.d/plugins/terraform-provider-mcpip .
```

```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides {
    "mcpip-security/mcpip" = "/home/you/.terraform.d/plugins"
  }
  direct {}
}
```

With a dev override in place there is no `terraform init` for this provider — run
`plan` and `apply` directly. Terraform prints a warning on every command saying an
override is active; that is expected.

```bash
export MCPIP_GATEWAY=http://localhost:8080

# `mcpip sandbox dev-token` mints into a 0600 token store and never prints — use --out
# when you need the value in hand. The capability is CAP_DIRECTORY_ADMIN; without it
# every resource in the plan fails with a correlation id and nothing else.
mcpip --context sbx sandbox dev-token --agent tf-admin \
  --cap b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20 --out ./tf.jwt
export MCPIP_TOKEN="$(cat ./tf.jwt)" && rm ./tf.jwt

terraform apply
```

Tests:

```bash
go test ./...
```

The unit tests cover the parts that are easy to get quietly wrong — policy-document
equivalence across the gateway's canonical round-trip, and the denial message. There
are no acceptance tests in CI because they need a live gateway; the lifecycle was
verified by hand against a sandbox gateway (create → no-op replan → external-drift
detection on both resources → force-replace on target change → destroy).

---

## Why this exists

The gateway is the choke point for what agents may do. Grant work that happens by
clicking around a console has no diff, no review, and no history — which is the same
problem as an agent that authorizes itself, one level up. Putting the catalog and the
overlay in Terraform means a change to either arrives as a pull request, gets a second
pair of eyes, and leaves a record in two places: your VCS, and the gateway's own WORM
ledger, which records the admin action independently.

Those two records are worth having precisely because they can disagree. If they do,
`data.mcpip_skills` will tell you — see the `check` block in the example.
