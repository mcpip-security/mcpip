terraform {
  required_providers {
    mcpip = {
      source = "mcpip-security/mcpip"
    }
  }
}

# Gateway and token come from MCPIP_GATEWAY / MCPIP_TOKEN. Keep the token out of the
# .tf files — it belongs to a principal holding CAP_DIRECTORY_ADMIN, and a token in
# version control is a credential in version control.
provider "mcpip" {}

# --- the catalog -------------------------------------------------------------
#
# An alias is the opaque name the agent calls. The agent never learns the target;
# neither does anyone reading `terraform show`, because `target` is marked sensitive.
# It IS in the state file, though — see the README before pointing this at production.

resource "mcpip_skill" "ledger_read" {
  alias   = "skill_ledger_read"
  target  = "cloud_rest:https://ledger.internal/v1/entries"
  service = "ledger"
  access  = "read"
}

# A write path into the same system is a separate alias at a stronger posture, not a
# flag on the read one. `restricted` requires `pin_required` — the gateway refuses the
# pair otherwise, and the provider will tell you at plan time rather than apply time.
resource "mcpip_skill" "ledger_post" {
  alias          = "skill_ledger_post"
  target         = "cloud_rest:https://ledger.internal/v1/postings"
  risk_tier      = "pin_required"
  classification = "restricted"
  service        = "ledger"
  access         = "write"
}

# --- the deny-only overlay ---------------------------------------------------
#
# One document per tenant. Rules can only tighten: nothing here grants anything that
# the catalog and capability model have not already allowed.

resource "mcpip_policy" "limits" {
  document = jsonencode({
    schema = "mcpip-policy/1"
    rules = [
      # No single posting over $500 without a human in the loop.
      {
        kind         = "amount"
        scope        = "alias"
        scope_value  = mcpip_skill.ledger_post.alias
        amount_field = "amount"
        max_amount   = "500.00"
      },
      # And no more than ten of them an hour, however small.
      {
        kind           = "velocity"
        scope          = "alias"
        scope_value    = mcpip_skill.ledger_post.alias
        max_actions    = 10
        window_seconds = 3600
      },
    ]
  })
}

# --- asserting nothing was added by hand -------------------------------------
#
# The data source lists what the gateway actually has. Comparing it against what this
# configuration declares turns "someone registered an alias in the console at 2am" from
# an invisible event into a failing plan.

data "mcpip_skills" "registered" {}

check "no_unmanaged_aliases" {
  assert {
    condition = length(setsubtract(
      toset(data.mcpip_skills.registered.aliases),
      toset([mcpip_skill.ledger_read.alias, mcpip_skill.ledger_post.alias]),
    )) == 0
    error_message = "An alias exists on the gateway that Terraform does not manage."
  }
}
