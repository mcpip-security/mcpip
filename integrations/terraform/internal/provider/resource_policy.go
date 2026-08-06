package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &policyResource{}
	_ resource.ResourceWithConfigure   = &policyResource{}
	_ resource.ResourceWithImportState = &policyResource{}
)

// NewPolicyResource returns the mcpip_policy resource.
func NewPolicyResource() resource.Resource { return &policyResource{} }

type policyResource struct {
	client *client
}

type policyModel struct {
	Document types.String `tfsdk:"document"`
}

func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The tenant's deny-only policy overlay.\n\n" +
			"One document per tenant, so declare **at most one** of these per gateway credential; " +
			"a second one silently overwrites the first on every apply.\n\n" +
			"The rules are carried as JSON rather than modelled as Terraform blocks, the way " +
			"`aws_iam_policy` does it. That is deliberate: the gateway validates the document " +
			"strictly and gains rule kinds over time, and a hand-modelled schema here would " +
			"reject a valid document the day a new kind ships.\n\n" +
			"The overlay is **deny-only and monotonic** — a rule can tighten what is allowed, " +
			"never grant. Deleting this resource returns the tenant to the honest no-limits " +
			"state; it does not open anything that was closed by capability or catalog.",
		Attributes: map[string]schema.Attribute{
			"document": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The policy document as JSON — use `jsonencode()`. Must carry " +
					"`schema = \"mcpip-policy/1\"` and a `rules` list.",
			},
		},
	}
}

func (r *policyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	r.client = c
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	document, err := r.client.getPolicy(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Could not read the policy document", err.Error())
		return
	}

	// No document stored is reported as an honest empty one rather than a 404, so
	// "deleted outside Terraform" looks like an empty rules list, not an absence.
	if isEmptyPolicy(document) {
		resp.State.RemoveResource(ctx)
		return
	}

	remote, err := json.Marshal(document)
	if err != nil {
		resp.Diagnostics.AddError("Could not encode the stored policy document", err.Error())
		return
	}

	// The gateway stores canonically, so a byte comparison against the operator's
	// jsonencode() output would show a permanent diff on key order alone. Compare
	// semantically and keep the configured text when they agree.
	same, err := jsonEquivalent(state.Document.ValueString(), string(remote))
	if err != nil {
		resp.Diagnostics.AddError("Could not compare the policy documents", err.Error())
		return
	}
	if !same {
		state.Document = types.StringValue(string(remote))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.deletePolicy(ctx); err != nil {
		resp.Diagnostics.AddError("Could not delete the policy document", err.Error())
	}
}

// ImportState adopts whatever document the tenant currently has. There is no id to
// supply — one document per tenant — so the import id is ignored by convention.
func (r *policyResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	document, err := r.client.getPolicy(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Could not read the policy document", err.Error())
		return
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		resp.Diagnostics.AddError("Could not encode the stored policy document", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, policyModel{Document: types.StringValue(string(encoded))})...)
}

func (r *policyResource) write(ctx context.Context, plan *policyModel, diags *diag.Diagnostics) {
	var document map[string]any
	if err := json.Unmarshal([]byte(plan.Document.ValueString()), &document); err != nil {
		diags.AddError(
			"document is not valid JSON",
			"Use jsonencode() to build it. Decoder said: "+err.Error(),
		)
		return
	}
	if err := r.client.putPolicy(ctx, document); err != nil {
		diags.AddError(
			"Gateway refused the policy document",
			err.Error()+"\n\nA malformed document is refused opaquely — the gateway will not say "+
				"which rule was wrong, because that answer is an oracle. Check the schema string, "+
				"the rule count, and the document size against docs/policies/.",
		)
	}
}

func isEmptyPolicy(document map[string]any) bool {
	if document == nil {
		return true
	}
	rules, ok := document["rules"]
	if !ok {
		return true
	}
	list, ok := rules.([]any)
	return ok && len(list) == 0
}

// jsonEquivalent reports whether two policy documents mean the same thing.
//
// Not a byte comparison, and not even a plain round-trip. The gateway stores the
// document canonically, which MATERIALIZES every unset optional rule field as an
// explicit null — a document written as
//
//	{"kind":"amount","scope":"alias","amount_field":"amount","max_amount":"500.00"}
//
// comes back carrying "max_actions":null, "window_seconds":null, "argument_field":null
// and so on. Compared naively that is a difference, so every plan after a successful
// apply proposes the same in-place update, forever.
//
// A provider with a permanent diff is worse than one that does nothing: it teaches the
// operator that `terraform plan` output is noise, and the next real change scrolls past
// unread. So null-valued keys are dropped from both sides before comparing. That is
// sound for this schema specifically — every optional rule field is declared
// `Optional[...] = None`, so null and absent are the same state. It would not be sound
// for a schema where an explicit null meant something.
func jsonEquivalent(a, b string) (bool, error) {
	var left, right any
	if err := json.Unmarshal([]byte(a), &left); err != nil {
		// State holding non-JSON means it was hand-edited; treat as different so the
		// stored document wins rather than erroring the whole plan.
		return false, nil //nolint:nilerr // deliberate: unparseable state is drift, not failure
	}
	if err := json.Unmarshal([]byte(b), &right); err != nil {
		return false, err
	}
	leftCanonical, err := json.Marshal(stripNulls(left))
	if err != nil {
		return false, err
	}
	rightCanonical, err := json.Marshal(stripNulls(right))
	if err != nil {
		return false, err
	}
	return string(leftCanonical) == string(rightCanonical), nil
}

// stripNulls recursively removes null-valued object keys. Nulls inside arrays are kept:
// dropping one would shift every later index, which changes meaning rather than
// normalizing it.
func stripNulls(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, inner := range typed {
			if inner == nil {
				continue
			}
			out[key] = stripNulls(inner)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, inner := range typed {
			out = append(out, stripNulls(inner))
		}
		return out
	default:
		return value
	}
}
