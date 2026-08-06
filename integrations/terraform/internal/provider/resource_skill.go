package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &skillResource{}
	_ resource.ResourceWithConfigure   = &skillResource{}
	_ resource.ResourceWithImportState = &skillResource{}
)

// NewSkillResource returns the mcpip_skill resource.
func NewSkillResource() resource.Resource { return &skillResource{} }

type skillResource struct {
	client *client
}

type skillModel struct {
	Alias          types.String `tfsdk:"alias"`
	Target         types.String `tfsdk:"target"`
	RiskTier       types.String `tfsdk:"risk_tier"`
	Classification types.String `tfsdk:"classification"`
	Service        types.String `tfsdk:"service"`
	Access         types.String `tfsdk:"access"`
	RegisteredAt   types.String `tfsdk:"registered_at"`
}

func (r *skillResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_skill"
}

func (r *skillResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An operator-registered alias→target binding — the opaque name an agent " +
			"calls, and the real system behind it.\n\n" +
			"> **The state file holds the mapping.** No admin route on the gateway ever returns " +
			"`target`; keeping the alias→target map inside the gateway is the product's central " +
			"invariant. Managing aliases from Terraform necessarily writes that map into " +
			"`terraform.tfstate`. Treat state as secret material of the same class as the gateway's " +
			"own directory: encrypted remote backend, access-controlled, never in git.",
		Attributes: map[string]schema.Attribute{
			"alias": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The opaque name agents call. Changing it replaces the resource.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"target": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
				MarkdownDescription: "The real system the alias resolves to. **Write-only**: the gateway " +
					"never returns it, so Terraform cannot detect drift on this attribute — only that " +
					"the alias still exists. Changing it replaces the resource, because " +
					"`/v1/admin/skills/register` is additive-only and there is no update route.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"risk_tier": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("auto"),
				MarkdownDescription: "Risk tier — `auto` or `pin_required`. Write-only, same as " +
					"`target`. Changing it replaces the resource.",
				Validators:    []validator.String{stringvalidator.OneOf("auto", "pin_required")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"classification": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("unclassified"),
				MarkdownDescription: "Classification — `unclassified` or `restricted`. A `restricted` " +
					"alias must also be `pin_required`; the gateway refuses the pair otherwise. " +
					"Write-only, same as `target`. Changing it replaces the resource.",
				Validators:    []validator.String{stringvalidator.OneOf("unclassified", "restricted")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"service": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Advisory service label for the operator console. Never an enforcement " +
					"input. The gateway does return this, so it is refreshed on read.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"access": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Advisory access mode for the console — `read` or `write`. Never " +
					"an enforcement input. Refreshed on read.",
				Validators:    []validator.String{stringvalidator.OneOf("read", "write")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"registered_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "When the gateway recorded the registration.",
			},
		},
	}
}

func (r *skillResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *skillResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan skillModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := skillBody{
		Alias:          plan.Alias.ValueString(),
		Target:         plan.Target.ValueString(),
		RiskTier:       plan.RiskTier.ValueString(),
		Classification: plan.Classification.ValueString(),
	}
	if !plan.Service.IsNull() && !plan.Service.IsUnknown() {
		v := plan.Service.ValueString()
		body.Service = &v
	}
	if !plan.Access.IsNull() && !plan.Access.IsUnknown() {
		v := plan.Access.ValueString()
		body.Access = &v
	}

	if err := r.client.registerSkill(ctx, body); err != nil {
		resp.Diagnostics.AddError("Could not register the alias", err.Error())
		return
	}

	// Read back the advisory metadata the gateway derives (service/access carry a
	// risk-derived fallback when unset, so echoing the plan would be a lie).
	entry, err := r.client.getSkill(ctx, body.Alias)
	if err != nil {
		resp.Diagnostics.AddError("Registered the alias but could not read it back", err.Error())
		return
	}
	if entry == nil {
		resp.Diagnostics.AddError(
			"Registered the alias but it is not in the overlay",
			"The register call succeeded and GET /v1/admin/skills/registered does not list "+
				"alias "+body.Alias+". This should not happen; please report it.",
		)
		return
	}
	applyEntry(&plan, entry)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *skillResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state skillModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	entry, err := r.client.getSkill(ctx, state.Alias.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not list registered aliases", err.Error())
		return
	}
	if entry == nil {
		// Deregistered outside Terraform. This is the one kind of drift the provider can
		// actually see, since target/risk_tier/classification are never returned.
		resp.State.RemoveResource(ctx)
		return
	}
	applyEntry(&state, entry)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update can never be called: every non-computed attribute requires replacement. It
// exists because resource.Resource demands it, and it fails loudly rather than
// silently doing nothing, which would look like a successful no-op change.
func (r *skillResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"mcpip_skill cannot be updated in place",
		"Every attribute of an alias requires replacement — the gateway's register route is "+
			"additive-only and exposes no update. Reaching this code means the schema and this "+
			"method disagree; please report it.",
	)
}

func (r *skillResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state skillModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.deregisterSkill(ctx, state.Alias.ValueString()); err != nil {
		resp.Diagnostics.AddError("Could not deregister the alias", err.Error())
	}
}

// ImportState imports by alias. Note what import cannot recover: target, risk_tier and
// classification are not returned by any route, so an imported resource carries null
// for them and the next plan proposes a replacement. That is honest — Terraform is
// telling you it does not know the mapping — but it means import is only useful for
// adopting aliases whose target you are re-declaring anyway.
func (r *skillResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("alias"), req.ID)...)
}

func applyEntry(m *skillModel, entry *skillEntry) {
	m.Alias = types.StringValue(entry.Alias)
	m.RegisteredAt = optionalString(entry.RegisteredAt)
	m.Service = optionalString(entry.Service)
	m.Access = optionalString(entry.Access)
}

func optionalString(v *string) types.String {
	if v == nil {
		return types.StringNull()
	}
	return types.StringValue(*v)
}
