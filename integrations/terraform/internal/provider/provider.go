// Package provider implements the Terraform provider for MCPIP.
//
// Scope is deliberately narrow, and bounded by what the admin API can actually do
// rather than by what would look good in a feature list:
//
//   - mcpip_skill  — an alias→target overlay entry. Create / read / delete. Every
//     enforcement attribute requires replacement, because the register route is
//     additive-only and no update route exists.
//   - mcpip_policy — the deny-only policy document. Full CRUD; the GET returns the
//     stored document, so this one gets real drift detection.
//
// There is no mcpip_user resource on purpose. PUT /v1/admin/users/{email} updates an
// existing operator; operators are created through an invite flow that mints a secret.
// A resource whose Create cannot create is worse than no resource.
package provider

import (
	"context"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const defaultTimeout = 30 * time.Second

// New returns the provider constructor Terraform calls at startup.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &mcpipProvider{version: version}
	}
}

type mcpipProvider struct {
	version string
}

type providerModel struct {
	Gateway        types.String `tfsdk:"gateway"`
	Token          types.String `tfsdk:"token"`
	TimeoutSeconds types.Int64  `tfsdk:"timeout_seconds"`
}

func (p *mcpipProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "mcpip"
	resp.Version = p.version
}

func (p *mcpipProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages authorization state on a self-hosted MCPIP gateway. " +
			"There is no vendor-hosted gateway; `gateway` is always a host you run.",
		Attributes: map[string]schema.Attribute{
			"gateway": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Base URL of the gateway, e.g. `https://mcpip.internal:8080`. " +
					"Falls back to the `MCPIP_GATEWAY` environment variable.",
			},
			"token": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				MarkdownDescription: "Bearer token for a principal holding `CAP_DIRECTORY_ADMIN`. " +
					"Falls back to `MCPIP_TOKEN`. Prefer the environment variable: a token in a " +
					"`.tf` file is a credential in version control.",
			},
			"timeout_seconds": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Per-request timeout. Defaults to 30.",
			},
		},
	}
}

func (p *mcpipProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	gateway := firstNonEmpty(config.Gateway.ValueString(), os.Getenv("MCPIP_GATEWAY"))
	token := firstNonEmpty(config.Token.ValueString(), os.Getenv("MCPIP_TOKEN"))

	if gateway == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("gateway"),
			"No gateway configured",
			"Set the provider's `gateway` attribute or the MCPIP_GATEWAY environment variable. "+
				"MCPIP is self-hosted — there is no default endpoint to fall back to.",
		)
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("token"),
			"No token configured",
			"Set the provider's `token` attribute or the MCPIP_TOKEN environment variable. "+
				"The token must belong to a principal holding CAP_DIRECTORY_ADMIN; anything else "+
				"is refused opaquely and every resource in the plan will fail with a correlation id.",
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	timeout := defaultTimeout
	if !config.TimeoutSeconds.IsNull() && config.TimeoutSeconds.ValueInt64() > 0 {
		timeout = time.Duration(config.TimeoutSeconds.ValueInt64()) * time.Second
	}

	c := newClient(gateway, token, timeout)
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *mcpipProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSkillResource,
		NewPolicyResource,
	}
}

func (p *mcpipProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSkillsDataSource,
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
