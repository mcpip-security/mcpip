package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &skillsDataSource{}
	_ datasource.DataSourceWithConfigure = &skillsDataSource{}
)

// NewSkillsDataSource returns the mcpip_skills data source.
func NewSkillsDataSource() datasource.DataSource { return &skillsDataSource{} }

type skillsDataSource struct {
	client *client
}

type skillsDataSourceModel struct {
	Aliases []string          `tfsdk:"aliases"`
	Entries []skillEntryModel `tfsdk:"entries"`
}

type skillEntryModel struct {
	Alias        types.String `tfsdk:"alias"`
	Service      types.String `tfsdk:"service"`
	Access       types.String `tfsdk:"access"`
	RegisteredAt types.String `tfsdk:"registered_at"`
}

func (d *skillsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_skills"
}

func (d *skillsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The operator-registered aliases on this tenant.\n\n" +
			"Only overlay entries appear — aliases that came from gateway config are immutable " +
			"and are not listed here. No `target` is returned for any of them; the gateway does " +
			"not expose the mapping to any caller.\n\n" +
			"Useful for asserting that nothing was registered outside Terraform: compare this " +
			"against your declared resources in a `check` block.",
		Attributes: map[string]schema.Attribute{
			"aliases": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Registered alias names, sorted.",
			},
			"entries": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The same aliases with the advisory metadata the gateway returns.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"alias":         schema.StringAttribute{Computed: true},
						"service":       schema.StringAttribute{Computed: true},
						"access":        schema.StringAttribute{Computed: true},
						"registered_at": schema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *skillsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	d.client = c
}

func (d *skillsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	entries, err := d.client.listRegisteredSkills(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Could not list registered aliases", err.Error())
		return
	}

	state := skillsDataSourceModel{
		Aliases: make([]string, 0, len(entries)),
		Entries: make([]skillEntryModel, 0, len(entries)),
	}
	for i := range entries {
		state.Aliases = append(state.Aliases, entries[i].Alias)
		state.Entries = append(state.Entries, skillEntryModel{
			Alias:        types.StringValue(entries[i].Alias),
			Service:      optionalString(entries[i].Service),
			Access:       optionalString(entries[i].Access),
			RegisteredAt: optionalString(entries[i].RegisteredAt),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
