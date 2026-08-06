package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
)

// The gateway stores policy documents canonically, materializing every unset optional
// rule field as an explicit null. If the provider treated that as a difference, every
// plan after a successful apply would propose the same update forever — and an operator
// who learns that plan output is noise stops reading it.
func TestPolicyDocumentsDifferingOnlyInExplicitNullsAreEquivalent(t *testing.T) {
	written := `{"schema":"mcpip-policy/1","rules":[
		{"kind":"amount","scope":"alias","scope_value":"skill_x",
		 "amount_field":"amount","max_amount":"500.00"}]}`
	// What GET /v1/admin/policy actually hands back for the document above.
	stored := `{"schema":"mcpip-policy/1","rules":[
		{"kind":"amount","scope":"alias","scope_value":"skill_x",
		 "amount_field":"amount","max_amount":"500.00",
		 "max_actions":null,"window_seconds":null,
		 "argument_field":null,"allowed_values":null,"forbidden_substrings":null}]}`

	same, err := jsonEquivalent(written, stored)
	if err != nil {
		t.Fatalf("jsonEquivalent: %v", err)
	}
	if !same {
		t.Fatal("a document and its canonical round-trip must compare equal, or every " +
			"plan after apply shows a permanent diff")
	}
}

func TestKeyOrderDoesNotMakeDocumentsDiffer(t *testing.T) {
	same, err := jsonEquivalent(
		`{"schema":"mcpip-policy/1","rules":[]}`,
		`{"rules":[],"schema":"mcpip-policy/1"}`,
	)
	if err != nil {
		t.Fatalf("jsonEquivalent: %v", err)
	}
	if !same {
		t.Fatal("key order is not a difference")
	}
}

// The null-stripping must not paper over a change an operator actually made.
func TestARealRuleChangeIsStillADifference(t *testing.T) {
	base := `{"schema":"mcpip-policy/1","rules":[{"kind":"amount","max_amount":"500.00"}]}`
	raised := `{"schema":"mcpip-policy/1","rules":[{"kind":"amount","max_amount":"5000.00"}]}`
	same, err := jsonEquivalent(base, raised)
	if err != nil {
		t.Fatalf("jsonEquivalent: %v", err)
	}
	if same {
		t.Fatal("raising a ceiling tenfold must show up as a difference")
	}
}

// Dropping a null inside an ARRAY would shift every later index, so stripNulls keeps
// those. Only object keys are dropped.
func TestNullsInsideArraysArePreserved(t *testing.T) {
	encoded, err := json.Marshal(stripNulls(map[string]any{
		"list": []any{"a", nil, "b"},
		"gone": nil,
	}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(encoded), `{"list":["a",null,"b"]}`; got != want {
		t.Fatalf("stripNulls = %s, want %s", got, want)
	}
}

// An MCPIP denial carries no reason — only a correlation id. The provider's whole job
// on the error path is to make sure the operator leaves with that id and the command
// that resolves it, rather than a bare "403".
func TestADenialSurfacesTheCorrelationIDAndTheCommand(t *testing.T) {
	err := newAPIError(http.StatusForbidden,
		[]byte(`{"error":"MCPIP: request denied by policy.","correlation_id":"abc123"}`))
	message := err.Error()
	for _, want := range []string{"abc123", "mcpip why abc123", "403"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error message %q does not mention %q", message, want)
		}
	}
}

func TestAnErrorWithoutACorrelationIDStillReads(t *testing.T) {
	err := newAPIError(http.StatusConflict,
		[]byte(`{"error":"alias_exists","detail":"this alias already resolves"}`))
	if !strings.Contains(err.Error(), "this alias already resolves") {
		t.Fatalf("detail should win over the error code: %q", err.Error())
	}
}

// The gateway answers "no policy stored" with an honest empty document rather than a
// 404, so absence has to be recognised by shape.
func TestAnEmptyPolicyDocumentCountsAsAbsent(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal([]byte(`{"schema":"mcpip-policy/1","rules":[]}`), &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !isEmptyPolicy(document) {
		t.Fatal("an empty rules list is the gateway's way of saying nothing is stored")
	}
}

func TestAPopulatedPolicyDocumentIsNotAbsent(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal([]byte(`{"schema":"mcpip-policy/1","rules":[{"kind":"amount"}]}`), &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if isEmptyPolicy(document) {
		t.Fatal("a document with rules is stored")
	}
}

// Schema validity is checked by the framework itself; a malformed attribute set is a
// panic at provider startup rather than a test failure somewhere later.
func TestSchemasAreValid(t *testing.T) {
	ctx := context.Background()

	t.Run("provider", func(t *testing.T) {
		resp := &provider.SchemaResponse{}
		(&mcpipProvider{}).Schema(ctx, provider.SchemaRequest{}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatal(resp.Diagnostics.Errors())
		}
	})

	for name, newResource := range map[string]func() resource.Resource{
		"mcpip_skill":  NewSkillResource,
		"mcpip_policy": NewPolicyResource,
	} {
		t.Run(name, func(t *testing.T) {
			resp := &fwresource.SchemaResponse{}
			newResource().Schema(ctx, fwresource.SchemaRequest{}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatal(resp.Diagnostics.Errors())
			}
		})
	}

	t.Run("mcpip_skills", func(t *testing.T) {
		resp := &fwdatasource.SchemaResponse{}
		NewSkillsDataSource().(datasource.DataSource).Schema(ctx, fwdatasource.SchemaRequest{}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatal(resp.Diagnostics.Errors())
		}
	})
}

// A gateway URL with a trailing slash must not produce "//v1/admin/...".
func TestTrailingSlashesAreTrimmedFromTheGatewayURL(t *testing.T) {
	if got := newClient("https://gw.internal:8080/", "t", 0).gateway; got != "https://gw.internal:8080" {
		t.Fatalf("gateway = %q", got)
	}
}
