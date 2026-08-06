package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// client is a thin typed wrapper over the MCPIP admin API.
//
// It exists mostly to translate one thing well: an MCPIP denial. The gateway answers
// a refused admin call with an opaque body — a generic message plus a correlation_id,
// and nothing else. That is deliberate and it is also the single most confusing thing
// a first-time operator can meet, so every error this client returns carries the
// correlation id and the command that resolves it.
type client struct {
	gateway string
	token   string
	http    *http.Client
}

func newClient(gateway, token string, timeout time.Duration) *client {
	return &client{
		gateway: strings.TrimRight(gateway, "/"),
		token:   token,
		http:    &http.Client{Timeout: timeout},
	}
}

// apiError is a non-2xx response from the gateway.
type apiError struct {
	StatusCode    int
	Message       string
	CorrelationID string
}

func (e *apiError) Error() string {
	if e.CorrelationID != "" {
		return fmt.Sprintf(
			"gateway refused the call (HTTP %d): %s\n\ncorrelation_id: %s\n"+
				"The concrete reason is never returned over the wire — it lives in the audit "+
				"record. Run:  mcpip why %s",
			e.StatusCode, e.Message, e.CorrelationID, e.CorrelationID,
		)
	}
	return fmt.Sprintf("gateway refused the call (HTTP %d): %s", e.StatusCode, e.Message)
}

// isNotFound reports whether the error is a 404, which several admin routes use as an
// indistinguishable "absent or not yours" answer rather than an existence oracle.
func isNotFound(err error) bool {
	var ae *apiError
	if ok := asAPIError(err, &ae); ok {
		return ae.StatusCode == http.StatusNotFound
	}
	return false
}

func asAPIError(err error, target **apiError) bool {
	if ae, ok := err.(*apiError); ok {
		*target = ae
		return true
	}
	return false
}

// do issues a request and decodes a JSON response body into out (which may be nil).
func (c *client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.gateway+path, reader)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newAPIError(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding response from %s %s: %w", method, path, err)
	}
	return nil
}

func newAPIError(status int, raw []byte) *apiError {
	err := &apiError{StatusCode: status, Message: strings.TrimSpace(string(raw))}
	var envelope struct {
		Error         string `json:"error"`
		Detail        string `json:"detail"`
		CorrelationID string `json:"correlation_id"`
	}
	if json.Unmarshal(raw, &envelope) == nil {
		err.CorrelationID = envelope.CorrelationID
		switch {
		case envelope.Detail != "":
			err.Message = envelope.Detail
		case envelope.Error != "":
			err.Message = envelope.Error
		}
	}
	if err.Message == "" {
		err.Message = http.StatusText(status)
	}
	return err
}

// --- skills (alias → target overlay entries) --------------------------------

type skillBody struct {
	Alias          string  `json:"alias"`
	Target         string  `json:"target"`
	RiskTier       string  `json:"risk_tier"`
	Classification string  `json:"classification"`
	Service        *string `json:"service,omitempty"`
	Access         *string `json:"access,omitempty"`
}

// skillEntry is what the gateway is willing to say back about a registered alias.
// Note what is NOT here: target, risk_tier, classification. The alias→target mapping
// is never returned by any admin route — see registerSkill's doc comment.
type skillEntry struct {
	Alias        string  `json:"alias"`
	RegisteredAt *string `json:"registered_at"`
	Service      *string `json:"service"`
	Access       *string `json:"access"`
}

// registerSkill creates a new alias. The route is ADDITIVE-ONLY: it answers 409 if the
// alias already resolves, and there is no update route at all. That is why every
// enforcement attribute on mcpip_skill requires replacement rather than updating in
// place — the provider is not free to choose otherwise.
func (c *client) registerSkill(ctx context.Context, body skillBody) error {
	return c.do(ctx, http.MethodPost, "/v1/admin/skills/register", body, nil)
}

func (c *client) listRegisteredSkills(ctx context.Context) ([]skillEntry, error) {
	var out struct {
		Entries []skillEntry `json:"entries"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/admin/skills/registered", nil, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

func (c *client) getSkill(ctx context.Context, alias string) (*skillEntry, error) {
	entries, err := c.listRegisteredSkills(ctx)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].Alias == alias {
			return &entries[i], nil
		}
	}
	return nil, nil
}

// deregisterSkill removes an overlay alias. The route is a no-op success for an alias
// that is not an overlay entry, so Delete is idempotent.
func (c *client) deregisterSkill(ctx context.Context, alias string) error {
	return c.do(ctx, http.MethodPost, "/v1/admin/skills/"+alias+"/deregister", nil, nil)
}

// --- the deny-only policy document ------------------------------------------

// getPolicy returns the tenant's policy document. The gateway answers an honest empty
// document rather than a 404 when nothing is stored, so callers compare against
// emptyPolicy rather than checking for absence.
func (c *client) getPolicy(ctx context.Context) (map[string]any, error) {
	var out struct {
		Policy map[string]any `json:"policy"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/admin/policy", nil, &out); err != nil {
		return nil, err
	}
	return out.Policy, nil
}

func (c *client) putPolicy(ctx context.Context, document map[string]any) error {
	return c.do(ctx, http.MethodPut, "/v1/admin/policy", document, nil)
}

func (c *client) deletePolicy(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/admin/policy/delete", nil, nil)
}
