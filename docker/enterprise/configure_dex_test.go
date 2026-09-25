package enterprise

import (
	"encoding/json"
	"guardrail-proxy/boundary"
	"guardrail-proxy/security"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestConfigureIdentityOnlyMode validates that Configure enters identity-only
// mode when StateURL, AuditURL, and DispatchKeyFile are all empty.
// It verifies that:
//   - startup does not require remote secret files
//   - s.Auth is replaced with the OIDC authenticator
//   - s.GlobalBudgets and s.Dispatch remain nil (local fallbacks kept)
func TestConfigureIdentityOnlyMode(t *testing.T) {
	dir := t.TempDir()

	cfg := map[string]any{
		"oidc": map[string]any{
			"issuer":          "https://issuer.example",
			"audience":        "https://loom.local/api",
			"discovery_url":   "https://issuer.example/.well-known/openid-configuration",
			"jwks_url":        "https://issuer.example/keys",
			"public_jwks_url": "https://issuer.example/keys",
			"bindings":        []any{},
		},
		"resource":          "http://control-plane:8080",
		"state_url":         "",
		"audit_url":         "",
		"state_token_file":  "",
		"audit_token_file":  "",
		"dispatch_key_file": "",
	}
	b, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "oidc.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	auditBuf := &strings.Builder{}
	s := &boundary.Server{
		Auth:       security.Registry{File: "/dev/null", Audience: "loom-local"},
		PolicyFile: "/dev/null",
		Audit:      &security.Audit{Writer: auditBuf},
		Budgets: &security.Budgets{Limits: security.Limits{
			RequestsPerMinute: 60, Calls: 500, Concurrent: 4,
			InputBytes: 65536, OutputTokens: 4096, Workflow: time.Hour,
		}},
		Client:   &http.Client{Timeout: 5 * time.Second},
		ModelURL: "http://agentgateway:8080",
		MCPURL:   "http://agentgateway:3000",
		GuardURL: "http://guardrail-proxy:9090",
	}

	handler, err := Configure(s, path)
	if err != nil {
		t.Fatalf("Configure returned error in identity-only mode: %v", err)
	}
	if handler == nil {
		t.Fatal("Configure returned nil handler")
	}
	if s.GlobalBudgets != nil {
		t.Error("identity-only mode must not set GlobalBudgets")
	}
	if s.Dispatch != nil {
		t.Error("identity-only mode must not set Dispatch")
	}
	if _, ok := s.Auth.(*security.OIDC); !ok {
		t.Errorf("expected *security.OIDC auth, got %T", s.Auth)
	}
	if s.ResourceURL != "http://control-plane:8080" {
		t.Errorf("unexpected ResourceURL: %q", s.ResourceURL)
	}
}

// TestConfigureIdentityOnlyRejectsPartialRemote ensures that a config with
// only one remote field set is rejected with an error (not silently ignored).
func TestConfigureIdentityOnlyRejectsPartialRemote(t *testing.T) {
	dir := t.TempDir()
	// state_url set but dispatch_key_file empty — this is ambiguous; Configure
	// must refuse to start rather than silently omitting dispatch signing.
	cfg := map[string]any{
		"oidc": map[string]any{
			"issuer":          "https://issuer.example",
			"audience":        "https://loom.local/api",
			"discovery_url":   "https://issuer.example/.well-known/openid-configuration",
			"jwks_url":        "https://issuer.example/keys",
			"public_jwks_url": "https://issuer.example/keys",
			"bindings":        []any{},
		},
		"resource":          "http://control-plane:8080",
		"state_url":         "http://state-service:9000",
		"audit_url":         "",
		"state_token_file":  filepath.Join(dir, "missing.token"),
		"audit_token_file":  "",
		"dispatch_key_file": "",
	}
	b, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "oidc.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	auditBuf := &strings.Builder{}
	s := &boundary.Server{
		Auth:       security.Registry{},
		PolicyFile: "/dev/null",
		Audit:      &security.Audit{Writer: auditBuf},
		Budgets:    &security.Budgets{},
		Client:     &http.Client{},
	}
	_, err := Configure(s, path)
	if err == nil {
		t.Fatal("expected error for partial remote config, got nil")
	}
}

// TestConfigureIdentityOnlyMetadata verifies the /.well-known/oauth-protected-resource
// endpoint is served correctly in identity-only mode.
func TestConfigureIdentityOnlyMetadata(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]any{
		"oidc": map[string]any{
			"issuer":          "https://dex.example",
			"audience":        "https://loom.local/api",
			"discovery_url":   "https://dex.example/.well-known/openid-configuration",
			"jwks_url":        "https://dex.example/keys",
			"public_jwks_url": "https://dex.example/keys",
			"bindings":        []any{},
		},
		"resource":          "https://loom.local",
		"state_url":         "",
		"audit_url":         "",
		"state_token_file":  "",
		"audit_token_file":  "",
		"dispatch_key_file": "",
	}
	b, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "oidc.json")
	os.WriteFile(path, b, 0o644)

	auditBuf := &strings.Builder{}
	s := &boundary.Server{
		Auth:       security.Registry{},
		PolicyFile: "/dev/null",
		Audit:      &security.Audit{Writer: auditBuf},
		Budgets:    &security.Budgets{},
		Client:     &http.Client{},
	}
	handler, err := Configure(s, path)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var meta map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &meta); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if meta["resource"] != "https://loom.local" {
		t.Errorf("unexpected resource: %v", meta["resource"])
	}
	servers, ok := meta["authorization_servers"].([]any)
	if !ok || len(servers) != 1 || servers[0] != "https://dex.example" {
		t.Errorf("unexpected authorization_servers: %v", meta["authorization_servers"])
	}
}
