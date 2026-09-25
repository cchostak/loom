package enterprise

import (
	"context"
	"encoding/json"
	"errors"
	"guardrail-proxy/boundary"
	"guardrail-proxy/security"
	"net/http"
	"os"
	"time"
)

type Config struct {
	OIDC            security.OIDC `json:"oidc"`
	Resource        string        `json:"resource"`
	StateURL        string        `json:"state_url"`
	AuditURL        string        `json:"audit_url"`
	StateTokenFile  string        `json:"state_token_file"`
	AuditTokenFile  string        `json:"audit_token_file"`
	DispatchKeyFile string        `json:"dispatch_key_file"`
}

func secret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 32 || len(b) > 4096 {
		return nil, errors.New("secret unavailable")
	}
	return b, nil
}

// Configure is opt-in and fails startup on invalid deployment configuration.
//
// When StateURL, AuditURL, and DispatchKeyFile are all empty the function
// enters identity-only mode: Dex (or any OIDC issuer) authenticates requests
// but local audit, local budgets, and no dispatch signing are used. This
// covers the Stage 1 identity increment without requiring full enterprise
// remote services.
func Configure(s *boundary.Server, path string) (http.Handler, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if security.Decode(b, &c) != nil || c.Resource == "" || c.OIDC.Issuer == "" {
		return nil, errors.New("invalid enterprise configuration")
	}

	// Identity-only mode: no remote state service, audit service, or dispatch
	// signing key required. Local fallbacks are preserved from the base Server.
	if c.StateURL == "" && c.AuditURL == "" && c.DispatchKeyFile == "" {
		s.Auth = &c.OIDC
		s.ResourceURL = c.Resource
		api := API{Auth: s.Auth, State: Remote{}, Next: s, Resource: c.Resource, Issuer: c.OIDC.Issuer}
		s.Metadata = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { api.ServeHTTP(w, r) })
		return api, nil
	}

	stateToken, err := secret(c.StateTokenFile)
	if err != nil {
		return nil, err
	}
	auditToken, err := secret(c.AuditTokenFile)
	if err != nil {
		return nil, err
	}
	key, err := secret(c.DispatchKeyFile)
	if err != nil {
		return nil, err
	}
	state := Remote{URL: c.StateURL, Token: string(stateToken)}
	s.Auth = ActiveAuth{Auth: &c.OIDC, State: state}
	s.GlobalBudgets = state
	s.Audit = &security.Audit{Writer: AuditWriter{Remote{URL: c.AuditURL, Token: string(auditToken)}}}
	s.ResourceURL = c.Resource
	s.Dispatch = func(a security.ActionRequest, body []byte, req *http.Request) error {
		proof, err := Sign(key, a.Identity, body)
		if err != nil {
			return err
		}
		req.Header.Set("X-Loom-Dispatch", proof)
		ctx, cancel := context.WithCancel(req.Context())
		*req = *req.WithContext(ctx)
		go func() {
			defer cancel()
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if state.Call("/active", Request{Identity: a.Identity}, nil) != nil {
						return
					}
				}
			}
		}()
		return nil
	}
	api := API{Auth: s.Auth, State: state, Next: s, Resource: c.Resource, Issuer: c.OIDC.Issuer}
	s.Metadata = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { api.ServeHTTP(w, r) })
	return api, nil
}

// LoadConfig supports tests and tooling without logging secret values.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	return c, err
}
