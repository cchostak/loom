package main

import (
	"testing"
)

// MCPAuthorizationRule models the CEL policy logic defined in agentgateway-config.yaml
type MCPAuthorizationRule struct {
	Name    string
	Action  string
	Allowed map[string]bool
}

func NewDefaultMCPPolicy() *MCPAuthorizationRule {
	return &MCPAuthorizationRule{
		Name:   "allow-read-only-tools",
		Action: "allow",
		Allowed: map[string]bool{
			"read_text_file":            true,
			"read_media_file":           true,
			"read_multiple_files":       true,
			"list_directory":            true,
			"list_directory_with_sizes": true,
			"directory_tree":            true,
			"search_files":              true,
			"get_file_info":             true,
			"list_allowed_directories":  true,
		},
	}
}

// Evaluate checks whether a tool invocation matches the allow rule
func (r *MCPAuthorizationRule) Evaluate(toolName string) string {
	if r.Allowed[toolName] {
		return "allow"
	}
	return "deny"
}

func TestMCPAuthorizationPolicy(t *testing.T) {
	policy := NewDefaultMCPPolicy()

	testCases := []struct {
		toolName       string
		expectedAction string
	}{
		// Allowed safe tools
		{"read_text_file", "allow"},
		{"read_media_file", "allow"},
		{"read_multiple_files", "allow"},
		{"list_directory", "allow"},
		{"list_directory_with_sizes", "allow"},
		{"directory_tree", "allow"},
		{"search_files", "allow"},
		{"get_file_info", "allow"},
		{"list_allowed_directories", "allow"},

		// Blocked / unauthorized tools (default deny)
		{"write_file", "deny"},
		{"delete_file", "deny"},
		{"execute_command", "deny"},
		{"bash", "deny"},
		{"sh", "deny"},
		{"install_package", "deny"},
		{"git_push", "deny"},
		{"arbitrary_tool", "deny"},
		{"", "deny"},
	}

	for _, tc := range testCases {
		t.Run("tool_"+tc.toolName, func(t *testing.T) {
			action := policy.Evaluate(tc.toolName)
			if action != tc.expectedAction {
				t.Errorf("tool '%s': expected action '%s', got '%s'", tc.toolName, tc.expectedAction, action)
			}
		})
	}
}

// DexJWTClaimRule models the CEL policy logic for Dex IdP claim validation
type DexJWTClaimRule struct {
	Issuer    string
	Audiences []string
}

func (r *DexJWTClaimRule) Evaluate(claims map[string]any) bool {
	iss, _ := claims["iss"].(string)
	if iss != r.Issuer {
		return false
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return false
	}
	audRaw, ok := claims["aud"]
	if !ok {
		return false
	}
	var auds []string
	switch v := audRaw.(type) {
	case string:
		auds = []string{v}
	case []string:
		auds = v
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok {
				auds = append(auds, s)
			}
		}
	}
	for _, expected := range r.Audiences {
		for _, a := range auds {
			if a == expected {
				return true
			}
		}
	}
	return false
}

func TestDexJWTClaimValidationPolicy(t *testing.T) {
	rule := &DexJWTClaimRule{
		Issuer:    "http://dex:5556/dex",
		Audiences: []string{"https://loom.local/api", "loom-local", "loom"},
	}

	testCases := []struct {
		name     string
		claims   map[string]any
		expected bool
	}{
		{
			name: "valid-claims",
			claims: map[string]any{
				"iss": "http://dex:5556/dex",
				"sub": "local-developer",
				"aud": "https://loom.local/api",
			},
			expected: true,
		},
		{
			name: "valid-array-audience",
			claims: map[string]any{
				"iss": "http://dex:5556/dex",
				"sub": "pipeline-svc",
				"aud": []any{"loom", "other"},
			},
			expected: true,
		},
		{
			name: "wrong-issuer",
			claims: map[string]any{
				"iss": "https://rogue-issuer.example",
				"sub": "attacker",
				"aud": "loom",
			},
			expected: false,
		},
		{
			name: "missing-subject",
			claims: map[string]any{
				"iss": "http://dex:5556/dex",
				"sub": "",
				"aud": "loom",
			},
			expected: false,
		},
		{
			name: "wrong-audience",
			claims: map[string]any{
				"iss": "http://dex:5556/dex",
				"sub": "user",
				"aud": "https://untrusted.service.example",
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := rule.Evaluate(tc.claims)
			if result != tc.expected {
				t.Errorf("claim evaluation for %s: expected %v, got %v", tc.name, tc.expected, result)
			}
		})
	}
}

// BudgetAndRateLimitRule models AgentGateway native rate limit and budget checks
type BudgetAndRateLimitRule struct {
	MaxRPM         int
	MaxTokens      int
	MaxDailyDollar float64
}

func (r *BudgetAndRateLimitRule) Evaluate(rpm int, tokens int, dollarSpend float64) (bool, string) {
	if rpm > r.MaxRPM {
		return false, "rate_limit_exceeded"
	}
	if tokens > r.MaxTokens {
		return false, "token_budget_exceeded"
	}
	if dollarSpend > r.MaxDailyDollar {
		return false, "dollar_budget_exceeded"
	}
	return true, "allowed"
}

func TestBudgetAndRateLimitPolicy(t *testing.T) {
	rule := &BudgetAndRateLimitRule{
		MaxRPM:         60,
		MaxTokens:      100000,
		MaxDailyDollar: 50.0,
	}

	testCases := []struct {
		name       string
		rpm        int
		tokens     int
		spend      float64
		expectedOK bool
		reason     string
	}{
		{"within-limits", 30, 5000, 10.0, true, "allowed"},
		{"rpm-breach", 65, 5000, 10.0, false, "rate_limit_exceeded"},
		{"token-breach", 30, 120000, 10.0, false, "token_budget_exceeded"},
		{"dollar-breach", 30, 5000, 55.0, false, "dollar_budget_exceeded"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := rule.Evaluate(tc.rpm, tc.tokens, tc.spend)
			if ok != tc.expectedOK || reason != tc.reason {
				t.Errorf("%s: expected (%v, %s), got (%v, %s)", tc.name, tc.expectedOK, tc.reason, ok, reason)
			}
		})
	}
}
