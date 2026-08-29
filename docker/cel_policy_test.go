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
