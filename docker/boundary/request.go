// Package boundary authenticates and authorizes traffic before Agentgateway.
package boundary

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"guardrail-proxy/safefs"
	"guardrail-proxy/security"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type Completion struct {
	Model     string    `json:"model"`
	Messages  []Message `json:"messages"`
	MaxTokens int       `json:"max_tokens"`
	Stream    bool      `json:"stream,omitempty"`
}

// Parse accepts a bounded, deliberately narrow protocol subset. It serializes
// validated data again so upstream and policy always consume the same values.
func Parse(r *http.Request, b []byte, id security.IdentityContext) (security.ActionRequest, []byte, int, error) {
	a := security.ActionRequest{Identity: id, Data: security.DataContext{Source: "authenticated-ingress", Producer: id.Workload, Trust: "untrusted", Sensitivity: "unknown", Origin: "user", Tainted: true}, SideEffects: "read", Risk: "low"}
	deny := errors.New("unsupported request")
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		return a, nil, 0, deny
	}
	if r.URL.Path == "/mcp" && r.Method == http.MethodDelete && len(b) == 0 && r.Header.Get("Mcp-Session-Id") != "" {
		a.Category, a.Tool, a.Method = "mcp", "protocol", "session/delete"
		a.Resource, a.Destination = "/workspace", "filesystem"
		a.Arguments, _ = json.Marshal(map[string]string{"session": r.Header.Get("Mcp-Session-Id")})
		return a, nil, 0, nil
	}
	if r.Method != http.MethodPost {
		return a, nil, 0, deny
	}
	if r.URL.Path == "/v1/chat/completions" {
		var c Completion
		if security.Decode(b, &c) != nil || c.Model == "" || len(c.Messages) == 0 || len(c.Messages) > 64 || c.Stream {
			return a, nil, 0, deny
		}
		for _, m := range c.Messages {
			if m.Content == "" || (m.Role != "system" && m.Role != "user" && m.Role != "assistant") {
				return a, nil, 0, deny
			}
		}
		if c.MaxTokens == 0 {
			c.MaxTokens = 1024
		}
		if c.MaxTokens < 1 || c.MaxTokens > 4096 {
			return a, nil, 0, deny
		}
		a.Category = "model"
		a.Tool = c.Model
		a.Method = "completion"
		a.Resource = "/models/" + c.Model
		a.Destination = "openrouter"
		a.SideEffects = "export"
		a.Risk = "medium"
		normalized, _ := json.Marshal(c)
		a.Arguments = normalized
		return a, normalized, c.MaxTokens, nil
	}
	if r.URL.Path != "/mcp" {
		return a, nil, 0, deny
	}
	var rpc safefs.RPC
	if security.Decode(b, &rpc) != nil || rpc.JSONRPC != "2.0" {
		return a, nil, 0, deny
	}
	a.Category = "mcp"
	a.Method = rpc.Method
	a.Destination = "filesystem"
	a.Resource = "/workspace"
	a.Tool = "protocol"
	switch rpc.Method {
	case "initialize":
		// Client metadata has no authority and is not forwarded.
		rpc.Params = json.RawMessage(`{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"loom-boundary","version":"1.0"}}`)
	case "ping", "tools/list", "notifications/initialized":
		rpc.Params = json.RawMessage(`{}`)
	case "tools/call":
		var call safefs.Call
		var args safefs.Arguments
		if security.Decode(rpc.Params, &call) != nil || security.Decode(call.Arguments, &args) != nil {
			return a, nil, 0, deny
		}
		// Agentgateway prefixes aggregated names. Only this configured target exists.
		name := strings.TrimPrefix(call.Name, "filesystem_")
		if name != "read_text_file" && name != "list_directory" {
			return a, nil, 0, deny
		}
		if _, err := security.WorkspacePath(args.Path); err != nil {
			return a, nil, 0, deny
		}
		a.Tool = name
		a.Resource = args.Path
		call.Meta = nil
		call.Arguments, _ = json.Marshal(args)
		rpc.Params, _ = json.Marshal(call)
	default:
		return a, nil, 0, deny
	}
	a.Arguments = rpc.Params
	normalized, _ := json.Marshal(rpc)
	return a, normalized, 0, nil
}
