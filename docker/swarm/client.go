package swarm

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

// Decision is the normalized result from Loom's live guardrail webhook.
type Decision struct {
	Blocked bool
	Reason  string
}

// ContentGuard inspects one request or response in the attack chain.
type ContentGuard interface {
	Inspect(context.Context, Phase, string) (Decision, error)
}

// HTTPGuard exercises the running guardrail service over its real webhook API.
type HTTPGuard struct {
	BaseURL string
	Client  *http.Client
}

// NewHTTPGuard creates a guardrail client with a bounded request timeout.
func NewHTTPGuard(baseURL string) *HTTPGuard {
	return &HTTPGuard{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client:  &http.Client{Timeout: 5 * time.Second},
	}
}

// Inspect submits normalized agentgateway request or response content.
func (g *HTTPGuard) Inspect(ctx context.Context, phase Phase, content string) (Decision, error) {
	payload := map[string]any{"body": map[string]any{
		"messages": []map[string]string{{"role": "user", "content": content}},
	}}
	if phase == PhaseResponse {
		payload = map[string]any{"body": map[string]any{
			"choices": []map[string]any{{
				"message": map[string]string{"role": "assistant", "content": content},
			}},
		}}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Decision{}, fmt.Errorf("encode guardrail request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.BaseURL+"/"+string(phase), bytes.NewReader(body))
	if err != nil {
		return Decision{}, fmt.Errorf("create guardrail request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := g.Client.Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("call guardrail: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Decision{}, fmt.Errorf("guardrail returned HTTP %d", response.StatusCode)
	}

	var result struct {
		Action *struct {
			StatusCode int    `json:"status_code"`
			Reason     string `json:"reason"`
		} `json:"action"`
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(responseBody) > 16384 {
		return Decision{}, fmt.Errorf("guardrail response limit")
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return Decision{}, fmt.Errorf("decode guardrail response: %w", err)
	}
	if result.Action == nil || result.Action.Reason == "" || (result.Action.StatusCode != 0 && result.Action.StatusCode != 403) {
		return Decision{}, fmt.Errorf("invalid guardrail action")
	}
	return Decision{Blocked: result.Action.StatusCode != 0, Reason: result.Action.Reason}, nil
}
