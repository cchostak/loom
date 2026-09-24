package boundary

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"guardrail-proxy/security"
)

type Server struct {
	ModelCircuit, ToolCircuit  security.Circuit
	Auth                       security.Authenticator
	PolicyFile                 string
	Audit                      *security.Audit
	Budgets                    *security.Budgets
	Client                     *http.Client
	ModelURL, MCPURL, GuardURL string
	mu                         sync.Mutex
	sessions                   map[string]string
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" && r.Method == http.MethodGet {
		w.WriteHeader(200)
		return
	}
	trace := security.NewID()
	w.Header().Set("X-Loom-Trace-ID", trace)
	id, err := s.Auth.Authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.deny(w, security.ActionRequest{}, trace, 401, "authentication_required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		s.deny(w, security.ActionRequest{Identity: id}, trace, 413, "input_limit")
		return
	}
	a, body, tokens, err := Parse(r, b, id)
	if err != nil {
		s.deny(w, a, trace, 400, "request_schema_denied")
		return
	}
	p, err := security.LoadPolicy(s.PolicyFile)
	if err != nil {
		s.deny(w, a, trace, 503, "policy_unavailable")
		return
	}
	d := p.Evaluate(a, time.Now().UTC())
	w.Header().Set("X-Loom-Decision-ID", d.ID)
	if s.Audit.Record(a, d, trace, "decision", 0) != nil {
		http.Error(w, "Audit unavailable", 503)
		return
	}
	if d.Outcome != "allow" {
		http.Error(w, "Policy denied: "+d.Reason, 403)
		return
	}
	// Closing an owned session releases resources and must remain possible when
	// an execution budget is exhausted. Authentication, policy, ownership and
	// audit still apply; cleanup cannot create sessions or invoke tools.
	if r.Method != http.MethodDelete {
		release, err := s.Budgets.Acquire(id.Tenant+"/"+id.Session, len(body), tokens, time.Now())
		if err != nil {
			s.deny(w, a, trace, 429, "budget_exceeded")
			return
		}
		defer release()
	}
	// Session identifiers returned by MCP are bound to the authenticated identity.
	session := r.Header.Get("Mcp-Session-Id")
	ownerKey := id.Tenant + "/" + id.Principal + "/" + id.Workload + "/" + id.Session
	if session != "" {
		s.mu.Lock()
		owner, ok := s.sessions[session]
		s.mu.Unlock()
		if !ok || owner != ownerKey {
			s.deny(w, a, trace, 403, "session_denied")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if a.Category == "model" && !s.inspect(ctx, body) {
		s.deny(w, a, trace, 403, "inspection_denied")
		return
	}
	target := s.MCPURL + "/mcp"
	if a.Category == "model" {
		target = s.ModelURL + "/v1/chat/completions"
	}
	circuit := &s.ToolCircuit
	if a.Category == "model" {
		circuit = &s.ModelCircuit
	}
	if !circuit.Allow(time.Now()) {
		s.deny(w, a, trace, 503, "circuit_open")
		return
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Upstream unavailable", 502)
		return
	}
	// Reconstruct headers. No credentials, identity claims or arbitrary headers pass.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("traceparent", "00-"+trace+"-"+security.NewID()[:16]+"-01")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	req.Header.Set("MCP-Protocol-Version", "2025-03-26")
	response, err := s.Client.Do(req)
	if err != nil {
		circuit.Complete(false, time.Now())
		_ = s.Audit.Record(a, d, trace, "result", 502)
		http.Error(w, "Upstream unavailable", 502)
		return
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(result) > 1<<20 {
		http.Error(w, "Output limit", 502)
		return
	}
	status := response.StatusCode
	circuit.Complete(status < 500, time.Now())
	// Inspect the entire result, including tool metadata and error content. No
	// arbitrary upstream error body or SSE bytes reach the caller without a check.
	if status >= 400 {
		result = []byte(`{"error":"Upstream rejected request"}`)
	} else if len(result) > 0 && !s.inspect(ctx, result) {
		status = 403
		result = []byte(`{"error":"Output inspection denied"}`)
	}
	if r.Method == http.MethodDelete && status < 400 {
		s.mu.Lock()
		delete(s.sessions, session)
		s.mu.Unlock()
	}
	if next := response.Header.Get("Mcp-Session-Id"); next != "" && status < 400 && r.Method != http.MethodDelete {
		s.mu.Lock()
		if s.sessions == nil {
			s.sessions = map[string]string{}
		}
		if len(s.sessions) >= 1024 {
			status = 503
			result = []byte(`{"error":"Session capacity"}`)
		} else {
			s.sessions[next] = ownerKey
			w.Header().Set("Mcp-Session-Id", next)
		}
		s.mu.Unlock()
	}
	if s.Audit.Record(a, d, trace, "result", status) != nil {
		http.Error(w, "Audit unavailable", 503)
		return
	}
	contentType := response.Header.Get("Content-Type")
	if status >= 400 || !strings.HasPrefix(contentType, "text/event-stream") {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = w.Write(result)
}

// inspect requires an explicit valid allowed result, never a zero-value pass.
func (s *Server) inspect(ctx context.Context, body []byte) bool {
	payload, _ := json.Marshal(map[string]string{"content": string(body)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.GuardURL+"/validate", bytes.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(b) > 4096 {
		return false
	}
	var result struct {
		Status  string   `json:"status"`
		Message string   `json:"message"`
		Error   string   `json:"error"`
		Matched []string `json:"matched"`
	}
	return security.Decode(b, &result) == nil && result.Status == "allowed"
}

// deny records boundary failures with fixed reason codes and no supplied text.
func (s *Server) deny(w http.ResponseWriter, a security.ActionRequest, trace string, status int, reason string) {
	now := time.Now().UTC()
	d := security.PolicyDecision{ID: security.NewID(), PolicyID: "loom-boundary", Version: "1", RuleID: reason, Outcome: "deny", Reason: reason, Explanation: "Boundary rejected request", Timestamp: now, Expires: now}
	w.Header().Set("X-Loom-Decision-ID", d.ID)
	if s.Audit.Record(a, d, trace, "denied", status) != nil {
		http.Error(w, "Audit unavailable", 503)
		return
	}
	http.Error(w, reason, status)
}
