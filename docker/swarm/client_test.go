package swarm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPGuardInspectRequestPasses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/request" {
			t.Errorf("path = %q, want /request", r.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":{"reason":"passed"}}`))
	}))
	defer server.Close()

	decision, err := NewHTTPGuard(server.URL+"/").Inspect(context.Background(), PhaseRequest, "hello")
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if decision.Blocked || decision.Reason != "passed" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestHTTPGuardInspectResponseBlocks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/response" {
			t.Errorf("path = %q, want /response", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"action":{"status_code":403,"reason":"blocked"}}`))
	}))
	defer server.Close()

	decision, err := NewHTTPGuard(server.URL).Inspect(context.Background(), PhaseResponse, "unsafe")
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !decision.Blocked || decision.Reason != "blocked" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestHTTPGuardRejectsNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := NewHTTPGuard(server.URL).Inspect(context.Background(), PhaseRequest, "hello")
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("Inspect() error = %v, want HTTP 503", err)
	}
}

func TestHTTPGuardRejectsMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()

	_, err := NewHTTPGuard(server.URL).Inspect(context.Background(), PhaseRequest, "hello")
	if err == nil || !strings.Contains(err.Error(), "decode guardrail response") {
		t.Fatalf("Inspect() error = %v, want decode error", err)
	}
}

func TestDefaultScenariosCoverRequestAndResponse(t *testing.T) {
	scenarios := DefaultScenarios()
	if len(scenarios) != 4 {
		t.Fatalf("len(DefaultScenarios()) = %d, want 4", len(scenarios))
	}
	phases := map[Phase]bool{}
	for _, scenario := range scenarios {
		if len(scenario.Steps) == 0 {
			t.Fatalf("scenario %q has no steps", scenario.Name)
		}
		phases[scenario.Steps[0].Phase] = true
	}
	if !phases[PhaseRequest] || !phases[PhaseResponse] {
		t.Fatalf("phases = %v, want request and response", phases)
	}
}

func TestHTTPGuardRejectsAmbiguousDecisions(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"action":null}`, `{"action":{}}`, `{"action":{"status_code":200,"reason":"bad"}}`, `{"action":{"reason":"pass"}} {}`, strings.Repeat("x", 16385)} {
		t.Run(body[:min(len(body), 24)], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer server.Close()
			if _, err := NewHTTPGuard(server.URL).Inspect(context.Background(), PhaseRequest, "inert"); err == nil {
				t.Fatal("ambiguous result allowed")
			}
		})
	}
}
