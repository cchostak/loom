package boundary

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOwnedSessionDelete(t *testing.T) {
	s, calls, audit := setup(t)
	// Obtain a session via a real authenticated/authorized request.
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/mcp", strings.NewReader(readRequest)))
	req := httptest.NewRequest("DELETE", "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", "upstream-session")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 || calls.Load() != 2 {
		t.Fatal(w.Code, calls.Load())
	}
	if len(s.sessions) != 0 {
		t.Fatal("session retained after delete")
	}
	if !strings.Contains(audit.String(), "session-delete") {
		t.Fatal("cleanup not audited")
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 403 || calls.Load() != 2 {
		t.Fatal("deleted session reused")
	}
}

func TestSessionDeleteRejectsInvalidRequests(t *testing.T) {
	for _, name := range []string{"missing", "foreign", "body", "query", "route", "auth", "workload"} {
		t.Run(name, func(t *testing.T) {
			s, calls, _ := setup(t)
			owner := "local/local-developer/local-agent/test"
			if name == "workload" {
				owner = "local/local-developer/other-workload/test"
			}
			s.sessions = map[string]string{"owned": owner}
			path, body, session := "/mcp", "", "owned"
			switch name {
			case "missing":
				session = ""
			case "foreign":
				session = "unknown"
			case "body":
				body = "{}"
			case "query":
				path += "?extra=1"
			case "route":
				path = "/v1/chat/completions"
			case "auth":
				s.Auth = authStub{true}
			}
			req := httptest.NewRequest(http.MethodDelete, path, strings.NewReader(body))
			req.Header.Set("Mcp-Session-Id", session)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
			if w.Code < 400 || calls.Load() != 0 {
				t.Fatal("invalid cleanup dispatched", w.Code)
			}
		})
	}
}

func TestSessionCloseWorksAfterBudgetExhaustion(t *testing.T) {
	s, calls, _ := setup(t)
	s.sessions = map[string]string{"owned": "local/local-developer/local-agent/test"}
	s.Budgets.Limits.InputBytes = -1
	req := httptest.NewRequest("DELETE", "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", "owned")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 || calls.Load() != 1 {
		t.Fatal("budget prevented owned cleanup")
	}
}
