package boundary

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"guardrail-proxy/security"
)

type authStub struct{ deny bool }

func (a authStub) Authenticate(*http.Request) (security.IdentityContext, error) {
	if a.deny {
		return security.IdentityContext{}, errors.New("deny")
	}
	return security.IdentityContext{Principal: "local-developer", Workload: "local-agent", Tenant: "local", Session: "test", Authentication: "test", Scopes: []string{"workspace:read", "model:invoke"}}, nil
}

func setup(t *testing.T) (*Server, *atomic.Int32, *bytes.Buffer) {
	t.Helper()
	calls := new(atomic.Int32)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		for _, key := range []string{"Authorization", "X-Principal", "X-Workload", "Cookie", "X-Api-Key"} {
			if r.Header.Get(key) != "" {
				t.Error("forwarded identity or secret", key)
			}
		}
		if !strings.HasPrefix(r.Header.Get("traceparent"), "00-") {
			t.Error("missing trace")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "upstream-session")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"safe"}]}}`))
	}))
	t.Cleanup(upstream.Close)
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"status":"allowed"}`)) }))
	t.Cleanup(guard.Close)
	file := filepath.Join(t.TempDir(), "policy.json")
	p, _ := os.ReadFile("../../config/policy.json")
	os.WriteFile(file, p, 0600)
	audit := new(bytes.Buffer)
	s := &Server{Auth: authStub{}, PolicyFile: file, Audit: &security.Audit{Writer: audit}, Budgets: &security.Budgets{Limits: security.Limits{RequestsPerMinute: 60, Calls: 100, Concurrent: 4, InputBytes: 65536, OutputTokens: 4096, Workflow: time.Hour}}, Client: &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ModelURL: upstream.URL, MCPURL: upstream.URL, GuardURL: guard.URL}
	return s, calls, audit
}

const readRequest = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/workspace/safe"}}}`
const completion = `{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hello"}],"max_tokens":128}`

func TestBoundaryNoDispatchOnDeny(t *testing.T) {
	for _, name := range []string{"auth", "policy outage", "malformed policy", "emergency", "unknown tool", "write", "traversal", "arguments", "batch", "method", "session spoof", "input budget", "token budget", "unknown model", "recursive method", "stream", "query credential"} {
		t.Run(name, func(t *testing.T) {
			s, calls, _ := setup(t)
			path, body, method := "/mcp", readRequest, "POST"
			switch name {
			case "auth":
				s.Auth = authStub{true}
			case "policy outage":
				os.Remove(s.PolicyFile)
			case "malformed policy":
				os.WriteFile(s.PolicyFile, []byte(`null`), 0600)
			case "emergency":
				p, _ := security.LoadPolicy(s.PolicyFile)
				p.EmergencyDeny = true
				b, _ := json.Marshal(p)
				os.WriteFile(s.PolicyFile, b, 0600)
			case "unknown tool":
				body = strings.ReplaceAll(body, "read_text_file", "arbitrary")
			case "write":
				body = strings.ReplaceAll(body, "read_text_file", "write_file")
			case "traversal":
				body = strings.ReplaceAll(body, "/workspace/safe", "/workspace/../private")
			case "arguments":
				body = strings.ReplaceAll(body, `"path":`, `"command":"inert","path":`)
			case "batch":
				body = "[" + body + "]"
			case "method":
				method = "GET"
			case "input budget":
				s.Budgets.Limits.InputBytes = 1
			case "token budget":
				path = "/v1/chat/completions"
				body = strings.ReplaceAll(completion, "128", "999999")
			case "unknown model":
				path = "/v1/chat/completions"
				body = strings.ReplaceAll(completion, "gpt-4o-mini", "unknown")
			case "recursive method":
				body = strings.ReplaceAll(body, "tools/call", "sampling/createMessage")
			case "stream":
				path = "/v1/chat/completions"
				body = strings.ReplaceAll(completion, `"max_tokens":128`, `"stream":true`)
			case "query credential":
				path += "?access_token=synthetic"
			}
			r := httptest.NewRequest(method, path, strings.NewReader(body))
			if name == "session spoof" {
				r.Header.Set("Mcp-Session-Id", "unknown")
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code < 400 || calls.Load() != 0 {
				t.Fatal(w.Code, calls.Load(), w.Body.String())
			}
		})
	}
}

func TestBoundaryStripsCredentialsAndAudits(t *testing.T) {
	for _, path := range []string{"/mcp", "/v1/chat/completions"} {
		t.Run(path, func(t *testing.T) {
			s, calls, audit := setup(t)
			body := readRequest
			if path != "/mcp" {
				body = completion
			}
			r := httptest.NewRequest("POST", path, strings.NewReader(body))
			for _, key := range []string{"Authorization", "X-Principal", "X-Workload", "Cookie", "X-Api-Key"} {
				r.Header.Set(key, "synthetic-secret")
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 200 || calls.Load() != 1 {
				t.Fatal(w.Code, w.Body.String())
			}
			if strings.Contains(audit.String(), "synthetic-secret") || strings.Contains(audit.String(), "/workspace/safe") {
				t.Fatal("audit leak")
			}
			if !strings.Contains(audit.String(), w.Header().Get("X-Loom-Decision-ID")) || !strings.Contains(audit.String(), w.Header().Get("X-Loom-Trace-ID")) {
				t.Fatal("missing correlation")
			}
		})
	}
}

func TestGuardFailuresDenyModelDispatch(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"status":"allowed"} {}`, `{"status":"error"}`, `{"status":"blocked"}`, `invalid`, strings.Repeat("x", 4097)} {
		t.Run(body[:min(len(body), 24)], func(t *testing.T) {
			s, calls, _ := setup(t)
			guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer guard.Close()
			s.GuardURL = guard.URL
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(completion)))
			if w.Code != 403 || calls.Load() != 0 {
				t.Fatal(w.Code, calls.Load())
			}
		})
	}
	s, calls, _ := setup(t)
	s.GuardURL = "http://127.0.0.1:1"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(completion)))
	if w.Code != 403 || calls.Load() != 0 {
		t.Fatal("outage dispatched")
	}
}

type failingAudit struct{}

func (failingAudit) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestAuditOutagePreventsExecution(t *testing.T) {
	s, calls, _ := setup(t)
	s.Audit.Writer = failingAudit{}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/mcp", strings.NewReader(readRequest)))
	if w.Code != 503 || calls.Load() != 0 {
		t.Fatal(w.Code)
	}
}

func TestUnsafeToolResultSuppressed(t *testing.T) {
	s, calls, _ := setup(t)
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"status":"blocked"}`)) }))
	defer guard.Close()
	s.GuardURL = guard.URL
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/mcp", strings.NewReader(readRequest)))
	if w.Code != 403 || calls.Load() != 1 || strings.Contains(w.Body.String(), `"safe"`) {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestUpstreamFailureContainment(t *testing.T) {
	for _, name := range []string{"unavailable", "timeout", "oversized", "redirect", "server error", "circuit"} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := setup(t)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch name {
				case "timeout":
					time.Sleep(100 * time.Millisecond)
				case "oversized":
					w.Write(bytes.Repeat([]byte("x"), (1<<20)+1))
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1:1")
					w.WriteHeader(302)
				case "server error", "circuit":
					w.WriteHeader(503)
					w.Write([]byte("synthetic-secret"))
				}
			}))
			defer upstream.Close()
			s.MCPURL = upstream.URL
			if name == "unavailable" {
				upstream.Close()
			}
			if name == "timeout" {
				s.Client.Timeout = 20 * time.Millisecond
			}
			repeats := 1
			if name == "circuit" {
				repeats = 4
			}
			for i := 0; i < repeats; i++ {
				w := httptest.NewRecorder()
				s.ServeHTTP(w, httptest.NewRequest("POST", "/mcp", strings.NewReader(readRequest)))
				if w.Code == 200 || strings.Contains(w.Body.String(), "synthetic-secret") || w.Header().Get("Location") != "" {
					t.Fatal(name, w.Code, w.Body.String())
				}
				if name == "circuit" && i == 3 && !strings.Contains(w.Body.String(), "circuit_open") {
					t.Fatal("circuit bypass")
				}
			}
		})
	}
}
