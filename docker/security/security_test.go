package security

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (Policy, ActionRequest) {
	t.Helper()
	p, err := LoadPolicy("../../config/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	return p, ActionRequest{Identity: IdentityContext{Principal: "local-developer", Workload: "local-agent", Tenant: "local", Session: "test", Authentication: "test", Scopes: []string{"workspace:read"}}, Category: "mcp", Tool: "read_text_file", Method: "tools/call", Resource: "/workspace/readme", Destination: "filesystem", SideEffects: "read", Data: DataContext{Trust: "untrusted", Sensitivity: "unknown", Tainted: true}}
}

func TestPolicyAuthorityAndContext(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ActionRequest)
	}{
		{"principal", func(a *ActionRequest) { a.Identity.Principal = "attacker" }},
		{"workload", func(a *ActionRequest) { a.Identity.Workload = "publisher" }},
		{"tenant", func(a *ActionRequest) { a.Identity.Tenant = "other" }},
		{"unknown identity", func(a *ActionRequest) { a.Identity.Authentication = "" }},
		{"scope", func(a *ActionRequest) { a.Identity.Scopes = nil }},
		{"delegation", func(a *ActionRequest) { a.Identity.DelegatedFrom = "admin" }},
		{"depth", func(a *ActionRequest) { a.Depth = 1 }},
		{"delegation depth", func(a *ActionRequest) { a.DelegationDepth = 1 }},
		{"tool", func(a *ActionRequest) { a.Tool = "execute_command" }},
		{"method", func(a *ActionRequest) { a.Method = "resources/read" }},
		{"resource", func(a *ActionRequest) { a.Resource = "/workspace-other/file" }},
		{"destination", func(a *ActionRequest) { a.Destination = "evil.example" }},
		{"classification", func(a *ActionRequest) { a.Data.Sensitivity = "secret" }},
		{"trust", func(a *ActionRequest) { a.Data.Trust = "trusted" }},
		{"write", func(a *ActionRequest) { a.SideEffects = "write" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, a := fixture(t)
			tc.mutate(&a)
			if p.Evaluate(a, time.Now()).Outcome != "deny" {
				t.Fatal("allowed")
			}
		})
	}
	p, a := fixture(t)
	d := p.Evaluate(a, time.Now())
	if d.Outcome != "allow" || d.ID == "" || d.RuleID == "default-deny" || d.Version == "" {
		t.Fatal(d)
	}
	for _, item := range []string{a.Identity.Principal, a.Identity.Workload, a.Identity.Session, a.Tool, a.Destination} {
		p.Disabled = []string{item}
		if p.Evaluate(a, time.Now()).Reason != "revoked" {
			t.Fatal(item)
		}
	}
	p.EmergencyDeny = true
	if p.Evaluate(a, time.Now()).Reason != "emergency_deny" {
		t.Fatal("emergency")
	}
}

func TestPolicyReloadFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.json")
	for _, body := range []string{"", `null`, `{}`, `{"id":"x","version":"1","extra":true}`, `{"id":"x","version":"1"} {}`, `{"id":"x","version":"1","rules":[{"id":"bad"}]}`} {
		os.WriteFile(file, []byte(body), 0600)
		if _, err := LoadPolicy(file); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	os.Remove(file)
	if _, err := LoadPolicy(file); err == nil {
		t.Fatal("missing policy allowed")
	}
}

func TestPathValidation(t *testing.T) {
	for _, p := range []string{"/etc/passwd", "/workspace/../secret", "/workspace/a/../../b", "/workspace//x", "/workspace/x/", "/workspace-other/x", "/workspace/%2e%2e", "/workspace/a\\b", "/workspace/\x00", "relative"} {
		if _, err := WorkspacePath(p); err == nil {
			t.Fatal(p)
		}
	}
	for _, p := range []string{"/workspace", "/workspace/file", "/workspace/dir/file"} {
		if _, err := WorkspacePath(p); err != nil {
			t.Fatal(p, err)
		}
	}
}

func TestProvenanceSurvivesTransforms(t *testing.T) {
	for _, origin := range []string{"user", "model", "tool", "retrieved", "memory", "agent"} {
		d := DataContext{Source: "source", Trust: "untrusted", Sensitivity: "secret", Origin: origin, Tainted: true, Integrity: "old"}
		for i := 0; i < 3; i++ {
			d = d.Derived("summarizer")
		}
		if !d.Tainted || d.Trust != "untrusted" || d.Sensitivity != "secret" || len(d.Parents) != 3 || d.Integrity != "" {
			t.Fatal(d)
		}
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("offline") }
func TestAuditContainsOnlySafeFields(t *testing.T) {
	for _, secret := range []string{"Bearer secret-value", "password-123", "sk-or-v1-secret", "PRIVATE KEY", "alice@example.com", "/private/customer-record"} {
		var b bytes.Buffer
		p, a := fixture(t)
		a.Resource = secret
		a.Arguments, _ = json.Marshal(map[string]string{"password": secret})
		d := p.Evaluate(a, time.Now())
		if err := (&Audit{Writer: &b}).Record(a, d, "trace", "decision", 0); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.String(), secret) || !strings.Contains(b.String(), d.ID) || !strings.Contains(b.String(), "trace") {
			t.Fatal(b.String())
		}
	}
	p, a := fixture(t)
	if (&Audit{Writer: brokenWriter{}}).Record(a, p.Evaluate(a, time.Now()), "trace", "decision", 0) == nil {
		t.Fatal("audit failure hidden")
	}
}

func FuzzWorkspacePath(f *testing.F) {
	for _, s := range []string{"/workspace", "/workspace/a", "/workspace/../etc", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := WorkspacePath(s)
		if err == nil && (strings.HasPrefix(r, "/") || strings.HasPrefix(r, "../") || strings.Contains(r, "/../") || r == "..") {
			t.Fatal(s, r)
		}
	})
}

func TestAuditCapacityStopsDispatch(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(100 << 20); err != nil {
		t.Fatal(err)
	}
	p, a := fixture(t)
	if (&Audit{Writer: f}).Record(a, p.Evaluate(a, time.Now()), "trace", "decision", 0) == nil {
		t.Fatal("unbounded audit growth")
	}
}
