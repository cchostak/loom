package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegistryAuthentication(t *testing.T) {
	token := strings.Repeat("x", 48)
	sum := sha256.Sum256([]byte(token))
	file := filepath.Join(t.TempDir(), "credentials.json")
	p, a := fixture(t)
	_ = p
	for _, name := range []string{"valid", "missing", "wrong", "expired", "audience", "spoofed", "malformed", "revoked"} {
		t.Run(name, func(t *testing.T) {
			c := Credential{Digest: hex.EncodeToString(sum[:]), Audience: "loom", Expires: time.Now().Add(time.Hour), Identity: a.Identity}
			r := httptest.NewRequest("POST", "/mcp", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			switch name {
			case "missing":
				r.Header.Del("Authorization")
			case "wrong":
				r.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 48))
			case "expired":
				c.Expires = time.Now().Add(-time.Second)
			case "audience":
				c.Audience = "other"
			case "spoofed":
				r.Header.Set("X-Principal", "admin")
			}
			b, _ := json.Marshal([]Credential{c})
			if name == "malformed" {
				b = []byte(`{}`)
			}
			if name == "revoked" {
				b = []byte(`[]`)
			}
			os.WriteFile(file, b, 0600)
			id, err := (Registry{file, "loom"}).Authenticate(r)
			if name == "valid" || name == "spoofed" {
				if err != nil || id.Principal != "local-developer" {
					t.Fatal(id, err)
				}
			} else if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestApprovalActionBinding(t *testing.T) {
	for _, name := range []string{"valid", "resource", "arguments", "actor", "destination", "side effects", "policy", "decision", "expired", "signature", "replay", "weak key"} {
		t.Run(name, func(t *testing.T) {
			p, a := fixture(t)
			d := p.Evaluate(a, time.Now())
			d.Outcome = "require_approval"
			store := Approvals{Key: []byte(strings.Repeat("k", 32))}
			approval, err := store.Issue(a, d, time.Now().Add(30*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "resource":
				a.Resource += "2"
			case "arguments":
				a.Arguments = json.RawMessage(`{"path":"/workspace/other"}`)
			case "actor":
				a.Identity.Principal = "other"
			case "destination":
				a.Destination = "elsewhere"
			case "side effects":
				a.SideEffects = "write"
			case "policy":
				d.Version = "new"
			case "decision":
				d.ID = "other"
			case "expired":
				approval.Expires = time.Now().Add(-time.Second)
			case "signature":
				approval.Signature = "bad"
			case "replay":
				if store.Consume(approval, a, d, time.Now()) != nil {
					t.Fatal("first use")
				}
			case "weak key":
				store.Key = nil
			}
			err = store.Consume(approval, a, d, time.Now())
			if (name == "valid") != (err == nil) {
				t.Fatal(name, err)
			}
		})
	}
}

func TestBudgetEnforcement(t *testing.T) {
	for _, name := range []string{"input", "tokens", "rate", "calls", "concurrency", "workflow", "release", "independent session"} {
		t.Run(name, func(t *testing.T) {
			b := Budgets{Limits: Limits{RequestsPerMinute: 2, Calls: 3, Concurrent: 1, InputBytes: 10, OutputTokens: 10, Workflow: time.Hour}}
			now := time.Now()
			size, tokens := 1, 1
			if name == "input" {
				size = 11
			}
			if name == "tokens" {
				tokens = 11
			}
			release, err := b.Acquire("session", size, tokens, now)
			if name == "input" || name == "tokens" {
				if err == nil {
					t.Fatal("limit bypass")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if name != "concurrency" {
				release()
				release()
			}
			next := now
			switch name {
			case "rate":
				r, _ := b.Acquire("session", 1, 1, now)
				r()
			case "calls":
				for i := 1; i <= 2; i++ {
					r, e := b.Acquire("session", 1, 1, now.Add(time.Duration(i)*time.Minute))
					if e != nil {
						t.Fatal(e)
					}
					r()
				}
				next = now.Add(3 * time.Minute)
			case "workflow":
				next = now.Add(time.Hour)
			}
			key := "session"
			if name == "independent session" {
				key = "other"
			}
			_, err = b.Acquire(key, 1, 1, next)
			allowed := name == "release" || name == "independent session"
			if allowed != (err == nil) {
				t.Fatal(name, err)
			}
		})
	}
}
