package security

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

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
