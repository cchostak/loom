package enterprise

import (
	"database/sql"
	"errors"
	"guardrail-proxy/security"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"), []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	s.Audit = func(any) error { return nil }
	return s
}
func actor(name string) security.IdentityContext {
	return security.IdentityContext{Principal: name, Tenant: "alpha", Workload: "worker", Session: "session-" + name, Scopes: []string{"document:read", "document:write", "action:propose"}}
}
func operator() security.IdentityContext {
	i := actor("bob")
	i.Scopes = append(i.Scopes, "operator:approve")
	return i
}
func apply(t *testing.T, s *Store, route string, q Request) any {
	t.Helper()
	v, err := s.Apply(route, q)
	if err != nil {
		t.Fatal(route, err)
	}
	return v
}
func TestDurableBudget(t *testing.T) {
	s := testStore(t)
	s.Calls = 2
	q := Request{Key: "identity", Size: 4, Tokens: 100}
	for range 2 {
		lease := apply(t, s, "/budget/acquire", q).(map[string]string)
		apply(t, s, "/budget/release", Request{ID: lease["id"]})
	}
	if _, err := s.Apply("/budget/acquire", q); err == nil {
		t.Fatal("quota reset")
	}
	var calls, tokens int
	if s.DB.QueryRow(`SELECT calls,tokens FROM budgets WHERE key=?`, q.Key).Scan(&calls, &tokens) != nil || calls != 2 || tokens != 200 {
		t.Fatal("missing durable reservation")
	}
	s.DB.Close()
	if _, err := s.Apply("/budget/acquire", q); err == nil {
		t.Fatal("failed open")
	}
}
func TestBudgetConcurrentAdmission(t *testing.T) {
	s := testStore(t)
	var count atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.Apply("/budget/acquire", Request{Key: "shared", Size: 1}); e == nil {
				count.Add(1)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 4 {
		t.Fatalf("admitted %d", count.Load())
	}
}
func TestApprovalLifecycle(t *testing.T) {
	for _, name := range []string{"success", "self approval", "no approval", "mutated", "foreign tenant", "revoked", "expired", "requester revoked", "approver revoked", "audit outage", "replay", "race"} {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			user, op := actor("alice"), operator()
			id := apply(t, s, "/actions/propose", Request{Identity: user, Content: "Create an inert receipt"}).(map[string]any)["id"].(string)
			if name == "self approval" {
				user.Scopes = append(user.Scopes, "operator:approve")
				if _, err := s.Apply("/actions/approve", Request{Identity: user, ID: id}); err == nil {
					t.Fatal("self approved")
				}
				return
			}
			if name != "no approval" {
				apply(t, s, "/actions/approve", Request{Identity: op, ID: id})
			}
			q := Request{Identity: user, ID: id}
			switch name {
			case "mutated":
				q.Content = "different action"
			case "foreign tenant":
				q.Identity.Tenant = "beta"
			case "revoked":
				apply(t, s, "/actions/revoke", Request{Identity: op, ID: id})
			case "expired":
				_, _ = s.DB.Exec(`UPDATE actions SET expires=0 WHERE id=?`, id)
			case "requester revoked":
				apply(t, s, "/revoke", Request{Identity: op, Kind: "principal", Value: "alice"})
			case "approver revoked":
				apply(t, s, "/revoke", Request{Identity: op, Kind: "principal", Value: "bob"})
			case "audit outage":
				s.Audit = func(any) error { return errors.New("offline") }
			}
			if name == "race" {
				var n atomic.Int32
				var wg sync.WaitGroup
				for range 12 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if _, err := s.Apply("/actions/execute", q); err == nil {
							n.Add(1)
						}
					}()
				}
				wg.Wait()
				if n.Load() != 1 {
					t.Fatal("multiple executions")
				}
				return
			}
			_, err := s.Apply("/actions/execute", q)
			want := name == "success" || name == "replay"
			if (err == nil) != want {
				t.Fatalf("unexpected result: %v", err)
			}
			if name == "replay" {
				if _, err := s.Apply("/actions/execute", q); err == nil {
					t.Fatal("replayed")
				}
			}
		})
	}
}
func TestLineageAndACL(t *testing.T) {
	s := testStore(t)
	alice, planner, op := actor("alice"), actor("planner"), operator()
	source := apply(t, s, "/documents/create", Request{Identity: alice, Content: "Untrusted repository instructions", Readers: []string{"planner"}}).(map[string]string)["id"]
	summary := apply(t, s, "/documents/derive", Request{Identity: alice, Content: "A summary", Parents: []string{source}, Readers: []string{"planner"}}).(map[string]string)["id"]
	d := apply(t, s, "/documents/read", Request{Identity: planner, ID: summary}).(Document)
	if !d.Data.Tainted || d.Data.Trust != "untrusted" || d.Data.Integrity == "" || len(d.Data.Parents) != 1 || d.Data.Parents[0] != source {
		t.Fatal("lineage lost")
	}
	foreign := planner
	foreign.Tenant = "beta"
	if _, err := s.Apply("/documents/read", Request{Identity: foreign, ID: summary}); err == nil {
		t.Fatal("cross tenant read")
	}
	apply(t, s, "/documents/revoke", Request{Identity: op, ID: source, Reader: "planner"})
	if _, err := s.Apply("/documents/read", Request{Identity: planner, ID: summary}); err == nil {
		t.Fatal("ancestor ACL ignored")
	}
	if _, err := s.Apply("/documents/derive", Request{Identity: planner, Content: "Laundered", Parents: []string{summary}}); err == nil {
		t.Fatal("revoked ancestor laundered")
	}
}
func TestTransactionRollback(t *testing.T) {
	s := testStore(t)
	_, err := s.transaction(func(tx *sql.Tx) (any, error) {
		_, e := tx.Exec(`INSERT INTO revoked VALUES ('principal','alpha/alice')`)
		if e != nil {
			return nil, e
		}
		return nil, denied
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	apply(t, s, "/active", Request{Identity: actor("alice")})
}
func TestAuditAppendChain(t *testing.T) {
	s := testStore(t)
	for range 2 {
		if _, err := s.appendEvent([]byte(`{"event":"decision"}`)); err != nil {
			t.Fatal(err)
		}
	}
	var prior, hash string
	if s.DB.QueryRow(`SELECT previous,hash FROM events WHERE seq=2`).Scan(&prior, &hash) != nil || prior == "" || hash == prior {
		t.Fatal("invalid chain")
	}
}
