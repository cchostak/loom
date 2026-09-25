// Package enterprise supplies optional local deployment services for Loom.
package enterprise

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"guardrail-proxy/security"
	_ "modernc.org/sqlite"
)

type Store struct {
	DB                  *sql.DB
	Key                 []byte
	Calls, Tokens, Rate int
	Audit               func(any) error
}

// Open uses full synchronous transactions; one writer serializes state changes.
func Open(path string, key []byte) (*Store, error) {
	if len(key) < 32 {
		return nil, errors.New("state signing key required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS normalization_queue (id TEXT PRIMARY KEY, tenant TEXT, finding TEXT);
 CREATE TABLE IF NOT EXISTS budgets (key TEXT PRIMARY KEY, started INTEGER, calls INTEGER, tokens INTEGER);
 CREATE TABLE IF NOT EXISTS leases (id TEXT PRIMARY KEY, key TEXT, expires INTEGER);
 CREATE TABLE IF NOT EXISTS rates (key TEXT PRIMARY KEY, window INTEGER, count INTEGER);
 CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, expires INTEGER);
 CREATE TABLE IF NOT EXISTS revoked (kind TEXT, value TEXT, PRIMARY KEY(kind,value));
 CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, tenant TEXT, requester TEXT, session TEXT, body TEXT, version INTEGER, expires INTEGER, approver TEXT, used INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0);
 CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, action TEXT UNIQUE, tenant TEXT);
 CREATE TABLE IF NOT EXISTS documents (id TEXT PRIMARY KEY, tenant TEXT, content TEXT, readers TEXT, roots TEXT, version INTEGER DEFAULT 1);
 CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT, previous TEXT, hash TEXT);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db, Key: key, Calls: 500, Tokens: 65536, Rate: 60}, nil
}

type Request struct {
	Identity security.IdentityContext `json:"identity"`
	Key      string                   `json:"key,omitempty"`
	ID       string                   `json:"id,omitempty"`
	Size     int                      `json:"size,omitempty"`
	Tokens   int                      `json:"tokens,omitempty"`
	Content  string                   `json:"content,omitempty"`
	Parents  []string                 `json:"parents,omitempty"`
	Readers  []string                 `json:"readers,omitempty"`
	Reader   string                   `json:"reader,omitempty"`
	Kind     string                   `json:"kind,omitempty"`
	Value    string                   `json:"value,omitempty"`
}

func (s *Store) transaction(fn func(*sql.Tx) (any, error)) (any, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := fn(tx)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
func has(id security.IdentityContext, scope string) bool {
	for _, v := range id.Scopes {
		if v == scope {
			return true
		}
	}
	return false
}
func jsonText(v any) string { b, _ := json.Marshal(v); return string(b) }

var denied = errors.New("operation denied")

// Active rejects persistent principal, workload or authenticated-session revocation.
func active(tx *sql.Tx, id security.IdentityContext) error {
	var n int
	err := tx.QueryRow(`SELECT count(*) FROM revoked WHERE (kind='principal' AND value=?) OR (kind='workload' AND value=?) OR (kind='session' AND value=?)`, id.Tenant+"/"+id.Principal, id.Tenant+"/"+id.Workload, id.Tenant+"/"+id.Session).Scan(&n)
	if err != nil {
		return err
	}
	if n > 0 {
		return denied
	}
	return nil
}

// Apply exposes a closed set of authenticated state operations.
func (s *Store) Apply(route string, q Request) (any, error) {
	return s.transaction(func(tx *sql.Tx) (any, error) {
		if route == "/budget/acquire" {
			return s.acquire(tx, q, time.Now().Unix())
		}
		if route == "/budget/release" {
			_, err := tx.Exec(`DELETE FROM leases WHERE id=?`, q.ID)
			return map[string]bool{"released": err == nil}, err
		}
		if active(tx, q.Identity) != nil {
			return nil, denied
		}
		switch route {
		case "/active":
			return map[string]bool{"active": true}, nil
		case "/revoke":
			if !has(q.Identity, "operator:approve") || (q.Kind != "principal" && q.Kind != "workload" && q.Kind != "session") || q.Value == "" {
				return nil, denied
			}
			if s.Audit == nil || s.Audit(map[string]string{"event": "revoke", "actor": q.Identity.Principal, "tenant": q.Identity.Tenant}) != nil {
				return nil, denied
			}
			_, err := tx.Exec(`INSERT OR IGNORE INTO revoked VALUES (?,?)`, q.Kind, q.Identity.Tenant+"/"+q.Value)
			return map[string]bool{"revoked": err == nil}, err
		case "/actions/propose", "/actions/approve", "/actions/execute", "/actions/revoke":
			return s.action(tx, route, q)
		case "/documents/create", "/documents/derive", "/documents/read", "/documents/revoke":
			return s.document(tx, route, q)
		}
		return nil, denied
	})
}
func (s *Store) acquire(tx *sql.Tx, q Request, now int64) (any, error) {
	if q.Key == "" || q.Size < 0 || q.Size > 65536 || q.Tokens < 0 || q.Tokens > 4096 {
		return nil, denied
	}
	if _, err := tx.Exec(`DELETE FROM leases WHERE expires<=?`, now); err != nil {
		return nil, err
	}
	var started int64
	var calls, tokens, concurrent int
	err := tx.QueryRow(`SELECT started,calls,tokens FROM budgets WHERE key=?`, q.Key).Scan(&started, &calls, &tokens)
	if err == sql.ErrNoRows {
		started = now
	} else if err != nil {
		return nil, err
	}
	if err = tx.QueryRow(`SELECT count(*) FROM leases WHERE key=?`, q.Key).Scan(&concurrent); err != nil {
		return nil, err
	}
	if now-started >= 3600 || calls >= s.Calls || tokens+q.Tokens > s.Tokens || concurrent >= 4 {
		return nil, denied
	}
	if _, err = tx.Exec(`INSERT INTO budgets VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET calls=excluded.calls,tokens=excluded.tokens`, q.Key, started, calls+1, tokens+q.Tokens); err != nil {
		return nil, err
	}
	lease := security.NewID()
	_, err = tx.Exec(`INSERT INTO leases VALUES (?,?,?)`, lease, q.Key, now+35)
	return map[string]string{"id": lease}, err
}
