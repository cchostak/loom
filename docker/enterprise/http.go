package enterprise

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"guardrail-proxy/security"
	"io"
	"net/http"
	"strings"
)

type Service struct {
	Store *Store
	Token string
	Mode  string
}

func (s Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/health" && r.Method == "GET" {
		var n int
		if s.Store.DB.QueryRow("SELECT 1").Scan(&n) != nil {
			http.Error(w, "storage unavailable", 503)
		}
		return
	}
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" || len(s.Token) < 32 || !hmac.Equal([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.Token)) {
		http.Error(w, "denied", 403)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if err != nil {
		http.Error(w, "input limit", 413)
		return
	}
	var result any
	if s.Mode == "audit" {
		if r.URL.Path != "/events" {
			http.Error(w, "denied", 403)
			return
		}
		result, err = s.Store.appendEvent(b)
	} else {
		var q Request
		err = security.Decode(b, &q)
		if err == nil {
			result, err = s.Store.Apply(r.URL.Path, q)
		}
	}
	if err != nil {
		http.Error(w, "operation denied or service unavailable", 403)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}
func (s *Store) appendEvent(b []byte) (any, error) {
	// Dedicated authenticated append-only API: no update/delete/read endpoint.
	var event map[string]any
	if json.Unmarshal(b, &event) != nil || len(event) == 0 {
		return nil, denied
	}
	return s.transaction(func(tx *sql.Tx) (any, error) {
		var previous string
		err := tx.QueryRow(`SELECT hash FROM events ORDER BY seq DESC LIMIT 1`).Scan(&previous)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		mac := hmac.New(sha256.New, s.Key)
		mac.Write([]byte(previous))
		mac.Write(b)
		hash := hex.EncodeToString(mac.Sum(nil))
		result, err := tx.Exec(`INSERT INTO events(body,previous,hash) VALUES (?,?,?)`, string(b), previous, hash)
		if err != nil {
			return nil, err
		}
		seq, err := result.LastInsertId()
		return map[string]any{"sequence": seq, "hash": hash}, err
	})
}

// API is an authenticated adapter; clients cannot supply the state service identity.
type API struct {
	Auth             security.Authenticator
	State            Remote
	Next             http.Handler
	Resource, Issuer string
}

func (a API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
		if r.Method != "GET" || (r.URL.Path != "/.well-known/oauth-protected-resource" && r.URL.Path != "/.well-known/oauth-protected-resource/mcp") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": a.Resource, "authorization_servers": []string{a.Issuer}, "bearer_methods_supported": []string{"header"}, "scopes_supported": []string{"model:invoke", "mcp:connect", "workspace:read", "document:read", "document:write", "action:propose"}})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/enterprise/") {
		a.Next.ServeHTTP(w, r)
		return
	}
	id, err := a.Auth.Authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+a.Resource+`/.well-known/oauth-protected-resource"`)
		http.Error(w, "authentication required", 401)
		return
	}
	if r.Method != "POST" || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		http.Error(w, "denied", 400)
		return
	}
	var q Request
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if err != nil || security.Decode(b, &q) != nil || q.Identity.Principal != "" || q.Identity.Tenant != "" || q.Key != "" {
		http.Error(w, "invalid request", 400)
		return
	}
	q.Identity = id
	route := strings.TrimPrefix(r.URL.Path, "/enterprise")
	if !(strings.HasPrefix(route, "/actions/") || strings.HasPrefix(route, "/documents/") || route == "/revoke") {
		http.NotFound(w, r)
		return
	}
	var result json.RawMessage
	if a.State.Call(route, q, &result) != nil {
		http.Error(w, "operation denied", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(result)
}
