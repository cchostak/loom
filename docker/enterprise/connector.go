package enterprise

import (
	"bytes"
	"database/sql"
	"io"
	"net/http"
	"time"
)

// Connector keeps provider credentials outside Agentgateway. Signed exact-body
// grants are short-lived, one-use and checked again against durable revocation.
type Connector struct {
	Store            *Store
	State            Remote
	Audit            Remote
	Client           *http.Client
	URL, ProviderKey string
}

func (c Connector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.URL.Path == "/health" {
		w.WriteHeader(200)
		return
	}
	if r.Method != "POST" || r.URL.Path != "/v1/chat/completions" || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		http.Error(w, "denied", 403)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if err != nil {
		http.Error(w, "denied", 413)
		return
	}
	p, err := Verify(c.Store.Key, r.Header.Get("X-Loom-Dispatch"))
	if err != nil || p.Digest != BodyDigest(b) || c.State.Call("/active", Request{Identity: p.Identity}, nil) != nil {
		http.Error(w, "dispatch denied", 403)
		return
	}
	if c.Audit.Call("/events", map[string]string{"event": "provider_dispatch", "id": p.ID, "tenant": p.Identity.Tenant, "workload": p.Identity.Workload}, nil) != nil {
		http.Error(w, "audit unavailable", 503)
		return
	}
	_, err = c.Store.transaction(func(tx *sql.Tx) (any, error) {
		if _, err := tx.Exec(`DELETE FROM nonces WHERE expires<=?`, time.Now().Unix()); err != nil {
			return nil, err
		}
		_, err := tx.Exec(`INSERT INTO nonces VALUES (?,?)`, p.ID, p.ExpiresAt.Unix())
		return nil, err
	})
	if err != nil {
		http.Error(w, "replayed dispatch", 403)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), "POST", c.URL, bytes.NewReader(b))
	if err != nil {
		http.Error(w, "provider unavailable", 502)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ProviderKey)
	res, err := c.Client.Do(req)
	if err != nil {
		http.Error(w, "provider unavailable", 502)
		return
	}
	defer res.Body.Close()
	result, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(result) > 1<<20 {
		http.Error(w, "provider response limit", 502)
		return
	}
	// No upstream headers or errors are exposed. Normal results still pass Loom inspection.
	if res.StatusCode != 200 {
		http.Error(w, "provider rejected request", 502)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(result)
}
