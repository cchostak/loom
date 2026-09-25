package security

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOIDCAccessTokens(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	encode := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	available := true
	kid := "first"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available {
			http.Error(w, "unavailable", 503)
			return
		}
		if r.URL.Path == "/discovery" {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://issuer.example", "jwks_uri": "https://issuer.example/jwks"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": encode(key.N.Bytes()), "e": encode(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer server.Close()
	o := OIDC{Issuer: "https://issuer.example", Audience: "https://loom.example", DiscoveryURL: server.URL + "/discovery", JWKSURL: server.URL + "/jwks", PublicJWKSURL: "https://issuer.example/jwks", Bindings: []OIDCBinding{{Subject: "alice", ClientID: "researcher", Identity: IdentityContext{Principal: "alice", Tenant: "alpha", Workload: "researcher", Session: "stable", Scopes: []string{"model:invoke"}}}}}
	for _, name := range []string{"valid", "wrong issuer", "wrong audience", "expired", "future", "id token", "unknown subject", "unknown client", "forged signature", "wrong algorithm", "missing expiry", "missing issued", "extra audience", "key rotation", "issuer outage", "scope escalation"} {
		t.Run(name, func(t *testing.T) {
			available = true
			kid = "first"
			now := time.Now()
			c := accessClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: "alice", Issuer: o.Issuer, Audience: []string{o.Audience}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))}, ClientID: "researcher", Scope: "model:invoke operator:approve"}
			typ := "at+jwt"
			var signing any = key
			var method jwt.SigningMethod = jwt.SigningMethodRS256
			switch name {
			case "wrong issuer":
				c.Issuer = "https://evil.example"
			case "wrong audience":
				c.Audience = []string{"elsewhere"}
			case "expired":
				c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Minute))
			case "future":
				c.NotBefore = jwt.NewNumericDate(now.Add(time.Hour))
			case "id token":
				typ = "JWT"
			case "unknown subject":
				c.Subject = "bob"
			case "unknown client":
				c.ClientID = "elsewhere"
			case "forged signature":
				signing, _ = rsa.GenerateKey(rand.Reader, 2048)
			case "wrong algorithm":
				method = jwt.SigningMethodHS256
				signing = []byte("a different key")
			case "missing expiry":
				c.ExpiresAt = nil
			case "missing issued":
				c.IssuedAt = nil
			case "extra audience":
				c.Audience = append(c.Audience, "another")
			case "key rotation":
				kid = "second"
			case "issuer outage":
				available = false
			}
			token := jwt.NewWithClaims(method, c)
			token.Header["typ"] = typ
			token.Header["kid"] = kid
			encoded, err := token.SignedString(signing)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/mcp", nil)
			req.Header.Set("Authorization", "Bearer "+encoded)
			req.Header.Set("X-Loom-Workload", "operator")
			id, err := o.Authenticate(req)
			valid := name == "valid" || name == "key rotation" || name == "scope escalation"
			if (err == nil) != valid {
				t.Fatalf("unexpected result: %v", err)
			}
			if valid && (id.Workload != "researcher" || len(id.Scopes) != 1 || id.Scopes[0] != "model:invoke") {
				t.Fatal("identity escalation")
			}
		})
	}
}
func TestBudgetKeysSeparateIdentity(t *testing.T) {
	base := IdentityContext{Principal: "a", Tenant: "t", Workload: "w", Session: "s"}
	seen := map[string]bool{BudgetKey(base): true}
	for _, change := range []func(*IdentityContext){func(i *IdentityContext) { i.Principal = "b" }, func(i *IdentityContext) { i.Tenant = "u" }, func(i *IdentityContext) { i.Workload = "x" }, func(i *IdentityContext) { i.Session = "r" }} {
		id := base
		change(&id)
		key := BudgetKey(id)
		if seen[key] {
			t.Fatal("quota collision")
		}
		seen[key] = true
	}
}
