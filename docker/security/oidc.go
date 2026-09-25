package security

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCBinding maps authenticated subjects and clients to server-owned authority.
type OIDCBinding struct {
	Subject  string          `json:"subject"`
	ClientID string          `json:"client_id"`
	Identity IdentityContext `json:"identity"`
}

type OIDC struct {
	Issuer        string        `json:"issuer"`
	Audience      string        `json:"audience"`
	DiscoveryURL  string        `json:"discovery_url"`
	JWKSURL       string        `json:"jwks_url"`
	PublicJWKSURL string        `json:"public_jwks_url"`
	Bindings      []OIDCBinding `json:"bindings"`
	Client        *http.Client  `json:"-"`
}

type accessClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

// Authenticate accepts resource-bound access tokens, never OIDC ID tokens.
// Discovery and keys are fetched from configured locations, not token headers.
// No stale-key fallback is used: issuer failure denies in this local reference.
func (o *OIDC) Authenticate(r *http.Request) (IdentityContext, error) {
	empty := IdentityContext{}
	denied := errors.New("invalid access token")
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || len(h) > 16384 {
		return empty, denied
	}
	var discovery struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if o.fetch(o.DiscoveryURL, &discovery) != nil || discovery.Issuer != o.Issuer || discovery.JWKS != o.PublicJWKSURL {
		return empty, denied
	}
	var keys struct {
		Keys []struct{ Kty, Kid, Use, Alg, N, E string } `json:"keys"`
	}
	if o.fetch(o.JWKSURL, &keys) != nil || len(keys.Keys) > 16 {
		return empty, denied
	}
	claims := &accessClaims{}
	token, err := jwt.ParseWithClaims(h[7:], claims, func(t *jwt.Token) (any, error) {
		if t.Header["typ"] != "at+jwt" {
			return nil, denied
		}
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, denied
		}
		for _, k := range keys.Keys {
			if k.Kid != kid || k.Kty != "RSA" || k.Use != "sig" || (k.Alg != "" && k.Alg != "RS256") {
				continue
			}
			n, e1 := base64.RawURLEncoding.DecodeString(k.N)
			e, e2 := base64.RawURLEncoding.DecodeString(k.E)
			if e1 != nil || e2 != nil || len(n) < 256 || len(n) > 512 || len(e) == 0 || len(e) > 4 {
				return nil, denied
			}
			exponent := new(big.Int).SetBytes(e).Int64()
			if exponent < 3 || exponent%2 == 0 || exponent > 2147483647 {
				return nil, denied
			}
			return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent)}, nil
		}
		return nil, denied
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(o.Issuer), jwt.WithAudience(o.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !token.Valid || claims.IssuedAt == nil || claims.Subject == "" || len(claims.Audience) != 1 || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 10*time.Minute {
		return empty, denied
	}
	for _, b := range o.Bindings {
		if b.Subject != claims.Subject || b.ClientID != claims.ClientID {
			continue
		}
		id := b.Identity
		if id.Principal == "" || id.Workload == "" || id.Tenant == "" || id.Session == "" {
			return empty, denied
		}
		id.Scopes = nil
		granted := strings.Fields(claims.Scope)
		for _, scope := range b.Identity.Scopes {
			for _, value := range granted {
				if scope == value {
					id.Scopes = append(id.Scopes, scope)
					break
				}
			}
		}
		id.Authentication = "oauth-access-token"
		return id, nil
	}
	return empty, denied
}

func (o *OIDC) fetch(url string, value any) error {
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("issuer unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(b) > 65536 {
		return errors.New("issuer response limit")
	}
	return json.Unmarshal(b, value)
}
