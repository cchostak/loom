package enterprise

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"guardrail-proxy/security"
	"time"
)

type Proof struct {
	jwt.RegisteredClaims
	Identity security.IdentityContext `json:"identity"`
	Digest   string                   `json:"digest"`
}

// BodyDigest canonicalizes the supported text protocol, preserving all fields.
func BodyDigest(body []byte) string {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return ""
	}
	if m, ok := value.(map[string]any); ok {
		if stream, ok := m["stream"].(bool); ok && !stream {
			delete(m, "stream")
		}
	}
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func Sign(key []byte, id security.IdentityContext, body []byte) (string, error) {
	if len(key) < 32 {
		return "", errors.New("dispatch key unavailable")
	}
	now := time.Now()
	p := Proof{RegisteredClaims: jwt.RegisteredClaims{Issuer: "loom-control-plane", Audience: []string{"loom-execution"}, ID: security.NewID(), IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second))}, Identity: id, Digest: BodyDigest(body)}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, p).SignedString(key)
}
func Verify(key []byte, encoded string) (*Proof, error) {
	if len(key) < 32 || len(encoded) > 16384 {
		return nil, denied
	}
	p := &Proof{}
	token, err := jwt.ParseWithClaims(encoded, p, func(*jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("loom-control-plane"), jwt.WithAudience("loom-execution"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !token.Valid || p.ID == "" || p.IssuedAt == nil || p.ExpiresAt.Sub(p.IssuedAt.Time) > 30*time.Second || p.Identity.Tenant == "" || p.Digest == "" {
		return nil, denied
	}
	return p, nil
}
