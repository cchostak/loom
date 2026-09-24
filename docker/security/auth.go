package security

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"time"
)

// Authenticator is implemented by a trusted local registry; production adapters
// must validate issuer, audience, signature and expiry before returning identity.
type Authenticator interface {
	Authenticate(*http.Request) (IdentityContext, error)
}

type Credential struct {
	Digest   string          `json:"sha256"`
	Audience string          `json:"audience"`
	Expires  time.Time       `json:"expires"`
	Identity IdentityContext `json:"identity"`
}

type Registry struct {
	File     string
	Audience string
}

func (r Registry) Authenticate(req *http.Request) (IdentityContext, error) {
	var empty IdentityContext
	token := req.Header.Get("Authorization")
	if len(token) < 39 || len(token) > 1024 || token[:7] != "Bearer " {
		return empty, errors.New("authentication required")
	}
	sum := sha256.Sum256([]byte(token[7:]))
	b, err := os.ReadFile(r.File)
	if err != nil || len(b) > 1<<20 {
		return empty, errors.New("identity registry unavailable")
	}
	var credentials []Credential
	if Decode(b, &credentials) != nil {
		return empty, errors.New("invalid identity registry")
	}
	for _, c := range credentials {
		if c.Digest == hex.EncodeToString(sum[:]) && c.Audience == r.Audience && time.Now().Before(c.Expires) && c.Identity.Principal != "" && c.Identity.Workload != "" && c.Identity.Tenant != "" && c.Identity.Session != "" {
			c.Identity.Authentication = "local-opaque-bearer"
			return c.Identity, nil
		}
	}
	return empty, errors.New("invalid credential")
}
