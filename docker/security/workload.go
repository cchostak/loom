package security

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type WorkloadRoute struct {
	Address string `json:"address"`
	ID      string `json:"id"`
}
type WorkloadConfig struct {
	ID               string                   `json:"id"`
	Socket           string                   `json:"socket"`
	Peers            []string                 `json:"peers"`
	Routes           map[string]WorkloadRoute `json:"routes"`
	IdentityBindings map[string][]string      `json:"identity_bindings"`
}
type Workload struct {
	Source  *workloadapi.X509Source
	Config  WorkloadConfig
	mu      sync.Mutex
	clients map[string]*http.Transport
}

// OpenWorkload obtains rotating short-lived credentials from the attested
// Workload API. Configuration cannot select a different identity from the source.
func OpenWorkload(ctx context.Context, path string) (*Workload, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config WorkloadConfig
	if Decode(b, &config) != nil || config.Socket == "" || config.ID == "" {
		return nil, errors.New("invalid workload configuration")
	}
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(config.Socket)))
	if err != nil {
		return nil, err
	}
	svid, err := source.GetX509SVID()
	if err != nil || svid.ID.String() != config.ID {
		source.Close()
		return nil, errors.New("workload identity mismatch")
	}
	return &Workload{Source: source, Config: config, clients: map[string]*http.Transport{}}, nil
}
func authorizeIDs(ids []string) tlsconfig.Authorizer {
	allowed := map[string]bool{}
	for _, id := range ids {
		allowed[id] = true
	}
	return func(id spiffeid.ID, chains [][]*x509.Certificate) error {
		if !allowed[id.String()] || len(chains) == 0 || len(chains[0]) == 0 {
			return errors.New("SPIFFE peer denied")
		}
		cert := chains[0][0]
		if cert.NotAfter.Sub(cert.NotBefore) > 10*time.Minute {
			return errors.New("SVID lifetime exceeds policy")
		}
		return nil
	}
}
func (w *Workload) ServerTLS() *tls.Config {
	c := tlsconfig.MTLSServerConfig(w.Source, w.Source, authorizeIDs(w.Config.Peers))
	c.MinVersion = tls.VersionTLS13
	c.SessionTicketsDisabled = true
	return c
}
func (w *Workload) ClientTLS(id string) *tls.Config {
	c := tlsconfig.MTLSClientConfig(w.Source, w.Source, authorizeIDs([]string{id}))
	c.MinVersion = tls.VersionTLS13
	return c
}

// RoundTrip rejects unlisted hosts; it never falls back to plaintext or a public
// route when the Workload API, trust bundle or peer identity is unavailable.
func (w *Workload) RoundTrip(r *http.Request) (*http.Response, error) {
	route, ok := w.Config.Routes[r.URL.Host]
	if !ok {
		return nil, errors.New("workload destination denied")
	}
	w.mu.Lock()
	transport := w.clients[route.ID]
	if transport == nil {
		transport = &http.Transport{TLSClientConfig: w.ClientTLS(route.ID), ForceAttemptHTTP2: true, IdleConnTimeout: 10 * time.Second, TLSHandshakeTimeout: 5 * time.Second, MaxIdleConns: 32}
		w.clients[route.ID] = transport
	}
	w.mu.Unlock()
	next := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = "https"
	u.Host = route.Address
	next.URL = &u
	return transport.RoundTrip(next)
}
func (w *Workload) MarshalIdentity() []byte {
	b, _ := json.Marshal(map[string]string{"spiffe_id": w.Config.ID})
	return b
}

type WorkloadAuth struct {
	Auth     Authenticator
	Bindings map[string][]string
}

func validateSVIDCert(cert *x509.Certificate, maxLife time.Duration) error {
	if cert == nil || len(cert.URIs) != 1 {
		return errors.New("SVID required")
	}
	if maxLife == 0 {
		maxLife = 10 * time.Minute
	}
	if cert.NotAfter.Sub(cert.NotBefore) > maxLife {
		return errors.New("SVID lifetime exceeds policy")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("SVID expired")
	}
	return nil
}

func (a WorkloadAuth) Authenticate(r *http.Request) (IdentityContext, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return IdentityContext{}, errors.New("mTLS required")
	}
	cert := r.TLS.PeerCertificates[0]
	if err := validateSVIDCert(cert, 10*time.Minute); err != nil {
		return IdentityContext{}, err
	}
	spiffeID := cert.URIs[0].String()
	if a.Auth != nil && r.Header.Get("Authorization") != "" {
		id, err := a.Auth.Authenticate(r)
		if err != nil {
			return id, err
		}
		if len(a.Bindings) > 0 {
			for _, workload := range a.Bindings[spiffeID] {
				if workload == id.Workload {
					return id, nil
				}
			}
			return IdentityContext{}, errors.New("credential and workload identity mismatch")
		}
		return id, nil
	}
	if len(a.Bindings) > 0 {
		workloads, ok := a.Bindings[spiffeID]
		if !ok || len(workloads) == 0 {
			return IdentityContext{}, errors.New("credential and workload identity mismatch")
		}
		return IdentityContext{
			Principal:      workloads[0],
			Workload:       workloads[0],
			Tenant:         "default",
			Session:        NewID(),
			Authentication: "spiffe-svid-mtls",
			Scopes:         []string{"swarm:agent", "mcp:access", "model:access"},
		}, nil
	}
	return ParseSVIDIdentity(cert)
}

// ParseSVIDIdentity extracts an IdentityContext directly from a validated short-lived SVID certificate.
func ParseSVIDIdentity(cert *x509.Certificate) (IdentityContext, error) {
	if err := validateSVIDCert(cert, 10*time.Minute); err != nil {
		return IdentityContext{}, err
	}
	uri := cert.URIs[0]
	if uri.Scheme != "spiffe" {
		return IdentityContext{}, errors.New("invalid SPIFFE URI scheme")
	}
	parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
	workload := "workload"
	if len(parts) >= 2 && parts[0] == "workload" {
		workload = parts[1]
	} else if len(parts) >= 1 && parts[0] != "" {
		workload = parts[len(parts)-1]
	}
	return IdentityContext{
		Principal:      workload,
		Workload:       workload,
		Tenant:         uri.Host,
		Session:        NewID(),
		Authentication: "spiffe-svid-mtls",
		Scopes:         []string{"swarm:agent", "mcp:access", "model:access"},
	}, nil
}

// SVIDAuthenticator provides direct cryptographic identity enforcement for A2A and
// container-to-container calls authenticated by short-lived SPIFFE SVIDs over mTLS.
type SVIDAuthenticator struct {
	AllowedPeers map[string]IdentityContext
	MaxLifetime  time.Duration
}

func (s SVIDAuthenticator) Authenticate(r *http.Request) (IdentityContext, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return IdentityContext{}, errors.New("mTLS required")
	}
	cert := r.TLS.PeerCertificates[0]
	if err := validateSVIDCert(cert, s.MaxLifetime); err != nil {
		return IdentityContext{}, err
	}
	spiffeID := cert.URIs[0].String()
	if len(s.AllowedPeers) > 0 {
		id, ok := s.AllowedPeers[spiffeID]
		if !ok {
			return IdentityContext{}, errors.New("SPIFFE peer denied")
		}
		if id.Authentication == "" {
			id.Authentication = "spiffe-svid-mtls"
		}
		if id.Session == "" {
			id.Session = NewID()
		}
		return id, nil
	}
	return ParseSVIDIdentity(cert)
}

// SVIDMiddleware enforces cryptographic identity (mTLS + short-lived SVID) on incoming requests.
func SVIDMiddleware(workload *Workload, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "mTLS required", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		if err := validateSVIDCert(cert, 10*time.Minute); err != nil {
			status := http.StatusUnauthorized
			if err.Error() == "SVID lifetime exceeds policy" {
				status = http.StatusForbidden
			}
			http.Error(w, err.Error(), status)
			return
		}
		if workload != nil && len(workload.Config.Peers) > 0 {
			spiffeID := cert.URIs[0].String()
			allowed := false
			for _, peer := range workload.Config.Peers {
				if peer == spiffeID {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "SPIFFE peer denied", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// WorkloadFromEnvironment enables identity enforcement only in the explicit
// SPIFFE deployment. A configured but unavailable identity source is fatal.
func WorkloadFromEnvironment() (*Workload, error) {
	path := os.Getenv("LOOM_WORKLOAD_CONFIG")
	if path == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	w, err := OpenWorkload(ctx, path)
	if err != nil {
		return nil, err
	}
	http.DefaultTransport = w
	return w, nil
}
func ServeWorkload(server *http.Server, w *Workload) error {
	if w == nil {
		return server.ListenAndServe()
	}
	server.TLSConfig = w.ServerTLS()
	return server.ListenAndServeTLS("", "")
}
