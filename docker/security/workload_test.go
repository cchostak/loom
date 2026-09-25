package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func makeTestCert(spiffeURI string, notBefore, notAfter time.Time) *x509.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	parsedURI, _ := url.Parse(spiffeURI)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-workload"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		URIs:         []*url.URL{parsedURI},
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

type mockAuth struct {
	id  IdentityContext
	err error
}

func (m mockAuth) Authenticate(*http.Request) (IdentityContext, error) {
	return m.id, m.err
}

func TestWorkloadAuthDirectSVID(t *testing.T) {
	now := time.Now()
	cert := makeTestCert("spiffe://loom.local/workload/strands-researcher", now.Add(-time.Minute), now.Add(4*time.Minute))
	auth := WorkloadAuth{
		Bindings: map[string][]string{
			"spiffe://loom.local/workload/strands-researcher": {"strands-researcher"},
		},
	}

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	id, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("expected direct SVID authentication to succeed, got %v", err)
	}
	if id.Workload != "strands-researcher" || id.Authentication != "spiffe-svid-mtls" {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestWorkloadAuthTokenBound(t *testing.T) {
	now := time.Now()
	cert := makeTestCert("spiffe://loom.local/workload/strands-planner", now.Add(-time.Minute), now.Add(4*time.Minute))
	auth := WorkloadAuth{
		Auth: mockAuth{id: IdentityContext{Workload: "strands-planner", Principal: "planner"}},
		Bindings: map[string][]string{
			"spiffe://loom.local/workload/strands-planner": {"strands-planner"},
		},
	}

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	req.Header.Set("Authorization", "Bearer valid-token")

	id, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("expected bound authentication to succeed, got %v", err)
	}
	if id.Workload != "strands-planner" {
		t.Fatalf("unexpected workload: %s", id.Workload)
	}
}

func TestWorkloadAuthRejections(t *testing.T) {
	now := time.Now()

	// 1. Missing mTLS
	reqNoTLS := httptest.NewRequest("GET", "/mcp", nil)
	auth := WorkloadAuth{}
	if _, err := auth.Authenticate(reqNoTLS); err == nil || err.Error() != "mTLS required" {
		t.Fatalf("expected 'mTLS required', got %v", err)
	}

	// 2. Missing SVID
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	noSVIDTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(5 * time.Minute),
	}
	der, _ := x509.CreateCertificate(rand.Reader, noSVIDTemplate, noSVIDTemplate, &key.PublicKey, key)
	noSVIDCert, _ := x509.ParseCertificate(der)

	reqNoSVID := httptest.NewRequest("GET", "/mcp", nil)
	reqNoSVID.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{noSVIDCert}}
	if _, err := auth.Authenticate(reqNoSVID); err == nil || err.Error() != "SVID required" {
		t.Fatalf("expected 'SVID required', got %v", err)
	}

	// 3. Lifetime exceeds policy (> 10m)
	longCert := makeTestCert("spiffe://loom.local/workload/rogue", now.Add(-time.Minute), now.Add(2*time.Hour))
	reqLong := httptest.NewRequest("GET", "/mcp", nil)
	reqLong.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{longCert}}
	if _, err := auth.Authenticate(reqLong); err == nil || err.Error() != "SVID lifetime exceeds policy" {
		t.Fatalf("expected 'SVID lifetime exceeds policy', got %v", err)
	}

	// 4. Expired SVID
	expiredCert := makeTestCert("spiffe://loom.local/workload/old", now.Add(-20*time.Minute), now.Add(-15*time.Minute))
	reqExpired := httptest.NewRequest("GET", "/mcp", nil)
	reqExpired.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{expiredCert}}
	if _, err := auth.Authenticate(reqExpired); err == nil || err.Error() != "SVID expired" {
		t.Fatalf("expected 'SVID expired', got %v", err)
	}

	// 5. Mismatched binding
	certPlanner := makeTestCert("spiffe://loom.local/workload/strands-planner", now.Add(-time.Minute), now.Add(4*time.Minute))
	authMismatch := WorkloadAuth{
		Auth: mockAuth{id: IdentityContext{Workload: "strands-operator"}},
		Bindings: map[string][]string{
			"spiffe://loom.local/workload/strands-planner": {"strands-planner"},
		},
	}
	reqMismatch := httptest.NewRequest("GET", "/mcp", nil)
	reqMismatch.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certPlanner}}
	reqMismatch.Header.Set("Authorization", "Bearer valid-token")
	if _, err := authMismatch.Authenticate(reqMismatch); err == nil || err.Error() != "credential and workload identity mismatch" {
		t.Fatalf("expected 'credential and workload identity mismatch', got %v", err)
	}
}

func TestSVIDAuthenticator(t *testing.T) {
	now := time.Now()
	cert := makeTestCert("spiffe://loom.local/workload/strands-operator", now.Add(-time.Minute), now.Add(5*time.Minute))
	auth := SVIDAuthenticator{
		AllowedPeers: map[string]IdentityContext{
			"spiffe://loom.local/workload/strands-operator": {
				Principal: "strands-operator",
				Workload:  "strands-operator",
				Tenant:    "loom.local",
			},
		},
	}

	req := httptest.NewRequest("POST", "/validate", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	id, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("SVIDAuthenticator failed: %v", err)
	}
	if id.Workload != "strands-operator" || id.Authentication != "spiffe-svid-mtls" {
		t.Fatalf("unexpected id: %+v", id)
	}

	// Denied peer
	unauthorizedCert := makeTestCert("spiffe://loom.local/workload/unauthorized", now.Add(-time.Minute), now.Add(5*time.Minute))
	reqBad := httptest.NewRequest("POST", "/validate", nil)
	reqBad.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{unauthorizedCert}}
	if _, err := auth.Authenticate(reqBad); err == nil || err.Error() != "SPIFFE peer denied" {
		t.Fatalf("expected 'SPIFFE peer denied', got %v", err)
	}
}

func TestSVIDMiddleware(t *testing.T) {
	now := time.Now()
	cert := makeTestCert("spiffe://loom.local/workload/control-plane", now.Add(-time.Minute), now.Add(5*time.Minute))
	workload := &Workload{
		Config: WorkloadConfig{
			Peers: []string{"spiffe://loom.local/workload/control-plane"},
		},
	}

	passed := false
	handler := SVIDMiddleware(workload, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passed = true
		w.WriteHeader(200)
	}))

	// Health endpoint bypasses mTLS
	rec := httptest.NewRecorder()
	reqHealth := httptest.NewRequest("GET", "/health", nil)
	handler.ServeHTTP(rec, reqHealth)
	if rec.Code != 200 || !passed {
		t.Fatalf("health check should pass, got code=%d", rec.Code)
	}

	// Valid mTLS call
	passed = false
	rec = httptest.NewRecorder()
	reqValid := httptest.NewRequest("POST", "/validate", nil)
	reqValid.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	handler.ServeHTTP(rec, reqValid)
	if rec.Code != 200 || !passed {
		t.Fatalf("valid mTLS call should pass, got code=%d", rec.Code)
	}

	// No mTLS
	rec = httptest.NewRecorder()
	reqNoTLS := httptest.NewRequest("POST", "/validate", nil)
	handler.ServeHTTP(rec, reqNoTLS)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing TLS should be 401, got %d", rec.Code)
	}
}
