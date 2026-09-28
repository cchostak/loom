// Package security defines Loom's trusted-boundary contracts.
package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Authenticator validates incoming requests and extracts identity context.
type Authenticator interface {
	Authenticate(*http.Request) (IdentityContext, error)
}

// GatewayAuth authenticates requests arriving through AgentGateway with edge-verified identity.
type GatewayAuth struct {
	Audience string
}

func (g GatewayAuth) Authenticate(r *http.Request) (IdentityContext, error) {
	auth := r.Header.Get("Authorization")
	principal := r.Header.Get("X-Principal")
	if auth == "" && principal == "" {
		return IdentityContext{}, errors.New("authentication required")
	}
	if principal == "" {
		principal = "gateway-authenticated-user"
	}
	workload := r.Header.Get("X-Workload")
	if workload == "" {
		workload = "gateway-workload"
	}
	tenant := r.Header.Get("X-Tenant")
	if tenant == "" {
		tenant = "default"
	}
	session := r.Header.Get("X-Session")
	if session == "" {
		session = "gateway-session"
	}
	return IdentityContext{
		Principal:      principal,
		Workload:       workload,
		Tenant:         tenant,
		Session:        session,
		Authentication: "agentgateway-edge-verified",
		Scopes:         []string{"workspace:read", "model:invoke"},
	}, nil
}

// BudgetLimiter permits a durable shared admission implementation.
type BudgetLimiter interface {
	Acquire(string, int, int, time.Time) (func(), error)
}

// ContextBudgetLimiter carries trusted correlation to admission events.
type ContextBudgetLimiter interface {
	AcquireFor(ControlContext, string, int, int, time.Time) (func(), error)
}

// BudgetKey binds admission to server-authenticated identity, not caller labels.
func BudgetKey(id IdentityContext) string {
	b, _ := json.Marshal([]string{id.Tenant, id.Principal, id.Workload, id.Session})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type IdentityContext struct {
	Principal      string   `json:"principal"`
	Workload       string   `json:"workload"`
	Tenant         string   `json:"tenant"`
	Session        string   `json:"session"`
	Authentication string   `json:"authentication"`
	DelegatedFrom  string   `json:"delegated_from,omitempty"`
	Scopes         []string `json:"scopes"`
}

type DataContext struct {
	Source      string   `json:"source"`
	Producer    string   `json:"producer"`
	Trust       string   `json:"trust"`
	Sensitivity string   `json:"sensitivity"`
	Origin      string   `json:"origin"`
	Tainted     bool     `json:"tainted"`
	Integrity   string   `json:"integrity,omitempty"`
	Parents     []string `json:"parents,omitempty"`
}

// Derived preserves taint and classification; transformation is not endorsement.
func (d DataContext) Derived(producer string) DataContext {
	d.Parents = append(append([]string{}, d.Parents...), d.Source)
	d.Producer = producer
	d.Origin = "derived"
	d.Integrity = ""
	return d
}

type ActionRequest struct {
	Identity        IdentityContext `json:"identity"`
	Category        string          `json:"category"`
	Tool            string          `json:"tool"`
	Method          string          `json:"method"`
	Arguments       json.RawMessage `json:"arguments"`
	Resource        string          `json:"resource"`
	Destination     string          `json:"destination"`
	SideEffects     string          `json:"side_effects"`
	Risk            string          `json:"risk"`
	Data            DataContext     `json:"data"`
	Depth           int             `json:"depth"`
	DelegationDepth int             `json:"delegation_depth"`
}

type PolicyDecision struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id"`
	Version     string    `json:"version"`
	RuleID      string    `json:"rule_id"`
	Outcome     string    `json:"outcome"`
	Reason      string    `json:"reason"`
	Explanation string    `json:"explanation"`
	Obligations []string  `json:"obligations"`
	Timestamp   time.Time `json:"timestamp"`
	Expires     time.Time `json:"expires"`
}

// NewID creates a correlation identifier independent of caller-controlled input.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure randomness unavailable")
	}
	return hex.EncodeToString(b[:])
}
