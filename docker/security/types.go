// Package security defines Loom's trusted-boundary contracts.
package security

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

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
