// Package swarm provides a deterministic adversarial-agent security lab.
package swarm

// Phase identifies which side of an LLM exchange is being inspected.
type Phase string

const (
	PhaseRequest  Phase = "request"
	PhaseResponse Phase = "response"
)

// Step is one handoff or tool action in an adversarial swarm scenario.
type Step struct {
	Agent                string `json:"agent"`
	TargetAgent          string `json:"target_agent,omitempty"`
	Content              string `json:"content"`
	Tool                 string `json:"tool,omitempty"`
	Trust                string `json:"trust"`
	Phase                Phase  `json:"phase"`
	CrossesTrustBoundary bool   `json:"crosses_trust_boundary,omitempty"`
}

// Scenario describes a reproducible attack chain.
type Scenario struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Steps       []Step `json:"steps"`
}

// Event records the decision made for a scenario step.
type Event struct {
	Agent   string `json:"agent"`
	Action  string `json:"action"`
	Blocked bool   `json:"blocked"`
	Control string `json:"control,omitempty"`
	Reason  string `json:"reason"`
}

// Result is the outcome of one scenario in one security mode.
type Result struct {
	Mode        string  `json:"mode"`
	Scenario    string  `json:"scenario"`
	Compromised bool    `json:"compromised"`
	Events      []Event `json:"events"`
}

// Report compares an unprotected baseline with the defended Loom stack.
type Report struct {
	Baseline             []Result `json:"baseline"`
	Defended             []Result `json:"defended"`
	BaselineCompromises  int      `json:"baseline_compromises"`
	DefendedCompromises  int      `json:"defended_compromises"`
	BlockedAttackPercent int      `json:"blocked_attack_percent"`
}
