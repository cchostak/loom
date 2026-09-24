package security

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"time"
)

type Rule struct {
	ID             string `json:"id"`
	Principal      string `json:"principal"`
	Workload       string `json:"workload"`
	Tenant         string `json:"tenant"`
	Scope          string `json:"scope"`
	Category       string `json:"category"`
	Tool           string `json:"tool"`
	Method         string `json:"method"`
	ResourcePrefix string `json:"resource_prefix"`
	Destination    string `json:"destination"`
	Trust          string `json:"trust"`
	Sensitivity    string `json:"sensitivity"`
	SideEffects    string `json:"side_effects"`
	Outcome        string `json:"outcome"`
}

type Policy struct {
	ID            string   `json:"id"`
	Version       string   `json:"version"`
	EmergencyDeny bool     `json:"emergency_deny"`
	Disabled      []string `json:"disabled"`
	Rules         []Rule   `json:"rules"`
}

// Decode rejects unknown fields, trailing data and null envelopes.
func Decode(data []byte, out any) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("null document")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// LoadPolicy rereads the mounted directory each request. Missing/bad files deny.
func LoadPolicy(file string) (Policy, error) {
	var p Policy
	b, err := os.ReadFile(file)
	if err != nil {
		return p, err
	}
	if len(b) > 1<<20 {
		return p, errors.New("policy too large")
	}
	if err = Decode(b, &p); err != nil {
		return p, err
	}
	if p.ID == "" || p.Version == "" {
		return p, errors.New("policy identity required")
	}
	for _, r := range p.Rules {
		if r.ID == "" || (r.Outcome != "allow" && r.Outcome != "require_approval") || r.Principal == "" || r.Workload == "" || r.Tenant == "" || r.Scope == "" || r.Destination == "" || r.ResourcePrefix == "" {
			return p, errors.New("invalid rule")
		}
	}
	return p, nil
}

// Evaluate is a default-deny exact-match policy with path-segment scope.
func (p Policy) Evaluate(a ActionRequest, now time.Time) PolicyDecision {
	d := PolicyDecision{ID: NewID(), PolicyID: p.ID, Version: p.Version, RuleID: "default-deny", Outcome: "deny", Reason: "no_matching_grant", Explanation: "No matching grant", Timestamp: now, Expires: now.Add(time.Minute), Obligations: []string{"audit_before_dispatch"}}
	if p.EmergencyDeny {
		d.Reason = "emergency_deny"
		return d
	}
	for _, value := range []string{a.Identity.Principal, a.Identity.Workload, a.Identity.Session, a.Tool, a.Destination} {
		if slices.Contains(p.Disabled, value) {
			d.Reason = "revoked"
			return d
		}
	}
	if a.Identity.Session == "" || a.Identity.Authentication == "" || a.Identity.DelegatedFrom != "" || a.Depth != 0 || a.DelegationDepth != 0 {
		d.Reason = "invalid_authority"
		return d
	}
	for _, r := range p.Rules {
		prefix := strings.TrimSuffix(r.ResourcePrefix, "/")
		if r.Principal == a.Identity.Principal && r.Workload == a.Identity.Workload && r.Tenant == a.Identity.Tenant && slices.Contains(a.Identity.Scopes, r.Scope) && r.Category == a.Category && r.Tool == a.Tool && r.Method == a.Method && (a.Resource == prefix || strings.HasPrefix(a.Resource, prefix+"/")) && r.Destination == a.Destination && r.Trust == a.Data.Trust && r.Sensitivity == a.Data.Sensitivity && r.SideEffects == a.SideEffects {
			d.RuleID = r.ID
			d.Outcome = r.Outcome
			d.Reason = "matched_grant"
			d.Explanation = "Matched scoped grant"
			return d
		}
	}
	return d
}

// WorkspacePath permits only canonical absolute workspace paths, never aliases.
func WorkspacePath(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\x00\\%") || path.Clean(value) != value || !(value == "/workspace" || strings.HasPrefix(value, "/workspace/")) {
		return "", errors.New("invalid workspace path")
	}
	return strings.TrimPrefix(strings.TrimPrefix(value, "/workspace"), "/"), nil
}
