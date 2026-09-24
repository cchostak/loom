package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

type Approval struct {
	ID, ActionHash, DecisionID, PolicyVersion, Signature string
	Expires                                              time.Time
}
type Approvals struct {
	Key  []byte
	mu   sync.Mutex
	used map[string]bool
}

// Issue is a backend contract for a future authenticated operator service.
// No HTTP issuance endpoint or privileged executor is enabled in local Loom.
func (a *Approvals) Issue(action ActionRequest, d PolicyDecision, expires time.Time) (Approval, error) {
	if len(a.Key) < 32 || d.Outcome != "require_approval" || !expires.After(d.Timestamp) || expires.After(d.Expires) {
		return Approval{}, errors.New("invalid approval")
	}
	b, err := json.Marshal(action)
	if err != nil {
		return Approval{}, err
	}
	digest := sha256.Sum256(b)
	p := Approval{ID: NewID(), ActionHash: hex.EncodeToString(digest[:]), DecisionID: d.ID, PolicyVersion: d.Version, Expires: expires}
	p.Signature = a.sign(p)
	return p, nil
}
func (a *Approvals) sign(p Approval) string {
	p.Signature = ""
	b, _ := json.Marshal(p)
	mac := hmac.New(sha256.New, a.Key)
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil))
}

// Consume verifies binding, expiry and one-time use. Reauthorize first.
func (a *Approvals) Consume(p Approval, action ActionRequest, d PolicyDecision, now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := json.Marshal(action)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(b)
	if len(a.Key) < 32 || d.Outcome != "require_approval" || !now.Before(p.Expires) || !now.Before(d.Expires) || p.DecisionID != d.ID || p.PolicyVersion != d.Version || p.ActionHash != hex.EncodeToString(digest[:]) || !hmac.Equal([]byte(p.Signature), []byte(a.sign(p))) || a.used[p.ID] {
		return errors.New("approval invalid")
	}
	if a.used == nil {
		a.used = map[string]bool{}
	}
	if len(a.used) >= 10000 {
		return errors.New("approval capacity")
	}
	a.used[p.ID] = true
	return nil
}
