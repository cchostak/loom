package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

type Limits struct {
	RequestsPerMinute, Calls, Concurrent, InputBytes, OutputTokens int
	Workflow                                                       time.Duration
}
type budgetState struct {
	Started, Window         time.Time
	Requests, Calls, Active int
}
type Budgets struct {
	mu     sync.Mutex
	states map[string]*budgetState
	Limits Limits
}

// Acquire counts all admitted operations against a server-issued session. State
// is bounded and never evicted to reset a session's exhausted lifetime budget.
func (b *Budgets) Acquire(key string, size, tokens int, now time.Time) (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.states == nil {
		b.states = map[string]*budgetState{}
	}
	s := b.states[key]
	if s == nil {
		if len(b.states) >= 1024 {
			return nil, errors.New("session capacity")
		}
		s = &budgetState{Started: now, Window: now}
		b.states[key] = s
	}
	if now.Sub(s.Window) >= time.Minute {
		s.Window = now
		s.Requests = 0
	}
	l := b.Limits
	if size > l.InputBytes || tokens < 0 || tokens > l.OutputTokens || now.Sub(s.Started) >= l.Workflow || s.Requests >= l.RequestsPerMinute || s.Calls >= l.Calls || s.Active >= l.Concurrent {
		return nil, errors.New("budget exceeded")
	}
	s.Requests++
	s.Calls++
	s.Active++
	var once sync.Once
	return func() { once.Do(func() { b.mu.Lock(); defer b.mu.Unlock(); s.Active-- }) }, nil
}

// BudgetLimiter permits a durable shared admission implementation.
type BudgetLimiter interface {
	Acquire(string, int, int, time.Time) (func(), error)
}

// BudgetKey binds admission to server-authenticated identity, not caller labels.
func BudgetKey(id IdentityContext) string {
	b, _ := json.Marshal([]string{id.Tenant, id.Principal, id.Workload, id.Session})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
