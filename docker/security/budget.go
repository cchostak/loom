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
	Events EventSink
	mu     sync.Mutex
	states map[string]*budgetState
	Limits Limits
}

func sanitizeResourceKey(key string) string {
	if key == "model" || key == "mcp" || (len(key) == 64 && isHexString(key)) {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func ensureContext(c ControlContext) ControlContext {
	if c.Tenant == "" {
		c.Tenant = "default"
	}
	if c.Workload == "" {
		c.Workload = "agent"
	}
	if c.TraceID == "" {
		c.TraceID = NewID()
	}
	if c.DecisionID == "" {
		c.DecisionID = NewID()
	}
	return c
}

// Acquire counts all admitted operations against a server-issued session. State
// is bounded and never evicted to reset a session's exhausted lifetime budget.
func (b *Budgets) Acquire(key string, size, tokens int, now time.Time) (func(), error) {
	return b.AcquireFor(ControlContext{}, key, size, tokens, now)
}

// AcquireFor emits a structured OpenTelemetry event and content-free denial when limits are exceeded.
func (b *Budgets) AcquireFor(c ControlContext, key string, size, tokens int, now time.Time) (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	resKey := sanitizeResourceKey(key)
	ctx := ensureContext(c)
	if b.states == nil {
		b.states = map[string]*budgetState{}
	}
	s := b.states[key]
	if s == nil {
		if len(b.states) >= 1024 {
			if b.Events != nil {
				b.Events.Emit(ControlEvent{ID: NewID(), Kind: "budget", Reason: "session_capacity", Resource: resKey, Context: ctx, At: now})
			}
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
		if b.Events != nil {
			b.Events.Emit(ControlEvent{ID: NewID(), Kind: "budget", Reason: "admission_limit", Resource: resKey, Context: ctx, At: now})
		}
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

// ContextBudgetLimiter carries trusted correlation to admission events.
type ContextBudgetLimiter interface {
	AcquireFor(ControlContext, string, int, int, time.Time) (func(), error)
}
