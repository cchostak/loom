package security

import (
	"sync"
	"time"
)

// Circuit stops dispatch after repeated upstream failures. It is process-local;
// it cannot provide fleet-wide health or cancel work already dispatched.
type Circuit struct {
	mu       sync.Mutex
	failures int
	until    time.Time
}

func (c *Circuit) Allow(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Before(c.until) {
		return false
	}
	if !c.until.IsZero() {
		c.failures = 0
		c.until = time.Time{}
	}
	return true
}

func (c *Circuit) Complete(success bool, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if success {
		c.failures = 0
		return
	}
	c.failures++
	if c.failures >= 3 {
		c.until = now.Add(30 * time.Second)
	}
}
