package security

import (
	"sync"
	"time"
)

// Circuit stops dispatch after repeated upstream failures. It is process-local;
// it cannot provide fleet-wide health or cancel work already dispatched.
type Circuit struct {
	Events   EventSink
	Resource string
	mu       sync.Mutex
	failures int
	until    time.Time
}

func (c *Circuit) resourceName() string {
	if c.Resource == "model" || c.Resource == "mcp" {
		return c.Resource
	}
	if c.Resource != "" {
		return sanitizeResourceKey(c.Resource)
	}
	return "model"
}

func (c *Circuit) Allow(now time.Time) bool { return c.AllowFor(ControlContext{}, now) }

func (c *Circuit) AllowFor(ctx ControlContext, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := c.resourceName()
	controlCtx := ensureContext(ctx)
	if now.Before(c.until) {
		if c.Events != nil {
			c.Events.Emit(ControlEvent{ID: NewID(), Kind: "circuit", Reason: "dispatch_blocked", Resource: res, Context: controlCtx, At: now})
		}
		return false
	}
	if !c.until.IsZero() {
		c.failures = 0
		c.until = time.Time{}
	}
	return true
}

func (c *Circuit) Complete(success bool, now time.Time) {
	c.CompleteFor(ControlContext{}, success, now)
}

func (c *Circuit) CompleteFor(ctx ControlContext, success bool, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if success {
		c.failures = 0
		return
	}
	c.failures++
	if c.failures >= 3 {
		if c.failures == 3 && c.Events != nil {
			res := c.resourceName()
			controlCtx := ensureContext(ctx)
			c.Events.Emit(ControlEvent{ID: NewID(), Kind: "circuit", Reason: "opened", Resource: res, Context: controlCtx, At: now})
		}
		c.until = now.Add(30 * time.Second)
	}
}
