package security

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// ControlContext contains correlation only; never prompts, arguments or credentials.
type ControlContext struct{ Tenant, Workload, Session, TraceID, DecisionID string }
type ControlEvent struct {
	ID, Kind, Reason, Resource string
	Context                    ControlContext
	At                         time.Time
}
type EventSink interface{ Emit(ControlEvent) }

// OTLPEvents is a bounded asynchronous OTLP/HTTP log exporter. Enforcement never
// waits for telemetry. Durable authoritative audit is a separate control.
type OTLPEvents struct {
 token string
	endpoint string
	client   *http.Client
	queue    chan ControlEvent
	Dropped  atomic.Uint64
}

func NewOTLPEvents(ctx context.Context, endpoint, token string, client *http.Client) *OTLPEvents {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	e := &OTLPEvents{endpoint: endpoint, token: token, client: client, queue: make(chan ControlEvent, 256)}
	go e.run(ctx)
	return e
}
func (e *OTLPEvents) Emit(event ControlEvent) {
	if event.ID == "" {
		event.ID = NewID()
	}
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	select {
	case e.queue <- event:
	default:
		e.Dropped.Add(1)
	}
}
func (e *OTLPEvents) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-e.queue:
			body, _ := json.Marshal(event.OTLP())
			sent := false
			for attempt := 0; attempt < 3; attempt++ {
				req, err := http.NewRequestWithContext(ctx, "POST", e.endpoint, bytes.NewReader(body))
				if err != nil {
					break
				}
				req.Header.Set("Content-Type", "application/json")
 if e.token!="" {req.Header.Set("Authorization","Bearer "+e.token)}
				res, err := e.client.Do(req)
				if err == nil {
					res.Body.Close()
					if res.StatusCode == 200 {
						sent = true
						break
					}
				}
				timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
			if !sent {
				e.Dropped.Add(1)
			}
		}
	}
}
func (e ControlEvent) OTLP() map[string]any {
	attrs := []any{}
	values := map[string]string{"loom.event_id": e.ID, "loom.kind": e.Kind, "loom.reason": e.Reason, "loom.resource": e.Resource, "loom.tenant": e.Context.Tenant, "loom.workload": e.Context.Workload, "loom.trace_id": e.Context.TraceID, "loom.decision_id": e.Context.DecisionID}
	for key, value := range values {
		if value != "" {
			attrs = append(attrs, map[string]any{"key": key, "value": map[string]string{"stringValue": value}})
		}
	}
	record := map[string]any{"timeUnixNano": strconv.FormatInt(e.At.UnixNano(), 10), "severityNumber": 13, "severityText": "WARN", "body": map[string]string{"stringValue": "loom.security.control"}, "attributes": attrs}
	return map[string]any{"resourceLogs": []any{map[string]any{"resource": map[string]any{"attributes": []any{map[string]any{"key": "service.name", "value": map[string]string{"stringValue": "loom-control-plane"}}}}, "scopeLogs": []any{map[string]any{"scope": map[string]string{"name": "loom.security", "version": "1"}, "logRecords": []any{record}}}}}}
}
