package enterprise

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"guardrail-proxy/security"
)

type testSink struct {
	events []security.ControlEvent
}

func (s *testSink) Emit(e security.ControlEvent) {
	s.events = append(s.events, e)
}

func otlpLogFromEvent(e security.ControlEvent) otlpLog {
	values := map[string]string{
		"loom.event_id":    e.ID,
		"loom.kind":        e.Kind,
		"loom.reason":      e.Reason,
		"loom.resource":    e.Resource,
		"loom.tenant":      e.Context.Tenant,
		"loom.workload":    e.Context.Workload,
		"loom.trace_id":    e.Context.TraceID,
		"loom.decision_id": e.Context.DecisionID,
	}
	var attrs []otlpAttribute
	for k, v := range values {
		if v != "" {
			attrs = append(attrs, otlpAttribute{Key: k, Value: otlpValue{String: v}})
		}
	}
	return otlpLog{
		Time:       strconv.FormatInt(e.At.UnixNano(), 10),
		Body:       otlpValue{String: "loom.security.control"},
		Attributes: attrs,
	}
}

func TestBudgetTelemetryEmitsAndNormalizes(t *testing.T) {
	sink := &testSink{}
	now := time.Now().UTC()
	b := &security.Budgets{
		Events: sink,
		Limits: security.Limits{
			Calls:             2,
			Concurrent:        2,
			InputBytes:        1000,
			OutputTokens:      500,
			RequestsPerMinute: 60,
			Workflow:          time.Hour,
		},
	}

	ctx := security.ControlContext{
		Tenant:     "enterprise-tenant",
		Workload:   "strands-researcher",
		Session:    "session-1",
		TraceID:    security.NewID(),
		DecisionID: security.NewID(),
	}

	// 1. Consume limit
	r1, err := b.AcquireFor(ctx, "session-key", 100, 50, now)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	r2, err := b.AcquireFor(ctx, "session-key", 100, 50, now)
	if err != nil {
		t.Fatalf("second acquire failed: %v", err)
	}
	_ = r1
	_ = r2

	// 2. Exceed calls limit -> triggers guardrail
	_, err = b.AcquireFor(ctx, "session-key", 100, 50, now)
	if err == nil {
		t.Fatal("expected budget exceeded error")
	}

	if len(sink.events) == 0 {
		t.Fatal("expected guardrail control event to be emitted")
	}
	event := sink.events[len(sink.events)-1]
	if event.Kind != "budget" || event.Reason != "admission_limit" {
		t.Fatalf("unexpected event: %+v", event)
	}

	// 3. Normalize into unified finding schema
	logRecord := otlpLogFromEvent(event)
	tenant, finding, err := Normalize(logRecord)
	if err != nil {
		t.Fatalf("Normalize failed: %v", err)
	}
	if tenant != "enterprise-tenant" {
		t.Fatalf("expected tenant 'enterprise-tenant', got %s", tenant)
	}
	if finding["finding_type"] != "policy_violation" {
		t.Fatalf("expected finding_type 'policy_violation', got %v", finding["finding_type"])
	}
	if finding["service_name"] != "loom" || finding["status"] != "new" {
		t.Fatalf("unexpected service_name/status: %+v", finding)
	}
	source := finding["source"].(map[string]any)
	if source["scanner"] != "loom" {
		t.Fatalf("expected source.scanner 'loom', got %v", source["scanner"])
	}
}

func TestCircuitTelemetryEmitsAndNormalizes(t *testing.T) {
	sink := &testSink{}
	now := time.Now().UTC()
	circuit := &security.Circuit{
		Events:   sink,
		Resource: "model",
	}

	ctx := security.ControlContext{
		Tenant:     "enterprise-tenant",
		Workload:   "strands-planner",
		Session:    "session-2",
		TraceID:    security.NewID(),
		DecisionID: security.NewID(),
	}

	// 3 failures trip the circuit
	circuit.CompleteFor(ctx, false, now)
	circuit.CompleteFor(ctx, false, now)
	circuit.CompleteFor(ctx, false, now)

	if len(sink.events) == 0 {
		t.Fatal("expected circuit opened event to be emitted")
	}
	openedEvent := sink.events[0]
	if openedEvent.Kind != "circuit" || openedEvent.Reason != "opened" {
		t.Fatalf("unexpected opened event: %+v", openedEvent)
	}

	// While open, dispatch is blocked
	if circuit.AllowFor(ctx, now) {
		t.Fatal("expected circuit to block dispatch")
	}
	blockedEvent := sink.events[1]
	if blockedEvent.Kind != "circuit" || blockedEvent.Reason != "dispatch_blocked" {
		t.Fatalf("unexpected blocked event: %+v", blockedEvent)
	}

	// Normalize circuit opened event
	logRecord := otlpLogFromEvent(openedEvent)
	_, finding, err := Normalize(logRecord)
	if err != nil {
		t.Fatalf("Normalize failed: %v", err)
	}
	if finding["finding_type"] != "posture_drift" {
		t.Fatalf("expected finding_type 'posture_drift', got %v", finding["finding_type"])
	}
	if finding["rule_id"] != "loom.circuit.opened" {
		t.Fatalf("expected rule_id 'loom.circuit.opened', got %v", finding["rule_id"])
	}
}

func TestNormalizerQueueIngestionAndAuditQuery(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "normalization.db")
	signingKey := make([]byte, 32)
	store, err := Open(dbPath, signingKey)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.DB.Close()

	ingestToken := "valid-ingest-token-with-minimum-32-chars-long"
	readToken := "valid-read-token-with-minimum-32-chars-long"
	normalizer := Normalizer{
		Store:       store,
		IngestToken: ingestToken,
		ReadToken:   readToken,
	}

	now := time.Now().UTC()
	event := security.ControlEvent{
		ID:       security.NewID(),
		Kind:     "budget",
		Reason:   "admission_limit",
		Resource: "model",
		Context: security.ControlContext{
			Tenant:     "compliance-tenant",
			Workload:   "strands-operator",
			TraceID:    security.NewID(),
			DecisionID: security.NewID(),
		},
		At: now,
	}

	otlpPayload := map[string]any{
		"resourceLogs": []any{
			map[string]any{
				"scopeLogs": []any{
					map[string]any{
						"logRecords": []any{
							otlpLogFromEvent(event),
						},
					},
				},
			},
		},
	}
	payloadBytes, _ := json.Marshal(otlpPayload)

	// Ingest via POST /v1/logs
	ingestReq := httptest.NewRequest("POST", "/v1/logs", bytes.NewReader(payloadBytes))
	ingestReq.Header.Set("Authorization", "Bearer "+ingestToken)
	ingestRec := httptest.NewRecorder()
	normalizer.ServeHTTP(ingestRec, ingestReq)

	if ingestRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from normalizer ingest, got %d: %s", ingestRec.Code, ingestRec.Body.String())
	}

	// Query via GET /findings
	queryReq := httptest.NewRequest("GET", "/findings", nil)
	queryReq.Header.Set("Authorization", "Bearer "+readToken)
	queryRec := httptest.NewRecorder()
	normalizer.ServeHTTP(queryRec, queryReq)

	if queryRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from findings query, got %d: %s", queryRec.Code, queryRec.Body.String())
	}

	var findings []map[string]any
	if err := json.Unmarshal(queryRec.Body.Bytes(), &findings); err != nil {
		t.Fatalf("failed to decode findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0]["tenant"] != "compliance-tenant" {
		t.Fatalf("unexpected tenant: %v", findings[0]["tenant"])
	}
}
