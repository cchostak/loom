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
	now := time.Now().UTC()
	ctx := security.ControlContext{
		Tenant:     "enterprise-tenant",
		Workload:   "strands-researcher",
		Session:    "session-1",
		TraceID:    security.NewID(),
		DecisionID: security.NewID(),
	}

	event := security.ControlEvent{
		ID:       security.NewID(),
		Kind:     "budget",
		Reason:   "admission_limit",
		Resource: "model",
		Context:  ctx,
		At:       now,
	}

	// Normalize into unified finding schema
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
	now := time.Now().UTC()
	ctx := security.ControlContext{
		Tenant:     "enterprise-tenant",
		Workload:   "strands-planner",
		Session:    "session-2",
		TraceID:    security.NewID(),
		DecisionID: security.NewID(),
	}

	openedEvent := security.ControlEvent{
		ID:       security.NewID(),
		Kind:     "circuit",
		Reason:   "opened",
		Resource: "model",
		Context:  ctx,
		At:       now,
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

func TestNormalizerSpanIngestionAndSPIFFEIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "normalization_spans.db")
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

	span := otlpSpan{
		TraceID:           "0123456789abcdef0123456789abcdef",
		SpanID:            "fedcba9876543210",
		Name:              "loom.operation",
		StartTimeUnixNano: strconv.FormatInt(time.Now().UnixNano(), 10),
		Attributes: []otlpSpanAttribute{
			{Key: "gen_ai.request.model", Value: map[string]any{"stringValue": "openai/gpt-4o-mini"}},
			{Key: "gen_ai.usage.input_tokens", Value: map[string]any{"intValue": 150}},
			{Key: "gen_ai.usage.output_tokens", Value: map[string]any{"intValue": 42}},
			{Key: "gen_ai.usage.cost", Value: map[string]any{"doubleValue": 0.00035}},
			{Key: "loom.workload", Value: map[string]any{"stringValue": "strands-researcher"}},
			{Key: "loom.tenant", Value: map[string]any{"stringValue": "spiffe-tenant"}},
		},
	}

	// 1. Direct NormalizeSpan validation
	tenant, finding, err := NormalizeSpan(span)
	if err != nil {
		t.Fatalf("NormalizeSpan failed: %v", err)
	}
	if tenant != "spiffe-tenant" {
		t.Fatalf("expected tenant 'spiffe-tenant', got %s", tenant)
	}
	affectedResource := finding["affected_resource"].(map[string]any)
	expectedSPIFFE := "spiffe://loom.local/workload/strands-researcher"
	if affectedResource["spiffe_id"] != expectedSPIFFE {
		t.Fatalf("expected spiffe_id %s, got %v", expectedSPIFFE, affectedResource["spiffe_id"])
	}
	source := finding["source"].(map[string]any)
	if source["scanner"] != "agentgateway" {
		t.Fatalf("expected scanner 'agentgateway', got %v", source["scanner"])
	}

	// 2. HTTP Ingestion via POST /v1/traces
	tracesPayload := map[string]any{
		"resourceSpans": []any{
			map[string]any{
				"scopeSpans": []any{
					map[string]any{
						"spans": []any{span},
					},
				},
			},
		},
	}
	payloadBytes, _ := json.Marshal(tracesPayload)

	ingestReq := httptest.NewRequest("POST", "/v1/traces", bytes.NewReader(payloadBytes))
	ingestReq.Header.Set("Authorization", "Bearer "+ingestToken)
	ingestRec := httptest.NewRecorder()
	normalizer.ServeHTTP(ingestRec, ingestReq)

	if ingestRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /v1/traces ingest, got %d: %s", ingestRec.Code, ingestRec.Body.String())
	}

	// 3. Query via GET /findings
	queryReq := httptest.NewRequest("GET", "/findings", nil)
	queryReq.Header.Set("Authorization", "Bearer "+readToken)
	queryRec := httptest.NewRecorder()
	normalizer.ServeHTTP(queryRec, queryReq)

	if queryRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /findings, got %d: %s", queryRec.Code, queryRec.Body.String())
	}

	var findings []map[string]any
	if err := json.Unmarshal(queryRec.Body.Bytes(), &findings); err != nil {
		t.Fatalf("failed to decode findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	fMap := findings[0]["finding"].(map[string]any)
	ar := fMap["affected_resource"].(map[string]any)
	if ar["spiffe_id"] != expectedSPIFFE {
		t.Fatalf("persisted finding expected spiffe_id %s, got %v", expectedSPIFFE, ar["spiffe_id"])
	}
}
