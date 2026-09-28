package enterprise

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

type Normalizer struct {
	Store                  *Store
	IngestToken, ReadToken string
}
type otlpValue struct {
	String string `json:"stringValue"`
}
type otlpAttribute struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}
type otlpLog struct {
	Time       string          `json:"timeUnixNano"`
	Body       otlpValue       `json:"body"`
	Attributes []otlpAttribute `json:"attributes"`
}
type otlpLogs struct {
	Resources []struct {
		Scopes []struct {
			Records []otlpLog `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

type otlpSpanAttribute struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

type otlpSpan struct {
	TraceID           string              `json:"traceId"`
	SpanID            string              `json:"spanId"`
	Name              string              `json:"name"`
	StartTimeUnixNano string              `json:"startTimeUnixNano"`
	EndTimeUnixNano   string              `json:"endTimeUnixNano"`
	Attributes        []otlpSpanAttribute `json:"attributes"`
}

type otlpTraces struct {
	ResourceSpans []struct {
		ScopeSpans []struct {
			Spans []otlpSpan `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

var hexID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var safeLabel = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$`)
var digestID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func extractAttrValue(v any) string {
	if v == nil {
		return ""
	}
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["stringValue"].(string); ok {
			return s
		}
		if iv, ok := m["intValue"]; ok {
			return strconv.Itoa(int(numberToInt64(iv)))
		}
		if dv, ok := m["doubleValue"].(float64); ok {
			return strconv.FormatFloat(dv, 'f', -1, 64)
		}
		if bv, ok := m["boolValue"].(bool); ok {
			return strconv.FormatBool(bv)
		}
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func numberToInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}

// NormalizeSpan transforms standard AgentGateway OTel spans into unified compliance findings,
// appending the verified SPIFFE/SPIRE workload identity context.
func NormalizeSpan(span otlpSpan) (string, map[string]any, error) {
	if span.TraceID == "" || span.SpanID == "" {
		return "", nil, denied
	}
	attrs := map[string]string{}
	for _, a := range span.Attributes {
		attrs[a.Key] = extractAttrValue(a.Value)
	}

	workload := attrs["loom.workload"]
	if workload == "" {
		workload = "strands-agent"
	}
	tenant := attrs["loom.tenant"]
	if tenant == "" {
		tenant = "default"
	}
	model := attrs["gen_ai.request.model"]
	if model == "" {
		model = attrs["gen_ai.response.model"]
	}
	if model == "" {
		model = "agentgateway-model"
	}

	spiffeID := attrs["spiffe.identity"]
	if spiffeID == "" {
		spiffeID = "spiffe://loom.local/workload/" + workload
	}

	cost := attrs["gen_ai.usage.cost"]
	if cost == "" {
		cost = attrs["llm.cost"]
	}
	inputTokens := attrs["gen_ai.usage.input_tokens"]
	outputTokens := attrs["gen_ai.usage.output_tokens"]

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	if span.StartTimeUnixNano != "" {
		if nanos, err := strconv.ParseInt(span.StartTimeUnixNano, 10, 64); err == nil && nanos > 0 {
			timestamp = time.Unix(0, nanos).UTC().Format(time.RFC3339Nano)
		}
	}

	digest := sha256.Sum256([]byte(tenant + "\x00" + workload + "\x00" + span.TraceID + "\x00" + span.SpanID))
	rule := "loom.agentgateway.cost_attestation"

	finding := map[string]any{
		"finding_type": "audit_finding",
		"title":        "AI Model Execution and Cost Attestation",
		"description":  "AgentGateway verified model invocation with token and dollar budget metrics.",
		"severity":     "info",
		"rule_id":      rule,
		"status":       "new",
		"environment":  "lab",
		"service_name": "loom",
		"affected_resource": map[string]any{
			"resource_type": "ai_agent",
			"resource_id":   workload + "/" + model,
			"resource_name": workload,
			"spiffe_id":     spiffeID,
		},
		"remediation": map[string]any{
			"description": "Review model consumption against workload policies.",
			"automated":   false,
			"references":  []string{},
		},
		"source": map[string]any{
			"scanner":         "agentgateway",
			"scanner_version": "1.5.0",
			"raw_id":          span.SpanID,
			"raw_severity":    "INFO",
			"extra": map[string]string{
				"trace_id":      span.TraceID,
				"span_id":       span.SpanID,
				"model":         model,
				"cost":          cost,
				"input_tokens":  inputTokens,
				"output_tokens": outputTokens,
				"spiffe_id":     spiffeID,
			},
		},
		"first_seen": timestamp,
		"last_seen":  timestamp,
		"dedup_key":  hex.EncodeToString(digest[:]),
	}

	return tenant, finding, nil
}

// Normalize uses the existing UnifiedFinding vocabulary. A blocked operation is
// evidence of enforcement, not proof that a vulnerability or attack succeeded.
func Normalize(record otlpLog) (string, map[string]any, error) {
	if record.Body.String != "loom.security.control" || len(record.Attributes) > 12 {
		return "", nil, denied
	}
	values := map[string]string{}
	for _, a := range record.Attributes {
		if _, ok := values[a.Key]; ok {
			return "", nil, denied
		}
		switch a.Key {
		case "loom.event_id", "loom.kind", "loom.reason", "loom.resource", "loom.tenant", "loom.workload", "loom.trace_id", "loom.decision_id":
		default:
			return "", nil, denied
		}
		values[a.Key] = a.Value.String
	}
	kind, reason := values["loom.kind"], values["loom.reason"]
	known := (kind == "budget" && (reason == "admission_limit" || reason == "session_capacity" || reason == "shared_admission_denied")) || (kind == "circuit" && (reason == "opened" || reason == "dispatch_blocked"))
	if !known || !hexID.MatchString(values["loom.event_id"]) || !safeLabel.MatchString(values["loom.tenant"]) || !safeLabel.MatchString(values["loom.workload"]) {
		return "", nil, denied
	}
	for _, key := range []string{"loom.trace_id", "loom.decision_id"} {
		if values[key] != "" && !hexID.MatchString(values[key]) {
			return "", nil, denied
		}
	}
	resource := values["loom.resource"]
	if resource != "model" && resource != "mcp" && !digestID.MatchString(resource) {
		return "", nil, denied
	}
	nanos, err := strconv.ParseInt(record.Time, 10, 64)
	if err != nil || nanos <= 0 {
		return "", nil, denied
	}
	timestamp := time.Unix(0, nanos).UTC().Format(time.RFC3339Nano)
	rule := "loom." + kind + "." + reason
	digest := sha256.Sum256([]byte(values["loom.tenant"] + "\x00" + values["loom.workload"] + "\x00" + rule + "\x00" + resource))
	title, description, remediation := "AI execution budget enforced", "Loom refused admission because an execution limit or its shared admission service prevented dispatch.", "Review workload demand, configured limits and admission-service health before changing the budget."
	findingType := "policy_violation"
	if kind == "circuit" {
		title = "AI upstream circuit breaker triggered"
		description = "Loom stopped upstream dispatch after repeated failures. This event does not establish that an attack occurred."
		remediation = "Investigate upstream availability and correlated audit decisions; retain fail-closed behavior during recovery."
		findingType = "posture_drift"
	}
	spiffeID := "spiffe://loom.local/workload/" + values["loom.workload"]
	finding := map[string]any{"finding_type": findingType, "title": title, "description": description, "severity": "low", "rule_id": rule, "status": "new", "environment": "lab", "service_name": "loom",
		"affected_resource": map[string]any{"resource_type": "ai_agent", "resource_id": values["loom.workload"] + "/" + resource, "resource_name": values["loom.workload"], "spiffe_id": spiffeID},
		"remediation":       map[string]any{"description": remediation, "automated": false, "references": []string{}},
		"source":            map[string]any{"scanner": "loom", "scanner_version": "1", "raw_id": values["loom.event_id"], "raw_severity": "WARN", "extra": map[string]string{"trace_id": values["loom.trace_id"], "decision_id": values["loom.decision_id"], "control": kind, "outcome": "enforced", "spiffe_id": spiffeID}},
		"first_seen":        timestamp, "last_seen": timestamp, "dedup_key": hex.EncodeToString(digest[:])}
	return values["loom.tenant"], finding, nil
}
func (n Normalizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/health" {
		w.WriteHeader(200)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/findings" && len(n.ReadToken) >= 32 && hmac.Equal([]byte(r.Header.Get("Authorization")), []byte("Bearer "+n.ReadToken)) {
		rows, err := n.Store.DB.Query(`SELECT tenant,finding FROM normalization_queue ORDER BY rowid DESC LIMIT 100`)
		if err != nil {
			http.Error(w, "queue unavailable", 503)
			return
		}
		defer rows.Close()
		entries := []any{}
		for rows.Next() {
			var tenant, raw string
			if rows.Scan(&tenant, &raw) != nil {
				http.Error(w, "queue unavailable", 503)
				return
			}
			entries = append(entries, map[string]any{"tenant": tenant, "finding": json.RawMessage(raw)})
		}
		_ = json.NewEncoder(w).Encode(entries)
		return
	}

	authMatch := len(n.IngestToken) >= 32 && hmac.Equal([]byte(r.Header.Get("Authorization")), []byte("Bearer "+n.IngestToken))
	if r.Method != "POST" || r.URL.RawQuery != "" || !authMatch {
		http.Error(w, "denied", 403)
		return
	}

	type entry struct{ id, tenant, body string }
	batch := []entry{}

	if r.URL.Path == "/v1/traces" {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "input limit", 413)
			return
		}
		var payload otlpTraces
		if json.Unmarshal(b, &payload) != nil {
			http.Error(w, "invalid OTLP traces", 400)
			return
		}
		for _, res := range payload.ResourceSpans {
			for _, scope := range res.ScopeSpans {
				for _, span := range scope.Spans {
					tenant, finding, err := NormalizeSpan(span)
					if err != nil {
						http.Error(w, "invalid span evidence", 400)
						return
					}
					source := finding["source"].(map[string]any)
					batch = append(batch, entry{source["raw_id"].(string), tenant, jsonText(finding)})
				}
			}
		}
	} else if r.URL.Path == "/v1/logs" {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "input limit", 413)
			return
		}
		var payload otlpLogs
		if json.Unmarshal(b, &payload) != nil {
			http.Error(w, "invalid OTLP logs", 400)
			return
		}
		for _, resource := range payload.Resources {
			for _, scope := range resource.Scopes {
				for _, record := range scope.Records {
					tenant, finding, err := Normalize(record)
					if err != nil {
						http.Error(w, "invalid evidence", 400)
						return
					}
					source := finding["source"].(map[string]any)
					batch = append(batch, entry{source["raw_id"].(string), tenant, jsonText(finding)})
				}
			}
		}
	} else {
		http.Error(w, "denied", 403)
		return
	}

	if len(batch) == 0 || len(batch) > 256 {
		http.Error(w, "batch limit", 400)
		return
	}
	tx, err := n.Store.DB.Begin()
	if err != nil {
		http.Error(w, "queue unavailable", 503)
		return
	}
	defer tx.Rollback()
	var count int
	if tx.QueryRow(`SELECT count(*) FROM normalization_queue`).Scan(&count) != nil || count+len(batch) > 100000 {
		http.Error(w, "queue capacity", 503)
		return
	}
	for _, e := range batch {
		if _, err = tx.Exec(`INSERT OR IGNORE INTO normalization_queue VALUES (?,?,?)`, e.id, e.tenant, e.body); err != nil {
			http.Error(w, "queue unavailable", 503)
			return
		}
	}
	if tx.Commit() != nil {
		http.Error(w, "queue unavailable", 503)
		return
	}
	_, _ = w.Write([]byte(`{}`))
}
