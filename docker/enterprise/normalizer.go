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

var hexID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var safeLabel = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$`)
var digestID = regexp.MustCompile(`^[a-f0-9]{64}$`)

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
	finding := map[string]any{"finding_type": findingType, "title": title, "description": description, "severity": "low", "rule_id": rule, "status": "new", "environment": "lab", "service_name": "loom",
		"affected_resource": map[string]string{"resource_type": "ai_agent", "resource_id": values["loom.workload"] + "/" + resource, "resource_name": values["loom.workload"]},
		"remediation":       map[string]any{"description": remediation, "automated": false, "references": []string{}},
		"source":            map[string]any{"scanner": "loom", "scanner_version": "1", "raw_id": values["loom.event_id"], "raw_severity": "WARN", "extra": map[string]string{"trace_id": values["loom.trace_id"], "decision_id": values["loom.decision_id"], "control": kind, "outcome": "enforced"}},
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
	if r.Method != "POST" || r.URL.Path != "/v1/logs" || r.URL.RawQuery != "" || len(n.IngestToken) < 32 || !hmac.Equal([]byte(r.Header.Get("Authorization")), []byte("Bearer "+n.IngestToken)) {
		http.Error(w, "denied", 403)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "input limit", 413)
		return
	}
	var payload otlpLogs
	if json.Unmarshal(b, &payload) != nil {
		http.Error(w, "invalid OTLP", 400)
		return
	}
	type entry struct{ id, tenant, body string }
	batch := []entry{}
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
