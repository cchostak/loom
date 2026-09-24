package main

import (
	"encoding/json"
	"guardrail-proxy/pii"
	"io"
	"log"
	"net/http"
	"strings"
)

func validateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(ValidationResponse{
			Status: "error",
			Error:  "Method not allowed. Use POST.",
		})
		return
	}

	bodyBytes, err := readRequestBody(w, r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ValidationResponse{
			Status: "error",
			Error:  "Failed to read request body",
		})
		return
	}

	if len(bodyBytes) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ValidationResponse{
			Status: "error",
			Error:  "Empty request body",
		})
		return
	}

	rawContent := inspectionText(bodyBytes)
	if reason := inspectSensitive(r.Context(), string(bodyBytes)); reason != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(ValidationResponse{Status: "blocked", Error: reason})
		return
	}
	matchedPatterns := findForbiddenPatterns(rawContent)

	w.Header().Set("Content-Type", "application/json")

	if len(matchedPatterns) > 0 {
		log.Printf("🚨 BLOCKED forbidden content. Matched patterns: %v", matchedPatterns)
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(ValidationResponse{
			Status:  "blocked",
			Error:   "Forbidden content detected by guardrail policy",
			Matched: matchedPatterns,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ValidationResponse{
		Status:  "allowed",
		Message: "Content passed guardrail verification",
	})
}

func guardrailWebhookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(ValidationResponse{
			Status: "error", Error: "Method not allowed. Use POST.",
		})
		return
	}

	bodyBytes, err := readRequestBody(w, r)
	if err != nil || len(bodyBytes) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ValidationResponse{
			Status: "error", Error: "Invalid or empty request body",
		})
		return
	}

	var envelope GuardrailEnvelope
	if json.Unmarshal(bodyBytes, &envelope) != nil || (len(envelope.Body.Messages) == 0 && len(envelope.Body.Choices) == 0) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ValidationResponse{Status: "error", Error: "Invalid webhook schema"})
		return
	}
	rawContent := inspectionText(bodyBytes)
	if reason := inspectSensitive(r.Context(), string(bodyBytes)); reason != "" {
		_ = json.NewEncoder(w).Encode(GuardrailWebhookResponse{Action: GuardrailAction{Body: "Content inspection denied", StatusCode: 403, Reason: reason}})
		return
	}
	matched := findForbiddenPatterns(rawContent)
	response := GuardrailWebhookResponse{Action: GuardrailAction{
		Reason: "Content passed Loom guardrail verification",
	}}
	if len(matched) > 0 {
		log.Printf("🚨 BLOCKED agentgateway webhook content. Matched patterns: %v", matched)
		response.Action = GuardrailAction{
			Body:       "Request blocked by Loom guardrail policy",
			StatusCode: http.StatusForbidden,
			Reason:     "Matched forbidden pattern: " + strings.Join(matched, ", "),
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	const maxBodyBytes = 1 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func extractContent(bodyBytes []byte) string {
	var direct WebhookPayload
	var normalized GuardrailEnvelope
	var content strings.Builder

	if err := json.Unmarshal(bodyBytes, &direct); err == nil {
		content.WriteString(direct.Content)
		content.WriteString(" ")
		content.WriteString(direct.Prompt)
		for _, message := range direct.Messages {
			content.WriteString(" ")
			content.WriteString(message.Content)
		}
	}
	if err := json.Unmarshal(bodyBytes, &normalized); err == nil {
		for _, message := range normalized.Body.Messages {
			content.WriteString(" ")
			content.WriteString(message.Content)
		}
		for _, choice := range normalized.Body.Choices {
			content.WriteString(" ")
			content.WriteString(choice.Message.Content)
		}
	}

	if strings.TrimSpace(content.String()) == "" {
		return string(bodyBytes)
	}
	return content.String()
}

func findForbiddenPatterns(content string) []string {
	lowerContent := strings.ToLower(content)
	matched := make([]string, 0)
	for _, pattern := range ForbiddenPatterns {
		if strings.Contains(lowerContent, strings.ToLower(pattern)) {
			matched = append(matched, pattern)
		}
	}
	return matched
}

// piiCheckHandler is a debug endpoint (only registered when DEBUG_MODE=true)
// that returns the raw Presidio analysis for a given text payload.
// Request: POST /pii-check with {"text": "..."}
// Response: the Presidio entity list JSON for tuning threshold values.
func piiCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(ValidationResponse{Status: "error", Error: "Use POST"})
		return
	}

	bodyBytes, err := readRequestBody(w, r)
	if err != nil || len(bodyBytes) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ValidationResponse{Status: "error", Error: "Invalid body"})
		return
	}

	var req struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(bodyBytes, &req); err != nil || req.Text == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ValidationResponse{Status: "error", Error: "JSON body with 'text' field required"})
		return
	}

	if piiScrubber == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(ValidationResponse{Status: "error", Error: "PII scrubber not initialised"})
		return
	}

	entities, err := piiScrubber.Analyze(r.Context(), req.Text)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(ValidationResponse{Status: "error", Error: "PII detector unavailable"})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"entities": entities,
		"redacted": pii.Redact(req.Text, entities),
	})
}
