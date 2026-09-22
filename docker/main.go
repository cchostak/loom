package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"guardrail-proxy/pii"
)

// WebhookPayload supports both direct {role, content, prompt} and messages array formats
type WebhookPayload struct {
	Role     string        `json:"role,omitempty"`
	Content  string        `json:"content,omitempty"`
	Prompt   string        `json:"prompt,omitempty"`
	Messages []ChatMessage `json:"messages,omitempty"`
}

// ChatMessage represents an individual conversational turn
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// GuardrailEnvelope is the normalized payload sent by agentgateway v1.5.
type GuardrailEnvelope struct {
	Body GuardrailBody `json:"body"`
}

// GuardrailBody represents request messages or response choices.
type GuardrailBody struct {
	Messages []ChatMessage     `json:"messages,omitempty"`
	Choices  []GuardrailChoice `json:"choices,omitempty"`
}

// GuardrailChoice contains one normalized LLM response.
type GuardrailChoice struct {
	Message ChatMessage `json:"message"`
}

// GuardrailWebhookResponse follows the agentgateway Guardrail Webhook API.
type GuardrailWebhookResponse struct {
	Action GuardrailAction `json:"action"`
}

// GuardrailAction is a pass action when Body is empty and a reject action when
// Body and StatusCode are populated.
type GuardrailAction struct {
	Body       string `json:"body,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// ValidationResponse represents the standardized JSON response from guardrail checks
type ValidationResponse struct {
	Status  string   `json:"status"`
	Message string   `json:"message,omitempty"`
	Error   string   `json:"error,omitempty"`
	Matched []string `json:"matched,omitempty"`
}

// piiScrubber is the package-level PII scrubber, initialised by main().
// It is safe for concurrent use.
var piiScrubber *pii.Scrubber

// ForbiddenPatterns contains disallowed strings and destructive system commands
var ForbiddenPatterns = []string{
	"ignore previous instructions",
	"disregard all prior instructions",
	"reveal your system prompt",
	"exfiltrate secrets",
	"sudo",
	"rm -rf",
	"chmod 777",
	"mkfs",
	":(){ :|:& };:",
	"dd if=",
	"> /dev/sda",
	"/etc/shadow",
	"/etc/passwd",
}

// SetupRouter registers and returns the HTTP request multiplexer
func SetupRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", validateHandler)
	mux.HandleFunc("/request", guardrailWebhookHandler)
	mux.HandleFunc("/response", guardrailWebhookHandler)
	mux.HandleFunc("/health", healthHandler)
	if os.Getenv("DEBUG_MODE") == "true" {
		mux.HandleFunc("/pii-check", piiCheckHandler)
	}
	return loggingMiddleware(mux)
}

func main() {
	// Initialise PII scrubber from environment.
	presidioURL := os.Getenv("PII_PRESIDIO_URL")
	if presidioURL == "" {
		presidioURL = "http://presidio-analyzer:5002"
	}
	threshold := 0.7
	if v := os.Getenv("PII_THRESHOLD"); v != "" {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			threshold = parsed
		}
	}
	piiScrubber = pii.NewScrubber(presidioURL, threshold)
	log.Printf("🔍 PII scrubber configured: presidio=%s threshold=%.2f", presidioURL, threshold)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9090"
	}

	handler := SetupRouter()
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Channel to listen for OS interrupt / termination signals
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Printf("🛡️ Guardrail Proxy starting on port %s...", port)
		log.Printf("🛡️ Enforcing %d forbidden pattern rules.", len(ForbiddenPatterns))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	<-stopChan
	log.Println("🛑 Shutting down Guardrail Proxy gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error during server shutdown: %v", err)
	}
	log.Println("✓ Guardrail Proxy stopped.")
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s %s from %s in %v",
			r.Method, r.URL.Path, r.Proto, r.RemoteAddr, time.Since(start))
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"service":   "guardrail-proxy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

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

	rawContent := extractContent(bodyBytes)
	scrubbed, piiEntities := scrubPII(r.Context(), rawContent)
	if len(piiEntities) > 0 {
		log.Printf("🔒 PII scrubbed: %d entit(ies) redacted before pattern check", len(piiEntities))
	}

	matchedPatterns := findForbiddenPatterns(scrubbed)

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

	rawContent := extractContent(bodyBytes)
	scrubbed, piiEntities := scrubPII(r.Context(), rawContent)
	if len(piiEntities) > 0 {
		log.Printf("🔒 PII scrubbed in webhook: %d entit(ies) redacted", len(piiEntities))
	}

	matched := findForbiddenPatterns(scrubbed)
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

// scrubPII calls Presidio via piiScrubber and returns the redacted text plus
// the list of detected entities. On error it fails open: returns the original
// text unchanged and logs a warning so the proxy continues operating.
func scrubPII(ctx context.Context, text string) (string, []pii.Entity) {
	if piiScrubber == nil {
		return text, nil
	}
	scrubbed, entities, err := piiScrubber.ScrubText(ctx, text)
	if err != nil {
		log.Printf("⚠️  PII scrubber error (fail-open): %v", err)
		return text, nil
	}
	return scrubbed, entities
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
		_ = json.NewEncoder(w).Encode(ValidationResponse{Status: "error", Error: "Presidio error: " + err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"entities": entities,
		"redacted": pii.Redact(req.Text, entities),
	})
}

