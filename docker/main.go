package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
	log.Printf("PII detector configured; threshold=%.2f", threshold)

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
			r.Method, "guardrail", r.Proto, "internal", time.Since(start))
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
