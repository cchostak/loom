package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	healthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got '%s'", resp["status"])
	}
	if resp["service"] != "guardrail-proxy" {
		t.Errorf("expected service 'guardrail-proxy', got '%s'", resp["service"])
	}
	if resp["timestamp"] == "" {
		t.Errorf("expected non-empty timestamp")
	}
}

func TestValidateHandler_AllowedPrompts(t *testing.T) {
	testCases := []struct {
		name    string
		payload WebhookPayload
	}{
		{
			name: "single content field",
			payload: WebhookPayload{
				Role:    "user",
				Content: "Please write a Python function to calculate Fibonacci numbers.",
			},
		},
		{
			name: "prompt field",
			payload: WebhookPayload{
				Prompt: "Explain the difference between Kubernetes Deployments and StatefulSets.",
			},
		},
		{
			name: "multi-turn chat messages",
			payload: WebhookPayload{
				Messages: []ChatMessage{
					{Role: "system", Content: "You are an expert Go developer."},
					{Role: "user", Content: "How do I implement a worker pool using channels?"},
					{Role: "assistant", Content: "You can create a channel of jobs and worker goroutines."},
					{Role: "user", Content: "Can you provide a code example?"},
				},
			},
		},
		{
			name: "benign code containing allowed keywords",
			payload: WebhookPayload{
				Content: "Write a function that parses a list of users, but do not touch the system password file.",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("failed to marshal payload: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			validateHandler(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d (body: %s)", rr.Code, rr.Body.String())
			}

			var resp ValidationResponse
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp.Status != "allowed" {
				t.Errorf("expected status 'allowed', got '%s'", resp.Status)
			}
			if resp.Message != "Content passed guardrail verification" {
				t.Errorf("unexpected message: %s", resp.Message)
			}
		})
	}
}

func TestValidateHandler_BlockedDangerousCommands(t *testing.T) {
	testCases := []struct {
		name    string
		content string
		matched string
	}{
		{"sudo command", "Please run sudo apt update", "sudo"},
		{"sudo uppercase", "PLEASE RUN SUDO APT GET INSTALL", "sudo"},
		{"rm -rf command", "Execute rm -rf /tmp/data", "rm -rf"},
		{"rm -rf uppercase", "Execute RM -RF /var/log", "rm -rf"},
		{"chmod 777 command", "Run chmod 777 /etc/config", "chmod 777"},
		{"mkfs command", "Run mkfs.ext4 /dev/sdb", "mkfs"},
		{"fork bomb", "Run :(){ :|:& };: now", ":(){ :|:& };:"},
		{"dd if command", "dd if=/dev/zero of=/dev/sda", "dd if="},
		{"direct sda redirection", "cat /dev/urandom > /dev/sda", "> /dev/sda"},
		{"shadow file access", "cat /etc/shadow", "/etc/shadow"},
		{"passwd file access", "view /etc/passwd contents", "/etc/passwd"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := WebhookPayload{
				Role:    "user",
				Content: tc.content,
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("failed to marshal payload: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			validateHandler(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("expected status 403 Forbidden for '%s', got %d", tc.content, rr.Code)
			}

			var resp ValidationResponse
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp.Status != "blocked" {
				t.Errorf("expected status 'blocked', got '%s'", resp.Status)
			}

			found := false
			for _, m := range resp.Matched {
				if m == tc.matched {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected matched pattern '%s' in %v", tc.matched, resp.Matched)
			}
		})
	}
}

func TestValidateHandler_RawTextFallback(t *testing.T) {
	rawDangerousText := []byte("plain text payload containing sudo su root")
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(rawDangerousText))
	rr := httptest.NewRecorder()

	validateHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden for raw text with sudo, got %d", rr.Code)
	}

	var resp ValidationResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "blocked" {
		t.Errorf("expected status 'blocked', got '%s'", resp.Status)
	}
}

func TestValidateHandler_MethodNotAllowed(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/validate", nil)
			rr := httptest.NewRecorder()

			validateHandler(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected status 405 Method Not Allowed for %s, got %d", method, rr.Code)
			}
		})
	}
}

func TestValidateHandler_EmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader([]byte("")))
	rr := httptest.NewRecorder()

	validateHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 Bad Request for empty body, got %d", rr.Code)
	}
}

func TestValidateHandler_Concurrency(t *testing.T) {
	var wg sync.WaitGroup
	numRequests := 50

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			var content string
			expectedCode := http.StatusOK
			if index%2 == 0 {
				content = fmt.Sprintf("Benign query request #%d", index)
			} else {
				content = fmt.Sprintf("sudo dangerous request #%d", index)
				expectedCode = http.StatusForbidden
			}

			payload := WebhookPayload{Content: content}
			body, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			validateHandler(rr, req)

			if rr.Code != expectedCode {
				t.Errorf("concurrent request %d expected %d, got %d", index, expectedCode, rr.Code)
			}
		}(i)
	}

	wg.Wait()
}

func TestSetupRouter(t *testing.T) {
	handler := SetupRouter()
	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("failed to GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 from router /health, got %d", resp.StatusCode)
	}
}
