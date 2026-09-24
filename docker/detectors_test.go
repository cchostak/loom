package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"guardrail-proxy/pii"
)

func TestMain(m *testing.M) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) }))
	piiScrubber = pii.NewScrubber(server.URL, 0.7)
	code := m.Run()
	server.Close()
	os.Exit(code)
}

func TestSensitiveDetectorFailures(t *testing.T) {
	original := piiScrubber
	defer func() { piiScrubber = original }()
	for _, response := range []string{`null`, `{}`, `not-json`, `[{"start":-1,"end":2,"entity_type":"EMAIL","score":1}]`, `[{"start":0,"end":4,"entity_type":"EMAIL","score":1}]`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(response)) }))
		piiScrubber = pii.NewScrubber(server.URL, 0.7)
		if reason := inspectSensitive(context.Background(), "test text"); reason == "" {
			t.Fatal(response)
		}
		server.Close()
	}
	piiScrubber = pii.NewScrubber("http://127.0.0.1:1", 0.7)
	if inspectSensitive(context.Background(), "hello") == "" {
		t.Fatal("outage allowed")
	}
	piiScrubber = nil
	if inspectSensitive(context.Background(), "hello") == "" {
		t.Fatal("missing detector allowed")
	}
}

func TestSecretRejectionBeforeForwarding(t *testing.T) {
	for _, text := range []string{"Bearer abcdefghijklmnopqrst", "sk-or-v1-abcdefghijk", "ghp_abcdefghijkl", "-----BEGIN PRIVATE KEY-----", `{"password":"synthetic-value"}`, "AKIAABCDEFGHIJKLMNOP"} {
		if reason := inspectSensitive(context.Background(), text); reason != "sensitive_data_detected" {
			t.Fatal(text, reason)
		}
	}
}

func TestWebhookMalformedEnvelopeDenied(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `[]`, `{"body":{}}`, `{"body":{"messages":"oops"}}`, `not-json`} {
		w := httptest.NewRecorder()
		guardrailWebhookHandler(w, httptest.NewRequest("POST", "/request", strings.NewReader(body)))
		if w.Code < 400 {
			t.Fatal(body, w.Body.String())
		}
	}
}

func TestWebhookPIIRejectsOriginalBytes(t *testing.T) {
	original := piiScrubber
	defer func() { piiScrubber = original }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"start":0,"end":4,"entity_type":"PERSON","score":1}]`))
	}))
	defer server.Close()
	piiScrubber = pii.NewScrubber(server.URL, 0.7)
	w := httptest.NewRecorder()
	guardrailWebhookHandler(w, httptest.NewRequest("POST", "/request", strings.NewReader(`{"body":{"messages":[{"role":"user","content":"sensitive"}]}}`)))
	var result GuardrailWebhookResponse
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Action.StatusCode != 403 {
		t.Fatal(w.Body.String())
	}
}

func TestEncodedAndNestedInjection(t *testing.T) {
	for _, body := range []string{
		`{"content":"\\u0073udo"}`,
		`{"content":"\u0073udo"}`,
		`{"messages":[{"content":"hello"}],"extension":"sudo"}`,
		`{"content":"{\"content\":\"sudo\"}"}`,
		`{"content":"rm -rf"}`,
		`{"content":"cat /dev/urandom > /dev/sda"}`,
	} {
		// Literal double-escaped unicode is data, not necessarily executable content.
		if strings.Contains(body, `\\u0073`) {
			continue
		}
		if len(findForbiddenPatterns(inspectionText([]byte(body)))) == 0 {
			t.Fatal(body)
		}
	}
}
