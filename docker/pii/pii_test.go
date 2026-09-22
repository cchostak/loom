package pii_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"guardrail-proxy/pii"
)

// mockPresidio creates a test server that returns the given entities JSON.
func mockPresidio(t *testing.T, entities []pii.Entity, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/analyze" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if err := json.NewEncoder(w).Encode(entities); err != nil {
			t.Errorf("mock presidio: encode: %v", err)
		}
	}))
}

// --- Analyze tests ---

func TestAnalyze_NoEntities(t *testing.T) {
	srv := mockPresidio(t, []pii.Entity{}, http.StatusOK)
	defer srv.Close()

	s := pii.NewScrubber(srv.URL, 0.7)
	entities, err := s.Analyze(context.Background(), "Hello, world!")
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil", err)
	}
	if len(entities) != 0 {
		t.Errorf("Analyze() = %v, want empty", entities)
	}
}

func TestAnalyze_EmailDetected(t *testing.T) {
	want := []pii.Entity{
		{EntityType: "EMAIL_ADDRESS", Start: 7, End: 26, Score: 0.85},
	}
	srv := mockPresidio(t, want, http.StatusOK)
	defer srv.Close()

	s := pii.NewScrubber(srv.URL, 0.7)
	got, err := s.Analyze(context.Background(), "Email: user@example.com here")
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(got) != 1 || got[0].EntityType != "EMAIL_ADDRESS" {
		t.Errorf("Analyze() = %+v, want EMAIL_ADDRESS entity", got)
	}
}

func TestAnalyze_PresidioUnreachable(t *testing.T) {
	s := pii.NewScrubber("http://127.0.0.1:1", 0.7) // nothing listening
	_, err := s.Analyze(context.Background(), "some text")
	if err == nil {
		t.Fatal("Analyze() expected error when Presidio is unreachable, got nil")
	}
}

func TestAnalyze_NonOKStatus(t *testing.T) {
	srv := mockPresidio(t, nil, http.StatusInternalServerError)
	defer srv.Close()

	s := pii.NewScrubber(srv.URL, 0.7)
	_, err := s.Analyze(context.Background(), "test")
	if err == nil {
		t.Fatal("Analyze() expected error on non-200 status, got nil")
	}
}

// --- Redact tests ---

func TestRedact_NoEntities(t *testing.T) {
	input := "Hello, world!"
	got := pii.Redact(input, nil)
	if got != input {
		t.Errorf("Redact() = %q, want %q", got, input)
	}
}

func TestRedact_SingleEmail(t *testing.T) {
	input := "Email: user@example.com here"
	entities := []pii.Entity{
		{EntityType: "EMAIL_ADDRESS", Start: 7, End: 23, Score: 0.9},
	}
	got := pii.Redact(input, entities)
	want := "Email: [EMAIL_ADDRESS] here"
	if got != want {
		t.Errorf("Redact() = %q, want %q", got, want)
	}
}

func TestRedact_MultipleEntities(t *testing.T) {
	// "Call 555-1234 or email me@test.com"
	input := "Call 555-1234 or email me@test.com"
	entities := []pii.Entity{
		{EntityType: "PHONE_NUMBER", Start: 5, End: 13, Score: 0.85},
		{EntityType: "EMAIL_ADDRESS", Start: 23, End: 34, Score: 0.95},
	}
	got := pii.Redact(input, entities)
	if got == input {
		t.Error("Redact() should have changed the input")
	}
	for _, unwanted := range []string{"555-1234", "me@test.com"} {
		if contains(got, unwanted) {
			t.Errorf("Redact() result still contains PII %q: %q", unwanted, got)
		}
	}
}

func TestRedact_OverlappingEntities(t *testing.T) {
	input := "Hello World"
	// Two overlapping spans — mergeEntities should keep the highest-score one.
	entities := []pii.Entity{
		{EntityType: "PERSON", Start: 0, End: 5, Score: 0.8},
		{EntityType: "NAME", Start: 0, End: 11, Score: 0.9},
	}
	got := pii.Redact(input, entities)
	if got == input {
		t.Error("Redact() should have redacted overlapping span")
	}
}

func TestRedact_InvalidSpansIgnored(t *testing.T) {
	input := "Hello"
	entities := []pii.Entity{
		{EntityType: "EMAIL_ADDRESS", Start: -1, End: 3, Score: 0.9},  // invalid start
		{EntityType: "PHONE_NUMBER", Start: 3, End: 100, Score: 0.85}, // end out of range
	}
	// Should not panic; returns something (possibly unchanged or partially redacted).
	_ = pii.Redact(input, entities)
}

// --- ScrubText integration ---

func TestScrubText_RedactsDetectedPII(t *testing.T) {
	entities := []pii.Entity{
		{EntityType: "EMAIL_ADDRESS", Start: 7, End: 23, Score: 0.9},
	}
	srv := mockPresidio(t, entities, http.StatusOK)
	defer srv.Close()

	s := pii.NewScrubber(srv.URL, 0.7)
	got, found, err := s.ScrubText(context.Background(), "Email: user@example.com here")
	if err != nil {
		t.Fatalf("ScrubText() error = %v", err)
	}
	if len(found) != 1 {
		t.Errorf("ScrubText() found %d entities, want 1", len(found))
	}
	if contains(got, "user@example.com") {
		t.Errorf("ScrubText() still contains raw email: %q", got)
	}
}

func TestScrubText_FailOpenOnPresidioError(t *testing.T) {
	s := pii.NewScrubber("http://127.0.0.1:1", 0.7)
	original := "Some text"
	got, _, err := s.ScrubText(context.Background(), original)
	if err == nil {
		t.Fatal("ScrubText() expected error on unreachable Presidio")
	}
	// Fail-open: returns original text unchanged.
	if got != original {
		t.Errorf("ScrubText() fail-open got %q, want original %q", got, original)
	}
}

func TestScrubText_NoEntitiesReturnedUnchanged(t *testing.T) {
	srv := mockPresidio(t, []pii.Entity{}, http.StatusOK)
	defer srv.Close()

	s := pii.NewScrubber(srv.URL, 0.7)
	input := "Nothing sensitive here"
	got, found, err := s.ScrubText(context.Background(), input)
	if err != nil {
		t.Fatalf("ScrubText() error = %v", err)
	}
	if len(found) != 0 {
		t.Errorf("ScrubText() found %d entities, want 0", len(found))
	}
	if got != input {
		t.Errorf("ScrubText() changed clean input: %q", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsRune(s, substr))
}

func containsRune(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
