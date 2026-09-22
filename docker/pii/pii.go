// Package pii provides PII detection and redaction via Microsoft Presidio.
//
// It calls the Presidio Analyzer REST API (POST /analyze) running as a sidecar
// service and replaces detected entities with [ENTITY_TYPE] placeholders so
// that sensitive data never reaches LLM backends or audit logs.
package pii

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Entity represents a single PII finding returned by Presidio.
type Entity struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

// analyzeRequest is the Presidio /analyze request body.
type analyzeRequest struct {
	Text      string    `json:"text"`
	Language  string    `json:"language"`
	Threshold float64   `json:"score_threshold"`
	Entities  []string  `json:"entities,omitempty"`
}

// Scrubber calls Presidio to detect and redact PII from text.
type Scrubber struct {
	presidioURL string
	threshold   float64
	httpClient  *http.Client
}

// NewScrubber constructs a Scrubber pointed at the given Presidio analyzer URL.
// threshold is the minimum confidence score (0.0–1.0) for a finding to be redacted.
func NewScrubber(presidioURL string, threshold float64) *Scrubber {
	return &Scrubber{
		presidioURL: strings.TrimRight(presidioURL, "/"),
		threshold:   threshold,
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

// Analyze returns all PII entities found in text that meet the threshold.
// If Presidio is unreachable it returns an empty slice and a non-nil error so
// callers can decide whether to fail open or closed.
func (s *Scrubber) Analyze(ctx context.Context, text string) ([]Entity, error) {
	payload := analyzeRequest{
		Text:      text,
		Language:  "en",
		Threshold: s.threshold,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("pii: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.presidioURL+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("pii: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pii: presidio unreachable: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("pii: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pii: presidio returned %d: %s", resp.StatusCode, respBytes)
	}

	var entities []Entity
	if err := json.Unmarshal(respBytes, &entities); err != nil {
		return nil, fmt.Errorf("pii: decode response: %w", err)
	}
	return entities, nil
}

// Redact replaces detected PII spans with [ENTITY_TYPE] placeholders.
// Overlapping entities are merged (highest score wins). Offsets are handled
// right-to-left so earlier spans are not shifted by replacements.
func Redact(text string, entities []Entity) string {
	if len(entities) == 0 {
		return text
	}

	// Sort descending by start offset so right-to-left replacement works.
	merged := mergeEntities(entities)
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].Start > merged[j].Start
	})

	runes := []rune(text)
	for _, e := range merged {
		start := e.Start
		end := e.End
		if start < 0 || end > len(runes) || start >= end {
			continue
		}
		placeholder := []rune("[" + e.EntityType + "]")
		runes = append(runes[:start], append(placeholder, runes[end:]...)...)
	}
	return string(runes)
}

// mergeEntities collapses overlapping spans, keeping the one with the highest
// score when two entities share the same span.
func mergeEntities(entities []Entity) []Entity {
	if len(entities) == 0 {
		return nil
	}
	// Sort ascending by start, then by score descending within the same start.
	sorted := make([]Entity, len(entities))
	copy(sorted, entities)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].Score > sorted[j].Score
	})

	out := []Entity{sorted[0]}
	for _, e := range sorted[1:] {
		last := &out[len(out)-1]
		if e.Start < last.End {
			// Overlapping — extend the current span if needed, prefer higher score.
			if e.Score > last.Score {
				last.EntityType = e.EntityType
				last.Score = e.Score
			}
			if e.End > last.End {
				last.End = e.End
			}
			continue
		}
		out = append(out, e)
	}
	return out
}

// ScrubText is a convenience wrapper that analyzes and immediately redacts text.
// On Presidio error it returns the original text unchanged (fail-open) and the
// error, letting callers log or escalate as appropriate.
func (s *Scrubber) ScrubText(ctx context.Context, text string) (string, []Entity, error) {
	entities, err := s.Analyze(ctx, text)
	if err != nil {
		return text, nil, err
	}
	return Redact(text, entities), entities, nil
}
