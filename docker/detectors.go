package main

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// Detector may be implemented by local classifiers or external DLP services.
// Errors are distinct from a clean result and always deny at the caller.
type Detector interface {
	Detect(context.Context, string) (bool, error)
}

type sensitiveDetector struct{}

var secretPattern = regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/=-]{12,}|\b(?:sk-or-v1-|sk-proj-|ghp_|github_pat_|AKIA)[A-Za-z0-9_-]{8,}|"(?:password|api_key|access_token|authorization)"\s*:\s*"[^"\s]+")`)

func (sensitiveDetector) Detect(ctx context.Context, text string) (bool, error) {
	if secretPattern.MatchString(text) {
		return true, nil
	}
	if piiScrubber == nil {
		return false, errors.New("detector unavailable")
	}
	entities, err := piiScrubber.Analyze(ctx, text)
	return len(entities) > 0, err
}

func inspectSensitive(ctx context.Context, text string) string {
	var detector Detector = sensitiveDetector{}
	found, err := detector.Detect(ctx, text)
	if err != nil {
		return "sensitive_detector_unavailable"
	}
	if found {
		return "sensitive_data_detected"
	}
	return ""
}

// inspectionText includes every JSON string, including encoded/nested content;
// selecting only known message fields would miss hostile extension fields.
func inspectionText(body []byte) string {
	var out strings.Builder
	var visit func(any, int)
	visit = func(value any, depth int) {
		if depth > 8 {
			return
		}
		switch v := value.(type) {
		case string:
			out.WriteString(v)
			out.WriteByte(' ')
			var nested any
			if json.Unmarshal([]byte(v), &nested) == nil {
				visit(nested, depth+1)
			}
		case []any:
			for _, item := range v {
				visit(item, depth+1)
			}
		case map[string]any:
			for key, item := range v {
				out.WriteString(key)
				out.WriteByte(' ')
				visit(item, depth+1)
			}
		}
	}
	out.Write(body)
	out.WriteByte(' ')
	var value any
	if json.Unmarshal(body, &value) == nil {
		visit(value, 0)
	}
	return out.String()
}
