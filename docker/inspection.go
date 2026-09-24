package main

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
)

// piiInspectionText presents decoded JSON leaves to the language classifier.
// Repeated serialized envelopes and escape punctuation are not natural language
// and produced false PERSON/NRP detections on protocol keys. Keep every key and
// scalar, including unknown fields and exact numeric values. Literal/secret
// detectors separately inspect both the original bytes and decoded strings.
func piiInspectionText(body string) string {
	var out strings.Builder
	var visit func(any, int)
	decode := func(text string) (any, bool) {
		decoder := json.NewDecoder(strings.NewReader(text))
		decoder.UseNumber()
		var value any
		if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
			return nil, false
		}
		return value, true
	}
	line := func(text string) { out.WriteString(text); out.WriteByte('\n') }
	visit = func(value any, depth int) {
		if depth > 32 {
			b, _ := json.Marshal(value)
			line(string(b)) // Preserve, rather than silently discard, deeper content.
			return
		}
		switch v := value.(type) {
		case string:
			if nested, ok := decode(v); ok {
				visit(nested, depth+1)
			} else {
				line(v)
			}
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				line(key)
				visit(v[key], depth+1)
			}
		case []any:
			for _, item := range v {
				visit(item, depth+1)
			}
		case json.Number:
			line(string(v))
		case bool:
			if v {
				line("true")
			} else {
				line("false")
			}
		case nil:
			line("null")
		}
	}
	visit(body, 0)
	return out.String()
}
