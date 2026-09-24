package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPIIInspectionPreservesAllData(t *testing.T) {
	cases := []struct {
		body   string
		values []string
	}{
		{`{"unknown":"person@example.test","another":{"sensitive":"value"}}`, []string{"unknown", "person@example.test", "sensitive", "value"}},
		{`{"account":123456789012345678901234567890}`, []string{"123456789012345678901234567890"}},
		{`{"content":"{\"email\":\"person@example.test\"}"}`, []string{"email", "person@example.test"}},
		{`{"person@example.test":"key also matters"}`, []string{"person@example.test", "key also matters"}},
		{"malformed { raw content", []string{"malformed { raw content"}},
		{`["unicode: \u0041",null,true,false]`, []string{"unicode: A", "null", "true", "false"}},
	}
	for _, tc := range cases {
		got := piiInspectionText(tc.body)
		for _, value := range tc.values {
			if !strings.Contains(got, value) {
				t.Errorf("missing %q in %q", value, got)
			}
		}
	}
}

func TestPIIInspectionStableAndNoEnvelopeDuplication(t *testing.T) {
	body := `{"z":"unique-content","a":"{\"tool\":\"read\",\"input\":{\"path\":\"/workspace\"}}"}`
	want := piiInspectionText(body)
	if strings.Count(want, "unique-content") != 1 || strings.Contains(want, `\"`) {
		t.Fatal(want)
	}
	for i := 0; i < 100; i++ {
		if got := piiInspectionText(body); got != want {
			t.Fatal("unstable classifier input")
		}
	}
}

func TestPIIInspectionDepthRetainsContent(t *testing.T) {
	text := "sensitive-marker"
	for i := 0; i < 20; i++ {
		b, _ := json.Marshal(map[string]string{"nested": text})
		text = string(b)
	}
	if !strings.Contains(piiInspectionText(text), "sensitive-marker") {
		t.Fatal("deep content discarded")
	}
}
